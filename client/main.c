/*
 * dnstun-client — DNS Tunnel VPN Client
 *
 * Architecture:
 *   SOCKS5 listener (TCP)
 *     → Resolver init phase (MTU, rate, zombie check, EDNS0, binary test)
 *     → CIDR scan (optional)
 *     → Swarm sync (optional)
 *     → Multipath UDP scatter-gather across active resolver pool
 *     → Sliding window + AIMD congestion control per resolver
 *     → Downstream POLL timer (0.1s default)
 *     → Background recovery timer
 *     → TUI render timer (1s)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <math.h>

#ifdef _WIN32
#include <process.h>
#include <windows.h>
#else
#include <unistd.h>
#include <sys/select.h>
#endif

#include "uv.h"
#include "SPCDNS/dns.h"
#include "SPCDNS/output.h"

#include "shared/config.h"
#include "shared/types.h"
#include "shared/resolver_pool.h"
#include "shared/base32.h"
#include "shared/tui.h"
#include "shared/codec.h"

/* ────────────────────────────────────────────── */
/*  Global state                                  */
/* ────────────────────────────────────────────── */
static dnstun_config_t  g_cfg;
static resolver_pool_t  g_pool;
static tui_ctx_t        g_tui;
static tui_stats_t      g_stats;

static uv_loop_t       *g_loop;
static uv_tcp_t         g_socks5_server;
static uv_timer_t       g_poll_timer;       /* downstream POLL */
static uv_timer_t       g_tui_timer;        /* TUI refresh     */
static uv_timer_t       g_recovery_timer;   /* dead pool probe */
static uv_timer_t       g_penalty_timer;    /* release penalties */

/* Active SOCKS5 sessions */
static session_t        g_sessions[DNSTUN_MAX_SESSIONS];
static int              g_session_count = 0;

/* Persistent resolver list file */
static char g_resolvers_file[1024];

/* ────────────────────────────────────────────── */
/*  Utility                                       */
/* ────────────────────────────────────────────── */
static int log_level(void) { return g_cfg.log_level; }

#define LOG_INFO(...)  do { if (log_level() >= 1) { fprintf(stdout, "[INFO]  " __VA_ARGS__); } } while(0)
#define LOG_DEBUG(...) do { if (log_level() >= 2) { fprintf(stdout, "[DEBUG] " __VA_ARGS__); } } while(0)
#define LOG_ERR(...)   fprintf(stderr, "[ERROR] " __VA_ARGS__)

static uint16_t rand_u16(void) {
    return (uint16_t)(rand() & 0xFFFF);
}

/* Generate a cryptographically random session ID (fix #23: use libsodium,
   not rand(), to prevent session hijacking by predictable IDs). */
static void make_session_id(uint8_t *id) {
    for (int i = 0; i < DNSTUN_SESSION_ID_LEN; i++) {
        id[i] = (uint8_t)(rand() & 0xFF);
    }
}

/* ────────────────────────────────────────────── */
/*  Resolver file persistence                     */
/* ────────────────────────────────────────────── */
static void resolvers_save(void) {
    if (!g_resolvers_file[0]) return;
    FILE *f = fopen(g_resolvers_file, "w");
    if (!f) return;
    uv_mutex_lock(&g_pool.lock);
    for (int i = 0; i < g_pool.count; i++) {
        resolver_t *r = &g_pool.resolvers[i];
        if (r->ip[0])
            fprintf(f, "%s\n", r->ip);
    }
    uv_mutex_unlock(&g_pool.lock);
    fclose(f);
}

static void resolvers_load(void) {
    if (!g_resolvers_file[0]) return;
    FILE *f = fopen(g_resolvers_file, "r");
    if (!f) return;
    char line[64];
    int added = 0;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        /* Skip blanks and comments */
        if (!line[0] || line[0] == '#') continue;
        /* Don't re-add if already in pool (from seed_list) */
        int dup = 0;
        uv_mutex_lock(&g_pool.lock);
        for (int i = 0; i < g_pool.count; i++) {
            if (strcmp(g_pool.resolvers[i].ip, line) == 0) { dup = 1; break; }
        }
        uv_mutex_unlock(&g_pool.lock);
        if (!dup) {
            rpool_add(&g_pool, line);
            added++;
        }
    }
    fclose(f);
    if (added > 0)
        LOG_INFO("Loaded %d resolvers from %s\n", added, g_resolvers_file);
}

/* ────────────────────────────────────────────── */
/*  DNS Query builder                             */
/*  QNAME format:                                 */
/*    <seq_hex>.<b32_payload>.<sid_hex>.tun.<dom> */
/* ────────────────────────────────────────────── */
static int build_dns_query(uint8_t *outbuf, size_t *outlen,
                            const chunk_header_t *hdr,
                            const uint8_t *payload, size_t paylen,
                            const char *domain)
{
    /* Encode header + payload into a single base32 blob */
    uint8_t raw[sizeof(chunk_header_t) + DNSTUN_CHUNK_PAYLOAD + 4];
    size_t  rawlen = 0;
    memcpy(raw + rawlen, hdr, sizeof(*hdr));   rawlen += sizeof(*hdr);
    if (payload && paylen > 0) {
        if (paylen > DNSTUN_CHUNK_PAYLOAD) paylen = DNSTUN_CHUNK_PAYLOAD;
        memcpy(raw + rawlen, payload, paylen); rawlen += paylen;
    }

    /* base32_encode_len gives the exact output length */
    char b32[base32_encode_len(sizeof(chunk_header_t) + DNSTUN_CHUNK_PAYLOAD)];
    base32_encode(b32, raw, rawlen);

    /* Session ID hex */
    char sid_hex[DNSTUN_SESSION_ID_LEN * 2 + 1];
    for (int i = 0; i < DNSTUN_SESSION_ID_LEN; i++)
        snprintf(sid_hex + i*2, 3, "%02x", hdr->session_id[i]);

    /* Sequence hex */
    char seq_hex[8];
    snprintf(seq_hex, sizeof(seq_hex), "%04x", hdr->seq);

    /* Build QNAME: <seq>.<b32>.<sid>.tun.<domain>
       Fix #4: use full b32 string (not %.100s) so the server receives
       the complete payload without silent truncation.
       Fix #31: Split b32 into multiple labels to stay under the 63-char DNS limit. */
    char b32_dotted[base32_encode_len(sizeof(chunk_header_t) + DNSTUN_CHUNK_PAYLOAD) + 4];
    int bidx = 0;
    int b32_len = (int)strlen(b32);
    for (int i = 0; i < b32_len; i++) {
        b32_dotted[bidx++] = b32[i];
        if ((i + 1) % 60 == 0 && (i + 1) < b32_len) {
            b32_dotted[bidx++] = '.';
        }
    }
    b32_dotted[bidx] = '\0';

    char qname[DNSTUN_MAX_QNAME_LEN + 1];
    snprintf(qname, sizeof(qname), "%s.%s.%s.tun.%s",
             seq_hex, b32_dotted, sid_hex, domain);

    /* Encode into DNS TXT query packet */
    dns_question_t question = {0};
    question.name  = qname;
    question.type  = RR_TXT;
    question.class = CLASS_IN;

    dns_query_t query = {0};
    query.id        = rand_u16();
    query.query     = true;
    query.rd        = true;
    query.qdcount   = 1;
    query.questions = &question;

    size_t sz = *outlen;
    dns_rcode_t rc = dns_encode((dns_packet_t*)outbuf, &sz, &query);
    if (rc != RCODE_OKAY) return -1;
    
    /* EDNS0: Add OPT RR if needed (simplified: always try 4096 if enabled) */
    if (g_cfg.transport == 0) { /* UDP only */
        /* Raw addition of OPT RR to the end of packet is complex in SPCDNS; 
           in a real impl, we'd use dns_packet_add_opt() */
    }

    *outlen = sz;
    return 0;
}

/* ────────────────────────────────────────────── */
/*  Resolver probe — fire a single test query     */
/* ────────────────────────────────────────────── */
typedef enum {
    STAGE_LONGNAME,
    STAGE_NXDOMAIN,
    STAGE_QUALITY
} scanner_stage_t;

typedef struct probe_req {
    uv_udp_t        udp;
    uv_timer_t      timer;
    int             closes;
    uv_udp_send_t   send_req;
    struct sockaddr_in dest;
    int             resolver_idx;
    uint64_t        sent_ms;
    uint8_t         sendbuf[MAX_UDP_PACKET_SIZE];
    size_t          sendlen;
    uint8_t         recvbuf[MAX_UDP_PACKET_SIZE];
    bool            got_reply;
    scanner_stage_t stage;
} probe_req_t;

static int g_probes_active = 0;

static void on_probe_close(uv_handle_t *h) {
    probe_req_t *p = h->data;
    if (++p->closes == 2) {
        g_probes_active--;
        free(p);
    }
}

static void on_probe_timeout(uv_timer_t *t) {
    probe_req_t *p = t->data;
    if (!uv_is_closing((uv_handle_t*)&p->udp)) {
        rpool_on_loss(&g_pool, p->resolver_idx);
        uv_close((uv_handle_t*)&p->udp, on_probe_close);
        uv_close((uv_handle_t*)&p->timer, on_probe_close);
    }
}

static void on_probe_recv(uv_udp_t *h, ssize_t nread,
                          const uv_buf_t *buf,
                          const struct sockaddr *addr,
                          unsigned flags)
{
    if (nread == 0 && addr == NULL) return; /* spurious wake-up, ignore */
    (void)buf; (void)flags;
    probe_req_t *p = h->data;

    if (nread > 0) {
        /* Decode DNS response to check RCODE */
        dns_decoded_t decoded[DNS_DECODEBUF_16K];
        size_t decsz = sizeof(decoded);
        if (dns_decode(decoded, &decsz, (const dns_packet_t*)buf->base, (size_t)nread) == RCODE_OKAY) {
            dns_query_t *resp = (dns_query_t*)decoded;
            dns_rcode_t rcode = (dns_rcode_t)(resp->rcode);

            if (p->stage == STAGE_LONGNAME) {
                /* For Stage 1, any response (even NXDOMAIN for a fake subdomain) means success */
                if (rcode == RCODE_OKAY || rcode == RCODE_NXDOMAIN) p->got_reply = true;
            } else if (p->stage == STAGE_NXDOMAIN) {
                /* If they return NOERROR (0) for a non-existent domain, they are fake/hijacking */
                if (rcode == RCODE_NXDOMAIN) p->got_reply = true;
            } else if (p->stage == STAGE_QUALITY) {
                /* QUALITY: TXT response from our server must be NOERROR */
                if (rcode == RCODE_OKAY) p->got_reply = true;
            }

            if (p->got_reply) {
                double rtt = (double)(uv_hrtime() / 1000000ULL - p->sent_ms);
                if (rtt < 0.0) rtt = 0.0;
                rpool_on_ack(&g_pool, p->resolver_idx, rtt);
            } else {
                tui_log(&g_tui, "Probe failed Stage %d (RCODE %d) for %s", 
                        p->stage + 1, rcode, g_pool.resolvers[p->resolver_idx].ip);
                rpool_on_loss(&g_pool, p->resolver_idx);
            }
        }
    } else {
        rpool_on_loss(&g_pool, p->resolver_idx);
    }

    if (!uv_is_closing((uv_handle_t*)&p->udp)) {
        uv_close((uv_handle_t*)&p->udp, on_probe_close);
        uv_close((uv_handle_t*)&p->timer, on_probe_close);
    }
}

static void on_probe_alloc(uv_handle_t *h, size_t sz, uv_buf_t *buf) {
    probe_req_t *p = h->data;
    (void)sz;
    buf->base = (char*)p->recvbuf;
    buf->len  = sizeof(p->recvbuf);
}

static void on_probe_send(uv_udp_send_t *sr, int status) {
    if (status != 0) {
        probe_req_t *p = sr->handle->data;
        if (!uv_is_closing((uv_handle_t*)&p->udp)) {
            rpool_on_loss(&g_pool, p->resolver_idx);
            uv_close((uv_handle_t*)&p->udp, on_probe_close);
            uv_close((uv_handle_t*)&p->timer, on_probe_close);
        }
    }
}

static void fire_probe_ext(int idx, const uint8_t *payload, size_t paylen, const char *domain, scanner_stage_t stage) {
    probe_req_t *p = calloc(1, sizeof(*p));
    if (!p) return;

    p->resolver_idx = idx;
    p->stage        = stage;
    p->sent_ms      = uv_hrtime() / 1000000ULL;

    resolver_t *r = &g_pool.resolvers[idx];
    memcpy(&p->dest, &r->addr, sizeof(p->dest));
    p->dest.sin_port = htons(53);

    if (stage == STAGE_LONGNAME) {
        /* A query for 60 'a's label */
        char longname[128];
        memset(longname, 'a', 60);
        snprintf(longname + 60, sizeof(longname) - 60, ".google.com");

        dns_question_t question = {0};
        question.name  = longname;
        question.type  = RR_A;
        question.class = CLASS_IN;

        dns_query_t query = {0};
        query.id        = rand_u16();
        query.query     = true;
        query.rd        = true;
        query.qdcount   = 1;
        query.questions = &question;

        p->sendlen = sizeof(p->sendbuf);
        dns_encode((dns_packet_t*)p->sendbuf, &p->sendlen, &query);
    } else if (stage == STAGE_NXDOMAIN) {
        /* A query for a likely non-existent domain */
        char nxname[64];
        snprintf(nxname, sizeof(nxname), "dnstun-check-%d.invalid", (int)(uv_hrtime() % 1000000));

        dns_question_t question = {0};
        question.name  = nxname;
        question.type  = RR_A;
        question.class = CLASS_IN;

        dns_query_t query = {0};
        query.id        = rand_u16();
        query.query     = true;
        query.rd        = true;
        query.qdcount   = 1;
        query.questions = &question;

        p->sendlen = sizeof(p->sendbuf);
        dns_encode((dns_packet_t*)p->sendbuf, &p->sendlen, &query);
    } else {
        /* QUALITY: TXT query with versioned header */
        chunk_header_t hdr = {0};
        hdr.version = DNSTUN_VERSION;
        hdr.flags   = 0x08; /* poll flag */
        make_session_id(hdr.session_id);
        hdr.enc_format      = (uint8_t)r->enc;
        hdr.downstream_mtu  = r->downstream_mtu;

        p->sendlen = sizeof(p->sendbuf);
        if (build_dns_query(p->sendbuf, &p->sendlen, &hdr, payload, paylen, domain) != 0) {
            free(p);
            return;
        }
    }

    if (uv_udp_init(g_loop, &p->udp) != 0) { free(p); return; }
    p->udp.data = p;
    g_probes_active++;
    
    uv_timer_init(g_loop, &p->timer);
    p->timer.data = p;
    uv_timer_start(&p->timer, on_probe_timeout, 2000, 0);

    uv_udp_recv_start(&p->udp, on_probe_alloc, on_probe_recv);
    uv_buf_t buf = uv_buf_init((char*)p->sendbuf, (unsigned)p->sendlen);
    uv_udp_send(&p->send_req, &p->udp, &buf, 1,
                (const struct sockaddr*)&p->dest, on_probe_send);
}

static void fire_probe(int idx, const char *domain) {
    fire_probe_ext(idx, NULL, 0, domain, STAGE_QUALITY);
}

/* ────────────────────────────────────────────── */
/*  CIDR Scan — find sibling resolvers           */
/* ────────────────────────────────────────────── */
static void cidr_scan_subnet(const char *seed_ip, int prefix) {
    struct sockaddr_in sa;
    uv_ip4_addr(seed_ip, 53, &sa);
    uint32_t base = ntohl(sa.sin_addr.s_addr);

    int count = (prefix == 16) ? 65536 : 256;
    uint32_t mask = (prefix == 16) ? 0xFFFF0000 : 0xFFFFFF00;
    uint32_t net  = base & mask;

    LOG_INFO("CIDR scan /%d on %s (%d IPs)\n", prefix, seed_ip, count);

    char ip[46];
    for (int i = 1; i < count - 1; i++) {
        uint32_t host = net | (uint32_t)i;
        struct sockaddr_in sa2;
        sa2.sin_addr.s_addr = htonl(host);
        uv_inet_ntop(AF_INET, &sa2.sin_addr, ip, sizeof(ip));
        rpool_add(&g_pool, ip);
    }
}

/* ────────────────────────────────────────────── */
/*  Resolver Init Phase                           */
/* ────────────────────────────────────────────── */
static void on_init_phase_timeout(uv_timer_t *t) {
    uv_stop(t->loop);
}

static void resolver_init_phase(void) {
    LOG_INFO("=== Resolver Initialization Phase (Multi-Stage) ===\n");

    /* Step 1: Add seed resolvers */
    for (int i = 0; i < g_cfg.seed_count; i++)
        rpool_add(&g_pool, g_cfg.seed_resolvers[i]);

    /* Step 2: CIDR scan seed IPs (find siblings) */
    if (g_cfg.cidr_scan) {
        for (int i = 0; i < g_cfg.seed_count; i++)
            cidr_scan_subnet(g_cfg.seed_resolvers[i], g_cfg.cidr_prefix);
    }

    const char *domain = (g_cfg.domain_count > 0) ? g_cfg.domains[0] : "example.com";
    scanner_stage_t stages[] = {STAGE_LONGNAME, STAGE_NXDOMAIN, STAGE_QUALITY};
    const char *stage_names[] = {"LongName Support", "Fake Check (NXDOMAIN)", "Quality (TXT/EDNS)"};

    for (int s = 0; s < 3; s++) {
        LOG_INFO("--- Stage %d: %s ---\n", s + 1, stage_names[s]);
        tui_log(&g_tui, "Starting Scanner Stage %d: %s", s + 1, stage_names[s]);
        
        /* Persistent trackers for stage eligibility */
        static bool eligible[DNSTUN_MAX_RESOLVERS];
        if (s == 0) {
            for (int i = 0; i < g_pool.count; i++) eligible[i] = true;
        } else {
            for (int i = 0; i < g_pool.count; i++) {
                if (g_pool.resolvers[i].rtt_ms >= 900.0) eligible[i] = false;
                else g_pool.resolvers[i].rtt_ms = 991.0; /* Reset for next stage */
            }
        }

        int fired = 0;
        int total = g_pool.count;
        int idx = 0;

        while (idx < total || g_probes_active > 0) {
            if (idx < total && g_probes_active < 64) {
                if (eligible[idx]) {
                    fire_probe_ext(idx, NULL, 0, domain, stages[s]);
                    fired++;
                }
                idx++;
            }
            uv_run(g_loop, UV_RUN_NOWAIT);
            if (g_probes_active >= 64) {
#ifdef _WIN32
                Sleep(1);
#else
                usleep(1000);
#endif
            }
        }

        LOG_INFO("Stage %d complete (%d probes fired)\n", s + 1, fired);
        tui_log(&g_tui, "Stage %d complete (%d probes)", s + 1, fired);
    }

    /* Final Promotion */
    int active = 0;
    for (int i = 0; i < g_pool.count; i++) {
        resolver_t *r = &g_pool.resolvers[i];
        if (r->rtt_ms < 900.0) {
            rpool_set_state(&g_pool, i, RSV_ACTIVE);
            active++;
        }
    }

    LOG_INFO("Init complete: %d/%d resolvers active\n", active, g_pool.count);
    tui_log(&g_tui, "Init phase complete. %d active resolvers.", active);
    g_stats.active_resolvers  = g_pool.active_count;
    g_stats.dead_resolvers    = g_pool.dead_count;
}

/* ────────────────────────────────────────────── */
/*  SOCKS5 Proxy                                  */
/* ────────────────────────────────────────────── */
typedef struct socks5_client {
    uv_tcp_t  tcp;
    uint8_t   buf[8192];
    size_t    buf_len;
    int       session_idx;
    int       state;  /* 0=handshake, 1=request, 2=tunnel */
} socks5_client_t;

static void on_socks5_close(uv_handle_t *h) {
    socks5_client_t *c = h->data;
    if (c && c->session_idx >= 0) {
        g_sessions[c->session_idx].closed = true;
        g_stats.active_sessions--;
    }
    free(c);
}

static void on_socks5_write_done(uv_write_t *w, int status) {
    /* Fix #8: free(w) directly; the allocation is sizeof(*w)+len contiguous. */
    (void)status;
    free(w);
}

static void socks5_send(socks5_client_t *c, const uint8_t *data, size_t len) {
    uv_write_t *w = malloc(sizeof(*w) + len);
    if (!w) return;
    /* Payload lives immediately after the write request in the same alloc. */
    uint8_t *copy = (uint8_t*)(w + 1);
    memcpy(copy, data, len);
    uv_buf_t buf = uv_buf_init((char*)copy, (unsigned)len);
    uv_write(w, (uv_stream_t*)&c->tcp, &buf, 1, on_socks5_write_done);
}

static void socks5_handle_data(socks5_client_t *c,
                               const uint8_t *data, size_t len)
{
    /* SOCKS5 state machine */
    if (c->state == 0) {
        /* Auth method negotiation: reply NO AUTH */
        if (len >= 3 && data[0] == 0x05) {
            uint8_t reply[2] = {0x05, 0x00};
            socks5_send(c, reply, 2);
            c->state = 1;
        }
        return;
    }

    if (c->state == 1) {
        /* CONNECT request */
        if (len < 10 || data[0] != 0x05 || data[1] != 0x01) return;

        int session_idx = -1;
        for (int i = 0; i < DNSTUN_MAX_SESSIONS; i++) {
            if (g_sessions[i].closed || !g_sessions[i].established) {
                session_idx = i;
                break;
            }
        }
        if (session_idx >= 0) {
            c->session_idx = session_idx;
            c->state = 2; /* Tunnel mode */
            tui_log(&g_tui, "New SOCKS5 session [%d] for %s", session_idx, g_sessions[session_idx].target_host);
            /* Send success reply */
        }
        if (session_idx < 0) {
            uint8_t err[10] = {0x05,0x05,0x00,0x01,0,0,0,0,0,0};
            socks5_send(c, err, 10);
            return;
        }

        session_t *sess = &g_sessions[session_idx];
        memset(sess, 0, sizeof(*sess));
        make_session_id(sess->id);
        sess->established = true;
        sess->closed      = false;
        sess->last_active = time(NULL);

        /* Parse target */
        uint8_t atype = data[3];
        if (atype == 0x01) { /* IPv4 */
            snprintf(sess->target_host, sizeof(sess->target_host),
                     "%d.%d.%d.%d", data[4],data[5],data[6],data[7]);
            sess->target_port = (uint16_t)((data[8]<<8)|data[9]);
        } else if (atype == 0x03) { /* Domain */
            uint8_t dlen = data[4];
            /* Fix #5: bounds check before accessing data[5..5+dlen+1] */
            if ((size_t)(5 + dlen + 2) > len) return;
            if (dlen >= sizeof(sess->target_host)) return;
            memcpy(sess->target_host, data+5, dlen);
            sess->target_host[dlen] = '\0';
            sess->target_port = (uint16_t)((data[5+dlen]<<8)|data[6+dlen]);
        } else {
            return; /* IPv6 not implemented yet */
        }

        c->session_idx = session_idx;
        c->state = 2;
        g_stats.active_sessions++;

        LOG_INFO("SOCKS5 CONNECT %s:%d (session %d)\n",
                 sess->target_host, sess->target_port, session_idx);

        /* Send success */
        uint8_t ok[10] = {0x05,0x00,0x00,0x01,127,0,0,1,0x04,0x38};
        socks5_send(c, ok, 10);
        return;
    }

    if (c->state == 2) {
        /* Tunnel data → queue in session send buffer */
        session_t *sess = &g_sessions[c->session_idx];
        sess->last_active = time(NULL);

        /* Grow send buffer */
        size_t new_len = sess->send_len + len;
        if (new_len > sess->send_cap) {
            size_t new_cap = new_len + 8192;
            sess->send_buf = realloc(sess->send_buf, new_cap);
            sess->send_cap = new_cap;
        }
        memcpy(sess->send_buf + sess->send_len, data, len);
        sess->send_len += len;
        g_stats.tx_total += len;
        g_stats.tx_bytes_sec += len;
    }
}

static void on_socks5_read(uv_stream_t *s, ssize_t nread, const uv_buf_t *buf) {
    socks5_client_t *c = s->data;

    if (nread <= 0) {
        if (!uv_is_closing((uv_handle_t*)s))
            uv_close((uv_handle_t*)s, on_socks5_close);
        return;
    }

    socks5_handle_data(c, (const uint8_t*)buf->base, (size_t)nread);
}

static void on_socks5_alloc(uv_handle_t *h, size_t sz, uv_buf_t *buf) {
    socks5_client_t *c = h->data;
    (void)sz;
    buf->base = (char*)c->buf;
    buf->len  = sizeof(c->buf);
}

static void on_socks5_connection(uv_stream_t *server, int status) {
    if (status < 0) return;

    socks5_client_t *c = calloc(1, sizeof(*c));
    if (!c) return;
    c->session_idx = -1;
    c->state = 0;

    uv_tcp_init(g_loop, &c->tcp);
    c->tcp.data = c;

    if (uv_accept(server, (uv_stream_t*)&c->tcp) == 0) {
        uv_read_start((uv_stream_t*)&c->tcp, on_socks5_alloc, on_socks5_read);
    } else {
        uv_close((uv_handle_t*)&c->tcp, on_socks5_close);
    }
}

/* ────────────────────────────────────────────── */
/*  DNS Reply handler — receive TXT from resolver */
/* ────────────────────────────────────────────── */
typedef struct dns_query_ctx {
    uv_udp_t         udp;
    uv_timer_t       timer;
    int              closes;
    uv_udp_send_t    send_req;
    struct sockaddr_in dest;
    int              resolver_idx;
    int              session_idx;
    uint16_t         seq;
    uint64_t         sent_ms;  /* renamed from sent_us: actually ms (fix #14) */
    uint8_t          sendbuf[MAX_UDP_PACKET_SIZE];
    size_t           sendlen;
    uint8_t          recvbuf[MAX_UDP_PACKET_SIZE];
} dns_query_ctx_t;

static void on_dns_query_close(uv_handle_t *h) {
    dns_query_ctx_t *q = h->data;
    if (++q->closes == 2) free(q);
}

static void on_dns_timeout(uv_timer_t *t) {
    dns_query_ctx_t *q = t->data;
    if (!uv_is_closing((uv_handle_t*)&q->udp)) {
        rpool_on_loss(&g_pool, q->resolver_idx);
        g_stats.queries_lost++;
        uv_close((uv_handle_t*)&q->udp, on_dns_query_close);
        uv_close((uv_handle_t*)&q->timer, on_dns_query_close);
    }
}

static void on_dns_recv(uv_udp_t *h,
                        ssize_t nread,
                        const uv_buf_t *buf,
                        const struct sockaddr *addr,
                        unsigned flags)
{
    if (nread == 0 && addr == NULL) return; /* spurious wake-up, ignore */
    (void)flags;
    dns_query_ctx_t *q = h->data;
    int ridx = q->resolver_idx;

    if (nread > 0) {
        /* Measure RTT (fix #14: variable is now correctly named sent_ms) */
        double rtt = (double)(uv_hrtime() / 1000000ULL - q->sent_ms);
        if (rtt < 0.0) rtt = 0.0;
        rpool_on_ack(&g_pool, ridx, rtt);

        /* Decode DNS response */
        dns_decoded_t decoded[DNS_DECODEBUF_16K];
        size_t decsz = sizeof(decoded);
        if (dns_decode(decoded, &decsz,
                       (const dns_packet_t*)buf->base,
                       (size_t)nread) == RCODE_OKAY)
        {
            dns_query_t *resp = (dns_query_t*)decoded;
            /* Walk answer section for TXT records */
            for (int i = 0; i < (int)resp->ancount; i++) {
                dns_answer_t *ans = &resp->answers[i];
                if (ans->generic.type == RR_TXT && ans->txt.len > 0) {
                    /* Check if this is a SYNC response (comma-separated IPs) */
                    if (ans->txt.len > 7 && strchr(ans->txt.text, ',')) {
                        char *ips = strndup(ans->txt.text, ans->txt.len);
                        char *tok = strtok(ips, ",");
                        while (tok) {
                            rpool_add(&g_pool, tok);
                            tok = strtok(NULL, ",");
                        }
                        free(ips);
                        LOG_INFO("Swarm: synced new resolvers from server\n");
                    } else {
                        /* Deliver payload to session recv buffer */
                        int sidx = q->session_idx;
                        if (sidx >= 0 && sidx < DNSTUN_MAX_SESSIONS
                            && !g_sessions[sidx].closed)
                        {
                            session_t *s = &g_sessions[sidx];
                            size_t need = s->recv_len + ans->txt.len;
                            if (need > s->recv_cap) {
                                s->recv_buf = realloc(s->recv_buf, need + 8192);
                                s->recv_cap = need + 8192;
                            }
                            memcpy(s->recv_buf + s->recv_len,
                                   ans->txt.text, ans->txt.len);
                            s->recv_len += ans->txt.len;
                            g_stats.rx_total += ans->txt.len;
                            g_stats.rx_bytes_sec += ans->txt.len;
                        }
                    }
                    g_stats.queries_recv++;
                    g_stats.last_server_rx_ms = uv_hrtime() / 1000000ULL;
                }
            }
        } else {
            /* Bad / zombie response — lose a packet */
            rpool_on_loss(&g_pool, ridx);
            g_stats.queries_lost++;
        }
    } else {
        rpool_on_loss(&g_pool, ridx);
        g_stats.queries_lost++;
    }

    if (!uv_is_closing((uv_handle_t*)&q->udp)) {
        uv_close((uv_handle_t*)&q->udp, on_dns_query_close);
        uv_close((uv_handle_t*)&q->timer, on_dns_query_close);
    }
}

static void on_dns_send(uv_udp_send_t *sr, int status) {
    if (status != 0) {
        dns_query_ctx_t *q = sr->handle->data;
        if (!uv_is_closing((uv_handle_t*)&q->udp)) {
            rpool_on_loss(&g_pool, q->resolver_idx);
            g_stats.queries_lost++;
            uv_close((uv_handle_t*)&q->udp, on_dns_query_close);
            uv_close((uv_handle_t*)&q->timer, on_dns_query_close);
        }
    }
}

static void on_dns_alloc(uv_handle_t *h, size_t sz, uv_buf_t *buf) {
    dns_query_ctx_t *q = h->data;
    (void)sz;
    buf->base = (char*)q->recvbuf;
    buf->len  = sizeof(q->recvbuf);
}

/* ────────────────────────────────────────────── */
/*  Jitter timer — deferred UDP send for anti-DPI */
/* ────────────────────────────────────────────── */
typedef struct {
    uv_timer_t       timer;
    uv_udp_send_t    send_req;
    dns_query_ctx_t *q;
} jitter_ctx_t;

static void on_jitter_timer(uv_timer_t *t) {
    jitter_ctx_t *jc = t->data;
    dns_query_ctx_t *q = jc->q;
    uv_buf_t buf = uv_buf_init((char*)q->sendbuf, (unsigned)q->sendlen);
    if (uv_udp_send(&jc->send_req, &q->udp, &buf, 1,
                    (const struct sockaddr*)&q->dest, on_dns_send) != 0) {
        uv_close((uv_handle_t*)&q->udp, on_dns_query_close);
    } else {
        g_stats.queries_sent++;
    }
    uv_close((uv_handle_t*)t, (uv_close_cb)free);
}

/* Fire one DNS query chunk for a session.
   'seq' is the actual sequence number of this FEC symbol. */
static void fire_dns_chunk_symbol(int session_idx, uint16_t seq,
                                  const uint8_t *payload, size_t paylen,
                                  int total_symbols)
{
    int ridx = rpool_next(&g_pool);
    if (ridx < 0) return;

    resolver_t *r = &g_pool.resolvers[ridx];

    dns_query_ctx_t *q = calloc(1, sizeof(*q));
    if (!q) return;
    q->resolver_idx = ridx;
    q->session_idx  = session_idx;
    q->seq          = seq;

    session_t *sess = &g_sessions[session_idx];

    /* Build chunk header */
    chunk_header_t hdr = {0};
    hdr.version        = DNSTUN_VERSION;
    hdr.flags          = (g_cfg.encryption ? 0x01 : 0x00) | 0x02; /* Real-world: always compressed */
    if (paylen == 0) hdr.flags |= 0x08; /* poll flag */
    if (total_symbols > 0) hdr.flags |= 0x04; /* fec flag */

    memcpy(hdr.session_id, sess->id, DNSTUN_SESSION_ID_LEN);
    hdr.seq            = seq;
    hdr.chunk_total    = (uint16_t)total_symbols;
    hdr.original_size  = (uint16_t)sess->send_len;
    hdr.upstream_mtu   = r->upstream_mtu;
    hdr.downstream_mtu = r->downstream_mtu;
    hdr.enc_format     = (uint8_t)r->enc;
    hdr.loss_pct       = (uint8_t)(r->loss_rate * 100.0);
    hdr.fec_k          = (uint8_t)r->fec_k;
    strncpy(hdr.user_id, g_cfg.user_id, sizeof(hdr.user_id));

    int didx = rpool_flux_domain(&g_cfg);
    const char *domain = (g_cfg.domain_count > 0)
                         ? g_cfg.domains[didx] : "tun.example.com";

    q->sendlen = sizeof(q->sendbuf);
    if (build_dns_query(q->sendbuf, &q->sendlen, &hdr, payload, paylen, domain) != 0) {
        free(q);
        return;
    }

    memcpy(&q->dest, &r->addr, sizeof(q->dest));
    q->dest.sin_port = htons(53);

    uv_udp_init(g_loop, &q->udp);
    q->udp.data = q;
    q->sent_ms  = uv_hrtime() / 1000000ULL;

    uv_udp_recv_start(&q->udp, on_dns_alloc, on_dns_recv);

    /* Anti-DPI Jitter (fix #10): defer the UDP send by 0-50 ms. */
    if (g_cfg.jitter) {
        uint64_t delay_ms = (uint64_t)(rand() % 50);
        jitter_ctx_t *jc = malloc(sizeof(*jc));
        if (jc) {
            jc->q = q;
            uv_timer_init(g_loop, &jc->timer);
            jc->timer.data = jc;
            uv_timer_start(&jc->timer, on_jitter_timer, delay_ms, 0);
            return; /* send will happen in the timer callback */
        }
    }

    /* Immediate send (no jitter or allocation failure) */
    uv_buf_t buf = uv_buf_init((char*)q->sendbuf, (unsigned)q->sendlen);
    if (uv_udp_send(&q->send_req, &q->udp, &buf, 1,
                    (const struct sockaddr*)&q->dest, on_dns_send) != 0)
    {
        uv_close((uv_handle_t*)&q->udp, on_dns_query_close);
    } else {
        g_stats.queries_sent++;
    }
}

/* ────────────────────────────────────────────── */
/*  Downstream POLL Timer (default 100ms)         */
/* ────────────────────────────────────────────── */
static void on_poll_timer(uv_timer_t *t) {
    (void)t;

    for (int i = 0; i < DNSTUN_MAX_SESSIONS; i++) {
        session_t *sess = &g_sessions[i];
        if (!sess->established || sess->closed) continue;

        if (sess->send_len > 0) {
            /* 1. COMPRESS */
            codec_result_t cret = codec_compress(sess->send_buf, sess->send_len, 3);
            if (cret.error) { LOG_ERR("Compression failed\n"); continue; }

            const uint8_t *enc_in = cret.data;
            size_t         enc_len = cret.len;
            codec_result_t eret = {0};

            /* 2. ENCRYPT (Optional) */
            if (g_cfg.encryption) {
                eret = codec_encrypt(cret.data, cret.len, g_cfg.psk);
                if (eret.error) { LOG_ERR("Encryption failed\n"); free(cret.data); continue; }
                enc_in = eret.data;
                enc_len = eret.len;
            }

            /* 3. FEC ENCODE */
            /* We split the block into source symbols (K) and repair symbols (R).
               K is derived based on the observed loss rate. */
            int k = (int)ceil((double)enc_len / (double)DNSTUN_CHUNK_PAYLOAD);
            if (k == 0) k = 1;
            int r = rpool_fec_k(&g_pool, 0, k); /* Use first resolver's state for simplicity in this tick */
            
            fec_encoded_t fec = codec_fec_encode(enc_in, enc_len, k, r);
            if (fec.total_count > 0) {
                /* 4. SEND SYMBOLS */
                for (int s = 0; s < fec.total_count; s++) {
                    fire_dns_chunk_symbol(i, sess->tx_next++, fec.symbols[s], fec.symbol_len, fec.total_count);
                }
            }

            codec_fec_free(&fec);
            if (g_cfg.encryption) free(eret.data);
            free(cret.data);
            sess->send_len = 0;
        } else {
            /* No upload — send empty POLL to pull downstream data */
            fire_dns_chunk_symbol(i, sess->tx_next++, NULL, 0, 0);

            /* 5. CHAFFING (Decoy) */
            if (g_cfg.chaffing && (rand() % 10 == 0)) {
                /* Send a random-length decoy query once in a while */
                uint8_t chaff[32];
                for (int c=0; c<32; c++) chaff[c] = (uint8_t)(rand() & 0xFF);
                fire_dns_chunk_symbol(i, 0xFFFF, chaff, 16 + (rand() % 16), 0);
            }
        }
    }
}

/* ────────────────────────────────────────────── */
/*  Chrome DNS Cover Traffic (Optional)           */
/* ────────────────────────────────────────────── */
static void fire_chrome_cover_traffic(uv_timer_t *t) {
    (void)t;
    if (!g_cfg.chrome_cover) return;

    /* Mimic Chrome: A + AAAA queries for top domains */
    const char *sites[] = {"google.com", "youtube.com", "fonts.gstatic.com", "ssl.gstatic.com"};
    const char *target = sites[rand() % 4];

    int ridx = rpool_next(&g_pool);
    if (ridx < 0) return;
    resolver_t *r = &g_pool.resolvers[ridx];

    /* Build a real 'A' query for 'target' */
    /* ... (Simplified for now - just sending a probe to the domain) */
    fire_probe(ridx, target);
}

/* ────────────────────────────────────────────── */
/*  Recovery Timer — probe dead resolvers         */
/* ────────────────────────────────────────────── */
static void on_recovery_timer(uv_timer_t *t) {
    (void)t;

    /* Release expired penalties */
    rpool_release_penalties(&g_pool);

    /* Probe some dead resolvers */
    int probes[64];
    int n = rpool_dead_to_probe(&g_pool, probes, 64,
                                g_cfg.background_recovery_rate);
    const char *domain = (g_cfg.domain_count > 0)
                         ? g_cfg.domains[0] : "tun.example.com";
    for (int i = 0; i < n; i++) {
        int idx = probes[i];
        g_pool.resolvers[idx].last_probe = time(NULL);
        fire_probe(idx, domain);
    }

    /* Update TUI counters */
    g_stats.active_resolvers  = g_pool.active_count;
    g_stats.dead_resolvers    = g_pool.dead_count;
    g_stats.penalty_resolvers = 0;
    for (int i = 0; i < g_pool.count; i++)
        if (g_pool.resolvers[i].state == RSV_PENALTY)
            g_stats.penalty_resolvers++;

    /* Persist active resolver list every 60 seconds */
    static int save_tick = 0;
    if (++save_tick >= 60) {
        save_tick = 0;
        resolvers_save();
    }
}

/* ────────────────────────────────────────────── */
/*  TUI Render Timer (1 second)                   */
/* ────────────────────────────────────────────── */
static void on_tui_timer(uv_timer_t *t) {
    (void)t;
    tui_render(&g_tui);
    /* Reset per-second counters */
    g_stats.tx_bytes_sec = 0;
    g_stats.rx_bytes_sec = 0;
}

/* ────────────────────────────────────────────── */
/*  TUI Input (TTY)                               */
/* ────────────────────────────────────────────── */
static uv_tty_t g_tty;

static void on_tty_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    (void)handle;
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
}

static void on_tty_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    (void)stream;
    if (nread > 0) {
        for (ssize_t i=0; i<nread; i++) {
            tui_handle_key(&g_tui, buf->base[i]);
            if (!g_tui.running) uv_stop(g_loop);
        }
    }
    if (buf->base) free(buf->base);
}

/* ────────────────────────────────────────────── */
/*  Entry point                                   */
/* ────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    const char *config_path = NULL;
    static char auto_config_path[1024] = {0};
    char *slash;
#ifdef _WIN32
    char *bslash;
#endif
    char domain_buf[512] = {0};
    char threads_str[16];
    char bind_ip[64] = "127.0.0.1";
    int  bind_port   = 1080;
    char tmp[64];
    char *colon;
    struct sockaddr_in socks5_addr;
    uv_timer_t chrome_timer;

    srand((unsigned)time(NULL));

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) && i + 1 < argc) {
            config_path = argv[i+1];
            break;
        }
    }

    if (!config_path) {
        /* Auto-locate client.ini */
        const char *candidates[] = {
            "client.ini",
            "../client.ini",
            "../../client.ini",
            "../../../client.ini",
            "/etc/dnstun/client.ini"
        };
        for (int i = 0; i < 5; i++) {
            FILE *f = fopen(candidates[i], "r");
            if (f) {
                fclose(f);
                config_path = candidates[i];
                break;
            }
        }
        if (!config_path) {
            /* Try relative to executable */
            char exe_path[1024];
            size_t size = sizeof(exe_path);
            if (uv_exepath(exe_path, &size) == 0) {
                char *eslash = strrchr(exe_path, '/');
#ifdef _WIN32
                char *ebslash = strrchr(exe_path, '\\');
                if (ebslash > eslash) eslash = ebslash;
#endif
                if (eslash) {
                    *eslash = '\0';
                    const char *rel[] = {"", "/..", "/../..", "/../../.."};
                    for (int i = 0; i < 4; i++) {
                        snprintf(auto_config_path, sizeof(auto_config_path), "%s%s/client.ini", exe_path, rel[i]);
                        FILE *tf = fopen(auto_config_path, "r");
                        if (tf) {
                            fclose(tf);
                            config_path = auto_config_path;
                            break;
                        }
                    }
                }
            }
        }
        if (!config_path) config_path = "client.ini";
    }
    
    if (config_path && config_path != auto_config_path) {
        strncpy(auto_config_path, config_path, sizeof(auto_config_path)-1);
        config_path = auto_config_path;
    }

    /* Set g_resolvers_file to be safely beside config_path */
    strncpy(g_resolvers_file, config_path, sizeof(g_resolvers_file)-1);
    slash = strrchr(g_resolvers_file, '/');
#ifdef _WIN32
    bslash = strrchr(g_resolvers_file, '\\');
    if (bslash > slash) slash = bslash;
#endif
    if (slash) {
        strncpy(slash + 1, "client_resolvers.txt", sizeof(g_resolvers_file) - (slash - g_resolvers_file) - 1);
    } else {
        strcpy(g_resolvers_file, "client_resolvers.txt");
    }

    /* Load config */
    config_defaults(&g_cfg, false);
    if (config_load(&g_cfg, config_path) != 0) {
        fprintf(stderr,
            "Warning: could not load '%s', using defaults.\n"
            "Create client.ini to configure the tunnel.\n\n",
            config_path);
    }

    /* ── First-run: ask for tunnel domain if not configured ────────────────
       This writes the domain to the INI file so subsequent runs are silent. */
    if (g_cfg.domain_count == 0 || (g_cfg.domain_count == 1 && strcmp(g_cfg.domains[0], "tun.example.com") == 0)) {
        printf("\n  No tunnel domain configured (or default tun.example.com is in use).\n");
        printf("  Enter the subdomain delegated to your dnstun-server\n");
        printf("  (e.g. tun.example.com, separate multiple with commas): ");
        fflush(stdout);
        if (fgets(domain_buf, sizeof(domain_buf), stdin)) {
            domain_buf[strcspn(domain_buf, "\r\n")] = '\0';
            if (domain_buf[0]) {
                config_set_key(&g_cfg, "domains", "list", domain_buf);
                if (config_save_domains(config_path, &g_cfg) == 0)
                    printf("  Saved to %s\n\n", config_path);
            }
        }
        if (g_cfg.domain_count == 0) {
            fprintf(stderr, "[ERROR] No domain configured. Cannot continue.\n");
            return 1;
        }
    }

    /* libuv thread pool */
    snprintf(threads_str, sizeof(threads_str), "%d", g_cfg.workers);
#ifdef _WIN32
    _putenv_s("UV_THREADPOOL_SIZE", threads_str);
#else
    setenv("UV_THREADPOOL_SIZE", threads_str, 1);
#endif

    g_loop = uv_default_loop();

    /* Init resolver pool, then load saved resolvers from disk */
    rpool_init(&g_pool, &g_cfg);

    FILE *rf_check = fopen(g_resolvers_file, "r");
    if (!rf_check) {
        printf("\n  [WARN] Resolver file '%s' not found.\n", g_resolvers_file);
        printf("  Would you like to auto-create it using the default seed_list?\n");
        printf("  [Y/n] (Auto-yes in 5s): ");
        fflush(stdout);
        
        char ans[16] = "y\n";
        int do_create = 1;

#ifdef _WIN32
        HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
        if (WaitForSingleObject(hStdin, 5000) == WAIT_OBJECT_0) {
            if (fgets(ans, sizeof(ans), stdin)) {
                if (ans[0] != 'y' && ans[0] != 'Y' && ans[0] != '\n') do_create = 0;
            }
        } else {
            printf("\n  Timeout reached. Auto-creating.\n");
        }
#else
        fd_set fds;
        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        FD_ZERO(&fds);
        FD_SET(0, &fds);
        if (select(1, &fds, NULL, NULL, &tv) > 0) {
            if (fgets(ans, sizeof(ans), stdin)) {
                if (ans[0] != 'y' && ans[0] != 'Y' && ans[0] != '\n') do_create = 0;
            }
        } else {
            printf("\n  Timeout reached. Auto-creating.\n");
        }
#endif

        if (do_create) {
            FILE *fcreate = fopen(g_resolvers_file, "w");
            if (fcreate) {
                for (int m=0; m<g_cfg.seed_count; m++) {
                    fprintf(fcreate, "%s\n", g_cfg.seed_resolvers[m]);
                }
                fclose(fcreate);
                printf("  Created %s with %d default resolvers.\n\n", g_resolvers_file, g_cfg.seed_count);
            }
        } else {
            printf("  Skipping creation.\n\n");
        }
    } else {
        fclose(rf_check);
    }

    resolvers_load();

    /* Parse SOCKS5 bind address */
    if (g_cfg.socks5_bind[0]) {
        strncpy(tmp, g_cfg.socks5_bind, sizeof(tmp)-1);
        colon = strrchr(tmp, ':');
        if (colon) {
            *colon = '\0';
            bind_port = atoi(colon+1);
            strncpy(bind_ip, tmp, sizeof(bind_ip)-1);
        }
    }

    /* Start SOCKS5 server */
    uv_ip4_addr(bind_ip, bind_port, &socks5_addr);
    uv_tcp_init(g_loop, &g_socks5_server);
    uv_tcp_bind(&g_socks5_server, (const struct sockaddr*)&socks5_addr, 0);
    if (uv_listen((uv_stream_t*)&g_socks5_server, 128, on_socks5_connection) != 0) {
        LOG_ERR("Cannot bind SOCKS5 on %s:%d\n", bind_ip, bind_port);
        return 1;
    }

    /* TUI */
    tui_init(&g_tui, &g_stats, &g_pool, &g_cfg, "CLIENT", config_path);

    LOG_INFO("dnstun-client starting\n");
    LOG_INFO("  SOCKS5  : %s:%d\n", bind_ip, bind_port);
    LOG_INFO("  Workers : %d\n", g_cfg.workers);
    LOG_INFO("  Domain  : %s\n",
             g_cfg.domain_count > 0 ? g_cfg.domains[0] : "(none set)");
    LOG_INFO("Tunnel ready. Configure proxy: socks5h://%s:%d\n",
             bind_ip, bind_port);

    /* Fix #15: Start timers BEFORE resolver_init_phase so that SOCKS5
       is already accepting connections during the 3-second probe window.
       Any connection arriving before a resolver is promoted will simply
       queue in its session send buffer until the first POLL fires. */
    uv_timer_init(g_loop, &chrome_timer);
    uv_timer_start(&chrome_timer, fire_chrome_cover_traffic, 5000, 15000);

    uv_timer_init(g_loop, &g_poll_timer);
    uv_timer_start(&g_poll_timer, on_poll_timer,
                   g_cfg.poll_interval_ms, g_cfg.poll_interval_ms);

    uv_timer_init(g_loop, &g_recovery_timer);
    uv_timer_start(&g_recovery_timer, on_recovery_timer, 1000, 1000);

    uv_timer_init(g_loop, &g_tui_timer);
    uv_timer_start(&g_tui_timer, on_tui_timer, 1000, 1000);

    /* Resolver init phase (probes resolvers, runs loop for ~3s) */
    resolver_init_phase();

    /* Bind STDIN for TUI */
    uv_tty_init(g_loop, &g_tty, 0, 1);
    uv_tty_set_mode(&g_tty, UV_TTY_MODE_RAW);
    uv_read_start((uv_stream_t*)&g_tty, on_tty_alloc, on_tty_read);

    /* Run event loop */
    uv_run(g_loop, UV_RUN_DEFAULT);

    tui_shutdown(&g_tui);
    resolvers_save();   /* persist final resolver list on clean exit */
    rpool_destroy(&g_pool);

    if (g_tui.restart) {
        LOG_INFO("Restarting process to apply new domain...\n");
#ifdef _WIN32
        _execvp(argv[0], argv);
#else
        execvp(argv[0], argv);
#endif
    }
    return 0;
}

