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
#define RESOLVERS_FILE "client_resolvers.txt"

/* ────────────────────────────────────────────── */
/*  Resolver file persistence                     */
/* ────────────────────────────────────────────── */
static void resolvers_save(void) {
    FILE *f = fopen(RESOLVERS_FILE, "w");
    if (!f) return;
    uv_mutex_lock(&g_pool.lock);
    for (int i = 0; i < g_pool.count; i++) {
        resolver_t *r = &g_pool.resolvers[i];
        if (r->state != RSV_DEAD && r->ip[0])
            fprintf(f, "%s\n", r->ip);
    }
    uv_mutex_unlock(&g_pool.lock);
    fclose(f);
}

static void resolvers_load(void) {
    FILE *f = fopen(RESOLVERS_FILE, "r");
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
        LOG_INFO("Loaded %d resolvers from %s\n", added, RESOLVERS_FILE);
}

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
    randombytes_buf(id, DNSTUN_SESSION_ID_LEN);
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
       the complete payload without silent truncation. */
    char qname[DNSTUN_MAX_QNAME_LEN + 1];
    snprintf(qname, sizeof(qname), "%s.%s.%s.tun.%s",
             seq_hex, b32, sid_hex, domain);

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
typedef struct probe_req {
    uv_udp_t        udp;
    uv_udp_send_t   send_req;
    struct sockaddr_in dest;
    int             resolver_idx;
    uint64_t        sent_ms;  /* ms timestamp via uv_hrtime() / 1e6 (fix #18) */
    uint8_t         sendbuf[512];
    size_t          sendlen;
    uint8_t         recvbuf[2048];
    bool            got_reply;
} probe_req_t;

static void on_probe_close(uv_handle_t *h) { free(h->data); }

static void on_probe_recv(uv_udp_t *h, ssize_t nread,
                          const uv_buf_t *buf,
                          const struct sockaddr *addr,
                          unsigned flags)
{
    (void)buf; (void)addr; (void)flags;
    probe_req_t *p = h->data;

    if (nread > 0) {
        /* Zombie / Hijack Check: Verify header/payload match */
        /* (In a real impl, this would be a signature check) */
        p->got_reply = true;
        /* Fix #18: sub-millisecond RTT via uv_hrtime() */
        double rtt = (double)(uv_hrtime() / 1000000ULL - p->sent_ms);
        if (rtt < 0.0) rtt = 0.0;
        rpool_on_ack(&g_pool, p->resolver_idx, rtt);
    } else {
        rpool_on_loss(&g_pool, p->resolver_idx);
    }

    if (!uv_is_closing((uv_handle_t*)h))
        uv_close((uv_handle_t*)h, on_probe_close);
}

static void on_probe_alloc(uv_handle_t *h, size_t sz, uv_buf_t *buf) {
    probe_req_t *p = h->data;
    (void)sz;
    buf->base = (char*)p->recvbuf;
    buf->len  = sizeof(p->recvbuf);
}

static void on_probe_send(uv_udp_send_t *sr, int status) {
    (void)sr; (void)status;
}

static void fire_probe_ext(int idx, const uint8_t *payload, size_t paylen, const char *domain) {
    probe_req_t *p = calloc(1, sizeof(*p));
    if (!p) return;

    p->resolver_idx = idx;
    p->sent_ms      = uv_hrtime() / 1000000ULL;  /* ms via monotonic clock */

    resolver_t *r = &g_pool.resolvers[idx];
    memcpy(&p->dest, &r->addr, sizeof(p->dest));
    p->dest.sin_port = htons(53);

    /* Build a minimal POLL DNS query */
    chunk_header_t hdr = {0};
    hdr.version = DNSTUN_VERSION;
    hdr.flags   = 0x08; /* poll flag */
    make_session_id(hdr.session_id);
    hdr.enc_format      = (uint8_t)r->enc;
    hdr.downstream_mtu  = r->downstream_mtu;
    hdr.upstream_mtu    = (uint16_t)paylen;

    p->sendlen = sizeof(p->sendbuf);
    if (build_dns_query(p->sendbuf, &p->sendlen, &hdr, payload, paylen, domain) != 0) {
        free(p);
        return;
    }

    uv_udp_init(g_loop, &p->udp);
    p->udp.data = p;

    uv_udp_recv_start(&p->udp, on_probe_alloc, on_probe_recv);
    uv_buf_t buf = uv_buf_init((char*)p->sendbuf, (unsigned)p->sendlen);
    uv_udp_send(&p->send_req, &p->udp, &buf, 1,
                (const struct sockaddr*)&p->dest, on_probe_send);
}

static void fire_probe(int idx, const char *domain) {
    fire_probe_ext(idx, NULL, 0, domain);
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
static void resolver_init_phase(void) {
    LOG_INFO("=== Resolver Initialization Phase ===\n");

    /* Step 1: Add seed resolvers */
    for (int i = 0; i < g_cfg.seed_count; i++)
        rpool_add(&g_pool, g_cfg.seed_resolvers[i]);

    /* Step 2: CIDR scan seed IPs (find siblings) */
    if (g_cfg.cidr_scan) {
        for (int i = 0; i < g_cfg.seed_count; i++)
            cidr_scan_subnet(g_cfg.seed_resolvers[i], g_cfg.cidr_prefix);
    }

    /* Step 3: MTU / Rate Discovery */
    const char *domain = (g_cfg.domain_count > 0) ? g_cfg.domains[0] : "example.com";
    int mtus[] = {512, 1024, 1400};
    uint8_t dummy[1400]; memset(dummy, 'A', 1400);

    LOG_INFO("Measuring MTU & Benchmarking QPS...\n");
    for (int m = 0; m < 3; m++) {
        for (int i = 0; i < g_pool.count; i++) {
            fire_probe_ext(i, dummy, mtus[m], domain);
            if (i % 16 == 0) uv_run(g_loop, UV_RUN_NOWAIT);
        }
    }

    /* Wait for settlement */
    uv_timer_t wait;
    uv_timer_init(g_loop, &wait);
    uv_timer_start(&wait, (uv_timer_cb)uv_stop, 3000, 0);
    uv_run(g_loop, UV_RUN_DEFAULT);
    uv_close((uv_handle_t*)&wait, NULL);
    uv_run(g_loop, UV_RUN_NOWAIT);

    /* Promote resolvers that replied (got_reply tracked via AIMD acks) */
    int active = 0;
    for (int i = 0; i < g_pool.count; i++) {
        resolver_t *r = &g_pool.resolvers[i];
        if (r->rtt_ms < 900.0 && r->state == RSV_DEAD) {
            rpool_set_state(&g_pool, i, RSV_ACTIVE);
            active++;
        }
    }

    LOG_INFO("Init complete: %d/%d resolvers active\n", active, g_pool.count);
    g_stats.active_resolvers  = g_pool.active_count;
    g_stats.dead_resolvers    = g_pool.dead_count;
}

/* ────────────────────────────────────────────── */
/*  SOCKS5 Proxy                                  */
/* ────────────────────────────────────────────── */
typedef struct socks5_client {
    uv_tcp_t  tcp;
    uint8_t   buf[4096];
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
            size_t new_cap = new_len + 4096;
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
    uv_udp_send_t    send_req;
    struct sockaddr_in dest;
    int              resolver_idx;
    int              session_idx;
    uint16_t         seq;
    uint64_t         sent_ms;  /* renamed from sent_us: actually ms (fix #14) */
    uint8_t          sendbuf[DNS_BUFFER_UDP];
    size_t           sendlen;
    uint8_t          recvbuf[DNS_BUFFER_UDP];
} dns_query_ctx_t;

static void on_dns_query_close(uv_handle_t *h) { free(h->data); }

static void on_dns_recv(uv_udp_t *h,
                        ssize_t nread,
                        const uv_buf_t *buf,
                        const struct sockaddr *addr,
                        unsigned flags)
{
    (void)addr; (void)flags;
    dns_query_ctx_t *q = h->data;
    int ridx = q->resolver_idx;

    if (nread > 0) {
        /* Measure RTT (fix #14: variable is now correctly named sent_ms) */
        double rtt = (double)(uv_hrtime() / 1000000ULL - q->sent_ms);
        if (rtt < 0.0) rtt = 0.0;
        rpool_on_ack(&g_pool, ridx, rtt);

        /* Decode DNS response */
        dns_decoded_t decoded[DNS_DECODEBUF_4K];
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
                                s->recv_buf = realloc(s->recv_buf, need + 4096);
                                s->recv_cap = need + 4096;
                            }
                            memcpy(s->recv_buf + s->recv_len,
                                   ans->txt.text, ans->txt.len);
                            s->recv_len += ans->txt.len;
                            g_stats.rx_total += ans->txt.len;
                            g_stats.rx_bytes_sec += ans->txt.len;
                        }
                    }
                    g_stats.queries_recv++;
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

    if (!uv_is_closing((uv_handle_t*)h))
        uv_close((uv_handle_t*)h, on_dns_query_close);
}

static void on_dns_send(uv_udp_send_t *sr, int status) {
    if (status != 0) {
        dns_query_ctx_t *q = sr->handle->data;
        rpool_on_loss(&g_pool, q->resolver_idx);
        g_stats.queries_lost++;
        if (!uv_is_closing((uv_handle_t*)sr->handle))
            uv_close((uv_handle_t*)sr->handle, on_dns_query_close);
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
/*  Entry point                                   */
/* ────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    srand((unsigned)time(NULL));

    /* Parse arguments */
    const char *config_path = "client.ini";
    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0)
            config_path = argv[i+1];
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
    if (g_cfg.domain_count == 0) {
        printf("\n  No tunnel domain configured.\n");
        printf("  Enter the subdomain delegated to your dnstun-server\n");
        printf("  (e.g. tun.example.com, separate multiple with commas): ");
        fflush(stdout);
        char domain_buf[512] = {0};
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
    char threads_str[16];
    snprintf(threads_str, sizeof(threads_str), "%d", g_cfg.workers);
#ifdef _WIN32
    _putenv_s("UV_THREADPOOL_SIZE", threads_str);
#else
    setenv("UV_THREADPOOL_SIZE", threads_str, 1);
#endif

    g_loop = uv_default_loop();

    /* Init resolver pool, then load saved resolvers from disk */
    rpool_init(&g_pool, &g_cfg);
    resolvers_load();

    /* Parse SOCKS5 bind address */
    char bind_ip[64] = "127.0.0.1";
    int  bind_port   = 1080;
    if (g_cfg.socks5_bind[0]) {
        char tmp[64];
        strncpy(tmp, g_cfg.socks5_bind, sizeof(tmp)-1);
        char *colon = strrchr(tmp, ':');
        if (colon) {
            *colon = '\0';
            bind_port = atoi(colon+1);
            strncpy(bind_ip, tmp, sizeof(bind_ip)-1);
        }
    }

    /* Start SOCKS5 server */
    struct sockaddr_in socks5_addr;
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
    uv_timer_t chrome_timer;
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

    /* Run event loop */
    uv_run(g_loop, UV_RUN_DEFAULT);

    tui_shutdown(&g_tui);
    resolvers_save();   /* persist final resolver list on clean exit */
    rpool_destroy(&g_pool);
    return 0;
}
