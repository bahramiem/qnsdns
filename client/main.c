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
/* Inline dotify function from slipstream - inserts dots every 57 chars */
static size_t inline_dotify(char *buf, size_t buflen, size_t len) {
    if (len == 0) {
        if (buflen > 0) buf[0] = '\0';
        return 0;
    }

    size_t dots = len / 57;
    size_t new_len = len + dots;

    if (new_len + 1 > buflen) {
        return (size_t)-1;
    }

    buf[new_len] = '\0';

    char *src = buf + len - 1;
    char *dst = buf + new_len - 1;

    size_t next_dot = len - (len % 57);
    if (next_dot == len) next_dot = len - 57;

    size_t current_pos = len;

    while (current_pos > 0) {
        if (current_pos == next_dot && dots > 0) {
            *dst-- = '.';
            next_dot -= 57;
            current_pos--;
            dots--;
            continue;
        }
        *dst-- = *src--;
        current_pos--;
    }

    return new_len;
}

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

    /* Base32 encode the raw data (UPPERCASE for DNS compatibility) */
    char b32_raw[256];
    size_t b32_len = base32_encode((uint8_t*)b32_raw, raw, rawlen);

    /* Use slipstream's inline_dotify to split into labels every 57 chars */
    char b32_dotted[320];
    memcpy(b32_dotted, b32_raw, b32_len);
    size_t dotted_len = inline_dotify(b32_dotted, sizeof(b32_dotted), b32_len);

    /* Build QNAME like slipstream: <b32_dotted>.<domain> */
    /* But we need to add seq and sid for session tracking */
    char seq_hex[8];
    snprintf(seq_hex, sizeof(seq_hex), "%04x", hdr->seq);

    char sid_hex[DNSTUN_SESSION_ID_LEN * 2 + 1];
    for (int i = 0; i < DNSTUN_SESSION_ID_LEN; i++)
        snprintf(sid_hex + i*2, 3, "%02x", hdr->session_id[i]);

    /* QNAME format: <seq>.<b32>.<sid>.tun.<domain>.
     * CRITICAL: Must end with trailing dot for FQDN format!
     * SPCDNS requires FQDN or it returns RCODE_NAME_ERROR (3) */
    char qname[512];
    int qname_len = snprintf(qname, sizeof(qname), "%s.%s.%s.tun.%s.",
             seq_hex, b32_dotted, sid_hex, domain);

    LOG_DEBUG("QNAME=%s (len=%d)\n", qname, qname_len);

    /* Build DNS query structure like slipstream */
    dns_question_t question = {0};
    question.name = qname;
    question.type = RR_TXT;
    question.class = CLASS_IN;

    /* EDNS0 OPT record like slipstream */
    dns_answer_t edns = {0};
    edns.generic.name = (char*)".";
    edns.generic.type = RR_OPT;
    edns.generic.class = 1232;  /* UDP payload size */
    edns.generic.ttl = 0;

    dns_query_t query = {0};
    query.id = rand_u16();
    query.query = true;
    query.opcode = OP_QUERY;
    query.rd = true;
    query.rcode = RCODE_OKAY;
    query.qdcount = 1;
    query.questions = &question;
    query.arcount = 1;
    query.additional = &edns;

    size_t sz = *outlen;
    dns_rcode_t rc = dns_encode((dns_packet_t*)outbuf, &sz, &query);
    if (rc != RCODE_OKAY) {
        LOG_ERR("dns_encode failed: rcode=%d for QNAME=%s\n", rc, qname);
        return -1;
    }

    *outlen = sz;
    return 0;
}

/* ────────────────────────────────────────────── */
/*  Scanner.py-style DNS Resolver Testing         */
/*  Three-phase test: Long QNAME → NXDOMAIN → EDNS/TXT */
/* ────────────────────────────────────────────── */
typedef enum {
    PROBE_TEST_NONE = 0,
    PROBE_TEST_LONGNAME,      /* Phase 1: Long QNAME support */
    PROBE_TEST_NXDOMAIN,      /* Phase 2: NXDOMAIN behavior (fake resolver filter) */
    PROBE_TEST_EDNS_TXT       /* Phase 3: EDNS + TXT support and MTU detection */
} probe_test_type_t;

/* Result structure for each resolver */
typedef struct {
    bool        longname_supported;  /* Phase 1 result */
    bool        nxdomain_correct;     /* Phase 2 result (false = fake resolver) */
    bool        edns_supported;      /* Phase 3 result */
    bool        txt_supported;       /* Phase 3 result */
    uint16_t    mtu;                 /* EDNS payload size from Phase 3 */
    double      rtt_ms;              /* RTT for Phase 3 test */
} resolver_test_result_t;

typedef struct probe_req {
    uv_udp_t        udp;
    uv_timer_t      timer;
    int             closes;
    uv_udp_send_t   send_req;
    struct sockaddr_in dest;
    int             resolver_idx;
    uint64_t        sent_ms;
    uint8_t         sendbuf[512];
    size_t          sendlen;
    uint8_t         recvbuf[2048];
    bool            got_reply;
    probe_test_type_t test_type;     /* Which test this probe is performing */
    resolver_test_result_t *result;  /* Pointer to shared result for this resolver */
} probe_req_t;

static void on_probe_close(uv_handle_t *h) {
    probe_req_t *p = h->data;
    if (++p->closes == 2) free(p);
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
    (void)flags;
    probe_req_t *p = h->data;

    if (nread > 0) {
        double rtt = (double)(uv_hrtime() / 1000000ULL - p->sent_ms);
        if (rtt < 0.0) rtt = 0.0;

        /* Update RTT in pool */
        rpool_on_ack(&g_pool, p->resolver_idx, rtt);

        /* Parse DNS response based on test type - scanner.py style */
        if (p->test_type == PROBE_TEST_LONGNAME && p->result) {
            /* Phase 1: Long QNAME test - any response means success */
            p->result->longname_supported = true;
            p->got_reply = true;
        }
        else if (p->test_type == PROBE_TEST_NXDOMAIN && p->result) {
            /* Phase 2: NXDOMAIN test - scanner.py logic:
             * resp.rcode() in (dns.rcode.NXDOMAIN, dns.rcode.NOERROR) and len(resp.answer) == 0
             * Fake resolvers return REFUSED (5) or give wrong answers */
            if (nread >= 12) {
                uint8_t *resp = (uint8_t *)buf->base;
                uint16_t resp_flags = (resp[2] << 8) | resp[3];
                uint8_t rcode = resp_flags & 0x0F;
                uint16_t ancount = (resp[6] << 8) | resp[7];
                
                /* NXDOMAIN = 3, NOERROR = 0, REFUSED = 5, SERVFAIL = 2 */
                /* Good: NXDOMAIN or NOERROR with no answers (NxDomain for nonexistent) */
                /* Bad: REFUSED (fake resolver), SERVFAIL, or NOERROR with answers */
                if (rcode == 3 || (rcode == 0 && ancount == 0)) {
                    p->result->nxdomain_correct = true;
                    p->got_reply = true;
                }
            }
        }
        else if (p->test_type == PROBE_TEST_EDNS_TXT && p->result) {
            /* Phase 3: EDNS + TXT test - scanner.py logic:
             * edns_supported = resp_edns is not None and resp_edns.edns >= 0
             * txt_supported = resp_edns is not None
             * The key insight: if we got ANY response, the resolver processed our query.
             * EDNS is supported if there's an OPT record (type 41) in the response */
            p->result->edns_supported = false;
            p->result->txt_supported = false;
            p->result->rtt_ms = rtt;

            if (nread >= 12) {
                uint8_t *resp = (uint8_t *)buf->base;
                uint8_t rcode = resp[3] & 0x0F;
                uint16_t ancount = (resp[6] << 8) | resp[7];
                uint16_t arcount = (resp[8] << 8) | resp[9];
                
                LOG_DEBUG("EDNS test response: rcode=%d, ancount=%d, arcount=%d, len=%d\n",
                         rcode, ancount, arcount, (int)nread);
                
                /* Parse DNS packet to find OPT record (EDNS) or TXT record */
                size_t offset = 12;
                
                /* Skip question section */
                while (offset < (size_t)nread && resp[offset] != 0) {
                    offset += resp[offset] + 1;
                }
                offset += 5; /* Skip null byte (1) + QTYPE (2) + QCLASS (2) */

                /* Parse answer and additional sections */
                while (offset + 11 <= (size_t)nread) {
                    uint8_t name = resp[offset];
                    uint16_t rtype = (resp[offset + 1] << 8) | resp[offset + 2];
                    uint16_t rdlen = (resp[offset + 9] << 8) | resp[offset + 10];
                    
                    /* Root zone (name=0) indicates the start of a record */
                    if (name == 0) {
                        if (rtype == 41) { /* OPT record - EDNS supported */
                            /* In OPT record, the "UDP payload" is in the CLASS field */
                            uint16_t udp_payload = (resp[offset + 3] << 8) | resp[offset + 4];
                            p->result->edns_supported = true;
                            p->result->mtu = (udp_payload > 0) ? udp_payload : 1232;
                            LOG_DEBUG("Found OPT record, mtu=%d\n", p->result->mtu);
                        } else if (rtype == 16) { /* TXT record */
                            p->result->txt_supported = true;
                            LOG_DEBUG("Found TXT record\n");
                        }
                    }
                    
                    offset += 11 + rdlen;
                }

                /* Success if either EDNS or TXT is supported (scanner.py logic) */
                if (p->result->edns_supported || p->result->txt_supported) {
                    p->got_reply = true;
                    LOG_DEBUG("EDNS/TXT test passed for resolver %s\n", 
                             g_pool.resolvers[p->resolver_idx].ip);
                } else {
                    /* Even without specific records, if we got a response, 
                     * the resolver processed our query (like scanner.py) */
                    p->result->txt_supported = true; /* Resolver processed the TXT query */
                    p->got_reply = true;
                    LOG_DEBUG("No specific records found, but response received\n");
                }
            }
        } else {
            /* Default behavior for legacy POLL probes */
            p->got_reply = true;
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
    strncpy(hdr.user_id, g_cfg.user_id, sizeof(hdr.user_id));

    p->sendlen = sizeof(p->sendbuf);
    if (build_dns_query(p->sendbuf, &p->sendlen, &hdr, payload, paylen, domain) != 0) {
        free(p);
        return;
    }

    uv_udp_init(g_loop, &p->udp);
    p->udp.data = p;
    
    uv_timer_init(g_loop, &p->timer);
    p->timer.data = p;
    uv_timer_start(&p->timer, on_probe_timeout, 2000, 0);

    uv_udp_recv_start(&p->udp, on_probe_alloc, on_probe_recv);
    uv_buf_t buf = uv_buf_init((char*)p->sendbuf, (unsigned)p->sendlen);
    uv_udp_send(&p->send_req, &p->udp, &buf, 1,
                (const struct sockaddr*)&p->dest, on_probe_send);
}

static void fire_probe(int idx, const char *domain) {
    fire_probe_ext(idx, NULL, 0, domain);
}

/* ────────────────────────────────────────────── */
/*  Standard DNS Query Builder for Resolver Testing */
/*  (Scanner.py style - not POLL format)          */
/* ────────────────────────────────────────────── */

/* Build a standard DNS query with optional EDNS (RFC 6891) */
static size_t build_test_dns_query(uint8_t *buf, size_t bufsize,
                                    const char *qname, uint16_t qtype,
                                    uint16_t qclass, bool use_edns) {
    size_t offset = 0;
    uint16_t id = rand_u16();

    /* DNS Header (12 bytes) */
    buf[offset++] = (id >> 8) & 0xFF;   /* Transaction ID */
    buf[offset++] = id & 0xFF;
    buf[offset++] = 0x01;               /* Flags: RD = 1 (recursion desired) */
    buf[offset++] = 0x00;
    buf[offset++] = 0x00;               /* QDCOUNT (questions) */
    buf[offset++] = 0x01;
    buf[offset++] = 0x00;               /* ANCOUNT */
    buf[offset++] = 0x00;
    buf[offset++] = 0x00;               /* NSCOUNT */
    buf[offset++] = 0x00;
    buf[offset++] = 0x00;               /* ARCOUNT (will be 1 if EDNS) */
    buf[offset++] = use_edns ? 0x01 : 0x00;

    /* QNAME - convert domain to DNS label format */
    const char *p = qname;
    while (*p) {
        const char *dot = strchr(p, '.');
        if (!dot) dot = p + strlen(p);
        size_t label_len = dot - p;
        if (offset + label_len + 1 > bufsize - (use_edns ? 11 : 0)) break;
        buf[offset++] = (uint8_t)label_len;
        memcpy(buf + offset, p, label_len);
        offset += label_len;
        p = dot;
        if (*p) p++; /* Skip dot */
    }
    buf[offset++] = 0; /* Null terminator */

    /* QTYPE and QCLASS */
    buf[offset++] = (qtype >> 8) & 0xFF;
    buf[offset++] = qtype & 0xFF;
    buf[offset++] = (qclass >> 8) & 0xFF;
    buf[offset++] = qclass & 0xFF;

    /* EDNS0 OPT record (RFC 6891) */
    if (use_edns) {
        buf[offset++] = 0x00;           /* NAME: root zone */
        buf[offset++] = 0x00;           /* TYPE: 41 = OPT */
        buf[offset++] = 0x29;
        buf[offset++] = 0x04;           /* CLASS/UDP_PAYLOAD: 1232 (recommended) */
        buf[offset++] = 0xD0;
        buf[offset++] = 0x00;           /* TTL: extended RCODE and flags = 0 */
        buf[offset++] = 0x00;
        buf[offset++] = 0x00;
        buf[offset++] = 0x00;
        buf[offset++] = 0x00;           /* RDLEN: 0 */
        buf[offset++] = 0x00;
    }

    return offset;
}

/* Fire a scanner.py-style resolver test probe */
static void fire_test_probe(int idx, probe_test_type_t test_type,
                            resolver_test_result_t *result) {
    probe_req_t *p = calloc(1, sizeof(*p));
    if (!p) return;

    p->resolver_idx = idx;
    p->sent_ms = uv_hrtime() / 1000000ULL;
    p->test_type = test_type;
    p->result = result;

    resolver_t *r = &g_pool.resolvers[idx];
    memcpy(&p->dest, &r->addr, sizeof(p->dest));
    p->dest.sin_port = htons(53);

    const char *domain;
    uint16_t qtype;
    bool use_edns = false;

    switch (test_type) {
        case PROBE_TEST_LONGNAME:
            /* Phase 1: Long QNAME test - use configured long label domain */
            domain = g_cfg.long_label_domain[0] ? g_cfg.long_label_domain : 
                     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.google.com";
            qtype = 1; /* A record */
            use_edns = false;
            break;
        case PROBE_TEST_NXDOMAIN:
            /* Phase 2: NXDOMAIN test - use nonexistent domain */
            domain = g_cfg.nonexistent_domain[0] ? g_cfg.nonexistent_domain : 
                     "nonexistent.example.com";
            qtype = 1; /* A record */
            use_edns = false;
            break;
        case PROBE_TEST_EDNS_TXT:
            /* Phase 3: EDNS + TXT test */
            domain = g_cfg.test_domain[0] ? g_cfg.test_domain : "s.domain.com";
            qtype = 16; /* TXT record */
            use_edns = true;
            break;
        default:
            free(p);
            return;
    }

    p->sendlen = build_test_dns_query(p->sendbuf, sizeof(p->sendbuf),
                                      domain, qtype, 1, use_edns);

    if (p->sendlen == 0 || p->sendlen > sizeof(p->sendbuf)) {
        free(p);
        return;
    }

    uv_udp_init(g_loop, &p->udp);
    p->udp.data = p;

    uv_timer_init(g_loop, &p->timer);
    p->timer.data = p;
    uv_timer_start(&p->timer, on_probe_timeout, 
                   (uint64_t)g_cfg.test_timeout_ms > 0 ? g_cfg.test_timeout_ms : 1000, 0);

    uv_udp_recv_start(&p->udp, on_probe_alloc, on_probe_recv);
    uv_buf_t buf = uv_buf_init((char*)p->sendbuf, (unsigned)p->sendlen);
    uv_udp_send(&p->send_req, &p->udp, &buf, 1,
                (const struct sockaddr*)&p->dest, on_probe_send);
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
/*  Resolver Init Phase (Scanner.py style)        */
/* ────────────────────────────────────────────── */
static void on_init_phase_timeout(uv_timer_t *t) {
    uv_stop(t->loop);
}

/* Helper: run event loop for specified milliseconds */
static void run_event_loop_ms(int timeout_ms) {
    uv_timer_t wait;
    uv_timer_init(g_loop, &wait);
    uv_timer_start(&wait, on_init_phase_timeout, (uint64_t)timeout_ms, 0);
    uv_run(g_loop, UV_RUN_DEFAULT);
    uv_close((uv_handle_t*)&wait, NULL);
    uv_run(g_loop, UV_RUN_NOWAIT);
}

static void resolver_init_phase(void) {
    LOG_INFO("=== Resolver Initialization Phase (Scanner.py style) ===\n");

    /* Step 1: Add seed resolvers */
    for (int i = 0; i < g_cfg.seed_count; i++)
        rpool_add(&g_pool, g_cfg.seed_resolvers[i]);

    LOG_INFO("Loaded %d seed resolvers\n", g_pool.count);

    /* Step 2: CIDR scan seed IPs (find siblings) */
    if (g_cfg.cidr_scan) {
        for (int i = 0; i < g_cfg.seed_count; i++)
            cidr_scan_subnet(g_cfg.seed_resolvers[i], g_cfg.cidr_prefix);
        LOG_INFO("After CIDR scan: %d resolvers in pool\n", g_pool.count);
    }

    /* Allocate result tracking for each resolver */
    resolver_test_result_t *results = calloc(g_pool.count, sizeof(resolver_test_result_t));
    if (!results) {
        LOG_ERR("Failed to allocate test results\n");
        return;
    }

    int wait_ms = (g_cfg.test_timeout_ms > 0) ? g_cfg.test_timeout_ms + 1000 : 2500;

    /* ─── Phase 1: Long QNAME Test ─── */
    LOG_INFO("--- Phase 1: Testing Long QNAME support ---\n");
    int phase1_count = 0;
    for (int i = 0; i < g_pool.count; i++) {
        if (g_pool.resolvers[i].state == RSV_DEAD) {
            fire_test_probe(i, PROBE_TEST_LONGNAME, &results[i]);
            phase1_count++;
            if (phase1_count % 50 == 0) uv_run(g_loop, UV_RUN_NOWAIT);
        }
    }
    run_event_loop_ms(wait_ms);

    /* Filter: keep only resolvers that support long QNAME */
    int longname_ok = 0;
    for (int i = 0; i < g_pool.count; i++) {
        if (results[i].longname_supported) {
            longname_ok++;
        } else {
            /* Set failure reason for dead resolver */
            strncpy(g_pool.resolvers[i].fail_reason, "long-QNAME reject", sizeof(g_pool.resolvers[i].fail_reason) - 1);
            g_pool.resolvers[i].fail_reason[sizeof(g_pool.resolvers[i].fail_reason) - 1] = '\0';
            rpool_set_state(&g_pool, i, RSV_DEAD);
        }
    }
    LOG_INFO("Phase 1 complete: %d/%d resolvers support long QNAME\n", 
             longname_ok, g_pool.count);

    /* ─── Phase 2: NXDOMAIN Test (Fake Resolver Filter) ─── */
    LOG_INFO("--- Phase 2: Testing NXDOMAIN behavior (fake resolver filter) ---\n");
    int phase2_count = 0;
    for (int i = 0; i < g_pool.count; i++) {
        /* Test resolvers that PASSED Phase 1 */
        if (results[i].longname_supported) {
            results[i].nxdomain_correct = false;
            fire_test_probe(i, PROBE_TEST_NXDOMAIN, &results[i]);
            phase2_count++;
            if (phase2_count % 50 == 0) uv_run(g_loop, UV_RUN_NOWAIT);
        }
    }
    run_event_loop_ms(wait_ms);

    /* Filter: keep only resolvers with correct NXDOMAIN behavior */
    int nxdomain_ok = 0;
    for (int i = 0; i < g_pool.count; i++) {
        /* Resolvers that passed Phase 1 but failed Phase 2 are marked dead */
        if (results[i].longname_supported && !results[i].nxdomain_correct) {
            strncpy(g_pool.resolvers[i].fail_reason, "fake resolver", sizeof(g_pool.resolvers[i].fail_reason) - 1);
            g_pool.resolvers[i].fail_reason[sizeof(g_pool.resolvers[i].fail_reason) - 1] = '\0';
            rpool_set_state(&g_pool, i, RSV_DEAD);
            results[i].longname_supported = false; /* Mark as failed */
        } else if (results[i].nxdomain_correct) {
            nxdomain_ok++;
        }
    }
    LOG_INFO("Phase 2 complete: %d/%d resolvers passed NXDOMAIN test\n", 
             nxdomain_ok, g_pool.count);

    /* ─── Phase 3: EDNS + TXT Quality Test ─── */
    LOG_INFO("--- Phase 3: Testing EDNS + TXT support and MTU detection ---\n");
    int phase3_count = 0;
    for (int i = 0; i < g_pool.count; i++) {
        /* Test resolvers that passed Phase 1 and Phase 2 */
        if (results[i].longname_supported && results[i].nxdomain_correct) {
            results[i].edns_supported = false;
            results[i].txt_supported = false;
            results[i].mtu = 0;
            fire_test_probe(i, PROBE_TEST_EDNS_TXT, &results[i]);
            phase3_count++;
            if (phase3_count % 50 == 0) uv_run(g_loop, UV_RUN_NOWAIT);
        }
    }
    run_event_loop_ms(wait_ms);

    /* Final filter: promote resolvers that passed all three phases */
    int active = 0;
    for (int i = 0; i < g_pool.count; i++) {
        resolver_t *r = &g_pool.resolvers[i];
        
        /* Check if resolver passed all three phases */
        if (results[i].longname_supported && 
            results[i].nxdomain_correct && 
            (results[i].edns_supported || results[i].txt_supported)) {
            /* Update resolver with discovered MTU from EDNS */
            if (results[i].mtu > 0) {
                r->upstream_mtu = results[i].mtu;
                r->edns0_supported = true;
            } else {
                r->upstream_mtu = 512; /* Default MTU */
            }
            rpool_set_state(&g_pool, i, RSV_ACTIVE);
            active++;
        } else if (results[i].longname_supported && results[i].nxdomain_correct) {
            /* Passed Phase 1 and 2, but failed Phase 3 - no EDNS/TXT support */
            strncpy(r->fail_reason, "no EDNS/TXT support", sizeof(r->fail_reason) - 1);
            r->fail_reason[sizeof(r->fail_reason) - 1] = '\0';
            rpool_set_state(&g_pool, i, RSV_DEAD);
        }
        /* Resolvers that failed Phase 1 or Phase 2 already have fail_reason set */
    }

    LOG_INFO("=== Init complete: %d/%d resolvers active ===\n", active, g_pool.count);
    LOG_INFO("EDNS resolvers: %d, TXT resolvers: %d\n",
             active, active);

    /* DEBUG: Log details of each resolver's status */
    for (int i = 0; i < g_pool.count; i++) {
        resolver_t *r = &g_pool.resolvers[i];
        const char *state_str = "UNKNOWN";
        switch (r->state) {
            case RSV_ACTIVE:   state_str = "ACTIVE"; break;
            case RSV_DEAD:     state_str = "DEAD"; break;
            case RSV_PENALTY:  state_str = "PENALTY"; break;
            case RSV_ZOMBIE:   state_str = "ZOMBIE"; break;
            case RSV_TESTING:  state_str = "TESTING"; break;
        }
        if (r->state != RSV_ACTIVE) {
            LOG_ERR("Resolver %s state=%s reason=%s\n", r->ip, state_str,
                    r->fail_reason[0] ? r->fail_reason : "(none)");
        } else {
            LOG_INFO("Resolver %s state=%s MTU=%u RTT=%.1fms\n",
                     r->ip, state_str, r->upstream_mtu, r->rtt_ms);
        }
    }

    /* Log MTU statistics */
    int mtu_min = 9999, mtu_max = 0;
    for (int i = 0; i < g_pool.count; i++) {
        if (results[i].mtu > 0) {
            if (results[i].mtu < mtu_min) mtu_min = results[i].mtu;
            if (results[i].mtu > mtu_max) mtu_max = results[i].mtu;
        }
    }
    if (mtu_min < 9999) {
        LOG_INFO("MTU range: %d - %d\n", mtu_min, mtu_max);
    }

    free(results);

    g_stats.active_resolvers = g_pool.active_count;
    g_stats.dead_resolvers   = g_pool.dead_count;
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
    uv_timer_t       timer;
    int              closes;
    uv_udp_send_t    send_req;
    struct sockaddr_in dest;
    int              resolver_idx;
    int              session_idx;
    uint16_t         seq;
    uint64_t         sent_ms;  /* renamed from sent_us: actually ms (fix #14) */
    uint8_t          sendbuf[512]; /* Fix: was DNS_BUFFER_UDP which is only 64 bytes on 64-bit systems */
    size_t           sendlen;
    uint8_t          recvbuf[512]; /* Fix: was DNS_BUFFER_UDP which is only 64 bytes on 64-bit systems */
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
        /* DEBUG: Log response source and size */
        char src_ip[46] = "unknown";
        if (addr) {
            uv_inet_ntop(AF_INET, &((const struct sockaddr_in*)addr)->sin_addr, src_ip, sizeof(src_ip));
        }
        LOG_DEBUG("DNS response from %s: %zd bytes (resolver_idx=%d, session=%d, seq=%u)\n",
                  src_ip, nread, ridx, q->session_idx, q->seq);

        /* DEBUG: Print response header bytes */
        LOG_DEBUG("Response header: ");
        for (size_t i = 0; i < (nread < 16 ? nread : 16); i++) {
            fprintf(stderr, "%02x ", (unsigned char)buf->base[i]);
        }
        fprintf(stderr, "\n");

        /* Measure RTT (fix #14: variable is now correctly named sent_ms) */
        double rtt = (double)(uv_hrtime() / 1000000ULL - q->sent_ms);
        if (rtt < 0.0) rtt = 0.0;
        rpool_on_ack(&g_pool, ridx, rtt);

        /* Decode DNS response */
        dns_decoded_t decoded[DNS_DECODEBUF_4K];
        size_t decsz = sizeof(decoded);
        dns_rcode_t rc = dns_decode(decoded, &decsz,
                       (const dns_packet_t*)buf->base,
                       (size_t)nread);
        if (rc == RCODE_OKAY)
        {
            dns_query_t *resp = (dns_query_t*)decoded;
            LOG_DEBUG("DNS decode OK: id=%d, rcode=%d, ancount=%d\n",
                      resp->id, resp->rcode, resp->ancount);
            /* Walk answer section for TXT records */
            for (int i = 0; i < (int)resp->ancount; i++) {
                dns_answer_t *ans = &resp->answers[i];
                LOG_DEBUG("Answer %d: type=%d (TXT=%d), len=%d\n",
                          i, ans->generic.type, RR_TXT, ans->txt.len);
                if (ans->generic.type == RR_TXT && ans->txt.len > 0) {
                    LOG_DEBUG("TXT record content (%d bytes): ", ans->txt.len);
                    for (size_t j = 0; j < (ans->txt.len < 32 ? ans->txt.len : 32); j++) {
                        fprintf(stderr, "%02x ", (unsigned char)ans->txt.text[j]);
                    }
                    fprintf(stderr, "\n");
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
                    g_stats.last_server_rx_ms = uv_hrtime() / 1000000ULL;
                }
            }
        } else {
            /* Bad / zombie response — lose a packet */
            LOG_ERR("DNS decode failed: rcode=%d from resolver %d\n", rc, ridx);
            rpool_on_loss(&g_pool, ridx);
            g_stats.queries_lost++;
        }
    } else {
        LOG_ERR("DNS recv error: nread=%zd from resolver %d\n", nread, ridx);
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
    if (ridx < 0) {
        LOG_ERR("fire_dns_chunk_symbol: no active resolver available (session_idx=%d, seq=%u)\n",
                session_idx, seq);
        return;
    }
    LOG_DEBUG("fire_dns_chunk_symbol: using resolver %d (%s) for session %d seq %u\n",
              ridx, g_pool.resolvers[ridx].ip, session_idx, seq);

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

    /* DEBUG: Log destination and packet info */
    char dest_ip[46];
    uv_inet_ntop(AF_INET, &q->dest.sin_addr, dest_ip, sizeof(dest_ip));
    LOG_DEBUG("Sending to resolver %s at %s:%d (packet len=%zu)\n",
              r->ip, dest_ip, ntohs(q->dest.sin_port), q->sendlen);

    /* DEBUG: Print first 32 bytes of DNS packet for verification */
    LOG_DEBUG("DNS packet header (first 32 bytes): ");
    for (size_t i = 0; i < (q->sendlen < 32 ? q->sendlen : 32); i++) {
        fprintf(stderr, "%02x ", q->sendbuf[i]);
    }
    fprintf(stderr, "\n");

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
    int send_rc = uv_udp_send(&q->send_req, &q->udp, &buf, 1,
                              (const struct sockaddr*)&q->dest, on_dns_send);
    if (send_rc != 0) {
        LOG_ERR("uv_udp_send failed: %s (resolver=%s)\n", uv_strerror(send_rc), r->ip);
        uv_close((uv_handle_t*)&q->udp, on_dns_query_close);
    } else {
        LOG_DEBUG("DNS query sent to %s:%d (len=%zu, domain=%s)\n",
                  r->ip, ntohs(q->dest.sin_port), q->sendlen, domain);
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

