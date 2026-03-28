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
/* Include winsock2.h BEFORE windows.h to prevent winsock.h conflicts */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>
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
#include "shared/mgmt.h"

/* Utility macros */
#ifndef max
#define max(a,b) ((a) >= (b) ? (a) : (b))
#endif
#ifndef min
#define min(a,b) ((a) <= (b) ? (a) : (b))
#endif

/* Platform fallbacks */
#ifdef _WIN32
static char* strndup(const char* s, size_t n) {
    size_t len = strnlen(s, n);
    char* news = (char*)malloc(len + 1);
    if (!news) return NULL;
    news[len] = '\0';
    return (char*)memcpy(news, s, len);
}
#endif

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
static mgmt_server_t    *g_mgmt;            /* Management server for TUI */

/* Active SOCKS5 sessions */
static session_t        g_sessions[DNSTUN_MAX_SESSIONS];
static int              g_session_count = 0;

/* Persistent resolver list file */
static char g_resolvers_file[1024];

/* Debug log file */
static FILE *g_debug_log = NULL;

/* ────────────────────────────────────────────── */
/*  Utility                                       */
/* ────────────────────────────────────────────── */
static int log_level(void) { return g_cfg.log_level; }

#define LOG_INFO(...)  do { if (log_level() >= 1) { fprintf(stdout, "[INFO]  " __VA_ARGS__); if (g_debug_log) fprintf(g_debug_log, "[INFO]  " __VA_ARGS__); tui_debug_log(&g_tui, 2, __VA_ARGS__); } } while(0)
#define LOG_DEBUG(...) do { if (log_level() >= 2) { fprintf(stdout, "[DEBUG] " __VA_ARGS__); if (g_debug_log) fprintf(g_debug_log, "[DEBUG] " __VA_ARGS__); tui_debug_log(&g_tui, 3, __VA_ARGS__); } } while(0)
#define LOG_WARN(...)  do { if (log_level() >= 1) { fprintf(stdout, "[WARN]  " __VA_ARGS__); if (g_debug_log) fprintf(g_debug_log, "[WARN]  " __VA_ARGS__); tui_debug_log(&g_tui, 1, __VA_ARGS__); } } while(0)
#define LOG_ERR(...)   do { fprintf(stderr, "[ERROR] " __VA_ARGS__); if (g_debug_log) fprintf(g_debug_log, "[ERROR] " __VA_ARGS__); tui_debug_log(&g_tui, 0, __VA_ARGS__); } while(0)

static uint16_t rand_u16(void) {
    return (uint16_t)(rand() & 0xFFFF);
}

/* Generate a unique 8-bit session ID (0-255) */
static uint8_t get_unused_session_id(void) {
    for (int i = 0; i < 256; i++) {
        uint8_t sid = (uint8_t)i;
        bool in_use = false;
        for (int j = 0; j < DNSTUN_MAX_SESSIONS; j++) {
            if (g_sessions[j].established && !g_sessions[j].closed && g_sessions[j].session_id == sid) {
                in_use = true;
                break;
            }
        }
        if (!in_use) return sid;
    }
    return 0; /* Should not happen with DNSTUN_MAX_SESSIONS <= 256 */
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
    /* New header is 5 bytes, payload can be up to DNSTUN_CHUNK_PAYLOAD */
    uint8_t raw[5 + DNSTUN_CHUNK_PAYLOAD];
    size_t  rawlen = 0;
    memcpy(raw, hdr, sizeof(chunk_header_t));   rawlen += sizeof(chunk_header_t);
    if (payload && paylen > 0) {
        /*
         * CRITICAL: Strict bounds checking for FEC compatibility.
         * Symbol size (T) in codec_fec_encode must match DNSTUN_CHUNK_PAYLOAD.
         * Silent truncation here breaks FEC decoding at the server.
         */
        if (paylen > DNSTUN_CHUNK_PAYLOAD) {
            LOG_ERR("Payload too large: %zu bytes (max %d). FEC symbol size mismatch!\n",
                    paylen, DNSTUN_CHUNK_PAYLOAD);
            return -1;
        }
        memcpy(raw + rawlen, payload, paylen); rawlen += paylen;
    }

    /* Base32 encode the raw data (UPPERCASE for DNS compatibility)
     * Formula: base32 output = ceil(input_len * 8 / 5)
     * For header(5) + payload(137) = 142 bytes: 142 * 8 / 5 = 228 bytes */
    #define BASE32_MAX_OUTPUT(max_input) (((max_input) * 8 + 4) / 5)
    char b32_raw[BASE32_MAX_OUTPUT(5 + DNSTUN_CHUNK_PAYLOAD)];
    size_t b32_len = base32_encode((uint8_t*)b32_raw, raw, rawlen);

    /* Use slipstream's inline_dotify to split into labels every 57 chars */
    /* Add extra space for dots: approximately raw_len/57 extra chars */
    char b32_dotted[BASE32_MAX_OUTPUT(5 + DNSTUN_CHUNK_PAYLOAD) + 64];
    memcpy(b32_dotted, b32_raw, b32_len);
    size_t dotted_len = inline_dotify(b32_dotted, sizeof(b32_dotted), b32_len);

    /* Build QNAME: <b32_dotted>.tun.<domain>.
     * New compact header doesn't include session_id in QNAME - it's in the flags byte
     * CRITICAL: Must end with trailing dot for FQDN format!
     * 
     * DNS QNAME maximum is 253 bytes. We need to ensure:
     * b32_dotted + "tun"(3) + domain + dots + trailing(1) <= 253
     * 
     * For domain ~15 chars: 3 + 15 + 1 = 19 overhead
     * Max b32_dotted = 253 - 19 - (dots overhead ~b32_len/57) ≈ 220 chars
     * Max base32 input ≈ 220 * 5 / 8 = 137 bytes
     * For header 5 bytes, max payload ≈ 132 bytes
     * 
     * DNSTUN_CHUNK_PAYLOAD is capped to ensure QNAME fits within DNS limits.
     * 
     * Fix: Strip trailing dot from domain to prevent double dots (e.g., "tun.example.com..") */
    char qname[512];
    char clean_domain[256];
    size_t domain_len = strlen(domain);
    if (domain_len > 0 && domain[domain_len - 1] == '.') {
        /* Strip trailing dot */
        strncpy(clean_domain, domain, domain_len - 1);
        clean_domain[domain_len - 1] = '\0';
    } else {
        strncpy(clean_domain, domain, sizeof(clean_domain) - 1);
        clean_domain[sizeof(clean_domain) - 1] = '\0';
    }
    int qname_len = snprintf(qname, sizeof(qname), "%s.tun.%s.",
             b32_dotted, clean_domain);

    if (qname_len > DNSTUN_MAX_QNAME_LEN) {
        LOG_ERR("QNAME too long: %d bytes (max %d). Reduce DNSTUN_CHUNK_PAYLOAD.\n",
                qname_len, DNSTUN_MAX_QNAME_LEN);
        return -1;
    }

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
/*  Plus MTU binary search testing for upstream/downstream */
/* ────────────────────────────────────────────── */
typedef enum {
    PROBE_TEST_NONE = 0,
    PROBE_TEST_LONGNAME,      /* Phase 1: Long QNAME support */
    PROBE_TEST_NXDOMAIN,      /* Phase 2: NXDOMAIN behavior (fake resolver filter) */
    PROBE_TEST_EDNS_TXT,      /* Phase 3: EDNS + TXT support detection */
    PROBE_TEST_MTU_UP,        /* MTU Binary search: Upload MTU test */
    PROBE_TEST_MTU_DOWN       /* MTU Binary search: Download MTU test */
} probe_test_type_t;

/* MTU binary search state */
typedef struct {
    int low;
    int high;
    int optimal;
    int min_threshold;
    int allowed_min_mtu;
    int retries;
    int test_size;           /* Current MTU size being tested */
    bool is_upload_test;     /* true for upload, false for download */
    int upstream_mtu;        /* Known upstream MTU for download test */
    int* tested_cache;      /* Cache of tested MTU values (bitmap) */
    int cache_size;
} mtu_binary_search_t;

/* Result structure for each resolver */
typedef struct {
    bool        longname_supported;  /* Phase 1 result */
    bool        nxdomain_correct;     /* Phase 2 result (false = fake resolver) */
    bool        edns_supported;      /* Phase 3 result */
    bool        txt_supported;       /* Phase 3 result */
    uint16_t    upstream_mtu;        /* EDNS payload size from Phase 3 / Binary search result */
    uint16_t    downstream_mtu;       /* Binary search result for download MTU */
    double      rtt_ms;              /* RTT for Phase 3 test */
    /* MTU binary search state */
    mtu_binary_search_t up_mtu_search;
    mtu_binary_search_t down_mtu_search;
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
    /* MTU test specific fields */
    int             mtu_under_test;  /* MTU size being tested */
    int             mtu_test_attempt; /* Current retry attempt */
    int             mtu_test_max;     /* Max retries for MTU test */
} probe_req_t;

/* ────────────────────────────────────────────── */
/*  Protocol Debug Packet (loopback test)          */
/* ────────────────────────────────────────────── */
typedef struct debug_pkt_ctx {
    uv_udp_t        udp;
    uv_timer_t      timer;
    int             closes;
    uv_udp_send_t   send_req;
    struct sockaddr_in dest;
    uint64_t        sent_ms;
    uint8_t         sendbuf[512];
    size_t          sendlen;
    uint8_t         recvbuf[512];
    uint32_t        expected_seq;
    char            expected_payload[64];
} debug_pkt_ctx_t;

static void on_debug_close(uv_handle_t *h) {
    debug_pkt_ctx_t *d = h->data;
    if (++d->closes == 2) free(d);
}

static void on_debug_timeout(uv_timer_t *t) {
    debug_pkt_ctx_t *d = t->data;
    tui_proto_test_on_timeout(&g_tui);
    if (!uv_is_closing((uv_handle_t*)&d->udp)) {
        uv_close((uv_handle_t*)&d->udp, on_debug_close);
        uv_close((uv_handle_t*)&d->timer, on_debug_close);
    }
}

static void on_debug_alloc(uv_handle_t *h, size_t sz, uv_buf_t *buf) {
    debug_pkt_ctx_t *d = h->data;
    (void)sz;
    buf->base = (char*)d->recvbuf;
    buf->len = sizeof(d->recvbuf);
}

static void on_debug_send(uv_udp_send_t *sr, int status) {
    (void)status;
    (void)sr;
}

static void on_debug_recv(uv_udp_t *h, ssize_t nread,
                         const uv_buf_t *buf,
                         const struct sockaddr *addr,
                         unsigned flags)
{
    if (nread == 0 && addr == NULL) return;
    (void)flags;
    
    debug_pkt_ctx_t *d = h->data;
    
    if (nread > 0) {
        /* Decode DNS response */
        dns_decoded_t decoded[DNS_DECODEBUF_4K];
        size_t decsz = sizeof(decoded);
        dns_rcode_t rc = dns_decode(decoded, &decsz,
                       (const dns_packet_t*)buf->base,
                       (size_t)nread);
        if (rc == RCODE_OKAY) {
            dns_query_t *resp = (dns_query_t*)decoded;
            for (int i = 0; i < (int)resp->ancount; i++) {
                dns_answer_t *ans = &resp->answers[i];
                if (ans->generic.type == RR_TXT && ans->txt.len > 0) {
                    /* Base64 decode the server response */
                    uint8_t decoded_payload[256];
                    ptrdiff_t decoded_len = base64_decode(decoded_payload, ans->txt.text, ans->txt.len);
                    
                    if (decoded_len > 0) {
                        /* Check if this matches our debug payload */
                        if ((size_t)decoded_len == strlen(d->expected_payload) &&
                            memcmp(decoded_payload, d->expected_payload, (size_t)decoded_len) == 0) {
                            /* Success! */
                            LOG_INFO("Debug packet %u loopback successful\n", d->expected_seq);
                            tui_proto_test_on_response(&g_tui, d->expected_seq);
                        }
                    }
                }
            }
        }
        
        /* Close and cleanup */
        if (!uv_is_closing((uv_handle_t*)&d->udp)) {
            uv_close((uv_handle_t*)&d->udp, on_debug_close);
        }
        uv_timer_stop(&d->timer);
        if (!uv_is_closing((uv_handle_t*)&d->timer)) {
            uv_close((uv_handle_t*)&d->timer, on_debug_close);
        }
    }
}

/* Send a debug packet through the normal codec pipeline */
void send_debug_packet(const char *payload, uint32_t seq) {
    /* Find an active resolver to send through */
    resolver_t *r = NULL;
    uv_mutex_lock(&g_pool.lock);
    for (int i = 0; i < g_pool.count; i++) {
        if (g_pool.resolvers[i].state == RSV_ACTIVE) {
            r = &g_pool.resolvers[i];
            break;
        }
    }
    uv_mutex_unlock(&g_pool.lock);
    
    if (!r) {
        LOG_ERR("No active resolver available for debug packet\n");
        tui_proto_test_on_timeout(&g_tui);
        return;
    }
    
    debug_pkt_ctx_t *d = calloc(1, sizeof(*d));
    if (!d) {
        tui_proto_test_on_timeout(&g_tui);
        return;
    }
    
    d->sent_ms = uv_hrtime() / 1000000ULL;
    d->expected_seq = seq;
    strncpy(d->expected_payload, payload, sizeof(d->expected_payload) - 1);
    
    memcpy(&d->dest, &r->addr, sizeof(d->dest));
    d->dest.sin_port = htons(53);
    
    /* Build chunk header - use session 255 (reserved for debug) */
    chunk_header_t hdr = {0};
    chunk_set_session_id(&hdr, 255);  /* Reserved session for debug */
    hdr.seq = (uint16_t)(seq & 0xFFFF);
    hdr.chunk_info = 0;  /* Single chunk, no FEC */
    
    /* Use first configured domain */
    const char *domain = (g_cfg.domain_count > 0) ? g_cfg.domains[0] : "tun.example.com";
    
    d->sendlen = sizeof(d->sendbuf);
    if (build_dns_query(d->sendbuf, &d->sendlen, &hdr, 
                        (const uint8_t*)payload, strlen(payload), domain) != 0) {
        free(d);
        tui_proto_test_on_timeout(&g_tui);
        return;
    }
    
    uv_udp_init(g_loop, &d->udp);
    d->udp.data = d;
    
    uv_timer_init(g_loop, &d->timer);
    d->timer.data = d;
    uv_timer_start(&d->timer, on_debug_timeout, 5000, 0);  /* 5 second timeout */
    
    uv_udp_recv_start(&d->udp, on_debug_alloc, on_debug_recv);
    
    uv_buf_t buf = uv_buf_init((char*)d->sendbuf, (unsigned)d->sendlen);
    uv_udp_send(&d->send_req, &d->udp, &buf, 1,
                (const struct sockaddr*)&d->dest, on_debug_send);
}

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
                
                /* Parse DNS packet to find OPT record (EDNS) or TXT record */
                size_t offset = 12;
                
                /* Skip question section with DNS pointer support */
                while (offset < (size_t)nread) {
                    uint8_t len = resp[offset];
                    if (len == 0) {
                        offset++;
                        break;
                    }
                    /* DNS pointer: top 2 bits set (0xC0) - follow the pointer */
                    if ((len & 0xC0) == 0xC0) {
                        /* Pointer takes 2 bytes - verify bounds */
                        if (offset + 2 > (size_t)nread) break;
                        /* Follow pointer to get new offset */
                        offset = ((len & 0x3F) << 8) | resp[offset + 1];
                        break; /* After pointer, question section ends */
                    }
                    /* Regular label - verify bounds */
                    if (offset + 1 + len > (size_t)nread) break;
                    offset += 1 + len;
                }
                offset += 5; /* Skip null byte (1) + QTYPE (2) + QCLASS (2) */
                if (offset > (size_t)nread) offset = (size_t)nread;

                /* Parse answer and additional sections with pointer support */
                size_t visited_count = 0;
                const size_t MAX_VISITED = 128; /* Prevent infinite loops */
                
                while (offset + 11 <= (size_t)nread && visited_count < MAX_VISITED) {
                    visited_count++;
                    
                    uint8_t name = resp[offset];
                    uint16_t rtype = (resp[offset + 1] << 8) | resp[offset + 2];
                    uint16_t rdlen = (resp[offset + 9] << 8) | resp[offset + 10];
                    
                    /* DNS pointer in name field */
                    if ((name & 0xC0) == 0xC0) {
                        /* Verify pointer bounds and follow it */
                        if (offset + 2 + 11 > (size_t)nread) break;
                        offset = ((name & 0x3F) << 8) | resp[offset + 1];
                        if (offset >= (size_t)nread) break;
                        continue;
                    }
                    
                    /* Root zone (name=0) indicates the start of a record */
                    if (name == 0) {
                        if (rtype == 41) { /* OPT record - EDNS supported */
                            /* In OPT record, the "UDP payload" is in the CLASS field */
                            uint16_t udp_payload = (resp[offset + 3] << 8) | resp[offset + 4];
                            p->result->edns_supported = true;
                            p->result->upstream_mtu = (udp_payload > 0) ? udp_payload : 1232;
                        } else if (rtype == 16) { /* TXT record */
                            p->result->txt_supported = true;
                        }
                    }
                    
                    /* Verify RDLEN doesn't overflow buffer */
                    if (offset + 11 + rdlen > (size_t)nread) break;
                    offset += 11 + rdlen;
                }

                /* Success if either EDNS or TXT is supported (scanner.py logic) */
                if (p->result->edns_supported || p->result->txt_supported) {
                    p->got_reply = true;
                } else {
                    /* Even without specific records, if we got a response, 
                     * the resolver processed our query (like scanner.py) */
                    p->result->txt_supported = true; /* Resolver processed the TXT query */
                    p->got_reply = true;
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

    /* Build a minimal POLL DNS query (compact 5-byte header) */
    chunk_header_t hdr = {0};
    hdr.flags   = CHUNK_FLAG_POLL;
    chunk_set_session_id(&hdr, 0); /* Polls use session 0 */
    hdr.seq = 0;
    hdr.chunk_info = 0; /* No FEC, single chunk */

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

/* Build a DNS query for MTU testing following the optimal algorithm:
 * - Upstream: Pad QNAME with random data labels to reach exact target MTU
 * - Downstream: Use mtu-req-[N].tun.domain.com format so server sends large response
 * Returns total packet size */
static size_t build_mtu_test_query(uint8_t *buf, size_t bufsize,
                                   const char *qname, uint16_t qtype,
                                   int target_mtu, bool is_upload) {
    size_t offset = 0;
    uint16_t id = rand_u16();
    
    /* DNS Header (12 bytes) */
    buf[offset++] = (id >> 8) & 0xFF;
    buf[offset++] = id & 0xFF;
    buf[offset++] = 0x01;               /* Flags: RD = 1 */
    buf[offset++] = 0x00;
    buf[offset++] = 0x00;               /* QDCOUNT */
    buf[offset++] = 0x01;
    buf[offset++] = 0x00;               /* ANCOUNT */
    buf[offset++] = 0x00;
    buf[offset++] = 0x00;               /* NSCOUNT */
    buf[offset++] = 0x00;
    buf[offset++] = 0x00;               /* ARCOUNT */
    buf[offset++] = 0x01;               /* 1 if EDNS */

    if (is_upload && target_mtu > 0) {
        /* UPSTREAM MTU TEST: Pad QNAME to reach exact target_mtu
         * Format: [padding_label].tun.domain.com
         * Where padding is random base32-compatible characters split into 63-char labels
         * 
         * Overhead calculation:
         *   DNS Header: 12 bytes
         *   QTYPE+QCLASS: 4 bytes
         *   EDNS OPT: 11 bytes
         *   QNAME null: 1 byte
         *   Total overhead: 28 bytes
         * 
         * QNAME overhead (excluding variable part):
         *   ".tun." = 5 bytes + domain
         *   Each label has 1-byte length prefix
         */
        size_t domain_len = strlen(qname);  /* "tun.domain.com" format */
        size_t base_qname_bytes = 1 + domain_len;  /* null + domain labels */
        size_t overhead = 12 + 4 + 11 + base_qname_bytes;  /* 28 + domain */
        size_t padding_needed = (target_mtu > (int)overhead) ? 
                                (target_mtu - (int)overhead) : 0;
        
        /* Fill padding with random base32-compatible characters */
        static const char b32_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        size_t pos = 0;
        while (padding_needed > 0) {
            /* Split into 63-char max labels */
            size_t label_len = (padding_needed > 63) ? 63 : padding_needed;
            
            /* Reserve 1 byte for label length prefix + label_len bytes + dots */
            if (offset + 1 + label_len + 1 > bufsize - 64) break;
            
            buf[offset++] = (uint8_t)label_len;
            for (size_t i = 0; i < label_len; i++) {
                buf[offset++] = b32_chars[rand() % 32];
            }
            padding_needed -= label_len;
            pos += label_len;
        }
        
        /* Add dot separator */
        buf[offset++] = '.';
        
        /* Add domain */
        const char *p = qname;
        while (*p) {
            const char *dot = strchr(p, '.');
            if (!dot) dot = p + strlen(p);
            size_t label_len = dot - p;
            if (offset + label_len + 1 > bufsize - 64) break;
            buf[offset++] = (uint8_t)label_len;
            memcpy(buf + offset, p, label_len);
            offset += label_len;
            p = dot;
            if (*p) p++;
        }
    } else if (!is_upload && target_mtu > 0) {
        /* DOWNSTREAM MTU TEST: Request specific response size
         * Format: mtu-req-[N].tun.domain.com
         * Server parses this and sends N-byte response */
        char prefix[32];
        snprintf(prefix, sizeof(prefix), "mtu-req-%d", target_mtu);
        
        /* Add prefix label */
        size_t prefix_len = strlen(prefix);
        buf[offset++] = (uint8_t)prefix_len;
        memcpy(buf + offset, prefix, prefix_len);
        offset += prefix_len;
        buf[offset++] = '.';
        
        /* Add domain */
        const char *p = qname;
        while (*p) {
            const char *dot = strchr(p, '.');
            if (!dot) dot = p + strlen(p);
            size_t label_len = dot - p;
            if (offset + label_len + 1 > bufsize - 64) break;
            buf[offset++] = (uint8_t)label_len;
            memcpy(buf + offset, p, label_len);
            offset += label_len;
            p = dot;
            if (*p) p++;
        }
    } else {
        /* No padding needed or size not specified */
        const char *p = qname;
        while (*p) {
            const char *dot = strchr(p, '.');
            if (!dot) dot = p + strlen(p);
            size_t label_len = dot - p;
            if (offset + label_len + 1 > bufsize - 64) break;
            buf[offset++] = (uint8_t)label_len;
            memcpy(buf + offset, p, label_len);
            offset += label_len;
            p = dot;
            if (*p) p++;
        }
    }
    
    buf[offset++] = 0;  /* QNAME null terminator */

    /* QTYPE and QCLASS */
    buf[offset++] = (qtype >> 8) & 0xFF;
    buf[offset++] = qtype & 0xFF;
    buf[offset++] = 0x00;  /* QCLASS: IN */
    buf[offset++] = 0x01;

    /* EDNS0 OPT record */
    buf[offset++] = 0x00;           /* NAME: root zone */
    buf[offset++] = 0x00;           /* TYPE: 41 = OPT */
    buf[offset++] = 0x29;
    /* UDP payload size - advertise our capability */
    uint16_t udp_size = (target_mtu > 0 && target_mtu < 1400) ? (uint16_t)target_mtu : 1232;
    buf[offset++] = (udp_size >> 8) & 0xFF;
    buf[offset++] = udp_size & 0xFF;
    buf[offset++] = 0x00;           /* TTL: extended RCODE and flags = 0 */
    buf[offset++] = 0x00;
    buf[offset++] = 0x00;
    buf[offset++] = 0x00;
    buf[offset++] = 0x00;           /* RDLEN: 0 */
    buf[offset++] = 0x00;

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
            /* Phase 3: EDNS + TXT test - add .tun. suffix so server processes these probes */
            {
                static char domain_buf[512];
                const char *base = g_cfg.test_domain[0] ? g_cfg.test_domain : "s.domain.com";
                snprintf(domain_buf, sizeof(domain_buf), "tun.%s", base);
                domain = domain_buf;
            }
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
/*  MTU Binary Search Testing (client.py style) */
/* ────────────────────────────────────────────── */

/* Initialize MTU binary search state */
static void init_mtu_binary_search(mtu_binary_search_t *bs, int min_mtu, int max_mtu,
                                   int min_threshold, int allowed_min_mtu, int retries,
                                   bool is_upload, int upstream_mtu) {
    memset(bs, 0, sizeof(*bs));
    bs->low = max(min_mtu, max(min_threshold, allowed_min_mtu));
    bs->high = max_mtu;
    bs->min_threshold = min_threshold;
    bs->allowed_min_mtu = allowed_min_mtu;
    bs->retries = retries;
    bs->optimal = 0;
    bs->is_upload_test = is_upload;
    bs->upstream_mtu = upstream_mtu;
    bs->test_size = bs->high;
    
    /* Allocate cache for tested values */
    bs->cache_size = (max_mtu / 8) + 1;
    bs->tested_cache = calloc(bs->cache_size, sizeof(int));
}

/* Check if MTU value has been tested */
static bool is_mtu_tested(mtu_binary_search_t *bs, int mtu) {
    if (!bs->tested_cache || mtu < 0 || mtu >= bs->cache_size * 8) return false;
    return (bs->tested_cache[mtu / 8] & (1 << (mtu % 8))) != 0;
}

/* Mark MTU value as tested with result */
static void mark_mtu_tested(mtu_binary_search_t *bs, int mtu, bool success) {
    if (!bs->tested_cache || mtu < 0 || mtu >= bs->cache_size * 8) return;
    if (success) {
        bs->tested_cache[mtu / 8] |= (1 << (mtu % 8));
    } else {
        bs->tested_cache[mtu / 8] &= ~(1 << (mtu % 8));
    }
}

/* Free MTU binary search state */
static void free_mtu_binary_search(mtu_binary_search_t *bs) {
    if (bs->tested_cache) {
        free(bs->tested_cache);
        bs->tested_cache = NULL;
    }
}

/* Get the next MTU to test based on binary search */
static int get_next_mtu_to_test(mtu_binary_search_t *bs) {
    if (bs->optimal > 0 && bs->test_size <= bs->optimal) {
        /* We've found the optimal and tested it */
        return 0; /* Done */
    }
    
    if (bs->optimal == 0) {
        /* First, test the high boundary */
        if (!is_mtu_tested(bs, bs->high)) {
            bs->test_size = bs->high;
            return bs->high;
        }
        /* High already tested, test the low boundary */
        if (!is_mtu_tested(bs, bs->low)) {
            bs->test_size = bs->low;
            return bs->low;
        }
    }
    
    /* Binary search: test middle value */
    int mid = (bs->optimal > 0) ? 
              ((bs->optimal + bs->low) / 2) : 
              ((bs->high + bs->low) / 2);
    
    /* Ensure we don't test the same value twice */
    while (is_mtu_tested(bs, mid) && mid < bs->high) {
        mid++;
    }
    
    if (mid >= bs->high || is_mtu_tested(bs, mid)) {
        return 0; /* Done */
    }
    
    bs->test_size = mid;
    return mid;
}

/* Perform MTU binary search and return optimal MTU */
static int perform_mtu_binary_search(mtu_binary_search_t *bs, 
                                     bool (*test_fn)(int mtu, void *arg), 
                                     void *arg) {
    if (bs->high <= 0 || bs->low > bs->high) {
        return 0;
    }
    
    /* First, test the high boundary */
    int mtu_to_test = get_next_mtu_to_test(bs);
    while (mtu_to_test > 0) {
        bool success = false;
        for (int attempt = 0; attempt < bs->retries; attempt++) {
            if (test_fn(mtu_to_test, arg)) {
                success = true;
                break;
            }
        }
        mark_mtu_tested(bs, mtu_to_test, success);
        
        if (success) {
            bs->optimal = mtu_to_test;
        }
        
        mtu_to_test = get_next_mtu_to_test(bs);
    }
    
    return bs->optimal;
}

/* Fire MTU test probe for a specific size */
static void fire_mtu_test_probe(int idx, probe_test_type_t test_type,
                                 resolver_test_result_t *result, int mtu_size) {
    probe_req_t *p = calloc(1, sizeof(*p));
    if (!p) return;
    
    p->resolver_idx = idx;
    p->sent_ms = uv_hrtime() / 1000000ULL;
    p->test_type = test_type;
    p->result = result;
    p->mtu_under_test = mtu_size;
    p->mtu_test_attempt = 0;
    p->mtu_test_max = g_cfg.mtu_test_retries > 0 ? g_cfg.mtu_test_retries : 2;
    
    resolver_t *r = &g_pool.resolvers[idx];
    memcpy(&p->dest, &r->addr, sizeof(p->dest));
    p->dest.sin_port = htons(53);
    
    /* Add .tun. suffix so server processes MTU probes */
    static char domain_buf[512];
    const char *base = g_cfg.test_domain[0] ? g_cfg.test_domain : "s.domain.com";
    snprintf(domain_buf, sizeof(domain_buf), "tun.%s", base);
    const char *domain = domain_buf;
    
    /* Use build_mtu_test_query which encodes mtu_size in:
     * - EDNS UDP payload size for upload tests
     * - QNAME prefix (e.g., 0200.tun.domain.com) for download tests */
    bool is_upload = (test_type == PROBE_TEST_MTU_UP);
    p->sendlen = build_mtu_test_query(p->sendbuf, sizeof(p->sendbuf),
                                      domain, 16, mtu_size, is_upload);
    
    if (p->sendlen == 0 || p->sendlen > sizeof(p->sendbuf)) {
        free(p);
        return;
    }
    
    uv_udp_init(g_loop, &p->udp);
    p->udp.data = p;
    
    uv_timer_init(g_loop, &p->timer);
    p->timer.data = p;
    uv_timer_start(&p->timer, on_probe_timeout,
                   (uint64_t)g_cfg.mtu_test_timeout_ms > 0 ? g_cfg.mtu_test_timeout_ms : 1000, 0);
    
    uv_udp_recv_start(&p->udp, on_probe_alloc, on_probe_recv);
    uv_buf_t buf = uv_buf_init((char*)p->sendbuf, (unsigned)p->sendlen);
    uv_udp_send(&p->send_req, &p->udp, &buf, 1,
                (const struct sockaddr*)&p->dest, on_probe_send);
}

/* Run MTU tests for all resolvers using binary search */
static void run_mtu_binary_search_tests(resolver_test_result_t *results) {
    LOG_INFO("=== Phase 4: MTU Binary Search Testing ===\n");
    LOG_INFO("Testing MTU sizes for all resolvers (parallel=%d)...\n", 
             g_cfg.mtu_test_parallelism);
    
    int mtu_test_count = 0;
    for (int i = 0; i < g_pool.count; i++) {
        resolver_t *r = &g_pool.resolvers[i];
        if (r->state != RSV_ACTIVE) continue;
        
        /* Initialize upload MTU binary search */
        init_mtu_binary_search(&results[i].up_mtu_search,
                              0, g_cfg.max_upload_mtu > 0 ? g_cfg.max_upload_mtu : 512,
                              30, g_cfg.min_upload_mtu, g_cfg.mtu_test_retries > 0 ? g_cfg.mtu_test_retries : 2,
                              true, 0);
        
        /* Initialize download MTU binary search */
        init_mtu_binary_search(&results[i].down_mtu_search,
                              0, g_cfg.max_download_mtu > 0 ? g_cfg.max_download_mtu : 1200,
                              30, g_cfg.min_download_mtu, g_cfg.mtu_test_retries > 0 ? g_cfg.mtu_test_retries : 2,
                              false, results[i].upstream_mtu);
        
        /* Fire initial MTU test probes */
        int first_up_mtu = get_next_mtu_to_test(&results[i].up_mtu_search);
        if (first_up_mtu > 0) {
            fire_mtu_test_probe(i, PROBE_TEST_MTU_UP, &results[i], first_up_mtu);
            mtu_test_count++;
        }
    }
    
    LOG_INFO("Started %d MTU tests\n", mtu_test_count);
}

/* Find maximum upstream MTU for a resolver */
static uint16_t find_max_upstream_mtu(int resolver_idx, uint16_t suggested_mtu) {
    /* Binary search for maximum upstream MTU */
    int low = 30;
    int high = g_cfg.max_upload_mtu > 0 ? g_cfg.max_upload_mtu : 512;
    int optimal = 0;
    int retries = g_cfg.mtu_test_retries > 0 ? g_cfg.mtu_test_retries : 2;
    
    for (int mtu = high; mtu >= low; mtu -= 10) {
        bool success = false;
        /* In a real implementation, we would send test probes here */
        /* For now, use the suggested MTU from EDNS as a starting point */
        if (mtu <= suggested_mtu) {
            optimal = mtu;
            break;
        }
    }
    
    if (optimal == 0 && suggested_mtu > 0) {
        optimal = suggested_mtu;
    }
    
    return (uint16_t)optimal;
}

/* Find maximum downstream MTU for a resolver */
static uint16_t find_max_downstream_mtu(int resolver_idx, uint16_t upstream_mtu) {
    /* Binary search for maximum downstream MTU */
    int low = 30;
    int high = g_cfg.max_download_mtu > 0 ? g_cfg.max_download_mtu : 1200;
    int optimal = 0;
    
    /* In a real implementation, we would send test probes here */
    /* For now, use a conservative default based on upstream MTU */
    if (upstream_mtu > 0) {
        optimal = (upstream_mtu * 2 > high) ? high : upstream_mtu * 2;
        if (optimal < 512) optimal = 512;
    }
    
    return (uint16_t)optimal;
}

/* ────────────────────────────────────────────── */
/*  Packet Aggregation - Pack multiple symbols into one packet */
/*  This maximizes payload utilization per transmission        */
/* ────────────────────────────────────────────── */

/* Calculate optimal symbols per packet based on MTU and symbol size */
static int calc_symbols_per_packet(uint16_t mtu, int symbol_size) {
    if (mtu <= 0 || symbol_size <= 0) return 1;
    int max_symbols = mtu / symbol_size;
    if (max_symbols < 1) max_symbols = 1;
    if (max_symbols > g_cfg.max_symbols_per_packet) {
        max_symbols = g_cfg.max_symbols_per_packet;
    }
    return max_symbols;
}

/* Initialize an aggregated packet with header */
static void agg_packet_init(agg_packet_t *pkt, const chunk_header_t *hdr) {
    if (!pkt) return;
    memset(pkt, 0, sizeof(*pkt));
    if (hdr) {
        memcpy(&pkt->hdr, hdr, sizeof(pkt->hdr));
    }
    pkt->symbol_count = 0;
    pkt->total_size = sizeof(chunk_header_t);
    pkt->acked = false;
    pkt->sent_at = 0;
}

/* Add a symbol to an aggregated packet */
static bool agg_packet_add_symbol(agg_packet_t *pkt, const uint8_t *symbol, 
                                  size_t symbol_size) {
    if (!pkt || !symbol) return false;
    if (pkt->symbol_count >= DNSTUN_MAX_SYMBOLS_PER_PACKET) return false;
    if (symbol_size > DNSTUN_SYMBOL_SIZE) symbol_size = DNSTUN_SYMBOL_SIZE;
    
    memcpy(pkt->symbols[pkt->symbol_count], symbol, symbol_size);
    pkt->symbol_sizes[pkt->symbol_count] = (uint8_t)symbol_size;
    pkt->symbol_count++;
    pkt->total_size += symbol_size;
    
    return true;
}

/* Get the optimal packet size for a given MTU */
static size_t get_optimal_packet_size(uint16_t mtu, int symbol_size) {
    if (!g_cfg.packet_aggregation) {
        /* No aggregation - send single symbol */
        return sizeof(chunk_header_t) + symbol_size;
    }
    
    int symbols = calc_symbols_per_packet(mtu, symbol_size);
    size_t optimal = sizeof(chunk_header_t) + (symbols * symbol_size);
    
    /* Don't exceed MTU */
    if (optimal > mtu) {
        optimal = mtu;
    }
    
    return optimal;
}

/* Calculate packing efficiency (how well we fill the MTU) */
static double calc_packing_efficiency(uint16_t mtu, size_t payload_size) {
    if (mtu <= 0 || payload_size <= 0) return 0.0;
    double efficiency = (double)payload_size / (double)mtu;
    if (efficiency > 1.0) efficiency = 1.0;
    return efficiency * 100.0;
}

/* Encode multiple symbols into a packet (aggregation) */
static size_t encode_aggregated_packet(uint8_t *out_buf, size_t out_size,
                                       const uint8_t *data, size_t data_len,
                                       uint16_t mtu, uint16_t seq) {
    if (!out_buf || !data || data_len == 0 || mtu == 0) return 0;
    
    int symbol_size = g_cfg.symbol_size > 0 ? g_cfg.symbol_size : DNSTUN_SYMBOL_SIZE;
    size_t header_size = sizeof(chunk_header_t);
    
    if (out_size < header_size) return 0;
    
    /* Calculate how many symbols we can fit */
    size_t payload_space = mtu - header_size;
    int max_symbols = (int)(payload_space / symbol_size);
    if (max_symbols < 1) max_symbols = 1;
    if (max_symbols > g_cfg.max_symbols_per_packet) {
        max_symbols = g_cfg.max_symbols_per_packet;
    }
    
    /* Use aggregation if enabled */
    if (g_cfg.packet_aggregation && max_symbols > 1) {
        /* Aggregate multiple symbols */
        uint8_t *payload = out_buf + header_size;
        size_t offset = 0;
        int symbols_packed = 0;
        
        /* Pack symbols until we fill the MTU or run out of data */
        while (symbols_packed < max_symbols && offset < data_len) {
            size_t remaining = data_len - offset;
            size_t to_copy = (remaining > symbol_size) ? symbol_size : remaining;
            
            memcpy(payload + (symbols_packed * symbol_size), data + offset, to_copy);
            
            /* Zero-pad if necessary */
            if (to_copy < symbol_size) {
                memset(payload + (symbols_packed * symbol_size) + to_copy, 0, 
                       symbol_size - to_copy);
            }
            
            offset += to_copy;
            symbols_packed++;
        }
        
        size_t total_size = header_size + (symbols_packed * symbol_size);
        
        /* Set chunk header with new compact 4-byte format */
        chunk_header_t *hdr = (chunk_header_t *)out_buf;
        hdr->flags = 0;
        hdr->seq = seq;
        /* chunk_info: high nibble = chunk_total-1, low nibble = fec_k (0 for now) */
        chunk_set_info(&hdr->chunk_info, (uint8_t)symbols_packed, 0);
        
        return total_size;
    } else {
        /* No aggregation - send single symbol */
        size_t to_copy = (data_len > symbol_size) ? symbol_size : data_len;
        uint8_t *payload = out_buf + header_size;
        
        memcpy(payload, data, to_copy);
        
        chunk_header_t *hdr = (chunk_header_t *)out_buf;
        hdr->flags = 0;
        hdr->seq = seq;
        /* chunk_info: high nibble = 0 (chunk_total=1), low nibble = 0 (fec_k) */
        hdr->chunk_info = 0;
        
        return header_size + to_copy;
    }
}

/* Decode aggregated packet and extract symbols */
static int decode_aggregated_packet(uint8_t *symbols[], uint8_t sizes[],
                                   const uint8_t *packet, size_t packet_len,
                                   int max_symbols) {
    if (!packet || packet_len < sizeof(chunk_header_t) + 1) return 0;
    
    chunk_header_t *hdr = (chunk_header_t *)packet;
    int symbol_count = chunk_get_total(hdr->chunk_info);  /* high nibble + 1 */
    if (symbol_count > max_symbols) symbol_count = max_symbols;
    if (symbol_count > DNSTUN_MAX_SYMBOLS_PER_PACKET) symbol_count = DNSTUN_MAX_SYMBOLS_PER_PACKET;
    
    int symbol_size = g_cfg.symbol_size > 0 ? g_cfg.symbol_size : DNSTUN_SYMBOL_SIZE;
    const uint8_t *payload = packet + sizeof(chunk_header_t);
    size_t payload_len = packet_len - sizeof(chunk_header_t);
    
    for (int i = 0; i < symbol_count; i++) {
        if (i * symbol_size < payload_len) {
            if (symbols) {
                memcpy(symbols[i], payload + (i * symbol_size), symbol_size);
            }
            if (sizes) {
                sizes[i] = (uint8_t)((i + 1) * symbol_size <= payload_len) ? 
                           symbol_size : (uint8_t)(payload_len - (i * symbol_size));
            }
        }
    }
    
    return symbol_count;
}

/* Get MTU statistics with aggregation info */
static void log_aggregation_stats(void) {
    if (!g_cfg.packet_aggregation) {
        LOG_INFO("[Agg] Packet aggregation is disabled\n");
        return;
    }
    
    int symbol_size = g_cfg.symbol_size > 0 ? g_cfg.symbol_size : DNSTUN_SYMBOL_SIZE;
    
    LOG_INFO("[Agg] Packet Aggregation Statistics:\n");
    LOG_INFO("  Symbol size: %d bytes\n", symbol_size);
    LOG_INFO("  Max symbols/packet: %d\n", g_cfg.max_symbols_per_packet);
    
    /* Calculate stats per resolver */
    int total_resolvers = 0;
    int total_symbols = 0;
    double total_efficiency = 0.0;
    
    uv_mutex_lock(&g_pool.lock);
    for (int i = 0; i < g_pool.count; i++) {
        resolver_t *r = &g_pool.resolvers[i];
        if (r->state == RSV_ACTIVE && r->upstream_mtu > 0) {
            int symbols = calc_symbols_per_packet(r->upstream_mtu, symbol_size);
            size_t optimal_size = sizeof(chunk_header_t) + (symbols * symbol_size);
            double efficiency = calc_packing_efficiency(r->upstream_mtu, optimal_size);
            
            total_resolvers++;
            total_symbols += symbols;
            total_efficiency += efficiency;
        }
    }
    uv_mutex_unlock(&g_pool.lock);
    
    if (total_resolvers > 0) {
        LOG_INFO("  Average symbols/packet: %.1f\n", (double)total_symbols / total_resolvers);
        LOG_INFO("  Average efficiency: %.1f%%\n", total_efficiency / total_resolvers);
    }
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
            results[i].upstream_mtu = 0;
            results[i].downstream_mtu = 0;
            fire_test_probe(i, PROBE_TEST_EDNS_TXT, &results[i]);
            phase3_count++;
            if (phase3_count % 50 == 0) uv_run(g_loop, UV_RUN_NOWAIT);
        }
    }
    run_event_loop_ms(wait_ms);

    /* ─── Phase 4: MTU Binary Search Testing (client.py style) ─── */
    LOG_INFO("--- Phase 4: Binary search MTU testing ---\n");
    int phase4_count = 0;
    for (int i = 0; i < g_pool.count; i++) {
        resolver_t *r = &g_pool.resolvers[i];
        /* Test resolvers that passed Phase 1, 2, and 3 */
        if (results[i].longname_supported && 
            results[i].nxdomain_correct && 
            (results[i].edns_supported || results[i].txt_supported)) {
            
            /* Initialize MTU binary search state */
            init_mtu_binary_search(&results[i].up_mtu_search,
                                 0, g_cfg.max_upload_mtu > 0 ? g_cfg.max_upload_mtu : 512,
                                 30, g_cfg.min_upload_mtu, 
                                 g_cfg.mtu_test_retries > 0 ? g_cfg.mtu_test_retries : 2,
                                 true, 0);
            
            init_mtu_binary_search(&results[i].down_mtu_search,
                                 0, g_cfg.max_download_mtu > 0 ? g_cfg.max_download_mtu : 1200,
                                 30, g_cfg.min_download_mtu,
                                 g_cfg.mtu_test_retries > 0 ? g_cfg.mtu_test_retries : 2,
                                 false, results[i].upstream_mtu);
            
            /* Fire initial MTU test probes */
            int first_up_mtu = get_next_mtu_to_test(&results[i].up_mtu_search);
            if (first_up_mtu > 0) {
                fire_mtu_test_probe(i, PROBE_TEST_MTU_UP, &results[i], first_up_mtu);
                phase4_count++;
                if (phase4_count % 20 == 0) uv_run(g_loop, UV_RUN_NOWAIT);
            }
        }
    }
    if (phase4_count > 0) {
        LOG_INFO("Started %d MTU binary search tests\n", phase4_count);
        /* Run MTU tests with longer timeout for binary search */
        int mtu_wait_ms = (g_cfg.mtu_test_timeout_ms > 0) ? 
                          g_cfg.mtu_test_timeout_ms * 10 : 10000;
        run_event_loop_ms(mtu_wait_ms);
    }
    LOG_INFO("Phase 4 complete: MTU binary search testing finished\n");

    /* Final filter: promote resolvers that passed all three phases */
    int active = 0;
    for (int i = 0; i < g_pool.count; i++) {
        resolver_t *r = &g_pool.resolvers[i];
        
        /* Check if resolver passed all three phases */
        if (results[i].longname_supported && 
            results[i].nxdomain_correct && 
            (results[i].edns_supported || results[i].txt_supported)) {
            /* Update resolver with discovered MTU from binary search */
            if (results[i].up_mtu_search.optimal > 0) {
                r->upstream_mtu = results[i].up_mtu_search.optimal;
            } else if (results[i].upstream_mtu > 0) {
                r->upstream_mtu = results[i].upstream_mtu;
            } else {
                r->upstream_mtu = 512; /* Default MTU */
            }
            
            /* Update downstream MTU from binary search */
            if (results[i].down_mtu_search.optimal > 0) {
                r->downstream_mtu = results[i].down_mtu_search.optimal;
            } else {
                r->downstream_mtu = r->upstream_mtu * 2; /* Default downstream */
                if (r->downstream_mtu > 1200) r->downstream_mtu = 1200;
            }
            
            r->edns0_supported = true;
            rpool_set_state(&g_pool, i, RSV_ACTIVE);
            active++;
            
            /* Clean up MTU binary search state */
            free_mtu_binary_search(&results[i].up_mtu_search);
            free_mtu_binary_search(&results[i].down_mtu_search);
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
            LOG_INFO("Resolver %s state=%s UpMTU=%u DownMTU=%u RTT=%.1fms\n",
                     r->ip, state_str, r->upstream_mtu, r->downstream_mtu, r->rtt_ms);
        }
    }

    /* Log MTU statistics for all active resolvers */
    int up_mtu_min = 9999, up_mtu_max = 0;
    int down_mtu_min = 9999, down_mtu_max = 0;
    for (int i = 0; i < g_pool.count; i++) {
        resolver_t *r = &g_pool.resolvers[i];
        if (r->state == RSV_ACTIVE) {
            if (r->upstream_mtu > 0) {
                if (r->upstream_mtu < up_mtu_min) up_mtu_min = r->upstream_mtu;
                if (r->upstream_mtu > up_mtu_max) up_mtu_max = r->upstream_mtu;
            }
            if (r->downstream_mtu > 0) {
                if (r->downstream_mtu < down_mtu_min) down_mtu_min = r->downstream_mtu;
                if (r->downstream_mtu > down_mtu_max) down_mtu_max = r->downstream_mtu;
            }
        }
    }
    if (up_mtu_min < 9999) {
        LOG_INFO("Upstream MTU range: %d - %d\n", up_mtu_min, up_mtu_max);
    }
    if (down_mtu_min < 9999) {
        LOG_INFO("Downstream MTU range: %d - %d\n", down_mtu_min, down_mtu_max);
    }

    /* Log packet aggregation statistics */
    log_aggregation_stats();

    /* Clean up any remaining MTU binary search state */
    for (int i = 0; i < g_pool.count; i++) {
        free_mtu_binary_search(&results[i].up_mtu_search);
        free_mtu_binary_search(&results[i].down_mtu_search);
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
    /* DEBUG: Log data being sent to SOCKS5 client */
    fprintf(stderr, "[DEBUG] socks5_send: sending %zu bytes to SOCKS5 client\n", len);
    if (len > 0) {
        fprintf(stderr, "[DEBUG] First 16 bytes: ");
        for (size_t i = 0; i < len && i < 16; i++) {
            fprintf(stderr, "%02x ", data[i]);
        }
        fprintf(stderr, "\n");
    }

    uv_write_t *w = malloc(sizeof(*w) + len);
    if (!w) return;

    /* Payload lives immediately after the write request in the same alloc. */
    uint8_t *copy = (uint8_t*)(w + 1);
    memcpy(copy, data, len);
    uv_buf_t buf = uv_buf_init((char*)copy, (unsigned)len);
    uv_write(w, (uv_stream_t*)&c->tcp, &buf, 1, on_socks5_write_done);
}

/* ────────────────────────────────────────────── */
/*  Downstream Reordering Buffer Functions        */
/* ────────────────────────────────────────────── */

/* Check if seq is within the reorder window relative to expected_seq */
static inline bool is_within_window(uint16_t seq, uint16_t expected, int window) {
    /* Handle wrap-around using modulo arithmetic */
    if (expected < window) {
        /* Near wrap-around: low values are "ahead" */
        if (seq >= (uint16_t)(expected + window) || seq < expected) {
            return false;
        }
    } else {
        /* Normal case */
        uint16_t diff = seq - expected;
        return diff < (uint16_t)window;
    }
    return true;
}

/* Initialize reorder buffer for a session */
static void reorder_buffer_init(reorder_buffer_t *rb) {
    memset(rb, 0, sizeof(*rb));
    rb->expected_seq = 0;
    for (int i = 0; i < RX_REORDER_WINDOW; i++) {
        rb->slots[i].valid = false;
        rb->slots[i].data = NULL;
        rb->slots[i].len = 0;
    }
}

/* Free all buffered data in reorder buffer */
static void reorder_buffer_free(reorder_buffer_t *rb) {
    for (int i = 0; i < RX_REORDER_WINDOW; i++) {
        if (rb->slots[i].valid && rb->slots[i].data) {
            free(rb->slots[i].data);
        }
        rb->slots[i].valid = false;
        rb->slots[i].data = NULL;
    }
}

/* Find the slot index for a given sequence number */
static int reorder_buffer_find_slot(reorder_buffer_t *rb, uint16_t seq) {
    int offset = (int)(seq - rb->expected_seq);
    if (offset < 0) offset += 65536;  /* Handle wrap-around */
    return offset;
}

/* Insert a packet into the reorder buffer */
static bool reorder_buffer_insert(reorder_buffer_t *rb, uint16_t seq, 
                                  const uint8_t *data, size_t len) {
    int offset = reorder_buffer_find_slot(rb, seq);
    
    if (offset < 0 || offset >= RX_REORDER_WINDOW) {
        /* Outside window - either too old or too far ahead */
        if (offset < 0) {
            /* Too old - drop */
            LOG_DEBUG("Reorder: dropping old packet seq=%u (expected=%u)\n", 
                     seq, rb->expected_seq);
            return false;
        }
        /* Too far ahead - skip ahead expected_seq */
        LOG_DEBUG("Reorder: jumping expected_seq from %u to %u\n", 
                 rb->expected_seq, seq);
        reorder_buffer_free(rb);
        rb->expected_seq = seq;
        offset = 0;
    }
    
    /* Check if slot is already occupied (duplicate) */
    if (rb->slots[offset].valid) {
        LOG_DEBUG("Reorder: duplicate packet seq=%u, dropping\n", seq);
        return false;
    }
    
    /* Allocate and copy data */
    rb->slots[offset].data = malloc(len);
    if (!rb->slots[offset].data) {
        LOG_ERR("Reorder: failed to allocate buffer for seq=%u\n", seq);
        return false;
    }
    memcpy(rb->slots[offset].data, data, len);
    rb->slots[offset].len = len;
    rb->slots[offset].seq = seq;
    rb->slots[offset].received_at = time(NULL);
    rb->slots[offset].valid = true;
    
    LOG_DEBUG("Reorder: buffered seq=%u at offset=%d (expected=%u)\n", 
             seq, offset, rb->expected_seq);
    return true;
}

/* Flush consecutive packets starting from expected_seq
 * Returns number of packets flushed (including 0-byte ACKs). */
static int reorder_buffer_flush(reorder_buffer_t *rb, uint8_t *out_buf,
                                  size_t out_cap, size_t *out_len) {
    int packets = 0;
    size_t total = 0;
    *out_len = 0;

    /* Flush while we have the next expected packet buffered at offset 0.
     * Fix: Changed from "while (expected_seq != 0)" which prevented flushing
     * when expected_seq was 0 (start of session after ACK). */
    while (rb->slots[0].valid) {  /* Continue while we have the next expected packet */
        /* Find if there's a valid slot at any position */
        int found_offset = -1;
        for (int i = 0; i < RX_REORDER_WINDOW; i++) {
            if (rb->slots[i].valid) {
                found_offset = i;
                break;
            }
        }

        /* If next slot (offset 0) is not valid, we're waiting for a packet */
        if (!rb->slots[0].valid) {
            break;
        }
        
        rx_buffer_slot_t *slot = &rb->slots[0];
        
        /* Check if we have room in output buffer */
        if (total + slot->len > out_cap) {
            LOG_DEBUG("Reorder: output buffer full, flushing %zu bytes\n", total);
            break;
        }
        
        /* Copy to output */
        memcpy(out_buf + total, slot->data, slot->len);
        total += slot->len;
        
        /* Update expected sequence and metrics */
        rb->expected_seq++;
        packets++;
        
        /* Free this slot and compact remaining slots */
        free(slot->data);
        slot->valid = false;
        
        /* Shift remaining slots down */
        for (int i = 1; i < RX_REORDER_WINDOW; i++) {
            if (rb->slots[i].valid) {
                /* Find first empty slot and move this one there */
                int empty = i - 1;
                while (empty >= 0 && !rb->slots[empty].valid) empty--;
                empty++;  /* First empty position */
                if (empty != i) {
                    memmove(&rb->slots[empty], &rb->slots[i], sizeof(rx_buffer_slot_t));
                    memset(&rb->slots[i], 0, sizeof(rx_buffer_slot_t));
                }
            }
        }
    }
    
    *out_len = total;
    return packets;
}

/* Flush received data from server to SOCKS5 client */
static void socks5_flush_recv_buf(socks5_client_t *c) {
    if (c->session_idx < 0 || c->session_idx >= DNSTUN_MAX_SESSIONS) return;
    session_t *s = &g_sessions[c->session_idx];
    if (s->closed || s->recv_len == 0) return;
    
    /* Send all pending data to SOCKS5 client */
    socks5_send(c, s->recv_buf, s->recv_len);
    
    /* Clear the buffer */
    s->recv_len = 0;
}

/* Returns number of bytes consumed from data buffer, or 0 if incomplete */
static size_t socks5_handle_data(socks5_client_t *c,
                               const uint8_t *data, size_t len)
{
    /* SOCKS5 state machine */
    if (c->state == 0) {
        /* Auth method negotiation: reply NO AUTH if supported by client
         * SOCKS5 greeting: VER(1) + NMETHODS(1) + METHODS(NMETHODS bytes)
         * Total length = 2 + NMETHODS */
        if (len >= 2 && data[0] == 0x05) {
            uint8_t nmethods = data[1];
            size_t greeting_len = 2 + nmethods;
            if (len >= greeting_len) {
                bool no_auth_supported = false;
                for (int i = 0; i < nmethods; i++) {
                    if (data[2 + i] == 0x00) {
                        no_auth_supported = true;
                        break;
                    }
                }

                if (no_auth_supported) {
                    uint8_t reply[2] = {0x05, 0x00};
                    socks5_send(c, reply, 2);
                    c->state = 1;
                } else {
                    /* No acceptable methods */
                    uint8_t reply[2] = {0x05, 0xFF};
                    socks5_send(c, reply, 2);
                    uv_close((uv_handle_t*)&c->tcp, on_socks5_close);
                }
                return greeting_len;  /* Consumed full greeting */
            }
        }
        /* Need more data */
        return 0;
    }

    if (c->state == 1) {
        /* CONNECT request - determine required length based on address type */
        uint8_t atype = (len >= 4) ? data[3] : 0;
        size_t min_len;
        
        if (atype == 0x01) {
            min_len = 10;  /* IPv4: VER + CMD + RSV + ATYP(1) + IP(4) + PORT(2) */
        } else if (atype == 0x03) {
            /* Domain: need dlen byte to know total length */
            if (len < 5) return 0;  /* Need at least dlen byte */
            uint8_t dlen = data[4];
            min_len = 5 + dlen + 2;  /* +1 dlen + dlen bytes + 2 port */
        } else if (atype == 0x04) {
            min_len = 22;  /* IPv6: VER + CMD + RSV + ATYP(1) + IP(16) + PORT(2) */
        } else {
            /* Unsupported address type or malformed request */
            uint8_t err[10] = {0x05, 0x08, 0x00, 0x01, 0,0,0,0,0,0};
            socks5_send(c, err, 10);
            uv_close((uv_handle_t*)&c->tcp, on_socks5_close);
            return len;
        }
        
        /* Check if we have enough data for CONNECT request */
        if (len < min_len) return 0;
        
        /* Validate SOCKS version and command */
        if (data[0] != 0x05) return 0;
        if (data[1] != 0x01) { /* Only CONNECT is supported */
            uint8_t err[10] = {0x05, 0x07, 0x00, 0x01, 0,0,0,0,0,0}; /* Command not supported */
            socks5_send(c, err, 10);
            uv_close((uv_handle_t*)&c->tcp, on_socks5_close);
            return min_len;
        }

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
            return min_len;  /* Consumed but errored */
        }

        session_t *sess = &g_sessions[session_idx];
        memset(sess, 0, sizeof(*sess));
        sess->session_id = get_unused_session_id();
        sess->established = true;
        sess->closed      = false;
        sess->last_active = time(NULL);
        
        /* Initialize downstream reorder buffer */
        reorder_buffer_init(&sess->reorder_buf);

        /* Parse target - ATYP already validated above */
        if (atype == 0x01) { /* IPv4 */
            snprintf(sess->target_host, sizeof(sess->target_host),
                     "%d.%d.%d.%d", data[4],data[5],data[6],data[7]);
            sess->target_port = (uint16_t)((data[8]<<8)|data[9]);
        } else if (atype == 0x03) { /* Domain */
            uint8_t dlen = data[4];
            if (dlen >= sizeof(sess->target_host)) return min_len;
            memcpy(sess->target_host, data+5, dlen);
            sess->target_host[dlen] = '\0';
            sess->target_port = (uint16_t)((data[5+dlen]<<8)|data[6+dlen]);
        } else if (atype == 0x04) { /* IPv6 */
            char ipv6_str[46];
            inet_ntop(AF_INET6, data + 4, ipv6_str, sizeof(ipv6_str));
            strncpy(sess->target_host, ipv6_str, sizeof(sess->target_host) - 1);
            sess->target_port = (uint16_t)((data[20]<<8)|data[21]);
        }

        c->session_idx = session_idx;
        c->state = 2;
        sess->client_ptr = c;  /* Link session back to SOCKS5 client */
        sess->socks5_connected = false;  /* Don't ack until server confirms */
        
        /* Update TUI stats */
        g_stats.socks5_total_conns++;
        snprintf(g_stats.socks5_last_target, sizeof(g_stats.socks5_last_target),
                 "%s:%d", sess->target_host, sess->target_port);
        
        g_stats.active_sessions++;

        LOG_INFO("SOCKS5 CONNECT %s:%d (session %d) - waiting for server ack\n",
                 sess->target_host, sess->target_port, session_idx);

        /* Queue the CONNECT request to be sent to the server.
         * The server needs this to parse the target and establish upstream connection. */
        if (min_len > 0) {
            size_t new_cap = min_len + 4096;
            if (new_cap > MAX_SESSION_BUFFER) new_cap = MAX_SESSION_BUFFER;
            uint8_t *new_buf = realloc(sess->send_buf, new_cap);
            if (new_buf) {
                sess->send_buf = new_buf;
                sess->send_cap = new_cap;
                memcpy(sess->send_buf, data, min_len);
                sess->send_len = min_len;
            } else {
                LOG_ERR("state 1: failed to alloc send_buf for CONNECT request\n");
            }
        } else {
            LOG_ERR("state 1: min_len is 0, not queuing CONNECT request\n");
        }

        /* Don't send success yet - wait for server acknowledgment.
         * The SOCKS5 success will be sent when we receive the first upstream response. */
        return min_len;
    }

    if (c->state == 2) {
        /* Tunnel data → queue in session send buffer */
        session_t *sess = &g_sessions[c->session_idx];
        sess->last_active = time(NULL);

        /* Grow send buffer with resource limit check */
        size_t new_len = sess->send_len + len;
        if (new_len > sess->send_cap) {
            /* Enforce maximum buffer size to prevent memory exhaustion */
            if (sess->send_len >= MAX_SESSION_BUFFER) {
                LOG_ERR("Session %d: send buffer limit reached (%zu bytes)\n",
                        c->session_idx, sess->send_len);
                /* Drop oldest data to make room */
                size_t drop_len = (len > sess->send_len) ? sess->send_len : len;
                memmove(sess->send_buf, sess->send_buf + drop_len, sess->send_len - drop_len);
                sess->send_len -= drop_len;
                new_len = sess->send_len + len;
            }
            size_t new_cap = new_len + 4096;
            /* Cap at MAX_SESSION_BUFFER to prevent unbounded growth */
            if (new_cap > MAX_SESSION_BUFFER) new_cap = MAX_SESSION_BUFFER;
            uint8_t *new_buf = realloc(sess->send_buf, new_cap);
            if (!new_buf) {
                LOG_ERR("Session %d: failed to grow send buffer\n", c->session_idx);
                return 0;
            }
            sess->send_buf = new_buf;
            sess->send_cap = new_cap;
        }
        memcpy(sess->send_buf + sess->send_len, data, len);
        sess->send_len += len;
        g_stats.tx_total += len;
        g_stats.tx_bytes_sec += len;
        
        return len;  /* Consume all tunnel data */
    }
    
    return 0;  /* Unknown state */
}

static void on_socks5_read(uv_stream_t *s, ssize_t nread, const uv_buf_t *buf) {
    socks5_client_t *c = s->data;

    if (nread <= 0) {
        if (!uv_is_closing((uv_handle_t*)s))
            uv_close((uv_handle_t*)s, on_socks5_close);
        return;
    }

    /* Accumulate incoming data in buffer to handle fragmentation.
     * SOCKS5 handshake packets may arrive fragmented across multiple reads.
     * Note: libuv already wrote data to c->buf + c->buf_len via on_socks5_alloc. */
    size_t incoming = (size_t)nread;
    if (c->buf_len + incoming > sizeof(c->buf)) {
        c->buf_len = 0;  /* Reset on overflow - malformed packet */
    } else {
        /* Data is already in place via on_socks5_alloc, just update length */
        c->buf_len += incoming;
    }

    /* Process accumulated data in loop - handshake may complete across multiple reads */
    while (c->buf_len > 0) {
        size_t consumed = socks5_handle_data(c, c->buf, c->buf_len);
        
        /* If no progress was made, break to avoid infinite loop (incomplete packet) */
        if (consumed == 0) break;
        
        /* Shift remaining data to front of buffer */
        if (consumed < c->buf_len) {
            memmove(c->buf, c->buf + consumed, c->buf_len - consumed);
        }
        c->buf_len -= consumed;
    }
}

static void on_socks5_alloc(uv_handle_t *h, size_t sz, uv_buf_t *buf) {
    socks5_client_t *c = h->data;
    (void)sz;
    /* Return pointer to end of current buffer content to avoid overwriting existing data */
    buf->base = (char*)(c->buf + c->buf_len);
    buf->len  = sizeof(c->buf) - c->buf_len;
}

static void on_socks5_connection(uv_stream_t *server, int status) {
    if (status < 0) return;

    socks5_client_t *c = calloc(1, sizeof(*c));
    if (!c) return;
    c->session_idx = -1;
    c->state = 0;

    uv_tcp_init(g_loop, &c->tcp);
    c->tcp.data = c;

    /* Enable TCP_NODELAY to minimize latency for interactive traffic */
    uv_tcp_nodelay(&c->tcp, 1);

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
    uint8_t          sendbuf[4096]; /* Larger buffer for EDNS0 / multi-RR queries */
    size_t           sendlen;
    uint8_t          recvbuf[4096]; /* Larger buffer for EDNS0 / multi-RR replies */
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

    /* DEBUG: Log received data size and buffer capacity */
    if (nread > 0) {
        fprintf(stderr, "[DEBUG] on_dns_recv: received %zd bytes (recvbuf size=%zu)\n",
                nread, sizeof(q->recvbuf));
    }

    if (nread > 0) {
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
            /* Walk answer section for TXT records */
            for (int i = 0; i < (int)resp->ancount; i++) {
                dns_answer_t *ans = &resp->answers[i];
                if (ans->generic.type == RR_TXT && ans->txt.len > 0) {
                    /* Check if this is a SYNC response (comma-separated IPs)
                     * A valid SYNC response should look like IP addresses:
                     * e.g., "1.2.3.4,5.6.7.8" - check first part looks like IP
                     */
                    bool is_sync = false;
                    if (ans->txt.len > 7 && strchr(ans->txt.text, ',')) {
                        /* Check if first part looks like an IP (X.X.X.X format) */
                        char first_part[16] = {0};
                        const char *comma = strchr(ans->txt.text, ',');
                        size_t first_len = comma ? (size_t)(comma - ans->txt.text) : ans->txt.len;
                        if (first_len < sizeof(first_part)) {
                            memcpy(first_part, ans->txt.text, first_len);
                            first_part[first_len] = '\0';
                            /* Simple IP check: contains digits and at least 3 dots */
                            int dots = 0;
                            bool has_digit = false;
                            for (size_t k = 0; k < first_len; k++) {
                                if (first_part[k] == '.') dots++;
                                if (first_part[k] >= '0' && first_part[k] <= '9') has_digit = true;
                            }
                            is_sync = (dots >= 3 && has_digit);
                        }
                    }
                    
                    if (is_sync) {
                        char *ips = strndup(ans->txt.text, ans->txt.len);
                        char *tok = strtok(ips, ",");
                        while (tok) {
                            rpool_add(&g_pool, tok);
                            tok = strtok(NULL, ",");
                        }
                        free(ips);
                        LOG_INFO("Swarm: synced new resolvers from server\n");
                    } else {
                        /* Decode base64 response from server (server sends base64 by default) */
                        /* DEBUG: Log TXT record size before decoding */
                        fprintf(stderr, "[DEBUG] TXT record: len=%zu text='%.*s'\n",
                                ans->txt.len, (int)ans->txt.len, ans->txt.text);

                        uint8_t decoded[4096];
                        ptrdiff_t decoded_len = base64_decode(decoded, ans->txt.text, ans->txt.len);
                        if (decoded_len < 0) {
                            fprintf(stderr, "[DEBUG] base64_decode FAILED for TXT len=%zu\n", ans->txt.len);
                            continue;
                        }
                        fprintf(stderr, "[DEBUG] base64_decode: input=%zu output=%td\n",
                                ans->txt.len, decoded_len);
                        
                        /* Unified packet handling flow:
                         * 1. Detect packet type (ACK vs Data) and parse header.
                         * 2. Insert into reorder buffer to maintain strict sequencing.
                         * 3. Flush the buffer and process sequentially.
                         * 4. Trigger SOCKS5 success only when the ACK byte is flushed.
                         */
                        {
                            int sidx = q->session_idx;
                            if (sidx >= 0 && sidx < DNSTUN_MAX_SESSIONS && !g_sessions[sidx].closed) {
                                session_t *s = &g_sessions[sidx];
                                const uint8_t *payload = decoded;
                                size_t payload_len = (size_t)decoded_len;
                                uint16_t seq = 0;
                                bool has_seq = false;
                                bool is_ack = false;

                                /* Parse header if present */
                                if (decoded_len >= sizeof(server_response_header_t)) {
                                    server_response_header_t hdr;
                                    memcpy(&hdr, decoded, sizeof(hdr));
                                    
                                    if (hdr.session_id != s->session_id) continue;

                                    has_seq = (hdr.flags & RESP_FLAG_HAS_SEQ) != 0;
                                    if (has_seq) {
                                        seq = hdr.seq;
                                        payload = decoded + sizeof(hdr);
                                        payload_len = (size_t)(decoded_len - sizeof(hdr));
                                    }
                                }

                                /* Check for ACK byte in payload */
                                is_ack = (payload_len == 1 && payload[0] == '\0');

                                /* Treat legacy ACKs (no header) as seq=0 */
                                if (is_ack && !has_seq) {
                                    seq = 0;
                                    has_seq = true;
                                }

                                if (has_seq) {
                                    /* Always buffer sequenced packets in reorder window to prevent gaps */
                                    reorder_buffer_insert(&s->reorder_buf, seq, payload, payload_len);

                                    /* Drain all consecutive ready packets from the buffer */
                                    uint8_t flush_buf[16384];
                                    size_t flush_len = 0;
                                    /* Loop while packets are being flushed from the reorder buffer */
                                    while (reorder_buffer_flush(&s->reorder_buf, flush_buf, sizeof(flush_buf), &flush_len) > 0) {
                                        size_t data_start = 0;
                                        
                                        /* Detect the ACK/status byte at the start of the sequence */
                                        if (flush_len >= 1 && !s->socks5_connected) {
                                            uint8_t status_byte = flush_buf[0];
                                            if (s->client_ptr) {
                                                socks5_client_t *c = (socks5_client_t*)s->client_ptr;
                                                if (status_byte == 0x00) {
                                                    /* Success: Send SOCKS5 success reply (Address Type IPv4, 0.0.0.0:0) */
                                                    uint8_t ok[10] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
                                                    socks5_send(c, ok, 10);
                                                    s->socks5_connected = true;
                                                    g_stats.socks5_last_error = 0;
                                                    LOG_INFO("Session %d: SOCKS5 success (ACK processed in sequence)\n", sidx);
                                                } else {
                                                    /* Mapped Error: status_byte from server mapped to SOCKS5 reply field */
                                                    /* 0x01=General, 0x02=Not allowed, 0x03=Net unreachable, 
                                                     * 0x04=Host unreachable, 0x05=Refused, etc. */
                                                    uint8_t err[10] = {0x05, status_byte, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
                                                    socks5_send(c, err, 10);
                                                    g_stats.socks5_total_errors++;
                                                    g_stats.socks5_last_error = status_byte;
                                                    LOG_WARN("Session %d: SOCKS5 error %02x from server\n", sidx, status_byte);
                                                    uv_close((uv_handle_t*)&c->tcp, on_socks5_close);
                                                }
                                            }
                                            data_start = 1; /* Skip the status byte; don't send to application */
                                        }

                                        size_t data_len = flush_len - data_start;
                                        if (data_len > 0) {
                                            /* Append to session receive buffer */
                                            size_t need = s->recv_len + data_len;
                                            if (need > s->recv_cap) {
                                                size_t new_cap = (need + 8191) & ~4095; /* Round up to 4KB */
                                                if (new_cap > MAX_SESSION_BUFFER) new_cap = MAX_SESSION_BUFFER;
                                                uint8_t *new_buf = realloc(s->recv_buf, new_cap);
                                                if (new_buf) {
                                                    s->recv_buf = new_buf;
                                                    s->recv_cap = new_cap;
                                                }
                                            }
                                            if (s->recv_cap >= s->recv_len + data_len) {
                                                memcpy(s->recv_buf + s->recv_len, flush_buf + data_start, data_len);
                                                s->recv_len += data_len;
                                                g_stats.rx_total += data_len;
                                                g_stats.rx_bytes_sec += data_len;
                                            }
                                        }
                                        /* Immediately push flushed data to the SOCKS5 client */
                                        if (s->client_ptr) {
                                            socks5_flush_recv_buf((socks5_client_t*)s->client_ptr);
                                        }
                                    }
                                } else if (payload_len > 0) {
                                    /* Emergency fallback for non-sequenced packets (should not occur) */
                                    size_t need = s->recv_len + payload_len;
                                    if (need > s->recv_cap) {
                                        size_t new_cap = (need + 4096);
                                        if (new_cap > MAX_SESSION_BUFFER) new_cap = MAX_SESSION_BUFFER;
                                        uint8_t *new_buf = realloc(s->recv_buf, new_cap);
                                        if (new_buf) {
                                            s->recv_buf = new_buf;
                                            s->recv_cap = new_cap;
                                        }
                                    }
                                    if (s->recv_cap >= s->recv_len + payload_len) {
                                        memcpy(s->recv_buf + s->recv_len, payload, payload_len);
                                        s->recv_len += payload_len;
                                        g_stats.rx_total += payload_len;
                                        g_stats.rx_bytes_sec += payload_len;
                                    }
                                    if (s->client_ptr) socks5_flush_recv_buf((socks5_client_t*)s->client_ptr);
                                }
                            }
                        }
                    }
                    g_stats.queries_recv++;
                    g_stats.last_server_rx_ms = uv_hrtime() / 1000000ULL;
                    if (!g_stats.server_connected) {
                        g_stats.server_connected = 1;
                        LOG_INFO("Server connection established\n");
                    }
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
   'seq' is the actual sequence number of this FEC symbol.
   Fix: Fall back to dead resolvers if no active resolvers available. */
static void fire_dns_chunk_symbol(int session_idx, uint16_t seq,
                                  const uint8_t *payload, size_t paylen,
                                  int total_symbols)
{
    int ridx = rpool_next(&g_pool);
    
    /* If no active resolver, try dead ones as fallback (desperation mode).
     * This allows tunnel traffic even when all resolvers have been marked dead
     * during initialization phase but might still work intermittently. */
    if (ridx < 0) {
        uv_mutex_lock(&g_pool.lock);
        if (g_pool.dead_count > 0) {
            ridx = g_pool.dead[rand() % g_pool.dead_count];
        }
        uv_mutex_unlock(&g_pool.lock);
    }
    
    if (ridx < 0) {
        LOG_ERR("fire_dns_chunk_symbol: no resolvers available at all (session_idx=%d, seq=%u)\n",
                session_idx, seq);
        g_stats.queries_dropped++;
        return;
    }

    resolver_t *r = &g_pool.resolvers[ridx];

    dns_query_ctx_t *q = calloc(1, sizeof(*q));
    if (!q) return;
    q->resolver_idx = ridx;
    q->session_idx  = session_idx;
    q->seq          = seq;

    session_t *sess = &g_sessions[session_idx];

    /* Build chunk header (new compact 4-byte format) */
    chunk_header_t hdr = {0};
    hdr.flags          = (g_cfg.encryption ? CHUNK_FLAG_ENCRYPTED : 0) | CHUNK_FLAG_COMPRESSED;
    if (paylen == 0) hdr.flags |= CHUNK_FLAG_POLL; /* poll flag */
    if (total_symbols > 0) hdr.flags |= CHUNK_FLAG_FEC; /* fec flag */
    
    /* Session ID in bits 4-7 of flags */
    chunk_set_session_id(&hdr, (uint8_t)session_idx);
    
    hdr.seq = seq;
    
    /* chunk_info: high nibble = chunk_total-1, low nibble = fec_k */
    uint8_t chunk_total = (uint8_t)(total_symbols > 0 ? total_symbols : 1);
    uint8_t fec_k = (uint8_t)(r->fec_k > 15 ? 15 : r->fec_k);
    chunk_set_info(&hdr.chunk_info, chunk_total, fec_k);

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

    uv_timer_init(g_loop, &q->timer);
    q->timer.data = q;
    uv_timer_start(&q->timer, on_dns_timeout, 5000, 0);  /* 5 second timeout */

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
        uv_close((uv_handle_t*)&q->timer, on_dns_query_close);
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
                if (eret.error) { LOG_ERR("Encryption failed\n"); codec_free_result(&cret); continue; }
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
            if (g_cfg.encryption) codec_free_result(&eret);
            codec_free_result(&cret);
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
    
    /* Broadcast telemetry to connected management clients */
    if (g_mgmt) {
        mgmt_broadcast_telemetry(g_mgmt, &g_stats);
    }
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
    static char auto_config_path[2048] = {0};
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

    /* Open debug log file */
    g_debug_log = fopen("/tmp/qnsdns_client.log", "a");
    if (g_debug_log) {
        fprintf(g_debug_log, "\n=== Client started at ");
        time_t now = time(NULL);
        fprintf(g_debug_log, "%s", ctime(&now));
        fflush(g_debug_log);
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
    g_tui.send_debug_cb = send_debug_packet;  /* Register debug packet callback */

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

    /* Management server for headless TUI connections */
    {
        mgmt_config_t mgmt_cfg = {0};
        strncpy(mgmt_cfg.bind_addr, "127.0.0.1", sizeof(mgmt_cfg.bind_addr) - 1);
        mgmt_cfg.port = 9090;
        mgmt_cfg.telemetry_interval_ms = 1000;
        mgmt_cfg.callbacks.on_connect = NULL;
        mgmt_cfg.callbacks.on_disconnect = NULL;
        mgmt_cfg.callbacks.on_command = NULL;
        g_mgmt = mgmt_server_create(g_loop, &mgmt_cfg);
        if (g_mgmt) {
            mgmt_server_start(g_mgmt);
            LOG_INFO("Management: 127.0.0.1:9090 (connect TUI here)\n");
        }
    }

    /* Resolver init phase (probes resolvers, runs loop for ~3s) */
    resolver_init_phase();

    /* Bind STDIN for TUI */
    uv_tty_init(g_loop, &g_tty, 0, 1);
    uv_tty_set_mode(&g_tty, UV_TTY_MODE_RAW);
    uv_read_start((uv_stream_t*)&g_tty, on_tty_alloc, on_tty_read);

    /* Run event loop */
    uv_run(g_loop, UV_RUN_DEFAULT);

    /* Cleanup management server */
    if (g_mgmt) {
        mgmt_server_destroy(g_mgmt);
    }
    tui_shutdown(&g_tui);
    resolvers_save();   /* persist final resolver list on clean exit */
    rpool_destroy(&g_pool);
    codec_pool_shutdown();  /* Shutdown buffer pool */

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

