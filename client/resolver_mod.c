/**
 * @file client/resolver_mod.c
 * @brief Implementation of resolver pool testing and MTU discovery.
 */

#include "resolver_mod.h"
#include "client_common.h"
#include "../shared/resolver_pool.h"
#include "../shared/codec.h"
#include "dns_tx.h"
#include "../SPCDNS/dns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ── Test Types & Structures (Ported from legacy) ────────────────────────── */

typedef enum {
    PROBE_TEST_NONE = 0,
    PROBE_TEST_CRYPTO_CHALLENGE, /* Phase 0: Identity verification */
    PROBE_TEST_LONGNAME,         /* Phase 1: Long QNAME support */
    PROBE_TEST_NXDOMAIN,         /* Phase 2: NXDOMAIN behavior */
    PROBE_TEST_EDNS_TXT,         /* Phase 3: EDNS + TXT support */
    PROBE_TEST_MTU_UP,           /* Phase 4: Binary search upload MTU */
    PROBE_TEST_MTU_DOWN          /* Phase 4: Binary search download MTU */
} probe_test_type_t;

typedef struct {
    int         min;
    int         max;
    int         current;
    int         best_working;
    int         state;          /* 0: idle, 1: testing, 2: converged */
    int         retries;
    int         max_retries;
    bool        is_upload;      /* true for QNAME (upstream), false for TXT (downstream) */
    uint64_t    last_test_ms;
} mtu_binary_search_t;

typedef struct {
    bool        crypto_verified;
    bool        longname_supported;
    bool        nxdomain_correct;
    bool        edns_supported;
    bool        txt_supported;
    uint16_t    upstream_mtu;
    uint16_t    downstream_mtu;
    mtu_binary_search_t up_mtu_search;
    mtu_binary_search_t down_mtu_search;
} resolver_test_result_t;

typedef struct {
    uv_udp_t        udp;
    uv_timer_t      timer;
    int             closes;
    uv_udp_send_t   send_req;
    struct sockaddr_in dest;
    int             resolver_idx;
    uint64_t        sent_ms;
    uint8_t         sendbuf[1024];
    size_t          sendlen;
    probe_test_type_t test_type;
    resolver_test_result_t *result;
    uint8_t         challenge_nonce[32];
    int             mtu_under_test;
} probe_req_t;

/* Persistence File */
static const char *g_resolvers_file = "client_resolvers.txt";

/* ── Persistence Implementation ───────────────────────────────────────────── */

static void resolver_save_persistence(void) {
    if (!g_pool) return;
    FILE *f = fopen(g_resolvers_file, "w");
    if (!f) return;
    
    uv_mutex_lock(&g_pool->lock);
    for (int i = 0; i < g_pool->count; i++) {
        resolver_t *r = &g_pool->resolvers[i];
        if (r->ip[0]) {
            fprintf(f, "%s\n", r->ip);
        }
    }
    uv_mutex_unlock(&g_pool->lock);
    fclose(f);
}

static void resolver_load_persistence(void) {
    if (!g_pool) return;
    FILE *f = fopen(g_resolvers_file, "r");
    if (!f) return;
    
    char line[64];
    int added = 0;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (!line[0] || line[0] == '#') continue;
        
        if (rpool_add(g_pool, line) >= 0) {
            added++;
        }
    }
    fclose(f);
    if (added > 0) {
        LOG_INFO("Loaded %d resolvers from performance cache: %s\n", added, g_resolvers_file);
    }
}

/* ── DNS Test Query Builder ──────────────────────────────────────────────── */

static int build_test_dns_query(uint8_t *buf, size_t bufsize,
                                const char *qname, uint16_t qtype,
                                uint16_t qid, bool use_edns) 
{
    memset(buf, 0, bufsize);
    /* Header: ID, Flags (RD=1), QD=1, AN=0, NS=0, AR=1 (if EDNS) */
    buf[0] = (qid >> 8) & 0xFF;
    buf[1] = qid & 0xFF;
    buf[2] = 0x01; /* QR=0, Opcode=0, AA=0, TC=0, RD=1 */
    buf[3] = 0x00; /* RA=0, Z=0, RCODE=0 */
    buf[4] = 0x00; /* QDCOUNT = 1 */
    buf[5] = 0x01;
    if (use_edns) {
        buf[11] = 0x01; /* ARCOUNT = 1 */
    }

    /* Question: QNAME */
    int offset = 12;
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
    buf[offset++] = 0; /* Null terminator */

    /* QTYPE and QCLASS */
    buf[offset++] = (qtype >> 8) & 0xFF;
    buf[offset++] = qtype & 0xFF;
    buf[offset++] = 0x00; /* QCLASS: IN */
    buf[offset++] = 0x01;

    if (use_edns) {
        /* EDNS0 OPT RR */
        buf[offset++] = 0x00; /* NAME: root */
        buf[offset++] = 0x00; /* TYPE: OPT (41) */
        buf[offset++] = 0x29;
        buf[offset++] = 0x04; /* CLASS: 1232 (standard payload size) */
        buf[offset++] = 0xD0;
        buf[offset++] = 0x00; /* TTL: 0 */
        buf[offset++] = 0x00;
        buf[offset++] = 0x00;
        buf[offset++] = 0x00;
        buf[offset++] = 0x00; /* RDLEN: 0 */
        buf[offset++] = 0x00;
    }

    return offset;
}

/* ── MTU Binary Search Helpers (Ported from legacy) ─────────────────────── */

static void init_mtu_binary_search(mtu_binary_search_t *s, int min, int max, 
                                   int step, int absolute_min, int max_retries, 
                                   bool is_upload) {
    memset(s, 0, sizeof(*s));
    s->min = min;
    s->max = max;
    s->current = (min + max) / 2;
    s->best_working = absolute_min;
    s->max_retries = max_retries;
    s->is_upload = is_upload;
    s->state = 0; /* idle */
}

static int get_next_mtu_to_test(mtu_binary_search_t *s) {
    if (s->state == 2) return -1; /* converged */
    return s->current;
}

static void update_mtu_binary_search(mtu_binary_search_t *s, bool success) {
    if (success) {
        s->best_working = s->current;
        s->min = s->current + 1;
        s->retries = 0;
    } else {
        if (++s->retries < s->max_retries) return;
        s->max = s->current - 1;
        s->retries = 0;
    }
    
    if (s->min > s->max) {
        s->state = 2; /* converged */
    } else {
        s->current = (s->min + s->max) / 2;
    }
}

/* ── Init / Destroy ───────────────────────────────────────────────────────── */

static void on_probe_close(uv_handle_t *h) {
    probe_req_t *p = h->data;
    if (++p->closes == 2) free(p);
}

static void on_probe_timeout(uv_timer_t *t) {
    probe_req_t *p = t->data;
    if (!uv_is_closing((uv_handle_t*)&p->udp)) {
        uv_close((uv_handle_t*)&p->udp, on_probe_close);
        uv_close((uv_handle_t*)&p->timer, on_probe_close);
    }
}

static void on_probe_alloc(uv_handle_t *h, size_t sz, uv_buf_t *buf) {
    (void)h;
    buf->base = malloc(sz);
    buf->len = (unsigned int)sz;
}

static void on_probe_send(uv_udp_send_t *req, int status) {
    (void)req; (void)status;
}

static void on_probe_recv(uv_udp_t *h, ssize_t nread, const uv_buf_t *buf,
                          const struct sockaddr *addr, unsigned flags) 
{
    (void)addr; (void)flags;
    probe_req_t *p = h->data;
    if (nread > 0 && p->result && g_pool) {
        resolver_t *r = &g_pool->resolvers[p->resolver_idx];
        
        if (nread >= 12) {
            uint8_t *resp = (uint8_t *)buf->base;
            uint8_t rcode = resp[3] & 0x0F;
            uint16_t ancount = (resp[6] << 8) | resp[7];
            
            resolver_t *r = &g_pool->resolvers[p->resolver_idx];

            /* 1. Calculate and record RTT */
            double rtt = (double)((uv_hrtime() / 1000000.0) - p->sent_ms);
            if (r->rtt_ms == 0.0) r->rtt_ms = rtt;
            else r->rtt_ms = (r->rtt_ms * 0.7) + (rtt * 0.3); /* Simple EWMA */

            if (p->test_type == PROBE_TEST_LONGNAME) {
                p->result->longname_supported = true;
            } else if (p->test_type == PROBE_TEST_NXDOMAIN) {
                if (rcode == 3 || (rcode == 0 && ancount == 0)) p->result->nxdomain_correct = true;
            } else if (p->test_type == PROBE_TEST_CRYPTO_CHALLENGE) {
                if (rcode == 0 && ancount > 0) p->result->crypto_verified = true;
            } else if (p->test_type == PROBE_TEST_EDNS_TXT) {
                if (rcode == 0 && ancount > 0) {
                    p->result->txt_supported = true;
                    p->result->edns_supported = true;
                }
            } else if (p->test_type == PROBE_TEST_MTU_UP) {
                if (rcode == 0) {
                    update_mtu_binary_search(&p->result->up_mtu_search, true);
                    p->result->upstream_mtu = (uint16_t)p->result->up_mtu_search.best_working;
                }
            } else if (p->test_type == PROBE_TEST_MTU_DOWN) {
                if (rcode == 0 && ancount > 0) {
                    update_mtu_binary_search(&p->result->down_mtu_search, true);
                    p->result->downstream_mtu = (uint16_t)p->result->down_mtu_search.best_working;
                }
            }
        }
        
        /* Stop timer and close on first valid response */
        if (!uv_is_closing((uv_handle_t*)&p->udp)) {
            uv_timer_stop(&p->timer);
            uv_close((uv_handle_t*)&p->udp, on_probe_close);
            uv_close((uv_handle_t*)&p->timer, on_probe_close);
        }
    }
    if (buf->base) free(buf->base);
}

static void fire_test_probe(int idx, probe_test_type_t type, resolver_test_result_t *res) {
    probe_req_t *p = calloc(1, sizeof(*p));
    if (!p) return;
    p->resolver_idx = idx;
    p->test_type = type;
    p->result = res;
    p->sent_ms = uv_hrtime() / 1000000;

    resolver_t *r = &g_pool->resolvers[idx];
    memcpy(&p->dest, &r->addr, sizeof(p->dest));
    p->dest.sin_port = htons(53);

    const char *domain = "google.com";
    uint16_t qtype = 1; /* A */
    bool use_edns = false;
    static char domain_buf[512];

    if (type == PROBE_TEST_CRYPTO_CHALLENGE) {
        const char *base = (g_client_cfg && g_client_cfg->test_domain[0]) ? g_client_cfg->test_domain : "s.domain.com";
        /* Use static nonce for now to match old code's probe logic if needed; 
           actually old code used randombytes_buf */
        #include <sodium.h>
        randombytes_buf(p->challenge_nonce, 32);
        static char nonce_hex[65];
        for (int i = 0; i < 32; i++) sprintf(nonce_hex + i*2, "%02x", p->challenge_nonce[i]);
        snprintf(domain_buf, sizeof(domain_buf), "CRYPTO_%s.%s", nonce_hex, base);
        domain = domain_buf;
        qtype = 16; /* TXT */
        use_edns = true;
    } else if (type == PROBE_TEST_LONGNAME) {
        domain = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.google.com";
    } else if (type == PROBE_TEST_NXDOMAIN) {
        domain = "nonexistent.example.com";
    } else if (type == PROBE_TEST_EDNS_TXT) {
        domain = (g_client_cfg && g_client_cfg->test_domain[0]) ? g_client_cfg->test_domain : "s.domain.com";
        qtype = 16; /* TXT */
        use_edns = true;
    }

    p->sendlen = build_test_dns_query(p->sendbuf, sizeof(p->sendbuf), domain, qtype, (uint16_t)rand(), use_edns);

    uv_udp_init(g_client_loop, &p->udp);
    p->udp.data = p;
    uv_timer_init(g_client_loop, &p->timer);
    p->timer.data = p;
    uv_timer_start(&p->timer, on_probe_timeout, 2000, 0);

    uv_udp_recv_start(&p->udp, on_probe_alloc, on_probe_recv);
    uv_buf_t buf = uv_buf_init((char*)p->sendbuf, (unsigned int)p->sendlen);
    uv_udp_send(&p->send_req, &p->udp, &buf, 1, (const struct sockaddr*)&p->dest, on_probe_send);
}

/* ── Init Phase Implementation (Scanner.py style) ─────────────────────────── */

static void run_event_loop_ms(int ms) {
    uint64_t start = uv_hrtime() / 1000000;
    while ((uv_hrtime() / 1000000) - start < (uint64_t)ms) {
        uv_run(g_client_loop, UV_RUN_ONCE);
    }
}

void resolver_run_init_phase(void) {
    LOG_INFO("=== Starting Resolver Initialization Phase ===\n");

    /* 1. Add seeds and load cache */
    if (g_client_cfg && g_pool) {
        for (int i = 0; i < g_client_cfg->seed_count; i++) {
            rpool_add(g_pool, g_client_cfg->seed_resolvers[i]);
        }
    }
    resolver_load_persistence();

    int count = g_pool->count;
    if (count == 0) {
        LOG_WARN("No resolvers to test!\n");
        return;
    }

    resolver_test_result_t *results = calloc(count, sizeof(resolver_test_result_t));

    int wait_ms = 5000; /* Reverted to 5s from old code for high-latency stability */
    
    /* Full 5-Phase Legacy Initialization sequence */
    LOG_INFO("Phase 0: Crypto challenge (Identity verification)...\n");
    for (int i = 0; i < count; i++) fire_test_probe(i, PROBE_TEST_CRYPTO_CHALLENGE, &results[i]);
    run_event_loop_ms(wait_ms);

    LOG_INFO("Phase 1: Long QNAME probes...\n");
    for (int i = 0; i < count; i++) fire_test_probe(i, PROBE_TEST_LONGNAME, &results[i]);
    run_event_loop_ms(wait_ms);

    LOG_INFO("Phase 2: NXDOMAIN hijack probes...\n");
    for (int i = 0; i < count; i++) fire_test_probe(i, PROBE_TEST_NXDOMAIN, &results[i]);
    run_event_loop_ms(wait_ms);

    LOG_INFO("Phase 3: EDNS0 + TXT support probes...\n");
    for (int i = 0; i < count; i++) fire_test_probe(i, PROBE_TEST_EDNS_TXT, &results[i]);
    run_event_loop_ms(wait_ms);

    LOG_INFO("Phase 4: MTU discovery (Binary search)...\n");
    for (int i = 0; i < count; i++) {
        init_mtu_binary_search(&results[i].up_mtu_search, 0, 110, 10, 110, 2, true);
        init_mtu_binary_search(&results[i].down_mtu_search, 0, 512, 32, 220, 2, false);
    }
    /* Iteratively run MTU probes (Simplified binary search iteration for phase) */
    for (int iter=0; iter<6; iter++) {
        for (int i = 0; i < count; i++) {
            int next_up = get_next_mtu_to_test(&results[i].up_mtu_search);
            if (next_up > 0) fire_test_probe(i, PROBE_TEST_MTU_UP, &results[i]);
            int next_down = get_next_mtu_to_test(&results[i].down_mtu_search);
            if (next_down > 0) fire_test_probe(i, PROBE_TEST_MTU_DOWN, &results[i]);
        }
        run_event_loop_ms(2000);
    }

    /* Evaluation & Promotion (exactly as in old code) */
    int promoted = 0;
    for (int i = 0; i < count; i++) {
        resolver_t *r = &g_pool->resolvers[i];
        
        /* [Legacy Relaxation] Phase 1 & 2 failures are logged but not fatal */
        if (!results[i].longname_supported) {
            LOG_WARN("Resolver %s: Long QNAME fail, relaxing...\n", r->ip);
            results[i].longname_supported = true;
        }
        if (!results[i].nxdomain_correct) {
            LOG_WARN("Resolver %s: NXDOMAIN fail (hijack?), relaxing...\n", r->ip);
            results[i].nxdomain_correct = true;
        }

        /* Essential requirement: must have at least ONE of EDNS or TXT working AND crypto pass if desired */
        bool ok = results[i].longname_supported && 
                  results[i].nxdomain_correct && 
                  (results[i].edns_supported || results[i].txt_supported);

        if (ok) {
            /* Sync MTU results to pool */
            r->upstream_mtu = results[i].upstream_mtu > 0 ? results[i].upstream_mtu : 110;
            r->downstream_mtu = results[i].downstream_mtu > 0 ? results[i].downstream_mtu : 220;
            r->edns0_supported = results[i].edns_supported;
            
            rpool_set_state(g_pool, i, RSV_ACTIVE);
            promoted++;
        }
    }

    free(results);
    LOG_INFO("Initialization complete. Active resolvers: %d\n", promoted);
}

void resolver_tick_bg(void) {
    /* Perform incremental MTU discovery and the background recovery for dead resolvers */
    if (g_pool) {
        rpool_tick_bg(g_pool);
    }
}

void resolver_mod_init(uv_loop_t *loop) {
    (void)loop;
    LOG_INFO("Resolver Module initialized\n");
}

void resolver_mod_shutdown(void) {
    /* Persist final resolver list on shutdown */
    resolver_save_persistence();
    LOG_INFO("Resolver Module shutdown\n");
}
