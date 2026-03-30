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
    PROBE_TEST_LONGNAME,      /* Phase 1: Long QNAME support */
    PROBE_TEST_NXDOMAIN,      /* Phase 2: NXDOMAIN behavior */
    PROBE_TEST_EDNS_TXT,      /* Phase 3: EDNS + TXT support */
} probe_test_type_t;

typedef struct {
    bool        longname_supported;
    bool        nxdomain_correct;
    bool        edns_supported;
    bool        txt_supported;
    uint16_t    upstream_mtu;
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

/* ── Probing Callbacks ───────────────────────────────────────────────────── */

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
    if (nread > 0 && p->result) {
        uint8_t *resp = (uint8_t*)buf->base;
        if (nread >= 12) {
            uint8_t rcode = resp[3] & 0x0F;
            if (p->test_type == PROBE_TEST_LONGNAME) {
                p->result->longname_supported = true;
            } else if (p->test_type == PROBE_TEST_NXDOMAIN) {
                if (rcode == 3 || rcode == 0) p->result->nxdomain_correct = true;
            } else if (p->test_type == PROBE_TEST_EDNS_TXT) {
                p->result->edns_supported = true;
                p->result->txt_supported = true;
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

    if (type == PROBE_TEST_LONGNAME) {
        domain = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.google.com";
    } else if (type == PROBE_TEST_NXDOMAIN) {
        domain = "nonexistent.example.com";
    } else if (type == PROBE_TEST_EDNS_TXT) {
        domain = g_client_cfg->test_domain[0] ? g_client_cfg->test_domain : "s.domain.com";
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

    /* Multi-phase probing */
    LOG_INFO("Phase 1: Long QNAME probes...\n");
    for (int i = 0; i < count; i++) fire_test_probe(i, PROBE_TEST_LONGNAME, &results[i]);
    run_event_loop_ms(2000);

    LOG_INFO("Phase 2: NXDOMAIN hijack probes...\n");
    for (int i = 0; i < count; i++) fire_test_probe(i, PROBE_TEST_NXDOMAIN, &results[i]);
    run_event_loop_ms(2000);

    LOG_INFO("Phase 3: EDNS0 + TXT support probes...\n");
    for (int i = 0; i < count; i++) fire_test_probe(i, PROBE_TEST_EDNS_TXT, &results[i]);
    run_event_loop_ms(2500);

    /* Evaluation & Promotion */
    int promoted = 0;
    for (int i = 0; i < count; i++) {
        bool ok = results[i].longname_supported && results[i].nxdomain_correct && results[i].txt_supported;
        if (ok) {
            rpool_set_state(g_pool, i, RSV_ACTIVE);
            promoted++;
        } else {
            /* Keep as DEAD, rpool_tick_bg will retry later */
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
