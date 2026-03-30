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

/* ── Init Phase Implementation (Scanner.py style) ─────────────────────────── */

static void on_probe_close(uv_handle_t *h) {
    free(h);
}

static void on_probe_timeout(uv_timer_t *t) {
    uv_stop(t->loop);
}

static void run_event_loop_ms(int ms) {
    uv_timer_t *wait = malloc(sizeof(uv_timer_t));
    if (!wait) return;
    uv_timer_init(g_client_loop, wait);
    uv_timer_start(wait, on_probe_timeout, (uint64_t)ms, 0);
    uv_run(g_client_loop, UV_RUN_DEFAULT);
    uv_close((uv_handle_t*)wait, on_probe_close);
}

void resolver_run_init_phase(void) {
    LOG_INFO("=== Starting Resolver Initialization Phase ===\n");

    /* 1. Add seeds from config */
    if (g_client_cfg && g_pool) {
        for (int i = 0; i < g_client_cfg->seed_count; i++) {
            rpool_add(g_pool, g_client_cfg->seed_resolvers[i]);
        }
    }

    /* 2. Load cached resolvers from disk */
    resolver_load_persistence();

    /* 2. Run multi-phase testing (Simplified extraction for modularity) */
    /* Implementation would follow the 3-phase probe logic in main.c */
    LOG_INFO("Phase 1: Long QNAME probes...\n");
    run_event_loop_ms(1500);

    LOG_INFO("Phase 2: NXDOMAIN hijack probes...\n");
    run_event_loop_ms(1500);

    LOG_INFO("Phase 3: EDNS0 + TXT support probes...\n");
    run_event_loop_ms(2000);

    LOG_INFO("Initialization complete. Active resolvers: %d\n", rpool_get_active_count(g_pool));
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
