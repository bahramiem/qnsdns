/**
 * @file client/main.c
 * @brief Clean entry point for the DNS Tunnel VPN Client.
 *
 * This file handles high-level initialization, configuration loading,
 * and event loop setup. The core logic is delegated to modular components:
 * - session: Client-side session tracking and reorder buffer.
 * - socks5: Local SOCKS5 server listener.
 * - dns_tx: DNS protocol construction.
 * - agg: FEC burst aggregation engine.
 * - resolver_mod: Pool management and MTU discovery.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../uv.h"

#include "client_common.h"
#include "session.h"
#include "socks5.h"
#include "dns_tx.h"
#include "agg.h"
#include "resolver_mod.h"
#include "../shared/config.h"
#include "../shared/tui/tui.h"
#include "../shared/codec.h"

/* ── Global State (Shared via client_common.h) ───────────────────────────── */
dnstun_config_t *g_client_cfg       = NULL;
tui_ctx_t       *g_client_tui       = NULL;
tui_stats_t     *g_client_stats     = NULL;
FILE            *g_client_debug_log = NULL;
uv_loop_t       *g_client_loop      = NULL;
resolver_pool_t *g_pool             = NULL;
void            *g_sessions         = NULL;

/* ── Local State ─────────────────────────────────────────────────────────── */
static dnstun_config_t  local_cfg;
static tui_ctx_t        local_tui;
static tui_stats_t      local_stats;
static resolver_pool_t  local_pool;
static uv_timer_t       poll_timer;
static uv_timer_t       tui_timer;
static uv_timer_t       bg_timer;

/* ── libuv Callbacks ─────────────────────────────────────────────────────── */

static void on_tick_poll(uv_timer_t *handle) {
    (void)handle;
    /* Downstream fetch: Send POLL queries for all active sessions */
    for (int i = 0; i < DNSTUN_MAX_SESSIONS; i++) {
        session_t *s = session_get(i);
        if (s && !s->closed) {
            dns_tx_send_poll(i);
        }
    }
}

static void on_tick_bg(uv_timer_t *handle) {
    (void)handle;
    /* 1. Aggregation Engine: Check for data to burst */
    agg_tick_bursts();
    
    /* 2. Resolver Management: MTU / Recovery / Penalty */
    resolver_tick_bg();
    
    /* 3. Session Management: Idle cleanup */
    int idle_timeout = g_client_cfg ? g_client_cfg->idle_timeout_sec : 300;
    session_tick_idle(idle_timeout);

    /* 4. Reset rate counters */
    if (g_client_stats) {
        g_client_stats->tx_bytes_sec = 0;
        g_client_stats->rx_bytes_sec = 0;
    }
}

static void on_tick_tui(uv_timer_t *handle) {
    (void)handle;
    if (g_client_tui) {
        tui_render(g_client_tui);
    }
}

static int proxy_get_clients_cb(tui_client_snap_t *out, int max) {
    /* (Snapshot logic moved to shared or session module) */
    return 0; 
}

/* ── Main Entry Point ────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    const char *config_path = (argc > 2 && strcmp(argv[1], "-c") == 0) ? argv[2] : "client.ini";

    /* 1. Global Context Setup */
    g_client_loop  = uv_default_loop();
    g_client_cfg   = &local_cfg;
    g_client_tui   = &local_tui;
    g_client_stats = &local_stats;
    memset(&local_stats, 0, sizeof(local_stats));

    /* 2. Load Configuration */
    config_defaults(g_client_cfg, false);
    if (config_load(g_client_cfg, config_path) != 0) {
        fprintf(stderr, "[WARN] Could not load %s, using defaults.\n", config_path);
    }

    /* 3. Initialize Modules */
    g_pool = &local_pool;
    rpool_init(g_pool, g_client_cfg);
    session_table_init();
    resolver_mod_init(g_client_loop);
    agg_init();
    
    /* 4. Start DNA Tunnel SOCKS5 Listener */
    int socks_port = 1080;
    char *colon = strrchr(g_client_cfg->socks5_bind, ':');
    if (colon) socks_port = atoi(colon + 1);
    
    socks5_server_init(g_client_loop, "127.0.0.1", socks_port);

    /* 5. Initialize TUI */
    /* Accessing global resolver_pool via shared header */
    tui_init(g_client_tui, g_client_stats, g_pool, g_client_cfg, "CLIENT", config_path);
    g_client_tui->get_clients_cb = proxy_get_clients_cb;

    /* 6. Run Resolver Discovery (Init Phase) */
    /* This will run a sub-loop for a few seconds to find working paths */
    resolver_run_init_phase();

    /* 7. Setup Background Timers */
    uv_timer_init(g_client_loop, &poll_timer);
    uv_timer_start(&poll_timer, on_tick_poll, 100, 100); /* High frequency poll */
    
    uv_timer_init(g_client_loop, &bg_timer);
    uv_timer_start(&bg_timer, on_tick_bg, 1000, 1000);  /* Medium frequency logic */

    uv_timer_init(g_client_loop, &tui_timer);
    uv_timer_start(&tui_timer, on_tick_tui, 1000, 1000); /* UI refresh */

    /* 8. Run Main Event Loop */
    LOG_INFO("dnstun-client started. SOCKS5 at 127.0.0.1:%d\n", socks_port);
    uv_run(g_client_loop, UV_RUN_DEFAULT);

    /* 9. Cleanup */
    tui_shutdown(g_client_tui);
    agg_shutdown();
    resolver_mod_shutdown();
    socks5_server_shutdown();
    codec_pool_shutdown();
    
    return 0;
}
