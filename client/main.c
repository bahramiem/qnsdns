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
static uv_timer_t       bg_timer;
static uv_timer_t       agg_timer;
static uv_tty_t         g_tty;

/* ── libuv Callbacks ─────────────────────────────────────────────────────── */

static void on_tty_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    (void)handle;
    buf->base = malloc(suggested_size);
    buf->len = (unsigned int)suggested_size;
}

static void on_tty_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    (void)stream;
    if (nread > 0) {
        for (ssize_t i = 0; i < nread; i++) {
            tui_handle_key(g_client_tui, buf->base[i]);
            if (g_client_tui && !g_client_tui->running) {
                uv_stop(g_client_loop);
            }
        }
    }
    if (buf->base) free(buf->base);
}

static void on_tick_poll(uv_timer_t *handle) {
    (void)handle;
    /* Downstream fetch: Send POLL queries for all active sessions */
    int active_count = session_get_active_count();
    for (int i = 0; i < active_count; i++) {
        int session_idx = session_get_next_active(i);
        if (session_idx >= 0) {
            session_t *s = session_get(session_idx);
            if (s && !s->closed) {
                dns_tx_send_poll(session_idx);
            }
        }
    }
}

static void on_tick_agg(uv_timer_t *handle) {
    (void)handle;
    /* 1. Aggregation Engine: Flush proxy payloads to DNS rapidly */
    agg_tick_bursts();
}

static void sync_stats_from_modules(void) {
    if (!g_client_stats || !g_pool) return;
    
    /* 1. Sync Resolver Counts */
    uv_mutex_lock(&g_pool->lock);
    g_client_stats->active_resolvers = g_pool->active_count;
    g_client_stats->dead_resolvers = g_pool->dead_count;
    
    /* Calculate Penalty count from the pool->resolvers state */
    int penalty = 0;
    for (int i = 0; i < g_pool->count; i++) {
        if (g_pool->resolvers[i].state == RSV_PENALTY) penalty++;
    }
    g_client_stats->penalty_resolvers = penalty;
    uv_mutex_unlock(&g_pool->lock);
    
    /* 2. Sync Session Counts */
    g_client_stats->active_sessions = session_get_active_count();
}

static void on_tick_maintenance(uv_timer_t *handle) {
    (void)handle;
    
    /* 1. Resolver Management: MTU / Recovery / Penalty */
    resolver_tick_bg();
    
    /* 2. Session Management: Idle cleanup */
    int idle_timeout = g_client_cfg ? g_client_cfg->idle_timeout_sec : 300;
    session_tick_idle(idle_timeout);
    
    /* 3. Sync stats from all modules into TUI stats */
    sync_stats_from_modules();
    
    /* 4. Reset rate counters (or handle accumulation if needed) */
    /* ... (bytes_sec are normally set by tx/rx paths, here we just show they are active) ... */
    
    /* 5. Update TUI */
    if (g_client_tui) {
        tui_render(g_client_tui);
        /* Clear byte counters after each TUI render to show instantaneous rate */
        g_client_stats->tx_bytes_sec = 0;
        g_client_stats->rx_bytes_sec = 0;
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

    /* 6. Setup Background Timers (Early Start for responsiveness) */
    uv_timer_init(g_client_loop, &poll_timer);
    
    int poll_int = g_client_cfg ? g_client_cfg->poll_interval_ms : 100;
    if (poll_int < 10) poll_int = 100;
    uv_timer_start(&poll_timer, on_tick_poll, poll_int, poll_int); /* High frequency poll */
    
    uv_timer_init(g_client_loop, &agg_timer);
    uv_timer_start(&agg_timer, on_tick_agg, g_client_cfg->agg_timer_ms, g_client_cfg->agg_timer_ms); /* Aggregation burst driver */
    
    uv_timer_init(g_client_loop, &bg_timer);
    uv_timer_start(&bg_timer, on_tick_maintenance, g_client_cfg->bg_timer_ms, g_client_cfg->bg_timer_ms);  /* Combined background maintenance & TUI refresh */

    /* 7. Run Resolver Discovery (Init Phase) */
    /* Starting discovery after timers ensures the TUI remains responsive during the 5s window */
    resolver_run_init_phase();

    /* 8. Bind STDIN for TUI */
    uv_tty_init(g_client_loop, &g_tty, 0, 1);
    uv_tty_set_mode(&g_tty, UV_TTY_MODE_RAW);
    uv_read_start((uv_stream_t*)&g_tty, on_tty_alloc, on_tty_read);

    /* 9. Run Main Event Loop */
    LOG_INFO("dnstun-client started. SOCKS5 at 127.0.0.1:%d\n", socks_port);
    uv_run(g_client_loop, UV_RUN_DEFAULT);

    /* 10. Cleanup */
    uv_tty_reset_mode();
    tui_shutdown(g_client_tui);
    agg_shutdown();
    resolver_mod_shutdown();
    socks5_server_shutdown();
    codec_pool_shutdown();
    
    return 0;
}
