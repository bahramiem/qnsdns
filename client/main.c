/**
 * @file client/main.c
 * @brief Clean entry point for the DNS Tunnel VPN Client.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../uv.h"

#include "client_common.h"
#include "session.h"
#include "dns_tx.h"
#include "socks5.h"
#include "resolver_mod.h"
#include "agg.h"
#include "../shared/config.h"
#include "../shared/tui/tui.h"
#include "../shared/codec.h"
#include "../shared/log.h"

/* ── Global State (Shared via client_common.h) ───────────────────────────── */
dnstun_config_t *g_client_cfg       = NULL;
tui_ctx_t       *g_client_tui       = NULL;
tui_stats_t     *g_client_stats     = NULL;
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
    agg_tick_bursts();
}

static void sync_stats_from_modules(void) {
    if (!g_client_stats || !g_pool) return;
    uv_mutex_lock(&g_pool->lock);
    g_client_stats->active_resolvers = g_pool->active_count;
    g_client_stats->dead_resolvers = g_pool->dead_count;
    int penalty = 0;
    for (int i = 0; i < g_pool->count; i++) {
        if (g_pool->resolvers[i].state == RSV_PENALTY) penalty++;
    }
    g_client_stats->penalty_resolvers = penalty;
    uv_mutex_unlock(&g_pool->lock);
    g_client_stats->active_sessions = session_get_active_count();
}

static void on_tick_maintenance(uv_timer_t *handle) {
    (void)handle;
    resolver_tick_bg();
    int idle_timeout = g_client_cfg ? g_client_cfg->idle_timeout_sec : 300;
    session_tick_idle(idle_timeout);
    sync_stats_from_modules();
    if (g_client_tui) {
        tui_render(g_client_tui);
        g_client_stats->tx_bytes_sec = 0;
        g_client_stats->rx_bytes_sec = 0;
    }
}

static void client_tui_log_callback(int level, const char *msg) {
    if (g_client_tui) {
        tui_debug_log(g_client_tui, level, "%s", msg);
    }
}

static int proxy_get_clients_cb(tui_client_snap_t *out, int max) {
    (void)out; (void)max;
    return 0; 
}

/* ── Main Entry Point ────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    const char *config_path = (argc > 2 && strcmp(argv[1], "-c") == 0) ? argv[2] : "client.ini";

    g_client_loop  = uv_default_loop();
    g_client_cfg   = &local_cfg;
    g_client_tui   = &local_tui;
    g_client_stats = &local_stats;
    memset(&local_stats, 0, sizeof(local_stats));

    config_defaults(g_client_cfg, false);
    if (argc > 1) {
        if (config_load(g_client_cfg, config_path) != 0) {
            fprintf(stderr, "Failed to load config: %s\n", config_path);
        }
    }

    qns_log_init("qnsdns_client.log", (log_level_t)g_client_cfg->log_level);
    LOG_INFO("=== Starting DNS Tunnel Client ===\n");
    
    g_pool = &local_pool;
    rpool_init(g_pool, g_client_cfg);
    session_table_init();
    resolver_mod_init(g_client_loop);
    agg_init();
    
    int socks_port = 1080;
    char *colon = strrchr(g_client_cfg->socks5_bind, ':');
    if (colon) socks_port = atoi(colon + 1);
    socks5_server_init(g_client_loop, "127.0.0.1", socks_port);

    tui_init(g_client_tui, g_client_stats, g_pool, g_client_cfg, "CLIENT", config_path);
    qns_log_set_tui_cb(client_tui_log_callback);
    
    g_client_tui->get_clients_cb = proxy_get_clients_cb;
    g_client_tui->send_debug_cb = dns_tx_send_debug_packet;

    uv_timer_init(g_client_loop, &poll_timer);
    int poll_int = g_client_cfg ? g_client_cfg->poll_interval_ms : 100;
    if (poll_int < 10) poll_int = 100;
    uv_timer_start(&poll_timer, on_tick_poll, poll_int, poll_int);
    
    uv_timer_init(g_client_loop, &agg_timer);
    uv_timer_start(&agg_timer, on_tick_agg, g_client_cfg->agg_timer_ms, g_client_cfg->agg_timer_ms);
    
    uv_timer_init(g_client_loop, &bg_timer);
    uv_timer_start(&bg_timer, on_tick_maintenance, g_client_cfg->bg_timer_ms, g_client_cfg->bg_timer_ms);

    resolver_run_init_phase();

    uv_tty_init(g_client_loop, &g_tty, 0, 1);
    uv_tty_set_mode(&g_tty, UV_TTY_MODE_RAW);
    uv_read_start((uv_stream_t*)&g_tty, on_tty_alloc, on_tty_read);

    LOG_INFO("dnstun-client started. SOCKS5 at 127.0.0.1:%d\n", socks_port);
    uv_run(g_client_loop, UV_RUN_DEFAULT);

    uv_tty_reset_mode();
    tui_shutdown(g_client_tui);
    qns_log_shutdown();
    agg_shutdown();
    resolver_mod_shutdown();
    socks5_server_shutdown();
    codec_pool_shutdown();
    
    return 0;
}
