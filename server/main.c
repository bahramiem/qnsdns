/**
 * @file server/main.c
 * @brief Clean entry point for the DNS Tunnel VPN Server.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../uv.h"

#include "server_common.h"
#include "swarm.h"
#include "session.h"
#include "dns_handler.h"
#include "../shared/config.h"
#include "../shared/tui/tui.h"
#include "../shared/codec.h"
#include "../shared/log.h"

/* ── Global State (Shared via server_common.h) ───────────────────────────── */
dnstun_config_t *g_server_cfg       = NULL;
tui_ctx_t       *g_server_tui       = NULL;
tui_stats_t     *g_server_stats     = NULL;

/* ── Local State ─────────────────────────────────────────────────────────── */
static dnstun_config_t  local_cfg;
static tui_ctx_t        local_tui;
static tui_stats_t      local_stats;
static uv_loop_t       *local_loop;
static uv_udp_t         udp_server;
static uv_timer_t       idle_timer;
static uv_tty_t         tty_input;

/* ── libuv Callbacks (Wiring to Modules) ─────────────────────────────────── */

static void on_alloc_buf(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    (void)handle;
    buf->base = malloc(suggested_size);
    buf->len = (unsigned int)suggested_size;
}

static void on_tty_read_key(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    if (nread > 0 && g_server_tui) {
        for (ssize_t i = 0; i < nread; i++) {
            tui_handle_key(g_server_tui, buf->base[i]);
            if (!g_server_tui->running) uv_stop(local_loop);
        }
    }
    if (buf->base) free(buf->base);
}

static void on_tick_maintenance(uv_timer_t *handle) {
    (void)handle;
    int timeout = g_server_cfg ? g_server_cfg->idle_timeout_sec : 300;
    session_manager_tick_idle(timeout);
    
    if (g_server_stats) {
        g_server_stats->tx_bytes_sec = 0;
        g_server_stats->rx_bytes_sec = 0;
    }
    
    if (g_server_tui) {
        if (g_server_stats) g_server_stats->active_resolvers = swarm_get_count();
        tui_render(g_server_tui);
    }
}

static void server_tui_log_callback(int level, const char *msg) {
    if (g_server_tui) {
        tui_debug_log(g_server_tui, level, "%s", msg);
    }
}

static int proxy_get_clients_cb(tui_client_snap_t *out, int max) {
    return session_get_snapshots(out, max);
}

/* ── Main Entry Point ────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    const char *config_path = (argc > 2 && strcmp(argv[1], "-c") == 0) ? argv[2] : "server.ini";

    g_server_cfg   = &local_cfg;
    g_server_tui   = &local_tui;
    g_server_stats = &local_stats;
    memset(&local_stats, 0, sizeof(local_stats));

    config_defaults(g_server_cfg, true);
    if (config_load(g_server_cfg, config_path) != 0) {
        fprintf(stderr, "[WARN] Could not load %s, using defaults.\n", config_path);
    }

    qns_log_init("qnsdns_server.txt", (log_level_t)g_server_cfg->log_level);
    LOG_INFO("=== Starting DNS Tunnel Server ===\n");

    local_loop = uv_default_loop();
    
    swarm_init(config_path, g_server_cfg);
    session_manager_init(local_loop);
    dns_handler_init();
    
    struct sockaddr_in addr;
    int port = 53;
    char bind_ip[64] = "0.0.0.0";
    
    uv_ip4_addr(bind_ip, port, &addr);
    uv_udp_init(local_loop, &udp_server);
    if (uv_udp_bind(&udp_server, (const struct sockaddr *)&addr, UV_UDP_REUSEADDR) != 0) {
        fprintf(stderr, "[ERROR] Cannot bind UDP %d. Run as Admin/Root?\n", port);
        return 1;
    }
    uv_udp_recv_start(&udp_server, on_alloc_buf, dns_handler_on_recv);

    static resolver_pool_t dummy_pool; 
    tui_init(g_server_tui, g_server_stats, &dummy_pool, g_server_cfg, "SERVER", config_path);
    qns_log_set_tui_cb(server_tui_log_callback);

    g_server_tui->get_clients_cb = proxy_get_clients_cb;

    uv_timer_init(local_loop, &idle_timer);
    uv_timer_start(&idle_timer, on_tick_maintenance, g_server_cfg->idle_timer_ms, g_server_cfg->idle_timer_ms);

    uv_tty_init(local_loop, &tty_input, 0, 1);
    uv_tty_set_mode(&tty_input, UV_TTY_MODE_RAW);
    uv_read_start((uv_stream_t *)&tty_input, on_alloc_buf, on_tty_read_key);

    LOG_INFO("dnstun-server started listening on port %d\n", port);
    uv_run(local_loop, UV_RUN_DEFAULT);

    uv_tty_reset_mode();
    tui_shutdown(g_server_tui);
    qns_log_shutdown();
    swarm_shutdown();
    codec_pool_shutdown();
    
    return 0;
}
