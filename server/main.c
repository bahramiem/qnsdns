/*
 * dnstun-server — DNS Tunnel VPN Server (Entry Point)
 *
 * Architecture:
 *   UDP DNS listener (port 53) via libuv
 *     → Parse QNAME → extract session-id, seq, chunk header + payload
 *     → Resolver Swarm: record source IP as functional resolver
 *     → Session demultiplexing (per session_id)
 *     → SYNC command: respond with swarm IP list
 *     → Forward payload to upstream target via TCP
 *     → Receive upstream response
 *     → Encode response into DNS TXT reply (FEC K from client header)
 *     → Send TXT reply back to querying resolver
 *     → TUI: sessions, bandwidth, errors
 *
 * Module layout:
 *   server/session/session.c  — Session lifecycle + upstream TCP
 *   server/swarm/swarm.c      — Resolver swarm IP tracking
 *   server/dns/protocol.c     — DNS TXT reply building + UDP dispatch
 *   server/tui/callbacks.c    — TUI render timers + TTY input
 */

#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <process.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#ifdef sync
#undef sync
#endif
#else
#include <arpa/inet.h>
#include <strings.h>
#include <unistd.h>
#endif

#include "uv.h"
#include "third_party/spcdns/dns.h"
#include "third_party/spcdns/output.h"

#include "shared/base32.h"
#include "shared/codec.h"
#include "shared/config.h"
#include "shared/mgmt.h"
#include "shared/resolver_pool.h"
#include "shared/tui.h"
#include "shared/types.h"

#include "server/session/session.h"
#include "server/swarm/swarm.h"
#include "server/dns/protocol.h"
#include "server/tui/callbacks.h"

/* ────────────────────────────────────────────── */
/*  Global state (extern'd by all server modules) */
/* ────────────────────────────────────────────── */
dnstun_config_t  g_cfg;
tui_ctx_t        g_tui;
tui_stats_t      g_stats;
uv_loop_t       *g_loop;
mgmt_server_t   *g_mgmt;

/* UDP listener */
uv_udp_t g_udp_server;

/* TUI timers */
uv_timer_t g_tui_timer;
uv_timer_t g_idle_timer;

/* Swarm mutex (used by swarm.c and shared via extern) */
uv_mutex_t g_swarm_lock;

/* Debug log (shared with submodules) is managed by dnstun_log_open in shared/tui.c */

/* ────────────────────────────────────────────── */
/*  Entry point                                   */
/* ────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    const char *config_path = NULL;
    static char auto_config_path[1024] = {0};
    char domain_buf[512] = {0};
    char threads_str[16];
    char *slash;
#ifdef _WIN32
    char *bslash;
#endif
    char bind_ip[64]  = "0.0.0.0";
    int  bind_port    = 53;
    char tmp[64];
    char *colon;
    struct sockaddr_in srv_addr;
    int r;
    static resolver_pool_t dummy_pool;

    /* ── Parse arguments ── */
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) &&
            i + 1 < argc) {
            config_path = argv[i + 1];
            break;
        }
    }

    /* ── Auto-locate server.ini ── */
    if (!config_path) {
        const char *candidates[] = {
            "server.ini", "../server.ini", "../../server.ini",
            "../../../server.ini", "/etc/dnstun/server.ini"
        };
        for (int i = 0; i < 5; i++) {
            FILE *f = fopen(candidates[i], "r");
            if (f) { fclose(f); config_path = candidates[i]; break; }
        }
        if (!config_path) {
            char exe_path[2048];
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
                        int written = snprintf(auto_config_path, sizeof(auto_config_path),
                                               "%s%s/server.ini", exe_path, rel[i]);
                        if (written < 0 || written >= (int)sizeof(auto_config_path)) continue;
                        FILE *tf = fopen(auto_config_path, "r");
                        if (tf) { fclose(tf); config_path = auto_config_path; break; }
                    }
                }
            }
        }
        if (!config_path) config_path = "server.ini";
    }

    if (config_path && config_path != auto_config_path) {
        strncpy(auto_config_path, config_path, sizeof(auto_config_path) - 1);
        config_path = auto_config_path;
    }

    /* ── Load config ── */
    config_defaults(&g_cfg, true);
    if (config_load(&g_cfg, config_path) != 0) {
        LOG_WARN("Could not load '%s', using defaults. Create server.ini to configure.\n", config_path);
    }

    /* ── Open debug log ── */
    dnstun_log_open("qnsdns_server.log");
    LOG_INFO("=== Server started ===\n");

    /* ── First-run domain prompt ── */
    if (g_cfg.domain_count == 0 ||
        (g_cfg.domain_count == 1 && strcmp(g_cfg.domains[0], "tun.example.com") == 0)) {
        printf("\n  No tunnel domain configured (or default tun.example.com).\n");
        printf("  Enter the subdomain this server will handle\n");
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
        if (g_cfg.domain_count == 0)
            LOG_WARN("No domain configured.\n");
    }

    /* ── libuv thread pool ── */
    snprintf(threads_str, sizeof(threads_str), "%d", g_cfg.workers);
#ifdef _WIN32
    _putenv_s("UV_THREADPOOL_SIZE", threads_str);
#else
    setenv("UV_THREADPOOL_SIZE", threads_str, 1);
#endif

    g_loop = uv_default_loop();

    /* ── Init swarm ── */
    strncpy(g_swarm_file, config_path, sizeof(g_swarm_file) - 1);
    slash = strrchr(g_swarm_file, '/');
#ifdef _WIN32
    bslash = strrchr(g_swarm_file, '\\');
    if (bslash > slash) slash = bslash;
#endif
    if (slash)
        strncpy(slash + 1, "server_resolvers.txt",
                sizeof(g_swarm_file) - (slash - g_swarm_file) - 1);
    else
        strcpy(g_swarm_file, "server_resolvers.txt");

    uv_mutex_init(&g_swarm_lock);
    if (g_cfg.swarm_save_disk) swarm_load();

    /* ── Parse bind address ── */
    if (g_cfg.server_bind[0]) {
        strncpy(tmp, g_cfg.server_bind, sizeof(tmp) - 1);
        colon = strrchr(tmp, ':');
        if (colon) {
            *colon = '\0';
            bind_port = atoi(colon + 1);
            strncpy(bind_ip, tmp, sizeof(bind_ip) - 1);
        }
    }

    /* ── Bind UDP port ── */
    uv_ip4_addr(bind_ip, bind_port, &srv_addr);
    uv_udp_init(g_loop, &g_udp_server);
    r = uv_udp_bind(&g_udp_server, (const struct sockaddr *)&srv_addr, UV_UDP_REUSEADDR);
    if (r != 0) {
        LOG_ERR("Cannot bind UDP %s:%d — %s\n", bind_ip, bind_port, uv_strerror(r));
        return 1;
    }
    uv_udp_recv_start(&g_udp_server, on_server_alloc, on_server_recv);

    /* ── TUI with dummy resolver pool (server shows swarm count) ── */
    memset(&dummy_pool, 0, sizeof(dummy_pool));
    uv_mutex_init(&dummy_pool.lock);
    dummy_pool.cfg = &g_cfg;

    tui_init(&g_tui, &g_stats, &dummy_pool, &g_cfg, "SERVER", config_path);
    g_tui.get_clients_cb = get_active_clients;

    /* ── Timers ── */
    uv_timer_init(g_loop, &g_idle_timer);
    uv_timer_start(&g_idle_timer, on_idle_timer, 1000, 1000);

    uv_timer_init(g_loop, &g_tui_timer);
    uv_timer_start(&g_tui_timer, on_tui_timer, 1000, 1000);

    /* ── Management server ── */
    {
        mgmt_config_t mgmt_cfg = {0};
        strncpy(mgmt_cfg.bind_addr, "127.0.0.1", sizeof(mgmt_cfg.bind_addr) - 1);
        mgmt_cfg.port                  = 9090;
        mgmt_cfg.telemetry_interval_ms = 1000;
        g_mgmt = mgmt_server_create(g_loop, &mgmt_cfg);
        if (g_mgmt) {
            mgmt_server_start(g_mgmt);
            LOG_INFO("Management : 127.0.0.1:9090\n");
        }
    }

    LOG_INFO("dnstun-server listening on %s:%d\n", bind_ip, bind_port);

    /* ── Bind STDIN for TUI ── */
    static uv_tty_t g_tty;
    uv_tty_init(g_loop, &g_tty, 0, 1);
    uv_tty_set_mode(&g_tty, UV_TTY_MODE_RAW);
    uv_read_start((uv_stream_t *)&g_tty, on_tty_alloc, on_tty_read);

    /* ── Run event loop ── */
    uv_run(g_loop, UV_RUN_DEFAULT);
    uv_tty_set_mode(&g_tty, UV_TTY_MODE_NORMAL);

    tui_shutdown(&g_tui);
    if (g_cfg.swarm_save_disk) swarm_save();
    uv_mutex_destroy(&g_swarm_lock);
    codec_pool_shutdown();

    if (g_tui.restart) {
        LOG_INFO("Restarting process...\n");
#ifdef _WIN32
        _execvp(argv[0], argv);
#else
        execvp(argv[0], argv);
#endif
    }
    return 0;
}
