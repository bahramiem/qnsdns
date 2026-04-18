/*
 * dnstun-client — DNS Tunnel VPN Client (Entry Point)
 *
 * Architecture:
 *   SOCKS5 TCP listener (port 1080) via libuv
 *     → Parse SOCKS5 CONNECT
 *     → Determine Target Host/Port
 *     → Tunnel encoding (compress + encrypt + FEC)
 *     → DNS TXT chunks sent via UDP to active resolvers (Round-Robin)
 *     → DNS replies received, decoded, reordered
 *     → Target response payload pushed back to SOCKS5 client
 *
 * Module layout:
 *   client/session/session.c      — Client tunnel session + reorder buffer
 *   client/dns/query.c            — DNS Query encoding and UDP handling
 *   client/socks5/proxy.c         — Local SOCKS5 server Implementation
 *   client/resolver/probe.c       — Resolver capability probing
 *   client/resolver/mtu.c         — MTU binary search optimization
 *   client/resolver/init.c        — Resolver boot phase + CIDR scan
 *   client/aggregation/packet.c   — Packet packing/aggregation logic
 *   client/debug/packet.c         — Diagnostic packet logic
 *   client/tui/callbacks.c        — TTY handling + timers + chunk pushing
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

#include "client/session/session.h"
#include "client/dns/query.h"
#include "shared/tui.h"
#include "client/socks5/proxy.h"
#include "client/resolver/probe.h"
#include "client/resolver/init.h"
#include "client/tui/callbacks.h"

/* ────────────────────────────────────────────── */
/*  Global State (extern'd by client modules)     */
/* ────────────────────────────────────────────── */
dnstun_config_t  g_cfg;
tui_ctx_t        g_tui;
tui_stats_t      g_stats;
uv_loop_t       *g_loop;
resolver_pool_t  g_pool;
mgmt_server_t   *g_mgmt;

/* DNS tunnel sessions */
session_t g_sessions[DNSTUN_MAX_SESSIONS];
int       g_session_count = 0;

/* Persistence paths */
char g_resolvers_file[1024] = {0};

/* TUI/Timers */
uv_timer_t g_tui_timer;
uv_timer_t g_idle_timer;
uv_timer_t g_poll_timer;
uv_tty_t   g_tty;

/* SOCKS5 listener */
uv_tcp_t g_socks5_server;

void detect_local_ip(char *out, size_t out_len) {
    uv_interface_address_t *info;
    int count, i;
    char addr[46];

    strncpy(out, "unknown", out_len);
    if (uv_interface_addresses(&info, &count) != 0) return;

    for (i = 0; i < count; i++) {
        uv_interface_address_t interface = info[i];
        if (interface.address.address4.sin_family == AF_INET && !interface.is_internal) {
            uv_ip4_name(&interface.address.address4, addr, sizeof(addr));
            strncpy(out, addr, out_len-1);
            out[out_len-1] = '\0';
            break;
        }
    }
    uv_free_interface_addresses(info, count);
}

void resolvers_save(void) {
    if (!g_resolvers_file[0]) return;
    FILE *f = fopen(g_resolvers_file, "w");
    if (!f) return;
    uv_mutex_lock(&g_pool.lock);
    for (int i = 0; i < g_pool.count; i++) {
        if (g_pool.resolvers[i].state == RSV_ACTIVE) {
            fprintf(f, "%s,%u,%u,%d,%u,%f\n",
                    g_pool.resolvers[i].ip,
                    g_pool.resolvers[i].upstream_mtu,
                    g_pool.resolvers[i].downstream_mtu,
                    g_pool.resolvers[i].enc,
                    g_pool.resolvers[i].fec_k,
                    g_pool.resolvers[i].loss_rate);
        }
    }
    uv_mutex_unlock(&g_pool.lock);
    fclose(f);
}

static int _rpool_find(resolver_pool_t *pool, const char *ip) {
    for (int i = 0; i < pool->count; i++) {
        if (strcmp(pool->resolvers[i].ip, ip) == 0) return i;
    }
    return -1;
}

void resolvers_load(void) {
    if (!g_resolvers_file[0]) return;
    FILE *f = fopen(g_resolvers_file, "r");
    if (!f) return;
    char line[256];
    uv_mutex_lock(&g_pool.lock);
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (!line[0]) continue;
        char *ip = strtok(line, ",");
        if (!ip) continue;
        int idx = _rpool_find(&g_pool, ip);
        if (idx < 0) {
            idx = g_pool.count++;
            strncpy(g_pool.resolvers[idx].ip, ip, sizeof(g_pool.resolvers[idx].ip)-1);
            uv_ip4_addr(ip, 53, &g_pool.resolvers[idx].addr);
        }
        char *umtu = strtok(NULL, ",");
        char *dmtu = strtok(NULL, ",");
        char *enc  = strtok(NULL, ",");
        char *feck = strtok(NULL, ",");
        char *loss = strtok(NULL, ",");
        if (umtu) g_pool.resolvers[idx].upstream_mtu   = (uint16_t)atoi(umtu);
        else      g_pool.resolvers[idx].upstream_mtu   = 220;
        if (dmtu) g_pool.resolvers[idx].downstream_mtu = (uint16_t)atoi(dmtu);
        else      g_pool.resolvers[idx].downstream_mtu = 512;
        if (enc)  g_pool.resolvers[idx].enc            = atoi(enc);
        if (feck) g_pool.resolvers[idx].fec_k          = (uint8_t)atoi(feck);
        if (loss) g_pool.resolvers[idx].loss_rate      = (float)atof(loss);
        g_pool.resolvers[idx].state = RSV_ACTIVE;
    }
    uv_mutex_unlock(&g_pool.lock);
    fclose(f);
}

/* ────────────────────────────────────────────── */
/*  Entry point                                   */
/* ────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    const char *config_path = NULL;
    static char auto_config_path[1024] = {0};
    char bind_ip[64]  = "127.0.0.1";
    int  bind_port    = 1080;
    char domain_buf[512] = {0};
    char tmp[64];
    char *colon;
    struct sockaddr_in socks5_addr;
    char *slash;
#ifdef _WIN32
    char *bslash;
#endif

    srand((unsigned int)time(NULL));

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) &&
            i + 1 < argc) {
            config_path = argv[i + 1];
            break;
        }
    }

    if (!config_path) {
        const char *candidates[] = {
            "client.ini", "../client.ini", "../../client.ini",
            "../../../client.ini", "/etc/dnstun/client.ini"
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
                                               "%s%s/client.ini", exe_path, rel[i]);
                        if (written < 0 || written >= (int)sizeof(auto_config_path)) continue;
                        FILE *tf = fopen(auto_config_path, "r");
                        if (tf) { fclose(tf); config_path = auto_config_path; break; }
                    }
                }
            }
        }
        if (!config_path) config_path = "client.ini";
    }

    if (config_path && config_path != auto_config_path) {
        strncpy(auto_config_path, config_path, sizeof(auto_config_path) - 1);
        config_path = auto_config_path;
    }

    config_defaults(&g_cfg, false);
    FILE *cf = fopen(config_path, "r");
    if (cf) {
        fclose(cf);
        if (config_load(&g_cfg, config_path) != 0) {
            LOG_WARN("Could not load '%s', using defaults. Check file format.\n", config_path);
        }
    } else {
        if (config_create_default(config_path, false) == 0) {
            LOG_INFO("Created default configuration file: %s\n", config_path);
            config_load(&g_cfg, config_path);
        } else {
            LOG_WARN("Could not create '%s', using hardcoded defaults.\n", config_path);
        }
    }
    dnstun_log_open("qnsdns_client.log");
    LOG_INFO("=== Client started ===\n");

    /* Prompt for domain if empty or default */
    if (g_cfg.domain_count == 0 ||
        (g_cfg.domain_count == 1 && strcmp(g_cfg.domains[0], "tun.example.com") == 0)) {
        printf("\n  No tunnel domain configured (or default tun.example.com).\n");
        printf("  Enter the subdomain to tunnel through\n");
        printf("  (e.g. tun.example.com, separate multiple with commas): ");
        fflush(stdout);
        if (fgets(domain_buf, sizeof(domain_buf), stdin)) {
            domain_buf[strcspn(domain_buf, "\r\n")] = '\0';
            if (domain_buf[0]) {
                config_set_key(&g_cfg, "domains", "list", domain_buf);
                if (config_save_domains(config_path, &g_cfg) == 0)
                    LOG_INFO("Saved domains to %s\n", config_path);
            }
        }
        if (g_cfg.domain_count == 0) {
            LOG_ERR("No domain configured. Exiting.\n");
            return 1;
        }
    }

    char threads_str[16];
    snprintf(threads_str, sizeof(threads_str), "%d", g_cfg.workers);
#ifdef _WIN32
    _putenv_s("UV_THREADPOOL_SIZE", threads_str);
#else
    setenv("UV_THREADPOOL_SIZE", threads_str, 1);
#endif

    g_loop = uv_default_loop();

    /* Initialize TUI and TTY FIRST so it can show progress during init phase */
    tui_init(&g_tui, &g_stats, &g_pool, &g_cfg, "CLIENT", config_path);
    g_tui.get_clients_cb = get_active_clients_client;

    /* Populate network identity in stats */
    detect_local_ip(g_stats.local_ip, sizeof(g_stats.local_ip));
    strncpy(g_stats.outside_ip, "detecting...", sizeof(g_stats.outside_ip)-1);
    strncpy(g_stats.socks_bind, g_cfg.socks5_bind, sizeof(g_stats.socks_bind)-1);
    if (!g_stats.socks_bind[0]) strcpy(g_stats.socks_bind, "127.0.0.1:1080");

    uv_timer_init(g_loop, &g_idle_timer);
    uv_timer_start(&g_idle_timer, on_idle_timer, 1000, 1000);

    uv_timer_init(g_loop, &g_poll_timer);
    uv_timer_start(&g_poll_timer, on_poll_timer, 50, 10);

    uv_timer_init(g_loop, &g_tui_timer);
    uv_timer_start(&g_tui_timer, on_tui_timer, 100, 500); /* Faster initial update */

    uv_tty_init(g_loop, &g_tty, 0, 1);
    uv_tty_set_mode(&g_tty, UV_TTY_MODE_RAW);
    uv_read_start((uv_stream_t*)&g_tty, on_tty_alloc, on_tty_read);

    rpool_init(&g_pool, &g_cfg);

    strncpy(g_resolvers_file, config_path, sizeof(g_resolvers_file) - 1);
    slash = strrchr(g_resolvers_file, '/');
#ifdef _WIN32
    bslash = strrchr(g_resolvers_file, '\\');
    if (bslash > slash) slash = bslash;
#endif
    if (slash) {
        strncpy(slash + 1, "client_resolvers.txt",
                sizeof(g_resolvers_file) - (slash - g_resolvers_file) - 1);
    } else {
        strcpy(g_resolvers_file, "client_resolvers.txt");
    }

    if (g_cfg.swarm_save_disk) resolvers_load();

    /* Always run resolver init phase to test & score resolvers.
     * If resolvers were loaded from disk they still need to be validated
     * and have their MTU / EDNS capabilities confirmed. */
    {
        uv_mutex_lock(&g_pool.lock);
        for (int i = 0; i < g_pool.count; i++)
            g_pool.resolvers[i].state = RSV_DEAD; /* force re-test */
        uv_mutex_unlock(&g_pool.lock);

        /* This will call uv_run internally, triggering TUI updates */
        resolver_init_phase();
    }

    memset(g_sessions, 0, sizeof(g_sessions));
    for (int i = 0; i < DNSTUN_MAX_SESSIONS; i++) {
        g_sessions[i].closed = true;
    }

    if (g_cfg.socks5_bind[0]) {
        strncpy(tmp, g_cfg.socks5_bind, sizeof(tmp)-1);
        tmp[sizeof(tmp)-1] = '\0';
        colon = strrchr(tmp, ':');
        if (colon) {
            *colon = '\0';
            bind_port = atoi(colon + 1);
            strncpy(bind_ip, tmp, sizeof(bind_ip)-1);
            bind_ip[sizeof(bind_ip)-1] = '\0';
        }
    }

    uv_ip4_addr(bind_ip, bind_port, &socks5_addr);
    uv_tcp_init(g_loop, &g_socks5_server);
    if (uv_tcp_bind(&g_socks5_server, (const struct sockaddr*)&socks5_addr, 0) != 0) {
        LOG_ERR("Cannot bind SOCKS5 port %d\n", bind_port);
        return 1;
    }
    uv_listen((uv_stream_t*)&g_socks5_server, 128, on_socks5_connection);

    {
        mgmt_config_t mgmt_cfg = {0};
        strncpy(mgmt_cfg.bind_addr, "127.0.0.1", sizeof(mgmt_cfg.bind_addr) - 1);
        mgmt_cfg.port                  = 9091; 
        mgmt_cfg.telemetry_interval_ms = 1000;
        g_mgmt = mgmt_server_create(g_loop, &mgmt_cfg);
        if (g_mgmt) {
            mgmt_server_start(g_mgmt);
        }
    }

    /* Start main loop */
    uv_run(g_loop, UV_RUN_DEFAULT);
    uv_tty_set_mode(&g_tty, UV_TTY_MODE_NORMAL);

    tui_shutdown(&g_tui);
    if (g_cfg.swarm_save_disk) resolvers_save();
    rpool_destroy(&g_pool);
    codec_pool_shutdown();

    if (g_tui.restart) {
#ifdef _WIN32
        _execvp(argv[0], argv);
#else
        execvp(argv[0], argv);
#endif
    }
    return 0;
}
