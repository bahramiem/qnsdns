/*
 * dnstun-server (Redesigned) — DNS Tunnel VPN Server with SOCKS5 Proxy
 *
 * New Architecture:
 *   SOCKS5 TCP listener (port 1080 default)
 *     → Parse SOCKS5 CONNECT requests
 *     → Extract target host/port
 *     → Encode target info + data into DNS queries
 *     → Send through DNS tunnel to client
 *     → Receive responses from client via DNS
 *     → Forward responses to SOCKS5 clients
 *
 *   DNS UDP listener (port 53)
 *     → Receive DNS responses from client
 *     → Decode response data
 *     → Forward to appropriate SOCKS5 session
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#ifdef _WIN32
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
#include "shared/config.h"
#include "shared/types.h"
#include "shared/resolver_pool.h"
#include "shared/base32.h"
#include "shared/tui.h"
#include "shared/codec.h"
#include "shared/mgmt.h"
#include "shared/dns_tunnel.h"
#include "shared/socks5_proxy.h"
#include "shared/session_mgr.h"
#include "shared/ai_optimizer.h"
#include "socks5_handler.h"

/* ────────────────────────────────────────────── */
/*  Global state                                  */
/* ────────────────────────────────────────────── */
static dnstun_config_t g_cfg;
static tui_ctx_t g_tui;
static tui_stats_t g_stats;
static uv_loop_t *g_loop;
static mgmt_server_t *g_mgmt;

/* New modular components */
static socks5_handler_t *g_socks5_handler;
static session_mgr_t *g_session_mgr;
static ai_optimizer_t *g_ai_optimizer;

/* DNS tunnel sessions */
static dns_tunnel_session_t *g_dns_sessions[DNSTUN_MAX_SESSIONS];

/* UDP listener for DNS responses from client */
static uv_udp_t g_dns_listener;

/* TUI timer */
static uv_timer_t g_tui_timer;
static uv_timer_t g_ai_timer;

/* ────────────────────────────────────────────── */
/*  Forward declarations                          */
/* ────────────────────────────────────────────── */
static void on_dns_response(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                           const struct sockaddr *addr, unsigned flags);
static void on_tui_timer(uv_timer_t *timer);
static void on_ai_timer(uv_timer_t *timer);

/* SOCKS5 handler callbacks */
static void on_socks5_connect_request(socks5_handler_t *handler, session_t *session,
                                    const char *host, uint16_t port);
static void on_socks5_data(socks5_handler_t *handler, session_t *session,
                          const uint8_t *data, size_t len);
static void on_socks5_close(socks5_handler_t *handler, session_t *session);

/* DNS tunnel callbacks */
static void on_dns_data_received(dns_tunnel_session_t *dns_session,
                               const uint8_t *data, size_t len);
static void on_dns_error(dns_tunnel_session_t *dns_session, int error_code);

/* ────────────────────────────────────────────── */
/*  Main implementation                           */
/* ────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    /* Initialize libsodium */
    if (sodium_init() < 0) {
        fprintf(stderr, "Failed to initialize libsodium\n");
        return 1;
    }

    /* Load configuration */
    if (config_load(&g_cfg, argc > 1 ? argv[1] : "server.ini") != 0) {
        fprintf(stderr, "Failed to load server configuration\n");
        return 1;
    }

    /* Initialize libuv event loop */
    g_loop = uv_default_loop();

    /* Initialize modular components */
    session_mgr_config_t sess_config = {
        .max_sessions = DNSTUN_MAX_SESSIONS,
        .idle_timeout_sec = g_cfg.idle_timeout_sec,
        .buffer_size_initial = 4096,
        .buffer_size_max = MAX_SESSION_BUFFER,
        .enable_stats = true
    };

    if (session_mgr_init(&sess_config) != 0) {
        fprintf(stderr, "Failed to initialize session manager\n");
        return 1;
    }
    g_session_mgr = &g_session_mgr; /* Global reference */

    /* Initialize AI optimizer if enabled */
    if (g_cfg.ai_enabled) {
        ai_config_t ai_config = {
            .enabled = true,
            .model_type = g_cfg.ai_model_type,
            .optimization_interval_ms = g_cfg.ai_optimization_interval_ms,
            .learning_rate = g_cfg.ai_learning_rate,
            .enable_training = g_cfg.ai_enable_training,
        };
        strncpy(ai_config.model_path, g_cfg.ai_model_path, sizeof(ai_config.model_path));
        strncpy(ai_config.training_data_path, g_cfg.ai_training_data_path, sizeof(ai_config.training_data_path));
        ai_config.max_training_samples = g_cfg.ai_max_training_samples;

        if (ai_optimizer_init(&ai_config) != 0) {
            fprintf(stderr, "Failed to initialize AI optimizer\n");
            return 1;
        }
    }

    /* Initialize DNS tunnel module */
    if (dns_tunnel_init(g_loop) != 0) {
        fprintf(stderr, "Failed to initialize DNS tunnel\n");
        return 1;
    }

    /* Create SOCKS5 handler */
    socks5_handler_config_t socks5_config = {
        .bind_address = {0},
        .max_clients = 1000,
        .idle_timeout_sec = g_cfg.idle_timeout_sec,
        .enable_compression = true,
        .enable_encryption = g_cfg.encryption
    };
    strncpy(socks5_config.bind_address, g_cfg.socks5_bind, sizeof(socks5_config.bind_address));

    g_socks5_handler = socks5_handler_create(&socks5_config, g_session_mgr);
    if (!g_socks5_handler) {
        fprintf(stderr, "Failed to create SOCKS5 handler\n");
        return 1;
    }

    /* Set SOCKS5 handler callbacks */
    g_socks5_handler->on_tunnel_data = on_socks5_data;
    g_socks5_handler->on_tunnel_error = NULL; /* TODO: implement */

    /* Start SOCKS5 handler */
    if (socks5_handler_start(g_socks5_handler, g_loop) != 0) {
        fprintf(stderr, "Failed to start SOCKS5 handler\n");
        return 1;
    }

    /* Setup DNS listener for responses from client */
    uv_udp_init(g_loop, &g_dns_listener);
    struct sockaddr_in dns_addr;
    uv_ip4_addr("0.0.0.0", 53, &dns_addr);
    uv_udp_bind(&g_dns_listener, (const struct sockaddr*)&dns_addr, 0);
    uv_udp_recv_start(&g_dns_listener, uv_buf_init, on_dns_response);

    /* Initialize TUI */
    tui_init(&g_tui, &g_cfg, &g_stats);
    g_tui.mode = "SERVER (SOCKS5)";

    /* Start management server for TUI */
    g_mgmt = mgmt_server_start(&g_cfg, g_loop, &g_tui);

    /* Setup timers */
    uv_timer_init(g_loop, &g_tui_timer);
    uv_timer_start(&g_tui_timer, on_tui_timer, 1000, 1000);

    if (g_cfg.ai_enabled) {
        uv_timer_init(g_loop, &g_ai_timer);
        uv_timer_start(&g_ai_timer, on_ai_timer, g_cfg.ai_optimization_interval_ms,
                      g_cfg.ai_optimization_interval_ms);
    }

    LOG_INFO("dnstun-server (redesigned) starting");
    LOG_INFO("  SOCKS5  : %s", g_cfg.socks5_bind);
    LOG_INFO("  DNS     : 0.0.0.0:53");
    LOG_INFO("  AI      : %s", g_cfg.ai_enabled ? "enabled" : "disabled");
    LOG_INFO("SOCKS5 proxy ready. External applications can connect to %s", g_cfg.socks5_bind);

    /* Run event loop */
    uv_run(g_loop, UV_RUN_DEFAULT);

    /* Cleanup */
    uv_timer_stop(&g_tui_timer);
    if (g_cfg.ai_enabled) {
        uv_timer_stop(&g_ai_timer);
    }

    socks5_handler_stop(g_socks5_handler);
    socks5_handler_destroy(g_socks5_handler);

    dns_tunnel_cleanup();
    if (g_cfg.ai_enabled) {
        ai_optimizer_cleanup();
    }
    session_mgr_cleanup();

    return 0;
}

/* ────────────────────────────────────────────── */
/*  DNS Response Handler                          */
/* ────────────────────────────────────────────── */
static void on_dns_response(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                           const struct sockaddr *addr, unsigned flags) {
    if (nread < 0) return;
    if (nread == 0) return;

    /* Parse DNS response and extract tunnel data */
    /* This would decode the DNS response format and extract session data */
    /* For now, stub implementation */

    LOG_DEBUG("Received DNS response: %zd bytes", nread);

    /* TODO: Parse DNS response format */
    /* TODO: Extract session ID and payload */
    /* TODO: Forward to appropriate SOCKS5 session via handler */
}

/* ────────────────────────────────────────────── */
/*  SOCKS5 Handler Callbacks                      */
/* ────────────────────────────────────────────── */
static void on_socks5_connect_request(socks5_handler_t *handler, session_t *session,
                                    const char *host, uint16_t port) {
    LOG_INFO("SOCKS5 CONNECT request: %s:%d (session %d)", host, port, session->session_id);

    /* Create DNS tunnel session for this SOCKS5 session */
    dns_tunnel_config_t dns_config = {
        .direction = TUNNEL_SERVER_TO_CLIENT,
        .session_id = session->session_id,
        .use_fec = true,
        .fec_k = 8,
        .use_compression = true,
        .use_encryption = g_cfg.encryption
    };
    strncpy(dns_config.domain, g_cfg.domains[0], sizeof(dns_config.domain));
    dns_config.mtu = g_cfg.downstream_mtu;

    dns_tunnel_session_t *dns_session = dns_tunnel_session_create(&dns_config);
    if (dns_session) {
        dns_session->on_data_received = on_dns_data_received;
        dns_session->on_error = on_dns_error;
        g_dns_sessions[session->session_id] = dns_session;

        /* Send target connection request through DNS tunnel */
        /* Format: CONNECT command + host + port */
        uint8_t connect_data[1024];
        size_t len = 0;
        connect_data[len++] = 0x01; /* CONNECT command */
        connect_data[len++] = strlen(host);
        memcpy(connect_data + len, host, strlen(host));
        len += strlen(host);
        connect_data[len++] = (port >> 8) & 0xFF;
        connect_data[len++] = port & 0xFF;

        dns_tunnel_send(dns_session, connect_data, len);
    }
}

static void on_socks5_data(socks5_handler_t *handler, session_t *session,
                          const uint8_t *data, size_t len) {
    /* Send data through DNS tunnel to client */
    dns_tunnel_session_t *dns_session = g_dns_sessions[session->session_id];
    if (dns_session) {
        dns_tunnel_send(dns_session, data, len);
    }
}

static void on_socks5_close(socks5_handler_t *handler, session_t *session) {
    LOG_INFO("SOCKS5 session closed: %d", session->session_id);

    /* Cleanup DNS tunnel session */
    dns_tunnel_session_t *dns_session = g_dns_sessions[session->session_id];
    if (dns_session) {
        dns_tunnel_session_destroy(dns_session);
        g_dns_sessions[session->session_id] = NULL;
    }
}

/* ────────────────────────────────────────────── */
/*  DNS Tunnel Callbacks                          */
/* ────────────────────────────────────────────── */
static void on_dns_data_received(dns_tunnel_session_t *dns_session,
                               const uint8_t *data, size_t len) {
    /* Forward received data to SOCKS5 client */
    session_t *session = session_find_by_id(dns_session->session_id);
    if (session) {
        socks5_handler_receive_from_tunnel(g_socks5_handler, session, data, len);
    }
}

static void on_dns_error(dns_tunnel_session_t *dns_session, int error_code) {
    LOG_ERR("DNS tunnel error for session %d: %d", dns_session->session_id, error_code);

    session_t *session = session_find_by_id(dns_session->session_id);
    if (session) {
        session_set_state(session, SESSION_STATE_ERROR);
    }
}

/* ────────────────────────────────────────────── */
/*  Timer Callbacks                               */
/* ────────────────────────────────────────────── */
static void on_tui_timer(uv_timer_t *timer) {
    tui_update(&g_tui, &g_stats);
}

static void on_ai_timer(uv_timer_t *timer) {
    /* Collect network metrics and run AI optimizations */
    /* TODO: Implement AI optimization loop */
    LOG_DEBUG("AI optimization timer fired");
}