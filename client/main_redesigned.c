/*
 * dnstun-client (Redesigned) — DNS Tunnel VPN Client (Tunnel Endpoint)
 *
 * New Architecture:
 *   DNS UDP listener (port 53 default)
 *     → Receive DNS queries from server
 *     → Decode target connection requests
 *     → Establish TCP connections to target hosts
 *     → Encode responses back into DNS responses
 *     → Send DNS responses back to server
 *
 *   Target Connector
 *     → Manages outbound TCP connections
 *     → Forwards data between DNS tunnel and targets
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
#include "shared/session_mgr.h"
#include "shared/ai_optimizer.h"
#include "target_connector.h"

/* ────────────────────────────────────────────── */
/*  Global state                                  */
/* ────────────────────────────────────────────── */
static dnstun_config_t g_cfg;
static tui_ctx_t g_tui;
static tui_stats_t g_stats;
static uv_loop_t *g_loop;
static mgmt_server_t *g_mgmt;

/* New modular components */
static target_connector_t *g_target_connector;
static session_mgr_t *g_session_mgr;
static ai_optimizer_t *g_ai_optimizer;

/* DNS tunnel sessions */
static dns_tunnel_session_t *g_dns_sessions[DNSTUN_MAX_SESSIONS];

/* UDP listener for DNS queries from server */
static uv_udp_t g_dns_listener;

/* TUI timer */
static uv_timer_t g_tui_timer;
static uv_timer_t g_ai_timer;

/* ────────────────────────────────────────────── */
/*  Forward declarations                          */
/* ────────────────────────────────────────────── */
static void on_dns_query(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                        const struct sockaddr *addr, unsigned flags);
static void on_tui_timer(uv_timer_t *timer);
static void on_ai_timer(uv_timer_t *timer);

/* Target connector callbacks */
static void on_target_data(target_connector_t *connector, session_t *session,
                          const uint8_t *data, size_t len);
static void on_target_error(target_connector_t *connector, session_t *session,
                           int error_code);

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
    if (config_load(&g_cfg, argc > 1 ? argv[1] : "client.ini") != 0) {
        fprintf(stderr, "Failed to load client configuration\n");
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

    /* Create target connector */
    target_connector_config_t target_config = {
        .max_connections = 1000,
        .connect_timeout_sec = 30,
        .idle_timeout_sec = g_cfg.idle_timeout_sec,
        .enable_tcp_nodelay = true,
        .enable_keepalive = true,
        .keepalive_interval_sec = 60
    };

    g_target_connector = target_connector_create(&target_config, g_session_mgr);
    if (!g_target_connector) {
        fprintf(stderr, "Failed to create target connector\n");
        return 1;
    }

    /* Initialize target connector with event loop */
    if (target_connector_init(g_target_connector, g_loop) != 0) {
        fprintf(stderr, "Failed to initialize target connector\n");
        return 1;
    }

    /* Set target connector callbacks */
    g_target_connector->on_tunnel_data = on_target_data;
    g_target_connector->on_connection_error = on_target_error;

    /* Setup DNS listener for queries from server */
    uv_udp_init(g_loop, &g_dns_listener);
    struct sockaddr_in dns_addr;
    uv_ip4_addr("0.0.0.0", 53, &dns_addr);
    uv_udp_bind(&g_dns_listener, (const struct sockaddr*)&dns_addr, 0);
    uv_udp_recv_start(&g_dns_listener, uv_buf_init, on_dns_query);

    /* Initialize TUI */
    resolver_pool_t dummy_pool = {0}; /* TODO: Initialize properly */
    tui_init(&g_tui, &g_stats, &dummy_pool, &g_cfg, "CLIENT (TUNNEL)", argc > 1 ? argv[1] : "client.ini");

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

    LOG_INFO("dnstun-client (redesigned) starting");
    LOG_INFO("  DNS     : 0.0.0.0:53");
    LOG_INFO("  AI      : %s", g_cfg.ai_enabled ? "enabled" : "disabled");
    LOG_INFO("Tunnel endpoint ready. Waiting for server connections.");

    /* Run event loop */
    uv_run(g_loop, UV_RUN_DEFAULT);

    /* Cleanup */
    uv_timer_stop(&g_tui_timer);
    if (g_cfg.ai_enabled) {
        uv_timer_stop(&g_ai_timer);
    }

    target_connector_destroy(g_target_connector);
    dns_tunnel_cleanup();
    if (g_cfg.ai_enabled) {
        ai_optimizer_cleanup();
    }
    session_mgr_cleanup();

    return 0;
}

/* ────────────────────────────────────────────── */
/*  DNS Query Handler                            */
/* ────────────────────────────────────────────── */
static void on_dns_query(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                        const struct sockaddr *addr, unsigned flags) {
    if (nread < 0) return;
    if (nread == 0) return;

    /* Parse DNS query and extract tunnel data */
    /* This would decode the DNS query format and extract session data */
    /* For now, stub implementation */

    LOG_DEBUG("Received DNS query: %zd bytes", nread);

    /* TODO: Parse DNS query format */
    /* TODO: Extract session ID and payload */
    /* TODO: Process CONNECT requests or forward data to targets */
}

/* ────────────────────────────────────────────── */
/*  Target Connector Callbacks                    */
/* ────────────────────────────────────────────── */
static void on_target_data(target_connector_t *connector, session_t *session,
                          const uint8_t *data, size_t len) {
    /* Send data through DNS tunnel back to server */
    dns_tunnel_session_t *dns_session = g_dns_sessions[session->session_id];
    if (dns_session) {
        dns_tunnel_send(dns_session, data, len);
    }
}

static void on_target_error(target_connector_t *connector, session_t *session,
                           int error_code) {
    LOG_ERR("Target connection error for session %d: %d", session->session_id, error_code);

    /* Send error status back through DNS tunnel */
    dns_tunnel_session_t *dns_session = g_dns_sessions[session->session_id];
    if (dns_session) {
        uint8_t error_data[2] = {0x00, (uint8_t)error_code}; /* Error status */
        dns_tunnel_send(dns_session, error_data, sizeof(error_data));
    }

    session_set_state(session, SESSION_STATE_ERROR);
}

/* ────────────────────────────────────────────── */
/*  DNS Tunnel Callbacks                          */
/* ────────────────────────────────────────────── */
static void on_dns_data_received(dns_tunnel_session_t *dns_session,
                               const uint8_t *data, size_t len) {
    session_t *session = session_find_by_id(dns_session->session_id);
    if (!session) {
        /* New session - check if this is a CONNECT request */
        if (len >= 3 && data[0] == 0x01) { /* CONNECT command */
            uint8_t host_len = data[1];
            if (len >= (size_t)(3 + host_len)) {
                char host[256];
                memcpy(host, data + 2, host_len);
                host[host_len] = '\0';
                uint16_t port = (data[2 + host_len] << 8) | data[3 + host_len];

                /* Create new session */
                session = session_create(SESSION_TYPE_TUNNEL_ENDPOINT, host, port);
                if (session) {
                    /* Connect to target */
                    if (target_connector_connect(g_target_connector, session, host, port) == 0) {
                        g_dns_sessions[session->session_id] = dns_session;
                        LOG_INFO("Connected to target %s:%d (session %d)", host, port, session->session_id);
                    } else {
                        LOG_ERR("Failed to connect to target %s:%d", host, port);
                        session_destroy(session);
                    }
                }
            }
        }
    } else {
        /* Existing session - forward data to target */
        target_connector_receive_from_tunnel(g_target_connector, session, data, len);
    }
}

static void on_dns_error(dns_tunnel_session_t *dns_session, int error_code) {
    LOG_ERR("DNS tunnel error for session %d: %d", dns_session->session_id, error_code);

    session_t *session = session_find_by_id(dns_session->session_id);
    if (session) {
        session_set_state(session, SESSION_STATE_ERROR);
        target_connector_close(g_target_connector, session);
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

    /* Cleanup idle connections */
    size_t cleaned = target_connector_cleanup_idle(g_target_connector, 300); /* 5 minutes */
    if (cleaned > 0) {
        LOG_INFO("Cleaned up %zu idle target connections", cleaned);
    }
}