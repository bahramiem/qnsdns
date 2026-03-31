#pragma once
#ifndef DNSTUN_CLIENT_TARGET_CONNECTOR_H
#define DNSTUN_CLIENT_TARGET_CONNECTOR_H

#include <uv.h>
#include "shared/session_mgr.h"

/* Client-side target connector - Manages outbound connections to target hosts */

/* Target connection configuration */
typedef struct target_connector_config {
    int max_connections;
    int connect_timeout_sec;
    int idle_timeout_sec;
    bool enable_tcp_nodelay;
    bool enable_keepalive;
    int keepalive_interval_sec;
} target_connector_config_t;

/* Target connection instance */
typedef struct target_connector {
    target_connector_config_t config;
    session_mgr_t *session_mgr;
    uv_loop_t *loop;

    /* Connection pool */
    struct {
        uv_tcp_t *tcp_handle;
        session_t *session;
        bool in_use;
        time_t last_active;
    } *connections;
    size_t connection_count;
    size_t max_connections;

    /* Callbacks to DNS tunnel */
    void (*on_tunnel_data)(struct target_connector *connector,
                          session_t *session, const uint8_t *data, size_t len);
    void (*on_connection_error)(struct target_connector *connector,
                               session_t *session, int error_code);

    void *user_data;
} target_connector_t;

/* Target connector statistics */
typedef struct target_connector_stats {
    uint64_t total_connections;
    uint64_t active_connections;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint32_t errors;
    time_t start_time;
} target_connector_stats_t;

/* API Functions */

/* Create target connector */
target_connector_t* target_connector_create(const target_connector_config_t *config,
                                           session_mgr_t *session_mgr);

/* Destroy target connector */
void target_connector_destroy(target_connector_t *connector);

/* Initialize with event loop */
int target_connector_init(target_connector_t *connector, uv_loop_t *loop);

/* Connect to target host */
int target_connector_connect(target_connector_t *connector,
                           session_t *session,
                           const char *host, uint16_t port);

/* Send data to target */
int target_connector_send(target_connector_t *connector,
                         session_t *session,
                         const uint8_t *data, size_t len);

/* Handle data received from tunnel (forward to target) */
int target_connector_receive_from_tunnel(target_connector_t *connector,
                                        session_t *session,
                                        const uint8_t *data, size_t len);

/* Close target connection */
void target_connector_close(target_connector_t *connector, session_t *session);

/* Get connector statistics */
void target_connector_get_stats(const target_connector_t *connector,
                               target_connector_stats_t *stats);

/* Cleanup idle connections */
size_t target_connector_cleanup_idle(target_connector_t *connector, int max_age_sec);

#endif /* DNSTUN_CLIENT_TARGET_CONNECTOR_H */