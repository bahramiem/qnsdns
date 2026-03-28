#pragma once
#ifndef DNSTUN_MGMT_H
#define DNSTUN_MGMT_H

#include "mgmt_protocol.h"
#include "types.h"
#include "uv.h"
#include "tui.h"
#include "resolver_pool.h"

/* ──────────────────────────────────────────────
   Management Server API
   
   This module provides a headless management interface
   for the dnstun core, enabling decoupled TUI clients.
 ────────────────────────────────────────────── */

/* Forward declarations */
struct mgmt_server;
struct mgmt_client;

/* ──────────────────────────────────────────────
   Callback Types
 ────────────────────────────────────────────── */

/* Called when a command is received from a TUI client */
typedef void (*mgmt_command_cb)(struct mgmt_client *client,
                                 uint32_t command_type,
                                 const void *payload,
                                 size_t payload_len,
                                 void *user_data);

/* Called when a client connects */
typedef void (*mgmt_connect_cb)(struct mgmt_client *client, void *user_data);

/* Called when a client disconnects */
typedef void (*mgmt_disconnect_cb)(struct mgmt_client *client, void *user_data);

/* ──────────────────────────────────────────────
   Callback Configuration
 ────────────────────────────────────────────── */
typedef struct {
    /* Command handlers */
    mgmt_command_cb    on_command;
    
    /* Connection handlers */
    mgmt_connect_cb    on_connect;
    mgmt_disconnect_cb on_disconnect;
    
    /* User data passed to callbacks */
    void               *user_data;
} mgmt_callbacks_t;

/* ──────────────────────────────────────────────
   Management Server
 ────────────────────────────────────────────── */

/* Server configuration */
typedef struct {
    /* Network binding */
    char     bind_addr[64];     /* "127.0.0.1" or "/var/run/dnstun.sock" */
    int      port;              /* TCP port (ignored for Unix sockets) */
    
    /* Protocol settings */
    uint32_t telemetry_interval_ms;  /* Default: 1000ms */
    uint32_t max_clients;           /* Default: MGMT_MAX_CLIENTS */
    uint32_t read_buffer_size;      /* Default: 4096 */
    
    /* Security */
    int      require_auth;           /* Require auth token for commands */
    char     auth_token[64];        /* Token for authentication */
    
    /* Callbacks */
    mgmt_callbacks_t callbacks;
} mgmt_config_t;

/* Server handle */
typedef struct mgmt_server mgmt_server_t;

/* Create and initialize a management server */
mgmt_server_t *mgmt_server_create(uv_loop_t *loop, const mgmt_config_t *config);

/* Start the management server */
int mgmt_server_start(mgmt_server_t *server);

/* Stop and destroy the management server */
void mgmt_server_destroy(mgmt_server_t *server);

/* Check if server is running */
int mgmt_server_is_running(mgmt_server_t *server);

/* ──────────────────────────────────────────────
   Telemetry Broadcasting
   (Push stats to all connected clients)
 ────────────────────────────────────────────── */

/* Broadcast telemetry to all connected TUI clients */
void mgmt_broadcast_telemetry(mgmt_server_t *server, 
                              const tui_stats_t *stats);

/* Broadcast telemetry with extended resolver info (client mode) */
void mgmt_broadcast_telemetry_full(mgmt_server_t *server,
                                   const tui_stats_t *stats,
                                   const resolver_pool_t *pool);

/* ──────────────────────────────────────────────
   Individual Client Messaging
 ────────────────────────────────────────────── */

/* Send a response to a specific client */
int mgmt_send_response(mgmt_server_t *server,
                       struct mgmt_client *client,
                       uint32_t command_id,
                       uint32_t status,
                       const void *payload,
                       size_t payload_len);

/* Send a telemetry frame to a specific client */
int mgmt_send_telemetry(mgmt_server_t *server,
                        struct mgmt_client *client,
                        const tui_stats_t *stats);

/* ──────────────────────────────────────────────
   Client Handle (for callbacks)
 ────────────────────────────────────────────── */
typedef struct mgmt_client mgmt_client_t;

/* Get client address (for logging) */
const char *mgmt_client_get_addr(mgmt_client_t *client);

/* Get client info (for callbacks) */
int mgmt_client_get_info(mgmt_client_t *client,
                         char *out_ip, size_t ip_len,
                         uint16_t *out_port);

/* Close a specific client connection */
void mgmt_client_close(mgmt_client_t *client);

/* ──────────────────────────────────────────────
   Server Statistics
 ────────────────────────────────────────────── */
typedef struct {
    uint32_t total_connections;
    uint32_t active_clients;
    uint32_t commands_received;
    uint32_t commands_failed;
    uint64_t bytes_sent;
    uint64_t bytes_received;
} mgmt_server_stats_t;

/* Get server statistics */
void mgmt_get_stats(mgmt_server_t *server, mgmt_server_stats_t *out_stats);

/* ──────────────────────────────────────────────
   Convenience: Single-Server Singleton
   (For simpler integration)
 ────────────────────────────────────────────── */

/* Initialize with default configuration */
mgmt_server_t *mgmt_init_default(uv_loop_t *loop);

/* Broadcast using global server instance */
void mgmt_broadcast(const tui_stats_t *stats);

#endif /* DNSTUN_MGMT_H */
