#pragma once
#ifndef DNSTUN_TUI_MGMT_CLIENT_H
#define DNSTUN_TUI_MGMT_CLIENT_H

#include <stdint.h>
#include <stdbool.h>
#include "uv.h"
#include "../shared/mgmt_protocol.h"

/* ──────────────────────────────────────────────
   Management Client for Standalone TUI
   
   This client connects to the dnstun-core management
   server via TCP socket and receives telemetry updates.
 ────────────────────────────────────────────── */

/* Connection state */
typedef enum {
    MGMT_STATE_DISCONNECTED = 0,
    MGMT_STATE_CONNECTING,
    MGMT_STATE_CONNECTED,
    MGMT_STATE_RECONNECTING
} mgmt_client_state_t;

/* Client handle */
typedef struct mgmt_client mgmt_client_t;

/* Telemetry callback */
typedef void (*mgmt_telemetry_cb)(const mgmt_telemetry_frame_t *frame, void *user_data);

/* ──────────────────────────────────────────────
   Client API
 ────────────────────────────────────────────── */

/* Create a new management client */
mgmt_client_t *mgmt_client_create(uv_loop_t *loop);

/* Destroy client and cleanup */
void mgmt_client_destroy(mgmt_client_t *client);

/* Connect to management server */
int mgmt_client_connect(mgmt_client_t *client, const char *host, int port);

/* Disconnect from server */
void mgmt_client_disconnect(mgmt_client_t *client);

/* Check connection state */
mgmt_client_state_t mgmt_client_get_state(mgmt_client_t *client);

/* Get last telemetry frame */
const mgmt_telemetry_frame_t *mgmt_client_get_stats(mgmt_client_t *client);

/* Set telemetry callback */
void mgmt_client_set_callback(mgmt_client_t *client, 
                               mgmt_telemetry_cb callback, 
                               void *user_data);

/* Send command to server */
int mgmt_client_send_command(mgmt_client_t *client, 
                             uint32_t command_type,
                             const void *payload,
                             size_t payload_len);

/* Reconnection control */
void mgmt_client_enable_reconnect(mgmt_client_t *client, bool enable);
int mgmt_client_get_reconnect_attempts(mgmt_client_t *client);

#endif /* DNSTUN_TUI_MGMT_CLIENT_H */
