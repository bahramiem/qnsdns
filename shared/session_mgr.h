#pragma once
#ifndef DNSTUN_SESSION_MGR_H
#define DNSTUN_SESSION_MGR_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "types.h"

/* Session Management Module - Manages tunnel sessions and state */

/* Session types */
typedef enum {
    SESSION_TYPE_SOCKS5_CLIENT,  /* Server-side SOCKS5 client session */
    SESSION_TYPE_TUNNEL_ENDPOINT  /* Client-side tunnel to target */
} session_type_t;

/* Session state */
typedef enum {
    SESSION_STATE_INIT,
    SESSION_STATE_CONNECTING,
    SESSION_STATE_CONNECTED,
    SESSION_STATE_ACTIVE,
    SESSION_STATE_CLOSING,
    SESSION_STATE_CLOSED,
    SESSION_STATE_ERROR
} session_state_t;

/* Session statistics */
typedef struct session_stats {
    time_t created_time;
    time_t last_active;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint32_t packets_sent;
    uint32_t packets_received;
    uint32_t errors;
    double avg_rtt_ms;
} session_stats_t;

/* Session structure */
typedef struct session {
    uint16_t session_id;
    session_type_t type;
    session_state_t state;

    /* Connection info */
    char remote_host[256];
    uint16_t remote_port;
    char local_host[256];
    uint16_t local_port;

    /* Protocol-specific data */
    union {
        /* For SOCKS5 client sessions (server-side) */
        struct {
            void *socks5_client;  /* socks5_client_t* */
            uint8_t target_atyp;
        } socks5;

        /* For tunnel endpoint sessions (client-side) */
        struct {
            uv_tcp_t *target_tcp;
            bool tcp_connected;
        } tunnel;
    } proto;

    /* DNS tunnel session */
    void *dns_session;  /* dns_tunnel_session_t* */

    /* Buffers */
    uint8_t *send_buffer;
    size_t send_len;
    size_t send_cap;
    uint8_t *recv_buffer;
    size_t recv_len;
    size_t recv_cap;

    /* Statistics */
    session_stats_t stats;

    /* Callbacks */
    void (*on_state_change)(struct session *session, session_state_t new_state);
    void (*on_data_received)(struct session *session, const uint8_t *data, size_t len);
    void (*on_error)(struct session *session, int error_code);
    void (*on_close)(struct session *session);

    /* User data */
    void *user_data;
} session_t;

/* Session manager configuration */
typedef struct session_mgr_config {
    int max_sessions;
    int idle_timeout_sec;
    int buffer_size_initial;
    int buffer_size_max;
    bool enable_stats;
} session_mgr_config_t;

/* Session manager */
typedef struct session_mgr {
    session_mgr_config_t config;
    session_t *sessions;
    size_t session_count;
    uint16_t next_session_id;

    /* Callbacks */
    void (*on_session_created)(struct session_mgr *mgr, session_t *session);
    void (*on_session_destroyed)(struct session_mgr *mgr, session_t *session);
} session_mgr_t;

/* API Functions */

/* Initialize session manager */
int session_mgr_init(session_mgr_config_t *config);

/* Cleanup session manager */
void session_mgr_cleanup(void);

/* Create a new session */
session_t* session_create(session_type_t type, const char *remote_host, uint16_t remote_port);

/* Destroy a session */
void session_destroy(session_t *session);

/* Find session by ID */
session_t* session_find_by_id(uint16_t session_id);

/* Get all active sessions */
size_t session_get_active(session_t **sessions, size_t max_count);

/* Send data through session */
int session_send(session_t *session, const uint8_t *data, size_t len);

/* Update session state */
void session_set_state(session_t *session, session_state_t state);

/* Get session statistics */
void session_get_stats(const session_t *session, session_stats_t *stats);

/* Cleanup idle sessions */
size_t session_cleanup_idle(int max_age_sec);

/* Get manager statistics */
void session_mgr_get_stats(session_mgr_stats_t *stats);

#endif /* DNSTUN_SESSION_MGR_H */