#pragma once
#ifndef DNSTUN_SERVER_SOCKS5_HANDLER_H
#define DNSTUN_SERVER_SOCKS5_HANDLER_H

#include <uv.h>
#include "shared/socks5_proxy.h"
#include "shared/session_mgr.h"

/* Server-side SOCKS5 handler - Manages SOCKS5 connections and tunnels data */

/* SOCKS5 handler configuration */
typedef struct socks5_handler_config {
    char bind_address[64];  /* "0.0.0.0:1080" */
    int max_clients;
    int idle_timeout_sec;
    bool enable_compression;
    bool enable_encryption;
} socks5_handler_config_t;

/* SOCKS5 handler instance */
typedef struct socks5_handler {
    socks5_server_t *server;
    socks5_handler_config_t config;
    session_mgr_t *session_mgr;

    /* Callbacks to DNS tunnel */
    void (*on_tunnel_data)(struct socks5_handler *handler,
                          session_t *session, const uint8_t *data, size_t len);
    void (*on_tunnel_error)(struct socks5_handler *handler,
                           session_t *session, int error_code);

    void *user_data;
} socks5_handler_t;

/* API Functions */

/* Create SOCKS5 handler */
socks5_handler_t* socks5_handler_create(const socks5_handler_config_t *config,
                                       session_mgr_t *session_mgr);

/* Destroy SOCKS5 handler */
void socks5_handler_destroy(socks5_handler_t *handler);

/* Start SOCKS5 handler */
int socks5_handler_start(socks5_handler_t *handler, uv_loop_t *loop);

/* Stop SOCKS5 handler */
void socks5_handler_stop(socks5_handler_t *handler);

/* Send data to SOCKS5 client via tunnel */
int socks5_handler_send_to_client(socks5_handler_t *handler,
                                 session_t *session,
                                 const uint8_t *data, size_t len);

/* Handle data received from tunnel (forward to SOCKS5 client) */
int socks5_handler_receive_from_tunnel(socks5_handler_t *handler,
                                      session_t *session,
                                      const uint8_t *data, size_t len);

/* Get handler statistics */
void socks5_handler_get_stats(const socks5_handler_t *handler,
                             socks5_handler_stats_t *stats);

#endif /* DNSTUN_SERVER_SOCKS5_HANDLER_H */