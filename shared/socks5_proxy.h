#pragma once
#ifndef DNSTUN_SOCKS5_PROXY_H
#define DNSTUN_SOCKS5_PROXY_H

#include <stdint.h>
#include <stdbool.h>
#include <uv.h>

/* SOCKS5 Proxy Module - RFC 1928 compliant SOCKS5 proxy implementation */

/* SOCKS5 protocol constants */
#define SOCKS5_VERSION 0x05
#define SOCKS5_AUTH_NONE 0x00
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_CMD_BIND 0x02
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6 0x04

/* SOCKS5 reply codes */
#define SOCKS5_REP_SUCCESS 0x00
#define SOCKS5_REP_GENERAL_FAILURE 0x01
#define SOCKS5_REP_CONNECTION_NOT_ALLOWED 0x02
#define SOCKS5_REP_NETWORK_UNREACHABLE 0x03
#define SOCKS5_REP_HOST_UNREACHABLE 0x04
#define SOCKS5_REP_CONNECTION_REFUSED 0x05
#define SOCKS5_REP_TTL_EXPIRED 0x06
#define SOCKS5_REP_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED 0x08

/* SOCKS5 client state */
typedef enum {
    SOCKS5_STATE_INIT,
    SOCKS5_STATE_AUTH_METHODS,
    SOCKS5_STATE_AUTH,
    SOCKS5_STATE_REQUEST,
    SOCKS5_STATE_CONNECTED,
    SOCKS5_STATE_ERROR
} socks5_state_t;

/* SOCKS5 client connection */
typedef struct socks5_client {
    uv_tcp_t tcp_handle;
    socks5_state_t state;
    uint8_t buffer[4096];
    size_t buffer_len;
    uint16_t session_id;

    /* Target information */
    char target_host[256];
    uint16_t target_port;
    uint8_t target_atyp;

    /* Callbacks */
    void (*on_connect_request)(struct socks5_client *client,
                             const char *host, uint16_t port);
    void (*on_data)(struct socks5_client *client,
                   const uint8_t *data, size_t len);
    void (*on_close)(struct socks5_client *client);
    void (*on_error)(struct socks5_client *client, int error_code);

    void *user_data;
} socks5_client_t;

/* SOCKS5 proxy configuration */
typedef struct socks5_config {
    char bind_address[64];  /* "0.0.0.0:1080" */
    bool allow_ipv4;
    bool allow_ipv6;
    bool allow_domain;
    int max_connections;
    int idle_timeout_sec;
} socks5_config_t;

/* SOCKS5 proxy server */
typedef struct socks5_server {
    uv_tcp_t tcp_server;
    socks5_config_t config;
    socks5_client_t *clients;
    size_t max_clients;
    size_t active_clients;

    /* Callbacks */
    void (*on_client_connected)(struct socks5_server *server,
                              socks5_client_t *client);
    void (*on_client_disconnected)(struct socks5_server *server,
                                 socks5_client_t *client);
} socks5_server_t;

/* SOCKS5 statistics */
typedef struct socks5_stats {
    uint64_t total_connections;
    uint64_t active_connections;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint32_t errors;
    time_t start_time;
} socks5_stats_t;

/* API Functions */

/* Initialize SOCKS5 proxy module */
int socks5_proxy_init(uv_loop_t *loop);

/* Cleanup SOCKS5 proxy module */
void socks5_proxy_cleanup(void);

/* Create SOCKS5 server */
socks5_server_t* socks5_server_create(const socks5_config_t *config);

/* Destroy SOCKS5 server */
void socks5_server_destroy(socks5_server_t *server);

/* Start SOCKS5 server */
int socks5_server_start(socks5_server_t *server);

/* Stop SOCKS5 server */
void socks5_server_stop(socks5_server_t *server);

/* Send data to SOCKS5 client */
int socks5_client_send(socks5_client_t *client, const uint8_t *data, size_t len);

/* Send SOCKS5 reply to client */
int socks5_client_send_reply(socks5_client_t *client, uint8_t reply_code);

/* Close SOCKS5 client connection */
void socks5_client_close(socks5_client_t *client);

/* Get client statistics */
void socks5_server_get_stats(const socks5_server_t *server,
                            socks5_stats_t *stats);

#endif /* DNSTUN_SOCKS5_PROXY_H */