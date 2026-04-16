/**
 * @file client/socks5/proxy.h
 * @brief SOCKS5 Proxy Server Implementation (Client Side)
 *
 * This module runs a local SOCKS5 proxy server that accepts connections from
 * applications (like curl or a browser). It implements the SOCKS5 handshake,
 * parses CONNECT requests, and routes payload data into DNS tunnel sessions.
 *
 * Example:
 *   // Setup a SOCKS5 bind address and start the server:
 *   uv_tcp_init(g_loop, &g_socks5_server);
 *   uv_tcp_bind(&g_socks5_server, (const struct sockaddr*)&socks5_addr, 0);
 *   uv_listen((uv_stream_t*)&g_socks5_server, 128, on_socks5_connection);
 */

#ifndef CLIENT_SOCKS5_PROXY_H
#define CLIENT_SOCKS5_PROXY_H

#include <stdint.h>
#include <stddef.h>
#include "uv.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Context for an active SOCKS5 client connection.
 *
 * Tracks the libuv TCP stream to the local application (e.g. curl) and
 * manages SOCKS5 handshake state (auth negotiation -> request -> tunnel).
 */
typedef struct socks5_client {
    uv_tcp_t  tcp;
    uint8_t   buf[4096];
    size_t    buf_len;
    int       session_idx;  /**< Index into g_sessions array */
    int       state;        /**< 0=handshake, 1=request, 2=tunnel */
} socks5_client_t;

/**
 * @brief Send raw data to the connected SOCKS5 client.
 *
 * @param c     The SOCKS5 client context.
 * @param data  Payload bytes.
 * @param len   Number of bytes to send.
 */
void socks5_send(socks5_client_t *c, const uint8_t *data, size_t len);

/**
 * @brief Handle a new incoming connection to the local SOCKS5 proxy.
 *
 * Passed directly to uv_listen(). Allocates a socks5_client_t and starts
 * reading from the client.
 */
void on_socks5_connection(uv_stream_t *server, int status);

/**
 * @brief Flush any pending downstream payload from the tunnel session
 *        into the local SOCKS5 socket.
 *
 * Called whenever new sequenced data is reassembled in the DNS module.
 *
 * @param c  The SOCKS5 client context.
 */
void socks5_flush_recv_buf(socks5_client_t *c);

/**
 * @brief Close the SOCKS5 connection and perform cleanup.
 */
void on_socks5_close(uv_handle_t *h);

#ifdef __cplusplus
}
#endif

#endif /* CLIENT_SOCKS5_PROXY_H */
