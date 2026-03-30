/**
 * @file client/socks5.h
 * @brief SOCKS5 server listener and handshake handling.
 *
 * Example Usage:
 * @code
 *   socks5_server_init(g_loop, "127.0.0.1", 1080);
 * @endcode
 */

#ifndef QNS_CLIENT_SOCKS5_H
#define QNS_CLIENT_SOCKS5_H

#include "../uv.h"
#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Initialize the SOCKS5 server listener.
 * @param loop libuv loop.
 * @param bind_addr Listen address (e.g., "127.0.0.1").
 * @param port Listen port (e.g., 1080).
 */
void socks5_server_init(uv_loop_t *loop, const char *bind_addr, int port);

/**
 * @brief Write received tunnel data to the TCP socket associated with a session.
 * @param sidx Session index.
 * @param data Data buffer.
 * @param len Data length.
 */
void socks5_write_to_session_client(int sidx, const uint8_t *data, size_t len);

void socks5_server_shutdown(void);

#endif /* QNS_CLIENT_SOCKS5_H */
