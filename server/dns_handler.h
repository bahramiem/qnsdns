/**
 * @file server/dns_handler.h
 * @brief Processing of incoming DNS requests and FEC reassembly.
 *
 * Example Usage:
 * @code
 *   dns_handler_init();
 *   uv_udp_recv_start(&g_udp_server, on_alloc, dns_handler_on_recv);
 * @endcode
 */

#ifndef QNS_SERVER_DNS_HANDLER_H
#define QNS_SERVER_DNS_HANDLER_H

#include <stdint.h>
#include <stdbool.h>
#include "../uv.h"

/**
 * @brief Main entry point for processing an incoming UDP DNS packet.
 */
void dns_handler_on_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                        const struct sockaddr *addr, unsigned int flags);

/**
 * @brief Initialize the DNS handler.
 */
void dns_handler_init(void);

#endif /* QNS_SERVER_DNS_HANDLER_H */
