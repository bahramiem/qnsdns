/**
 * @file client/resolver/init.h
 * @brief DNS Resolver Initial Discovery and Lifecycle
 */

#ifndef CLIENT_RESOLVER_INIT_H
#define CLIENT_RESOLVER_INIT_H

#include "uv.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Scan a given seed IP subnet for other working resolvers.
 */
void cidr_scan_subnet(const char *seed_ip, int prefix);

/**
 * @brief Wait for event loop ms.
 */
void run_event_loop_ms(int timeout_ms);

/**
 * @brief Performs the entire initialization lifecycle.
 */
void resolver_init_phase(void);

#ifdef __cplusplus
}
#endif

#endif /* CLIENT_RESOLVER_INIT_H */
