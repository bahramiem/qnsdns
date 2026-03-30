/**
 * @file client/resolver_mod.h
 * @brief Resolver pool management, MTU discovery, and background probes.
 *
 * Example Usage:
 * @code
 *   resolver_run_init_phase(); 
 *   resolver_tick_bg(); // Periodic
 * @endcode
 */

#ifndef QNS_CLIENT_RESOLVER_MOD_H
#define QNS_CLIENT_RESOLVER_MOD_H

#include <stdint.h>
#include <stdbool.h>
#include "uv.h"

/**
 * @brief Initialize the resolver module.
 * @param loop libuv loop.
 */
void resolver_mod_init(uv_loop_t *loop);

/**
 * @brief Run the initial resolver testing phase (long QNAME, NXDOMAIN, EDNS).
 * 
 * This blocks the main thread for the duration of the tests (init phase).
 */
void resolver_run_init_phase(void);

/**
 * @brief Background task for MTU binary search and dead-pool recovery.
 */
void resolver_tick_bg(void);

/**
 * @brief Shutdown the resolver module.
 */
void resolver_mod_shutdown(void);

#endif /* QNS_CLIENT_RESOLVER_MOD_H */
