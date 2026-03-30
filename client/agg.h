/**
 * @file client/agg.h
 * @brief Traffic aggregation and FEC burst engine for the client.
 *
 * Example Usage:
 * @code
 *   agg_tick_bursts(); // Periodic task
 * @endcode
 */

#ifndef QNS_CLIENT_AGG_H
#define QNS_CLIENT_AGG_H

#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Initialize the aggregation engine.
 */
void agg_init(void);

/**
 * @brief Main periodic task for the aggregation engine.
 *
 * This function:
 * 1. Checks all active sessions for pending outbound data.
 * 2. Packs data into fixed-size FEC symbols.
 * 3. Applies FEC encoding (RaptorQ) if configured.
 * 4. Dispatches the resulting burst via the DNS transmission layer.
 */
void agg_tick_bursts(void);

/**
 * @brief Shutdown the aggregation engine and free resources.
 */
void agg_shutdown(void);

#endif /* QNS_CLIENT_AGG_H */
