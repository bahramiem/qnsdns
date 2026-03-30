/**
 * @file client/session.h
 * @brief Client-side session management and reorder buffer tracking.
 */

#ifndef QNS_CLIENT_SESSION_H
#define QNS_CLIENT_SESSION_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "../shared/types.h"

/**
 * @brief Initialize the client session table.
 */
void session_table_init(void);

/**
 * @brief Find an available session slot.
 * @return session_idx or -1 if full.
 */
int session_alloc(void);

/**
 * @brief Get a session by index.
 */
session_t* session_get(int idx);

/**
 * @brief Close a session and free its buffers.
 */
void session_close(int idx);

/**
 * @brief Generate a unique 8-bit session ID for the wire (0-255).
 */
uint8_t session_get_unused_id(void);

/**
 * @brief Find session index by its wire ID.
 */
int session_find_by_wire_id(uint8_t wire_id);

/**
 * @brief Clean up idle sessions.
 * @param timeout_sec Seconds of inactivity before closing.
 */
void session_tick_idle(int timeout_sec);

#endif /* QNS_CLIENT_SESSION_H */
