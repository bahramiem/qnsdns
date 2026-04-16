/**
 * @file client/tui/callbacks.h
 * @brief Client-Side TUI Timer Callbacks, TTY, and Main Processing Loops
 *
 * This module connects the client state (sessions, resolver pool) 
 * to the generic TUI, handles keyboard input, logs, and processes background
 * tasks including polling and data transmission (chunk firing).
 */

#ifndef CLIENT_TUI_CALLBACKS_H
#define CLIENT_TUI_CALLBACKS_H

#include "uv.h"
#include "shared/tui.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Idle timer callback (1 second).
 * Handle resolver pool timeouts and statistics reset.
 */
void on_idle_timer(uv_timer_t *t);

/**
 * @brief Main polling timer (variable ms).
 * Fires DNS queries, splits data, creates FEC bursts.
 */
void on_poll_timer(uv_timer_t *t);

/**
 * @brief TUI render timer (1 second).
 */
void on_tui_timer(uv_timer_t *t);

/**
 * @brief Fills client snapshot structures for TUI display.
 */
int get_active_clients_client(tui_client_snap_t *out, int max_clients);

/**
 * @brief libuv TTY read buffer allocator.
 */
void on_tty_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);

/**
 * @brief libuv TTY read callback.
 */
void on_tty_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);

#ifdef __cplusplus
}
#endif

#endif /* CLIENT_TUI_CALLBACKS_H */
