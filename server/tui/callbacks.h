/**
 * @file server/tui/callbacks.h
 * @brief Server-Side TUI Timer Callbacks and TTY Input Handling
 *
 * Bridges the core networking state (sessions, swarm) to the shared TUI
 * rendering layer. These callbacks are invoked by libuv timers and do two things:
 *   1. Collect statistics from live state.
 *   2. Call tui_render() or handle keyboard events.
 *
 * Example:
 *   uv_timer_init(loop, &g_tui_timer);
 *   uv_timer_start(&g_tui_timer, on_tui_timer, 1000, 1000);
 *   uv_timer_init(loop, &g_idle_timer);
 *   uv_timer_start(&g_idle_timer, on_idle_timer, 1000, 1000);
 */

#ifndef SERVER_TUI_CALLBACKS_H
#define SERVER_TUI_CALLBACKS_H

#include "uv.h"
#include "shared/tui.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Idle timer callback (1 second).
 *
 * Handles:
 *   - Session idle timeout enforcement.
 *   - Periodic swarm file save.
 *   - Per-second bandwidth counter reset.
 */
void on_idle_timer(uv_timer_t *t);

/**
 * @brief TUI render timer callback (1 second).
 *
 * Counts active sessions, updates stats, then calls tui_render().
 */
void on_tui_timer(uv_timer_t *t);

/**
 * @brief Fill a tui_client_snap_t array from the session table.
 *
 * Called by the TUI to display active client connections.
 *
 * @param out          Output array to fill.
 * @param max_clients  Maximum elements in @p out.
 * @return Number of active sessions written.
 */
int get_active_clients(tui_client_snap_t *out, int max_clients);

/**
 * @brief libuv TTY read buffer allocator.
 */
void on_tty_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);

/**
 * @brief libuv TTY read callback — forwards keypresses to tui_handle_key().
 */
void on_tty_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);

#ifdef __cplusplus
}
#endif

#endif /* SERVER_TUI_CALLBACKS_H */
