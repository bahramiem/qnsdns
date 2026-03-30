/**
 * @file shared/tui/log.h
 * @brief Debug logging management for the TUI.
 */

#ifndef QNS_TUI_LOG_H
#define QNS_TUI_LOG_H

#include "core.h"
#include <stdarg.h>

/**
 * @brief Initialize the log buffer.
 */
void tui_debug_init(tui_ctx_t *t);

/**
 * @brief Log a message to the TUI debug panel.
 */
void tui_debug_log(tui_ctx_t *t, int level, const char *fmt, ...);

/**
 * @brief Clear all logs.
 */
void tui_debug_clear(tui_ctx_t *t);

/**
 * @brief Set the visible log level.
 */
void tui_debug_set_level(tui_ctx_t *t, int level);

/**
 * @brief Scroll the debug log view.
 */
void tui_debug_scroll_up(tui_ctx_t *t, int lines);
void tui_debug_scroll_down(tui_ctx_t *t, int lines);

#endif /* QNS_TUI_LOG_H */
