/**
 * @file shared/tui/render.h
 * @brief Core rendering functions and screen management for the TUI.
 */

#ifndef QNS_TUI_RENDER_H
#define QNS_TUI_RENDER_H

#include "core.h"

/**
 * @brief Main render function for the TUI.
 *
 * This function clears the screen and delegates to sub-panel renderers
 * based on the current context state.
 */
void tui_render(tui_ctx_t *t);

/**
 * @brief Get the latest terminal width and height.
 */
void tui_get_terminal_size(int *width, int *height);

/**
 * @brief Shutdown the TUI and restore terminal settings.
 */
void tui_shutdown(tui_ctx_t *t);

/* ── Drawing Helpers (used by panel modules) ───────────────────────────────*/

void tui_draw_box(int x, int y, int width, int height, const char *color, const char *title);
void tui_draw_hline(int x, int y, int width, const char *color);
void tui_draw_vline(int x, int y, int height, const char *color);
void tui_repeat_char(const char *c, int count);

void tui_draw_progress_bar(int x, int y, int width, double percent, 
                           const char *label, const char *value_str,
                           const char *color_low, const char *color_mid, const char *color_high);

void tui_draw_throughput_bar(int x, int y, int width, double kbps,
                             const char *label, int is_upload);

#endif /* QNS_TUI_RENDER_H */
