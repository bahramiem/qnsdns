/**
 * @file shared/tui/panels.h
 * @brief Panel-specific rendering functions for the TUI.
 */

#ifndef QNS_TUI_PANELS_H
#define QNS_TUI_PANELS_H

#include "core.h"

/**
 * @brief Render individual TUI panels.
 */
void tui_render_sidebar(tui_ctx_t *t, int x, int y, int height);
void tui_render_dashboard(tui_ctx_t *t, int x, int y, int width, int height);
void tui_render_resolvers_view(tui_ctx_t *t, int x, int y, int width, int height);
void tui_render_config_view(tui_ctx_t *t, int x, int y, int width, int height);
void tui_render_debug_view(tui_ctx_t *t, int x, int y, int width, int height);
void tui_render_help_view(tui_ctx_t *t, int x, int y, int width, int height);
void tui_render_proto_test_view(tui_ctx_t *t, int x, int y, int width, int height);
void tui_render_log_panel(tui_ctx_t *t, int x, int y, int width, int height);

#endif /* QNS_TUI_PANELS_H */
