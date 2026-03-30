/**
 * @file shared/tui/tui.h
 * @brief Public interface for the Modular TUI.
 * 
 * This is the main entry point for using the TUI in both the 
 * client and server.
 * 
 * @example
 * tui_ctx_t tui;
 * tui_init(&tui, &stats, &pool, &cfg, "CLIENT", "/etc/dnstun.ini");
 * while (tui.running) {
 *     tui_render(&tui);
 *     int key = get_key();
 *     tui_handle_key(&tui, key);
 * }
 * tui_shutdown(&tui);
 */

#ifndef QNS_TUI_H
#define QNS_TUI_H

#include "core.h"
#include "ansi.h"
#include "log.h"
#include "render.h"
#include "input.h"
#include "panels.h"

/**
 * @brief Initialize the TUI system.
 */
void tui_init(tui_ctx_t *t, tui_stats_t *stats,
              resolver_pool_t *pool, dnstun_config_t *cfg,
              const char *mode, const char *config_path);

#endif /* QNS_TUI_H */
