/**
 * @file shared/tui/input.h
 * @brief Keyboard input and command handling for the TUI.
 */

#ifndef QNS_TUI_INPUT_H
#define QNS_TUI_INPUT_H

#include "core.h"

/**
 * @brief Process a single key press.
 */
void tui_handle_key(tui_ctx_t *t, int key);

/**
 * @brief Start collecting text input from the user (e.g., for adding a resolver).
 */
void tui_start_input(tui_ctx_t *t, const char *label, void (*done_cb)(tui_ctx_t*, const char*));

#endif /* QNS_TUI_INPUT_H */
