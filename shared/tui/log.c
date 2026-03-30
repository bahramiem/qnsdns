/**
 * @file shared/tui/log.c
 * @brief Logic for managing the TUI log buffer.
 */

#include "log.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "../uv.h"

void tui_debug_init(tui_ctx_t *t) {
    memset(&t->debug, 0, sizeof(t->debug));
    t->debug.level = 2; // Default to INFO
    t->debug.auto_scroll = 1;
}

void tui_debug_log(tui_ctx_t *t, int level, const char *fmt, ...) {
    if (level > t->debug.level) return;
    
    va_list ap;
    va_start(ap, fmt);
    
    int idx = t->debug.head % TUI_DEBUG_LINES;
    
    /* 1. Get a timestamp for when this log happened */
    static uint64_t start_time = 0;
    uint64_t now = uv_hrtime() / 1000000ULL;
    if (start_time == 0) start_time = now;
    uint64_t rel_ms = now - start_time;
    
    /* 2. Format a human-readable prefix: [+0000123ms INF] */
    const char *level_str = (level == 0) ? "ERR" :
                            (level == 1) ? "WRN" :
                            (level == 2) ? "INF" : "DBG";
    
    int prefix_len = snprintf(t->debug.lines[idx], TUI_DEBUG_LINE_SIZE,
                              "[+%07ums] %s ",
                              (unsigned)(rel_ms % 10000000),
                              level_str);
    
    /* 3. Add the actual log message */
    vsnprintf(t->debug.lines[idx] + prefix_len, TUI_DEBUG_LINE_SIZE - prefix_len, fmt, ap);
    va_end(ap);
    
    /* 4. Ensure the line is null-terminated */
    t->debug.lines[idx][TUI_DEBUG_LINE_SIZE - 1] = '\0';
    
    /* 5. Update the buffer markers */
    t->debug.head++;
    t->debug.count++;
    if (t->debug.count > TUI_DEBUG_LINES) t->debug.count = TUI_DEBUG_LINES;
}

void tui_debug_clear(tui_ctx_t *t) {
    memset(&t->debug, 0, sizeof(t->debug));
    t->debug.level = 2;
    t->debug.auto_scroll = 1;
}

void tui_debug_set_level(tui_ctx_t *t, int level) {
    t->debug.level = level;
}

void tui_debug_scroll_up(tui_ctx_t *t, int lines) {
    t->debug_scroll -= lines;
    if (t->debug_scroll < 0) t->debug_scroll = 0;
}

void tui_debug_scroll_down(tui_ctx_t *t, int lines) {
    t->debug_scroll += lines;
    /* We don't cap scroll down because count is dynamic, 
     * render_debug_view handles the upper safety bound. */
}
