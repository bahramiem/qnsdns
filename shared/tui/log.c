/**
 * @file shared/tui/log.c
 * @brief Logic for managing the TUI log buffer.
 */

#include "log.h"
#include "ansi.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "../../uv.h"

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
}

void tui_render_log_line(const char *line, int y, int x, int width) {
    if (width <= 0) return;

    char buf[512];
    strncpy(buf, line, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    /* Truncate to width first to prevent overflow during highlighting */
    if ((int)strlen(buf) > width - 1) {
        buf[width - 1] = '\0';
    }

    /* Extract log level from format: [+XXXXXXXms] LEVEL message */
    const char *level_start = strstr(buf, "]");
    int level = 2; /* Default INFO */

    if (level_start) {
        level_start += 2;
        if (strncmp(level_start, "ERR", 3) == 0) level = 0;
        else if (strncmp(level_start, "WRN", 3) == 0) level = 1;
        else if (strncmp(level_start, "DBG", 3) == 0) level = 3;
    }

    /* Apply color based on level */
    const char *level_color = ANSI_GREEN;
    if (level == 0) level_color = ANSI_RED;
    else if (level == 1) level_color = ANSI_YELLOW;
    else if (level == 3) level_color = ANSI_CYAN;

    printf("\033[%d;%dH", y, x);

    /* Print character by character to handle highlighting */
    int pos = 0;
    int printed = 0;
    int max_print = width - 1;

    while (buf[pos] && printed < max_print) {
        int is_keyword = 0;
        const char *color = NULL;

        if (strncmp(&buf[pos], "session", 7) == 0) { is_keyword = 7; color = ANSI_BR_YELLOW; }
        else if (strncmp(&buf[pos], "DNS", 3) == 0) { is_keyword = 3; color = ANSI_BR_BLUE; }
        else if (strncmp(&buf[pos], "FEC", 3) == 0) { is_keyword = 3; color = ANSI_BR_MAGENTA; }
        else if (strncmp(&buf[pos], "resolver", 8) == 0) { is_keyword = 8; color = ANSI_BR_GREEN; }
        else if (strncmp(&buf[pos], "CONNECT", 7) == 0) { is_keyword = 7; color = ANSI_BR_WHITE; }
        else if (strncmp(&buf[pos], "error", 5) == 0) { is_keyword = 5; color = ANSI_BR_RED; }
        else if (strncmp(&buf[pos], "failed", 6) == 0) { is_keyword = 6; color = ANSI_BR_RED; }

        if (is_keyword && printed + is_keyword <= max_print) {
            printf("%s", color);
            for (int k = 0; k < is_keyword && printed < max_print; k++) {
                putchar(buf[pos++]);
                printed++;
            }
            printf(ANSI_RESET);
        } else {
            putchar(buf[pos++]);
            printed++;
        }
    }

    /* Clear rest of line */
    if (printed < max_print) {
        printf("%*s", max_print - printed, "");
    }
}
