/**
 * @file shared/tui/render.c
 * @brief Main rendering engine for the TUI.
 */

#include "render.h"
#include "ansi.h"
#include "panels.h"
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/ioctl.h>
#include <unistd.h>
#endif

/* ── Global Terminal Geometry ──────────────────────────────────────────────*/
static int g_term_width = 120;
static int g_term_height = 40;

void tui_get_terminal_size(int *width, int *height) {
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi)) {
        g_term_width = csbi.srWindow.Right - csbi.srWindow.Left + 1;
        g_term_height = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
    }
#else
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        g_term_width = ws.ws_col;
        g_term_height = ws.ws_row;
    }
#endif
    if (g_term_width < MIN_TERM_WIDTH) g_term_width = MIN_TERM_WIDTH;
    if (g_term_height < MIN_TERM_HEIGHT) g_term_height = MIN_TERM_HEIGHT;

    if (width) *width = g_term_width;
    if (height) *height = g_term_height;
}

void tui_repeat_char(const char *c, int count) {
    for (int i = 0; i < count; i++) printf("%s", c);
}

void tui_draw_hline(int x, int y, int width, const char *color) {
    printf("\033[%d;%dH%s", y, x, color);
    tui_repeat_char(BOX_HORZ, width);
    printf(ANSI_RESET);
}

void tui_draw_vline(int x, int y, int height, const char *color) {
    for (int i = 0; i < height; i++) {
        printf("\033[%d;%dH%s%s" ANSI_RESET, y + i, x, color, BOX_VERT);
    }
}

void tui_draw_box(int x, int y, int width, int height, const char *color, const char *title) {
    printf("\033[%d;%dH%s%s" ANSI_RESET, y, x, color, BOX_TOP_LEFT);
    tui_repeat_char(BOX_HORZ, width - 2);
    printf("%s%s" ANSI_RESET, color, BOX_TOP_RIGHT);
    
    if (title && strlen(title) > 0) {
        int title_x = x + (width - (int)strlen(title)) / 2;
        printf("\033[%d;%dH%s %s %s" ANSI_RESET, y, title_x, color, title, BOX_T_DOWN);
    }
    
    for (int i = 1; i < height - 1; i++) {
        printf("\033[%d;%dH%s%s" ANSI_RESET, y + i, x, color, BOX_VERT);
        printf("\033[%d;%dH%s%s" ANSI_RESET, y + i, x + width - 1, color, BOX_VERT);
    }
    
    printf("\033[%d;%dH%s%s" ANSI_RESET, y + height - 1, x, color, BOX_BOT_LEFT);
    tui_repeat_char(BOX_HORZ, width - 2);
    printf("%s%s" ANSI_RESET, color, BOX_BOT_RIGHT);
}

void tui_render(tui_ctx_t *t) {
    if (!t) return;
    tui_get_terminal_size(NULL, NULL);
    
    printf(ANSI_CLEAR);
    
    int content_x = SIDEBAR_WIDTH + 2;
    int content_width = g_term_width - SIDEBAR_WIDTH - 3;
    int content_height = g_term_height - 1;
    
    /* 1. Draw Persistent UI Elements (Sidebar) */
    tui_render_sidebar(t, 1, 1, g_term_height);
    
    /* 2. Delegate Rendering to current active panel */
    switch (t->panel) {
        case 0: tui_render_dashboard(t, content_x, 1, content_width, content_height); break;
        case 1: tui_render_resolvers_view(t, content_x, 1, content_width, content_height); break;
        case 2: tui_render_config_view(t, content_x, 1, content_width, content_height); break;
        case 3: tui_render_debug_view(t, content_x, 1, content_width, content_height); break;
        case 4: tui_render_help_view(t, content_x, 1, content_width, content_height); break;
        case 5: tui_render_proto_test_view(t, content_x, 1, content_width, content_height); break;
        default: tui_render_dashboard(t, content_x, 1, content_width, content_height); break;
    }
    
    fflush(stdout);
}

void tui_init(tui_ctx_t *t, tui_stats_t *stats,
              resolver_pool_t *pool, dnstun_config_t *cfg,
              const char *mode, const char *config_path)
{
    if (!t) return;
    memset(t, 0, sizeof(*t));
    t->stats = stats;
    t->pool = pool;
    t->cfg = cfg;
    t->config_path = config_path;
    t->running = 1;
    t->panel = 0; /* Dashboard */
    
    if (stats && mode) {
        strncpy(stats->mode, mode, sizeof(stats->mode) - 1);
    }
    
    /* Initial terminal size detection */
    tui_get_terminal_size(NULL, NULL);
    
    /* Clear and Hide Cursor for cleaner starting */
    printf(ANSI_CLEAR ANSI_HIDE_CUR);
    fflush(stdout);
}

void tui_shutdown(tui_ctx_t *t) {
    (void)t;
    printf(ANSI_SHOW_CUR ANSI_CLEAR);
    fflush(stdout);
}

/* ── Progress Bar Rendering ────────────────────────────────────────────────*/
void tui_draw_progress_bar(int x, int y, int width, double percent, 
                           const char *label, const char *value_str,
                           const char *color_low, const char *color_mid, const char *color_high) {
    int filled = (int)(percent * (width - 2) / 100.0);
    if (filled > width - 2) filled = width - 2;
    if (filled < 0) filled = 0;
    
    const char *bar_color = color_low;
    if (percent > 33) bar_color = color_mid;
    if (percent > 66) bar_color = color_high;
    
    printf("\033[%d;%dH" ANSI_DIM "%s" ANSI_RESET, y, x, label);
    printf("\033[%d;%dH%s", y, x + 6, BOX_T_RIGHT);
    
    printf("%s", bar_color);
    for (int i = 0; i < filled; i++) printf(BAR_FULL);
    printf(ANSI_RESET);
    
    for (int i = filled; i < width - 2; i++) printf(BAR_EMPTY);
    printf("%s " ANSI_CYAN "%s" ANSI_RESET, BOX_T_LEFT, value_str);
}

void tui_draw_throughput_bar(int x, int y, int width, double kbps,
                             const char *label, int is_upload) {
    const char *color = is_upload ? ANSI_BR_GREEN : ANSI_BR_CYAN;
    const char *icon = is_upload ? "^" : "v";

    /* Scale: 0-1000 KB/s maps to 0-100% */
    double percent = (kbps / 1000.0) * 100.0;
    if (percent > 100) percent = 100;

    /* Leave space for icon (2 chars), bar, space (1), and "NNNN " (5) */
    int bar_width = width - 8;
    if (bar_width < 4) bar_width = 4;

    int filled = (int)(percent * bar_width / 100.0);

    printf("\033[%d;%dH%s%s" ANSI_RESET, y, x, color, icon);
    printf("%s", is_upload ? ANSI_GREEN : ANSI_CYAN);

    for (int i = 0; i < filled; i++) printf(BAR_FULL);
    printf(ANSI_RESET);
    for (int i = filled; i < bar_width; i++) printf(BAR_EMPTY);

    /* Truncate large numbers - show integer KB/s to save space */
    if (kbps > 9999.9) kbps = 9999.9;
    printf(" " ANSI_BOLD "%4.0f" ANSI_RESET, kbps);
}
