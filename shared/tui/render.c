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
    printf(ANSI_SHOW_CUR);
    printf(ANSI_CLEAR);
    fflush(stdout);
}
