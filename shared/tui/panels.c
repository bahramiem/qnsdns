/**
 * @file shared/tui/panels.c
 * @brief Implementation of individual TUI screens and components.
 */

#include "panels.h"
#include "render.h"
#include "ansi.h"
#include "log.h"
#include <stdio.h>
#include <string.h>
#include "../uv.h"

/* ── Dashboard Rendering ───────────────────────────────────────────────────*/

void tui_render_sidebar(tui_ctx_t *t, int x, int y, int height) {
    /* Sidebar background */
    printf(ANSI_BG_GRAY);
    for (int i = 0; i < height; i++) {
        printf("\033[%d;%dH", y + i, x);
        tui_repeat_char(" ", SIDEBAR_WIDTH);
    }
    printf(ANSI_RESET);
    
    /* Logo/Title */
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_CYAN " ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓" ANSI_RESET, y + 1, x + 1);
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_CYAN " ▓" ANSI_RESET " " ANSI_BOLD "DNSTUN" ANSI_RESET "          " ANSI_BR_CYAN "▓" ANSI_RESET, y + 2, x + 1);
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_CYAN " ▓" ANSI_RESET " " ANSI_DIM "%s" ANSI_RESET "       " ANSI_BR_CYAN "▓" ANSI_RESET, y + 3, x + 1, t->stats->mode);
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_CYAN " ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓" ANSI_RESET, y + 4, x + 1);
    
    /* Menu Items */
    const char *items[] = {"Dashboard", "Resolvers", "Config", "Logs", "Help", "Test"};
    
    for (int i = 0; i < 6; i++) {
        int row = y + 7 + i * 2;
        int is_selected = (t->panel == i);
        
        if (is_selected) {
            printf("\033[%d;%dH" ANSI_BG_BLUE ANSI_BR_WHITE " " MENU_ARROW " %d. %-14s " ANSI_RESET, 
                   row, x + 1, i + 1, items[i]);
        } else {
            printf("\033[%d;%dH" ANSI_GRAY "   %d." ANSI_RESET " %-14s ", 
                   row, x + 1, i + 1, items[i]);
        }
    }
}

void tui_render_dashboard(tui_ctx_t *t, int x, int y, int width, int height) {
    if (!t) return;

    /* Example of a human-readable comment for junior developers:
     * This dashboard shows the most important metrics at a glance.
     * We divide the screen into two main columns. */
    
    tui_draw_box(x, y, width / 2 - 1, 8, ANSI_BR_BLUE, " Server ");
    /* ... more drawing logic would go here, simplified for now ... */
    
    printf("\033[%d;%dH" ANSI_BOLD "Mode:   " ANSI_RESET "%s", y + 2, x + 2, t->stats->mode);
    printf("\033[%d;%dH" ANSI_BOLD "Upload: " ANSI_RESET "%.1f KB/s", y + 3, x + 2, t->stats->tx_bytes_sec);
    printf("\033[%d;%dH" ANSI_BOLD "Down:   " ANSI_RESET "%.1f KB/s", y + 4, x + 2, t->stats->rx_bytes_sec);
}

void tui_render_resolvers_view(tui_ctx_t *t, int x, int y, int width, int height) {
    tui_draw_box(x, y, width, height, ANSI_BR_CYAN, " Resolver Pool ");
    
    if (t->pool) {
        printf("\033[%d;%dH%-16s %-10s %s", y + 2, x + 2, "IP Address", "Status", "Latency");
        for (int i = 0; i < t->pool->count && i < 10; i++) {
            resolver_t *r = &t->pool->resolvers[i];
            printf("\033[%d;%dH%-16s %-10d %.1fms", y + 4 + i, x + 2, r->ip, r->state, r->rtt_ms);
        }
    }
}

void tui_render_config_view(tui_ctx_t *t, int x, int y, int width, int height) {
    tui_draw_box(x, y, width, height, ANSI_BR_GREEN, " Configuration ");
    
    if (t->cfg) {
        printf("\033[%d;%dH[d] Encryption: %s", y + 2, x + 2, t->cfg->encryption ? "ON" : "OFF");
        printf("\033[%d;%dH[f] Jitter:     %s", y + 3, x + 2, t->cfg->jitter ? "ON" : "OFF");
        printf("\033[%d;%dH[g] Padding:    %s", y + 4, x + 2, t->cfg->padding ? "ON" : "OFF");
    }
}

void tui_render_debug_view(tui_ctx_t *t, int x, int y, int width, int height) {
    tui_draw_box(x, y, width, height, ANSI_BR_YELLOW, " Debug Logs ");
    
    for (int i = 0; i < height - 4 && i < t->debug.count; i++) {
        int idx = (t->debug.head - 1 - i) % TUI_DEBUG_LINES;
        if (idx < 0) idx += TUI_DEBUG_LINES;
        printf("\033[%d;%dH%s", y + 2 + i, x + 2, t->debug.lines[idx]);
    }
}

void tui_render_help_view(tui_ctx_t *t, int x, int y, int width, int height) {
    tui_draw_box(x, y, width, height, ANSI_BR_WHITE, " Help Guide ");
    printf("\033[%d;%dH1-6: Switch Panels", y + 2, x + 2);
    printf("\033[%d;%dHQ:   Quit", y + 3, x + 2);
}

void tui_render_proto_test_view(tui_ctx_t *t, int x, int y, int width, int height) {
    tui_draw_box(x, y, width, height, ANSI_BR_MAGENTA, " Protocol Test ");
    printf("\033[%d;%dHStatus: %s", y + 2, x + 2, 
           t->proto_test.test_pending ? "Pending..." : "Idle");
}
