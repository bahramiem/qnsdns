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
#include <ctype.h>
#include <stdarg.h>
#include "../../uv.h"

/* ── Log Panel (Shared across views) ──────────────────────────────────────*/

void tui_render_log_panel(tui_ctx_t *t, int x, int y, int width, int height) {
    /* Panel border with title */
    tui_draw_box(x, y, width, height, ANSI_DIM, " Live Logs ");
    
    /* Log level indicator */
    const char *levels[] = {"E", "W", "I", "D"};
    const char *level_colors[] = {ANSI_RED, ANSI_YELLOW, ANSI_GREEN, ANSI_CYAN};
    int level_x = x + width - 12;
    printf("\033[%d;%dH" ANSI_DIM "[" ANSI_RESET, y, level_x);
    for (int i = 0; i < 4; i++) {
        if (i == t->debug.level) {
            printf("%s%s" ANSI_RESET, level_colors[i], levels[i]);
        } else {
            printf(ANSI_DIM "%s" ANSI_RESET, levels[i]);
        }
    }
    printf(ANSI_DIM "]" ANSI_RESET);
    
    /* Log lines */
    int lines_to_show = height - 2;
    int start_idx = t->debug.head - lines_to_show;
    if (start_idx < 0) start_idx = 0;

    for (int i = 0; i < lines_to_show; i++) {
        int log_idx = (start_idx + i) % TUI_DEBUG_LINES;
        int row = y + 1 + i;

        /* Clear line first */
        printf("\033[%d;%dH", row, x + 1);
        for (int j = 0; j < width - 2; j++) putchar(' ');

        if (log_idx < t->debug.count) {
            tui_render_log_line(t->debug.lines[log_idx], row, x + 2, width - 4);
        }
    }
}

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
    const char *items[] = {"Dashboard", "Resolvers", "Config", "Debug Logs", "Help", "Test"};
    const char *keys[] = {"1", "2", "3", "4", "5", "6"};
    
    for (int i = 0; i < 6; i++) {
        int row = y + 7 + i * 2;
        int is_selected = (t->panel == i);
        
        if (is_selected) {
            printf("\033[%d;%dH" ANSI_BG_BLUE ANSI_BR_WHITE " " MENU_ARROW " %s. %-14s " ANSI_RESET, 
                   row, x + 1, keys[i], items[i]);
        } else {
            printf("\033[%d;%dH" ANSI_GRAY "   %s." ANSI_RESET " %-14s ", 
                   row, x + 1, keys[i], items[i]);
        }
    }
    
    /* Quit hint */
    printf("\033[%d;%dH" ANSI_DIM "Press [Q] to quit" ANSI_RESET, y + height - 1, x + 1);
}

void tui_render_dashboard(tui_ctx_t *t, int x, int y, int width, int height) {
    int content_height = height - LOG_HEIGHT - 2;
    int mid_x = x + width / 2;
    
    /* Title Bar */
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_WHITE, y, x);
    printf("═══ DNSTUN %s ═══", t->stats->mode);
    printf(ANSI_RESET);
    
    /* Server Status Panel */
    int panel_y = y + 2;
    int panel_w = (width - 3) / 2;
    
    tui_draw_box(x, panel_y, panel_w, 6, ANSI_BR_BLUE, " Server Status ");
    
    const char *status;
    const char *status_color;
    if (t->stats->server_connected) {
        status = "Connected";
        status_color = ANSI_BR_GREEN;
    } else if (t->stats->last_server_rx_ms < 5000) {
        status = "ONLINE";
        status_color = ANSI_BR_GREEN;
    } else {
        status = "OFFLINE";
        status_color = ANSI_BR_RED;
    }
    
    printf("\033[%d;%dH" ANSI_BOLD "Status:   %s%s" ANSI_RESET, panel_y + 2, x + 2, status_color, status);
    
    double avg_rtt = 0;
    int active_res = 0;
    if (t->pool) {
        for (int i = 0; i < t->pool->count; i++) {
            if (t->pool->resolvers[i].state == RSV_ACTIVE && t->pool->resolvers[i].rtt_ms < 990.0) {
                avg_rtt += t->pool->resolvers[i].rtt_ms;
                active_res++;
            }
        }
    }
    if (active_res > 0) avg_rtt /= active_res;
    else avg_rtt = 0.0;

    printf("\033[%d;%dH" ANSI_BOLD "Latency:  " ANSI_RESET "%.1f ms", panel_y + 3, x + 2, avg_rtt);
    printf("\033[%d;%dH" ANSI_BOLD "Loss:     " ANSI_RESET "%.1f%%", panel_y + 4, x + 2,
           t->stats->queries_sent > 0 ? 
           (double)t->stats->queries_lost * 100.0 / t->stats->queries_sent : 0);
    
    /* Throughput Panel */
    tui_draw_box(mid_x, panel_y, panel_w, 6, ANSI_BR_MAGENTA, " Throughput ");
    
    tui_draw_throughput_bar(mid_x + 2, panel_y + 2, panel_w - 4, t->stats->tx_bytes_sec, "Upload", 1);
    tui_draw_throughput_bar(mid_x + 2, panel_y + 4, panel_w - 4, t->stats->rx_bytes_sec, "Download", 0);
    
    /* Sessions Panel */
    int session_y = panel_y + 7;
    int session_h = content_height - 7;
    
    tui_draw_box(x, session_y, panel_w, session_h, ANSI_BR_YELLOW, " Active Sessions ");
    
    printf("\033[%d;%dH" ANSI_BOLD "Active:    " ANSI_RESET ANSI_BR_GREEN "%3d" ANSI_RESET, session_y + 2, x + 2, 
           t->stats->active_sessions);
    printf("\033[%d;%dH" ANSI_BOLD "Total TX:  " ANSI_RESET "%6.1f MB", session_y + 3, x + 2,
           t->stats->tx_total / (1024.0 * 1024.0));
    printf("\033[%d;%dH" ANSI_BOLD "Total RX:  " ANSI_RESET "%6.1f MB", session_y + 4, x + 2,
           t->stats->rx_total / (1024.0 * 1024.0));
    
    /* Stats section */
    printf("\033[%d;%dH" ANSI_DIM "─ Stats ──────────────" ANSI_RESET, session_y + 6, x + 2);
    printf("\033[%d;%dH" ANSI_GREEN "▲ " ANSI_RESET "↑ %5.1f KB/s", session_y + 7, x + 2, t->stats->tx_bytes_sec);
    printf("\033[%d;%dH" ANSI_CYAN "▼ " ANSI_RESET "↓ %5.1f KB/s", session_y + 8, x + 2, t->stats->rx_bytes_sec);
    printf("\033[%d;%dH" ANSI_YELLOW "◆ " ANSI_RESET "Sessions: %d", session_y + 9, x + 2, t->stats->active_sessions);
    printf("\033[%d;%dH" ANSI_MAGENTA "◇ " ANSI_RESET "Resolvers: %d", session_y + 10, x + 2, t->stats->active_resolvers);
    
    /* Query Stats */
    printf("\033[%d;%dH" ANSI_DIM "Queries ─────────────" ANSI_RESET, session_y + 12, x + 2);
    printf("\033[%d;%dH" ANSI_BOLD "Sent:     " ANSI_RESET "%6llu", session_y + 13, x + 2,
           (unsigned long long)t->stats->queries_sent);
    printf("\033[%d;%dH" ANSI_BOLD "Received: " ANSI_RESET "%6llu", session_y + 14, x + 2,
           (unsigned long long)t->stats->queries_recv);
    printf("\033[%d;%dH" ANSI_BOLD "Lost:     " ANSI_RESET "%6llu", session_y + 15, x + 2,
           (unsigned long long)t->stats->queries_lost);
    
    /* SOCKS5 Activity */
    if (strcmp(t->stats->mode, "CLIENT") == 0) {
        printf("\033[%d;%dH" ANSI_DIM "SOCKS5 Activity ──────" ANSI_RESET, session_y + 17, x + 2);
        printf("\033[%d;%dH" ANSI_BOLD "Total:    " ANSI_RESET "%6u", session_y + 18, x + 2, t->stats->socks5_total_conns);
        printf("\033[%d;%dH" ANSI_BOLD "Errors:   " ANSI_RESET ANSI_RED "%6u" ANSI_RESET, session_y + 19, x + 2, t->stats->socks5_total_errors);
        
        if (t->stats->socks5_last_target[0]) {
            printf("\033[%d;%dH" ANSI_DIM "Last target:" ANSI_RESET, session_y + 20, x + 2);
            printf("\033[%d;%dH" ANSI_CYAN " %s" ANSI_RESET, session_y + 21, x + 2, t->stats->socks5_last_target);
            
            if (t->stats->socks5_last_error != 0) {
                printf("\033[%d;%dH" ANSI_BR_RED " ! Error 0x%02x" ANSI_RESET, session_y + 22, x + 2, t->stats->socks5_last_error);
            } else {
                printf("\033[%d;%dH" ANSI_BR_GREEN " ✓ Connected" ANSI_RESET, session_y + 22, x + 2);
            }
        }
    }
    
    /* Resolvers Panel */
    tui_draw_box(mid_x, session_y, panel_w, session_h, ANSI_BR_CYAN, " Resolvers ");
    
    printf("\033[%d;%dH" ANSI_BOLD "Active:   " ANSI_RESET ANSI_BR_GREEN "%3d" ANSI_RESET, session_y + 2, mid_x + 2,
           t->stats->active_resolvers);
    printf("\033[%d;%dH" ANSI_BOLD "Penalty:  " ANSI_RESET ANSI_YELLOW "%3d" ANSI_RESET, session_y + 3, mid_x + 2,
           t->stats->penalty_resolvers);
    printf("\033[%d;%dH" ANSI_BOLD "Dead:     " ANSI_RESET ANSI_RED "%3d" ANSI_RESET, session_y + 4, mid_x + 2,
           t->stats->dead_resolvers);
    
    /* Domains */
    printf("\033[%d;%dH" ANSI_DIM "Domains ──────────────" ANSI_RESET, session_y + 6, mid_x + 2);
    if (t->cfg->domain_count > 0) {
        for (int i = 0; i < t->cfg->domain_count && i < 4; i++) {
            printf("\033[%d;%dH" ANSI_CYAN "%s" ANSI_RESET, session_y + 7 + i, mid_x + 2,
                   t->cfg->domains[i]);
        }
    }
    
    /* Live Log Panel at bottom */
    const int log_y = y + content_height;
    tui_render_log_panel(t, x, log_y, width, LOG_HEIGHT);
}

void tui_render_resolvers_view(tui_ctx_t *t, int x, int y, int width, int height) {
    int content_height = height - LOG_HEIGHT - 2;
    
    tui_draw_box(x, y, width, content_height, ANSI_BR_CYAN, " Resolver Pool ");
    
    if (strcmp(t->stats->mode, "SERVER") == 0) {
        printf("\033[%d;%dHServer mode - Client list would appear here", y + 2, x + 2);
    } else {
        resolver_pool_t *pool = t->pool;
        
        /* Header */
        printf("\033[%d;%dH" ANSI_BOLD "%-16s %-9s %5s %6s %5s %4s %5s %4s" ANSI_RESET,
               y + 2, x + 2, "IP", "State", "cwnd", "RTTms", "QPS", "MTU", "Loss%", "FEC");
        
        /* List resolvers */
        int shown = 0;
        int max_shown = content_height - 5;
        
        uv_mutex_lock(&pool->lock);
        for (int i = 0; i < pool->count && shown < max_shown; i++) {
            resolver_t *r = &pool->resolvers[i];
            int row = y + 4 + shown;
            
            const char *state_color = ANSI_GREEN;
            if (r->state == RSV_PENALTY) state_color = ANSI_YELLOW;
            if (r->state == RSV_DEAD || r->state == RSV_ZOMBIE) state_color = ANSI_RED;
            
            printf("\033[%d;%dH" ANSI_DIM "%-16s" ANSI_RESET " %s%-9s" ANSI_RESET " %5.0f %6.1f %5.0f %4d %5.1f %4u",
                   row, x + 2, r->ip, state_color,
                   r->state == RSV_ACTIVE ? "ACTIVE" :
                   r->state == RSV_PENALTY ? "PENALTY" :
                   r->state == RSV_DEAD ? "DEAD" :
                   r->state == RSV_ZOMBIE ? "ZOMBIE" :
                   r->state == RSV_TESTING ? "TESTING" : "UNKNOWN",
                   r->cwnd, r->rtt_ms, r->max_qps, r->downstream_mtu,
                   r->loss_rate * 100.0, r->fec_k);
            shown++;
        }
        uv_mutex_unlock(&pool->lock);
        
        printf("\033[%d;%dH" ANSI_DIM "Showing %d of %d resolvers" ANSI_RESET,
               y + content_height - 2, x + 2, shown, pool->count);
    }
    
    /* Live Log Panel */
    tui_render_log_panel(t, x, y + content_height, width, LOG_HEIGHT);
}

void tui_render_config_view(tui_ctx_t *t, int x, int y, int width, int height) {
    int content_height = height - LOG_HEIGHT - 2;
    
    tui_draw_box(x, y, width, content_height, ANSI_BR_GREEN, " Live Configuration ");
    
    dnstun_config_t *c = t->cfg;
    int row = y + 2;
    
    /* Toggleable settings with visual indicators */
    printf("\033[%d;%dH%s[ d ]" ANSI_RESET " Encryption    : %s", 
           row++, x + 2, c->encryption ? ANSI_BG_GREEN ANSI_BR_WHITE : ANSI_DIM,
           c->encryption ? ANSI_GREEN "● ON" ANSI_RESET : ANSI_RED "○ OFF" ANSI_RESET);
    
    printf("\033[%d;%dH%s[ f ]" ANSI_RESET " Jitter        : %s",
           row++, x + 2, c->jitter ? ANSI_BG_GREEN ANSI_BR_WHITE : ANSI_DIM,
           c->jitter ? ANSI_GREEN "● ON" ANSI_RESET : ANSI_RED "○ OFF" ANSI_RESET);
    
    printf("\033[%d;%dH%s[ g ]" ANSI_RESET " Padding       : %s",
           row++, x + 2, c->padding ? ANSI_BG_GREEN ANSI_BR_WHITE : ANSI_DIM,
           c->padding ? ANSI_GREEN "● ON" ANSI_RESET : ANSI_RED "○ OFF" ANSI_RESET);
    
    printf("\033[%d;%dH%s[ h ]" ANSI_RESET " Chaffing      : %s",
           row++, x + 2, c->chaffing ? ANSI_BG_GREEN ANSI_BR_WHITE : ANSI_DIM,
           c->chaffing ? ANSI_GREEN "● ON" ANSI_RESET : ANSI_RED "○ OFF" ANSI_RESET);
    
    printf("\033[%d;%dH%s[ i ]" ANSI_RESET " Chrome Cover  : %s",
           row++, x + 2, c->chrome_cover ? ANSI_BG_GREEN ANSI_BR_WHITE : ANSI_DIM,
           c->chrome_cover ? ANSI_GREEN "● ON" ANSI_RESET : ANSI_RED "○ OFF" ANSI_RESET);
    
    printf("\033[%d;%dH%s[ j ]" ANSI_RESET " DNS Flux      : %s",
           row++, x + 2, c->dns_flux ? ANSI_BG_GREEN ANSI_BR_WHITE : ANSI_DIM,
           c->dns_flux ? ANSI_GREEN "● ON" ANSI_RESET : ANSI_RED "○ OFF" ANSI_RESET);
    
    /* Numeric settings */
    row += 2;
    printf("\033[%d;%dH" ANSI_BOLD "Poll Interval: " ANSI_RESET "%d ms", row++, x + 2, c->poll_interval_ms);
    printf("\033[%d;%dH" ANSI_BOLD "FEC Window:    " ANSI_RESET "%d", row++, x + 2, c->fec_window);
    printf("\033[%d;%dH" ANSI_BOLD "Max CWND:      " ANSI_RESET "%.0f", row++, x + 2, c->cwnd_max);
    
    /* Domains */
    row += 2;
    printf("\033[%d;%dH" ANSI_BOLD "Domains [m]:   " ANSI_RESET, row++, x + 2);
    for (int i = 0; i < c->domain_count && i < 3; i++) {
        printf(ANSI_CYAN "%s" ANSI_RESET " ", c->domains[i]);
    }
    
    /* Add resolver hint */
    printf("\033[%d;%dH" ANSI_DIM "Press [r] to add resolver" ANSI_RESET, 
           y + content_height - 2, x + 2);
    
    /* Live Log Panel */
    tui_render_log_panel(t, x, y + content_height, width, LOG_HEIGHT);
}

void tui_render_debug_view(tui_ctx_t *t, int x, int y, int width, int height) {
    /* Full-screen log view */
    tui_draw_box(x, y, width, height - 1, ANSI_BR_YELLOW, " Debug Logs (Panel 4) ");
    
    /* Log level controls - context dependent */
    printf("\033[%d;%dH" ANSI_BR_CYAN "[0]" ANSI_RESET "Err  " ANSI_BR_CYAN "[!]" ANSI_RESET "Wrn  " ANSI_BR_CYAN "[@]" ANSI_RESET "Inf  " ANSI_BR_CYAN "[#]" ANSI_RESET "Vrb  " ANSI_DIM "[↑↓]Scroll" ANSI_RESET,
           y, x + 2);
    
    int lines_to_show = height - 4;
    int start_idx = t->debug_scroll;
    int max_idx = t->debug.count - lines_to_show;
    if (max_idx < 0) max_idx = 0;
    if (start_idx > max_idx) start_idx = max_idx;
    if (start_idx < 0) start_idx = 0;
    
    for (int i = 0; i < lines_to_show; i++) {
        int log_idx = start_idx + i;
        int row = y + 2 + i;
        
        if (log_idx < t->debug.count && log_idx >= 0) {
            int buf_idx = log_idx % TUI_DEBUG_LINES;
            tui_render_log_line(t->debug.lines[buf_idx], row, x + 2, width - 4);
        } else {
            printf("\033[%d;%dH%*s", row, x + 2, width - 4, "");
        }
    }
    
    /* Scroll indicator */
    printf("\033[%d;%dH" ANSI_DIM "Lines: %d-%d of %d" ANSI_RESET,
           y + height - 2, x + 2, start_idx + 1, 
           start_idx + lines_to_show > t->debug.count ? t->debug.count : start_idx + lines_to_show,
           t->debug.count);
}

void tui_render_help_view(tui_ctx_t *t, int x, int y, int width, int height) {
    int content_height = height - LOG_HEIGHT - 2;
    
    tui_draw_box(x, y, width, content_height, ANSI_BR_CYAN, " DNSTUN Help Guide ");
    
    int row = y + 2;
    int col = x + 2;
    int section_width = (width - 6) / 2;
    
    /* Left Column: Navigation */
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_WHITE BOX_TOP_LEFT BOX_HORZ BOX_HORZ BOX_HORZ " Navigation " BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_TOP_RIGHT ANSI_RESET, row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  1  " ANSI_RESET "Dashboard (main stats view)", row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  2  " ANSI_RESET "Resolver Pool", row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  3  " ANSI_RESET "Configuration Editor", row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  4  " ANSI_RESET "Debug Logs (full screen)", row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  5  " ANSI_RESET "This Help Guide", row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  6  " ANSI_RESET "Protocol Test", row++, col);
    printf("\033[%d;%dH" ANSI_BR_WHITE BOX_BOT_LEFT BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_BOT_RIGHT ANSI_RESET, row++, col);
    
    row++;
    
    /* Left Column: Config Panel Commands */
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_WHITE BOX_TOP_LEFT BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ " Config Commands " BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_TOP_RIGHT ANSI_RESET, row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  d  " ANSI_RESET "Toggle Encryption", row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  f  " ANSI_RESET "Toggle Jitter", row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  g  " ANSI_RESET "Toggle Padding", row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  h  " ANSI_RESET "Toggle Chaffing", row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  i  " ANSI_RESET "Toggle Chrome Cover", row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  j  " ANSI_RESET "Toggle DNS Flux", row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  r  " ANSI_RESET "Add Resolver", row++, col);
    printf("\033[%d;%dH" ANSI_BR_WHITE BOX_BOT_LEFT BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_BOT_RIGHT ANSI_RESET, row++, col);
    
    /* Right Column: Log Level (Debug panel only) */
    int right_col = col + section_width + 4;
    int right_row = y + 2;
    
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_WHITE BOX_TOP_LEFT BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ " Log Level " BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_TOP_RIGHT ANSI_RESET, right_row++, right_col);
    printf("\033[%d;%dH" ANSI_CYAN "  0  " ANSI_RESET "Errors only", right_row++, right_col);
    printf("\033[%d;%dH" ANSI_CYAN "  !  " ANSI_RESET "Warnings + Errors", right_row++, right_col);
    printf("\033[%d;%dH" ANSI_CYAN "  @  " ANSI_RESET "Info + Warnings + Errors", right_row++, right_col);
    printf("\033[%d;%dH" ANSI_CYAN "  #  " ANSI_RESET "Verbose (all messages)", right_row++, right_col);
    printf("\033[%d;%dH" ANSI_BR_WHITE BOX_BOT_LEFT BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_HORZ BOX_BOT_RIGHT ANSI_RESET, right_row++, right_col);
    
    /* Live Log Panel */
    tui_render_log_panel(t, x, y + content_height, width, LOG_HEIGHT);
}

void tui_render_proto_test_view(tui_ctx_t *t, int x, int y, int width, int height) {
    int content_height = height - LOG_HEIGHT - 2;
    
    tui_draw_box(x, y, width, content_height, ANSI_BR_MAGENTA, " Protocol Test ");
    
    int row = y + 2;
    int col = x + 2;
    
    printf("\033[%d;%dH" ANSI_BOLD "Protocol Loopback Test" ANSI_RESET, row++, col);
    row++;
    
    if (t->proto_test.test_pending) {
        uint64_t now = uv_hrtime() / 1000000ULL;
        uint64_t elapsed = now - t->proto_test.last_test_sent_ms;
        printf("\033[%d;%dH" ANSI_BR_YELLOW "◉ PENDING" ANSI_RESET " - waiting for response (%llums)", 
               row++, col, (unsigned long long)elapsed);
    } else if (t->proto_test.last_test_sent_ms > 0) {
        uint64_t latency = t->proto_test.last_test_recv_ms - t->proto_test.last_test_sent_ms;
        if (t->proto_test.last_test_success) {
            printf("\033[%d;%dH" ANSI_BR_GREEN "✓ SUCCESS" ANSI_RESET " - Latency: %llu ms", 
                   row++, col, (unsigned long long)latency);
        } else {
            printf("\033[%d;%dH" ANSI_BR_RED "✗ TIMEOUT" ANSI_RESET " - No response received", 
                   row++, col);
        }
    } else {
        printf("\033[%d;%dH" ANSI_DIM "No test performed yet" ANSI_RESET, row++, col);
    }
    row++;
    
    printf("\033[%d;%dH" ANSI_BOLD "Last Test Details:" ANSI_RESET, row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  Seq:     " ANSI_RESET "%u", row++, col, t->proto_test.test_sequence);
    printf("\033[%d;%dH" ANSI_CYAN "  Payload: " ANSI_RESET "%s", row++, col, 
           *t->proto_test.test_payload ? t->proto_test.test_payload : "(none)");
    
    /* Live Log Panel */
    tui_render_log_panel(t, x, y + content_height, width, LOG_HEIGHT);
}

