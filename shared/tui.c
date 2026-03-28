#include "tui.h"
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <stdarg.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#else
#include <sys/ioctl.h>
#include <unistd.h>
#endif

/* ═══════════════════════════════════════════════════════════════════════════
   MODERN TUI DESIGN - 2 Column Dashboard with Live Logging
   ═══════════════════════════════════════════════════════════════════════════ */

/* ── ANSI Escape Codes ──────────────────────────────────────────────────────*/
#define ANSI_RESET      "\033[0m"
#define ANSI_BOLD       "\033[1m"
#define ANSI_DIM        "\033[2m"
#define ANSI_ITALIC     "\033[3m"
#define ANSI_UNDERLINE  "\033[4m"
#define ANSI_BLINK      "\033[5m"

/* Foreground Colors */
#define ANSI_BLACK      "\033[30m"
#define ANSI_RED        "\033[31m"
#define ANSI_GREEN      "\033[32m"
#define ANSI_YELLOW     "\033[33m"
#define ANSI_BLUE       "\033[34m"
#define ANSI_MAGENTA    "\033[35m"
#define ANSI_CYAN       "\033[36m"
#define ANSI_WHITE      "\033[37m"
#define ANSI_GRAY       "\033[90m"
#define ANSI_BR_RED     "\033[91m"
#define ANSI_BR_GREEN   "\033[92m"
#define ANSI_BR_YELLOW  "\033[93m"
#define ANSI_BR_BLUE    "\033[94m"
#define ANSI_BR_MAGENTA "\033[95m"
#define ANSI_BR_CYAN    "\033[96m"
#define ANSI_BR_WHITE   "\033[97m"

/* Background Colors */
#define ANSI_BG_BLACK   "\033[40m"
#define ANSI_BG_RED     "\033[41m"
#define ANSI_BG_GREEN   "\033[42m"
#define ANSI_BG_YELLOW  "\033[43m"
#define ANSI_BG_BLUE    "\033[44m"
#define ANSI_BG_MAGENTA "\033[45m"
#define ANSI_BG_CYAN    "\033[46m"
#define ANSI_BG_GRAY    "\033[100m"

/* Cursor Control */
#define ANSI_CLEAR      "\033[2J\033[H"
#define ANSI_HIDE_CUR   "\033[?25l"
#define ANSI_SHOW_CUR   "\033[?25h"
#define ANSI_SAVE_CUR   "\033[s"
#define ANSI_RESTORE_CUR "\033[u"

/* ── Unicode Box Drawing Characters ────────────────────────────────────────*/
#define BOX_HORZ        "─"
#define BOX_VERT        "│"
#define BOX_TOP_LEFT    "┌"
#define BOX_TOP_RIGHT   "┐"
#define BOX_BOT_LEFT    "└"
#define BOX_BOT_RIGHT   "┘"
#define BOX_CROSS       "┼"
#define BOX_T_DOWN      "┬"
#define BOX_T_UP        "┴"
#define BOX_T_RIGHT     "├"
#define BOX_T_LEFT      "┤"
#define BOX_DOUBLE_HORZ "═"
#define BOX_DOUBLE_VERT "║"
#define BOX_DOUBLE_TL   "╔"
#define BOX_DOUBLE_TR   "╗"
#define BOX_DOUBLE_BL   "╚"
#define BOX_DOUBLE_BR   "╝"

/* Progress Bar Unicode Blocks */
#define BAR_EMPTY       "░"
#define BAR_LIGHT       "▒"
#define BAR_MEDIUM      "▓"
#define BAR_FULL        "█"
#define BAR_LEFT        "▌"
#define BAR_RIGHT       "▐"

/* ── Layout Constants ──────────────────────────────────────────────────────*/
#define SIDEBAR_WIDTH   22
#define LOG_HEIGHT      8
#define MIN_TERM_WIDTH  100
#define MIN_TERM_HEIGHT 30

/* ── Global State ──────────────────────────────────────────────────────────*/
static int g_term_width = 120;
static int g_term_height = 40;

/* ── Helper Functions ──────────────────────────────────────────────────────*/

static void get_terminal_size(void) {
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
}

static void repeat_char(const char *c, int count) {
    for (int i = 0; i < count; i++) printf("%s", c);
}

static void draw_hline(int x, int y, int width, const char *color) {
    printf("\033[%d;%dH%s", y, x, color);
    repeat_char(BOX_HORZ, width);
    printf(ANSI_RESET);
}

static void draw_vline(int x, int y, int height, const char *color) {
    for (int i = 0; i < height; i++) {
        printf("\033[%d;%dH%s%s" ANSI_RESET, y + i, x, color, BOX_VERT);
    }
}

static void draw_box(int x, int y, int width, int height, const char *color, const char *title) {
    printf("\033[%d;%dH%s%s" ANSI_RESET, y, x, color, BOX_TOP_LEFT);
    repeat_char(BOX_HORZ, width - 2);
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
    repeat_char(BOX_HORZ, width - 2);
    printf("%s%s" ANSI_RESET, color, BOX_BOT_RIGHT);
}

/* ── Progress Bar Rendering ────────────────────────────────────────────────*/
static void draw_progress_bar(int x, int y, int width, double percent, 
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

static void draw_throughput_bar(int x, int y, int width, double kbps,
                                 const char *label, int is_upload) {
    const char *color = is_upload ? ANSI_BR_GREEN : ANSI_BR_CYAN;
    const char *icon = is_upload ? "▲" : "▼";

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

/* ── Sidebar Menu ──────────────────────────────────────────────────────────*/
static void draw_sidebar(tui_ctx_t *t, int x, int y, int height) {
    /* Sidebar background */
    printf(ANSI_BG_GRAY);
    for (int i = 0; i < height; i++) {
        printf("\033[%d;%dH", y + i, x);
        repeat_char(" ", SIDEBAR_WIDTH);
    }
    printf(ANSI_RESET);
    
    /* Logo/Title */
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_CYAN " ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓" ANSI_RESET, y + 1, x + 1);
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_CYAN " ▓" ANSI_RESET " " ANSI_BOLD "DNSTUN" ANSI_RESET "          " ANSI_BR_CYAN "▓" ANSI_RESET, y + 2, x + 1);
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_CYAN " ▓" ANSI_RESET " " ANSI_DIM "%s" ANSI_RESET "       " ANSI_BR_CYAN "▓" ANSI_RESET, y + 3, x + 1, t->stats->mode);
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_CYAN " ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓" ANSI_RESET, y + 4, x + 1);
    
    /* Menu Items */
    const char *items[] = {"Dashboard", "Resolvers", "Config", "Debug Logs", "Help"};
    const char *keys[] = {"1", "2", "3", "4", "5"};
    
    for (int i = 0; i < 5; i++) {
        int row = y + 7 + i * 2;
        int is_selected = (t->panel == i);
        
        if (is_selected) {
            printf("\033[%d;%dH" ANSI_BG_BLUE ANSI_BR_WHITE " ▶ %s. %-14s " ANSI_RESET, 
                   row, x + 1, keys[i], items[i]);
        } else {
            printf("\033[%d;%dH" ANSI_GRAY "   %s." ANSI_RESET " %-14s ", 
                   row, x + 1, keys[i], items[i]);
        }
    }
    
    /* Quit hint */
    printf("\033[%d;%dH" ANSI_DIM "Press [Q] to quit" ANSI_RESET, y + height - 1, x + 1);
}

/* ── Smart Log Highlighting ────────────────────────────────────────────────*/
static const char* highlight_log_keyword(const char *line, const char *keyword, const char *color) {
    static char result[512];
    const char *pos = strstr(line, keyword);
    if (!pos) return line;
    
    int prefix_len = (int)(pos - line);
    snprintf(result, sizeof(result), "%.*s%s%s%s%s",
             prefix_len, line,
             color, keyword, ANSI_RESET,
             pos + strlen(keyword));
    return result;
}

static void render_log_line(const char *line, int y, int x, int width) {
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

    /* Smart keyword highlighting - just print directly with color codes */
    printf("\033[%d;%dH", y, x);

    /* Print character by character to handle highlighting */
    int pos = 0;
    int printed = 0;
    int max_print = width - 1;

    while (buf[pos] && printed < max_print) {
        /* Check for keywords */
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

/* ── Live Log Panel ────────────────────────────────────────────────────────*/
static void draw_log_panel(tui_ctx_t *t, int x, int y, int width, int height) {
    /* Panel border with title */
    draw_box(x, y, width, height, ANSI_DIM, " Live Logs ");
    
    /* Log level indicator - compact, fits in title area */
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
    
    /* Log lines - clear entire area first to prevent artifacts */
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
            render_log_line(t->debug.lines[log_idx], row, x + 2, width - 4);
        }
    }
}

/* ── Main Dashboard View ───────────────────────────────────────────────────*/
static void render_dashboard(tui_ctx_t *t, int x, int y, int width, int height) {
    int content_height = height - LOG_HEIGHT - 2;
    int mid_x = x + width / 2;
    
    /* Title Bar */
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_WHITE, y, x);
    printf("═══ DNSTUN %s ═══", t->stats->mode);
    printf(ANSI_RESET);
    
    /* Server Status Panel */
    int panel_y = y + 2;
    int panel_w = (width - 3) / 2;
    
    draw_box(x, panel_y, panel_w, 6, ANSI_BR_BLUE, " Server Status ");
    
    /* Show "Connected" when server_connected flag is set, otherwise show ONLINE/OFFLINE based on last response */
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
    printf("\033[%d;%dH" ANSI_BOLD "Latency:  " ANSI_RESET "%.1f ms", panel_y + 3, x + 2, 
           (double)t->stats->last_server_rx_ms);
    printf("\033[%d;%dH" ANSI_BOLD "Loss:     " ANSI_RESET "%.1f%%", panel_y + 4, x + 2,
           t->stats->queries_sent > 0 ? 
           (double)t->stats->queries_lost * 100.0 / t->stats->queries_sent : 0);
    
    /* Throughput Panel */
    draw_box(mid_x, panel_y, panel_w, 6, ANSI_BR_MAGENTA, " Throughput ");
    
    draw_throughput_bar(mid_x + 2, panel_y + 2, panel_w - 4, t->stats->tx_bytes_sec, "Upload", 1);
    draw_throughput_bar(mid_x + 2, panel_y + 4, panel_w - 4, t->stats->rx_bytes_sec, "Download", 0);
    
    /* Sessions Panel */
    int session_y = panel_y + 7;
    int session_h = content_height - 7;
    
    draw_box(x, session_y, panel_w, session_h, ANSI_BR_YELLOW, " Active Sessions ");
    
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
    draw_box(mid_x, session_y, panel_w, session_h, ANSI_BR_CYAN, " Resolvers ");
    
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
    draw_log_panel(t, x, y + content_height, width, LOG_HEIGHT);
}

/* ── Resolvers View ────────────────────────────────────────────────────────*/
static void render_resolvers_view(tui_ctx_t *t, int x, int y, int width, int height) {
    int content_height = height - LOG_HEIGHT - 2;
    
    draw_box(x, y, width, content_height, ANSI_BR_CYAN, " Resolver Pool ");
    
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
    draw_log_panel(t, x, y + content_height, width, LOG_HEIGHT);
}

/* ── Config View ───────────────────────────────────────────────────────────*/
static void render_config_view(tui_ctx_t *t, int x, int y, int width, int height) {
    int content_height = height - LOG_HEIGHT - 2;
    
    draw_box(x, y, width, content_height, ANSI_BR_GREEN, " Live Configuration ");
    
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
    draw_log_panel(t, x, y + content_height, width, LOG_HEIGHT);
}

/* ── Protocol Test View ──────────────────────────────────────────────────────*/
static void render_proto_test_view(tui_ctx_t *t, int x, int y, int width, int height) {
    int content_height = height - LOG_HEIGHT - 2;
    
    draw_box(x, y, width, content_height, ANSI_BR_MAGENTA, " Protocol Test ");
    
    int row = y + 2;
    int col = x + 2;
    
    /* Test status */
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
    
    /* Last test details */
    printf("\033[%d;%dH" ANSI_BOLD "Last Test Details:" ANSI_RESET, row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  Seq:     " ANSI_RESET "%u", row++, col, t->proto_test.test_sequence);
    printf("\033[%d;%dH" ANSI_CYAN "  Payload: " ANSI_RESET "%s", row++, col, 
           *t->proto_test.test_payload ? t->proto_test.test_payload : "(none)");
    row++;
    
    /* Instructions */
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_CYAN "Instructions:" ANSI_RESET, row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  [x] or [X]" ANSI_RESET " - Send new protocol test packet", row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  [6]      " ANSI_RESET " - Return to this panel", row++, col);
    
    /* Live Log Panel */
    draw_log_panel(t, x, y + content_height, width, LOG_HEIGHT);
}

/* ── Debug View (Full Screen Logs) ─────────────────────────────────────────*/
static void render_debug_view(tui_ctx_t *t, int x, int y, int width, int height) {
    /* Full-screen log view */
    draw_box(x, y, width, height - 1, ANSI_BR_YELLOW, " Debug Logs (Panel 4) ");
    
    /* Log level controls - context dependent */
    printf("\033[%d;%dH" ANSI_BR_CYAN "[0]" ANSI_RESET "Err  " ANSI_BR_CYAN "[!]" ANSI_RESET "Wrn  " ANSI_BR_CYAN "[@]" ANSI_RESET "Inf  " ANSI_BR_CYAN "[#]" ANSI_RESET "Vrb  " ANSI_DIM "[↑↓]Scroll" ANSI_RESET,
           y, x + 2);
    
    /* More log lines */
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
            render_log_line(t->debug.lines[buf_idx], row, x + 2, width - 4);
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

/* ── Help View ───────────────────────────────────────────────────────────────*/
static void render_help_view(tui_ctx_t *t, int x, int y, int width, int height) {
    int content_height = height - LOG_HEIGHT - 2;
    
    draw_box(x, y, width, content_height, ANSI_BR_CYAN, " DNSTUN Help Guide ");
    
    int row = y + 2;
    int col = x + 2;
    int section_width = (width - 6) / 2;
    
    /* Left Column: Navigation */
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_WHITE "╭─ Navigation ─────────────────────" ANSI_RESET, row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  1  " ANSI_RESET "Dashboard (main stats view)", row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  2  " ANSI_RESET "Resolver Pool", row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  3  " ANSI_RESET "Configuration Editor", row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  4  " ANSI_RESET "Debug Logs (full screen)", row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  5  " ANSI_RESET "This Help Guide", row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  6  " ANSI_RESET "Protocol Test", row++, col);
    printf("\033[%d;%dH" ANSI_BR_WHITE "╰────────────────────────────────────────" ANSI_RESET, row++, col);
    
    row++; /* spacing */
    
    /* Left Column: Config Panel Commands */
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_WHITE "╭─ Config Panel Commands ─────────────" ANSI_RESET, row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  d  " ANSI_RESET "Toggle Encryption", row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  f  " ANSI_RESET "Toggle Jitter", row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  g  " ANSI_RESET "Toggle Padding", row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  h  " ANSI_RESET "Toggle Chaffing", row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  i  " ANSI_RESET "Toggle Chrome Cover", row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  j  " ANSI_RESET "Toggle DNS Flux", row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  r  " ANSI_RESET "Add Resolver", row++, col);
    printf("\033[%d;%dH" ANSI_BR_WHITE "╰────────────────────────────────────────" ANSI_RESET, row++, col);
    
    row++; /* spacing */
    
    /* Left Column: Log Level (Debug panel only) */
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_WHITE "╭─ Log Level (in Debug panel) ─────────" ANSI_RESET, row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  0  " ANSI_RESET "Errors only", row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  !  " ANSI_RESET "Warnings + Errors", row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  @  " ANSI_RESET "Info + Warnings + Errors", row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  #  " ANSI_RESET "Verbose (all messages)", row++, col);
    printf("\033[%d;%dH" ANSI_BR_WHITE "╰────────────────────────────────────────" ANSI_RESET, row++, col);
    
    /* Right Column: TUI Control */
    int right_col = col + section_width + 4;
    int right_row = y + 2;
    
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_GREEN "╭─ TUI & Tunnel Control ──────────────" ANSI_RESET, right_row++, right_col);
    printf("\033[%d;%dH" ANSI_BR_YELLOW "  Q  " ANSI_RESET "Quit TUI (tunnel keeps running!)", right_row++, right_col);
    printf("\033[%d;%dH" ANSI_BR_YELLOW "      " ANSI_RESET "Close this terminal or press", right_row++, right_col);
    printf("\033[%d;%dH" ANSI_BR_YELLOW "      " ANSI_RESET "Ctrl+C to exit TUI only.", right_row++, right_col);
    printf("\033[%d;%dH" ANSI_BR_YELLOW "      " ANSI_RESET "The tunnel will continue in", right_row++, right_col);
    printf("\033[%d;%dH" ANSI_BR_YELLOW "      " ANSI_RESET "background.", right_row++, right_col);
    printf("\033[%d;%dH" ANSI_BR_WHITE "╰────────────────────────────────────────" ANSI_RESET, right_row++, right_col);
    
    right_row++; /* spacing */
    
    /* Right Column: Reconnect Info */
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_MAGENTA "╭─ Reconnecting TUI ─────────────────" ANSI_RESET, right_row++, right_col);
    printf("\033[%d;%dH" ANSI_WHITE "  To re-open the TUI after closing:" ANSI_RESET, right_row++, right_col);
    printf("\033[%d;%dH" ANSI_CYAN "      $ " ANSI_RESET "./dnstun-client", right_row++, right_col);
    printf("\033[%d;%dH" ANSI_CYAN "      $ " ANSI_RESET "./dnstun-server", right_row++, right_col);
    printf("\033[%d;%dH" ANSI_WHITE "  (run again from another terminal)" ANSI_RESET, right_row++, right_col);
    printf("\033[%d;%dH" ANSI_BR_WHITE "╰────────────────────────────────────────" ANSI_RESET, right_row++, right_col);
    
    right_row++; /* spacing */
    
    /* Right Column: Remote Management */
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_BLUE "╭─ Remote Management ─────────────────" ANSI_RESET, right_row++, right_col);
    printf("\033[%d;%dH" ANSI_WHITE "  SSH tunnel for remote TUI:" ANSI_RESET, right_row++, right_col);
    printf("\033[%d;%dH" ANSI_CYAN " $ " ANSI_RESET "ssh -L 9090:localhost:9090", right_row++, right_col);
    printf("\033[%d;%dH" ANSI_CYAN "   " ANSI_RESET " user@your-server", right_row++, right_col);
    printf("\033[%d;%dH" ANSI_CYAN " $ " ANSI_RESET "./dnstun-tui --host localhost", right_row++, right_col);
    printf("\033[%d;%dH" ANSI_BR_WHITE "╰────────────────────────────────────────" ANSI_RESET, right_row++, right_col);
    
    /* Info Box at Bottom - properly sized NOTE */
    int note_box_width = width - 4;
    row = y + content_height - 9;
    printf("\033[%d;%dH" ANSI_BR_CYAN "┌%.*s┐" ANSI_RESET, row, col, note_box_width, "──────────────────────────────────────────────────────────────────────────────");
    row++;
    printf("\033[%d;%dH" ANSI_BR_CYAN "│" ANSI_RESET " " ANSI_BOLD ANSI_BR_WHITE "NOTE:" ANSI_RESET " Press [Q] to detach TUI. Tunnel continues running!", row++, col);
    printf("\033[%d;%dH" ANSI_BR_CYAN "│" ANSI_RESET, row++, col);
    printf("\033[%d;%dH" ANSI_BR_CYAN "│" ANSI_RESET " Close terminal or Ctrl+C to exit TUI only. Run ./dnstun-client", row++, col);
    printf("\033[%d;%dH" ANSI_BR_CYAN "│" ANSI_RESET " again to reconnect TUI.", row++, col);
    row++;
    printf("\033[%d;%dH" ANSI_BR_CYAN "└%.*s┘" ANSI_RESET, row, col, note_box_width, "──────────────────────────────────────────────────────────────────────────────");
    
    /* Live Log Panel */
    draw_log_panel(t, x, y + content_height, width, LOG_HEIGHT);
}

/* ═══════════════════════════════════════════════════════════════════════════
   PUBLIC API IMPLEMENTATION
   ═══════════════════════════════════════════════════════════════════════════ */

void tui_init(tui_ctx_t *t, tui_stats_t *stats,
              resolver_pool_t *pool, dnstun_config_t *cfg,
              const char *mode, const char *config_path)
{
    memset(t, 0, sizeof(*t));
    t->stats       = stats;
    t->pool        = pool;
    t->cfg         = cfg;
    t->running     = 1;
    t->panel       = 0;
    t->config_path = config_path;
    strncpy(stats->mode, mode, sizeof(stats->mode)-1);

    /* Initialize debug buffer */
    t->debug.level = 2;        /* default INFO */
    t->debug.auto_scroll = 1;
    t->debug_scroll = 0;

    /* Initialize protocol test state */
    memset(&t->proto_test, 0, sizeof(t->proto_test));
    t->send_debug_cb = NULL;

#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD dwMode = 0;
        if (GetConsoleMode(hOut, &dwMode)) {
            dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            SetConsoleMode(hOut, dwMode);
        }
    }
#endif

    printf(ANSI_HIDE_CUR);
    get_terminal_size();
}

void tui_render(tui_ctx_t *t) {
    get_terminal_size();
    printf(ANSI_CLEAR);
    
    int content_x = SIDEBAR_WIDTH + 2;
    int content_width = g_term_width - SIDEBAR_WIDTH - 3;
    int content_height = g_term_height - 1;
    
    /* Draw sidebar (always visible) */
    draw_sidebar(t, 1, 1, g_term_height);
    
    /* Draw content based on current panel */
    switch (t->panel) {
        case 0: render_dashboard(t, content_x, 1, content_width, content_height); break;
        case 1: render_resolvers_view(t, content_x, 1, content_width, content_height); break;
        case 2: render_config_view(t, content_x, 1, content_width, content_height); break;
        case 3: render_debug_view(t, content_x, 1, content_width, content_height); break;
        case 4: render_help_view(t, content_x, 1, content_width, content_height); break;
        case 5: render_proto_test_view(t, content_x, 1, content_width, content_height); break;
        default: render_dashboard(t, content_x, 1, content_width, content_height); break;
    }
    
    fflush(stdout);
}

void tui_handle_key(tui_ctx_t *t, int key) {
    dnstun_config_t *c = t->cfg;

    /* Handle input mode first */
    if (t->input_mode) {
        if (key == '\r' || key == '\n') {
            t->input_buf[t->input_len] = '\0';
            if (t->input_done_cb)
                t->input_done_cb(t, t->input_buf);
            t->input_mode = 0;
            t->input_len  = 0;
            memset(t->input_buf, 0, sizeof(t->input_buf));
        } else if (key == 27) {
            t->input_mode = 0;
            t->input_len  = 0;
            memset(t->input_buf, 0, sizeof(t->input_buf));
        } else if ((key == 127 || key == '\b') && t->input_len > 0) {
            t->input_buf[--t->input_len] = '\0';
        } else if (isprint(key) && t->input_len < (int)sizeof(t->input_buf) - 1) {
            t->input_buf[t->input_len++] = (char)key;
        }
        tui_render(t);
        return;
    }

    /* Navigation keys */
    switch (key) {
        case '1': t->panel = 0; break;
        case '2': t->panel = 1; break;
        case '3': t->panel = 2; break;
        case '4': t->panel = 3; break;
        case '5': t->panel = 4; break;
        case '6': t->panel = 5; break;
        case 'x':
        case 'X':
            t->panel = 5;  /* Protocol Test panel */
            /* Trigger protocol test */
            if (t->send_debug_cb && !t->proto_test.test_pending) {
                t->proto_test.test_sequence++;
                snprintf(t->proto_test.test_payload, sizeof(t->proto_test.test_payload),
                         "PROTO_TEST_%u", t->proto_test.test_sequence);
                t->proto_test.last_test_sent_ms = uv_hrtime() / 1000000ULL;
                t->proto_test.test_pending = 1;
                t->send_debug_cb(t->proto_test.test_payload, t->proto_test.test_sequence);
            }
            break;
        case 'q': 
        case 'Q': 
            t->running = 0; 
            break;
            
        /* Debug log controls - only when on debug panel (panel 3) */
        case '0': if (t->panel == 3) tui_debug_set_level(t, 0); break;
        case '!': if (t->panel == 3) tui_debug_set_level(t, 1); break;  /* Shift+1 = ! */
        case '@': if (t->panel == 3) tui_debug_set_level(t, 2); break;  /* Shift+2 = @ */
        case '#': if (t->panel == 3) tui_debug_set_level(t, 3); break;  /* Shift+3 = # */
        
        /* Scroll controls in debug view */
        case 'A': /* Up arrow - need proper escape sequence handling */
            if (t->panel == 3 && t->debug_scroll > 0) t->debug_scroll--;
            break;
        case 'B': /* Down arrow */
            if (t->panel == 3) t->debug_scroll++;
            break;
        
        /* Config toggles */
        case 'd': 
        case 'D': 
            if (t->panel == 2) config_set_key(c,"encryption","enabled", c->encryption ? "false":"true"); 
            break;
        case 'f': 
        case 'F': 
            if (t->panel == 2) config_set_key(c,"obfuscation","jitter", c->jitter ? "false":"true"); 
            break;
        case 'g': 
        case 'G': 
            if (t->panel == 2) config_set_key(c,"obfuscation","padding", c->padding ? "false":"true"); 
            break;
        case 'h': 
        case 'H': 
            if (t->panel == 2) config_set_key(c,"obfuscation","chaffing", c->chaffing ? "false":"true"); 
            break;
        case 'i': 
        case 'I': 
            if (t->panel == 2) config_set_key(c,"obfuscation","chrome_cover", c->chrome_cover ? "false":"true"); 
            break;
        case 'j': 
        case 'J': 
            if (t->panel == 2) config_set_key(c,"domains","dns_flux", c->dns_flux ? "false":"true"); 
            break;
    }
    
    tui_render(t);
}

void tui_shutdown(tui_ctx_t *t) {
    (void)t;
    printf(ANSI_SHOW_CUR);
    printf(ANSI_CLEAR);
}

/* ── Debug Log Functions ───────────────────────────────────────────────────*/

void tui_debug_init(tui_ctx_t *t) {
    memset(&t->debug, 0, sizeof(t->debug));
    t->debug.level = 2;
    t->debug.auto_scroll = 1;
    t->debug_scroll = 0;
}

void tui_debug_clear(tui_ctx_t *t) {
    memset(&t->debug, 0, sizeof(t->debug));
    t->debug.level = 2;
    t->debug.auto_scroll = 1;
    t->debug_scroll = 0;
}

void tui_debug_set_level(tui_ctx_t *t, int level) {
    if (level >= 0 && level <= 3) {
        t->debug.level = level;
    }
}

void tui_debug_log(tui_ctx_t *t, int level, const char *fmt, ...) {
    if (level > t->debug.level) return;
    
    va_list ap;
    va_start(ap, fmt);
    
    int idx = t->debug.head % TUI_DEBUG_LINES;
    
    /* Get relative timestamp */
    static uint64_t start_time = 0;
    uint64_t now = uv_hrtime() / 1000000ULL;
    if (start_time == 0) start_time = now;
    uint64_t rel_ms = now - start_time;
    
    /* Format prefix: [+XXXXXXXms LEVEL] */
    const char *level_str = (level == 0) ? "ERR" :
                            (level == 1) ? "WRN" :
                            (level == 2) ? "INF" : "DBG";
    
    int prefix_len = snprintf(t->debug.lines[idx], TUI_DEBUG_LINE_SIZE,
                              "[+%07ums] %s ",
                              (unsigned)(rel_ms % 10000000),
                              level_str);
    
    /* Append message */
    vsnprintf(t->debug.lines[idx] + prefix_len, TUI_DEBUG_LINE_SIZE - prefix_len, fmt, ap);
    va_end(ap);
    
    /* Ensure null termination */
    t->debug.lines[idx][TUI_DEBUG_LINE_SIZE - 1] = '\0';
    
    t->debug.head++;
    t->debug.count++;
    if (t->debug.count > TUI_DEBUG_LINES) t->debug.count = TUI_DEBUG_LINES;
}

void tui_debug_scroll_up(tui_ctx_t *t, int lines) {
    t->debug_scroll -= lines;
    if (t->debug_scroll < 0) t->debug_scroll = 0;
}

void tui_debug_scroll_down(tui_ctx_t *t, int lines) {
    t->debug_scroll += lines;
}

/* ── Input Mode Functions ──────────────────────────────────────────────────*/

void tui_start_input(tui_ctx_t *t, const char *label, void (*done_cb)(tui_ctx_t*, const char*)) {
    t->input_mode = 1;
    t->input_len = 0;
    memset(t->input_buf, 0, sizeof(t->input_buf));
    strncpy(t->input_label, label, sizeof(t->input_label) - 1);
    t->input_done_cb = done_cb;
}

/* ═══════════════════════════════════════════════════════════════════════════
   LEGACY COMPATIBILITY FUNCTIONS
   ═══════════════════════════════════════════════════════════════════════════ */

/* Stub for protocol test panel - kept for compatibility */
static void render_proto_test(tui_ctx_t *t) {
    (void)t;
    /* Protocol test now integrated into dashboard */
}

void tui_proto_test_start(tui_ctx_t *t) {
    (void)t;
    /* Stub - protocol test functionality can be added later */
}

/* Protocol test API implementations */
void tui_proto_test_init(tui_ctx_t *t) {
    memset(&t->proto_test, 0, sizeof(t->proto_test));
}

void tui_proto_test_on_response(tui_ctx_t *t, uint32_t recv_seq) {
    (void)recv_seq;
    t->proto_test.test_pending = 0;
    t->proto_test.last_test_success = 1;
    t->proto_test.last_test_recv_ms = uv_hrtime() / 1000000ULL;
}

void tui_proto_test_on_timeout(tui_ctx_t *t) {
    t->proto_test.test_pending = 0;
    t->proto_test.last_test_success = 0;
}
