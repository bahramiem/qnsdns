/*
 * DNSTUN TUI Renderer - Standalone Version
 * 
 * Simplified rendering engine that uses cached telemetry
 * from the management client connection.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <ctype.h>

#ifdef _WIN32
/* Include winsock2.h BEFORE windows.h to prevent winsock.h conflicts */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#else
#include <sys/ioctl.h>
#include <unistd.h>
#endif

#include "mgmt_client.h"
#include "../shared/mgmt_protocol.h"

/* ── ANSI Escape Codes ──────────────────────────────────────────────────────*/
#define ANSI_RESET      "\033[0m"
#define ANSI_BOLD       "\033[1m"
#define ANSI_DIM        "\033[2m"

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
#define ANSI_BG_BLUE    "\033[44m"
#define ANSI_BG_GRAY    "\033[100m"

/* Cursor Control */
#define ANSI_CLEAR      "\033[2J\033[H"
#define ANSI_HIDE_CUR   "\033[?25l"
#define ANSI_SHOW_CUR   "\033[?25h"

/* ── Unicode Box Drawing Characters ────────────────────────────────────────*/
#define BOX_HORZ        "─"
#define BOX_VERT        "│"
#define BOX_TOP_LEFT    "┌"
#define BOX_TOP_RIGHT   "┐"
#define BOX_BOT_LEFT    "└"
#define BOX_BOT_RIGHT   "┘"
#define BOX_T_DOWN      "┬"
#define BOX_T_LEFT      "├"
#define BOX_T_RIGHT     "┤"

/* Progress Bar Unicode Blocks */
#define BAR_EMPTY       "░"
#define BAR_FULL        "█"

/* ── Layout Constants ──────────────────────────────────────────────────────*/
#define SIDEBAR_WIDTH   22
#define MIN_TERM_WIDTH  100
#define MIN_TERM_HEIGHT 30

/* ── Renderer State ────────────────────────────────────────────────────────*/
typedef struct {
    int      term_width;
    int      term_height;
    int      panel;       /* 0=dashboard, 1=help */
    int      running;
    int      debug_scroll;
} renderer_t;

static renderer_t g_renderer;

/* ── Helper Functions ──────────────────────────────────────────────────────*/

static void get_terminal_size(void) {
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi)) {
        g_renderer.term_width = csbi.srWindow.Right - csbi.srWindow.Left + 1;
        g_renderer.term_height = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
    }
#else
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        g_renderer.term_width = ws.ws_col;
        g_renderer.term_height = ws.ws_row;
    }
#endif
    if (g_renderer.term_width < MIN_TERM_WIDTH) g_renderer.term_width = MIN_TERM_WIDTH;
    if (g_renderer.term_height < MIN_TERM_HEIGHT) g_renderer.term_height = MIN_TERM_HEIGHT;
}

static void repeat_char(const char *c, int count) {
    for (int i = 0; i < count; i++) printf("%s", c);
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

/* ── Draw Sidebar ──────────────────────────────────────────────────────────*/

static void draw_sidebar(int height) {
    int x = 1, y = 1;
    
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
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_CYAN " ▓" ANSI_RESET " Standalone  " ANSI_BR_CYAN "▓" ANSI_RESET, y + 3, x + 1);
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_CYAN " ▓" ANSI_RESET "    TUI       " ANSI_BR_CYAN "▓" ANSI_RESET, y + 4, x + 1);
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_CYAN " ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓" ANSI_RESET, y + 5, x + 1);
    
    /* Menu Items */
    const char *items[] = {"Dashboard", "Help / Guide"};
    const char *keys[] = {"1", "2"};
    
    for (int i = 0; i < 2; i++) {
        int row = y + 8 + i * 2;
        int is_selected = (g_renderer.panel == i);
        
        if (is_selected) {
            printf("\033[%d;%dH" ANSI_BG_BLUE ANSI_BR_WHITE " ▶ %s. %-14s " ANSI_RESET, 
                   row, x + 1, keys[i], items[i]);
        } else {
            printf("\033[%d;%dH" ANSI_GRAY "   %s." ANSI_RESET " %-14s ", 
                   row, x + 1, keys[i], items[i]);
        }
    }
    
    /* Status */
    printf("\033[%d;%dH" ANSI_DIM "───────────────────" ANSI_RESET, y + 14, x + 1);
    printf("\033[%d;%dH" ANSI_DIM "Status: ", y + 15, x + 1);
    printf(ANSI_BR_GREEN "Connected" ANSI_RESET);
    
    /* Quit hint */
    printf("\033[%d;%dH" ANSI_DIM "Press [Q] to quit" ANSI_RESET, y + height - 1, x + 1);
}

/* ── Draw Dashboard ───────────────────────────────────────────────────────*/

static void draw_throughput_bar(int x, int y, int width, double kbps, const char *label, int is_upload) {
    const char *color = is_upload ? ANSI_BR_GREEN : ANSI_BR_CYAN;
    const char *icon = is_upload ? "▲" : "▼";

    double percent = (kbps / 1000.0) * 100.0;
    if (percent > 100) percent = 100;

    int bar_width = width - 8;
    if (bar_width < 4) bar_width = 4;

    int filled = (int)(percent * bar_width / 100.0);

    printf("\033[%d;%dH%s%s" ANSI_RESET, y, x, color, icon);
    printf("%s", is_upload ? ANSI_GREEN : ANSI_CYAN);

    for (int i = 0; i < filled; i++) printf(BAR_FULL);
    printf(ANSI_RESET);
    for (int i = filled; i < bar_width; i++) printf(BAR_EMPTY);

    if (kbps > 9999.9) kbps = 9999.9;
    printf(" " ANSI_BOLD "%4.0f" ANSI_RESET, kbps);
}

static void draw_dashboard(const mgmt_telemetry_frame_t *stats) {
    int x = SIDEBAR_WIDTH + 2;
    int y = 1;
    int width = g_renderer.term_width - SIDEBAR_WIDTH - 3;
    int height = g_renderer.term_height - 1;
    int mid_x = x + width / 2;
    int panel_w = (width - 3) / 2;
    
    /* Title Bar */
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_WHITE, y, x);
    printf("═══ DNSTUN %s ═══", stats->mode);
    printf(ANSI_RESET);
    
    /* Server Status Panel */
    int panel_y = y + 2;
    draw_box(x, panel_y, panel_w, 6, ANSI_BR_BLUE, " Tunnel Status ");
    
    const char *status = stats->server_connected ? "Connected" : "Offline";
    const char *status_color = stats->server_connected ? ANSI_BR_GREEN : ANSI_BR_RED;
    
    printf("\033[%d;%dH" ANSI_BOLD "Status:   %s%s" ANSI_RESET, panel_y + 2, x + 2, status_color, status);
    printf("\033[%d;%dH" ANSI_BOLD "Latency:  " ANSI_RESET "%.1f ms", panel_y + 3, x + 2, (double)stats->last_server_rx_ms);
    printf("\033[%d;%dH" ANSI_BOLD "Mode:     " ANSI_RESET "%s", panel_y + 4, x + 2, stats->mode);
    
    /* Throughput Panel */
    draw_box(mid_x, panel_y, panel_w, 6, ANSI_BR_MAGENTA, " Throughput ");
    
    draw_throughput_bar(mid_x + 2, panel_y + 2, panel_w - 4, stats->tx_bytes_sec, "Upload", 1);
    draw_throughput_bar(mid_x + 2, panel_y + 4, panel_w - 4, stats->rx_bytes_sec, "Download", 0);
    
    /* Sessions Panel */
    int session_y = panel_y + 7;
    int session_h = height - 12;
    
    draw_box(x, session_y, panel_w, session_h, ANSI_BR_YELLOW, " Sessions ");
    
    printf("\033[%d;%dH" ANSI_BOLD "Active:    " ANSI_RESET ANSI_BR_GREEN "%3d" ANSI_RESET, session_y + 2, x + 2, stats->active_sessions);
    printf("\033[%d;%dH" ANSI_BOLD "Total TX:  " ANSI_RESET "%6.1f MB", session_y + 3, x + 2, stats->tx_total / (1024.0 * 1024.0));
    printf("\033[%d;%dH" ANSI_BOLD "Total RX:  " ANSI_RESET "%6.1f MB", session_y + 4, x + 2, stats->rx_total / (1024.0 * 1024.0));
    printf("\033[%d;%dH" ANSI_BOLD "TX Rate:   " ANSI_RESET "%5.1f KB/s", session_y + 6, x + 2, stats->tx_bytes_sec);
    printf("\033[%d;%dH" ANSI_BOLD "RX Rate:   " ANSI_RESET "%5.1f KB/s", session_y + 7, x + 2, stats->rx_bytes_sec);
    
    /* Resolvers Panel */
    draw_box(mid_x, session_y, panel_w, session_h, ANSI_BR_CYAN, " Resolvers ");
    
    printf("\033[%d;%dH" ANSI_BOLD "Active:   " ANSI_RESET ANSI_BR_GREEN "%3d" ANSI_RESET, session_y + 2, mid_x + 2, stats->active_resolvers);
    printf("\033[%d;%dH" ANSI_BOLD "Dead:     " ANSI_RESET ANSI_RED "%3d" ANSI_RESET, session_y + 3, mid_x + 2, stats->dead_resolvers);
    printf("\033[%d;%dH" ANSI_BOLD "Penalty:  " ANSI_RESET ANSI_YELLOW "%3d" ANSI_RESET, session_y + 4, mid_x + 2, stats->penalty_resolvers);
    
    /* DNS Stats */
    printf("\033[%d;%dH" ANSI_DIM "DNS Stats ─────────────" ANSI_RESET, session_y + 6, mid_x + 2);
    printf("\033[%d;%dH" ANSI_BOLD "Sent:     " ANSI_RESET "%6llu", session_y + 7, mid_x + 2, (unsigned long long)stats->queries_sent);
    printf("\033[%d;%dH" ANSI_BOLD "Received: " ANSI_RESET "%6llu", session_y + 8, mid_x + 2, (unsigned long long)stats->queries_recv);
    printf("\033[%d;%dH" ANSI_BOLD "Lost:     " ANSI_RESET ANSI_RED "%6llu" ANSI_RESET, session_y + 9, mid_x + 2, (unsigned long long)stats->queries_lost);
}

/* ── Draw Help View ───────────────────────────────────────────────────────*/

static void draw_help_view(void) {
    int x = SIDEBAR_WIDTH + 2;
    int y = 1;
    int width = g_renderer.term_width - SIDEBAR_WIDTH - 3;
    int height = g_renderer.term_height - 1;
    
    draw_box(x, y, width, height, ANSI_BR_CYAN, " DNSTUN Standalone TUI - Help Guide ");
    
    int row = y + 2;
    int col = x + 2;
    int section_width = (width - 6) / 2;
    
    /* Left Column: Navigation */
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_WHITE "╭─ Navigation ─────────────────────" ANSI_RESET, row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  1  " ANSI_RESET "Dashboard (main stats view)", row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  2  " ANSI_RESET "Help Guide (this page)", row++, col);
    printf("\033[%d;%dH" ANSI_BR_WHITE "╰────────────────────────────────────────" ANSI_RESET, row++, col);
    
    row++;
    
    /* Left Column: Connection Info */
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_WHITE "╭─ Connection ──────────────────────" ANSI_RESET, row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  Connected to: " ANSI_RESET "127.0.0.1:9090", row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  Protocol:    " ANSI_RESET "Binary (v1)", row++, col);
    printf("\033[%d;%dH" ANSI_BR_WHITE "╰────────────────────────────────────────" ANSI_RESET, row++, col);
    
    row++;
    
    /* Left Column: Keyboard Shortcuts */
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_WHITE "╭─ Keyboard Shortcuts ──────────────" ANSI_RESET, row++, col);
    printf("\033[%d;%dH" ANSI_CYAN "  Q  " ANSI_RESET "Quit TUI (tunnel keeps running!)", row++, col);
    printf("\033[%d;%dH" ANSI_BR_WHITE "╰────────────────────────────────────────" ANSI_RESET, row++, col);
    
    /* Right Column */
    int right_col = col + section_width + 4;
    int right_row = y + 2;
    
    /* Right Column: About */
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_GREEN "╭─ About Standalone TUI ─────────────" ANSI_RESET, right_row++, right_col);
    printf("\033[%d;%dH" ANSI_WHITE "  This TUI connects to the dnstun-core" ANSI_RESET, right_row++, right_col);
    printf("\033[%d;%dH" ANSI_WHITE "  management server over TCP socket." ANSI_RESET, right_row++, right_col);
    printf("\033[%d;%dH" ANSI_WHITE "  " ANSI_RESET, right_row++, right_col);
    printf("\033[%d;%dH" ANSI_WHITE "  Benefits:" ANSI_RESET, right_row++, right_col);
    printf("\033[%d;%dH" ANSI_GREEN "  • TUI crash doesn't kill tunnel" ANSI_RESET, right_row++, right_col);
    printf("\033[%d;%dH" ANSI_GREEN "  • Multiple TUIs can connect" ANSI_RESET, right_row++, right_col);
    printf("\033[%d;%dH" ANSI_GREEN "  • Remote access via SSH tunnel" ANSI_RESET, right_row++, right_col);
    printf("\033[%d;%dH" ANSI_BR_WHITE "╰────────────────────────────────────────" ANSI_RESET, right_row++, right_col);
    
    right_row++;
    
    /* Right Column: SSH Tunnel */
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_BLUE "╭─ Remote Management ─────────────────" ANSI_RESET, right_row++, right_col);
    printf("\033[%d;%dH" ANSI_WHITE "  SSH tunnel for remote access:" ANSI_RESET, right_row++, right_col);
    printf("\033[%d;%dH" ANSI_CYAN " $ " ANSI_RESET "ssh -L 9090:localhost:9090", right_row++, right_col);
    printf("\033[%d;%dH" ANSI_CYAN "     " ANSI_RESET " user@your-server", right_row++, right_col);
    printf("\033[%d;%dH" ANSI_CYAN " $ " ANSI_RESET "./dnstun-tui --host localhost", right_row++, right_col);
    printf("\033[%d;%dH" ANSI_BR_WHITE "╰────────────────────────────────────────" ANSI_RESET, right_row++, right_col);
    
    /* Info Box */
    int info_y = y + height - 8;
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_CYAN "┌%.*s┐" ANSI_RESET, info_y, col, width - 4, "───────────────────────────────────────────────────────────────────────────────────────");
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_CYAN "│" ANSI_RESET ANSI_BOLD ANSI_BR_WHITE " NOTE: " ANSI_RESET " Press [Q] to detach TUI. The tunnel continues running.", info_y + 1, col);
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_CYAN "│" ANSI_RESET " Run ./dnstun-tui again to reconnect the TUI to the same tunnel.", info_y + 2, col);
    printf("\033[%d;%dH" ANSI_BOLD ANSI_BR_CYAN "└%.*s┘" ANSI_RESET, info_y + 3, col, width - 4, "───────────────────────────────────────────────────────────────────────────────────────");
}

/* ── Public API ───────────────────────────────────────────────────────────*/

void renderer_init(void) {
    memset(&g_renderer, 0, sizeof(g_renderer));
    g_renderer.panel = 0;
    g_renderer.running = 1;
    
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

void renderer_shutdown(void) {
    printf(ANSI_SHOW_CUR);
    printf(ANSI_CLEAR);
}

void renderer_render(const mgmt_telemetry_frame_t *stats) {
    get_terminal_size();
    printf(ANSI_CLEAR);
    
    /* Draw sidebar (always visible) */
    draw_sidebar(g_renderer.term_height);
    
    /* Draw content based on panel */
    switch (g_renderer.panel) {
        case 0:
            if (stats) {
                draw_dashboard(stats);
            } else {
                int x = SIDEBAR_WIDTH + 2;
                int y = g_renderer.term_height / 2;
                printf("\033[%d;%dH" ANSI_YELLOW "Connecting to dnstun-core..." ANSI_RESET, y, x);
            }
            break;
        case 1:
            draw_help_view();
            break;
    }
    
    fflush(stdout);
}

void renderer_handle_key(int key) {
    switch (key) {
        case '1':
            g_renderer.panel = 0;
            break;
        case '2':
            g_renderer.panel = 1;
            break;
        case 'q':
        case 'Q':
            g_renderer.running = 0;
            break;
        case 'A': /* Up arrow */
            if (g_renderer.panel == 1 && g_renderer.debug_scroll > 0) {
                g_renderer.debug_scroll--;
            }
            break;
        case 'B': /* Down arrow */
            if (g_renderer.panel == 1) {
                g_renderer.debug_scroll++;
            }
            break;
    }
}

int renderer_is_running(void) {
    return g_renderer.running;
}
