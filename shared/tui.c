#include "tui.h"
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <stdarg.h>
#include <time.h>
#include <math.h>
#include <uv.h>

#ifdef _WIN32
#include <windows.h>
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 * ANSI COLOR CODES
 * ═══════════════════════════════════════════════════════════════════════════ */
#define ANSI_RESET          "\033[0m"
#define ANSI_BOLD          "\033[1m"
#define ANSI_DIM           "\033[2m"
#define ANSI_BRIGHT        "\033[1m"

/* Foreground colors */
#define F_BLACK            "\033[30m"
#define F_RED              "\033[31m"
#define F_GREEN            "\033[32m"
#define F_YELLOW           "\033[33m"
#define F_BLUE             "\033[34m"
#define F_MAGENTA          "\033[35m"
#define F_CYAN             "\033[36m"
#define F_WHITE            "\033[37m"
#define F_BRIGHT_BLACK     "\033[90m"
#define F_BRIGHT_RED       "\033[91m"
#define F_BRIGHT_GREEN     "\033[92m"
#define F_BRIGHT_YELLOW    "\033[93m"
#define F_BRIGHT_BLUE      "\033[94m"
#define F_BRIGHT_MAGENTA   "\033[95m"
#define F_BRIGHT_CYAN      "\033[96m"
#define F_BRIGHT_WHITE     "\033[97m"

/* Background colors */
#define B_BLACK             "\033[40m"
#define B_BLUE              "\033[44m"
#define B_CYAN              "\033[46m"
#define B_WHITE             "\033[47m"

/* Terminal control */
#define ANSI_CLEAR          "\033[2J\033[H"
#define ANSI_HIDE_CUR       "\033[?25l"
#define ANSI_SHOW_CUR       "\033[?25h"
#define ANSI_CLEAR_EOL      "\033[K"
#define ANSI_HOME           "\033[H"

/* Compound colors */
#define C_RESET            ANSI_RESET
#define C_HEADER          ANSI_BOLD F_CYAN
#define C_TITLE           ANSI_BOLD F_BRIGHT_CYAN
#define C_STAT_LABEL      ANSI_BOLD F_BLUE
#define C_STAT_VALUE      ANSI_BOLD F_WHITE
#define C_SUCCESS         ANSI_BOLD F_GREEN
#define C_WARNING         ANSI_BOLD F_YELLOW
#define C_ERROR           ANSI_BOLD F_RED
#define C_INFO            F_CYAN
#define C_DEBUG           F_BRIGHT_BLACK
#define C_ACTIVE          F_GREEN
#define C_PENALTY         F_YELLOW
#define C_DEAD            F_RED
#define C_UPLOAD          F_GREEN
#define C_DOWNLOAD        F_CYAN
#define C_BORDER          F_BLUE
#define C_HIGHLIGHT       B_BLUE F_WHITE

/* ═══════════════════════════════════════════════════════════════════════════
 * UNICODE BOX-DRAWING CHARACTERS
 * ═══════════════════════════════════════════════════════════════════════════ */
#define BOX_TL      "\u250C"  /* ┌ */
#define BOX_TR      "\u2510"  /* ┐ */
#define BOX_BL      "\u2514"  /* └ */
#define BOX_BR      "\u2518"  /* ┘ */
#define BOX_H       "\u2500"  /* ─ */
#define BOX_V       "\u2502"  /* │ */
#define BOX_MID_TL  "\u252C"  /* ├ */
#define BOX_MID_TR  "\u2524"  /* ┤ */
#define BOX_MID_BL  "\u251C"  /* ├ */
#define BOX_MID_BR  "\u2534"  /* ┴ */
#define BOX_CROSS   "\u253C"  /* ┼ */

/* Double-box characters for headers */
#define DBOX_TL     "\u2554"  /* ╔ */
#define DBOX_TR     "\u2557"  /* ╗ */
#define DBOX_BL     "\u255A"  /* ╚ */
#define DBOX_BR     "\u255D"  /* ╝ */
#define DBOX_H      "\u2550"  /* ═ */
#define DBOX_V      "\u2551"  /* ║ */

/* ═══════════════════════════════════════════════════════════════════════════
 * ICONS (using Unicode symbols)
 * ═══════════════════════════════════════════════════════════════════════════ */
#define ICON_UP     "\u2191"   /* ↑ */
#define ICON_DOWN   "\u2193"   /* ↓ */
#define ICON_LEFT   "\u2190"   /* ← */
#define ICON_RIGHT  "\u2192"   /* → */
#define ICON_CHECK  "\u2713"   /* ✓ */
#define ICON_CROSS  "\u2717"   /* ✗ */
#define ICON_STAR   "\u2605"   /* ★ */
#define ICON_DOT    "\u2022"   /* • */
#define ICON_BULLET "\u25CF"   /* ● */
#define ICON_EMPTY  "\u25CB"   /* ○ */
#define ICON_BLOCK  "\u2588"   /* █ */
#define ICON_LIGHT  "\u2591"   /* ░ */
#define ICON_MED    "\u2592"   /* ▒ */
#define ICON_DARK   "\u2593"   /* █ */
#define ICON_SHIELD "\u26E8"   /* ⛨ */
#define ICON_LOCK   "\uD83D\uDD12"  /* 🔒 */
#define ICON_UNLOCK "\uD83D\uDD13"  /* 🔓 */
#define ICON_WARN   "\u26A0"   /* ⚠ */
#define ICON_INFO   "\u2139"   /* ℹ */
#define ICON_BOLT   "\u26A1"   /* ⚡ */
#define ICON_RADIO  "\uD83D\uDCF8" /* 📸 */

/* ═══════════════════════════════════════════════════════════════════════════
 * HELPER FUNCTIONS
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Create a horizontal line with box characters */
static void box_line(int width, const char *h, const char *color) {
    printf("%s", color);
    printf("%s", BOX_V);
    for (int i = 1; i < width - 1; i++) printf("%s", h);
    printf("%s", BOX_V);
    printf(ANSI_RESET "\n");
}

/* Create a double horizontal line */
static void double_box_line(int width) {
    printf(C_BORDER);
    printf("%s", DBOX_H);
    for (int i = 1; i < width - 1; i++) printf("%s", DBOX_H);
    printf("%s", DBOX_H);
    printf(ANSI_RESET "\n");
}

/* Create a box header with title */
static void box_header(int width, const char *title, const char *color) {
    printf("%s", color);
    printf("%s", BOX_TL);
    int title_len = (int)strlen(title);
    int padding = (width - 2 - title_len) / 2;
    for (int i = 0; i < padding; i++) printf("%s", BOX_H);
    printf(ANSI_BOLD "%s" ANSI_RESET, title);
    for (int i = 0; i < width - 2 - title_len - padding; i++) printf("%s", BOX_H);
    printf("%s", BOX_TR);
    printf(ANSI_RESET "\n");
}

/* Create a box footer */
static void box_footer(int width, const char *color) {
    printf("%s", color);
    printf("%s", BOX_BL);
    for (int i = 1; i < width - 1; i++) printf("%s", BOX_H);
    printf("%s", BOX_BR);
    printf(ANSI_RESET "\n");
}

/* Print a centered text in a box row */
static void box_row_center(int width, const char *text, const char *color) {
    int text_len = (int)strlen(text);
    int padding = (width - 2 - text_len) / 2;
    printf("%s%s", color, BOX_V);
    printf(ANSI_RESET);
    for (int i = 0; i < padding; i++) putchar(' ');
    printf("%s", text);
    for (int i = 0; i < width - 2 - text_len - padding; i++) putchar(' ');
    printf("%s%s" ANSI_RESET "\n", color, BOX_V);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * THROUGHPUT BAR CHART
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Draw a throughput bar with smooth visualization */
static void draw_throughput_bar(double bytes_per_sec, double max_expected, 
                                int bar_width, const char *color) {
    /* Calculate fill percentage */
    double pct = (max_expected > 0) ? (bytes_per_sec / max_expected) : 0;
    if (pct > 1.0) pct = 1.0;
    
    int filled = (int)(pct * bar_width);
    
    /* Draw the bar */
    printf(" %s[", color);
    for (int i = 0; i < bar_width; i++) {
        if (i < filled) {
            /* Gradient effect based on fill level */
            if (pct > 0.8) {
                printf(F_RED "%c" ANSI_RESET, 0xDB);  /* Full block */
            } else if (pct > 0.5) {
                printf(F_YELLOW "%c" ANSI_RESET, 0xDB);
            } else {
                printf("%s%c" ANSI_RESET, color, 0xDB);
            }
        } else if (i == filled && filled < bar_width) {
            /* Partial block for sub-character precision */
            printf("%s%c" ANSI_RESET, color, 0xB0);
        } else {
            printf(F_BRIGHT_BLACK "%c" ANSI_RESET, 0xB0);  /* Light shade */
        }
    }
    printf("]");
    
    /* Draw percentage */
    printf(" %s%5.1f%%" ANSI_RESET, color, pct * 100);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * LOG HIGHLIGHTING
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Color-coded icons for log levels */
static const char* log_icon(int level) {
    switch (level) {
        case 0: return ANSI_BOLD F_RED    "✗";   /* ERROR */
        case 1: return ANSI_BOLD F_YELLOW  "⚠";   /* WARN */
        case 2: return ANSI_BOLD F_GREEN   "✓";   /* INFO */
        case 3: return ANSI_BOLD F_BRIGHT_BLACK "·"; /* DEBUG */
        default: return "?";
    }
}

/* Highlight keywords in log output */
static void highlight_keywords(const char *text, char *out, size_t out_size) {
    static const struct {
        const char *keyword;
        const char *color;
        const char *icon;
    } highlights[] = {
        {"ERROR",    F_RED,     "✗"},
        {"WARN",     F_YELLOW,  "⚠"},
        {"INFO",     F_GREEN,   "✓"},
        {"DEBUG",    F_BRIGHT_BLACK, "·"},
        {"session",  F_CYAN,    NULL},
        {"TX",       F_GREEN,   NULL},
        {"RX",       F_CYAN,    NULL},
        {"CONNECT",  F_GREEN,   NULL},
        {"CLOSE",   F_YELLOW,  NULL},
        {"FAILED",  F_RED,     NULL},
        {"timeout", F_RED,     NULL},
        {"retry",   F_YELLOW,  NULL},
        {"DNS",     F_BLUE,    NULL},
        {"TXT",     F_MAGENTA, NULL},
        {"base64",  F_MAGENTA, NULL},
        {"base32",  F_MAGENTA, NULL},
        {"encrypt", F_GREEN,   NULL},
        {"decrypt", F_CYAN,    NULL},
        {"FEC",      F_YELLOW,  NULL},
        {"MTU",      F_BLUE,    NULL},
        {"RTT",      F_GREEN,   NULL},
    };
    
    strncpy(out, text, out_size - 1);
    out[out_size - 1] = '\0';
    
    /* Simple keyword highlighting - replace in place */
    for (size_t k = 0; k < sizeof(highlights) / sizeof(highlights[0]); k++) {
        char *pos = out;
        while ((pos = strstr(pos, highlights[k].keyword)) != NULL) {
            /* Find the position and insert color codes */
            size_t offset = pos - out;
            char temp[1024];
            strncpy(temp, pos + strlen(highlights[k].keyword), sizeof(temp) - 1);
            
            if (highlights[k].icon) {
                snprintf(pos, out_size - offset, "%s%s%s" ANSI_RESET, 
                        highlights[k].color, highlights[k].icon, temp);
            } else {
                snprintf(pos, out_size - offset, "%s%s" ANSI_RESET, 
                        highlights[k].color, temp);
            }
            pos += strlen(highlights[k].keyword) + strlen(ANSI_RESET) + 
                   (highlights[k].icon ? strlen(highlights[k].icon) : 0);
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * RESOLVER STATE DISPLAY
 * ═══════════════════════════════════════════════════════════════════════════ */

static const char *state_str(resolver_state_t s) {
    switch(s) {
        case RSV_ACTIVE:  return F_GREEN  "● ACTIVE " C_RESET;
        case RSV_PENALTY: return F_YELLOW "◐ PENALTY" C_RESET;
        case RSV_DEAD:    return F_RED    "○ DEAD   " C_RESET;
        case RSV_ZOMBIE:  return F_RED    "◌ ZOMBIE " C_RESET;
        case RSV_TESTING: return F_CYAN   "◎ TESTING" C_RESET;
        default:          return "? UNKNOWN";
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DEBUG LOG SYSTEM
 * ═══════════════════════════════════════════════════════════════════════════ */

void tui_debug_init(tui_ctx_t *t) {
    memset(&t->debug, 0, sizeof(t->debug));
    t->debug.level = 2;     /* default to INFO */
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
    
    /* Format prefix with icon and color */
    static const char *level_colors[] = {
        F_RED,    /* ERR */
        F_YELLOW, /* WRN */
        F_GREEN,  /* INF */
        F_BRIGHT_BLACK /* DBG */
    };
    
    int prefix_len = snprintf(t->debug.lines[idx], TUI_DEBUG_LINE_SIZE,
                              ANSI_BOLD "[+%07ums] %s %s " ANSI_RESET,
                              (unsigned)(rel_ms % 10000000),
                              log_icon(level),
                              level_colors[level]);
    
    /* Format the rest with va_list */
    vsnprintf(t->debug.lines[idx] + prefix_len,
              TUI_DEBUG_LINE_SIZE - prefix_len - 1,
              fmt, ap);
    
    /* Apply keyword highlighting */
    highlight_keywords(t->debug.lines[idx], t->debug.lines[idx], TUI_DEBUG_LINE_SIZE);
    
    t->debug.timestamps[idx] = rel_ms;
    t->debug.head++;
    if (t->debug.count < TUI_DEBUG_LINES) t->debug.count++;
    
    va_end(ap);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * INPUT BAR
 * ═══════════════════════════════════════════════════════════════════════════ */

static void render_input_bar(tui_ctx_t *t) {
    double_box_line(72);
    printf(DBOX_V);
    printf(C_HIGHLIGHT " %s " ANSI_RESET, t->input_label);
    for (int i = 54; i < 71; i++) putchar(' ');
    printf(DBOX_V "\n");
    printf(DBOX_V " " C_STAT_VALUE ">");
    printf(ANSI_RESET " %.*s" ANSI_BOLD "_" ANSI_RESET, t->input_len, t->input_buf);
    for (int i = t->input_len + 3; i < 70; i++) putchar(' ');
    printf(DBOX_V "\n");
    double_box_line(72);
    printf(C_INFO " [Enter] confirm   [Esc] cancel   [Backspace] delete" ANSI_RESET "\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * PANEL 0: DASHBOARD (New Premium Design)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void render_stats(tui_ctx_t *t) {
    tui_stats_t *s = t->stats;
    int W = 80;
    
    printf(ANSI_HOME);
    
    /* Header */
    printf(C_TITLE);
    printf("%s", DBOX_TL);
    for (int i=1; i<W-1; i++) printf("%s", DBOX_H);
    printf("%s\n%s", DBOX_TR, DBOX_V);
    printf(ANSI_BOLD "  %s  DNSTUN %s v1.2.7  %s  " ANSI_RESET, ICON_BOLT, s->mode, ICON_BOLT);
    for (int i=32; i<W-1; i++) printf(" ");
    printf(C_TITLE "%s\n%s", DBOX_V, DBOX_BL);
    for (int i=1; i<W-1; i++) printf("%s", DBOX_H);
    printf("%s\n" ANSI_RESET, DBOX_BR);

    /* 2-Column Section Top: CONFIG & PERFORMANCE */
    int C1_W = 39;
    int C2_W = 39;
    
    /* Left: CONFIG */
    printf(C_BORDER "%s", BOX_TL);
    for (int i=1; i<10; i++) printf("%s", BOX_H);
    printf(ANSI_BOLD " CONFIG " ANSI_RESET C_BORDER);
    for (int i=18; i<C1_W-1; i++) printf("%s", BOX_H);
    printf("%s ", BOX_TR);
    
    /* Right: CORE STATS */
    printf(C_BORDER "%s", BOX_TL);
    for (int i=1; i<10; i++) printf("%s", BOX_H);
    printf(ANSI_BOLD " PERFORMANCE " ANSI_RESET C_BORDER);
    for (int i=23; i<C2_W-1; i++) printf("%s", BOX_H);
    printf("%s\n" ANSI_RESET, BOX_TR);

    /* Row 1 content */
    printf(C_BORDER "%s" ANSI_RESET " PSK:  %-25.25s " C_BORDER "%s " ANSI_RESET, BOX_V, t->cfg->psk[0] ? "********" : "(none)", BOX_V);
    printf(C_BORDER "%s" ANSI_RESET " UP:   ", BOX_V);
    draw_throughput_bar(s->tx_bytes_sec, 1024*1024, 20, C_UPLOAD);
    printf(" " C_BORDER "%s\n", BOX_V);

    /* Row 2 content */
    printf(C_BORDER "%s" ANSI_RESET " Crypt: %-25s " C_BORDER "%s " ANSI_RESET, BOX_V, t->cfg->encryption ? "ChaCha20-Poly1305" : "INSECURE / NONE", BOX_V);
    printf(C_BORDER "%s" ANSI_RESET " DOWN: ", BOX_V);
    draw_throughput_bar(s->rx_bytes_sec, 1024*1024, 20, C_DOWNLOAD);
    printf(" " C_BORDER "%s\n", BOX_V);

    /* Row 3 content */
    printf(C_BORDER "%s" ANSI_RESET " Poll:  %-25d " C_BORDER "%s " ANSI_RESET, BOX_V, t->cfg->poll_interval_ms, BOX_V);
    printf(C_BORDER "%s" ANSI_RESET " Loss: ", BOX_V);
    double lp = s->queries_sent > 0 ? 100.0 * (double)s->queries_lost / (double)s->queries_sent : 0.0;
    draw_throughput_bar(lp * 100 * 1024, 100 * 1024, 20, C_WARNING); /* visualize loss % */
    printf(" " C_BORDER "%s\n", BOX_V);

    /* Closers */
    printf(C_BORDER "%s", BOX_BL);
    for (int i=1; i<C1_W-1; i++) printf("%s", BOX_H);
    printf("%s ", BOX_BR);
    printf(C_BORDER "%s", BOX_BL);
    for (int i=1; i<C2_W-1; i++) printf("%s", BOX_H);
    printf("%s\n" ANSI_RESET, BOX_BR);

    /* 2-Column Section Bottom: RESOLVERS & SESSIONS */
    /* Left: RESOLVERS */
    printf(C_BORDER "%s", BOX_TL);
    for (int i=1; i<10; i++) printf("%s", BOX_H);
    printf(ANSI_BOLD " RESOLVERS (%d) " ANSI_RESET C_BORDER, t->pool->count);
    for (int i=25; i<C1_W-1; i++) printf("%s", BOX_H);
    printf("%s ", BOX_TR);
    
    /* Right: SESSIONS */
    printf(C_BORDER "%s", BOX_TL);
    for (int i=1; i<10; i++) printf("%s", BOX_H);
    printf(ANSI_BOLD " SESSIONS (%d) " ANSI_RESET C_BORDER, s->active_sessions);
    for (int i=24; i<C2_W-1; i++) printf("%s", BOX_H);
    printf("%s\n" ANSI_RESET, BOX_TR);

    /* Resolver List (last 4) */
    uv_mutex_lock(&t->pool->lock);
    int nrs = t->pool->count;
    for (int i=0; i<4; i++) {
        printf(C_BORDER "%s" ANSI_RESET " ", BOX_V);
        if (i < nrs) {
            resolver_t *r = &t->pool->resolvers[i];
            printf("%-15s %s%-.9s" ANSI_RESET " %5.0fms ", r->ip, 
                   r->state == RSV_ACTIVE ? C_ACTIVE : C_DEAD, state_str(r->state), r->rtt_ms);
        } else {
            for (int k=0; k<36; k++) printf(" ");
        }
        printf(C_BORDER "%s " ANSI_RESET "%s" ANSI_RESET " ", BOX_V, BOX_V);
        /* Sessions (not easily accessible here, just show stats) */
        if (i == 0) printf("Total Active:   " C_STAT_VALUE "%-10d" ANSI_RESET, s->active_sessions);
        else if (i == 1) printf("Total Sent:     " C_STAT_VALUE "%-10llu" ANSI_RESET, (unsigned long long)s->tx_total / 1024);
        else if (i == 2) printf("Total Recv:     " C_STAT_VALUE "%-10llu" ANSI_RESET, (unsigned long long)s->rx_total / 1024);
        else printf("                          ");
        
        for (int k=26; k<36; k++) printf(" ");
        printf(C_BORDER "%s\n" ANSI_RESET, BOX_V);
    }
    uv_mutex_unlock(&t->pool->lock);

    printf(C_BORDER "%s", BOX_BL);
    for (int i=1; i<C1_W-1; i++) printf("%s", BOX_H);
    printf("%s ", BOX_BR);
    printf(C_BORDER "%s", BOX_BL);
    for (int i=1; i<C2_W-1; i++) printf("%s", BOX_H);
    printf("%s\n" ANSI_RESET, BOX_BR);

    /* LIVE LOG PANEL */
    printf(C_BORDER "%s", BOX_TL);
    for (int i=1; i<10; i++) printf("%s", BOX_H);
    printf(ANSI_BOLD " LIVE LOG " ANSI_RESET C_BORDER);
    for (int i=20; i<W-1; i++) printf("%s", BOX_H);
    printf("%s\n" ANSI_RESET, BOX_TR);

    int log_lines = 5;
    int count = t->debug.count;
    for (int i=0; i<log_lines; i++) {
        printf(C_BORDER "%s" ANSI_RESET " ", BOX_V);
        if (count > 0 && i < log_lines) {
            int visible_idx = i + (count > log_lines ? count - log_lines : 0);
            int idx = (t->debug.head - count + visible_idx) % TUI_DEBUG_LINES;
            if (idx < 0) idx += TUI_DEBUG_LINES;
            printf("%-75.75s", t->debug.lines[idx]);
        } else {
            for (int k=0; k<75; k++) printf(" ");
        }
        printf(C_BORDER " %s\n" ANSI_RESET, BOX_V);
    }
    box_footer(W, C_BORDER);

    /* Navigation */
    printf(ANSI_BOLD " [1]" ANSI_RESET " Dash  " ANSI_BOLD "[2]" ANSI_RESET " Net  " ANSI_BOLD "[3]" ANSI_RESET " Conf  " ANSI_BOLD "[4]" ANSI_RESET " Log " ANSI_BOLD "[q]" ANSI_RESET " Quit\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * PANEL 1: RESOLVER TABLE (Enhanced)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void render_resolvers(tui_ctx_t *t) {
    printf(ANSI_HOME);
    if (strcmp(t->stats->mode, "SERVER") == 0) {
        if (!t->get_clients_cb) {
            box_header(76, " ACTIVE CLIENT SESSIONS ", C_HEADER);
            printf("%s", BOX_V);
            for (int i = 1; i < 76; i++) putchar(' ');
            printf("%s\n", BOX_V);
            box_footer(76, C_BORDER);
            return;
        }
        tui_client_snap_t snaps[24];
        int num = t->get_clients_cb(snaps, 24);
        
        box_header(76, " ACTIVE CLIENT SESSIONS ", C_HEADER);
        
        /* Header row */
        printf("%s" ANSI_BOLD " " F_CYAN "%-15s %-10s %5s %6s %5s %4s %6s " ANSI_RESET "%s\n",
               BOX_V, "Client IP", "User ID", "MTU", "Loss%", "FEC", "Enc", "Idle(s)", BOX_V);
        printf("%s", BOX_V);
        for (int i = 1; i < 76; i++) printf("%s", BOX_H);
        printf("%s\n", BOX_V);
        
        for (int i = 0; i < num && i < 15; i++) {
            printf("%s ", BOX_V);
            printf("%-15s %-10s %5d %6.1f %5d %4s %6u ",
                   snaps[i].ip,
                   snaps[i].user_id[0] ? snaps[i].user_id : "-",
                   snaps[i].downstream_mtu,
                   (double)snaps[i].loss_pct,
                   (int)snaps[i].fec_k,
                   snaps[i].enc_format == ENC_BINARY ? F_RED "bin" ANSI_RESET : F_GREEN "b64" ANSI_RESET,
                   snaps[i].idle_sec);
            for (int j = 70; j < 76; j++) putchar(' ');
            printf("%s\n", BOX_V);
        }
        
        box_footer(76, C_BORDER);
        printf(C_INFO "  [1]" ANSI_RESET " Stats   [Any Key] Back   "
               C_ERROR "[q]" ANSI_RESET " Quit\n");
        return;
    }

    /* Client resolver pool view */
    resolver_pool_t *pool = t->pool;

    /* Snapshot resolver data while locked */
    typedef struct {
        char             ip[46];
        resolver_state_t state;
        double           cwnd;
        double           rtt_ms;
        double           max_qps;
        int              downstream_mtu;
        double           loss_rate;
        uint32_t         fec_k;
        enc_format_t     enc;
        char             fail_reason[64];
    } snap_t;

    snap_t snaps[24];
    int shown = 0;
    int total = 0;

    uv_mutex_lock(&pool->lock);
    total = pool->count;
    for (int i = 0; i < pool->count && shown < 24; i++) {
        resolver_t *r = &pool->resolvers[i];
        snaps[shown].state         = r->state;
        snaps[shown].cwnd          = r->cwnd;
        snaps[shown].rtt_ms        = r->rtt_ms;
        snaps[shown].max_qps       = r->max_qps;
        snaps[shown].downstream_mtu = r->downstream_mtu;
        snaps[shown].loss_rate     = r->loss_rate;
        snaps[shown].fec_k         = r->fec_k;
        snaps[shown].enc           = r->enc;
        strncpy(snaps[shown].ip, r->ip, sizeof(snaps[shown].ip) - 1);
        strncpy(snaps[shown].fail_reason, r->fail_reason, sizeof(snaps[shown].fail_reason) - 1);
        snaps[shown].fail_reason[sizeof(snaps[shown].fail_reason) - 1] = '\0';
        shown++;
    }
    uv_mutex_unlock(&pool->lock);

    box_header(76, " RESOLVER POOL ", C_HEADER);
    printf("%s" ANSI_BOLD " " F_CYAN "%-15s %-10s %6s %6s %5s %4s %5s %4s " ANSI_RESET "%s\n",
           BOX_V, "IP", "State", "cwnd", "RTT(ms)", "QPS", "MTU", "Loss%", "FEC", BOX_V);
    printf("%s", BOX_V);
    for (int i = 1; i < 76; i++) printf("%s", BOX_H);
    printf("%s\n", BOX_V);

    for (int i = 0; i < shown; i++) {
        snap_t *s = &snaps[i];
        printf("%s ", BOX_V);
        printf("%-15s ", s->ip);
        
        /* State with icon */
        printf("%s", s->state == RSV_ACTIVE ? C_ACTIVE :
                    s->state == RSV_PENALTY ? C_PENALTY : C_DEAD);
        printf("%-10s" ANSI_RESET, state_str(s->state));
        
        printf(" %5.0f %6.1f %5.0f %4d %5.1f %4u",
               s->cwnd, s->rtt_ms, s->max_qps, s->downstream_mtu,
               s->loss_rate * 100.0, s->fec_k);
        
        /* Enc format indicator */
        printf(" %s", s->enc == ENC_BINARY ? F_RED "bin" ANSI_RESET : F_GREEN "b64" ANSI_RESET);
        
        /* Failure reason for dead/zombie */
        if ((s->state == RSV_DEAD || s->state == RSV_ZOMBIE) && s->fail_reason[0]) {
            printf(" " C_ERROR "%s" ANSI_RESET, s->fail_reason);
        }
        
        for (int j = 70; j < 76; j++) putchar(' ');
        printf("%s\n", BOX_V);
    }

    box_footer(76, C_BORDER);
    printf(C_INFO "  [1]" ANSI_RESET " Stats   " C_INFO "[2]" ANSI_RESET " Resolvers   "
           C_INFO "[3]" ANSI_RESET " Config   " C_INFO "[4]" ANSI_RESET " Log   "
           C_WARNING "[r]" ANSI_RESET " Add Resolver   " C_ERROR "[q]" ANSI_RESET " Quit\n");
    
    if (t->input_mode)
        render_input_bar(t);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * PANEL 2: CONFIG (Enhanced)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void render_config(tui_ctx_t *t) {
    printf(ANSI_HOME);
    box_header(76, " LIVE CONFIG ", C_HEADER);
    
    dnstun_config_t *c = t->cfg;
    const char *ciphers[]    = { "none","chacha20","aes256gcm","noise_nk" };
    const char *transports[] = { "udp","doh","dot" };
    
    printf("%s  " C_STAT_LABEL "[a]" ANSI_RESET " poll_interval_ms  = " C_INFO "%-5d" ANSI_RESET, BOX_V, c->poll_interval_ms);
    printf("        " C_STAT_LABEL "[b]" ANSI_RESET " fec_window        = " C_INFO "%-5d" ANSI_RESET "  %s\n", c->fec_window, BOX_V);
    
    printf("%s  " C_STAT_LABEL "[c]" ANSI_RESET " cwnd_max          = " C_INFO "%-5.0f" ANSI_RESET, BOX_V, c->cwnd_max);
    printf("        " C_STAT_LABEL "[d]" ANSI_RESET " encryption        = %s    %s\n", 
           c->encryption ? C_SUCCESS "ON " ANSI_RESET : C_ERROR "OFF" ANSI_RESET, BOX_V);
    
    printf("%s  " C_STAT_LABEL "[e]" ANSI_RESET " cipher            = " C_INFO "%-10s" ANSI_RESET, BOX_V,
           (c->cipher < 4) ? ciphers[c->cipher] : "?");
    printf("   " C_STAT_LABEL "[f]" ANSI_RESET " jitter            = %s    %s\n", 
           c->jitter ? C_SUCCESS "ON " ANSI_RESET : C_ERROR "OFF" ANSI_RESET, BOX_V);
    
    printf("%s  " C_STAT_LABEL "[g]" ANSI_RESET " padding           = %s", BOX_V,
           c->padding ? C_SUCCESS "ON " ANSI_RESET : C_ERROR "OFF" ANSI_RESET);
    printf("          " C_STAT_LABEL "[h]" ANSI_RESET " chaffing          = %s    %s\n", 
           c->chaffing ? C_SUCCESS "ON " ANSI_RESET : C_ERROR "OFF" ANSI_RESET, BOX_V);
    
    printf("%s  " C_STAT_LABEL "[i]" ANSI_RESET " chrome_cover     = %s", BOX_V,
           c->chrome_cover ? C_SUCCESS "ON " ANSI_RESET : C_ERROR "OFF" ANSI_RESET);
    printf("        " C_STAT_LABEL "[j]" ANSI_RESET " dns_flux          = %s    %s\n", 
           c->dns_flux ? C_SUCCESS "ON " ANSI_RESET : C_ERROR "OFF" ANSI_RESET, BOX_V);
    
    printf("%s  " C_STAT_LABEL "[k]" ANSI_RESET " transport         = " C_INFO "%-10s" ANSI_RESET, BOX_V,
           (c->transport < 3) ? transports[c->transport] : "?");
    printf("   " C_STAT_LABEL "[l]" ANSI_RESET " log_level         = " C_INFO "%-5d" ANSI_RESET "  %s\n", c->log_level, BOX_V);
    
    /* Domains display */
    printf("%s  " C_STAT_LABEL "[m]" ANSI_RESET " domains           = " C_INFO, BOX_V);
    int dlen = 0;
    if (c->domain_count > 0) {
        for (int i = 0; i < c->domain_count; i++) {
            if (i > 0) { printf(","); dlen++; }
            printf("%s", c->domains[i]);
            dlen += (int)strlen(c->domains[i]);
        }
    } else {
        printf(C_ERROR "(none)" ANSI_RESET);
        dlen += 6;
    }
    for (int i=dlen; i<52; i++) putchar(' ');
    printf("%s\n", BOX_V);
    
    box_footer(76, C_BORDER);
    printf(C_INFO "  [1]" ANSI_RESET " Stats   " C_INFO "[2]" ANSI_RESET " Resolvers   "
           C_INFO "[3]" ANSI_RESET " Config   " C_INFO "[4]" ANSI_RESET " Log   "
           C_ERROR "[q]" ANSI_RESET " Quit\n");

    if (t->input_mode)
        render_input_bar(t);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * PANEL 3: DEBUG LOG (Enhanced)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void render_debug(tui_ctx_t *t) {
    box_header(76, " LIVE LOG ", C_HEADER);
    
    const char *level_names[] = { "ERR", "WRN", "INF", "DBG" };
    const char *level_colors[] = { F_RED, F_YELLOW, F_GREEN, F_BRIGHT_BLACK };
    
    printf("%s  Log Levels: ", BOX_V);
    for (int i = 0; i <= 3; i++) {
        if (i <= t->debug.level) {
            printf("%s%s %s" ANSI_RESET, level_colors[i], log_icon(i), level_names[i]);
        } else {
            printf(F_BRIGHT_BLACK "  %s" ANSI_RESET, level_names[i]);
        }
        if (i < 3) printf("  ");
    }
    for (int i=0; i<30; i++) putchar(' ');
    printf("%s\n", BOX_V);

    printf("%s     [c] Clear   [a] Auto-scroll %s", BOX_V,
           t->debug.auto_scroll ? C_SUCCESS "ON" ANSI_RESET : C_ERROR "OFF" ANSI_RESET);
    for (int i=0; i<30; i++) putchar(' ');
    printf("%s\n", BOX_V);
    
    printf("%s", BOX_V);
    for (int i = 1; i < 76; i++) printf("%s", BOX_H);
    printf("%s\n", BOX_V);
    
    int total_lines = t->debug.count;
    int visible_lines = 12;
    
    /* Calculate scroll window */
    int start_idx;
    int end_idx;
    
    if (t->debug.auto_scroll || t->debug_scroll == 0) {
        start_idx = (total_lines > visible_lines) ? (total_lines - visible_lines) : 0;
        end_idx = total_lines;
    } else {
        start_idx = t->debug_scroll;
        end_idx = (start_idx + visible_lines < total_lines) ? 
                  start_idx + visible_lines : total_lines;
    }
    
    if (total_lines == 0) {
        printf("%s", BOX_V);
        printf(C_DEBUG "  (no log messages yet - press keys or start a session)" ANSI_RESET);
        for (int i = 60; i < 74; i++) putchar(' ');
        printf("%s\n", BOX_V);
    } else {
        for (int i = start_idx; i < end_idx; i++) {
            int idx = (t->debug.head - total_lines + i) % TUI_DEBUG_LINES;
            if (idx < 0) idx += TUI_DEBUG_LINES;
            printf("%s ", BOX_V);
            /* Truncate long lines */
            int len = (int)strlen(t->debug.lines[idx]);
            /* We need to be careful with visible length vs byte length due to ANSI */
            printf("%-73.73s", t->debug.lines[idx]);
            printf(" %s\n", BOX_V);
        }
        /* Fill empty lines if needed */
        for (int i = end_idx - start_idx; i < visible_lines; i++) {
            printf("%s", BOX_V);
            for (int k=0; k<74; k++) putchar(' ');
            printf("%s\n", BOX_V);
        }
    }
    
    box_footer(76, C_BORDER);
    printf(C_INFO "  [1]" ANSI_RESET " Stats   " C_INFO "[2]" ANSI_RESET " Resolvers   "
           C_INFO "[3]" ANSI_RESET " Config   " C_INFO "[4]" ANSI_RESET " Log   "
           C_ERROR "[q]" ANSI_RESET " Quit\n");
    printf(C_DEBUG "  [j/↓] Scroll Down   [k/↑] Scroll Up   [0-3] Level   [c] Clear   [a] Auto-scroll" ANSI_RESET "\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * CALLBACKS
 * ═══════════════════════════════════════════════════════════════════════════ */

static void on_domain_input_done(tui_ctx_t *t, const char *value) {
    if (value && value[0]) {
        config_set_key(t->cfg, "domains", "list", value);
        if (t->config_path)
            config_save_domains(t->config_path, t->cfg);
    }
}

static void on_resolver_input_done(tui_ctx_t *t, const char *value) {
    if (!value || !value[0]) return;
    
    /* Trim whitespace */
    char ip[64] = {0};
    const char *p = value;
    while (*p == ' ' || *p == '\t') p++;
    strncpy(ip, p, sizeof(ip)-1);
    char *end = ip + strlen(ip) - 1;
    while (end > ip && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) *end-- = '\0';
    if (!ip[0]) return;

    rpool_add(t->pool, ip);

    /* Append to resolver file for persistence */
    if (t->config_path) {
        char rf_path[1024];
        strncpy(rf_path, t->config_path, sizeof(rf_path)-1);
        char *slash = strrchr(rf_path, '/');
#ifdef _WIN32
        char *bslash = strrchr(rf_path, '\\');
        if (bslash > slash) slash = bslash;
#endif
        if (slash) strncpy(slash + 1, "client_resolvers.txt", sizeof(rf_path) - (slash - rf_path) - 1);
        else strcpy(rf_path, "client_resolvers.txt");

        FILE *rf = fopen(rf_path, "a");
        if (rf) { fprintf(rf, "%s\n", ip); fclose(rf); }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * PUBLIC API
 * ═══════════════════════════════════════════════════════════════════════════ */

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
    t->debug.level = 2;
    t->debug.auto_scroll = 1;
    t->debug_scroll = 0;

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
}

void tui_render(tui_ctx_t *t) {
    switch (t->panel) {
        case 0: render_stats(t);     break;
        case 1: render_resolvers(t); break;
        case 2: render_config(t);    break;
        case 3: render_debug(t);     break;
        default: render_stats(t);    break;
    }
    fflush(stdout);
}

void tui_handle_key(tui_ctx_t *t, int key) {
    dnstun_config_t *c = t->cfg;

    /* Input mode: accumulate text */
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

    /* Normal mode */
    if (strcmp(t->stats->mode, "SERVER") == 0 && t->panel == 1) {
        if (key == 'q') {
            t->running = 0;
        } else {
            t->panel = 0;
        }
        tui_render(t);
        return;
    }

    switch (key) {
        case '1': t->panel = 0; break;
        case '2': t->panel = 1; break;
        case '3': t->panel = 2; break;
        case '4': t->panel = 3; break;
        case 'q': case 'Q': t->running = 0; break;

        /* Config panel live toggles */
        case 'd': config_set_key(c,"encryption","enabled", c->encryption ? "false":"true"); break;
        case 'f': config_set_key(c,"obfuscation","jitter",  c->jitter     ? "false":"true"); break;
        case 'g': config_set_key(c,"obfuscation","padding", c->padding    ? "false":"true"); break;
        case 'h': config_set_key(c,"obfuscation","chaffing",c->chaffing   ? "false":"true"); break;
        case 'i': config_set_key(c,"obfuscation","chrome_cover",c->chrome_cover?"false":"true"); break;
        case 'j': config_set_key(c,"domains","dns_flux",   c->dns_flux    ? "false":"true"); break;

        /* Domain edit */
        case 'm':
            t->panel = 2;
            t->input_mode = 1;
            t->input_len  = 0;
            memset(t->input_buf, 0, sizeof(t->input_buf));
            strncpy(t->input_label,
                    "Edit domains (comma-separated, e.g. tun.example.com)",
                    sizeof(t->input_label) - 1);
            for (int i = 0; i < c->domain_count; i++) {
                if (i > 0 && t->input_len < (int)sizeof(t->input_buf) - 2)
                    t->input_buf[t->input_len++] = ',';
                int rem = (int)sizeof(t->input_buf) - t->input_len - 1;
                if (rem > 0) {
                    int dl = (int)strlen(c->domains[i]);
                    if (dl > rem) dl = rem;
                    memcpy(t->input_buf + t->input_len, c->domains[i], (size_t)dl);
                    t->input_len += dl;
                }
            }
            t->input_done_cb = on_domain_input_done;
            break;

        /* Add resolver */
        case 'r':
            t->panel = 1;
            t->input_mode = 1;
            t->input_len  = 0;
            memset(t->input_buf, 0, sizeof(t->input_buf));
            strncpy(t->input_label,
                    "Add resolver IP (e.g. 8.8.8.8)",
                    sizeof(t->input_label) - 1);
            t->input_done_cb = on_resolver_input_done;
            break;

        default: break;
    }

    /* Debug panel specific keys */
    if (t->panel == 3) {
        switch (key) {
            case 'c': case 'C': tui_debug_clear(t); break;
            case 'a': case 'A':
                t->debug.auto_scroll = !t->debug.auto_scroll;
                if (t->debug.auto_scroll) t->debug_scroll = 0;
                break;
            case '0': case '1': case '2': case '3':
                tui_debug_set_level(t, key - '0');
                break;
            case 'k': case 'K': case 'H': case 'u': case 'U':
                if (!t->debug.auto_scroll && t->debug_scroll > 0) t->debug_scroll--;
                break;
            case 'j': case 'J': case 'L': case 'd': case 'D':
                if (!t->debug.auto_scroll) {
                    int max_scroll = (t->debug.count > 12) ? (t->debug.count - 12) : 0;
                    if (t->debug_scroll < max_scroll) t->debug_scroll++;
                }
                break;
            default: break;
        }
    }

    t->panel = t->panel % 4;
    tui_render(t);
}

void tui_shutdown(tui_ctx_t *t) {
    t->running = 0;
    uv_tty_reset_mode();
    printf(ANSI_SHOW_CUR ANSI_RESET "\n");
    fflush(stdout);
}
