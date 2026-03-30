/**
 * @file shared/tui/ansi.h
 * @brief ANSI escape sequences and UI constants for the TUI.
 */

#ifndef QNS_TUI_ANSI_H
#define QNS_TUI_ANSI_H

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

/* ── Menu Arrow Character (Windows-compatible) ─────────────────────────────*/
#ifdef _WIN32
#define MENU_ARROW      ">"
#else
#define MENU_ARROW      "▶"
#endif

/* ── Layout Constants ──────────────────────────────────────────────────────*/
#define SIDEBAR_WIDTH   22
#define LOG_HEIGHT      8
#define MIN_TERM_WIDTH  100
#define MIN_TERM_HEIGHT 30

#endif /* QNS_TUI_ANSI_H */
