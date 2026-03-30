#include "log.h"
#include "../uv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ── Internal State ──────────────────────────────────────────────────────── */
static FILE         *g_file = NULL;
static log_level_t   g_level = LOG_LEVEL_INFO;
static log_tui_cb_t  g_tui_cb = NULL;
static uv_mutex_t    g_lock;
static bool          g_init = false;

void qns_log_init(const char *filename, log_level_t level) {
    if (g_init) return;
    
    g_level = level;
    if (filename) {
        g_file = fopen(filename, "a");
    }
    
    uv_mutex_init(&g_lock);
    g_init = true;
}

void qns_log_shutdown(void) {
    if (!g_init) return;
    
    uv_mutex_lock(&g_lock);
    if (g_file) {
        fclose(g_file);
        g_file = NULL;
    }
    g_init = false;
    uv_mutex_unlock(&g_lock);
    uv_mutex_destroy(&g_lock);
}

void qns_log_set_tui_cb(log_tui_cb_t cb) {
    uv_mutex_lock(&g_lock);
    g_tui_cb = cb;
    uv_mutex_unlock(&g_lock);
}

static const char* level_to_str(log_level_t l) {
    switch(l) {
        case LOG_LEVEL_ERROR: return "ERROR";
        case LOG_LEVEL_WARN:  return "WARN ";
        case LOG_LEVEL_INFO:  return "INFO ";
        case LOG_LEVEL_DEBUG: return "DEBUG";
        default:              return "UNKN ";
    }
}

void qns_log_msg(log_level_t level, const char *fmt, ...) {
    if (!g_init || level > g_level) return;

    va_list args;
    char buffer[1024];

    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    /* 1. Time string for File/Console */
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[24];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

    uv_mutex_lock(&g_lock);

    /* 2. File Output (with timestamps) */
    if (g_file) {
        fprintf(g_file, "[%s] [%s] %s", time_str, level_to_str(level), buffer);
        fflush(g_file);
    }

    /* 3. Console Output (if not in TUI mode or as backup) */
    /* (In TUI mode, we might want to skip this to avoid mangling the screen, 
        but for now we keep it simple or user can use logs) */
#ifndef _WIN32
    /* Simple color prefix for unix-like consoles */
    const char *color = "";
    if (level == LOG_LEVEL_ERROR) color = "\033[1;31m";
    else if (level == LOG_LEVEL_WARN)  color = "\033[1;33m";
    fprintf(stdout, "%s[%s]%s %s", color, level_to_str(level), "\033[0m", buffer);
#else
    fprintf(stdout, "[%s] %s", level_to_str(level), buffer);
#endif
    fflush(stdout);

    /* 4. TUI Redirection */
    if (g_tui_cb) {
        g_tui_cb((int)level, buffer);
    }

    uv_mutex_unlock(&g_lock);
}
