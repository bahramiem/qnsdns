/**
 * @file shared/log.h
 * @brief Unified thread-safe logging system for both client and server.
 * 
 * Supports simultaneous output to console, file, and TUI.
 */

#ifndef QNS_SHARED_LOG_H
#define QNS_SHARED_LOG_H

#include <stdarg.h>
#include <stdbool.h>

/**
 * @brief Log severity levels.
 */
typedef enum {
    LOG_LEVEL_ERROR = 0,
    LOG_LEVEL_WARN  = 1,
    LOG_LEVEL_INFO  = 2,
    LOG_LEVEL_DEBUG = 3
} log_level_t;

/**
 * @brief TUI logging callback.
 */
typedef void (*log_tui_cb_t)(int level, const char *msg);

/**
 * @brief Initialise the logging system.
 * @param filename File path for the log (appended to). NULL for no file.
 * @param level Runtime log level for console/file.
 */
void qns_log_init(const char *filename, log_level_t level);

/**
 * @brief Shutdown the logging system and close files.
 */
void qns_log_shutdown(void);

/**
 * @brief Set the TUI redirection callback.
 * @param cb Function to receive formatted logs.
 */
void qns_log_set_tui_cb(log_tui_cb_t cb);

/**
 * @brief Internal log dispatcher. Use macros instead.
 */
void qns_log_msg(log_level_t level, const char *fmt, ...);

/* ── Logging Macros ──────────────────────────────────────────────────────── */

#define LOG_ERR(...)   qns_log_msg(LOG_LEVEL_ERROR, __VA_ARGS__)
#define LOG_WARN(...)  qns_log_msg(LOG_LEVEL_WARN,  __VA_ARGS__)
#define LOG_INFO(...)  qns_log_msg(LOG_LEVEL_INFO,  __VA_ARGS__)
#define LOG_DEBUG(...) qns_log_msg(LOG_LEVEL_DEBUG, __VA_ARGS__)

#endif /* QNS_SHARED_LOG_H */
