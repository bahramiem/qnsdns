/**
 * @file server/server_common.h
 * @brief Common logging and global state pointers for the server.
 */

#ifndef QNS_SERVER_COMMON_H
#define QNS_SERVER_COMMON_H

#include "../shared/config.h"
#include "../shared/tui/tui.h"
#include <stdio.h>
#include <time.h>

/* Global Pointers (set in main.c) */
extern dnstun_config_t *g_server_cfg;
extern tui_ctx_t       *g_server_tui;
extern tui_stats_t     *g_server_stats;
extern FILE            *g_server_debug_log;

/* Logging Macros */
#define LOG_INFO(...)                                                          \
  do {                                                                         \
    if (g_server_cfg && g_server_cfg->log_level >= 1) {                        \
      fprintf(stdout, "[INFO]  " __VA_ARGS__);                                 \
      if (g_server_debug_log)                                                  \
        fprintf(g_server_debug_log, "[INFO]  " __VA_ARGS__);                  \
      if (g_server_tui)                                                        \
        tui_debug_log(g_server_tui, 2, __VA_ARGS__);                           \
    }                                                                          \
  } while (0)

#define LOG_DEBUG(...)                                                         \
  do {                                                                         \
    if (g_server_cfg && g_server_cfg->log_level >= 2) {                        \
      fprintf(stdout, "[DEBUG] " __VA_ARGS__);                                 \
      if (g_server_debug_log)                                                  \
        fprintf(g_server_debug_log, "[DEBUG] " __VA_ARGS__);                  \
      if (g_server_tui)                                                        \
        tui_debug_log(g_server_tui, 3, __VA_ARGS__);                           \
    }                                                                          \
  } while (0)

#define LOG_ERR(...)                                                           \
  do {                                                                         \
    fprintf(stderr, "[ERROR] " __VA_ARGS__);                                   \
    if (g_server_debug_log)                                                    \
      fprintf(g_server_debug_log, "[ERROR] " __VA_ARGS__);                     \
    if (g_server_tui)                                                          \
      tui_debug_log(g_server_tui, 0, __VA_ARGS__);                             \
  } while (0)

#endif /* QNS_SERVER_COMMON_H */
