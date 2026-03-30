/**
 * @file client/client_common.h
 * @brief Common logging and global state pointers for the client.
 */

#ifndef QNS_CLIENT_COMMON_H
#define QNS_CLIENT_COMMON_H

#include "../shared/config.h"
#include "../shared/tui/tui.h"
#include "../uv.h"
#include <stdio.h>

/* Global Pointers (set in main.c) */
extern dnstun_config_t *g_client_cfg;
extern tui_ctx_t       *g_client_tui;
extern tui_stats_t     *g_client_stats;
extern FILE            *g_client_debug_log;
extern uv_loop_t       *g_client_loop;
extern resolver_pool_t *g_pool;
extern void            *g_sessions;  /* session_table_t* */

/* Logging Macros */
#define LOG_INFO(...)                                                          \
  do {                                                                         \
    if (g_client_cfg && g_client_cfg->log_level >= 1) {                        \
      fprintf(stdout, "[INFO]  " __VA_ARGS__);                                 \
      if (g_client_debug_log)                                                  \
        fprintf(g_client_debug_log, "[INFO]  " __VA_ARGS__);                  \
      if (g_client_tui)                                                        \
        tui_debug_log(g_client_tui, 2, __VA_ARGS__);                           \
    }                                                                          \
  } while (0)

#define LOG_DEBUG(...)                                                         \
  do {                                                                         \
    if (g_client_cfg && g_client_cfg->log_level >= 2) {                        \
      fprintf(stdout, "[DEBUG] " __VA_ARGS__);                                 \
      if (g_client_debug_log)                                                  \
        fprintf(g_client_debug_log, "[DEBUG] " __VA_ARGS__);                  \
      if (g_client_tui)                                                        \
        tui_debug_log(g_client_tui, 3, __VA_ARGS__);                           \
    }                                                                          \
  } while (0)

#define LOG_WARN(...)                                                          \
  do {                                                                         \
    if (g_client_cfg && g_client_cfg->log_level >= 1) {                        \
      fprintf(stdout, "[WARN]  " __VA_ARGS__);                                 \
      if (g_client_debug_log)                                                  \
        fprintf(g_client_debug_log, "[WARN]  " __VA_ARGS__);                  \
      if (g_client_tui)                                                        \
        tui_debug_log(g_client_tui, 1, __VA_ARGS__);                           \
    }                                                                          \
  } while (0)

#define LOG_ERR(...)                                                           \
  do {                                                                         \
    fprintf(stderr, "[ERROR] " __VA_ARGS__);                                   \
    if (g_client_debug_log)                                                    \
      fprintf(g_client_debug_log, "[ERROR] " __VA_ARGS__);                     \
    if (g_client_tui)                                                          \
      tui_debug_log(g_client_tui, 0, __VA_ARGS__);                             \
  } while (0)

#endif /* QNS_CLIENT_COMMON_H */
