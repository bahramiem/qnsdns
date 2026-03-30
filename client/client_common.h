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

#include "../shared/log.h"

#endif /* QNS_CLIENT_COMMON_H */
