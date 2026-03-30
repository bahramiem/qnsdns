/**
 * @file server/server_common.h
 * @brief Common logging and global state pointers for the server.
 */

#ifndef QNS_SERVER_COMMON_H
#define QNS_SERVER_COMMON_H

#include "../shared/config.h"
#include "../shared/tui/tui.h"
#include "../shared/log.h"
#include <stdio.h>
#include <time.h>

/* Global Pointers (set in main.c) */
extern dnstun_config_t *g_server_cfg;
extern tui_ctx_t       *g_server_tui;
extern tui_stats_t     *g_server_stats;

#endif /* QNS_SERVER_COMMON_H */
