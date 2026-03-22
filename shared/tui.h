#pragma once
#ifndef DNSTUN_TUI_H
#define DNSTUN_TUI_H

#include "types.h"
#include "resolver_pool.h"
#include "config.h"

/* ──────────────────────────────────────────────
   TUI Stats — updated atomically by I/O workers
────────────────────────────────────────────── */
typedef struct {
    double   tx_bytes_sec;       /* current upload KB/s   */
    double   rx_bytes_sec;       /* current download KB/s */
    uint64_t tx_total;
    uint64_t rx_total;
    int      active_sessions;
    int      active_resolvers;
    int      dead_resolvers;
    int      penalty_resolvers;
    uint64_t queries_sent;
    uint64_t queries_recv;
    uint64_t queries_lost;
    char     mode[32];           /* "CLIENT" or "SERVER" */
} tui_stats_t;

/* ──────────────────────────────────────────────
   TUI context
────────────────────────────────────────────── */
typedef struct {
    tui_stats_t      *stats;
    resolver_pool_t  *pool;
    dnstun_config_t  *cfg;
    volatile int      running;
    int               panel;        /* 0=stats, 1=resolvers, 2=config */
} tui_ctx_t;

/* Init and run (called once per second from a timer or a dedicated thread) */
void tui_init(tui_ctx_t *t, tui_stats_t *stats,
              resolver_pool_t *pool, dnstun_config_t *cfg,
              const char *mode);
void tui_render(tui_ctx_t *t);
void tui_handle_key(tui_ctx_t *t, int key);
void tui_shutdown(tui_ctx_t *t);

#endif /* DNSTUN_TUI_H */
