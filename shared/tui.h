#pragma once
#ifndef DNSTUN_TUI_H
#define DNSTUN_TUI_H

#include "types.h"
#include "resolver_pool.h"
#include "config.h"
#include "uv.h"
#include <stdarg.h>

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
    uint64_t last_server_rx_ms;  /* time of last successful TXT response from server */
    char     mode[32];           /* "CLIENT" or "SERVER" */
} tui_stats_t;

/* ──────────────────────────────────────────────
   TUI Server Snapshot (mock competencies for server clients)
────────────────────────────────────────────── */
typedef struct {
    char     ip[46];
    char     user_id[16];
    uint16_t downstream_mtu;
    uint8_t  loss_pct;
    uint8_t  fec_k;
    uint8_t  enc_format;
    uint32_t idle_sec;
} tui_client_snap_t;

/* ──────────────────────────────────────────────
   TUI context
────────────────────────────────────────────── */
/* ──────────────────────────────────────────────
   Log Ring Buffer
────────────────────────────────────────────── */
#define TUI_LOG_LINES   256
#define TUI_LOG_WIDTH   180

typedef enum {
    TUI_LOG_DEBUG = 0,
    TUI_LOG_INFO  = 1,
    TUI_LOG_WARN  = 2,
    TUI_LOG_ERR   = 3
} tui_log_level_t;

typedef struct {
    char             text[TUI_LOG_WIDTH];
    tui_log_level_t  level;
} tui_log_entry_t;

/* ──────────────────────────────────────────────
   TUI context
────────────────────────────────────────────── */
typedef struct tui_ctx {
    tui_stats_t      *stats;
    resolver_pool_t  *pool;
    dnstun_config_t  *cfg;
    volatile int      running;
    volatile int      restart;
    int               panel;        /* 0=stats,1=resolvers,2=logs,3=config */
    const char       *config_path;  /* path to INI file for saving         */

    /* Inline text-input mode */
    int   input_mode;               /* 0=normal, 1=collecting input   */
    char  input_buf[512];
    int   input_len;
    char  input_label[64];
    /* Callback invoked with final string when Enter is pressed */
    void (*input_done_cb)(struct tui_ctx *t, const char *value);

    /* Callback for server to fetch active client sessions */
    int (*get_clients_cb)(tui_client_snap_t *out, int max_clients);

    /* Log ring buffer (thread-safe) */
    tui_log_entry_t  log_ring[TUI_LOG_LINES];
    int              log_head;      /* next write position (ring)      */
    int              log_count;     /* total entries written so far    */
    int              log_scroll;    /* scroll offset from bottom (0=bottom) */
    uv_mutex_t       log_lock;
} tui_ctx_t;

/* Init and run (called once per second from a timer or a dedicated thread) */
void tui_init(tui_ctx_t *t, tui_stats_t *stats,
              resolver_pool_t *pool, dnstun_config_t *cfg,
              const char *mode, const char *config_path);
void tui_render(tui_ctx_t *t);
void tui_handle_key(tui_ctx_t *t, int key);
void tui_shutdown(tui_ctx_t *t);

/* Log into the TUI log panel (thread-safe, printf-style) */
void tui_log(tui_ctx_t *t, tui_log_level_t level, const char *fmt, ...)
             __attribute__((format(printf, 3, 4)));

/* Global TUI context pointer — set by tui_init so LOG_* macros can reach it */
extern tui_ctx_t *g_tui_ctx;

#define LOG_DEBUG(fmt, ...) tui_log(g_tui_ctx, TUI_LOG_DEBUG, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  tui_log(g_tui_ctx, TUI_LOG_INFO,  fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  tui_log(g_tui_ctx, TUI_LOG_WARN,  fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...)   tui_log(g_tui_ctx, TUI_LOG_ERR,   fmt, ##__VA_ARGS__)

#endif /* DNSTUN_TUI_H */
