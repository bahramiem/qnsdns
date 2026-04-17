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
    uint64_t queries_dropped;    /* queries dropped due to no available resolvers */
    uint64_t last_server_rx_ms;  /* time of last successful TXT response from server */
    int      server_connected;   /* 1 = client has connected to server */
    char     mode[32];           /* "CLIENT" or "SERVER" */
    
    /* Network Identity (per-mode) */
    char     local_ip[48];
    char     outside_ip[48];
    char     socks_bind[64];     /* display string "host:port" */
    
    /* SOCKS5 Telemetry */
    uint32_t socks5_total_conns;
    uint32_t socks5_total_errors;
    char     socks5_last_target[64]; /* host:port */
    uint8_t  socks5_last_error;      /* Last SOCKS5 error code */
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
   Debug log buffer
────────────────────────────────────────────── */
#define TUI_DEBUG_LINES 256
#define TUI_DEBUG_LINE_SIZE 512

typedef struct {
    char     lines[TUI_DEBUG_LINES][TUI_DEBUG_LINE_SIZE];
    uint64_t timestamps[TUI_DEBUG_LINES];  /* relative ms timestamp */
    int      head;          /* next write position */
    int      count;         /* total lines ever written */
    int      auto_scroll;   /* 1 = auto-scroll to newest */
    int      level;         /* 0=errors, 1=warnings, 2=info, 3=verbose */
} tui_debug_buf_t;

/* ──────────────────────────────────────────────
   Protocol Test State (for debug packet loopback testing)
────────────────────────────────────────────── */
typedef struct {
    uint64_t last_test_sent_ms;      /* timestamp when test was sent */
    uint64_t last_test_recv_ms;      /* timestamp when response was received */
    int      test_pending;           /* 1 = waiting for response */
    int      last_test_success;      /* 1 = last test succeeded */
    uint32_t test_sequence;          /* sequence number for current test */
    char     test_payload[64];       /* payload sent in last test */
} tui_proto_test_t;

/* Callback for sending debug packet from TUI */
typedef void (*tui_send_debug_cb)(const char *payload, uint32_t seq);

/* Callback for sending tunnel control commands from TUI */
/* cmd: MGMT_CMD_CLOSE_TUNNEL, MGMT_CMD_RESTART_TUNNEL, etc. */
typedef void (*tui_send_command_cb)(uint32_t cmd);

/* ──────────────────────────────────────────────
   TUI context
────────────────────────────────────────────── */
typedef struct tui_ctx {
    tui_stats_t      *stats;
    resolver_pool_t  *pool;
    dnstun_config_t  *cfg;
    volatile int      running;
    volatile int      restart;
    int               panel;        /* 0=stats, 1=resolvers, 2=config, 3=debug, 4=help, 5=proto_test */
    const char       *config_path;  /* path to INI file for saving    */

    /* Inline text-input mode */
    int   input_mode;               /* 0=normal, 1=collecting input   */
    char  input_buf[512];
    int   input_len;
    char  input_label[64];
    /* Callback invoked with final string when Enter is pressed */
    void (*input_done_cb)(struct tui_ctx *t, const char *value);

    /* Callback for server to fetch active client sessions */
    int (*get_clients_cb)(tui_client_snap_t *out, int max_clients);

    /* Debug screen */
    tui_debug_buf_t   debug;
    int               debug_scroll;     /* scroll offset for debug view */

    /* Protocol test screen */
    tui_proto_test_t  proto_test;       /* protocol loopback test state */
    tui_send_debug_cb send_debug_cb;    /* callback to send debug packet */
    tui_send_command_cb send_command_cb; /* callback to send tunnel control commands */
    
#ifdef _WIN32
    unsigned int      orig_cp;          /* original console output codepage */
    unsigned long     orig_mode;        /* original console mode */
#endif
} tui_ctx_t;

/* ──────────────────────────────────────────────
   Global logging — routes to TUI panel + disk log file.
   All modules should use these instead of fprintf(stdout/stderr).
────────────────────────────────────────────── */
#define DNSTUN_LOG_ERR  0
#define DNSTUN_LOG_WARN 1
#define DNSTUN_LOG_INFO 2
#define DNSTUN_LOG_DBG  3

/* Open (or re-open) the disk log file. Call once from main() after config. */
void dnstun_log_open(const char *path);

/* Log a message: goes to TUI debug panel AND disk log file. */
void dnstun_log(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

/* Convenience macros — these replace the per-file fprintf LOG_* macros */
#define LOG_INFO(...)  dnstun_log(DNSTUN_LOG_INFO, __VA_ARGS__)
#define LOG_WARN(...)  dnstun_log(DNSTUN_LOG_WARN, __VA_ARGS__)
#define LOG_ERR(...)   dnstun_log(DNSTUN_LOG_ERR,  __VA_ARGS__)
#define LOG_DEBUG(...) dnstun_log(DNSTUN_LOG_DBG,  __VA_ARGS__)
#define DBGLOG(...)    LOG_DEBUG(__VA_ARGS__)

/* Debug API */
void tui_debug_init(tui_ctx_t *t);
void tui_debug_log(tui_ctx_t *t, int level, const char *fmt, ...);
void tui_debug_clear(tui_ctx_t *t);
void tui_debug_set_level(tui_ctx_t *t, int level);

/* Protocol test API */
void tui_proto_test_init(tui_ctx_t *t);
void tui_proto_test_on_response(tui_ctx_t *t, uint32_t recv_seq);
void tui_proto_test_on_timeout(tui_ctx_t *t);

/* Init and run (called once per second from a timer or a dedicated thread) */
void tui_init(tui_ctx_t *t, tui_stats_t *stats,
              resolver_pool_t *pool, dnstun_config_t *cfg,
              const char *mode, const char *config_path);
void tui_render(tui_ctx_t *t);
void tui_handle_key(tui_ctx_t *t, int key);
void tui_shutdown(tui_ctx_t *t);

#endif /* DNSTUN_TUI_H */
