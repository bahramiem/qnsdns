/**
 * @file shared/tui/core.h
 * @brief Core types and structure definitions for the TUI.
 *
 * This file contains the shared context and telemetry structures 
 * that are used across all TUI modules.
 *
 * Example Usage (Initializing the TUI):
 * @code
 *   tui_ctx_t tui;
 *   tui_stats_t stats;
 *   tui_init(&tui, &stats, &pool, &cfg, "CLIENT", "client.ini");
 *   tui_render(&tui);
 *   tui_shutdown(&tui);
 * @endcode
 */

#ifndef QNS_TUI_CORE_H
#define QNS_TUI_CORE_H

#include "../types.h"
#include "../resolver_pool.h"
#include "../config.h"
#include <stdint.h>
#include <stdbool.h>

/**
 * @brief TUI Stats — updated atomically by I/O workers.
 */
typedef struct {
    double   tx_bytes_sec;       /**< Current upload KB/s   */
    double   rx_bytes_sec;       /**< Current download KB/s */
    uint64_t tx_total;
    uint64_t rx_total;
    int      active_sessions;
    int      active_resolvers;
    int      dead_resolvers;
    int      penalty_resolvers;
    uint64_t queries_sent;
    uint64_t queries_recv;
    uint64_t queries_lost;
    uint64_t queries_dropped;    /**< Queries dropped due to no available resolvers */
    uint64_t last_server_rx_ms;  /**< Time of last successful TXT response from server */
    int      server_connected;   /**< 1 = client has connected to server */
    char     mode[32];           /**< "CLIENT" or "SERVER" */
    
    /* SOCKS5 Telemetry */
    uint32_t socks5_total_conns;
    uint32_t socks5_total_errors;
    char     socks5_last_target[64]; /**< host:port */
    uint8_t  socks5_last_error;      /**< Last SOCKS5 error code */
} tui_stats_t;

/**
 * @brief TUI Server Snapshot.
 */
typedef struct {
    char     ip[46];
    char     user_id[16];
    uint16_t downstream_mtu;
    uint8_t  loss_pct;
    uint8_t  fec_k;
    uint8_t  enc_format;
    uint32_t idle_sec;
} tui_client_snap_t;

/**
 * @brief Debug log buffer.
 */
#define TUI_DEBUG_LINES 256
#define TUI_DEBUG_LINE_SIZE 512

typedef struct {
    char     lines[TUI_DEBUG_LINES][TUI_DEBUG_LINE_SIZE];
    uint64_t timestamps[TUI_DEBUG_LINES];  /**< Relative ms timestamp */
    int      head;          /**< Next write position */
    int      count;         /**< Total lines ever written */
    int      auto_scroll;   /**< 1 = auto-scroll to newest */
    int      level;         /**< 0=errors, 1=warnings, 2=info, 3=verbose */
} tui_debug_buf_t;

/**
 * @brief Protocol Test State.
 */
typedef struct {
    uint64_t last_test_sent_ms;      /**< Timestamp when test was sent */
    uint64_t last_test_recv_ms;      /**< Timestamp when response was received */
    int      test_pending;           /**< 1 = waiting for response */
    int      last_test_success;      /**< 1 = last test succeeded */
    uint32_t test_sequence;          /**< Sequence number for current test */
    char     test_payload[64];       /**< Payload sent in last test */
} tui_proto_test_t;

typedef void (*tui_send_debug_cb)(const char *payload, uint32_t seq);
typedef void (*tui_send_command_cb)(uint32_t cmd);

/**
 * @brief TUI Context - The central management object for UI.
 */
typedef struct tui_ctx {
    tui_stats_t      *stats;
    resolver_pool_t  *pool;
    dnstun_config_t  *cfg;
    volatile int      running;
    volatile int      restart;
    int               panel;        /**< 0=stats, 1=resolvers, 2=config, 3=debug, 4=help, 5=proto_test */
    const char       *config_path;  /**< Path to INI file for saving */

    /* Inline text-input mode */
    int   input_mode;               /**< 0=normal, 1=collecting input */
    char  input_buf[512];
    int   input_len;
    char  input_label[64];
    void (*input_done_cb)(struct tui_ctx *t, const char *value);

    /* Callback for server to fetch active client sessions */
    int (*get_clients_cb)(tui_client_snap_t *out, int max_clients);

    /* Debug screen */
    tui_debug_buf_t   debug;
    int               debug_scroll;     /**< Scroll offset for debug view */

    /* Protocol test screen */
    tui_proto_test_t  proto_test;       /**< Protocol loopback test state */
    tui_send_debug_cb send_debug_cb;
    tui_send_command_cb send_command_cb;
} tui_ctx_t;

#endif /* QNS_TUI_CORE_H */
