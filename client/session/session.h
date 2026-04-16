/**
 * @file client/session/session.h
 * @brief Client-Side Session State and Downstream Reorder Buffer
 *
 * The session tracks one SOCKS5 tunnel connection end-to-end:
 *   - Upstream send buffer (data queued to the DNS server)
 *   - Downstream receive buffer with reorder window
 *   - SOCKS5 connection state
 *
 * Reorder buffer:
 *   The server sends sequenced TXT records. DNS responses can arrive out of
 *   order. The reorder buffer reassembles them into the correct sequence
 *   before delivering to the SOCKS5 client (curl).
 *
 * Example:
 *   reorder_buffer_init(&sess->reorder_buf);
 *   reorder_buffer_insert(&sess->reorder_buf, seq, data, len);
 *   uint8_t flush[16384]; size_t flush_len;
 *   reorder_buffer_flush(&sess->reorder_buf, flush, sizeof(flush), &flush_len);
 */

#ifndef CLIENT_SESSION_H
#define CLIENT_SESSION_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Reorder buffer configuration ── */
#define RX_REORDER_WINDOW 512

/**
 * @brief One slot in the downstream reorder buffer.
 */
typedef struct {
    bool     valid;        /**< True if this slot has been filled */
    uint8_t *data;         /**< Heap-allocated payload */
    size_t   len;          /**< Payload length */
    uint16_t seq;          /**< DNS sequence number of this packet */
    time_t   received_at;  /**< Timestamp for timeout/debug */
} rx_buffer_slot_t;

/**
 * @brief Downstream reorder buffer (per session).
 *
 * Maintains a sliding window of received server TXT records, ordered by
 * downstream sequence number. Slots are flushed in-order to the SOCKS5 client.
 */
typedef struct {
    rx_buffer_slot_t slots[RX_REORDER_WINDOW];
    uint16_t         expected_seq;  /**< Next sequence number we expect to flush */
} reorder_buffer_t;

/* ── Buffer and session size limits ── */
#define MAX_SESSION_BUFFER (4 * 1024 * 1024)  /* 4 MB per session */

/**
 * @brief Per-connection tunnel session state (client side).
 */
typedef struct session {
    bool     established;      /**< True once SOCKS5 CONNECT is parsed */
    bool     closed;           /**< True once the SOCKS5 TCP handle is gone */
    bool     socks5_connected; /**< True once we've sent the SOCKS5 success reply */
    bool     status_consumed;  /**< True once we've processed the server's ACK byte */
    bool     first_seq_received; /**< True once we received seq=0 from server */

    uint8_t  session_id;       /**< 8-bit tunnel session ID */

    char     target_host[256]; /**< SOCKS5 CONNECT target hostname or IP */
    uint16_t target_port;      /**< SOCKS5 CONNECT target port */

    /** Upstream send buffer — data queued to send through DNS tunnel */
    uint8_t *send_buf;
    size_t   send_len;
    size_t   send_cap;

    /** Downstream receive buffer — data received from server, pending flush */
    uint8_t *recv_buf;
    size_t   recv_len;
    size_t   recv_cap;

    /** Downstream reorder buffer */
    reorder_buffer_t reorder_buf;

    /** Back-pointer to the socks5_client_t that owns this session */
    void    *client_ptr;

    /** Next upload sequence number */
    uint16_t tx_next;

    time_t   last_active;
} session_t;

/* ────────────────────────────────────────────── */
/*  Reorder buffer API                            */
/* ────────────────────────────────────────────── */

/**
 * @brief Initialize a reorder buffer to empty state.
 */
void reorder_buffer_init(reorder_buffer_t *rb);

/**
 * @brief Free all heap-allocated slot data in a reorder buffer.
 */
void reorder_buffer_free(reorder_buffer_t *rb);

/**
 * @brief Insert a received packet into the reorder buffer.
 *
 * If `seq` is exactly at `expected_seq`, the packet slots into offset 0.
 * If `seq` is ahead by more than the window, stale slots are discarded.
 * Duplicates are silently dropped.
 *
 * @return true on success, false if dropped.
 */
bool reorder_buffer_insert(reorder_buffer_t *rb, uint16_t seq,
                            const uint8_t *data, size_t len);

/**
 * @brief Flush consecutive packets starting from `expected_seq` into @p out_buf.
 *
 * Continues flushing as long as the next expected slot is present.
 *
 * @param rb       Reorder buffer.
 * @param out_buf  Output buffer for flushed data.
 * @param out_cap  Capacity of @p out_buf.
 * @param out_len  Set to total bytes flushed.
 * @return Number of packets flushed (including 0-byte ACK packets).
 */
int reorder_buffer_flush(reorder_buffer_t *rb, uint8_t *out_buf,
                          size_t out_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* CLIENT_SESSION_H */
