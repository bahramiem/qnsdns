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

#include "shared/types.h"

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
