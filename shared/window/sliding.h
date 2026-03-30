/**
 * @file shared/window/sliding.h
 * @brief Shared sliding window and reorder buffer logic.
 * 
 * This module provides common utilities for sequence number management,
 * ACK tracking, and out-of-order packet reassembly.
 * 
 * @example
 * #include "shared/window/sliding.h"
 * 
 * // 1. Initialize a reorder buffer
 * reorder_buffer_t rb;
 * reorder_buffer_init(&rb);
 * 
 * // 2. Insert a packet that arrived out of order
 * reorder_buffer_insert(&rb, packet_seq, data, len);
 * 
 * // 3. Pull consecutive packets in order
 * size_t out_len;
 * reorder_buffer_flush(&rb, output_buffer, cap, &out_len);
 */

#ifndef QNS_WINDOW_SLIDING_H
#define QNS_WINDOW_SLIDING_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include "../types.h"
#include "../errors.h"

/**
 * @brief Check if a sequence number is within the tracking window.
 */
bool qns_window_is_in_range(uint16_t seq, uint16_t expected, int window_size);

/**
 * @brief Initialize a reorder buffer.
 */
void qns_reorder_init(reorder_buffer_t *rb);

/**
 * @brief Free all data and clear the reorder buffer.
 */
void qns_reorder_free(reorder_buffer_t *rb);

/**
 * @brief Insert a packet into the reorder buffer.
 * @return QNS_OK if inserted, or error if duplicate/out of window.
 */
qns_err_t qns_reorder_insert(reorder_buffer_t *rb, uint16_t seq, const uint8_t *data, size_t len);

/**
 * @brief Flush all consecutive ordered packets from the buffer.
 * @param rb Buffer to flush.
 * @param out_buf Destination buffer for data.
 * @param out_cap Capacity of out_buf.
 * @param out_len [Out] Total bytes written to out_buf.
 * @return Number of packets successfully flushed.
 */
int qns_reorder_flush(reorder_buffer_t *rb, uint8_t *out_buf, size_t out_cap, size_t *out_len);

#endif /* QNS_WINDOW_SLIDING_H */
