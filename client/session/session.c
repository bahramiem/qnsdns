/**
 * @file client/session/session.c
 * @brief Client Session Reorder Buffer Implementation
 *
 * Extracted from client/main.c lines 2037-2197.
 *
 * The reorder buffer uses a fixed-size sliding window. Each slot corresponds
 * to a downstream sequence-number offset from `expected_seq`.
 *
 * Slot 0 = expected_seq, slot 1 = expected_seq+1, etc.
 * When slot 0 is flushed, all remaining slots slide down by one position.
 *
 * Example flow:
 *   1. Server sends seq=5 (expected=3). Stored at slot 2.
 *   2. Server sends seq=3 (expected=3). Stored at slot 0 → triggers flush.
 *   3. Server sends seq=4. Stored at slot 0 (after flush moved expected to 4).
 *   4. seq=4 and seq=5 both flush in order.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>

#include "client/session/session.h"

/* Logging — provided by main.c (uses g_tui, g_cfg) */
extern int          log_level(void);

#define LOG_DEBUG(...) do { if (log_level() >= 2) { } } while(0)
#define LOG_ERR(...)   do { } while(0)

/* ────────────────────────────────────────────── */
/*  Reorder Buffer                                */
/* ────────────────────────────────────────────── */

void reorder_buffer_init(reorder_buffer_t *rb) {
    memset(rb, 0, sizeof(*rb));
    rb->expected_seq = 0;
    for (int i = 0; i < RX_REORDER_WINDOW; i++) {
        rb->slots[i].valid = false;
        rb->slots[i].data  = NULL;
        rb->slots[i].len   = 0;
    }
}

void reorder_buffer_free(reorder_buffer_t *rb) {
    for (int i = 0; i < RX_REORDER_WINDOW; i++) {
        if (rb->slots[i].valid && rb->slots[i].data) {
            free(rb->slots[i].data);
        }
        rb->slots[i].valid = false;
        rb->slots[i].data  = NULL;
    }
}

bool reorder_buffer_insert(reorder_buffer_t *rb, uint16_t seq,
                            const uint8_t *data, size_t len) {
    int offset = (int)(seq - rb->expected_seq);
    if (offset < 0) offset += 65536; /* Handle 16-bit wrap-around */

    if (offset < 0 || offset >= RX_REORDER_WINDOW) {
        if (offset < 0) {
            /* Too old — drop */
            return false;
        }
        /* Too far ahead — discard stale window and jump */
        reorder_buffer_free(rb);
        rb->expected_seq = seq;
        offset = 0;
    }

    /* Duplicate check */
    if (rb->slots[offset].valid) {
        return false;
    }

    /* Allocate and copy data */
    rb->slots[offset].data = malloc(len > 0 ? len : 1);
    if (!rb->slots[offset].data) {
        return false;
    }
    if (len > 0) memcpy(rb->slots[offset].data, data, len);
    rb->slots[offset].len         = len;
    rb->slots[offset].seq         = seq;
    rb->slots[offset].received_at = time(NULL);
    rb->slots[offset].valid       = true;
    return true;
}

int reorder_buffer_flush(reorder_buffer_t *rb, uint8_t *out_buf,
                          size_t out_cap, size_t *out_len) {
    int    packets = 0;
    size_t total   = 0;
    *out_len = 0;

    /* Flush as long as the next expected slot (offset 0) is filled */
    while (rb->slots[0].valid) {
        rx_buffer_slot_t *slot = &rb->slots[0];

        /* Bounds check */
        if (total + slot->len > out_cap) break;

        /* Copy to output */
        if (slot->len > 0)
            memcpy(out_buf + total, slot->data, slot->len);
        total += slot->len;

        rb->expected_seq++;
        packets++;

        /* Free this slot and compact remaining slots by one position */
        free(slot->data);
        slot->valid = false;

        memmove(&rb->slots[0], &rb->slots[1],
                (RX_REORDER_WINDOW - 1) * sizeof(rx_buffer_slot_t));
        memset(&rb->slots[RX_REORDER_WINDOW - 1], 0, sizeof(rx_buffer_slot_t));
        rb->slots[RX_REORDER_WINDOW - 1].valid = false;
    }

    *out_len = total;
    return packets;
}
