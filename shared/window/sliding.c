/**
 * @file shared/window/sliding.c
 * @brief Logic for sliding windows and reorder buffers.
 * 
 * This module ensures that even if DNS packets arrive out of order, 
 * the data is delivered to the application in the correct sequence.
 * 
 * @example
 * // Pull data in sequential order
 * qns_reorder_init(&s->reorder_buf);
 * qns_reorder_insert(&s->reorder_buf, msg->seq, msg->data, msg->len);
 * qns_reorder_flush(&s->reorder_buf, s->recv_buf, s->recv_cap, &flushed_len);
 */

#include "shared/window/sliding.h"
#include <stdlib.h>
#include <string.h>

/**
 * @brief Checks if a sequence number is within a certain range.
 * 
 * Sequence numbers (0-65535) eventually wrap around. This function
 * uses modular arithmetic to check if a packet is "new" (ahead) 
 * or "old" (behind) compared to what we are expecting.
 * 
 * @param seq The sequence number of the incoming packet.
 * @param expected The sequence number we are next expecting.
 * @param window_size How many packets "ahead" we are willing to buffer.
 */
bool qns_window_is_in_range(uint16_t seq, uint16_t expected, int window_size) {
    /* 1. Calculate the difference between what we got and what we expect */
    uint16_t diff = seq - expected;
    
    /* 2. If the difference is small, it's within our valid 'window' */
    return diff < (uint16_t)window_size;
}

/**
 * @brief Sets up a fresh reorder buffer.
 * 
 * This resets the sequence tracker to 0 and prepares all storage 
 * slots to be empty.
 */
void qns_reorder_init(reorder_buffer_t *rb) {
    if (!rb) return;
    
    memset(rb, 0, sizeof(*rb));
    rb->expected_seq = 0;
    
    /* Initially, no slots have data */
    for (int i = 0; i < RX_REORDER_WINDOW; i++) {
        rb->slots[i].valid = false;
        rb->slots[i].data = NULL;
        rb->slots[i].len = 0;
    }
}

/**
 * @brief Clears everything in the reorder buffer.
 * 
 * This is critical to call when a session closes to prevent 
 * memory leaks, or when a session resets.
 */
void qns_reorder_free(reorder_buffer_t *rb) {
    if (!rb) return;
    
    for (int i = 0; i < RX_REORDER_WINDOW; i++) {
        if (rb->slots[i].valid && rb->slots[i].data) {
            free(rb->slots[i].data);
        }
        rb->slots[i].valid = false;
        rb->slots[i].data = NULL;
    }
}

/**
 * @brief Buffers a packet that arrived out of sequence.
 * 
 * If we expect "Packet 1" but get "Packet 3" first, we save 
 * Packet 3 in a slot until Packet 1 and 2 arrive.
 */
qns_err_t qns_reorder_insert(reorder_buffer_t *rb, uint16_t seq, const uint8_t *data, size_t len) {
    if (!rb || !data) return QNS_ERR_NULL_PTR;

    /* 1. Calculate how far ahead of 'expected' this packet is */
    int offset = (int)(seq - rb->expected_seq);
    if (offset < 0) offset += 65536; /* Handle wrap-around from 65535 to 0 */

    /* 2. Check if the packet is too old (already processed) or too new (outside window) */
    if (offset < 0 || offset >= RX_REORDER_WINDOW) {
        if (offset < 0) {
            /* This is a duplicate of a packet we already finished with */
            return QNS_ERR_INVALID_PARAM; 
        }
        
        /* The server sent us something way too far in the future! 
         * We have to clear everything and 'jump' to this new sequence. */
        qns_reorder_free(rb);
        rb->expected_seq = seq;
        offset = 0;
    }

    /* 3. Check if we already have this exact packet (Network duplicate) */
    if (rb->slots[offset].valid) {
        return QNS_OK; /* No error, but we don't need to save it again */
    }

    /* 4. Save the data into the correct slot */
    rb->slots[offset].data = malloc(len);
    if (!rb->slots[offset].data) {
        return QNS_ERR_MALLOC;
    }
    
    memcpy(rb->slots[offset].data, data, len);
    rb->slots[offset].len = len;
    rb->slots[offset].seq = seq;
    rb->slots[offset].received_at = time(NULL);
    rb->slots[offset].valid = true;

    return QNS_OK;
}

/**
 * @brief Pull out all packets that are now in the correct order.
 * 
 * This returns as much data as possible back to the main application
 * until it hits a "gap" (a missing sequence number).
 */
int qns_reorder_flush(reorder_buffer_t *rb, uint8_t *out_buf, size_t out_cap, size_t *out_len) {
    if (!rb || !out_buf || !out_len) return 0;

    int packets_flushed = 0;
    size_t total_bytes = 0;
    *out_len = 0;

    /* While we have a valid packet in 'Slot 0' (the next expected one)... */
    while (rb->slots[0].valid) {
        rx_buffer_slot_t *slot = &rb->slots[0];

        /* 1. Make sure it fits in the output buffer */
        if (total_bytes + slot->len > out_cap) {
            break; /* Application buffer full */
        }

        /* 2. Move data to output */
        memcpy(out_buf + total_bytes, slot->data, slot->len);
        total_bytes += slot->len;

        /* 3. Increment what we expect next */
        rb->expected_seq++;
        packets_flushed++;

        /* 4. Cleanup the used slot */
        free(slot->data);
        slot->valid = false;

        /* 5. Shift all other future packets 'down' by one slot */
        /* If we just flushed Packet 5, then Packet 6 (if present) is now 
         * our next 'expected' packet in Slot 0. */
        memmove(&rb->slots[0], &rb->slots[1], (RX_REORDER_WINDOW - 1) * sizeof(rx_buffer_slot_t));
        
        /* Clear the last slot that was shifted out */
        memset(&rb->slots[RX_REORDER_WINDOW - 1], 0, sizeof(rx_buffer_slot_t));
    }

    *out_len = total_bytes;
    return packets_flushed;
}
