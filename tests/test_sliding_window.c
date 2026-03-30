/**
 * @file tests/test_sliding_window.c
 * @brief Unit tests for the shared sliding window and reorder buffer.
 */

#include "../shared/window/sliding.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void test_basic_reorder(void) {
    printf("Running test_basic_reorder...\n");
    
    reorder_buffer_t rb;
    qns_reorder_init(&rb);

    /* 1. Insert seq 1 (Out-of-order, expected is 0) */
    uint8_t d1[] = "World";
    qns_reorder_insert(&rb, 1, d1, 5);

    /* 2. Flush should be empty (0 is missing) */
    uint8_t out[128];
    size_t outlen = 0;
    int flushed = qns_reorder_flush(&rb, out, sizeof(out), &outlen);
    assert(flushed == 0);
    assert(outlen == 0);

    /* 3. Insert seq 0 (The missing piece) */
    uint8_t d0[] = "Hello ";
    qns_reorder_insert(&rb, 0, d0, 6);

    /* 4. Flush should now yield both packets in order */
    flushed = qns_reorder_flush(&rb, out, sizeof(out), &outlen);
    assert(flushed == 2);
    assert(outlen == 11);
    assert(memcmp(out, "Hello World", 11) == 0);

    qns_reorder_free(&rb);
    printf("test_basic_reorder PASSED\n");
}

void test_window_wrap(void) {
    printf("Running test_window_wrap...\n");
    
    reorder_buffer_t rb;
    qns_reorder_init(&rb);
    
    /* Simulate being near the 16-bit wrap point */
    rb.expected_seq = 65534;
    
    uint8_t d1[] = "A";
    uint8_t d2[] = "B";
    uint8_t d3[] = "C";
    
    qns_reorder_insert(&rb, 65535, d2, 1);
    qns_reorder_insert(&rb, 0, d3, 1);
    qns_reorder_insert(&rb, 65534, d1, 1);
    
    uint8_t out[128];
    size_t outlen = 0;
    int flushed = qns_reorder_flush(&rb, out, sizeof(out), &outlen);
    
    assert(flushed == 3);
    assert(outlen == 3);
    assert(memcmp(out, "ABC", 3) == 0);
    assert(rb.expected_seq == 1);
    
    qns_reorder_free(&rb);
    printf("test_window_wrap PASSED\n");
}

int main(void) {
    test_basic_reorder();
    test_window_wrap();
    printf("\nAll Sliding Window tests PASSED!\n");
    return 0;
}
