/**
 * @file client/resolver/mtu.h
 * @brief MTU Binary Search Logic
 *
 * Implements the algorithms for binary searching the optimal upstream
 * and downstream MTU for a given resolver.
 */

#ifndef CLIENT_RESOLVER_MTU_H
#define CLIENT_RESOLVER_MTU_H

#include "client/resolver/probe.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the MTU binary search state.
 */
void init_mtu_binary_search(mtu_binary_search_t *search, int current, int max_mtu,
                            int window, int min_mtu, int max_retries,
                            bool is_upload, int dependent_mtu);

/**
 * @brief Free resources associated with a binary search.
 */
void free_mtu_binary_search(mtu_binary_search_t *search);

/**
 * @brief Get the next MTU value to test. Returns -1 if finished.
 */
int get_next_mtu_to_test(mtu_binary_search_t *search);

/**
 * @brief Mark the result of the current test payload size.
 */
void mark_mtu_tested(mtu_binary_search_t *search, int mtu, bool success);

/**
 * @brief Fire a specific MTU test probe for upload/download.
 */
void fire_mtu_test_probe(int resolver_idx, probe_test_type_t test_type,
                         resolver_test_result_t *res, int mtu_size);

#ifdef __cplusplus
}
#endif

#endif /* CLIENT_RESOLVER_MTU_H */
