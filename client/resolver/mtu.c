/**
 * @file client/resolver/mtu.c
 * @brief MTU Binary Search Implementation
 *
 * Extracted from client/main.c lines 1278-1470.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "shared/config.h"

#include "client/resolver/mtu.h"
#include "client/resolver/probe.h"

extern dnstun_config_t g_cfg;
#include "shared/tui.h"


/* ────────────────────────────────────────────── */
/*  MTU Binary Search Operations                  */
/* ────────────────────────────────────────────── */

void init_mtu_binary_search(mtu_binary_search_t *search, int current, int max_mtu, 
                           int window, int min_mtu, int max_retries, 
                           bool is_upload, int dependent_mtu) {
    if (!search) return;
    
    /* Free any existing cache */
    if (search->tested_cache) {
        free(search->tested_cache);
        search->tested_cache = NULL;
    }
    
    memset(search, 0, sizeof(*search));
    
    search->active = true;
    /* Default max MTU if not specified */
    int effective_max = max_mtu > 0 ? max_mtu : (is_upload ? 512 : 4096);
    /* Lower bound starts at current or min_mtu */
    search->low = current > min_mtu ? current : min_mtu;
    /* Upper bound starts at min(current + window, max_mtu) */
    search->high = current > 0 ? current + window : effective_max;
    if (search->high > effective_max) search->high = effective_max;
    
    search->test_size = search->high;
    search->optimal = current > 0 ? current : 0;
    search->retries = 0;
    search->max_retries = max_retries > 0 ? max_retries : 2;
    search->is_upload = is_upload;
    search->last_test_ms = 0;
    search->dependent_mtu = dependent_mtu;
    
    /* Allocate cache for tested values */
    search->cache_size = (effective_max / 8) + 1;
    search->tested_cache = calloc(search->cache_size, sizeof(int));
}

void free_mtu_binary_search(mtu_binary_search_t *search) {
    if (search) {
        if (search->tested_cache) {
            free(search->tested_cache);
            search->tested_cache = NULL;
        }
        search->active = false;
    }
}

static bool is_mtu_tested(mtu_binary_search_t *search, int mtu) {
    if (!search || !search->tested_cache || mtu < 0 || mtu >= search->cache_size * 8) return false;
    return (search->tested_cache[mtu / 8] & (1 << (mtu % 8))) != 0;
}

int get_next_mtu_to_test(mtu_binary_search_t *search) {
    if (!search || !search->active) return -1;
    
    if (search->low > search->high) {
        search->active = false;
        return -1;
    }
    
    /* Calculate mid favoring the upper side when we have a known optimal */
    int mid = (search->high + search->low) / 2;
    
    /* Ensure we don't test the same value twice by probing around mid */
    int original_mid = mid;
    while (is_mtu_tested(search, mid) && mid <= search->high) {
        mid++;
    }
    if (mid > search->high) {
        mid = original_mid - 1;
        while (is_mtu_tested(search, mid) && mid >= search->low) {
            mid--;
        }
    }
    
    if (mid > search->high || mid < search->low || is_mtu_tested(search, mid)) {
        search->active = false;
        return -1;
    }
    
    search->test_size = mid;
    return mid;
}

void mark_mtu_tested(mtu_binary_search_t *search, int mtu, bool success) {
    if (!search || !search->active) return;
    
    /* Mark in cache */
    if (search->tested_cache && mtu >= 0 && mtu < search->cache_size * 8) {
        search->tested_cache[mtu / 8] |= (1 << (mtu % 8));
    }
    
    if (success) {
        /* MTU works, shift lower bound up */
        if (mtu >= search->low) {
            search->low = mtu + 1;
        }
        /* If we succeeded, we can keep the optimal value updated */
        if (mtu > search->optimal) {
            search->optimal = mtu;
        }
        /* Double the window upwards to find real upper bound if we're hitting high limit */
        int effective_max = search->is_upload ? 
                           (g_cfg.max_upload_mtu > 0 ? g_cfg.max_upload_mtu : 512) : 
                           (g_cfg.max_download_mtu > 0 ? g_cfg.max_download_mtu : 4096);
                           
        if (search->high <= mtu && mtu < effective_max) {
            search->high = mtu + 60; /* Extend search space */
            if (search->high > effective_max) search->high = effective_max;
            search->test_size = search->high;
        }
        /* Reset retries on success */
        search->retries = 0;
    } else {
        /* MTU failed, check retries */
        search->retries++;
        if (search->retries >= search->max_retries) {
            /* Definitely failed, shift upper bound down */
            if (mtu <= search->high) {
                search->high = mtu - 1;
            }
            search->retries = 0; /* Reset for next test */
        } else {
            /* Uncheck from tested cache so we retry */
            if (search->tested_cache && mtu >= 0 && mtu < search->cache_size * 8) {
                search->tested_cache[mtu / 8] &= ~(1 << (mtu % 8));
            }
        }
    }
}

void fire_mtu_test_probe(int resolver_idx, probe_test_type_t test_type, 
                         resolver_test_result_t *res, int mtu_size) {
    int flux_idx = g_cfg.domain_count > 0 ? (rand() % g_cfg.domain_count) : 0;
    const char *domain = g_cfg.domain_count > 0 ? g_cfg.domains[flux_idx] : "tun.example.com";
    
    if (res && test_type == PROBE_TEST_MTU_UP) {
        res->up_mtu_search.last_test_ms = uv_hrtime() / 1000000;
    } else if (res && test_type == PROBE_TEST_MTU_DOWN) {
        res->down_mtu_search.last_test_ms = uv_hrtime() / 1000000;
    }
    
    fire_probe_ext(resolver_idx, domain, true, test_type, res, mtu_size);
}
