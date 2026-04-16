/**
 * @file client/resolver/probe.h
 * @brief DNS Resolver Probing and Capability Testing
 *
 * Provides the mechanism to test public resolvers during initialization.
 * Phases include:
 *  - Probe (just checking if alive)
 *  - Long QNAME testing (can it handle 253 byte qnames?)
 *  - NXDOMAIN testing (is it a fake resolver intercepting everything?)
 *  - EDNS0 / TXT capability
 */

#ifndef CLIENT_RESOLVER_PROBE_H
#define CLIENT_RESOLVER_PROBE_H

#include <stdint.h>
#include <stdbool.h>
#include "uv.h"
#include "shared/resolver_pool.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PROBE_TEST_LONGNAME = 1,
    PROBE_TEST_NXDOMAIN = 2,
    PROBE_TEST_EDNS_TXT = 3,
    PROBE_TEST_MTU_UP   = 4,
    PROBE_TEST_MTU_DOWN = 5
} probe_test_type_t;

/**
 * @brief State structure for doing a binary search around MTU.
 */
typedef struct mtu_binary_search {
    bool     active;
    int      low;
    int      high;
    int      current_test;
    int      optimal;
    int      retries;
    int      max_retries;
    bool     is_upload;
    uint64_t last_test_ms;
    int      dependent_mtu;
} mtu_binary_search_t;

/**
 * @brief Holds result sets from the initialization phase.
 */
typedef struct resolver_test_result {
    bool longname_supported;
    bool nxdomain_correct;
    bool edns_supported;
    bool txt_supported;
    int  upstream_mtu;
    int  downstream_mtu;
    float packet_loss;

    mtu_binary_search_t up_mtu_search;
    mtu_binary_search_t down_mtu_search;
} resolver_test_result_t;

/**
 * @brief Fire a test probe and funnel results into a callback ctx.
 */
void fire_test_probe(int resolver_idx, probe_test_type_t test_type, resolver_test_result_t *res);

/**
 * @brief Fire a regular keep-alive / latency checking probe.
 */
void fire_probe(int resolver_idx, const char *domain);

/**
 * @brief Extended probe utility used by initialization and periodic checks.
 */
void fire_probe_ext(int resolver_idx, const char *domain, bool is_init_probe,
                    probe_test_type_t test_type, resolver_test_result_t *test_res,
                    int mtu_test_val);

/**
 * @brief Build a fake DNS query used specifically to test MTU bounds.
 */
int build_mtu_test_query(uint8_t *outbuf, size_t *outlen, const char *domain,
                         uint16_t id, int mtu_size);

#ifdef __cplusplus
}
#endif

#endif /* CLIENT_RESOLVER_PROBE_H */
