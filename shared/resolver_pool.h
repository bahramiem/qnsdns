#pragma once
#ifndef DNSTUN_RESOLVER_POOL_H
#define DNSTUN_RESOLVER_POOL_H

#include "types.h"
#include "config.h"
#include "uv.h"

/* ──────────────────────────────────────────────
   Resolver pool — manages active / penalty / dead sets
────────────────────────────────────────────── */
typedef struct {
    resolver_t   resolvers[DNSTUN_MAX_RESOLVERS];
    int          count;

    /* indices into resolvers[] for fast iteration */
    int          active[DNSTUN_MAX_RESOLVERS];
    int          active_count;

    int          dead[DNSTUN_MAX_RESOLVERS];
    int          dead_count;

    uv_mutex_t   lock;
    int          rr_cursor;     /* round-robin next-index (owned by pool) */

    const dnstun_config_t *cfg;
} resolver_pool_t;

/* Init / destroy */
int  rpool_init(resolver_pool_t *pool, const dnstun_config_t *cfg);
void rpool_destroy(resolver_pool_t *pool);

/* Add a resolver by IP string. Returns index or -1. */
int  rpool_add(resolver_pool_t *pool, const char *ip);

/* Mark state transitions */
void rpool_set_state(resolver_pool_t *pool, int idx, resolver_state_t s);

/* Pick the next active resolver in round-robin (thread-safe).
   Returns index, or -1 if none available. */
int  rpool_next(resolver_pool_t *pool);

/* Health check — Returns number of successes in last 30 samples */
int  rpool_health_score(resolver_pool_t *pool, int idx);

/* AIMD congestion window update */
void rpool_on_ack(resolver_pool_t *pool, int idx, double rtt_ms);
void rpool_on_loss(resolver_pool_t *pool, int idx);
void rpool_on_rtt_spike(resolver_pool_t *pool, int idx);

/* Adaptive FEC — recalculate FEC K for a resolver */
uint32_t rpool_fec_k(resolver_pool_t *pool, int idx, int raw_symbols);

/* Penalty box — call on rate limit hit; uses resolver's cooldown_ms */
void rpool_penalise(resolver_pool_t *pool, int idx);

/* Check and release resolvers whose penalty has expired */
void rpool_release_penalties(resolver_pool_t *pool);

/* Background recovery — returns IDs to probe this tick */
int  rpool_dead_to_probe(resolver_pool_t *pool, int *out_indices, int max, int rate);

/* DNS Flux — active domain index for current time */
int  rpool_flux_domain(const dnstun_config_t *cfg);

/* Swarm — add a list of IPs received from the server */
int  rpool_swarm_merge(resolver_pool_t *pool, const char **ips, int count);

#endif /* DNSTUN_RESOLVER_POOL_H */
