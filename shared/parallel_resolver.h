#pragma once
#ifndef DNSTUN_PARALLEL_RESOLVER_H
#define DNSTUN_PARALLEL_RESOLVER_H

#include <stdint.h>
#include <stdbool.h>
#include <uv.h>
#include "types.h"

/* Parallel Resolver Pool - Ultra-High Parallelism DNS Queries */

/* ────────────────────────────────────────────────────────────── */
/*  Resolver Performance Metrics                                  */
/* ────────────────────────────────────────────────────────────── */

typedef struct resolver_score {
    double latency_ms;          /* EWMA latency */
    double success_rate;        /* Success rate 0.0-1.0 */
    double bandwidth_bps;       /* Estimated bandwidth */
    int active_queries;         /* Currently active queries */
    time_t last_success;        /* Last successful response */
    time_t last_attempt;        /* Last query attempt */
    uint32_t total_queries;     /* Total queries sent */
    uint32_t total_responses;   /* Total responses received */
} resolver_score_t;

/* ────────────────────────────────────────────────────────────── */
/*  Parallel Query State                                          */
/* ────────────────────────────────────────────────────────────── */

typedef struct parallel_query {
    uint8_t *payload;           /* Query payload */
    size_t payload_len;
    uint16_t query_id;          /* DNS query ID */
    int resolver_indices[5];    /* Up to 5 resolvers for redundancy */
    int resolver_count;         /* Number of resolvers used */
    uv_timer_t *timeout_timer;  /* Query timeout */
    bool completed;             /* Query completed (success/failure) */
    time_t start_time;          /* Query start time */
    struct parallel_resolver_pool *pool; /* Reference to pool for callbacks */
    struct parallel_query *next;
} parallel_query_t;

/* ────────────────────────────────────────────────────────────── */
/*  Parallel Resolver Pool                                        */
/* ────────────────────────────────────────────────────────────── */

#define MAX_PARALLEL_RESOLVERS 1000
#define MAX_CONCURRENT_QUERIES 10000

typedef struct parallel_resolver_pool {
    /* Resolver management */
    resolver_t resolvers[MAX_PARALLEL_RESOLVERS];
    resolver_score_t scores[MAX_PARALLEL_RESOLVERS];
    int resolver_count;

    /* Query management */
    parallel_query_t *active_queries;
    size_t active_query_count;
    uint16_t next_query_id;

    /* Configuration */
    int redundancy_factor;      /* Queries per resolver (1-5) */
    int max_concurrent_per_resolver; /* Max concurrent queries per resolver */
    double timeout_ms;          /* Query timeout */
    double ewma_alpha;          /* EWMA smoothing factor */

    /* Threading */
    uv_mutex_t lock;
    uv_loop_t *loop;

    /* Statistics */
    uint64_t total_queries_sent;
    uint64_t total_responses_received;
    uint64_t total_timeouts;
    double avg_latency_ms;

    /* Callbacks */
    void (*on_query_complete)(struct parallel_resolver_pool *pool,
                            const uint8_t *response, size_t len,
                            const struct sockaddr *addr, uint16_t query_id);
    void (*on_query_timeout)(struct parallel_resolver_pool *pool,
                           uint16_t query_id);
} parallel_resolver_pool_t;

/* ────────────────────────────────────────────────────────────── */
/*  API Functions                                                 */
/* ────────────────────────────────────────────────────────────── */

/* Initialize parallel resolver pool */
int parallel_resolver_pool_init(parallel_resolver_pool_t *pool, uv_loop_t *loop);

/* Cleanup parallel resolver pool */
void parallel_resolver_pool_cleanup(parallel_resolver_pool_t *pool);

/* Add resolver to pool */
int parallel_resolver_pool_add(parallel_resolver_pool_t *pool, const char *ip);

/* Send query with high parallelism and redundancy */
int parallel_resolver_pool_send(parallel_resolver_pool_t *pool,
                               const uint8_t *payload, size_t len);

/* Process incoming DNS response */
void parallel_resolver_pool_process_response(parallel_resolver_pool_t *pool,
                                           const uint8_t *response, size_t len,
                                           const struct sockaddr *addr);

/* Update resolver performance metrics */
void parallel_resolver_pool_update_metrics(parallel_resolver_pool_t *pool,
                                         int resolver_idx, double latency_ms,
                                         bool success);

/* Get top N resolvers by performance */
int parallel_resolver_pool_get_top_resolvers(parallel_resolver_pool_t *pool,
                                           int *indices, int max_count);

/* Load balancing: select optimal resolvers for query */
int parallel_resolver_pool_select_resolvers(parallel_resolver_pool_t *pool,
                                          int *indices, int max_count);

/* Get pool statistics */
typedef struct {
    int total_resolvers;
    int active_resolvers;
    size_t active_queries;
    double avg_latency_ms;
    double success_rate;
    uint64_t queries_per_second;
} parallel_resolver_stats_t;

void parallel_resolver_pool_get_stats(const parallel_resolver_pool_t *pool,
                                    parallel_resolver_stats_t *stats);

/* Adaptive parameter tuning */
void parallel_resolver_pool_adapt_parameters(parallel_resolver_pool_t *pool);

/* Background maintenance */
void parallel_resolver_pool_maintenance(parallel_resolver_pool_t *pool);

#endif /* DNSTUN_PARALLEL_RESOLVER_H */