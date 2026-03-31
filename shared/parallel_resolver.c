#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <assert.h>
#include "parallel_resolver.h"

/* Parallel Resolver Pool Implementation */

/* ────────────────────────────────────────────────────────────── */
/*  Internal Functions                                            */
/* ────────────────────────────────────────────────────────────── */

static double calculate_resolver_score(const resolver_score_t *score) {
    if (score->total_queries == 0) return 0.0;

    double latency_weight = 1.0 / (1.0 + score->latency_ms / 100.0);
    double success_weight = score->success_rate;
    double load_penalty = 1.0 / (1.0 + score->active_queries / 10.0);

    /* Freshness bonus for recently successful resolvers */
    time_t now = time(NULL);
    double freshness = (now - score->last_success < 60) ? 1.2 : 1.0;

    return (latency_weight * 0.4 + success_weight * 0.4 + load_penalty * 0.2) * freshness;
}

static int compare_resolver_scores(const void *a, const void *b) {
    const resolver_score_t *score_a = a;
    const resolver_score_t *score_b = b;
    double score_a_val = calculate_resolver_score(score_a);
    double score_b_val = calculate_resolver_score(score_b);
    return (score_b_val > score_a_val) ? 1 : (score_b_val < score_a_val) ? -1 : 0;
}

static void on_query_timeout(uv_timer_t *timer) {
    parallel_query_t *query = timer->data;
    if (!query || !query->pool) return;

    /* Mark query as timed out */
    query->completed = true;

    /* Note: The pool cleanup will handle removing this query and updating metrics */
    /* Call timeout callback if registered */
    if (query->pool->on_query_timeout) {
        query->pool->on_query_timeout(query->pool, query->query_id);
    }
}

/* ────────────────────────────────────────────────────────────── */
/*  API Implementation                                            */
/* ────────────────────────────────────────────────────────────── */

int parallel_resolver_pool_init(parallel_resolver_pool_t *pool, uv_loop_t *loop) {
    memset(pool, 0, sizeof(*pool));

    pool->loop = loop;
    pool->redundancy_factor = 3;  /* Send to 3 resolvers by default */
    pool->max_concurrent_per_resolver = 10;
    pool->timeout_ms = 2000.0;    /* 2 second timeout */
    pool->ewma_alpha = 0.1;       /* EWMA smoothing factor */

    uv_mutex_init(&pool->lock);

    return 0;
}

void parallel_resolver_pool_cleanup(parallel_resolver_pool_t *pool) {
    uv_mutex_lock(&pool->lock);

    /* Clean up active queries */
    parallel_query_t *query = pool->active_queries;
    while (query) {
        parallel_query_t *next = query->next;
        if (query->timeout_timer) {
            uv_timer_stop(query->timeout_timer);
            uv_close((uv_handle_t*)query->timeout_timer, NULL);
            free(query->timeout_timer);
        }
        free(query->payload);
        free(query);
        query = next;
    }

    uv_mutex_unlock(&pool->lock);
    uv_mutex_destroy(&pool->lock);
}

int parallel_resolver_pool_add(parallel_resolver_pool_t *pool, const char *ip) {
    uv_mutex_lock(&pool->lock);

    if (pool->resolver_count >= MAX_PARALLEL_RESOLVERS) {
        uv_mutex_unlock(&pool->lock);
        return -1;
    }

    int idx = pool->resolver_count++;
    resolver_t *resolver = &pool->resolvers[idx];
    resolver_score_t *score = &pool->scores[idx];

    /* Initialize resolver */
    memset(resolver, 0, sizeof(*resolver));
    strncpy(resolver->ip, ip, sizeof(resolver->ip) - 1);
    resolver->state = RSV_ACTIVE;

    /* Initialize performance score */
    memset(score, 0, sizeof(*score));
    score->latency_ms = 100.0;     /* Initial estimate */
    score->success_rate = 1.0;     /* Assume good initially */
    score->last_success = time(NULL);
    score->last_attempt = time(NULL);

    uv_mutex_unlock(&pool->lock);
    return idx;
}

int parallel_resolver_pool_send(parallel_resolver_pool_t *pool,
                               const uint8_t *payload, size_t len) {
    uv_mutex_lock(&pool->lock);

    if (pool->active_query_count >= MAX_CONCURRENT_QUERIES) {
        uv_mutex_unlock(&pool->lock);
        return -1;  /* Too many active queries */
    }

    /* Select optimal resolvers */
    int resolver_indices[5];
    int resolver_count = parallel_resolver_pool_select_resolvers(pool,
                                                                 resolver_indices,
                                                                 pool->redundancy_factor);
    if (resolver_count == 0) {
        uv_mutex_unlock(&pool->lock);
        return -1;  /* No available resolvers */
    }

    /* Create query */
    parallel_query_t *query = calloc(1, sizeof(*query));
    if (!query) {
        uv_mutex_unlock(&pool->lock);
        return -1;
    }

    query->payload = malloc(len);
    if (!query->payload) {
        free(query);
        uv_mutex_unlock(&pool->lock);
        return -1;
    }

    memcpy(query->payload, payload, len);
    query->payload_len = len;
    query->query_id = pool->next_query_id++;
    memcpy(query->resolver_indices, resolver_indices, sizeof(int) * resolver_count);
    query->resolver_count = resolver_count;
    query->start_time = time(NULL);
    query->pool = pool;

    /* Setup timeout timer */
    query->timeout_timer = malloc(sizeof(uv_timer_t));
    if (query->timeout_timer) {
        uv_timer_init(pool->loop, query->timeout_timer);
        query->timeout_timer->data = query;
        uv_timer_start(query->timeout_timer, on_query_timeout, (uint64_t)pool->timeout_ms, 0);
    }

    /* Add to active queries */
    query->next = pool->active_queries;
    pool->active_queries = query;
    pool->active_query_count++;

    /* Update resolver active query counts */
    for (int i = 0; i < resolver_count; i++) {
        int idx = resolver_indices[i];
        pool->scores[idx].active_queries++;
        pool->scores[idx].total_queries++;
        pool->scores[idx].last_attempt = time(NULL);
    }

    uv_mutex_unlock(&pool->lock);

    /* TODO: Actually send UDP packets to selected resolvers */
    /* This would involve creating UDP sockets and sending packets */

    return query->query_id;
}

void parallel_resolver_pool_process_response(parallel_resolver_pool_t *pool,
                                           const uint8_t *response, size_t len,
                                           const struct sockaddr *addr) {
    uv_mutex_lock(&pool->lock);

    pool->total_responses_received++;

    /* TODO: Extract query ID from DNS response */
    /* For now, assume we can correlate based on addr and find the matching query */
    /* This would require parsing the DNS response header to get the query ID */

    uint16_t query_id = 0; /* Extract from response */
    parallel_query_t *query = pool->active_queries;
    parallel_query_t *prev = NULL;

    /* Find matching query */
    while (query) {
        /* TODO: Proper correlation logic - for now just mark first active query */
        if (!query->completed) {
            query_id = query->query_id;
            query->completed = true;
            break;
        }
        prev = query;
        query = query->next;
    }

    if (query) {
        /* Remove from active list */
        if (prev) {
            prev->next = query->next;
        } else {
            pool->active_queries = query->next;
        }
        pool->active_query_count--;

        /* Update resolver metrics */
        double latency_ms = (time(NULL) - query->start_time) * 1000.0;
        for (int i = 0; i < query->resolver_count; i++) {
            int idx = query->resolver_indices[i];
            parallel_resolver_pool_update_metrics(pool, idx, latency_ms, true);
        }

        /* Stop and cleanup timeout timer */
        if (query->timeout_timer) {
            uv_timer_stop(query->timeout_timer);
            uv_close((uv_handle_t*)query->timeout_timer, NULL);
            free(query->timeout_timer);
        }

        /* Call completion callback */
        if (pool->on_query_complete) {
            pool->on_query_complete(pool, response, len, addr, query_id);
        }

        /* Cleanup query */
        free(query->payload);
        free(query);
    }

    uv_mutex_unlock(&pool->lock);
}

void parallel_resolver_pool_update_metrics(parallel_resolver_pool_t *pool,
                                         int resolver_idx, double latency_ms,
                                         bool success) {
    uv_mutex_lock(&pool->lock);

    if (resolver_idx < 0 || resolver_idx >= pool->resolver_count) {
        uv_mutex_unlock(&pool->lock);
        return;
    }

    resolver_score_t *score = &pool->scores[resolver_idx];

    /* Update EWMA latency */
    if (score->total_responses == 0) {
        score->latency_ms = latency_ms;
    } else {
        score->latency_ms = pool->ewma_alpha * latency_ms +
                           (1.0 - pool->ewma_alpha) * score->latency_ms;
    }

    /* Update success rate */
    score->total_responses++;
    double new_success_rate = (double)(score->total_responses - (success ? 0 : 1)) /
                             score->total_responses;
    score->success_rate = pool->ewma_alpha * (success ? 1.0 : 0.0) +
                         (1.0 - pool->ewma_alpha) * score->success_rate;

    if (success) {
        score->last_success = time(NULL);
    }

    score->active_queries = (score->active_queries > 0) ?
                           score->active_queries - 1 : 0;

    uv_mutex_unlock(&pool->lock);
}

int parallel_resolver_pool_get_top_resolvers(parallel_resolver_pool_t *pool,
                                           int *indices, int max_count) {
    uv_mutex_lock(&pool->lock);

    /* Create sortable array of resolver indices */
    typedef struct {
        int index;
        resolver_score_t score;
    } resolver_entry_t;

    resolver_entry_t *entries = malloc(sizeof(resolver_entry_t) * pool->resolver_count);
    if (!entries) {
        uv_mutex_unlock(&pool->lock);
        return 0;
    }

    for (int i = 0; i < pool->resolver_count; i++) {
        entries[i].index = i;
        memcpy(&entries[i].score, &pool->scores[i], sizeof(resolver_score_t));
    }

    /* Sort by performance score */
    qsort(entries, pool->resolver_count, sizeof(resolver_entry_t), compare_resolver_scores);

    /* Extract top indices */
    int count = (max_count < pool->resolver_count) ? max_count : pool->resolver_count;
    for (int i = 0; i < count; i++) {
        indices[i] = entries[i].index;
    }

    free(entries);
    uv_mutex_unlock(&pool->lock);

    return count;
}

int parallel_resolver_pool_select_resolvers(parallel_resolver_pool_t *pool,
                                          int *indices, int max_count) {
    return parallel_resolver_pool_get_top_resolvers(pool, indices, max_count);
}

void parallel_resolver_pool_get_stats(const parallel_resolver_pool_t *pool,
                                    parallel_resolver_stats_t *stats) {
    if (!stats) return;

    uv_mutex_lock(&pool->lock);

    memset(stats, 0, sizeof(*stats));
    stats->total_resolvers = pool->resolver_count;
    stats->active_queries = pool->active_query_count;

    /* Calculate statistics */
    int active_count = 0;
    double total_latency = 0.0;
    uint64_t total_successes = 0;
    uint64_t total_attempts = 0;

    for (int i = 0; i < pool->resolver_count; i++) {
        const resolver_score_t *score = &pool->scores[i];
        if (score->total_queries > 0) {
            active_count++;
            total_latency += score->latency_ms;
            total_successes += (uint64_t)(score->success_rate * score->total_queries);
            total_attempts += score->total_queries;
        }
    }

    stats->active_resolvers = active_count;
    if (active_count > 0) {
        stats->avg_latency_ms = total_latency / active_count;
        stats->success_rate = total_attempts > 0 ?
                             (double)total_successes / total_attempts : 0.0;
    }

    /* Rough queries per second estimate */
    time_t now = time(NULL);
    static time_t last_time = 0;
    static uint64_t last_queries = 0;

    if (last_time > 0 && now > last_time) {
        uint64_t queries_diff = pool->total_queries_sent - last_queries;
        time_t time_diff = now - last_time;
        stats->queries_per_second = (double)queries_diff / time_diff;
    }

    last_time = now;
    last_queries = pool->total_queries_sent;

    uv_mutex_unlock(&pool->lock);
}

void parallel_resolver_pool_adapt_parameters(parallel_resolver_pool_t *pool) {
    uv_mutex_lock(&pool->lock);

    parallel_resolver_stats_t stats;
    parallel_resolver_pool_get_stats(pool, &stats);

    /* Adapt redundancy based on success rate */
    if (stats.success_rate > 0.95) {
        pool->redundancy_factor = (pool->redundancy_factor > 1) ?
                                 pool->redundancy_factor - 1 : 1;
    } else if (stats.success_rate < 0.80) {
        pool->redundancy_factor = (pool->redundancy_factor < 5) ?
                                 pool->redundancy_factor + 1 : 5;
    }

    /* Adapt timeout based on average latency */
    if (stats.avg_latency_ms > 0) {
        pool->timeout_ms = stats.avg_latency_ms * 3.0;  /* 3x average latency */
        if (pool->timeout_ms < 500) pool->timeout_ms = 500;   /* Minimum 500ms */
        if (pool->timeout_ms > 5000) pool->timeout_ms = 5000; /* Maximum 5s */
    }

    uv_mutex_unlock(&pool->lock);
}

void parallel_resolver_pool_maintenance(parallel_resolver_pool_t *pool) {
    uv_mutex_lock(&pool->lock);

    time_t now = time(NULL);

    /* Clean up timed out queries */
    parallel_query_t **query_ptr = &pool->active_queries;
    while (*query_ptr) {
        parallel_query_t *query = *query_ptr;

        if (now - query->start_time > (time_t)(pool->timeout_ms / 1000.0)) {
            /* Query timed out */
            *query_ptr = query->next;  /* Remove from list */

            pool->total_timeouts++;

            /* Update resolver metrics for timeout */
            for (int i = 0; i < query->resolver_count; i++) {
                int idx = query->resolver_indices[i];
                parallel_resolver_pool_update_metrics(pool, idx, pool->timeout_ms, false);
            }

            /* Clean up query */
            if (query->timeout_timer) {
                uv_timer_stop(query->timeout_timer);
                uv_close((uv_handle_t*)query->timeout_timer, NULL);
                free(query->timeout_timer);
            }
            free(query->payload);
            free(query);

            pool->active_query_count--;
        } else {
            query_ptr = &query->next;
        }
    }

    /* Periodic parameter adaptation */
    static time_t last_adaptation = 0;
    if (now - last_adaptation > 60) {  /* Every minute */
        parallel_resolver_pool_adapt_parameters(pool);
        last_adaptation = now;
    }

    uv_mutex_unlock(&pool->lock);
}