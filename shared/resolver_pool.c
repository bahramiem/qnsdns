#include "resolver_pool.h"
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <stdio.h>
#include <time.h>

/* ── Init / Destroy ─────────────────────────────────────────────────────────*/
int rpool_init(resolver_pool_t *pool, const dnstun_config_t *cfg) {
    memset(pool, 0, sizeof(*pool));
    pool->cfg = cfg;
    pool->rr_cursor = 0;
    uv_mutex_init(&pool->lock);
    return 0;
}

void rpool_destroy(resolver_pool_t *pool) {
    uv_mutex_destroy(&pool->lock);
}

/* ── Add resolver ───────────────────────────────────────────────────────────*/
int rpool_add(resolver_pool_t *pool, const char *ip) {
    uv_mutex_lock(&pool->lock);

    if (pool->count >= DNSTUN_MAX_RESOLVERS) {
        uv_mutex_unlock(&pool->lock);
        return -1;
    }

    /* Check duplicate */
    for (int i = 0; i < pool->count; i++) {
        if (strcmp(pool->resolvers[i].ip, ip) == 0) {
            uv_mutex_unlock(&pool->lock);
            return i;
        }
    }

    int idx = pool->count++;
    resolver_t *r = &pool->resolvers[idx];
    memset(r, 0, sizeof(*r));
    strncpy(r->ip, ip, sizeof(r->ip)-1);
    uv_ip4_addr(ip, 53, &r->addr);
    r->fail_reason[0] = '\0'; /* Clear failure reason */
    r->state          = RSV_DEAD; /* start in dead; testing promotes it */
    r->cwnd           = pool->cfg->cwnd_init;
    r->cwnd_max       = pool->cfg->cwnd_max;
    r->upstream_mtu   = 220;  /* conservative default */
    r->downstream_mtu = 512;
    r->loss_rate      = 0.0;
    r->fec_k          = 0;
    r->rtt_ms         = 999.0;
    r->rtt_baseline   = 999.0;
    r->enc            = ENC_BASE64;

    /* add to dead list */
    pool->dead[pool->dead_count++] = idx;

    uv_mutex_unlock(&pool->lock);
    return idx;
}

/* ── State transitions ──────────────────────────────────────────────────────
 * Fix #12: remove from ALL lists before adding to the target list.         */
void rpool_set_state(resolver_pool_t *pool, int idx, resolver_state_t s) {
    uv_mutex_lock(&pool->lock);

    resolver_t *r = &pool->resolvers[idx];
    r->state = s;

    /* Remove from active list (if present) */
    for (int i = 0; i < pool->active_count; i++) {
        if (pool->active[i] == idx) {
            pool->active[i] = pool->active[--pool->active_count];
            break;
        }
    }
    /* Remove from dead list (if present) */
    for (int i = 0; i < pool->dead_count; i++) {
        if (pool->dead[i] == idx) {
            pool->dead[i] = pool->dead[--pool->dead_count];
            break;
        }
    }

    /* Add to new list */
    if (s == RSV_ACTIVE) {
        pool->active[pool->active_count++] = idx;
    } else if (s == RSV_DEAD || s == RSV_PENALTY || s == RSV_ZOMBIE) {
        pool->dead[pool->dead_count++] = idx;
    }

    uv_mutex_unlock(&pool->lock);
}

/* ── Round-Robin next active ────────────────────────────────────────────────
 * Fix #7: cursor is now a field of pool, not a global.                     */
int rpool_next(resolver_pool_t *pool) {
    uv_mutex_lock(&pool->lock);
    int result = -1;
    if (pool->active_count > 0) {
        pool->rr_cursor = pool->rr_cursor % pool->active_count;
        result = pool->active[pool->rr_cursor];
        pool->rr_cursor = (pool->rr_cursor + 1) % pool->active_count;
    }
    uv_mutex_unlock(&pool->lock);
    return result;
}

/* ── AIMD Congestion Control ────────────────────────────────────────────────*/
void rpool_on_ack(resolver_pool_t *pool, int idx, double rtt_ms) {
    uv_mutex_lock(&pool->lock);
    resolver_t *r = &pool->resolvers[idx];

    /* EWMA RTT baseline (alpha=0.125 like TCP) */
    if (r->rtt_baseline >= 999.0)
        r->rtt_baseline = rtt_ms;
    else
        r->rtt_baseline = 0.875 * r->rtt_baseline + 0.125 * rtt_ms;
    r->rtt_ms = rtt_ms;

    /* AIMD additive increase */
    if (r->cwnd < r->cwnd_max)
        r->cwnd += 1.0 / r->cwnd;

    /* RTT spike check: soft penalty if RTT > 2x baseline */
    if (rtt_ms > 2.0 * r->rtt_baseline && r->rtt_baseline < 900.0) {
        r->cwnd *= 0.75;
        if (r->cwnd < 1.0) r->cwnd = 1.0;
    }

    /* EWMA loss rate: successful ACK drives it down */
    r->loss_rate = 0.95 * r->loss_rate + 0.05 * 0.0;

    uv_mutex_unlock(&pool->lock);
}

void rpool_on_loss(resolver_pool_t *pool, int idx) {
    uv_mutex_lock(&pool->lock);
    resolver_t *r = &pool->resolvers[idx];

    /* AIMD multiplicative decrease */
    r->cwnd *= 0.5;
    if (r->cwnd < 1.0) r->cwnd = 1.0;

    /* EWMA loss update */
    r->loss_rate = 0.95 * r->loss_rate + 0.05 * 1.0;

    uv_mutex_unlock(&pool->lock);
}

void rpool_on_rtt_spike(resolver_pool_t *pool, int idx) {
    uv_mutex_lock(&pool->lock);
    resolver_t *r = &pool->resolvers[idx];
    r->cwnd *= 0.75;
    if (r->cwnd < 1.0) r->cwnd = 1.0;
    uv_mutex_unlock(&pool->lock);
}

/* ── Adaptive FEC K ─────────────────────────────────────────────────────────*/
uint32_t rpool_fec_k(resolver_pool_t *pool, int idx, int raw_symbols) {
    uv_mutex_lock(&pool->lock);
    double loss = pool->resolvers[idx].loss_rate;
    uv_mutex_unlock(&pool->lock);

    /* FEC K = ceil(raw_symbols * loss / (1 - loss)) */
    if (loss <= 0.0) return 0;
    if (loss >= 0.5) loss = 0.5; /* cap at 50% overhead max */
    return (uint32_t)ceil((double)raw_symbols * loss / (1.0 - loss));
}

/* ── Penalty Box ────────────────────────────────────────────────────────────
 * Fix #1: was calling rpool_set_state (which acquires lock) while holding
 * the lock → deadlock on non-recursive mutexes.  Now we compute everything
 * while locked, release, then call rpool_set_state separately.            */
void rpool_penalise(resolver_pool_t *pool, int idx) {
    uv_mutex_lock(&pool->lock);
    resolver_t *r = &pool->resolvers[idx];
    double cd = r->cooldown_ms > 0.0 ? r->cooldown_ms : 60000.0;
    r->penalty_until = time(NULL) + (time_t)(cd / 1000.0);
    uv_mutex_unlock(&pool->lock);

    /* rpool_set_state acquires the lock itself — safe now that we released */
    rpool_set_state(pool, idx, RSV_PENALTY);
}

/* ── Release Penalties ──────────────────────────────────────────────────────
 * Fix #2: collect expired-penalty indices while locked (single pass, O(N)),
 * then release the lock and call rpool_set_state for each one.            */
void rpool_release_penalties(resolver_pool_t *pool) {
    time_t now = time(NULL);

    /* Collect expired indices without holding the lock across set_state */
    int to_release[DNSTUN_MAX_RESOLVERS];
    int n = 0;

    uv_mutex_lock(&pool->lock);
    for (int i = 0; i < pool->dead_count; i++) {
        int idx = pool->dead[i];
        if (pool->resolvers[idx].state == RSV_PENALTY &&
            pool->resolvers[idx].penalty_until <= now)
        {
            to_release[n++] = idx;
        }
    }
    uv_mutex_unlock(&pool->lock);

    /* Promote each collected resolver (rpool_set_state re-acquires lock) */
    for (int i = 0; i < n; i++) {
        rpool_set_state(pool, to_release[i], RSV_ACTIVE);
    }
}

/* ── Background Recovery — choose dead resolvers to probe ───────────────────*/
int rpool_dead_to_probe(resolver_pool_t *pool,
                        int *out_indices, int max, int rate)
{
    time_t now = time(NULL);
    /* minimum seconds between probes per resolver = 1/rate * dead_count */
    uv_mutex_lock(&pool->lock);
    int out = 0;
    for (int i = 0; i < pool->dead_count && out < max; i++) {
        int idx = pool->dead[i];
        resolver_t *r = &pool->resolvers[idx];
        if (r->state == RSV_ZOMBIE) continue; /* never re-probe zombies */
        /* Rate-limit: probe at most `rate` IPs per second globally */
        time_t next_probe = r->last_probe + (time_t)(pool->dead_count / (rate > 0 ? rate : 1));
        if (now >= next_probe) {
            out_indices[out++] = idx;
        }
    }
    uv_mutex_unlock(&pool->lock);
    return out;
}

/* ── DNS Flux — deterministic domain index for current time ─────────────────*/
int rpool_flux_domain(const dnstun_config_t *cfg) {
    if (cfg->domain_count <= 1) return 0;
    if (!cfg->dns_flux) return 0;
    time_t period = (time_t)cfg->flux_period_sec;
    if (period <= 0) period = 21600;
    time_t slot = time(NULL) / period;
    return (int)(slot % (time_t)cfg->domain_count);
}

/* ── Swarm merge ─────────────────────────────────────────────────────────────*/
int rpool_swarm_merge(resolver_pool_t *pool, const char **ips, int count) {
    int added = 0;
    for (int i = 0; i < count; i++) {
        int idx = rpool_add(pool, ips[i]);
        if (idx >= 0) {
            pool->resolvers[idx].from_swarm = true;
            added++;
        }
    }
    return added;
}
