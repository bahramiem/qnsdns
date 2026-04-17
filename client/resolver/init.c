/**
 * @file client/resolver/init.c
 * @brief DNS Resolver Initial Discovery and Lifecycle Implementation
 *
 * Extracted from client/main.c lines 1683-1984.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include "shared/config.h"
#include "shared/resolver_pool.h"
#include "uv.h"

#include "client/resolver/init.h"
#include "client/resolver/mtu.h"
#include "client/resolver/probe.h"
#include "shared/tui.h"

extern uv_loop_t *g_loop;
extern dnstun_config_t g_cfg;
extern resolver_pool_t g_pool;
extern tui_stats_t g_stats;

/* Forward declaration for aggregation stats */
extern void log_aggregation_stats(void);

extern int log_level(void);


/* ────────────────────────────────────────────── */
/*  CIDR Scan                                     */
/* ────────────────────────────────────────────── */

void cidr_scan_subnet(const char *seed_ip, int prefix) {
  struct sockaddr_in sa;
  uv_ip4_addr(seed_ip, 53, &sa);
  uint32_t base = ntohl(sa.sin_addr.s_addr);

  int count = (prefix == 16) ? 65536 : 256;
  uint32_t mask = (prefix == 16) ? 0xFFFF0000 : 0xFFFFFF00;
  uint32_t net = base & mask;

  LOG_INFO("CIDR scan /%d on %s (%d IPs)\n", prefix, seed_ip, count);

  char ip[46];
  for (int i = 1; i < count - 1; i++) {
    uint32_t host = net | (uint32_t)i;
    struct sockaddr_in sa2;
    sa2.sin_addr.s_addr = htonl(host);
    uv_inet_ntop(AF_INET, &sa2.sin_addr, ip, sizeof(ip));
    rpool_add(&g_pool, ip);
  }
}

/* ────────────────────────────────────────────── */
/*  Resolver Init Phase (Scanner.py style)        */
/* ────────────────────────────────────────────── */

static void on_init_phase_timeout(uv_timer_t *t) { uv_stop(t->loop); }

void run_event_loop_ms(int timeout_ms) {
  uv_timer_t wait;
  uv_timer_init(g_loop, &wait);
  uv_timer_start(&wait, on_init_phase_timeout, (uint64_t)timeout_ms, 0);
  uv_run(g_loop, UV_RUN_DEFAULT);
  uv_close((uv_handle_t *)&wait, NULL);
  uv_run(g_loop, UV_RUN_NOWAIT);
}

void resolver_init_phase(void) {
  LOG_INFO("=== Resolver Initialization Phase (Scanner.py style) ===\n");

  /* Step 1: Add seed resolvers */
  for (int i = 0; i < g_cfg.seed_count; i++)
    rpool_add(&g_pool, g_cfg.seed_resolvers[i]);

  LOG_INFO("Loaded %d seed resolvers\n", g_pool.count);

  /* Step 2: CIDR scan seed IPs */
  if (g_cfg.cidr_scan) {
    for (int i = 0; i < g_cfg.seed_count; i++)
      cidr_scan_subnet(g_cfg.seed_resolvers[i], g_cfg.cidr_prefix);
    LOG_INFO("After CIDR scan: %d resolvers in pool\n", g_pool.count);
  }

  resolver_test_result_t *results =
      calloc(g_pool.count, sizeof(resolver_test_result_t));
  if (!results) {
    LOG_ERR("Failed to allocate test results\n");
    return;
  }

  int wait_ms =
      (g_cfg.test_timeout_ms > 0) ? g_cfg.test_timeout_ms + 1000 : 5000;

  /* ─── Phase 1: Long QNAME Test ─── */
  LOG_INFO("--- Phase 1: Testing Long QNAME support ---\n");
  int phase1_count = 0;
  for (int i = 0; i < g_pool.count; i++) {
    if (g_pool.resolvers[i].state == RSV_DEAD) {
      fire_test_probe(i, PROBE_TEST_LONGNAME, &results[i]);
      phase1_count++;
      if (phase1_count % 50 == 0)
        uv_run(g_loop, UV_RUN_NOWAIT);
    }
  }
  run_event_loop_ms(wait_ms);

  int longname_ok = 0;
  for (int i = 0; i < g_pool.count; i++) {
    if (results[i].longname_supported) {
      longname_ok++;
    } else {
      LOG_WARN("Resolver %s does not support long QNAME, marking as degraded "
               "but alive\n",
               g_pool.resolvers[i].ip);
      longname_ok++;
      results[i].longname_supported = true;
    }
  }
  LOG_INFO("Phase 1 complete: %d/%d resolvers passed or relaxed\n", longname_ok,
           g_pool.count);

  /* ─── Phase 2: NXDOMAIN Test ─── */
  LOG_INFO(
      "--- Phase 2: Testing NXDOMAIN behavior (fake resolver filter) ---\n");
  int phase2_count = 0;
  for (int i = 0; i < g_pool.count; i++) {
    if (results[i].longname_supported) {
      results[i].nxdomain_correct = false;
      fire_test_probe(i, PROBE_TEST_NXDOMAIN, &results[i]);
      phase2_count++;
      if (phase2_count % 50 == 0)
        uv_run(g_loop, UV_RUN_NOWAIT);
    }
  }
  run_event_loop_ms(wait_ms);

  int nxdomain_ok = 0;
  for (int i = 0; i < g_pool.count; i++) {
    if (results[i].longname_supported && !results[i].nxdomain_correct) {
      LOG_WARN(
          "Resolver %s failed NXDOMAIN (possible hijack), proceeding anyway\n",
          g_pool.resolvers[i].ip);
      nxdomain_ok++;
      results[i].nxdomain_correct = true;
    } else if (results[i].nxdomain_correct) {
      nxdomain_ok++;
    }
  }
  LOG_INFO("Phase 2 complete: %d/%d resolvers passed or relaxed\n", nxdomain_ok,
           g_pool.count);

  /* ─── Phase 3: EDNS + TXT Quality Test ─── */
  LOG_INFO("--- Phase 3: Testing EDNS + TXT support and MTU detection ---\n");
  int phase3_count = 0;
  for (int i = 0; i < g_pool.count; i++) {
    if (results[i].longname_supported && results[i].nxdomain_correct) {
      results[i].edns_supported = false;
      results[i].txt_supported = false;
      results[i].upstream_mtu = 0;
      results[i].downstream_mtu = 0;
      fire_test_probe(i, PROBE_TEST_EDNS_TXT, &results[i]);
      phase3_count++;
      if (phase3_count % 50 == 0)
        uv_run(g_loop, UV_RUN_NOWAIT);
    }
  }
  run_event_loop_ms(wait_ms);

  /* ─── Phase 4: MTU Binary Search Testing ─── */
  LOG_INFO("--- Phase 4: Binary search MTU testing ---\n");
  int phase4_count = 0;
  for (int i = 0; i < g_pool.count; i++) {
    if (results[i].longname_supported && results[i].nxdomain_correct &&
        (results[i].edns_supported || results[i].txt_supported)) {

      init_mtu_binary_search(
          &results[i].up_mtu_search, 0,
          g_cfg.max_upload_mtu > 0 ? g_cfg.max_upload_mtu : 1500, 30,
          g_cfg.min_upload_mtu,
          g_cfg.mtu_test_retries > 0 ? g_cfg.mtu_test_retries : 2, true, 0);

      /* Use Phase 3 EDNS advertised payload as a starting upper bound for downstream MTU search.
       * If Phase 3 failed or reported very low, use max_download_mtu (default 1200+). */
      int down_hint = results[i].downstream_mtu;
      if (down_hint < 512) down_hint = g_cfg.max_download_mtu > 0 ? g_cfg.max_download_mtu : 1500;
      if (down_hint > 4096) down_hint = 4096;

      init_mtu_binary_search(&results[i].down_mtu_search, 0,
                             down_hint, 30, g_cfg.min_download_mtu,
                             g_cfg.mtu_test_retries > 0 ? g_cfg.mtu_test_retries
                                                        : 2,
                             false, results[i].upstream_mtu);

      int first_up_mtu = get_next_mtu_to_test(&results[i].up_mtu_search);
      if (first_up_mtu > 0) {
        fire_mtu_test_probe(i, PROBE_TEST_MTU_UP, &results[i], first_up_mtu);
        phase4_count++;
        if (phase4_count % 20 == 0)
          uv_run(g_loop, UV_RUN_NOWAIT);
      }

      int first_down_mtu = get_next_mtu_to_test(&results[i].down_mtu_search);
      if (first_down_mtu > 0) {
        fire_mtu_test_probe(i, PROBE_TEST_MTU_DOWN, &results[i],
                            first_down_mtu);
        phase4_count++;
        if (phase4_count % 20 == 0)
          uv_run(g_loop, UV_RUN_NOWAIT);
      }
    }
  }
  if (phase4_count > 0) {
    LOG_INFO("Started %d MTU binary search tests\n", phase4_count);
    int mtu_wait_ms = (g_cfg.mtu_test_timeout_ms > 0)
                          ? g_cfg.mtu_test_timeout_ms * 20
                          : 20000;
    run_event_loop_ms(mtu_wait_ms);
  }
  LOG_INFO("Phase 4 complete: MTU binary search testing finished\n");

  /* Final filter */
  int active = 0;
  for (int i = 0; i < g_pool.count; i++) {
    resolver_t *r = &g_pool.resolvers[i];

    if (results[i].longname_supported && results[i].nxdomain_correct &&
        (results[i].edns_supported || results[i].txt_supported)) {
      /* Upstream MTU */
      if (results[i].up_mtu_search.optimal > 0)
        r->true_upstream_mtu = results[i].up_mtu_search.optimal;
      else if (results[i].upstream_mtu > 0)
        r->true_upstream_mtu = results[i].upstream_mtu;
      else
        r->true_upstream_mtu = 50;
      
      r->upstream_mtu = r->true_upstream_mtu;
      if (g_cfg.max_upload_mtu > 0 && r->upstream_mtu > g_cfg.max_upload_mtu)
          r->upstream_mtu = g_cfg.max_upload_mtu;

      /* Downstream MTU */
      if (results[i].down_mtu_search.optimal > 0)
        r->true_downstream_mtu = results[i].down_mtu_search.optimal;
      else if (results[i].downstream_mtu > 0)
        r->true_downstream_mtu = results[i].downstream_mtu;
      else
        r->true_downstream_mtu = 200;

      r->downstream_mtu = r->true_downstream_mtu;
      if (g_cfg.max_download_mtu > 0 && r->downstream_mtu > g_cfg.max_download_mtu)
        r->downstream_mtu = g_cfg.max_download_mtu;

      r->edns0_supported = true;
      rpool_set_state(&g_pool, i, RSV_ACTIVE);
      active++;
    } else if (results[i].longname_supported && results[i].nxdomain_correct) {
      LOG_WARN("Resolver %s failed Phase 3 (no EDNS/TXT), using minimal MTU "
               "fallback\n",
               r->ip);
      r->true_upstream_mtu = 512;
      r->true_downstream_mtu = 220;
      r->upstream_mtu = 512;
      r->downstream_mtu = 220;
      r->edns0_supported = false;
      rpool_set_state(&g_pool, i, RSV_ACTIVE);
      active++;
    }

    free_mtu_binary_search(&results[i].up_mtu_search);
    free_mtu_binary_search(&results[i].down_mtu_search);
  }

  LOG_INFO("=== Init complete: %d/%d resolvers active ===\n", active,
           g_pool.count);

  /* MTU stats */
  int up_mtu_min = 9999, up_mtu_max = 0;
  int down_mtu_min = 9999, down_mtu_max = 0;
  for (int i = 0; i < g_pool.count; i++) {
    resolver_t *r = &g_pool.resolvers[i];
    if (r->state == RSV_ACTIVE) {
      if (r->true_upstream_mtu > 0) {
        if (r->true_upstream_mtu < up_mtu_min)
          up_mtu_min = r->true_upstream_mtu;
        if (r->true_upstream_mtu > up_mtu_max)
          up_mtu_max = r->true_upstream_mtu;
      }
      if (r->true_downstream_mtu > 0) {
        if (r->true_downstream_mtu < down_mtu_min)
          down_mtu_min = r->true_downstream_mtu;
        if (r->true_downstream_mtu > down_mtu_max)
          down_mtu_max = r->true_downstream_mtu;
      }
    }
  }
  if (up_mtu_min < 9999)
    LOG_INFO("Upstream MTU range: %d - %d\n", up_mtu_min, up_mtu_max);
  if (down_mtu_min < 9999)
    LOG_INFO("Downstream MTU range: %d - %d\n", down_mtu_min, down_mtu_max);

  log_aggregation_stats();
  free(results);

  g_stats.active_resolvers = g_pool.active_count;
  g_stats.dead_resolvers = g_pool.dead_count;
}
