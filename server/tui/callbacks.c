/**
 * @file server/tui/callbacks.c
 * @brief Server-Side TUI Timer Callbacks and TTY Input Handling Implementation
 *
 * Extracted from server/main.c lines 1525-1629.
 *
 * Timer architecture:
 *   g_idle_timer (1s)  → on_idle_timer  → enforces idle timeouts, saves swarm
 *   g_tui_timer  (1s)  → on_tui_timer   → counts sessions, calls tui_render()
 *
 * TTY architecture:
 *   g_tty (STDIN) → on_tty_alloc (malloc buffer)
 *               → on_tty_read  (forward key to tui_handle_key)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "uv.h"
#include "shared/config.h"
#include "shared/tui.h"
#include "shared/types.h"
#include "shared/mgmt.h"

#include "server/session/session.h"
#include "server/swarm/swarm.h"
#include "server/tui/callbacks.h"

/* ── Externals from main.c ── */
extern dnstun_config_t  g_cfg;
extern tui_ctx_t        g_tui;
extern tui_stats_t      g_stats;
extern uv_loop_t       *g_loop;
extern mgmt_server_t   *g_mgmt;



/* ────────────────────────────────────────────── */
/*  Idle / cleanup timer (1s)                     */
/* ────────────────────────────────────────────── */

void on_idle_timer(uv_timer_t *t) {
    (void)t;
    time_t now = time(NULL);

    /* Step 1: Close idle sessions */
    for (int i = 0; i < SRV_MAX_SESSIONS; i++) {
        srv_session_t *s = &g_sessions[i];
        if (!s->used) continue;
        if (now - s->last_active > g_cfg.idle_timeout_sec) {
            LOG_INFO("Session %d idle timeout\n", i);
            session_close(i);
        }
    }

    /* Step 2: Persist swarm every 60 ticks */
    static int save_tick = 0;
    if (++save_tick >= 60) {
        save_tick = 0;
        if (g_cfg.swarm_save_disk) swarm_save();
    }

    /* Step 3: Reset per-second counters */
    g_stats.tx_bytes_sec = 0;
    g_stats.rx_bytes_sec = 0;
}

/* ────────────────────────────────────────────── */
/*  TUI Render Timer (1s)                         */
/* ────────────────────────────────────────────── */

void on_tui_timer(uv_timer_t *t) {
    (void)t;

    /* Count active sessions */
    int n = 0;
    for (int i = 0; i < SRV_MAX_SESSIONS; i++)
        if (g_sessions[i].used) n++;
    g_stats.active_sessions = n;

    g_stats.active_resolvers = g_swarm_count;

    tui_render(&g_tui);

    /* Broadcast telemetry to management clients */
    if (g_mgmt) mgmt_broadcast_telemetry(g_mgmt, &g_stats);
}

/* ────────────────────────────────────────────── */
/*  TUI Active Clients Snapshot                   */
/* ────────────────────────────────────────────── */

int get_active_clients(tui_client_snap_t *out, int max_clients) {
    int count = 0;
    time_t now = time(NULL);
    for (int i = 0; i < SRV_MAX_SESSIONS && count < max_clients; i++) {
        if (!g_sessions[i].used) continue;
        uv_ip4_name(&g_sessions[i].client_addr, out[count].ip, sizeof(out[count].ip));
        out[count].downstream_mtu = g_sessions[i].cl_downstream_mtu;
        out[count].loss_pct       = g_sessions[i].cl_loss_pct;
        out[count].fec_k          = g_sessions[i].cl_fec_k;
        out[count].enc_format     = g_sessions[i].cl_enc_format;
        out[count].idle_sec       = (uint32_t)(now - g_sessions[i].last_active);
        strncpy(out[count].user_id, g_sessions[i].user_id,
                sizeof(out[count].user_id) - 1);
        out[count].user_id[sizeof(out[count].user_id) - 1] = '\0';
        count++;
    }
    return count;
}

/* ────────────────────────────────────────────── */
/*  TTY Input (STDIN → TUI keys)                  */
/* ────────────────────────────────────────────── */

void on_tty_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    (void)handle;
    buf->base = malloc(suggested_size);
    buf->len  = suggested_size;
}

void on_tty_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    (void)stream;
    if (nread > 0) {
        for (ssize_t i = 0; i < nread; i++) {
            tui_handle_key(&g_tui, buf->base[i]);
            if (!g_tui.running) uv_stop(g_loop);
        }
    }
    if (buf->base) free(buf->base);
}
