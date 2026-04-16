/**
 * @file server/swarm/swarm.c
 * @brief Resolver Swarm IP Database Implementation
 *
 * Tracks all resolver IPs that have queried the server. Stores them in an
 * in-memory array and optionally persists them to a file.
 *
 * Thread safety: all public functions lock g_swarm_lock before accessing state.
 *
 * Example usage:
 *   // On server startup:
 *   uv_mutex_init(&g_swarm_lock);
 *   swarm_load();
 *
 *   // On every incoming query:
 *   swarm_record_ip(src_ip);
 *
 *   // Periodically:
 *   swarm_save();
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "uv.h"

#include "server/swarm/swarm.h"

/* ── Module-level state ── */
char g_swarm_ips[SWARM_MAX][46];
int  g_swarm_count = 0;
char g_swarm_file[1024] = {0};

/* Lock is defined extern in main.c and initialized there. */
extern uv_mutex_t g_swarm_lock;

/* Logging helper — routes to the same LOG_INFO used in main. */
extern void srv_log_info(const char *fmt, ...);

/* ── Implementation ── */

void swarm_record_ip(const char *ip) {
    uv_mutex_lock(&g_swarm_lock);
    for (int i = 0; i < g_swarm_count; i++) {
        if (strcmp(g_swarm_ips[i], ip) == 0) {
            uv_mutex_unlock(&g_swarm_lock);
            return;
        }
    }
    if (g_swarm_count < SWARM_MAX) {
        strncpy(g_swarm_ips[g_swarm_count++], ip, 45);
        /* Log after unlock to avoid holding lock during IO */
    }
    uv_mutex_unlock(&g_swarm_lock);
}

void swarm_save(void) {
    if (!g_swarm_file[0]) return;
    FILE *f = fopen(g_swarm_file, "w");
    if (!f) return;
    uv_mutex_lock(&g_swarm_lock);
    for (int i = 0; i < g_swarm_count; i++)
        fprintf(f, "%s\n", g_swarm_ips[i]);
    uv_mutex_unlock(&g_swarm_lock);
    fclose(f);
}

void swarm_load(void) {
    if (!g_swarm_file[0]) return;
    FILE *f = fopen(g_swarm_file, "r");
    if (!f) return;
    char ip[64];
    while (fgets(ip, sizeof(ip), f)) {
        /* Trim trailing newline */
        ip[strcspn(ip, "\r\n")] = '\0';
        if (ip[0])
            swarm_record_ip(ip);
    }
    fclose(f);
}

size_t swarm_build_sync_text(char *out, size_t out_cap) {
    size_t slen = 0;
    uv_mutex_lock(&g_swarm_lock);
    for (int i = 0; i < g_swarm_count && slen < out_cap - 48; i++) {
        slen += (size_t)snprintf(out + slen, out_cap - slen, "%s,", g_swarm_ips[i]);
    }
    uv_mutex_unlock(&g_swarm_lock);
    return slen;
}
