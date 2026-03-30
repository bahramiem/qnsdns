/**
 * @file server/swarm.c
 * @brief Implementation of functional resolver tracking.
 */

#include "swarm.h"
#include "server_common.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../uv.h"

/* Swarm Database Configuration */
#define SWARM_MAX 16384

/* Local private state — protected by mutex */
static char         g_swarm_ips[SWARM_MAX][46];
static int          g_swarm_count = 0;
static uv_mutex_t   g_swarm_lock;
static char         g_swarm_save_path[1024];
static bool         g_swarm_save_disk = false;

void swarm_init(const char *config_path, dnstun_config_t *cfg) {
    g_swarm_count = 0;
    uv_mutex_init(&g_swarm_lock);
    
    if (cfg) {
        g_swarm_save_disk = cfg->swarm_save_disk;
    }

    /* Set up server swarm file path safely beside config_path */
    if (config_path) {
        strncpy(g_swarm_save_path, config_path, sizeof(g_swarm_save_path) - 1);
        char *slash = strrchr(g_swarm_save_path, '/');
#ifdef _WIN32
        char *bslash = strrchr(g_swarm_save_path, '\\');
        if (bslash > slash) slash = bslash;
#endif
        if (slash) {
            strncpy(slash + 1, "server_resolvers.txt", 
                    sizeof(g_swarm_save_path) - (slash - g_swarm_save_path) - 2);
        } else {
            strcpy(g_swarm_save_path, "server_resolvers.txt");
        }
    } else {
        strcpy(g_swarm_save_path, "server_resolvers.txt");
    }

    /* Load functional resolvers from disk if persistence is enabled */
    if (g_swarm_save_disk) {
        FILE *f = fopen(g_swarm_save_path, "r");
        if (f) {
            char ip[64];
            while (fgets(ip, sizeof(ip), f)) {
                ip[strcspn(ip, "\r\n")] = '\0';
                if (ip[0]) {
                    swarm_record_ip(ip);
                }
            }
            fclose(f);
        }
    }
    
    LOG_INFO("Swarm initialized: path=%s, save_disk=%d, count=%d\n", 
             g_swarm_save_path, g_swarm_save_disk, g_swarm_count);
}

void swarm_record_ip(const char *ip) {
    if (!ip) return;
    
    uv_mutex_lock(&g_swarm_lock);
    
    /* Check for duplicates */
    for (int i = 0; i < g_swarm_count; i++) {
        if (strcmp(g_swarm_ips[i], ip) == 0) {
            uv_mutex_unlock(&g_swarm_lock);
            return;
        }
    }
    
    /* Add new IP to list */
    if (g_swarm_count < SWARM_MAX) {
        strncpy(g_swarm_ips[g_swarm_count++], ip, 45);
        LOG_INFO("Swarm: +%s (%d total)\n", ip, g_swarm_count);
    }
    
    uv_mutex_unlock(&g_swarm_lock);
}

int swarm_get_count(void) {
    int count;
    uv_mutex_lock(&g_swarm_lock);
    count = g_swarm_count;
    uv_mutex_unlock(&g_swarm_lock);
    return count;
}

size_t swarm_get_list_text(char *out, size_t out_size) {
    if (!out || out_size == 0) return 0;
    
    size_t slen = 0;
    uv_mutex_lock(&g_swarm_lock);
    
    /* Build comma-separated list of known functional resolvers */
    for (int i = 0; i < g_swarm_count && slen < out_size - 48; i++) {
        slen += (size_t)snprintf(out + slen, out_size - slen, "%s,", g_swarm_ips[i]);
    }
    
    uv_mutex_unlock(&g_swarm_lock);
    return slen;
}

void swarm_shutdown(void) {
    /* Persistent save to disk */
    if (g_swarm_save_disk && g_swarm_save_path[0]) {
        FILE *f = fopen(g_swarm_save_path, "w");
        if (f) {
            uv_mutex_lock(&g_swarm_lock);
            for (int i = 0; i < g_swarm_count; i++) {
                fprintf(f, "%s\n", g_swarm_ips[i]);
            }
            uv_mutex_unlock(&g_swarm_lock);
            fclose(f);
            LOG_INFO("Swarm saved to %s\n", g_swarm_save_path);
        }
    }
    
    uv_mutex_destroy(&g_swarm_lock);
}
