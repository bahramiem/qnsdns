/**
 * @file client/session.c
 * @brief Implementation of client-side session management.
 */

#include "session.h"
#include "client_common.h"
#include "../shared/window/sliding.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* Global session table for the client */
static session_t g_client_sessions[DNSTUN_MAX_SESSIONS];

/* Active session tracking for optimized polling */
static uint16_t g_active_sessions[DNSTUN_MAX_SESSIONS];
static uint16_t g_active_session_count = 0;

void session_table_init(void) {
    memset(g_client_sessions, 0, sizeof(g_client_sessions));
    memset(g_active_sessions, 0, sizeof(g_active_sessions));
    g_active_session_count = 0;
    for (int i = 0; i < DNSTUN_MAX_SESSIONS; i++) {
        g_client_sessions[i].closed = true;
    }
    LOG_INFO("Session Table initialized: %d slots\n", DNSTUN_MAX_SESSIONS);
}

int session_alloc(void) {
    for (int i = 0; i < DNSTUN_MAX_SESSIONS; i++) {
        if (g_client_sessions[i].closed) {
            memset(&g_client_sessions[i], 0, sizeof(session_t));
            g_client_sessions[i].established = true;
            g_client_sessions[i].closed = false;
            g_client_sessions[i].last_active = time(NULL);
            
            /* Initialize the modular reorder buffer */
            qns_reorder_init(&g_client_sessions[i].reorder_buf);
            
            /* Track active session */
            if (g_active_session_count < DNSTUN_MAX_SESSIONS) {
                g_active_sessions[g_active_session_count++] = i;
            }
            
            if (g_client_stats) g_client_stats->active_sessions++;
            return i;
        }
    }
    return -1;
}

session_t* session_get(int idx) {
    if (idx < 0 || idx >= DNSTUN_MAX_SESSIONS) return NULL;
    return &g_client_sessions[idx];
}

void session_close(int idx) {
    if (idx < 0 || idx >= DNSTUN_MAX_SESSIONS) return;
    session_t *s = &g_client_sessions[idx];
    if (s->closed) return;
    
    if (s->send_buf) free(s->send_buf);
    if (s->recv_buf) free(s->recv_buf);
    
    /* Cleanup reorder buffer */
    qns_reorder_free(&s->reorder_buf);
    
    s->closed = true;
    s->established = false;
    
    /* Remove from active session tracking */
    for (uint16_t i = 0; i < g_active_session_count; i++) {
        if (g_active_sessions[i] == idx) {
            // Shift remaining elements left
            for (uint16_t j = i; j < g_active_session_count - 1; j++) {
                g_active_sessions[j] = g_active_sessions[j + 1];
            }
            g_active_session_count--;
            break;
        }
    }
    
    if (g_client_stats && g_client_stats->active_sessions > 0) {
        g_client_stats->active_sessions--;
    }
    
    LOG_INFO("Sess %d (ID %u) closed\n", idx, s->session_id);
}

uint8_t session_get_unused_id(void) {
    /* Randomly probe for an unused wire ID */
    for (int i = 0; i < 256; i++) {
        uint8_t sid = (uint8_t)(rand() % 256);
        bool in_use = false;
        for (int j = 0; j < DNSTUN_MAX_SESSIONS; j++) {
            if (!g_client_sessions[j].closed && g_client_sessions[j].session_id == sid) {
                in_use = true;
                break;
            }
        }
        if (!in_use) return sid;
    }
    return 0; /* Fallback (should not happen) */
}

int session_find_by_wire_id(uint8_t wire_id) {
    for (int i = 0; i < DNSTUN_MAX_SESSIONS; i++) {
        if (!g_client_sessions[i].closed && g_client_sessions[i].session_id == wire_id) {
            return i;
        }
    }
    return -1;
}

void session_tick_idle(int timeout_sec) {
    time_t now = time(NULL);
    for (int i = 0; i < DNSTUN_MAX_SESSIONS; i++) {
        if (!g_client_sessions[i].closed && (now - g_client_sessions[i].last_active > timeout_sec)) {
            LOG_INFO("Sess %d (ID %u) idle cleanup\n", i, g_client_sessions[i].session_id);
            session_close(i);
        }
    }
}

/**
 * @brief Get the number of active sessions.
 * @return Number of currently active sessions.
 */
int session_get_active_count(void) {
    return g_active_session_count;
}

/**
 * @brief Get the first active session index.
 * @param start_idx Index to start searching from.
 * @return Next active session index or -1 if none found.
 */
int session_get_next_active(int start_idx) {
    if (start_idx < 0 || start_idx >= g_active_session_count) {
        return -1;
    }
    return g_active_sessions[start_idx];
}
