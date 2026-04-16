/**
 * @file server/swarm/swarm.h
 * @brief Resolver Swarm IP Database — Server-Side
 *
 * The "swarm" is the set of all DNS resolver IPs that have ever sent a query
 * to this server. When a client sends a SYNC command, the server replies with
 * the full swarm list so the client can discover more working resolvers.
 *
 * Example usage:
 *   // Record an IP when a query arrives from it:
 *   swarm_record_ip("1.2.3.4");
 *
 *   // Save swarm to disk and reload on restart:
 *   swarm_save();
 *   swarm_load();
 */

#ifndef SERVER_SWARM_H
#define SERVER_SWARM_H

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum number of IPs the swarm can track */
#define SWARM_MAX 16384

/* ── Swarm state (extern — defined in swarm.c, referenced by main.c) ── */
extern char g_swarm_ips[SWARM_MAX][46];
extern int  g_swarm_count;

/** Path to the file where swarm IPs are persisted across restarts. */
extern char g_swarm_file[1024];

/**
 * @brief Record a new resolver IP in the swarm database.
 *
 * Thread-safe. Duplicates are ignored. Does nothing if the swarm is full.
 *
 * @param ip  Null-terminated IPv4 or IPv6 address string (max 45 chars).
 */
void swarm_record_ip(const char *ip);

/**
 * @brief Save the current swarm IP list to g_swarm_file.
 *
 * No-op if g_swarm_file is empty.
 */
void swarm_save(void);

/**
 * @brief Load swarm IPs from g_swarm_file into the in-memory database.
 *
 * No-op if g_swarm_file is empty or the file does not exist.
 */
void swarm_load(void);

/**
 * @brief Build the swarm text string for a SYNC response.
 *
 * Writes comma-separated IPs into @p out (max @p out_cap bytes).
 * Returns the number of bytes written (not including the null terminator).
 *
 * @param out      Output buffer.
 * @param out_cap  Size of output buffer.
 * @return         Number of bytes written.
 */
size_t swarm_build_sync_text(char *out, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif /* SERVER_SWARM_H */
