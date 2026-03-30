/**
 * @file server/swarm.h
 * @brief functional resolver tracking and persistence.
 *
 * Example Usage:
 * @code
 *   swarm_init("server.ini", &g_cfg);
 *   swarm_record_ip("8.8.8.8");
 *   char list[1024];
 *   swarm_get_list_text(list, sizeof(list));
 *   swarm_shutdown();
 * @endcode
 */

#ifndef QNS_SERVER_SWARM_H
#define QNS_SERVER_SWARM_H

#include <stdint.h>
#include <stdbool.h>
#include "../shared/config.h"

/**
 * @brief Initialize the swarm database.
 * @param config_path Path used to determine where to save/load resolvers.
 * @param cfg Pointer to global config for disk-save preference.
 */
void swarm_init(const char *config_path, dnstun_config_t *cfg);

/**
 * @brief Record a functional resolver IP address.
 * @param ip IPv4 string.
 */
void swarm_record_ip(const char *ip);

/**
 * @brief Get the current count of known resolvers.
 */
int swarm_get_count(void);

/**
 * @brief Build a comma-separated list of swarm IPs for SYNC replies.
 * @param out Output buffer.
 * @param out_size Size of output buffer.
 * @return Number of bytes written.
 */
size_t swarm_get_list_text(char *out, size_t out_size);

/**
 * @brief Shutdown and save swarm if configured.
 */
void swarm_shutdown(void);

#endif /* QNS_SERVER_SWARM_H */
