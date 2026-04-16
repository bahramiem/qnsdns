/**
 * @file client/aggregation/packet.h
 * @brief Packet Aggregation for Improved Efficiency
 *
 * Provides logic to pack multiple FEC symbols into single packets based on MTU.
 */

#ifndef CLIENT_AGGREGATION_PACKET_H
#define CLIENT_AGGREGATION_PACKET_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Calculate the maximum number of symbols that can fit in a packet of the given MTU.
 */
int calc_symbols_per_packet(int mtu, int symbol_size);

/**
 * @brief Calculate packing efficiency as a percentage.
 */
double calc_packing_efficiency(int mtu, size_t optimal_size);

/**
 * @brief Encode multiple symbols into a single aggregated packet buffer.
 */
int encode_aggregated_packet(uint8_t *out_buf, size_t out_cap, uint16_t seq,
                             uint8_t *symbols[], uint8_t sizes[], int count);

/**
 * @brief Decode an aggregated packet back into symbols.
 */
int decode_aggregated_packet(uint8_t *symbols[], uint8_t sizes[],
                             const uint8_t *packet, size_t packet_len,
                             int max_symbols);

/**
 * @brief Log current aggregation statistics based on active resolvers.
 */
void log_aggregation_stats(void);

#ifdef __cplusplus
}
#endif

#endif /* CLIENT_AGGREGATION_PACKET_H */
