/**
 * @file client/debug/packet.h
 * @brief Simple Debug/Ping Packet Tester
 *
 * Implements logic for firing special string payloads to trace them
 * through the server and measure basic pipeline latency.
 */

#ifndef CLIENT_DEBUG_PACKET_H
#define CLIENT_DEBUG_PACKET_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Fire a debug packet containing a string.
 */
void fire_debug_packet(const char *msg);

#ifdef __cplusplus
}
#endif

#endif /* CLIENT_DEBUG_PACKET_H */
