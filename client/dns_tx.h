/**
 * @file client/dns_tx.h
 * @brief DNS query construction and transmission logic.
 *
 * Example Usage:
 * @code
 *   uint8_t buf[512]; size_t len = 512;
 *   dns_tx_build_query(buf, &len, &hdr, payload, paylen, "tun.example.com");
 * @endcode
 */

#ifndef QNS_CLIENT_DNS_TX_H
#define QNS_CLIENT_DNS_TX_H

#include <stdint.h>
#include <stdbool.h>
#include "../shared/types.h"

/**
 * @brief Build a DNS TXT query with Base32 payload and dotification.
 * 
 * @param outbuf Output buffer for DNS packet.
 * @param outlen [in/out] Size of output buffer.
 * @param hdr Chunk header to include in payload.
 * @param payload Binary data to include.
 * @param paylen Length of payload data.
 * @param domain DNS domain suffix (e.g. "tun.example.com").
 * @return 0 on success, -1 on failure.
 */
int dns_tx_build_query(uint8_t *outbuf, size_t *outlen,
                        const chunk_header_t *hdr,
                        const uint8_t *payload, size_t paylen,
                        const char *domain);

/**
 * @brief Send a raw session poll (downstream fetch) to the server.
 * @param session_idx Client session index.
 */
void dns_tx_send_poll(int session_idx);

/**
 * @brief Send a handshake packet (MTU probe) to establish session parameters.
 * @param session_idx Client session index.
 */
void dns_tx_send_handshake(int session_idx);

#endif /* QNS_CLIENT_DNS_TX_H */
