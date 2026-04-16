/**
 * @file client/dns/query.h
 * @brief DNS Query Building and Reply Handling (Client Side)
 *
 * This module handles all DNS protocol work on the client side:
 *   - Building TXT queries that encode tunnel data into the QNAME via Base32.
 *   - Receiving TXT replies from resolvers and routing payload to sessions.
 *   - Firing DNS queries (fire_dns_chunk_symbol) and managing jitter.
 *   - Sending MTU handshake packets to the server.
 *
 * Example usage:
 *   // Build and send one FEC data chunk:
 *   fire_dns_chunk_symbol(session_idx, seq, payload, paylen, total, oti_c, oti_s);
 *
 *   // On a new SOCKS5 connection:
 *   send_mtu_handshake(session_idx);
 */

#ifndef CLIENT_DNS_QUERY_H
#define CLIENT_DNS_QUERY_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "uv.h"
#include "shared/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Inline dotify — inserts a '.' every 57 characters for DNS label splitting.
 *
 * DNS labels are limited to 63 characters each. Base32-encoded data must be
 * split into labels before being used as a QNAME. This function transforms an
 * already-encoded string in-place by inserting dots every 57 characters.
 *
 * @param buf     Buffer containing the Base32 string (modified in place).
 * @param buflen  Maximum capacity of @p buf (must have room for the dots).
 * @param len     Current length of the data in @p buf (without null terminator).
 * @return New length after dots inserted, or (size_t)-1 on overflow.
 */
size_t inline_dotify(char *buf, size_t buflen, size_t len);

/**
 * @brief Build a raw DNS TXT query packet encoding a tunnel chunk.
 *
 * Encodes `hdr` + `payload` as Base32, inserts dots every 57 chars, then
 * builds a full DNS query with EDNS0 OPT record.
 *
 * @param outbuf   Output buffer for the raw UDP packet.
 * @param outlen   In: buffer capacity. Out: actual bytes written.
 * @param hdr      Chunk header to encode.
 * @param payload  Tunnel payload to encode (may be NULL for poll).
 * @param paylen   Length of payload.
 * @param domain   Tunnel domain suffix (e.g. "tun.example.com").
 * @return 0 on success, -1 on QNAME too long or encode error.
 */
int build_dns_query(uint8_t *outbuf, size_t *outlen,
                     const chunk_header_t *hdr,
                     const uint8_t *payload, size_t paylen,
                     const char *domain);

/**
 * @brief Fire one DNS TXT query for the given session and FEC symbol.
 *
 * Selects a resolver from the pool (falling back to dead resolvers if needed),
 * builds the DNS query packet, and sends it via UDP with an 8-second timeout.
 *
 * @param session_idx    Client session index.
 * @param seq            Upstream sequence number for this symbol.
 * @param payload        FEC symbol data (NULL for poll queries).
 * @param paylen         Symbol data length.
 * @param total_symbols  Total FEC symbols in this burst (0 = non-FEC).
 * @param oti_common     RaptorQ OTI common field (0 if not FEC).
 * @param oti_scheme     RaptorQ OTI scheme field (0 if not FEC).
 */
void fire_dns_chunk_symbol(int session_idx, uint16_t seq,
                            const uint8_t *payload, size_t paylen,
                            int total_symbols,
                            uint64_t oti_common, uint32_t oti_scheme);

/**
 * @brief Send an MTU handshake to the server for the given session.
 *
 * Sends a 5-byte capability packet: version(1) + upstream_mtu(2) + downstream_mtu(2).
 * The server detects it by: payload_len==5 && payload[0]==DNSTUN_VERSION.
 */
void send_mtu_handshake(int session_idx);

#ifdef __cplusplus
}
#endif

#endif /* CLIENT_DNS_QUERY_H */
