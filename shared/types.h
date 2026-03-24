#pragma once
#ifndef DNSTUN_TYPES_H
#define DNSTUN_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <netinet/in.h>
#  include <arpa/inet.h>
#endif

/* ──────────────────────────────────────────────
   Constants
────────────────────────────────────────────── */
#define DNSTUN_MAX_RESOLVERS     4096
#define DNSTUN_MAX_SESSIONS      16     /* 4-bit session ID: 0-15 */
#define DNSTUN_MAX_DOMAINS       32
#define DNSTUN_MAX_LABEL_LEN     63
#define DNSTUN_MAX_QNAME_LEN     253

/* Buffer sizes for downstream MTU
 * Default to 512 for DNS TXT compatibility (many resolvers drop >512 byte responses)
 * Server will use this unless client reports different preference via handshake */
#define DNSTUN_MAX_DOWNSTREAM_MTU   512    /* Conservative default for DNS TXT */
#define DNSTUN_SERVER_BUFFER_SIZE   65536  /* 64KB */
#define DNSTUN_CLIENT_BUFFER_SIZE   65536  /* 64KB */

/* max payload bytes per DNS query
 * With new 4-byte header and base32 encoding:
 * - chunk_header_t (4 bytes)
 * - base32 encoding overhead (4 * 8/5 = 7 bytes)
 * - QNAME prefix (~22 bytes)
 * - base32 dotify overhead
 * Safe max payload ≈ 137 bytes */
#define DNSTUN_CHUNK_PAYLOAD     137    /* max base32 payload bytes per DNS query */
#define DNSTUN_SESSION_ID_LEN    4
#define DNSTUN_VERSION           1

/* Downstream encoding types (for server → client) */
#define DNSTUN_ENC_BASE64       0      /* Default */
#define DNSTUN_ENC_HEX          1

/* ──────────────────────────────────────────────
   Resolver Health States
────────────────────────────────────────────── */
typedef enum {
    RSV_ACTIVE   = 0,   /* healthy, in round-robin */
    RSV_PENALTY  = 1,   /* rate-limited, in cooldown */
    RSV_DEAD     = 2,   /* failed all tests */
    RSV_ZOMBIE   = 3,   /* intercepting / poisoned */
    RSV_TESTING  = 4    /* currently being benchmarked */
} resolver_state_t;

/* ──────────────────────────────────────────────
   Encoding format discovered per resolver
────────────────────────────────────────────── */
typedef enum {
    ENC_BINARY = 0,
    ENC_BASE64 = 1
} enc_format_t;

/* ──────────────────────────────────────────────
   Cipher suite
────────────────────────────────────────────── */
typedef enum {
    CIPHER_NONE       = 0,
    CIPHER_CHACHA20   = 1,
    CIPHER_AES256GCM  = 2,
    CIPHER_NOISE_NK   = 3
} cipher_t;

/* ──────────────────────────────────────────────
   Transport mode
────────────────────────────────────────────── */
typedef enum {
    TRANSPORT_UDP  = 0,  /* raw UDP port 53 */
    TRANSPORT_DOH  = 1,  /* DNS-over-HTTPS port 443 */
    TRANSPORT_DOT  = 2   /* DNS-over-TLS  port 853 */
} transport_t;

/* ──────────────────────────────────────────────
   Resolver record — all discovered capabilities
────────────────────────────────────────────── */
typedef struct resolver {
    struct sockaddr_in addr;
    char               ip[46];

    resolver_state_t   state;
    enc_format_t      enc;

    /* MTU */
    uint16_t           upstream_mtu;   /* max query payload bytes */
    uint16_t           downstream_mtu; /* max TXT response bytes */
    bool               edns0_supported;

    /* RTT */
    double             rtt_ms;         /* last measured round-trip */
    double             rtt_baseline;   /* EWMA baseline */

    /* Rate / congestion */
    double             max_qps;        /* burst-test determined max QPS */
    double             cwnd;           /* AIMD congestion window */
    double             cwnd_max;       /* config-capped ceiling */

    /* Loss */
    double             loss_rate;      /* EWMA 0.0–1.0 */
    uint32_t           fec_k;          /* current FEC redundancy ratio */

    /* Penalty box */
    double             cooldown_ms;    /* measured recovery duration */
    time_t             penalty_until;  /* unix epoch deadline */

    /* Background recovery */
    time_t             last_probe;

    /* Swarm */
    bool               from_swarm;     /* added by server swarm sync */

    /* Scanner.py style test results */
    char               fail_reason[64]; /* Reason for failure in resolver testing */
} resolver_t;

/* ──────────────────────────────────────────────
   New Compact DNS Tunnel chunk header (4 bytes)
   Used for upstream: Client → Server (Base32 in QNAME)
────────────────────────────────────────────── */
#pragma pack(push, 1)
typedef struct {
    uint8_t  flags;          /* bits 0-3: flags, bits 4-7: session_id (4 bits = 0-15) */
    uint16_t seq;            /* sequence number (2 bytes) */
    uint8_t  chunk_info;     /* high nibble: chunk_total-1, low nibble: fec_k */
} chunk_header_t;            /* Total: 4 bytes */
#pragma pack(pop)

/* ──────────────────────────────────────────────
   Server response header (2 bytes)
   Used for downstream: Server → Client (Base64/Hex in TXT)
────────────────────────────────────────────── */
#pragma pack(push, 1)
typedef struct {
    uint8_t  flags;          /* bit 0: encoding_type (0=base64, 1=hex), bits 1-7: reserved */
    uint8_t  session_id;     /* session ID (4 bits used, 0-15) */
} server_response_header_t;   /* Total: 2 bytes */
#pragma pack(pop)

/* ──────────────────────────────────────────────
   Handshake packet (5 bytes)
   Sent once per resolver: Client → Server
   Contains version and MTU info
────────────────────────────────────────────── */
#pragma pack(push, 1)
typedef struct {
    uint8_t  version;        /* protocol version */
    uint16_t upstream_mtu;   /* client's upstream MTU */
    uint16_t downstream_mtu; /* requested downstream MTU */
} handshake_packet_t;        /* Total: 5 bytes */
#pragma pack(pop)

/* ──────────────────────────────────────────────
   Resolver MTU info (stored per resolver on server)
────────────────────────────────────────────── */
typedef struct {
    uint32_t ip;             /* resolver IP */
    uint16_t upstream_mtu;    /* stored from handshake */
    uint16_t downstream_mtu; /* stored from handshake */
    uint8_t  version;        /* protocol version */
    bool     handshake_done;  /* true after first contact */
    time_t   handshake_time; /* when handshake occurred */
} resolver_mtu_info_t;

/* Flag bit masks for chunk_header_t */
#define CHUNK_FLAG_ENCRYPTED   0x01
#define CHUNK_FLAG_COMPRESSED  0x02
#define CHUNK_FLAG_FEC        0x04
#define CHUNK_FLAG_POLL       0x08
#define CHUNK_SESSION_MASK    0xF0
#define CHUNK_SESSION_SHIFT   4

/* Flag bit masks for server_response_header_t */
#define RESP_ENC_MASK        0x01  /* 0=base64, 1=hex */

/* ──────────────────────────────────────────────
   [MEDIUM] Variable-Length Encoding (Varint) for Header Compression
   
   For small values (0-127), varints use only 1 byte instead of 2.
   This can compress the 2-byte seq field when values are small.
   
   Varint encoding format (Google Protocol Buffers style):
   - 7 bits per byte contain value
   - MSB indicates if more bytes follow (1 = more, 0 = last)
   - Maximum 10 bytes for 64-bit values
────────────────────────────────────────────── */

/* Encode a 32-bit unsigned integer to varint format
 * Returns number of bytes written (max 5 for 32-bit values)
 * out must have at least 5 bytes space */
static inline int encode_varint32(uint8_t *out, uint32_t value) {
    int i = 0;
    while (value > 0x7F) {
        out[i++] = (uint8_t)((value & 0x7F) | 0x80);
        value >>= 7;
    }
    out[i++] = (uint8_t)(value & 0x7F);
    return i;
}

/* Decode a varint to 32-bit unsigned integer
 * Returns number of bytes consumed, or -1 on error
 * Returns 0 if input is NULL or len is 0 */
static inline int decode_varint32(const uint8_t *in, size_t len, uint32_t *out) {
    uint32_t result = 0;
    int shift = 0;
    int i = 0;
    
    if (!in || len == 0) return 0;
    
    while (i < 5 && i < (int)len) {
        uint8_t b = in[i++];
        result |= ((uint32_t)(b & 0x7F) << shift);
        if ((b & 0x80) == 0) {
            *out = result;
            return i;
        }
        shift += 7;
        if (shift >= 32) return -1;  /* Overflow */
    }
    return -1;  /* Incomplete varint */
}

/* Encode a 16-bit unsigned integer to varint format
 * Returns number of bytes written (max 3 for 16-bit values)
 * out must have at least 3 bytes space */
static inline int encode_varint16(uint8_t *out, uint16_t value) {
    if (value < 0x80) {
        out[0] = (uint8_t)value;
        return 1;
    }
    out[0] = (uint8_t)((value & 0x7F) | 0x80);
    out[1] = (uint8_t)((value >> 7) & 0x7F);
    return 2;
}

/* Decode a varint to 16-bit unsigned integer
 * Returns number of bytes consumed, or -1 on error
 * Returns 0 if input is NULL or len is 0 */
static inline int decode_varint16(const uint8_t *in, size_t len, uint16_t *out) {
    uint32_t val32;
    int bytes = decode_varint32(in, len, &val32);
    if (bytes < 0 || val32 > 0xFFFF) return -1;
    *out = (uint16_t)val32;
    return bytes;
}

/* Inline functions for header manipulation */
static inline uint8_t chunk_get_session_id(uint8_t flags) {
    return (flags & CHUNK_SESSION_MASK) >> CHUNK_SESSION_SHIFT;
}

static inline void chunk_set_session_id(uint8_t *flags, uint8_t sid) {
    *flags = (*flags & ~CHUNK_SESSION_MASK) | ((sid << CHUNK_SESSION_SHIFT) & CHUNK_SESSION_MASK);
}

static inline uint8_t chunk_get_chunk_total(uint8_t chunk_info) {
    return ((chunk_info >> 4) & 0x0F) + 1;
}

/* Alias for chunk_get_chunk_total */
#define chunk_get_total(chunk_info) chunk_get_chunk_total(chunk_info)

static inline uint8_t chunk_get_fec_k(uint8_t chunk_info) {
    return chunk_info & 0x0F;
}

static inline void chunk_set_info(uint8_t *ci, uint8_t total, uint8_t k) {
    *ci = (((total - 1) & 0x0F) << 4) | (k & 0x0F);
}

static inline uint8_t resp_get_encoding(uint8_t flags) {
    return flags & RESP_ENC_MASK;
}

static inline void resp_set_encoding(uint8_t *flags, uint8_t enc) {
    *flags = (*flags & ~RESP_ENC_MASK) | (enc & RESP_ENC_MASK);
}

/* ──────────────────────────────────────────────
   Chunk payload in-flight
────────────────────────────────────────────── */
typedef struct {
    chunk_header_t hdr;
    uint8_t        data[DNSTUN_CHUNK_PAYLOAD];
    size_t         data_len;
    bool           acked;
    time_t         sent_at;
} chunk_t;

/* ──────────────────────────────────────────────
   Packet Aggregation - pack multiple symbols into one packet
   This maximizes payload utilization per transmission
────────────────────────────────────────────── */
#define DNSTUN_SYMBOL_SIZE       64   /* Optimal rateless symbol size (bytes) */
#define DNSTUN_MAX_SYMBOLS_PER_PACKET 16  /* Maximum symbols to aggregate */

/* Aggregated packet - contains multiple symbols for one transmission */
typedef struct {
    chunk_header_t hdr;
    uint8_t        symbols[DNSTUN_MAX_SYMBOLS_PER_PACKET][DNSTUN_SYMBOL_SIZE];
    uint8_t        symbol_count;        /* Number of symbols in this packet */
    uint8_t        symbol_sizes[DNSTUN_MAX_SYMBOLS_PER_PACKET]; /* Actual size per symbol */
    size_t         total_size;         /* Total payload size */
    bool           acked;
    time_t         sent_at;
} agg_packet_t;

/* Symbol encoding state for aggregation */
typedef struct {
    uint8_t   symbol_id;        /* Current symbol ID */
    uint8_t   buffer[DNSTUN_SYMBOL_SIZE]; /* Symbol encoding buffer */
    uint16_t  source_block;     /* Source block number */
    uint8_t   encoding_id;      /* Encoding type (systematic, random, etc.) */
} symbol_encoder_t;

/* ──────────────────────────────────────────────
   Active SOCKS5 session
────────────────────────────────────────────── */
/* Resource limits to prevent memory exhaustion (10MB max per session buffer) */
#define MAX_SESSION_BUFFER (10 * 1024 * 1024)

typedef struct session {
    uint8_t   session_id;    /* 4-bit session ID (0-15), embedded in chunk header */
    char      target_host[256];
    uint16_t  target_port;
    bool      established;

    /* send/recv ring buffers */
    uint8_t  *send_buf;
    size_t    send_len;
    size_t    send_cap;

    uint8_t  *recv_buf;
    size_t    recv_len;
    size_t    recv_cap;

    /* sliding window */
    uint16_t  tx_next;    /* next seq to send */
    uint16_t  tx_acked;   /* last acked seq */
    uint16_t  rx_next;    /* expected receive seq */

    time_t    last_active;
    bool      closed;
    
    /* Client-specific: SOCKS5 handshake state */
    bool      socks5_connected;  /* true once SOCKS5 success sent */
    
    /* Client-specific: back-pointer to SOCKS5 client (client only) */
    void      *client_ptr;
} session_t;

#endif /* DNSTUN_TYPES_H */
