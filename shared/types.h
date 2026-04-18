#pragma once
#ifndef DNSTUN_TYPES_H
#define DNSTUN_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include "shared/codec.h"

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
#define DNSTUN_MAX_SESSIONS      256    /* 8-bit session ID: 0-255 */
#define DNSTUN_MAX_DOMAINS       32
#define DNSTUN_MAX_LABEL_LEN     63
#define DNSTUN_MAX_QNAME_LEN     253

/* Buffer sizes for downstream MTU
 * DEFAULT: 320 for DNS TXT compatibility (ensures total response < 512 bytes)
 * Server will use this unless client reports different preference via handshake */
#define DNSTUN_MAX_DOWNSTREAM_MTU   220    /* Maximally compatible default for DNS TXT */
#define DNSTUN_SERVER_BUFFER_SIZE   65536  /* 64KB */
#define DNSTUN_CLIENT_BUFFER_SIZE   65536  /* 64KB */

/* max payload bytes per DNS query
 * With new 5-byte header and base32 encoding:
 * - chunk_header_t (5 bytes)
 * - base32 encoding overhead (~1.6x)
 * - QNAME prefix (~22 bytes)
 * - base32 dotify overhead
 * Reduced to 110 to keep total QNAME < 253 even with longer domains. */
#define DNSTUN_CHUNK_PAYLOAD     110    /* max base32 payload bytes per DNS query */
#define DNSTUN_SESSION_ID_LEN    8
#define DNSTUN_VERSION           1

/* Downstream encoding types (for server → client) */
#define DNSTUN_ENC_BASE64       0      /* Default */
#define DNSTUN_ENC_HEX          1

#define DNSTUN_DEBUG_PREFIX "PROTO_TEST_"      /* Prefix for protocol loop test (matches 't'/'T' key) */

/* ──────────────────────────────────────────────
   Client Capability Header (prepended to every query)
   This tells the server the client's capabilities for this resolver path.
   Format: version(1) + upstream_mtu(2) + downstream_mtu(2) + encoding(1) + loss_pct(1)
   Total: 7 bytes
────────────────────────────────────────────── */
#pragma pack(push, 1)
typedef struct {
    uint8_t  version;         /* DNSTUN_VERSION */
    uint16_t upstream_mtu;    /* Client's upstream MTU for this resolver */
    uint16_t downstream_mtu;  /* Client's downstream MTU for this resolver */
    uint8_t  encoding;        /* DNSTUN_ENC_BASE64 or DNSTUN_ENC_HEX */
    uint8_t  loss_pct;       /* Observed loss rate (0-100) */
    uint16_t ack_seq;        /* The sequence number the client is expecting next (Downstream ACK) */
} capability_header_t;
#pragma pack(pop)

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
    uint16_t           upstream_mtu;   /* max query payload bytes (capped) */
    uint16_t           downstream_mtu; /* max TXT response bytes (capped) */
    uint16_t           true_upstream_mtu;   /* max query payload bytes (uncapped, for TUI) */
    uint16_t           true_downstream_mtu; /* max TXT response bytes (uncapped, for TUI) */
    bool               edns0_supported;

    /* RTT */
    double             rtt_ms;         /* last measured round-trip */
    double             rtt_baseline;   /* EWMA baseline */

    /* Rate / congestion */
    double             max_qps;        /* burst-test determined max QPS */
    double             cwnd;           /* AIMD congestion window */
    double             cwnd_max;       /* config-capped ceiling */
    uint64_t           last_query_ms;  /* Per-resolver rate-limit timestamp (ms) */

    /* Loss */
    double             loss_rate;      /* EWMA 0.0–1.0 */
    uint32_t           fec_k;          /* current FEC redundancy ratio */
    int                fail_count;     /* consecutive failures for death threshold */

    /* Penalty box */
    double             cooldown_ms;    /* measured recovery duration */
    time_t             penalty_until;  /* unix epoch deadline */

    /* Background recovery */
    time_t             last_probe;

    bool               mtu_verified;   /* true if binary search successfully found an optimal value */

    /* Swarm */
    bool               from_swarm;     /* added by server swarm sync */

    /* Scanner.py style test results */
    char               fail_reason[64]; /* Reason for failure in resolver testing */
} resolver_t;

/* ──────────────────────────────────────────────
   Ultra-Compact DNS Tunnel chunk header (5 bytes)
    Used for upstream: Client → Server (Base32 in QNAME)
    FEC parameters (K, N) are negotiated during handshake.
    Layout: session_id(1) + flags(1) + seq(2) + esi(1)
  ────────────────────────────────────────────── */
#pragma pack(push, 1)
typedef struct {
    uint8_t  sid;            /* full 8-bit session ID (0 - 255) */
    uint8_t  flags;          /* full 8-bit flags (includes CHUNK_FLAG_IS_TUNNEL) */
    uint16_t seq;            /* burst id / sequence number (2 bytes) */
} query_header_t;            /* Common Query Header: 4 bytes */
#pragma pack(pop)

/* Helper defines for compatibility and clarity */
typedef query_header_t chunk_header_t; 

/* ──────────────────────────────────────────────
   Server response header (4 bytes)
   Used for downstream: Server → Client (Base64/Hex in TXT)
   Added sequence number for out-of-order packet handling
────────────────────────────────────────────── */
#pragma pack(push, 1)
typedef struct {
    uint8_t  session_id;     /* 8-bit session ID (0-255) */
    uint8_t  flags;          /* bit 0: encoding_type (0=base64, 1=hex)
                              * bit 1: has_sequence (1 = seq field is valid)
                              * bit 2: compression (1 = payload is compressed)
                              * bits 3-7: reserved */
    uint16_t seq;            /* sequence number (2 bytes) */
    uint16_t ack_seq;        /* cumulative ACK: next expected upstream seq (2 bytes) */
} server_response_header_t;   /* Total: 6 bytes */
#pragma pack(pop)

/* Flag bit masks for server_response_header_t */
#define RESP_ENC_MASK        0x01  /* 0=base64, 1=hex */
#define RESP_FLAG_HAS_SEQ    0x02  /* 1 = seq field is valid (downstream sequencing) */
#define RESP_FLAG_COMPRESSED 0x04  /* 1 = payload is compressed */
#define RESP_FLAG_MORE_DATA  0x08  /* 1 = server has more data pending in its buffer */

/* ──────────────────────────────────────────────
   Downstream Reordering Buffer
   Used for handling out-of-order packets on downstream
────────────────────────────────────────────── */
#define RX_REORDER_WINDOW    128    /* Number of slots in reorder buffer */

/* Single slot in the reorder buffer */
typedef struct {
    uint8_t  *data;          /* Buffered packet data (allocated) */
    size_t    len;           /* Data length */
    uint16_t  seq;           /* Sequence number */
    time_t    received_at;   /* Timestamp for expiry */
    bool      valid;         /* Slot occupied */
} rx_buffer_slot_t;

/* Reorder buffer for a session */
typedef struct {
    rx_buffer_slot_t slots[RX_REORDER_WINDOW];
    uint16_t         expected_seq;  /* Next expected sequence number */
} reorder_buffer_t;

/* ──────────────────────────────────────────────
   Handshake packet (5 bytes)
   Sent once per resolver: Client → Server
   Contains version and MTU info
────────────────────────────────────────────── */
#pragma pack(push, 1)
typedef struct {
    uint8_t  version;        /* protocol version */
    uint16_t upstream_mtu;   /* client's upstream MTU override */
    uint16_t downstream_mtu; /* requested downstream MTU */
    uint16_t fec_k;          /* Negotiated source symbols (K) */
    uint16_t fec_n;          /* Negotiated total symbols (N) */
    uint16_t symbol_size;    /* Negotiated granular symbol size T */
    uint8_t  encoding;       /* Handshake encoding pref (base64/hex) */
    uint8_t  loss_pct;       /* Estimated loss pct */
} handshake_packet_t;        /* Total: 13 bytes */
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
#define CHUNK_FLAG_HANDSHAKE  0x10  /* New Handshake flag */
#define CHUNK_FLAG_IS_TUNNEL  0x80  /* Mandatory bit for all tunnel packets */

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
static inline uint8_t chunk_get_session_id(const chunk_header_t *hdr) {
    return hdr->sid;
}

static inline void chunk_set_session_id(chunk_header_t *hdr, uint8_t sid) {
    hdr->sid = sid;
}

/* Extended 32-bit chunk_info format (header now 20 bytes total):
 * bits 0-7: esi (Encoding Symbol ID: 0 to N-1)
 * bits 8-15: fec_k (Source symbols count: K)
 * bits 16-31: chunk_total - 1 (Total symbols: N)
 */
static inline uint8_t chunk_get_esi(uint32_t chunk_info) {
    return (uint8_t)(chunk_info & 0xFF);
}

static inline uint16_t chunk_get_chunk_total(uint32_t chunk_info) {
    return (uint16_t)(((chunk_info >> 16) & 0xFFFF) + 1);
}

/* Alias for chunk_get_chunk_total */
#define chunk_get_total(chunk_info) chunk_get_chunk_total(chunk_info)

static inline uint8_t chunk_get_fec_k(uint32_t chunk_info) {
    return (uint8_t)((chunk_info >> 8) & 0xFF);
}

static inline void chunk_set_info(uint32_t *ci, uint16_t total, uint8_t k, uint8_t esi) {
    (void)ci; (void)total; (void)k; (void)esi;
    /* [DEPRECATED] Handshake now handles static FEC params; headers use direct ESI field. */
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
   FEC Burst Reassembly State (Server only)
────────────────────────────────────────────── */
#define SRV_MAX_FEC_SLOTS     32     /* Concurrent bursts per session */
#define FEC_BURST_TIMEOUT_SEC 10     /* Evict bursts older than 10s */

typedef struct {
    uint16_t  burst_id;         /* Sequence number (identifies the burst) */
    int       count_needed;     /* Total symbols in burst (N) */
    int       count_received;   /* Symbols received so far */
    uint8_t **symbols;          /* Array of received symbols [count_needed] */
    size_t    symbol_len;       /* Length of each symbol */
    uint64_t  oti_common;       /* FEC decoder info */
    uint32_t  oti_scheme;       /* FEC decoder info */
    bool      has_oti;          /* True if OTI was sent in header */
    bool      decoded;          /* True once successfully decoded */
    time_t    last_active;      /* Timestamp for eviction logic */
    bool      used;             /* True if this slot is active */
} fec_burst_t;

/* ──────────────────────────────────────────────
   Active SOCKS5 session
────────────────────────────────────────────── */
/* Resource limits to prevent memory exhaustion (10MB max per session buffer) */
#define MAX_SESSION_BUFFER (10 * 1024 * 1024)

typedef struct session {
    uint8_t   session_id;    /* 8-bit session ID (0-255) */
    char      target_host[256];
    uint16_t  target_port;
    bool      established;      /* true if SOCKS5 session is active */
    bool      socks5_connected; /* true once SOCKS5 success/handshake done */
    bool      fec_synced;       /* True once handshake echoed back by server */
    bool      fast_poll;        /* Server signaled 'MORE_DATA' flag */
    bool      socks5_pending_ok; /* True if server is ready but waiting for FEC sync */
    time_t    last_handshake; /* Timestamp of last handshake attempt */

    /* Partial burst tracking (Resume logic) */
    uint16_t  tx_burst_esi;     /* Next ESI to send in current burst */
    uint16_t  tx_burst_total;   /* Total symbols needed for current burst */

    /* send/recv ring buffers */
    uint8_t  *send_buf;
    size_t    send_len;
    size_t    send_cap;

    uint8_t  *recv_buf;
    size_t    recv_len;
    size_t    recv_cap;

    /* Persistent FEC Stage */
    fec_encoded_t tx_fec;    /* Current burst symbols */
    bool          tx_fec_active;
    size_t        tx_fec_len;  /* encoded byte count for the current burst */

    /* Handshake-negotiated parameters */
    uint16_t  cl_fec_k;
    uint16_t  cl_fec_n;
    uint16_t  cl_symbol_size;
    uint8_t   cl_loss_pct;
    char      user_id[16];

    /* sliding window / reliability */
    uint16_t  tx_next;    /* next seq to send */
    uint16_t  tx_acked;   /* server's next expected seq (everything < tx_acked is confirmed) */
    uint32_t  tx_offset_map[256]; /* map seq % 256 to send_buf cumulative offset at start of burst */
    uint16_t  rx_next;    /* next expected receive seq from server */

    time_t    last_active;
    time_t    last_ack_time; /* time when tx_acked last advanced */
    bool      closed;
    
    /* Client-specific: SOCKS5 handshake state */
    bool      status_consumed;   /* true once server status byte is stripped */
    bool      first_seq_received; /* true once first seq=0 response received (used to clear stale buffer) */
    
    /* Client-specific: back-pointer to SOCKS5 client (client only) */
    void      *client_ptr;
    
    /* Downstream reordering buffer (for handling out-of-order responses) */
    reorder_buffer_t reorder_buf;
} session_t;

#endif /* DNSTUN_TYPES_H */
