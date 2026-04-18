#pragma once
#ifndef DNSTUN_CONSTANTS_H
#define DNSTUN_CONSTANTS_H

/* ──────────────────────────────────────────────
   Constants
   Moved from types.h to break circular dependencies
────────────────────────────────────────────── */
#define DNSTUN_MAX_RESOLVERS     4096
#define DNSTUN_MAX_SESSIONS      256    /* 8-bit session ID: 0-255 */
#define DNSTUN_MAX_DOMAINS       32
#define DNSTUN_MAX_LABEL_LEN     63
#define DNSTUN_MAX_QNAME_LEN     253

#define DNSTUN_MAX_DOWNSTREAM_MTU   220    /* Maximally compatible default for DNS TXT */
#define DNSTUN_SERVER_BUFFER_SIZE   65536  /* 64KB */
#define DNSTUN_CLIENT_BUFFER_SIZE   65536  /* 64KB */

#define DNSTUN_CHUNK_PAYLOAD     110    /* max base32 payload bytes per DNS query */
#define DNSTUN_SESSION_ID_LEN    8
#define DNSTUN_VERSION           1

/* Downstream encoding types (for server → client) */
#define DNSTUN_ENC_BASE64       0      /* Default */
#define DNSTUN_ENC_HEX          1

#define DNSTUN_DEBUG_PREFIX "PROTO_TEST_"

/* ──────────────────────────────────────────────
   Enums
────────────────────────────────────────────── */

typedef enum {
    RSV_ACTIVE   = 0,   /* healthy, in round-robin */
    RSV_PENALTY  = 1,   /* rate-limited, in cooldown */
    RSV_DEAD     = 2,   /* failed all tests */
    RSV_ZOMBIE   = 3,   /* intercepting / poisoned */
    RSV_TESTING  = 4    /* currently being benchmarked */
} resolver_state_t;

typedef enum {
    ENC_BINARY = 0,
    ENC_BASE64 = 1
} enc_format_t;

typedef enum {
    CIPHER_NONE       = 0,
    CIPHER_CHACHA20   = 1,
    CIPHER_AES256GCM  = 2,
    CIPHER_NOISE_NK   = 3
} cipher_t;

typedef enum {
    TRANSPORT_UDP  = 0,  /* raw UDP port 53 */
    TRANSPORT_DOH  = 1,  /* DNS-over-HTTPS port 443 */
    TRANSPORT_DOT  = 2   /* DNS-over-TLS  port 853 */
} transport_t;

#endif /* DNSTUN_CONSTANTS_H */
