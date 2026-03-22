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
#define DNSTUN_MAX_SESSIONS      1024
#define DNSTUN_MAX_DOMAINS       32
#define DNSTUN_MAX_LABEL_LEN     63
#define DNSTUN_MAX_QNAME_LEN     253
#define DNSTUN_CHUNK_PAYLOAD     160   /* max base32 payload bytes per DNS label block */
#define DNSTUN_SESSION_ID_LEN    4
#define DNSTUN_VERSION           1

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
    enc_format_t       enc;

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
} resolver_t;

/* ──────────────────────────────────────────────
   DNS Tunnel chunk header (embedded in QNAME)
────────────────────────────────────────────── */
#pragma pack(push, 1)
typedef struct {
    uint8_t  version;        /* protocol version */
    uint8_t  flags;          /* bit0=encrypted, bit1=compressed, bit2=fec, bit3=poll */
    uint8_t  session_id[DNSTUN_SESSION_ID_LEN];
    uint16_t seq;            /* sequence number */
    uint16_t chunk_total;    /* total chunks in this burst */
    uint16_t original_size;  /* size before compression */
    uint16_t upstream_mtu;   /* client's upstream MTU */
    uint16_t downstream_mtu; /* client-requested downstream MTU */
    uint8_t  enc_format;     /* enc_format_t */
    uint8_t  loss_pct;       /* loss rate 0-100 */
    uint8_t  fec_k;          /* FEC redundancy count */
    char     user_id[12];    /* User ID */
    uint8_t  reserved;
} chunk_header_t;
#pragma pack(pop)

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
   Active SOCKS5 session
────────────────────────────────────────────── */
typedef struct session {
    uint8_t   id[DNSTUN_SESSION_ID_LEN];
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
} session_t;

#endif /* DNSTUN_TYPES_H */
