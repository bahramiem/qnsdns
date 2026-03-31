#pragma once
#ifndef DNSTUN_ULTRA_CODEC_H
#define DNSTUN_ULTRA_CODEC_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Ultra-Efficient DNS Tunnel Codec - Minimal Overhead Encoding */

/* ────────────────────────────────────────────────────────────── */
/*  Ultra-Compact Header Format (2 bytes)                        */
/* ────────────────────────────────────────────────────────────── */

/*
 * Ultra-Header Format (24 bits total):
 *
 *  23 22 21 20  19 18 17 16  15 14 13 12  11 10  9  8  7  6  5  4  3  2  1  0
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │  SessID   │  Sequence High 4 bits  │           Sequence Low 8 bits          │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                             Flags byte                                     │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * SessID (4 bits): Session ID (0-15 for multiplexing)
 * Sequence (12 bits): Per-session sequence number (0-4095)
 * Flags (8 bits): Lower 4 bits: [Comp][Enc][FEC][Dir] - Compression, Encryption, FEC, Direction
 *                Upper 4 bits: Reserved for future use (must be zero)
 */

typedef struct {
    uint8_t byte0;  /* SessID(4) + Sequence High(4) */
    uint8_t byte1;  /* Sequence Low(8) */
    uint8_t flags;  /* Flags byte */
} ultra_header_t;

/* Header flag bits */
#define ULTRA_FLAG_COMPRESSION    (1 << 3)  /* 0b1000 */
#define ULTRA_FLAG_ENCRYPTION     (1 << 2)  /* 0b0100 */
#define ULTRA_FLAG_FEC           (1 << 1)  /* 0b0010 */
#define ULTRA_FLAG_DIRECTION      (1 << 0)  /* 0b0001 */ /* 0=client->server, 1=server->client */

/* Session ID mask */
#define ULTRA_SESSION_MASK        0xF0      /* Top 4 bits */
#define ULTRA_SESSION_SHIFT       4

/* Sequence number handling */
#define ULTRA_SEQ_HIGH_MASK       0x0F      /* Bottom 4 bits of byte0 */
#define ULTRA_SEQ_LOW_MASK        0xFF      /* All 8 bits of byte1 */

/* ────────────────────────────────────────────────────────────── */
/*  Ultra-Codec Configuration                                     */
/* ────────────────────────────────────────────────────────────── */

typedef struct {
    bool enable_compression;
    bool enable_encryption;
    bool enable_fec;
    int compression_level;      /* 0=none, 1=fast, 2=best */
    const char *psk;           /* Pre-shared key for encryption */
    size_t max_payload_size;    /* Maximum payload per DNS query */
    bool enable_deduplication;  /* Dictionary-based deduplication */
} ultra_codec_config_t;

/* ────────────────────────────────────────────────────────────── */
/*  Ultra-Codec Result                                            */
/* ────────────────────────────────────────────────────────────── */

typedef struct {
    uint8_t *data;
    size_t len;
    bool error;
    uint16_t session_id;
    uint16_t sequence;
    uint8_t flags;
} ultra_codec_result_t;

/* ────────────────────────────────────────────────────────────── */
/*  Deduplication Dictionary                                      */
/* ────────────────────────────────────────────────────────────── */

#define ULTRA_DICT_SIZE 4096
#define ULTRA_DICT_ENTRIES 256

typedef struct {
    uint8_t dictionary[ULTRA_DICT_SIZE];
    uint16_t entries[ULTRA_DICT_ENTRIES];  /* Offset + length pairs */
    size_t dict_used;
    size_t entry_count;
} ultra_dict_t;

/* ────────────────────────────────────────────────────────────── */
/*  API Functions                                                 */
/* ────────────────────────────────────────────────────────────── */

/* Initialize ultra-codec */
int ultra_codec_init(const ultra_codec_config_t *config);

/* Cleanup ultra-codec */
void ultra_codec_cleanup(void);

/* Encode payload with ultra-compact header */
ultra_codec_result_t ultra_codec_encode(const uint8_t *payload, size_t len,
                                       uint16_t session_id, uint16_t sequence,
                                       bool to_server);

/* Decode payload from ultra-compact format */
ultra_codec_result_t ultra_codec_decode(const uint8_t *data, size_t len);

/* Create ultra-header */
bool ultra_header_create(ultra_header_t *header, uint16_t session_id,
                        uint16_t sequence, uint8_t flags);

/* Parse ultra-header */
bool ultra_header_parse(const ultra_header_t *header, uint16_t *session_id,
                       uint16_t *sequence, uint8_t *flags);

/* Binary-to-DNS encoding (no base32 overhead) */
ultra_codec_result_t ultra_dns_encode(const uint8_t *binary, size_t len);

/* DNS-to-binary decoding */
ultra_codec_result_t ultra_dns_decode(const uint8_t *dns_data, size_t len);

/* Dictionary-based deduplication */
ultra_codec_result_t ultra_deduplicate(const uint8_t *data, size_t len);
ultra_codec_result_t ultra_deduplicate_restore(const uint8_t *data, size_t len);

/* Update deduplication dictionary */
void ultra_dict_update(const uint8_t *data, size_t len);

/* Get codec statistics */
typedef struct {
    size_t total_encoded;
    size_t total_decoded;
    double avg_compression_ratio;
    uint32_t dict_hits;
    uint32_t dict_misses;
} ultra_codec_stats_t;

void ultra_codec_get_stats(ultra_codec_stats_t *stats);

#endif /* DNSTUN_ULTRA_CODEC_H */