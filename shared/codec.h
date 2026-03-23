#pragma once
#ifndef DNSTUN_CODEC_H
#define DNSTUN_CODEC_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "config.h"

/* ──────────────────────────────────────────────
   Codec Result
────────────────────────────────────────────── */
typedef struct {
    uint8_t *data;
    size_t   len;
    bool     error;
} codec_result_t;

/* ──────────────────────────────────────────────
   API
────────────────────────────────────────────── */

/* 1. COMPRESS (Zstd)
   Returns compressed data. Must be freed by caller if data != NULL. */
codec_result_t codec_compress(const uint8_t *in, size_t inlen, int level);

/* 2. DECOMPRESS (Zstd) */
codec_result_t codec_decompress(const uint8_t *in, size_t inlen, size_t original_size);

/* 3. ENCRYPT (ChaCha20-Poly1305)
   Prepends 12-byte random nonce. */
codec_result_t codec_encrypt(const uint8_t *in, size_t inlen, const char *psk);

/* 4. DECRYPT (ChaCha20-Poly1305) */
codec_result_t codec_decrypt(const uint8_t *in, size_t inlen, const char *psk);

/* 5. FEC ENCODE (RaptorQ)
   Returns an array of symbols (source + repair).
   k = source symbols count, r = repair symbols count. */
typedef struct {
    uint8_t **symbols;
    size_t    symbol_len;
    int       total_count;
} fec_encoded_t;

fec_encoded_t codec_fec_encode(const uint8_t *in, size_t inlen, int k, int r);

/* 6. FEC DECODE (RaptorQ) */
codec_result_t codec_fec_decode(fec_encoded_t *encoded, size_t original_len);

void codec_fec_free(fec_encoded_t *f);

/* ──────────────────────────────────────────────
   Buffer Pool Management
   
   The codec functions use an internal buffer pool to reduce
   malloc/free overhead. Use these functions to properly return
   buffers to the pool instead of calling free() directly.
────────────────────────────────────────────── */

/* Free a codec result, returning its buffer to the pool */
void codec_free_result(codec_result_t *res);

/* Shutdown the buffer pool (call at program exit) */
void codec_pool_shutdown(void);

#endif /* DNSTUN_CODEC_H */
