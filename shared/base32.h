/* base32.h — Encoding functions for DNS tunnel
 * - base32: upstream client → server (DNS QNAME safe)
 * - base64: downstream server → client (TXT record, URL-safe RFC 4648)
 * - hex: downstream server → client (alternative TXT encoding)
 */
#pragma once
#ifndef DNSTUN_BASE32_H
#define DNSTUN_BASE32_H

#include <stddef.h>
#include <stdint.h>

/* ─── Base32 (for upstream: client → server) ─── */
/* Returns number of bytes written to out, or -1 on error.
   out must be at least base32_encode_len(inlen) bytes. */
size_t base32_encode(char *out, const uint8_t *in, size_t inlen);

/* Returns number of bytes written to out, or -1 on error.
   in must be a null-terminated base32 string. */
ptrdiff_t base32_decode(uint8_t *out, const char *in, size_t inlen);

/* Returns encoded length (including null terminator) for inlen bytes. */
static inline size_t base32_encode_len(size_t inlen) {
    return ((inlen + 4) / 5) * 8 + 1;
}

/* Returns max decoded length for an encoded string of enclen chars. */
static inline size_t base32_decode_max(size_t enclen) {
    return (enclen / 8) * 5 + 5;
}

/* ─── Hex (for downstream: server → client) ─── */
/* Returns number of bytes written to out. */
size_t hex_encode(char *out, const uint8_t *in, size_t inlen);

/* Returns number of bytes written to out, or -1 on error. */
ptrdiff_t hex_decode(uint8_t *out, const char *in, size_t inlen);

/* Returns encoded length (including null terminator) for inlen bytes. */
static inline size_t hex_encode_len(size_t inlen) {
    return inlen * 2 + 1;
}

/* Returns max decoded length for an encoded string of enclen chars. */
static inline size_t hex_decode_max(size_t enclen) {
    return (enclen + 1) / 2;
}

/* ─── Base64 (for downstream: server → client, URL-safe RFC 4648) ─── */
/* Returns number of bytes written to out, or -1 on error. */
size_t base64_encode(char *out, const uint8_t *in, size_t inlen);

/* Returns number of bytes written to out, or -1 on error. */
ptrdiff_t base64_decode(uint8_t *out, const char *in, size_t inlen);

/* Returns encoded length (including null terminator) for inlen bytes. */
static inline size_t base64_encode_len(size_t inlen) {
    return ((inlen + 2) / 3) * 4 + 1;
}

/* Returns max decoded length for an encoded string of enclen chars. */
static inline size_t base64_decode_max(size_t enclen) {
    return (enclen / 4) * 3 + 3;
}

#endif /* DNSTUN_BASE32_H */
