/* base32.h — RFC 4648 Base32 (lowercase, no padding) for DNS QNAME encoding */
#pragma once
#ifndef DNSTUN_BASE32_H
#define DNSTUN_BASE32_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* Returns number of bytes written to out, or -1 on error.
   out must be at least base32_encode_len(inlen) bytes. */
size_t base32_encode(char *out, const uint8_t *in, size_t inlen);

/* Returns number of bytes written to out, or -1 on error.
   in must be a null-terminated base32 string. */
ssize_t base32_decode(uint8_t *out, const char *in, size_t inlen);

/* Returns encoded length (including null terminator) for inlen bytes. */
static inline size_t base32_encode_len(size_t inlen) {
    return ((inlen + 4) / 5) * 8 + 1;
}

/* Returns max decoded length for an encoded string of enclen chars. */
static inline size_t base32_decode_max(size_t enclen) {
    return (enclen / 8) * 5 + 5;
}

#endif /* DNSTUN_BASE32_H */
