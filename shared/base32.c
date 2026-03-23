#include "base32.h"
#include <string.h>
#include <ctype.h>

static const char B32_ALPHA[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
static const char HEX_ALPHA[] = "0123456789abcdef";

static int b32_val(char c) {
    c = tolower((unsigned char)c);
    if (c >= 'a' && c <= 'z') return c - 'a';
    if (c >= '2' && c <= '7') return 26 + (c - '2');
    return -1;
}

static int hex_val(char c) {
    c = tolower((unsigned char)c);
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    return -1;
}

size_t base32_encode(char *out, const uint8_t *in, size_t inlen) {
    size_t i = 0, o = 0;
    uint64_t buf = 0;
    int bits = 0;

    while (i < inlen) {
        buf = (buf << 8) | in[i++];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[o++] = B32_ALPHA[(buf >> bits) & 0x1F];
        }
    }
    if (bits > 0)
        out[o++] = B32_ALPHA[(buf << (5 - bits)) & 0x1F];
    out[o] = '\0';
    return o;
}

ptrdiff_t base32_decode(uint8_t *out, const char *in, size_t inlen) {
    size_t  o    = 0;
    uint64_t buf = 0;
    int bits = 0;

    for (size_t i = 0; i < inlen; i++) {
        if (in[i] == '=' || in[i] == '\0') break;
        int v = b32_val(in[i]);
        if (v < 0) return -1;
        buf = (buf << 5) | (uint64_t)v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (uint8_t)((buf >> bits) & 0xFF);
        }
    }
    return (ptrdiff_t)o;
}

/* ──────────────────────────────────────────────
   Hex encoding/decoding for downstream (server → client)
────────────────────────────────────────────── */

size_t hex_encode(char *out, const uint8_t *in, size_t inlen) {
    size_t o = 0;
    for (size_t i = 0; i < inlen; i++) {
        out[o++] = HEX_ALPHA[(in[i] >> 4) & 0x0F];
        out[o++] = HEX_ALPHA[in[i] & 0x0F];
    }
    out[o] = '\0';
    return o;
}

ptrdiff_t hex_decode(uint8_t *out, const char *in, size_t inlen) {
    size_t o = 0;
    for (size_t i = 0; i + 1 < inlen; i += 2) {
        int hi = hex_val(in[i]);
        int lo = hex_val(in[i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[o++] = (uint8_t)((hi << 4) | lo);
    }
    return (ptrdiff_t)o;
}

/* ──────────────────────────────────────────────
   Base64 encoding/decoding for downstream (server → client)
   Uses URL-safe base64 (RFC 4648) with + → - and / → _
────────────────────────────────────────────── */

static const char BASE64_ALPHA[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static int base64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return 26 + (c - 'a');
    if (c >= '0' && c <= '9') return 52 + (c - '0');
    if (c == '-' || c == '+') return 62;
    if (c == '_' || c == '/') return 63;
    return -1;
}

size_t base64_encode(char *out, const uint8_t *in, size_t inlen) {
    size_t i = 0, o = 0;
    uint32_t buf = 0;
    int bits = 0;

    while (i < inlen) {
        buf = (buf << 8) | in[i++];
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            out[o++] = BASE64_ALPHA[(buf >> bits) & 0x3F];
        }
    }
    if (bits > 0) {
        out[o++] = BASE64_ALPHA[(buf << (6 - bits)) & 0x3F];
    }
    out[o] = '\0';
    return o;
}

ptrdiff_t base64_decode(uint8_t *out, const char *in, size_t inlen) {
    size_t  o    = 0;
    uint32_t buf = 0;
    int bits = 0;

    for (size_t i = 0; i < inlen; i++) {
        if (in[i] == '=' || in[i] == '\0') break;
        int v = base64_val(in[i]);
        if (v < 0) return -1;
        buf = (buf << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (uint8_t)((buf >> bits) & 0xFF);
        }
    }
    return (ptrdiff_t)o;
}
