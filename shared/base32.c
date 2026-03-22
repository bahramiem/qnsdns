#include "base32.h"
#include <string.h>
#include <ctype.h>

static const char B32_ALPHA[] = "abcdefghijklmnopqrstuvwxyz234567";

static int b32_val(char c) {
    c = tolower((unsigned char)c);
    if (c >= 'a' && c <= 'z') return c - 'a';
    if (c >= '2' && c <= '7') return 26 + (c - '2');
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

ssize_t base32_decode(uint8_t *out, const char *in, size_t inlen) {
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
    return (ssize_t)o;
}
