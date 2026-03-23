#include "base32.h"
#include <string.h>
#include <ctype.h>

static const char B32_ALPHA[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
static const char HEX_ALPHA[] = "0123456789abcdef";

/*
 * [HIGH] O(1) Lookup Tables for Encoding/Decoding
 * Instead of conditional checks in loops, use 256-byte static lookup tables.
 * This eliminates branches and provides constant-time character-to-value mapping.
 * For base32 (36 valid chars), base64 (64 valid chars), and hex (22 valid chars),
 * these tables provide significant speedup over tolower() + conditional checks.
 */
static int8_t b32_table[256];   /* -1 = invalid, 0-31 = valid base32 value */
static int8_t hex_table[256];   /* -1 = invalid, 0-15 = valid hex value */
static int8_t b64_table[256];   /* -1 = invalid, 0-63 = valid base64 value */
static volatile uint8_t tables_initialized = 0;

/* Initialize lookup tables once at startup */
static void init_tables(void) {
    if (tables_initialized) return;
    
    /* Initialize base32 table: 0-25 for A-Z, 26-31 for 2-7 */
    for (int i = 0; i < 256; i++) b32_table[i] = -1;
    for (int i = 0; i < 26; i++) {
        b32_table[(unsigned char)('A' + i)] = i;
        b32_table[(unsigned char)('a' + i)] = i;  /* lowercase handled inline */
    }
    for (int i = 0; i < 6; i++) {
        b32_table[(unsigned char)('2' + i)] = 26 + i;
    }
    
    /* Initialize hex table: 0-9 for digits, 10-15 for a-f/A-F */
    for (int i = 0; i < 256; i++) hex_table[i] = -1;
    for (int i = 0; i < 10; i++) hex_table[(unsigned char)('0' + i)] = i;
    for (int i = 0; i < 6; i++) {
        hex_table[(unsigned char)('a' + i)] = 10 + i;
        hex_table[(unsigned char)('A' + i)] = 10 + i;
    }
    
    /* Initialize base64 table: A-Z (0-25), a-z (26-51), 0-9 (52-61), - (62), _ (63) */
    for (int i = 0; i < 256; i++) b64_table[i] = -1;
    for (int i = 0; i < 26; i++) {
        b64_table[(unsigned char)('A' + i)] = i;
        b64_table[(unsigned char)('a' + i)] = 26 + i;
    }
    for (int i = 0; i < 10; i++) b64_table[(unsigned char)('0' + i)] = 52 + i;
    b64_table[(unsigned char)'-'] = 62;
    b64_table[(unsigned char)'+'] = 62;
    b64_table[(unsigned char)'_'] = 63;
    b64_table[(unsigned char)'/'] = 63;
    
    tables_initialized = 1;
}

/* O(1) base32 value lookup with case-insensitive handling */
static inline int b32_val(char c) {
    unsigned char uc = (unsigned char)c;
    if (uc >= 'a' && uc <= 'z') {
        return uc - 'a';  /* Fast path for lowercase */
    }
    return b32_table[uc];  /* Table handles A-Z and 2-7 */
}

/* O(1) hex value lookup */
static inline int hex_val(char c) {
    return hex_table[(unsigned char)c];
}

/* O(1) base64 value lookup */
static inline int base64_val(char c) {
    return b64_table[(unsigned char)c];
}

/* Initialize tables on first use - called lazily */
static void base32_init(void) {
    init_tables();
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
    /* Lazy initialization of lookup tables */
    if (!tables_initialized) base32_init();
    
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
    /* Lazy initialization of lookup tables */
    if (!tables_initialized) base32_init();
    
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

/* base64_val is now defined inline at the top of the file */

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
    /* Lazy initialization of lookup tables */
    if (!tables_initialized) base32_init();
    
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
