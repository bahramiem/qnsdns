#include "codec.h"
#include <stdlib.h>
#include <string.h>

/* Headers for external libraries */
#include <zstd.h>
#include <sodium.h>
#include <RaptorQ/RaptorQ.h>

/* ── COMPRESSION (Zstd) ─────────────────────────────────────────────────── */

codec_result_t codec_compress(const uint8_t *in, size_t inlen, int level) {
    codec_result_t res = {0};
    size_t bound = ZSTD_compressBound(inlen);
    res.data = malloc(bound);
    if (!res.data) { res.error = true; return res; }

    size_t csize = ZSTD_compress(res.data, bound, in, inlen, level ? level : 3);
    if (ZSTD_isError(csize)) {
        free(res.data);
        res.data = NULL;
        res.error = true;
    } else {
        res.len = csize;
    }
    return res;
}

codec_result_t codec_decompress(const uint8_t *in, size_t inlen, size_t original_size) {
    codec_result_t res = {0};
    res.data = malloc(original_size);
    if (!res.data) { res.error = true; return res; }

    size_t dsize = ZSTD_decompress(res.data, original_size, in, inlen);
    if (ZSTD_isError(dsize)) {
        free(res.data);
        res.data = NULL;
        res.error = true;
    } else {
        res.len = dsize;
    }
    return res;
}

/* ── ENCRYPTION (Sodium / ChaCha20-Poly1305) ─────────────────────────────── */

codec_result_t codec_encrypt(const uint8_t *in, size_t inlen, const char *psk) {
    codec_result_t res = {0};
    if (sodium_init() < 0) { res.error = true; return res; }

    /* Hash PSK to 32-byte key */
    unsigned char key[crypto_aead_chachapoly1305_ietf_KEYBYTES];
    crypto_generichash(key, sizeof(key), (const unsigned char*)psk, strlen(psk), NULL, 0);

    size_t out_max = inlen + crypto_aead_chachapoly1305_ietf_NPUBBYTES + crypto_aead_chachapoly1305_ietf_ABYTES;
    res.data = malloc(out_max);
    if (!res.data) { res.error = true; return res; }

    unsigned char *nonce = res.data;
    unsigned char *ciphertext = res.data + crypto_aead_chachapoly1305_ietf_NPUBBYTES;
    unsigned long long clen;

    randombytes_buf(nonce, crypto_aead_chachapoly1305_ietf_NPUBBYTES);

    crypto_aead_chachapoly1305_ietf_encrypt(ciphertext, &clen,
                                             in, (unsigned long long)inlen,
                                             NULL, 0,
                                             NULL, nonce, key);

    res.len = (size_t)clen + crypto_aead_chachapoly1305_ietf_NPUBBYTES;
    return res;
}

codec_result_t codec_decrypt(const uint8_t *in, size_t inlen, const char *psk) {
    codec_result_t res = {0};
    if (sodium_init() < 0) { res.error = true; return res; }
    if (inlen <= crypto_aead_chachapoly1305_ietf_NPUBBYTES + crypto_aead_chachapoly1305_ietf_ABYTES) {
        res.error = true; return res;
    }

    unsigned char key[crypto_aead_chachapoly1305_ietf_KEYBYTES];
    crypto_generichash(key, sizeof(key), (const unsigned char*)psk, strlen(psk), NULL, 0);

    const unsigned char *nonce = in;
    const unsigned char *ciphertext = in + crypto_aead_chachapoly1305_ietf_NPUBBYTES;
    size_t cipherlen = inlen - crypto_aead_chachapoly1305_ietf_NPUBBYTES;

    res.data = malloc(cipherlen); /* always larger than plaintext */
    if (!res.data) { res.error = true; return res; }

    unsigned long long plen;
    if (crypto_aead_chachapoly1305_ietf_decrypt(res.data, &plen,
                                                 NULL,
                                                 ciphertext, (unsigned long long)cipherlen,
                                                 NULL, 0,
                                                 nonce, key) != 0) {
        free(res.data);
        res.data = NULL;
        res.error = true;
    } else {
        res.len = (size_t)plen;
    }
    return res;
}

/* ── FEC (RaptorQ / RFC 6330) ────────────────────────────────────────────── */

/* Simplified C wrapping for libRaptorQ C API */

fec_encoded_t codec_fec_encode(const uint8_t *in, size_t inlen, int k, int r) {
    fec_encoded_t res = {0};
    /* Symbol size: we target ~160 bytes for DNS chunk efficiency */
    uint16_t T = 160;
    
    struct RaptorQ_ptr *enc = RaptorQ_Enc(RQ_ENC_8, (void*)in, (uint32_t)inlen, 4, 10, T);
    if (!enc) return res;

    res.symbol_len = T;
    res.total_count = k + r;
    res.symbols = calloc(res.total_count, sizeof(uint8_t*));

    for (int i = 0; i < res.total_count; i++) {
        res.symbols[i] = malloc(T);
        void *p = res.symbols[i];
        /* i < k are source symbols, i >= k are repair symbols */
        uint32_t id = (uint32_t)i;
        RaptorQ_encode(enc, &p, T, id, 0);
    }

    RaptorQ_free(&enc);
    return res;
}

codec_result_t codec_fec_decode(fec_encoded_t *encoded, size_t original_len) {
    codec_result_t res = {0};
    uint16_t T = (uint16_t)encoded->symbol_len;

    struct RaptorQ_ptr *dec = RaptorQ_Dec(RQ_DEC_8, (uint32_t)original_len, 4, 10, T);
    if (!dec) { res.error = true; return res; }

    for (int i = 0; i < encoded->total_count; i++) {
        if (encoded->symbols[i]) {
            void *p = encoded->symbols[i];
            RaptorQ_add_symbol_id(dec, &p, T, (uint32_t)i, 0);
        }
    }

    res.data = malloc(original_len);
    if (!res.data) { RaptorQ_free(&dec); res.error = true; return res; }

    void *out = res.data;
    if (RaptorQ_decode_aligned(dec, &out, (uint32_t)original_len, 0) != original_len) {
        free(res.data);
        res.data = NULL;
        res.error = true;
    } else {
        res.len = original_len;
    }

    RaptorQ_free(&dec);
    return res;
}

void codec_fec_free(fec_encoded_t *f) {
    if (!f->symbols) return;
    for (int i = 0; i < f->total_count; i++) {
        free(f->symbols[i]);
    }
    free(f->symbols);
    memset(f, 0, sizeof(*f));
}
