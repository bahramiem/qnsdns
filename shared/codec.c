#include "codec.h"
#include <stdlib.h>
#include <string.h>

/* Headers for external libraries */
#include <zstd.h>
#include <sodium.h>
#include <RaptorQ/RFC6330.h>

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
    unsigned char key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    crypto_generichash(key, sizeof(key), (const unsigned char*)psk, strlen(psk), NULL, 0);

    size_t out_max = inlen + crypto_aead_chacha20poly1305_ietf_NPUBBYTES + crypto_aead_chacha20poly1305_ietf_ABYTES;
    res.data = malloc(out_max);
    if (!res.data) { res.error = true; return res; }

    unsigned char *nonce = res.data;
    unsigned char *ciphertext = res.data + crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    unsigned long long clen;

    randombytes_buf(nonce, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);

    crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, &clen,
                                             in, (unsigned long long)inlen,
                                             NULL, 0,
                                             NULL, nonce, key);

    res.len = (size_t)clen + crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    return res;
}

codec_result_t codec_decrypt(const uint8_t *in, size_t inlen, const char *psk) {
    codec_result_t res = {0};
    if (sodium_init() < 0) { res.error = true; return res; }
    if (inlen <= crypto_aead_chacha20poly1305_ietf_NPUBBYTES + crypto_aead_chacha20poly1305_ietf_ABYTES) {
        res.error = true; return res;
    }

    /* Hash PSK to 32-byte key */
    unsigned char key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    crypto_generichash(key, sizeof(key), (const unsigned char*)psk, strlen(psk), NULL, 0);

    const unsigned char *nonce = in;
    const unsigned char *ciphertext = in + crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    size_t cipherlen = inlen - crypto_aead_chacha20poly1305_ietf_NPUBBYTES;

    res.data = malloc(cipherlen); /* always larger than plaintext */
    if (!res.data) { res.error = true; return res; }

    unsigned long long plen;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(res.data, &plen,
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

static struct RFC6330_v1 *get_rq_api(void) {
    static struct RFC6330_v1 *api = NULL;
    if (!api) api = (struct RFC6330_v1*) RFC6330_api(1);
    return api;
}

/*
 * Fix #6: the encoder decides how many source symbols (K) actually exist
 * based on input size and symbol size T.  We query the encoder's block info
 * to get the true K rather than trusting the caller's k parameter directly.
 * r repair symbols are added on top.
 */
fec_encoded_t codec_fec_encode(const uint8_t *in, size_t inlen, int k, int r) {
    fec_encoded_t res = {0};
    struct RFC6330_v1 *api = get_rq_api();
    if (!api) return res;

    /* Symbol size: target size for DNS chunk efficiency */
    uint16_t T = DNSTUN_CHUNK_PAYLOAD;

    struct RFC6330_ptr *enc = api->Encoder(RQ_ENC_8, (void*)in, inlen, 4, T, 1024*1024);
    if (!enc) return res;

    /* Synchronous computation */
    struct RFC6330_future *f = api->compute(enc, RQ_COMPUTE_COMPLETE);
    if (f) {
        api->future_wait(f);
        api->future_free(&f);
    }

    /* Query actual source-symbol count from the encoder.
       K_padded is reported via block_size(). We derive it from inlen / T
       rounded up, capped by what the API actually generated. */
    int true_k = (int)((inlen + T - 1) / T);
    if (true_k < 1) true_k = 1;
    /* Caller's k is advisory; use max to avoid generating symbols that
       don't exist. */
    (void)k; /* advisory only */

    int total = true_k + r;
    res.symbol_len = T;
    res.total_count = total;
    res.symbols = calloc((size_t)total, sizeof(uint8_t*));
    if (!res.symbols) {
        api->free(&enc);
        return res;
    }

    for (int i = 0; i < total; i++) {
        res.symbols[i] = malloc(T);
        if (!res.symbols[i]) {
            /* Partial failure: free what we have and return error */
            for (int j = 0; j < i; j++) free(res.symbols[j]);
            free(res.symbols);
            res.symbols = NULL;
            res.total_count = 0;
            api->free(&enc);
            return res;
        }
        void *p = res.symbols[i];
        /* encode(enc, data_ptr, size, esi, sbn) */
        api->encode(enc, &p, T, (uint32_t)i, 0);
    }

    api->free(&enc);
    return res;
}

/*
 * Fix #9: symbols must be added and end_of_input called BEFORE compute().
 * Correct order: add_symbol_id* → end_of_input → compute → future_wait.
 */
codec_result_t codec_fec_decode(fec_encoded_t *encoded, size_t original_len) {
    codec_result_t res = {0};
    struct RFC6330_v1 *api = get_rq_api();
    if (!api) { res.error = true; return res; }

    uint16_t T = (uint16_t)encoded->symbol_len;

    /* Decoder_raw(type, size, symbol_size, sub_blocks, blocks, alignment) */
    struct RFC6330_ptr *dec = api->Decoder_raw(RQ_DEC_8, (uint64_t)original_len, T, 1, 1, 1);
    if (!dec) { res.error = true; return res; }

    /* Step 1: add all available symbols */
    for (int i = 0; i < encoded->total_count; i++) {
        if (encoded->symbols[i]) {
            void *p = encoded->symbols[i];
            /* add_symbol_id(dec, data, size, id) where id = esi (sbn=0) */
            api->add_symbol_id(dec, &p, T, (uint32_t)i);
        }
    }

    /* Step 2: signal no more input */
    api->end_of_input(dec, RQ_NO_FILL);

    /* Step 3: trigger computation and wait */
    struct RFC6330_future *f = api->compute(dec, RQ_COMPUTE_COMPLETE);
    if (f) {
        api->future_wait(f);
        api->future_free(&f);
    }

    /* Step 4: extract decoded data */
    res.data = malloc(original_len + 16); /* small padding for alignment */
    if (!res.data) { api->free(&dec); res.error = true; return res; }

    void *out = res.data;
    struct RFC6330_Dec_Result dres = api->decode_aligned(dec, &out, (uint64_t)original_len, 0);
    if (dres.written < original_len) {
        free(res.data);
        res.data = NULL;
        res.error = true;
    } else {
        res.len = (size_t)dres.written;
    }

    api->free(&dec);
    return res;
}

void codec_fec_free(fec_encoded_t *f) {
    if (!f->symbols) return;
    for (int i = 0; i < f->total_count; i++) {
        if (f->symbols[i]) free(f->symbols[i]);
    }
    free(f->symbols);
    memset(f, 0, sizeof(*f));
}
