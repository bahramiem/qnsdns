#include "codec.h"
#include "tui.h"
#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Headers for external libraries */
#include <zstd.h>
#include <sodium.h>
#include <RaptorQ/RFC6330.h>

/* For uv_mutex_t type */
#include "uv.h"

/*
 * [HIGH] Buffer Pool to Avoid Frequent Allocations
 * 
 * For small DNS packets (137 bytes), the overhead of heap management and
 * potential fragmentation is significant. This buffer pool provides:
 * - Pre-allocated buffers of common sizes
 * - Thread-safe acquire/release semantics
 * - Reduced malloc/free overhead
 * 
 * Buffer sizes are optimized for DNS tunnel payloads:
 * - Small (256B): base32 decoded chunks
 * - Medium (1024B): compressed chunks
 * - Large (4096B): downstream MTU
 * - XL (16KB): FEC decoded data
 */
#define BUFFER_POOL_SMALL    256
#define BUFFER_POOL_MEDIUM   1024
#define BUFFER_POOL_LARGE    4096
#define BUFFER_POOL_XL       (1024 * 16)

typedef struct buffer_node {
    uint8_t *data;
    size_t   size;
    struct buffer_node *next;
} buffer_node_t;

typedef struct {
    buffer_node_t *pool_256;    /* 256B buffers */
    buffer_node_t *pool_1k;     /* 1024B buffers */
    buffer_node_t *pool_4k;     /* 4096B buffers */
    buffer_node_t *pool_16k;    /* 16KB buffers */
    uv_mutex_t lock;
    int init_done;
} buffer_pool_t;

static buffer_pool_t g_pool = {0};
static uv_once_t g_pool_init_once = UV_ONCE_INIT;
static uv_once_t g_rq_api_init_once = UV_ONCE_INIT;
static struct RFC6330_v1 *g_rq_api = NULL;

/* Get the appropriate pool for a given size */
static buffer_node_t** get_pool_for_size(size_t size) {
    if (size <= BUFFER_POOL_SMALL) return &g_pool.pool_256;
    if (size <= BUFFER_POOL_MEDIUM) return &g_pool.pool_1k;
    if (size <= BUFFER_POOL_LARGE) return &g_pool.pool_4k;
    return &g_pool.pool_16k;
}

/* Get the exact pool bucket size */
static size_t get_bucket_size(size_t requested) {
    if (requested <= BUFFER_POOL_SMALL) return BUFFER_POOL_SMALL;
    if (requested <= BUFFER_POOL_MEDIUM) return BUFFER_POOL_MEDIUM;
    if (requested <= BUFFER_POOL_LARGE) return BUFFER_POOL_LARGE;
    return BUFFER_POOL_XL;
}

/* Thread-safe buffer pool initialization (called via uv_once) */
static void buffer_pool_init_impl(void) {
    uv_mutex_init(&g_pool.lock);
    
    /* Pre-allocate 64 buffers per size class = 256 buffers total */
    const int PREALLOC_PER_SIZE = 64;
    const size_t sizes[] = {
        BUFFER_POOL_SMALL, BUFFER_POOL_MEDIUM,
        BUFFER_POOL_LARGE, BUFFER_POOL_XL
    };
    buffer_node_t **buckets[4];
    buckets[0] = &g_pool.pool_256;
    buckets[1] = &g_pool.pool_1k;
    buckets[2] = &g_pool.pool_4k;
    buckets[3] = &g_pool.pool_16k;
    
    for (int i = 0; i < 4; i++) {
        buffer_node_t *head = NULL;
        for (int j = 0; j < PREALLOC_PER_SIZE; j++) {
            buffer_node_t *node = malloc(sizeof(buffer_node_t));
            if (!node) continue;
            node->data = malloc(sizes[i]);
            if (!node->data) {
                free(node);
                continue;
            }
            node->size = sizes[i];
            node->next = head;
            head = node;
        }
        *buckets[i] = head;
    }
    
    g_pool.init_done = 1;
}

/* Acquire a buffer from the pool (returns NULL if pool empty) */
static uint8_t* buffer_pool_acquire(size_t size) {
    /* Thread-safe one-time initialization */
    uv_once(&g_pool_init_once, buffer_pool_init_impl);
    
    size_t bucket_size = get_bucket_size(size);
    buffer_node_t **pool = get_pool_for_size(size);
    
    uv_mutex_lock(&g_pool.lock);
    if (*pool) {
        buffer_node_t *node = *pool;
        *pool = node->next;
        uv_mutex_unlock(&g_pool.lock);
        return node->data;
    }
    uv_mutex_unlock(&g_pool.lock);
    
    /* Pool empty - fallback to malloc */
    return malloc(bucket_size);
}

/* Release a buffer back to the pool */
static void buffer_pool_release(uint8_t *data, size_t size) {
    if (!data) return;
    /* Thread-safe one-time initialization */
    uv_once(&g_pool_init_once, buffer_pool_init_impl);
    
    size_t bucket_size = get_bucket_size(size);
    buffer_node_t **pool = get_pool_for_size(size);
    
    buffer_node_t *node = malloc(sizeof(buffer_node_t));
    if (!node) {
        /* Allocation failed - just free the buffer */
        free(data);
        return;
    }
    
    node->data = data;
    node->size = bucket_size;
    
    uv_mutex_lock(&g_pool.lock);
    node->next = *pool;
    *pool = node;
    uv_mutex_unlock(&g_pool.lock);
}

/* Destroy buffer pool (call at shutdown) */
static void buffer_pool_destroy_impl(void) {
    if (!g_pool.init_done) return;
    
    uv_mutex_lock(&g_pool.lock);
    
    buffer_node_t *pools[4];
    pools[0] = g_pool.pool_256;
    pools[1] = g_pool.pool_1k;
    pools[2] = g_pool.pool_4k;
    pools[3] = g_pool.pool_16k;
    for (int i = 0; i < 4; i++) {
        buffer_node_t *node = pools[i];
        while (node) {
            buffer_node_t *next = node->next;
            free(node->data);
            free(node);
            node = next;
        }
    }
    
    uv_mutex_unlock(&g_pool.lock);
    uv_mutex_destroy(&g_pool.lock);
    g_pool.init_done = 0;
}

/* ── COMPRESSION (Zstd) ─────────────────────────────────────────────────── */

codec_result_t codec_compress(const uint8_t *in, size_t inlen, int level) {
    codec_result_t res = {0};
    size_t bound = ZSTD_compressBound(inlen);
    
    /* Try buffer pool first, fallback to malloc */
    res.data = buffer_pool_acquire(bound);
    if (!res.data) { res.error = true; return res; }

    size_t csize = ZSTD_compress(res.data, bound, in, inlen, level ? level : 3);
    if (ZSTD_isError(csize)) {
        buffer_pool_release(res.data, bound);
        res.data = NULL;
        res.error = true;
    } else {
        res.len = csize;
    }
    return res;
}

codec_result_t codec_decompress(const uint8_t *in, size_t inlen, size_t original_size) {
    codec_result_t res = {0};
    
    /* If original_size is 0, use a reasonable maximum buffer size */
    if (original_size == 0) {
        /* Use 10x compression ratio estimate, capped at 1MB */
        original_size = (inlen > 102400) ? 1024*1024 : inlen * 10;
    }
    
    /* Try buffer pool first, fallback to malloc */
    res.data = buffer_pool_acquire(original_size);
    if (!res.data) { res.error = true; return res; }

    size_t dsize = ZSTD_decompress(res.data, original_size, in, inlen);
    if (ZSTD_isError(dsize)) {
        buffer_pool_release(res.data, original_size);
        res.data = NULL;
        res.error = true;
    } else {
        res.len = dsize;
        /* NOTE: Do NOT shrink buffer with realloc.
         * The buffer pool expects fixed-size buckets. Shrinking via realloc
         * causes capacity mismatches when the buffer is returned to the pool.
         * The extra space is simply unused but keeps pool integrity. */
    }
    return res;
}

/* ── ENCRYPTION (Sodium / ChaCha20-Poly1305) ─────────────────────────────── */

codec_result_t codec_encrypt(const uint8_t *in, size_t inlen, const char *psk) {
    codec_result_t res = {0};
    if (sodium_init() < 0) { res.error = true; return res; }

    /* Hash PSK to 32-byte key */
    unsigned char key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    if (crypto_generichash(key, sizeof(key), (const unsigned char*)psk, strlen(psk), NULL, 0) != 0) {
        res.error = true;
        return res;
    }

    size_t out_max = inlen + crypto_aead_chacha20poly1305_ietf_NPUBBYTES + crypto_aead_chacha20poly1305_ietf_ABYTES;
    /* Try buffer pool first, fallback to malloc */
    res.data = buffer_pool_acquire(out_max);
    if (!res.data) { res.error = true; return res; }

    unsigned char *nonce = res.data;
    unsigned char *ciphertext = res.data + crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    unsigned long long clen;

    randombytes_buf(nonce, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);

    int enc_ret = crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, &clen,
                                             in, (unsigned long long)inlen,
                                             NULL, 0,
                                             NULL, nonce, key);
    
    if (enc_ret != 0) {
        /* Encryption failed - release the buffer */
        buffer_pool_release(res.data, out_max);
        res.data = NULL;
        res.error = true;
        return res;
    }

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
    if (crypto_generichash(key, sizeof(key), (const unsigned char*)psk, strlen(psk), NULL, 0) != 0) {
        res.error = true;
        return res;
    }

    const unsigned char *nonce = in;
    const unsigned char *ciphertext = in + crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    size_t cipherlen = inlen - crypto_aead_chacha20poly1305_ietf_NPUBBYTES;

    /* Try buffer pool first, fallback to malloc */
    res.data = buffer_pool_acquire(cipherlen); /* always larger than plaintext */
    if (!res.data) { res.error = true; return res; }

    unsigned long long plen;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(res.data, &plen,
                                                 NULL,
                                                 ciphertext, (unsigned long long)cipherlen,
                                                 NULL, 0,
                                                 nonce, key) != 0) {
        buffer_pool_release(res.data, cipherlen);
        res.data = NULL;
        res.error = true;
    } else {
        res.len = (size_t)plen;
    }
    return res;
}

#include <RaptorQ/v1/wrapper/C_RAW_API.h>

/* ── FEC (RaptorQ / RAW API) ────────────────────────────────────────────── */

static struct RaptorQ_v1 *g_rq_raw_api = NULL;
static uv_once_t g_rq_raw_api_init_once = UV_ONCE_INIT;

/* Thread-safe RaptorQ RAW API initialization */
static void get_rq_raw_api_init(void) {
    g_rq_raw_api = (struct RaptorQ_v1*) RaptorQ_api(1);
}

static struct RaptorQ_v1 *get_rq_raw_api(void) {
    uv_once(&g_rq_raw_api_init_once, get_rq_raw_api_init);
    return g_rq_raw_api;
}

/*
 * RaptorQ RAW API implementation:
 * - We negotiate K and N during the handshake.
 * - We prepend a 2-byte length to the data before encoding to handle variable sizes within the fixed block.
 */

fec_encoded_t codec_fec_encode(const uint8_t *in, size_t inlen, int k, int r, uint16_t symbol_size) {
    fec_encoded_t res = {0};
    struct RaptorQ_v1 *api = get_rq_raw_api();
    if (!api) return res;

    uint16_t T = symbol_size;
    int total = k + r;

    /* Per plan: prepend 2-byte length to data for reconstruction without OTI */
    size_t padded_inlen = inlen + 2;
    uint8_t *padded_in = malloc(padded_inlen);
    if (!padded_in) return res;
    padded_in[0] = (uint8_t)((inlen >> 8) & 0xFF);
    padded_in[1] = (uint8_t)(inlen & 0xFF);
    memcpy(padded_in + 2, in, inlen);

    /* Encoder(type, symbols, symbol_size) */
    /* Note: symbols must be a valid enum value from block_sizes.hpp mappings.
     * RaptorQ_Block_Size is an enum. We cast the integer k to it.
     * libRaptorQ supports specific block sizes. */
    struct RaptorQ_ptr *enc = api->Encoder(RQ_ENC_8, (RaptorQ_Block_Size)k, T);
    if (!enc) {
        free(padded_in);
        return res;
    }

    /* set_data(enc, data_ptr, size) */
    void *p_in = padded_in;
    api->set_data(enc, &p_in, padded_inlen);
    
    /* Synchronous computation */
    struct RaptorQ_future_enc *f = api->compute(enc);
    if (f) {
        api->future_wait((struct RaptorQ_future*)f);
        api->future_free((struct RaptorQ_future**)&f);
    }

    res.symbol_len = T;
    res.total_count = total;
    res.k_source = (uint16_t)k;
    res.symbols = calloc((size_t)total, sizeof(uint8_t*));
    if (!res.symbols) {
        api->free(&enc);
        free(padded_in);
        return res;
    }

    for (int i = 0; i < total; i++) {
        res.symbols[i] = malloc(T);
        if (!res.symbols[i]) {
            for (int j = 0; j < i; j++) free(res.symbols[j]);
            free(res.symbols);
            res.symbols = NULL;
            res.total_count = 0;
            api->free(&enc);
            free(padded_in);
            return res;
        }
        void *p_out = res.symbols[i];
        api->encode(enc, &p_out, T, (uint32_t)i);
    }

    api->free(&enc);
    free(padded_in);
    return res;
}

codec_result_t codec_fec_decode(fec_encoded_t *encoded, size_t original_len) {
    /* [DEPRECATED] use codec_fec_decode_raw with negotiated params */
    (void)original_len;
    return codec_fec_decode_raw(encoded, encoded->k_source);
}

codec_result_t codec_fec_decode_raw(fec_encoded_t *encoded, uint16_t k) {
    codec_result_t res = {0};
    struct RaptorQ_v1 *api = get_rq_raw_api();
    if (!api) { res.error = true; return res; }

    uint16_t T = (uint16_t)encoded->symbol_len;
    if (T == 0) T = DNSTUN_CHUNK_PAYLOAD;

    /* Decoder(type, symbols, symbol_size, report_type) */
    struct RaptorQ_ptr *dec = api->Decoder(RQ_DEC_8, (RaptorQ_Block_Size)k, T, RQ_COMPLETE);
    if (!dec) { res.error = true; return res; }

    /* Step 1: add all available symbols */
    for (int i = 0; i < encoded->total_count; i++) {
        if (encoded->symbols[i]) {
            void *p = encoded->symbols[i];
            api->add_symbol(dec, &p, T, (uint32_t)i);
        }
    }

    /* Step 2: signal no more input */
    api->end_of_input(dec, RQ_NO_FILL);

    /* Step 3: wait for completion if not already ready */
    if (!api->ready(dec)) {
        struct RaptorQ_future_dec *f = api->wait(dec);
        if (f) {
            api->future_wait((struct RaptorQ_future*)f);
            api->future_free((struct RaptorQ_future**)&f);
        }
    }

    /* Step 4: extraction */
    /* The decoder buffer must be large enough for K * T */
    size_t max_out = (size_t)k * T;
    res.data = buffer_pool_acquire(max_out);
    if (!res.data) { api->free(&dec); res.error = true; return res; }

    void *out_ptr = res.data;
    struct RaptorQ_Dec_Written dres = api->decode_bytes(dec, &out_ptr, max_out, 0, 0);
    
    if (dres.written < 2) {
        buffer_pool_release(res.data, max_out);
        res.data = NULL;
        res.error = true;
    } else {
        /* Recover actual length from the 2-byte prefix */
        uint16_t actual_len = (uint16_t)((res.data[0] << 8) | res.data[1]);
        if (actual_len > dres.written - 2) {
            /* Corruption or invalid length */
            buffer_pool_release(res.data, max_out);
            res.data = NULL;
            res.error = true;
        } else {
            /* Shift data to remove the 2-byte length prefix */
            memmove(res.data, res.data + 2, actual_len);
            res.len = actual_len;
        }
    }

    api->free(&dec);
    return res;
}

codec_result_t codec_fec_decode_oti(fec_encoded_t *encoded) {
    /* [DEPRECATED] OTI is no longer used in the ultra-compact protocol */
    (void)encoded;
    codec_result_t res = {0};
    res.error = true;
    return res;
}

void codec_fec_free(fec_encoded_t *f) {
    if (!f) return;
    if (f->symbols) {
        for (int i = 0; i < f->total_count; i++) {
            if (f->symbols[i]) free(f->symbols[i]);
        }
        free(f->symbols);
    }
    memset(f, 0, sizeof(*f));
}

/* ── Buffer Pool Public API ────────────────────────────────────────────────
   
   IMPORTANT: Always use these functions to free codec results instead of
   calling free() directly. This returns buffers to the pool for reuse.
─────────────────────────────────────────────────────────────────────────── */

/* Free a codec result, returning its buffer to the pool for reuse */
void codec_free_result(codec_result_t *res) {
    if (!res || !res->data) return;
    buffer_pool_release(res->data, res->len);
    res->data = NULL;
    res->len = 0;
    res->error = false;
}

/* Shutdown the buffer pool and free all pre-allocated buffers.
   Call this at program exit to clean up. */
void codec_pool_shutdown(void) {
    buffer_pool_destroy_impl();
}
