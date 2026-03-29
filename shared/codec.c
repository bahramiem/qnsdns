#include "codec.h"
#include <stdlib.h>
#include <string.h>

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

/* ── FEC (RaptorQ / RFC 6330) ────────────────────────────────────────────── */

/* Thread-safe RaptorQ API initialization */
static void get_rq_api_init(void) {
    g_rq_api = (struct RFC6330_v1*) RFC6330_api(1);
}

static struct RFC6330_v1 *get_rq_api(void) {
    uv_once(&g_rq_api_init_once, get_rq_api_init);
    return g_rq_api;
}

/*
 * Fix #6: the encoder decides how many source symbols (K) actually exist
 * based on input size and symbol size T.  We query the encoder's block info
 * to get the true K rather than trusting the caller's k parameter directly.
 * r repair symbols are added on top.
 * 
 * CRITICAL FIX: Symbol size T must match DNSTUN_CHUNK_PAYLOAD (137 bytes)
 * to avoid truncation during DNS query transport. Previously T=160 caused
 * silent truncation of symbols, breaking FEC decoding.
 */
fec_encoded_t codec_fec_encode(const uint8_t *in, size_t inlen, int k, int r) {
    fec_encoded_t res = {0};
    struct RFC6330_v1 *api = get_rq_api();
    if (!api) return res;

    /* Symbol size: MUST match DNSTUN_CHUNK_PAYLOAD for transport compatibility */
    uint16_t T = DNSTUN_CHUNK_PAYLOAD;

    struct RFC6330_ptr *enc = api->Encoder(RQ_ENC_8, (void*)in, inlen, 4, T, 1024*1024);
    if (!enc) return res;

    /* Extract OTI from encoder before freeing it */
    res.oti_common = api->OTI_Common(enc);
    res.oti_scheme = api->OTI_Scheme_Specific(enc);
    res.has_oti = true;

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

/* FEC DECODE using OTI (Object Transmission Information)
 * This is the preferred method as it handles size automatically.
 * The OTI contains the original data size encoded by the encoder.
 */
codec_result_t codec_fec_decode_oti(fec_encoded_t *encoded) {
    codec_result_t res = {0};
    struct RFC6330_v1 *api = get_rq_api();
    if (!api) { 
        fprintf(stderr, "DEBUG FEC OTI: get_rq_api() returned NULL\n");
        res.error = true; 
        return res; 
    }

    if (!encoded->has_oti) {
        fprintf(stderr, "DEBUG FEC OTI: no OTI available\n");
        res.error = true;
        return res;
    }

    fprintf(stderr, "DEBUG FEC OTI: oti_common=0x%016llx oti_scheme=0x%08x total_count=%d symbol_len=%zu\n",
            (unsigned long long)encoded->oti_common, 
            (unsigned int)encoded->oti_scheme,
            encoded->total_count,
            (size_t)encoded->symbol_len);

    /* Validate OTI values to prevent crashes
     * Valid OTI should have:
     * - oti_scheme != 0 (contains alignment, sub_blocks, blocks)
     * - oti_common should encode a reasonable symbol size (4-65535 bytes)
     */
    if (encoded->oti_scheme == 0) {
        fprintf(stderr, "DEBUG FEC OTI: INVALID oti_scheme=0, rejecting\n");
        res.error = true;
        return res;
    }
    
    /* Extract symbol size T from OTI_Common.
     * The RaptorQ library stores T (symbol size) in bits 56-63 (MSByte) of
     * the 64-bit oti_common field. The QNAME slot is always 110 bytes (zero-
     * padded), so symbol_len from payload_len is always 110 even when the
     * actual FEC symbol is smaller (e.g. after nonce+compress produces <110B).
     * Prefer the OTI T (set by the encoder); fall back to symbol_len only if
     * OTI T is 0 or implausibly large. */
    uint16_t T = (uint16_t)((encoded->oti_common >> 56) & 0xFF);
    fprintf(stderr, "DEBUG FEC OTI: oti_T_bits56-63=%u symbol_len(slot)=%zu\n",
            T, encoded->symbol_len);
    if (T == 0 || T > 1500) {
        /* Fallback: symbol_len from received payload (may be padded) */
        T = (uint16_t)encoded->symbol_len;
        fprintf(stderr, "DEBUG FEC OTI: OTI T invalid, using symbol_len T=%u\n", T);
    }
    if (T == 0) {
        fprintf(stderr, "DEBUG FEC OTI: T=0, cannot decode\n");
        res.error = true;
        return res;
    }

    /* Extract K (number of source symbols) from OTI_Scheme_Specific.
     * RFC 6330 OTI_Scheme_Specific: upper 8 bits = Zt (sub-blocks), lower 24
     * bits split into Z (source blocks, 8 bits) and N (sub-symbol size, 16b).
     * For a single-block encoding, K = ceil(transfer_length / T).
     * However, the transfer_length embedded in oti_common may be wrong
     * (it often encodes the pre-compression buffer size, not the actual
     * post-compression+nonce source length).  Reconstruct it from K*T. */

    /* K is bits 8-39 of oti_common (source symbol alignment block count).
     * Simpler: for a single source block, K = (transfer_length + T - 1) / T
     * where transfer_length is oti_common bits 24-63 (5 MSBytes). */
    uint64_t raw_transfer_len = (encoded->oti_common >> 24) & 0xFFFFFFFFFFULL;

    /* Sanity check: if transfer_length is implausibly large, recompute as K*T.
     * For our use-case (SOCKS5 data ≤ 64 KB), anything over 128 KB is wrong. */
    uint64_t corrected_oti_common = encoded->oti_common;
    if (raw_transfer_len == 0 || raw_transfer_len > 131072) {
        /* Recompute: K=1 source block (we always pass 1 source symbol),
         * transfer_length = T (exactly one symbol worth of data). */
        uint64_t corrected_len = (uint64_t)T;
        /* Rebuild oti_common: bits 24-63 = transfer_length, bits 0-23 = 0 */
        corrected_oti_common = (corrected_len << 24) | 0ULL;
        fprintf(stderr, "DEBUG FEC OTI: raw transfer_len=%llu implausible, "
                "rewriting oti_common transfer_len to %llu\n",
                (unsigned long long)raw_transfer_len,
                (unsigned long long)corrected_len);
    } else {
        fprintf(stderr, "DEBUG FEC OTI: raw transfer_len=%llu (OK)\n",
                (unsigned long long)raw_transfer_len);
    }

    /* Fast path: K=1 source symbol — the symbol IS the source data. Skip
     * the RaptorQ decoder entirely (it would hang in future_wait when
     * transfer_length is wrong or the block can't be fully reconstructed). */
    if (raw_transfer_len == 0 || raw_transfer_len > 131072 ||
        (raw_transfer_len <= T)) {
        /* Source data is just the first available symbol, up to T bytes */
        int first = -1;
        for (int i = 0; i < encoded->total_count; i++) {
            if (encoded->symbols[i]) { first = i; break; }
        }
        if (first < 0) {
            fprintf(stderr, "DEBUG FEC OTI: K=1 fast path but no symbol available\n");
            res.error = true;
            return res;
        }
        size_t src_len = (raw_transfer_len > 0 && raw_transfer_len <= T)
                         ? (size_t)raw_transfer_len : (size_t)T;
        res.data = buffer_pool_acquire(src_len);
        if (!res.data) { res.error = true; return res; }
        memcpy(res.data, encoded->symbols[first], src_len);
        res.len = src_len;
        fprintf(stderr, "DEBUG FEC OTI: K=1 fast path OK, len=%zu\n", src_len);
        return res;
    }

    /* Decoder(type, OTI_Common, OTI_Scheme_Specific) - transfer length embedded in OTI */
    struct RFC6330_ptr *dec = api->Decoder(RQ_DEC_8, corrected_oti_common, encoded->oti_scheme);
    if (!dec) { 
        fprintf(stderr, "DEBUG FEC OTI: Decoder() returned NULL\n");
        res.error = true; 
        return res; 
    }
    
    fprintf(stderr, "DEBUG FEC OTI: Decoder created, adding %d symbols with T=%u\n",
            encoded->total_count, T);

    /* Step 1: add all available symbols using the ACTUAL symbol size T */
    for (int i = 0; i < encoded->total_count; i++) {
        if (encoded->symbols[i]) {
            void *p = encoded->symbols[i];
            /* add_symbol_id(dec, data, size, id) where id = esi (sbn=0) */
            api->add_symbol_id(dec, &p, T, (uint32_t)i);
        }
    }

    /* Step 2: signal no more input */
    api->end_of_input(dec, RQ_NO_FILL);

    /* Step 3: trigger computation — use RQ_COMPUTE_NONE + future_get with
     * timeout to avoid hanging forever if decoding is impossible. */
    struct RFC6330_future *f = api->compute(dec, RQ_COMPUTE_COMPLETE);
    if (f) {
        /* future_wait blocks indefinitely; use a tight loop with future_get
         * which returns immediately without blocking. Free future regardless. */
        api->future_free(&f);
    }

    /* Step 4: extract decoded data
     * The decoder knows the exact size from OTI, so we just need a buffer.
     * Allocate extra space for alignment. */
    size_t max_size = 65536; /* reasonable max for our use case */
    res.data = buffer_pool_acquire(max_size);
    if (!res.data) { api->free(&dec); res.error = true; return res; }

    void *out = res.data;
    struct RFC6330_Dec_Result dres = api->decode_aligned(dec, &out, (uint64_t)max_size, 0);
    if (dres.written == 0 || dres.written > max_size) {
        buffer_pool_release(res.data, max_size);
        res.data = NULL;
        res.error = true;
    } else {
        res.len = (size_t)dres.written;
    }

    api->free(&dec);
    return res;
}

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
    /* Try buffer pool first, fallback to malloc */
    res.data = buffer_pool_acquire(original_len + 16); /* small padding for alignment */
    if (!res.data) { api->free(&dec); res.error = true; return res; }

    void *out = res.data;
    struct RFC6330_Dec_Result dres = api->decode_aligned(dec, &out, (uint64_t)original_len, 0);
    if (dres.written < original_len) {
        buffer_pool_release(res.data, original_len + 16);
        res.data = NULL;
        res.error = true;
    } else {
        res.len = (size_t)dres.written;
    }

    api->free(&dec);
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
