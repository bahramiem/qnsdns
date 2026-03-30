/**
 * @file shared/fec/raptorq.c
 * @brief RaptorQ (RFC 6330) implementation of the FEC interface.
 * 
 * This module wraps the RaptorQ library into the generic fec_t interface.
 * 
 * @example
 * // 1. Use it as part of the abstract interface
 * fec_t *rq = fec_raptorq_create();
 */

#include "core.h"
#include <RaptorQ/RFC6330.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../../uv.h"

/* Static API handle for RaptorQ - initialized once per process */
static struct RFC6330_v1 *g_rq_api = NULL;
static uv_once_t g_rq_api_init_once = UV_ONCE_INIT;

typedef struct {
    struct RFC6330_v1 *api;
} raptorq_priv_t;

static void raptorq_api_init_impl(void) {
    g_rq_api = (struct RFC6330_v1*) RFC6330_api(1);
}

static struct RFC6330_v1* get_rq_api(void) {
    uv_once(&g_rq_api_init_once, raptorq_api_init_impl);
    return g_rq_api;
}

/* Method: Encode */
static qns_fec_data_t raptorq_encode(fec_t *self, const uint8_t *in, size_t inlen, int k, int r) {
    qns_fec_data_t res = {0};
    raptorq_priv_t *priv = (raptorq_priv_t *)self->priv;
    struct RFC6330_v1 *api = priv->api;
    
    if (!api || inlen == 0) return res;

    /* Symbol size: T must be small enough for DNS transport (~110-140 bytes) */
    /* We'll use a standard default or derive it. */
    uint16_t T = 110; 

    struct RFC6330_ptr *enc = api->Encoder(RQ_ENC_8, (void*)in, inlen, 4, T, 1024*1024);
    if (!enc) return res;

    res.oti_common = api->OTI_Common(enc);
    res.oti_scheme = api->OTI_Scheme_Specific(enc);
    res.has_oti = true;

    struct RFC6330_future *f = api->compute(enc, RQ_COMPUTE_COMPLETE);
    if (f) {
        api->future_wait(f);
        api->future_free(&f);
    }

    int true_k = (int)((inlen + T - 1) / T);
    if (true_k < 1) true_k = 1;
    res.k_source = true_k;

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
            for (int j = 0; j < i; j++) free(res.symbols[j]);
            free(res.symbols);
            res.symbols = NULL;
            api->free(&enc);
            return res;
        }
        void *p = res.symbols[i];
        api->encode(enc, &p, T, (uint32_t)i, 0);
    }

    api->free(&enc);
    return res;
}

/* Method: Decode */
static qns_err_t raptorq_decode(fec_t *self, qns_fec_data_t *encoded, qns_fec_result_t *out) {
    raptorq_priv_t *priv = (raptorq_priv_t *)self->priv;
    struct RFC6330_v1 *api = priv->api;
    
    if (!api || !encoded || !encoded->has_oti) return QNS_ERR_INVALID_PARAM;

    /* Pass big-endian OTI directly - Decoder() calls b_to_h() internally */
    struct RFC6330_ptr *dec = api->Decoder(RQ_DEC_8, encoded->oti_common, encoded->oti_scheme);
    if (!dec) return QNS_ERR_FEC_DECODE;

    uint16_t T = (uint16_t)encoded->symbol_len;

    /* Add symbols */
    for (int i = 0; i < (int)encoded->total_count; i++) {
        if (encoded->symbols[i]) {
            void *p = encoded->symbols[i];
            api->add_symbol_id(dec, &p, T, (uint32_t)i);
        }
    }

    api->end_of_input(dec, RQ_NO_FILL);

    struct RFC6330_future *f = api->compute(dec, RQ_COMPUTE_COMPLETE);
    if (f) {
        api->future_wait(f);
        api->future_free(&f);
    }

    /* Extract decoded data - Decoder knows size from OTI */
    /* For now, we'll allocate a 64KB buffer, similar to codec.c */
    size_t max_size = 65536; 
    out->data = malloc(max_size);
    if (!out->data) {
        api->free(&dec);
        return QNS_ERR_MALLOC;
    }

    void *out_ptr = out->data;
    struct RFC6330_Dec_Result dres = api->decode_aligned(dec, &out_ptr, (uint64_t)max_size, 0);
    
    if (dres.written == 0 || dres.written > max_size) {
        free(out->data);
        out->data = NULL;
        api->free(&dec);
        return QNS_ERR_FEC_DECODE;
    }

    out->len = (size_t)dres.written;
    api->free(&dec);
    return QNS_OK;
}

/* Method: Free Data */
static void raptorq_free_data(fec_t *self, qns_fec_data_t *data) {
    if (!data) return;
    if (data->symbols) {
        for (uint32_t i = 0; i < data->total_count; i++) {
            if (data->symbols[i]) free(data->symbols[i]);
        }
        free(data->symbols);
    }
    memset(data, 0, sizeof(*data));
}

/* Method: Destroy Interface */
static void raptorq_destroy(fec_t *self) {
    if (!self) return;
    if (self->priv) free(self->priv);
    free(self);
}

/* Factory */
fec_t* fec_raptorq_create(void) {
    fec_t *fec = calloc(1, sizeof(fec_t));
    if (!fec) return NULL;

    raptorq_priv_t *priv = calloc(1, sizeof(raptorq_priv_t));
    if (!priv) {
        free(fec);
        return NULL;
    }

    priv->api = get_rq_api();
    fec->priv = priv;
    fec->name = "RaptorQ";
    fec->encode = raptorq_encode;
    fec->decode = raptorq_decode;
    fec->free_data = raptorq_free_data;
    fec->destroy = raptorq_destroy;

    return fec;
}
