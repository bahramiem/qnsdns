/**
 * @file shared/fec/reedsolomon.c
 * @brief Placeholder for Reed-Solomon FEC implementation.
 * 
 * This file serves as a future-proof placeholder. Currently, it 
 * returns error codes as it is not yet implemented.
 */

#include "shared/fec/core.h"
#include <stdlib.h>
#include <string.h>

static qns_fec_data_t rs_encode(fec_t *self, const uint8_t *in, size_t inlen, int k, int r) {
    qns_fec_data_t res = {0};
    (void)self; (void)in; (void)inlen; (void)k; (void)r;
    return res;
}

static qns_err_t rs_decode(fec_t *self, qns_fec_data_t *encoded, qns_fec_result_t *out) {
    (void)self; (void)encoded; (void)out;
    return QNS_ERR_GENERIC; /* Not implemented */
}

static void rs_free_data(fec_t *self, qns_fec_data_t *data) {
    (void)self; (void)data;
}

static void rs_destroy(fec_t *self) {
    free(self);
}

fec_t* fec_reedsolomon_create(void) {
    fec_t *fec = calloc(1, sizeof(fec_t));
    if (!fec) return NULL;

    fec->name = "Reed-Solomon (Stub)";
    fec->encode = rs_encode;
    fec->decode = rs_decode;
    fec->free_data = rs_free_data;
    fec->destroy = rs_destroy;

    return fec;
}
