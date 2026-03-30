/**
 * @file shared/fec/core.h
 * @brief Abstract interface for Forward Error Correction (FEC).
 * 
 * This file defines the generic interface that all FEC implementations 
 * (like RaptorQ or Reed-Solomon) must follow. This allows the core 
 * networking logic to be agnostic of the specific mathematical algorithm.
 * 
 * @example
 * // 1. Initialize the FEC system
 * fec_t *fec = fec_raptorq_create(); 
 * 
 * // 2. Encode some data
 * fec_encoded_t encoded = fec->encode(fec, source_data, data_len, k, r);
 * 
 * // 3. Decode at the receiver
 * qns_err_t err = fec->decode(fec, &encoded, &decoded_res);
 */

#ifndef QNS_FEC_CORE_H
#define QNS_FEC_CORE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "../errors.h"

/**
 * @brief Container for FEC encoded symbols.
 */
typedef struct {
    uint8_t  **symbols;       /**< Array of pointers to symbol buffers */
    uint32_t   total_count;   /**< Total number of symbols (K + R) */
    uint32_t   k_source;      /**< Number of source symbols */
    size_t     symbol_len;    /**< Length of each symbol in bytes */
    
    /* OTI (Object Transmission Information) for RaptorQ */
    bool       has_oti;       
    uint64_t   oti_common;    
    uint32_t   oti_scheme;    
} qns_fec_data_t;

/**
 * @brief Result of a decoding operation.
 */
typedef struct {
    uint8_t *data;           /**< Decoded plaintext data */
    size_t   len;            /**< Length of decoded data */
} qns_fec_result_t;

/**
 * @brief FEC Interface structure.
 */
typedef struct fec_interface {
    const char *name;        /**< Name of the FEC implementation (e.g., "RaptorQ") */

    /**
     * @brief Encode data into symbols.
     * @param in Pure data to encode.
     * @param inlen Length of input data.
     * @param k Requested source symbols (advisory).
     * @param r Number of repair symbols to generate.
     */
    qns_fec_data_t (*encode)(struct fec_interface *self, const uint8_t *in, size_t inlen, int k, int r);

    /**
     * @brief Decode symbols back into data.
     */
    qns_err_t (*decode)(struct fec_interface *self, qns_fec_data_t *encoded, qns_fec_result_t *out);

    /**
     * @brief Free the encoded symbols structure.
     */
    void (*free_data)(struct fec_interface *self, qns_fec_data_t *data);

    /**
     * @brief Destroy the FEC instance.
     */
    void (*destroy)(struct fec_interface *self);

    void *priv;              /**< Implementation-specific private data */
} fec_t;

/* Factory functions for specific implementations */
fec_t* fec_raptorq_create(void);
fec_t* fec_reedsolomon_create(void);

#endif /* QNS_FEC_CORE_H */
