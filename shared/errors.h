/**
 * @file shared/errors.h
 * @brief Unified error code definitions for the qnsdns project.
 * 
 * This file provides a centralized enum for all possible error states
 * across the client and server. Modular components should return 
 * questi_err_t for consistent error propagation.
 * 
 * @example
 * #include "shared/errors.h"
 * 
 * qns_err_t my_function() {
 *     if (failure_condition) {
 *         return QNS_ERR_TIMEOUT;
 *     }
 *     return QNS_OK;
 * }
 */

#ifndef QNS_ERRORS_H
#define QNS_ERRORS_H

typedef enum {
    QNS_OK = 0,                /**< Success */
    
    /* Generic Errors */
    QNS_ERR_GENERIC = -1,      /**< Unspecified error */
    QNS_ERR_MALLOC = -2,       /**< Memory allocation failure */
    QNS_ERR_NULL_PTR = -3,     /**< Unexpected null pointer */
    QNS_ERR_INVALID_PARAM = -4, /**< Invalid parameter passed to function */
    QNS_ERR_BUFFER_FULL = -5,  /**< Internal buffer limit reached */
    
    /* Network / Socket Errors */
    QNS_ERR_SEND = -10,        /**< Socket send failed */
    QNS_ERR_RECV = -11,        /**< Socket receive failed */
    QNS_ERR_TIMEOUT = -12,     /**< Operation timed out */
    QNS_ERR_CONN_CLOSED = -13, /**< Connection closed by peer */
    
    /* Protocol / FEC Errors */
    QNS_ERR_FEC_DECODE = -20,  /**< FEC decoding failed (not enough symbols) */
    QNS_ERR_FEC_ENCODE = -21,  /**< FEC encoding initialization failed */
    QNS_ERR_SEQ_JUMP = -22,    /**< Unexpected sequence number gap */
    QNS_ERR_DECOMPRESS = -23,  /**< Decompression failure (Zstd) */
    QNS_ERR_DECRYPT = -24,     /**< Decryption failure */
    
    /* SOCKS5 Errors */
    QNS_ERR_SOCKS5_VERSION = -30, /**< Invalid SOCKS5 version */
    QNS_ERR_SOCKS5_AUTH    = -31, /**< SOCKS5 authentication failure */
    QNS_ERR_SOCKS5_CMD     = -32, /**< Unsupported SOCKS5 command */
} qns_err_t;

/**
 * @brief Get a human-readable string for an error code.
 */
static inline const char* qns_err_str(qns_err_t err) {
    switch (err) {
        case QNS_OK: return "Success";
        case QNS_ERR_GENERIC: return "Generic Error";
        case QNS_ERR_MALLOC: return "Memory Allocation Failure";
        case QNS_ERR_NULL_PTR: return "Null Pointer Error";
        case QNS_ERR_INVALID_PARAM: return "Invalid Parameter";
        case QNS_ERR_BUFFER_FULL: return "Buffer Full";
        case QNS_ERR_SEND: return "Send Failed";
        case QNS_ERR_RECV: return "Receive Failed";
        case QNS_ERR_TIMEOUT: return "Timeout";
        case QNS_ERR_CONN_CLOSED: return "Connection Closed";
        case QNS_ERR_FEC_DECODE: return "FEC Decode Failed";
        case QNS_ERR_FEC_ENCODE: return "FEC Encode Failed";
        case QNS_ERR_SEQ_JUMP: return "Sequence Jump Error";
        case QNS_ERR_DECOMPRESS: return "Decompression Failed";
        case QNS_ERR_DECRYPT: return "Decryption Failed";
        case QNS_ERR_SOCKS5_VERSION: return "Invalid SOCKS5 Version";
        case QNS_ERR_SOCKS5_AUTH: return "SOCKS5 Auth Failure";
        case QNS_ERR_SOCKS5_CMD: return "SOCKS5 Unsupported Command";
        default: return "Unknown Error";
    }
}

#endif /* QNS_ERRORS_H */
