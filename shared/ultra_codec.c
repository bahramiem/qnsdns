#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "ultra_codec.h"
#include "codec.h"  /* For underlying compression/encryption */
#include <uv.h>     /* For mutex */

/* Ultra-Efficient DNS Tunnel Codec Implementation */

/* ────────────────────────────────────────────────────────────── */
/*  Internal State                                                */
/* ────────────────────────────────────────────────────────────── */

static ultra_codec_config_t g_config;
static ultra_dict_t g_dict;
static ultra_codec_stats_t g_stats;
static bool g_initialized = false;
static uv_mutex_t g_mutex;

/* ────────────────────────────────────────────────────────────── */
/*  Header Operations                                             */
/* ────────────────────────────────────────────────────────────── */

bool ultra_header_create(ultra_header_t *header, uint16_t session_id,
                         uint16_t sequence, uint8_t flags) {
    if (!header || session_id >= 16 || sequence >= 4096 || flags >= 16) {
        return false;
    }

    uint8_t seq_high = (sequence >> 8) & 0x0F;  /* Top 4 bits of sequence */
    uint8_t seq_low = sequence & 0xFF;          /* Bottom 8 bits of sequence */

    header->byte0 = (uint8_t)((session_id << ULTRA_SESSION_SHIFT) | seq_high);
    header->byte1 = seq_low;
    header->flags = flags;
    return true;
}

bool ultra_header_parse(const ultra_header_t *header, uint16_t *session_id,
                       uint16_t *sequence, uint8_t *flags) {
    if (!header || !session_id || !sequence || !flags) return false;

    *session_id = (header->byte0 & ULTRA_SESSION_MASK) >> ULTRA_SESSION_SHIFT;
    *flags = header->flags;

    uint8_t seq_high = header->byte0 & ULTRA_SEQ_HIGH_MASK;  /* Bottom 4 bits are sequence high */
    uint8_t seq_low = header->byte1 & ULTRA_SEQ_LOW_MASK;

    *sequence = (uint16_t)((seq_high << 8) | seq_low);

    return true;
}

/* ────────────────────────────────────────────────────────────── */
/*  Dictionary Operations                                         */
/* ────────────────────────────────────────────────────────────── */

static void ultra_dict_init(ultra_dict_t *dict) {
    memset(dict, 0, sizeof(*dict));
}

static void ultra_dict_add_pattern(ultra_dict_t *dict, const uint8_t *pattern, size_t len) {
    if (len < 4 || len > 255) return;  /* Only patterns worth compressing */
    if (dict->entry_count >= ULTRA_DICT_ENTRIES) return;
    if (dict->dict_used + len > ULTRA_DICT_SIZE) return;

    /* Check if pattern already exists */
    for (size_t i = 0; i < dict->entry_count; i++) {
        uint16_t offset = dict->entries[i] >> 8;
        uint8_t length = dict->entries[i] & 0xFF;
        if (length == len && memcmp(dict->dictionary + offset, pattern, len) == 0) {
            return;  /* Already exists */
        }
    }

    /* Add new pattern */
    uint16_t offset = dict->dict_used;
    uint16_t entry = (offset << 8) | (uint8_t)len;
    dict->entries[dict->entry_count++] = entry;
    memcpy(dict->dictionary + offset, pattern, len);
    dict->dict_used += len;
}

/* ────────────────────────────────────────────────────────────── */
/*  Core Codec Operations                                         */
/* ────────────────────────────────────────────────────────────── */

int ultra_codec_init(const ultra_codec_config_t *config) {
    if (g_initialized) return 0;

    uv_mutex_init(&g_mutex);
    uv_mutex_lock(&g_mutex);

    memcpy(&g_config, config, sizeof(*config));
    ultra_dict_init(&g_dict);
    memset(&g_stats, 0, sizeof(g_stats));

    g_initialized = true;

    uv_mutex_unlock(&g_mutex);
    return 0;
}

void ultra_codec_cleanup(void) {
    uv_mutex_lock(&g_mutex);
    g_initialized = false;
    memset(&g_config, 0, sizeof(g_config));
    memset(&g_dict, 0, sizeof(g_dict));
    memset(&g_stats, 0, sizeof(g_stats));
    uv_mutex_unlock(&g_mutex);
    uv_mutex_destroy(&g_mutex);
}

ultra_codec_result_t ultra_codec_encode(const uint8_t *payload, size_t len,
                                       uint16_t session_id, uint16_t sequence,
                                       bool to_server) {
    ultra_codec_result_t result = {0};
    result.error = true;
    uint8_t *dedup_data = NULL;
    uint8_t *comp_data = NULL;
    uint8_t *enc_data = NULL;

    uv_mutex_lock(&g_mutex);
    if (!g_initialized) {
        uv_mutex_unlock(&g_mutex);
        return result;
    }
    uv_mutex_unlock(&g_mutex);

    if (!payload || len == 0) return result;

    /* Start with ultra-header */
    ultra_header_t header;
    uint8_t flags = 0;

    uv_mutex_lock(&g_mutex);
    if (g_config.enable_compression) flags |= ULTRA_FLAG_COMPRESSION;
    if (g_config.enable_encryption) flags |= ULTRA_FLAG_ENCRYPTION;
    if (g_config.enable_fec) flags |= ULTRA_FLAG_FEC;
    if (!to_server) flags |= ULTRA_FLAG_DIRECTION;
    uv_mutex_unlock(&g_mutex);

    if (!ultra_header_create(&header, session_id, sequence, flags)) {
        goto cleanup;
    }

    /* Process payload */
    const uint8_t *processed_payload = payload;
    size_t processed_len = len;

    /* Deduplication (if enabled) */
    uv_mutex_lock(&g_mutex);
    if (g_config.enable_deduplication) {
        uv_mutex_unlock(&g_mutex);
        ultra_codec_result_t dedup = ultra_deduplicate(payload, len);
        if (!dedup.error) {
            dedup_data = dedup.data;
            processed_payload = dedup.data;
            processed_len = dedup.len;
            flags |= ULTRA_FLAG_COMPRESSION;  /* Mark as compressed */
        }
    } else {
        uv_mutex_unlock(&g_mutex);
    }

    /* Compression */
    if (flags & ULTRA_FLAG_COMPRESSION && processed_len > 64) {
        codec_result_t comp = codec_compress(processed_payload, processed_len,
                                           g_config.compression_level);
        if (!comp.error) {
            comp_data = comp.data;
            processed_payload = comp.data;
            processed_len = comp.len;
        }
    }

    /* Encryption */
    if (flags & ULTRA_FLAG_ENCRYPTION) {
        codec_result_t enc = codec_encrypt(processed_payload, processed_len,
                                         g_config.psk);
        if (!enc.error) {
            enc_data = enc.data;
            processed_payload = enc.data;
            processed_len = enc.len;
        }
    }

    /* Allocate result buffer */
    result.len = sizeof(ultra_header_t) + processed_len;
    result.data = malloc(result.len);
    if (!result.data) goto cleanup;

    /* Copy header and payload */
    memcpy(result.data, &header, sizeof(ultra_header_t));
    memcpy(result.data + sizeof(ultra_header_t), processed_payload, processed_len);

    result.session_id = session_id;
    result.sequence = sequence;
    result.flags = flags;
    result.error = false;

    uv_mutex_lock(&g_mutex);
    g_stats.total_encoded += len;
    uv_mutex_unlock(&g_mutex);

cleanup:
    free(dedup_data);
    free(comp_data);
    free(enc_data);
    return result;
}

ultra_codec_result_t ultra_codec_decode(const uint8_t *data, size_t len) {
    ultra_codec_result_t result = {0};
    result.error = true;
    uint8_t *dec_data = NULL;
    uint8_t *decomp_data = NULL;
    uint8_t *restore_data = NULL;

    uv_mutex_lock(&g_mutex);
    if (!g_initialized) {
        uv_mutex_unlock(&g_mutex);
        return result;
    }
    uv_mutex_unlock(&g_mutex);

    if (!data || len < sizeof(ultra_header_t)) return result;

    /* Parse header */
    const ultra_header_t *header = (const ultra_header_t*)data;
    uint16_t session_id, sequence;
    uint8_t flags;

    if (!ultra_header_parse(header, &session_id, &sequence, &flags)) goto cleanup;

    /* Extract payload */
    const uint8_t *payload = data + sizeof(ultra_header_t);
    size_t payload_len = len - sizeof(ultra_header_t);

    /* Decryption */
    if (flags & ULTRA_FLAG_ENCRYPTION) {
        codec_result_t dec = codec_decrypt(payload, payload_len, g_config.psk);
        if (dec.error) goto cleanup;
        dec_data = dec.data;
        payload = dec.data;
        payload_len = dec.len;
    }

    /* Decompression */
    if (flags & ULTRA_FLAG_COMPRESSION) {
        codec_result_t decomp = codec_decompress(payload, payload_len, 0);
        if (decomp.error) goto cleanup;
        decomp_data = decomp.data;
        payload = decomp.data;
        payload_len = decomp.len;
    }

    /* Deduplication restore */
    uv_mutex_lock(&g_mutex);
    if (g_config.enable_deduplication && (flags & ULTRA_FLAG_COMPRESSION)) {
        uv_mutex_unlock(&g_mutex);
        ultra_codec_result_t restore = ultra_deduplicate_restore(payload, payload_len);
        if (!restore.error) {
            restore_data = restore.data;
            payload = restore.data;
            payload_len = restore.len;
        }
    } else {
        uv_mutex_unlock(&g_mutex);
    }

    /* Create result */
    result.data = malloc(payload_len);
    if (!result.data) goto cleanup;

    memcpy(result.data, payload, payload_len);
    result.len = payload_len;
    result.session_id = session_id;
    result.sequence = sequence;
    result.flags = flags;
    result.error = false;

    uv_mutex_lock(&g_mutex);
    g_stats.total_decoded += payload_len;
    uv_mutex_unlock(&g_mutex);

cleanup:
    free(dec_data);
    free(decomp_data);
    free(restore_data);
    return result;
}

/* ────────────────────────────────────────────────────────────── */
/*  DNS Binary Encoding (No Base32)                              */
/* ────────────────────────────────────────────────────────────── */

ultra_codec_result_t ultra_dns_encode(const uint8_t *binary, size_t len) {
    ultra_codec_result_t result = {0};
    result.error = true;

    if (!binary || len == 0) return result;

    /* For DNS QNAME encoding, we need to handle special characters */
    /* DNS labels can contain binary data, but we escape problematic bytes */
    size_t max_encoded = len * 2 + 2;  /* Worst case escaping */
    result.data = malloc(max_encoded);
    if (!result.data) return result;

    uint8_t *out = result.data;
    size_t out_len = 0;

    /* Add length prefix for first label */
    if (len > 63) len = 63;  /* DNS label length limit */
    *out++ = (uint8_t)len;
    out_len++;

    /* Copy binary data, escaping problematic bytes */
    for (size_t i = 0; i < len && out_len < max_encoded - 1; i++) {
        uint8_t byte = binary[i];

        /* Escape null bytes, dots (label separators), and non-printable chars */
        if (byte == 0x00 || byte == 0x2E || byte < 0x20 || byte > 0x7E || byte == 0x5C) {
            if (out_len >= max_encoded - 2) break;
            *out++ = 0x5C;  /* Escape character '\' */
            *out++ = byte;
            out_len += 2;
        } else {
            *out++ = byte;
            out_len++;
        }
    }

    /* Null terminate the QNAME */
    *out = 0x00;
    out_len++;

    result.len = out_len;
    result.error = false;
    return result;
}

ultra_codec_result_t ultra_dns_decode(const uint8_t *dns_data, size_t len) {
    ultra_codec_result_t result = {0};
    result.error = true;

    if (!dns_data || len < 2) return result;

    /* Parse DNS QNAME format */
    const uint8_t *ptr = dns_data;
    uint8_t label_len = *ptr++;

    if (label_len == 0 || label_len > 63) return result;

    result.data = malloc(label_len);
    if (!result.data) return result;

    uint8_t *out = result.data;
    size_t out_len = 0;

    /* Decode label, handling escapes */
    for (size_t i = 0; i < label_len && ptr < dns_data + len; i++) {
        uint8_t byte = *ptr++;

        if (byte == 0x5C && ptr < dns_data + len) {  /* Escape sequence */
            byte = *ptr++;  /* Next byte is the escaped character */
        }

        if (out_len < label_len) {
            out[out_len++] = byte;
        }
    }

    result.len = out_len;
    result.error = false;
    return result;
}

/* ────────────────────────────────────────────────────────────── */
/*  Deduplication Operations                                     */
/* ────────────────────────────────────────────────────────────── */

ultra_codec_result_t ultra_deduplicate(const uint8_t *data, size_t len) {
    ultra_codec_result_t result = {0};
    result.error = true;

    if (!data || len == 0) return result;

    /* Simple deduplication: look for repeated patterns */
    for (size_t i = 0; i < g_dict.entry_count; i++) {
        uint16_t entry = g_dict.entries[i];
        uint16_t offset = entry >> 8;
        uint8_t pattern_len = entry & 0xFF;

        if (pattern_len <= len &&
            memcmp(data, g_dict.dictionary + offset, pattern_len) == 0) {

            /* Found match - encode as dictionary reference */
            result.data = malloc(3);  /* 2 bytes offset + 1 byte length */
            if (!result.data) return result;

            result.data[0] = offset >> 8;
            result.data[1] = offset & 0xFF;
            result.data[2] = pattern_len;
            result.len = 3;
            result.error = false;

            g_stats.dict_hits++;
            return result;
        }
    }

    /* No match found - store original data */
    result.data = malloc(len + 1);
    if (!result.data) return result;

    result.data[0] = 0xFF;  /* Marker for uncompressed data */
    memcpy(result.data + 1, data, len);
    result.len = len + 1;
    result.error = false;

    g_stats.dict_misses++;
    return result;
}

ultra_codec_result_t ultra_deduplicate_restore(const uint8_t *data, size_t len) {
    ultra_codec_result_t result = {0};
    result.error = true;

    if (!data || len < 1) return result;

    if (data[0] == 0xFF) {
        /* Uncompressed data */
        size_t orig_len = len - 1;
        result.data = malloc(orig_len);
        if (!result.data) return result;

        memcpy(result.data, data + 1, orig_len);
        result.len = orig_len;
        result.error = false;
    } else if (len >= 3) {
        /* Dictionary reference */
        uint16_t offset = (data[0] << 8) | data[1];
        uint8_t pattern_len = data[2];

        if (offset + pattern_len <= g_dict.dict_used) {
            result.data = malloc(pattern_len);
            if (!result.data) return result;

            memcpy(result.data, g_dict.dictionary + offset, pattern_len);
            result.len = pattern_len;
            result.error = false;
        }
    }

    return result;
}

void ultra_dict_update(const uint8_t *data, size_t len) {
    uv_mutex_lock(&g_mutex);
    if (!g_config.enable_deduplication) {
        uv_mutex_unlock(&g_mutex);
        return;
    }
    uv_mutex_unlock(&g_mutex);

    if (!data || len < 8) return;

    uv_mutex_lock(&g_mutex);
    /* Add patterns to dictionary for future deduplication */
    for (size_t i = 0; i <= len - 8; i += 4) {
        size_t pattern_len = (len - i > 16) ? 16 : len - i;
        ultra_dict_add_pattern(&g_dict, data + i, pattern_len);
    }
    uv_mutex_unlock(&g_mutex);
}

void ultra_codec_get_stats(ultra_codec_stats_t *stats) {
    if (stats) {
        uv_mutex_lock(&g_mutex);
        memcpy(stats, &g_stats, sizeof(*stats));

        if (g_stats.total_encoded > 0) {
            stats->avg_compression_ratio = (double)g_stats.total_decoded / g_stats.total_encoded;
        }
        uv_mutex_unlock(&g_mutex);
    }
}