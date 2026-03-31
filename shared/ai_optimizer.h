#pragma once
#ifndef DNSTUN_AI_OPTIMIZER_H
#define DNSTUN_AI_OPTIMIZER_H

#include <stdint.h>
#include <stdbool.h>
#include "types.h"

/* AI Optimizer Module - Machine learning driven optimizations */

/* AI optimization features */
typedef enum {
    AI_OPT_RESOLVER_SELECTION,
    AI_OPT_FEC_ADAPTATION,
    AI_OPT_CONGESTION_CONTROL,
    AI_OPT_TRAFFIC_COMPRESSION,
    AI_OPT_ROUTING_OPTIMIZATION
} ai_optimization_type_t;

/* AI model types */
typedef enum {
    AI_MODEL_NEURAL_NETWORK,
    AI_MODEL_DECISION_TREE,
    AI_MODEL_REINFORCEMENT_LEARNING,
    AI_MODEL_STATISTICAL
} ai_model_type_t;

/* AI optimizer configuration */
typedef struct ai_config {
    bool enabled;
    ai_model_type_t model_type;
    char model_path[512];
    int optimization_interval_ms;
    double learning_rate;
    bool enable_training;
    char training_data_path[512];
    int max_training_samples;
} ai_config_t;

/* Network metrics for AI analysis */
typedef struct network_metrics {
    double latency_ms;
    double jitter_ms;
    double packet_loss_percent;
    uint64_t bandwidth_bps;
    int resolver_count;
    time_t measurement_time;
} network_metrics_t;

/* Session statistics (forward declaration) */
typedef struct session_stats {
    time_t created_time;
    time_t last_active;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint32_t packets_sent;
    uint32_t packets_received;
    uint32_t errors;
    double avg_rtt_ms;
} session_stats_t;

/* Traffic pattern analysis */
typedef struct traffic_pattern {
    uint64_t total_bytes;
    uint32_t packet_count;
    double avg_packet_size;
    int protocol_type;  /* Detected protocol (HTTP, HTTPS, etc.) */
    bool is_compressible;
    time_t start_time;
} traffic_pattern_t;

/* AI statistics */
typedef struct ai_stats {
    int models_loaded;
    uint64_t training_samples_processed;
    uint64_t predictions_made;
    double avg_confidence;
    time_t last_training_time;
} ai_stats_t;

/* AI optimization result */
typedef struct ai_result {
    ai_optimization_type_t type;
    double confidence_score;  /* 0.0 to 1.0 */
    union {
        /* Resolver selection */
        struct {
            int recommended_resolvers[DNSTUN_MAX_RESOLVERS];
            int resolver_count;
            double expected_performance;
        } resolver;

        /* FEC adaptation */
        struct {
            int recommended_k;
            int recommended_m;
            double expected_reliability;
        } fec;

        /* Congestion control */
        struct {
            double optimal_window;
            int recommended_timeout_ms;
            double expected_throughput;
        } congestion;

        /* Traffic optimization */
        struct {
            int compression_level;
            bool use_deduplication;
            double expected_savings_percent;
        } traffic;
    } data;
} ai_result_t;

/* AI optimizer instance */
typedef struct ai_optimizer {
    ai_config_t config;
    void *model_context;  /* Internal model data */
    bool initialized;

    /* Metrics history */
    network_metrics_t *metrics_history;
    size_t metrics_count;
    size_t metrics_capacity;

    /* Training data */
    traffic_pattern_t *training_samples;
    size_t training_count;
    size_t training_capacity;
} ai_optimizer_t;

/* API Functions */

/* Initialize AI optimizer */
int ai_optimizer_init(const ai_config_t *config);

/* Cleanup AI optimizer */
void ai_optimizer_cleanup(void);

/* Analyze network conditions and provide recommendations */
int ai_optimize_resolver_selection(const network_metrics_t *metrics,
                                 ai_result_t *result);

/* Adapt FEC parameters based on network conditions */
int ai_optimize_fec(const network_metrics_t *metrics,
                   const session_stats_t *session_stats,
                   ai_result_t *result);

/* Optimize congestion control parameters */
int ai_optimize_congestion(const network_metrics_t *metrics,
                          const session_stats_t *session_stats,
                          ai_result_t *result);

/* Analyze traffic patterns for optimization */
int ai_analyze_traffic(const uint8_t *data, size_t len,
                      traffic_pattern_t *pattern);

/* Optimize traffic compression/encoding */
int ai_optimize_traffic_compression(const traffic_pattern_t *pattern,
                                   ai_result_t *result);

/* Update AI model with new data */
int ai_update_model(const network_metrics_t *metrics,
                   const session_stats_t *stats);

/* Save AI model state */
int ai_save_model(const char *path);

/* Load AI model state */
int ai_load_model(const char *path);

/* Get AI optimizer statistics */
void ai_get_stats(ai_stats_t *stats);

#endif /* DNSTUN_AI_OPTIMIZER_H */