/*
 * CloudUnflare Enhanced - Result Aggregation and Correlation Framework
 *
 * Advanced result correlation, deduplication, and intelligence fusion
 * for multi-module reconnaissance operations with real-time analytics
 *
 * Agent: ARCHITECT (data flow design)
 * Coordination: DATASCIENCE, OPTIMIZER, SECURITY
 * Performance: Real-time correlation with <100ms latency
 */

#ifndef RECON_RESULT_AGGREGATOR_H
#define RECON_RESULT_AGGREGATOR_H

#include "recon_module_interface.h"
#include "dns_enhanced.h"
#include "platform_compat.h"
#include <sqlite3.h>

// Result correlation types
typedef enum {
    CORRELATION_NONE,
    CORRELATION_IP_ADDRESS,
    CORRELATION_DOMAIN_NAME,
    CORRELATION_SUBDOMAIN,
    CORRELATION_SERVICE_BANNER,
    CORRELATION_SSL_CERTIFICATE,
    CORRELATION_TIMING_PATTERN,
    CORRELATION_GEOGRAPHIC,
    CORRELATION_INFRASTRUCTURE,
    CORRELATION_BEHAVIORAL
} correlation_type_t;

// Result confidence levels
typedef enum {
    CONFIDENCE_VERY_LOW = 1,
    CONFIDENCE_LOW = 25,
    CONFIDENCE_MEDIUM = 50,
    CONFIDENCE_HIGH = 75,
    CONFIDENCE_VERY_HIGH = 90,
    CONFIDENCE_CERTAIN = 100
} confidence_level_t;

// Result priority levels
typedef enum {
    RESULT_PRIORITY_NOISE = 1,
    RESULT_PRIORITY_LOW = 25,
    RESULT_PRIORITY_NORMAL = 50,
    RESULT_PRIORITY_HIGH = 75,
    RESULT_PRIORITY_CRITICAL = 100
} result_priority_t;

// Enhanced result structure with correlation metadata
typedef struct {
    // Original result data
    recon_result_t base_result;

    // Correlation metadata
    uint64_t result_id;
    uint64_t correlation_group_id;
    correlation_type_t correlation_types[8];
    uint32_t correlation_count;

    // Confidence and validation
    confidence_level_t confidence;
    result_priority_t priority;
    bool validated;
    bool false_positive;
    double reliability_score;

    // Temporal analysis
    time_t first_seen;
    time_t last_seen;
    uint32_t occurrence_count;
    time_t *occurrence_timestamps;

    // Source tracking
    char source_module[RECON_MODULE_MAX_NAME_LEN];
    char source_operation_id[64];
    char source_ip[INET6_ADDRSTRLEN];

    // Enrichment data
    char geolocation[128];
    char isp_info[256];
    char threat_classification[64];
    char infrastructure_type[64];

    // Cross-references
    uint64_t *related_results;
    uint32_t related_count;
    uint64_t parent_result_id;
    uint64_t *child_result_ids;
    uint32_t child_count;

    // Analysis metadata
    bool anomalous;
    double anomaly_score;
    char analysis_notes[512];
    time_t last_analysis;

    pthread_mutex_t result_mutex;
} enhanced_result_t;

// Correlation group for related results
typedef struct {
    uint64_t group_id;
    correlation_type_t correlation_type;
    enhanced_result_t **results;
    uint32_t result_count;
    uint32_t max_results;

    // Group metadata
    confidence_level_t group_confidence;
    result_priority_t group_priority;
    time_t group_created;
    time_t group_updated;
    char group_description[256];

    // Analysis data
    bool analysis_complete;
    double group_reliability;
    char threat_assessment[128];

    pthread_mutex_t group_mutex;
} correlation_group_t;

// Result pattern for trend analysis
typedef struct {
    char pattern_name[128];
    char pattern_description[256];
    correlation_type_t pattern_type;

    // Pattern matching criteria
    char *match_criteria[16];
    uint32_t criteria_count;
    uint32_t min_occurrences;
    time_t time_window_seconds;

    // Pattern statistics
    uint32_t total_matches;
    time_t first_match;
    time_t last_match;
    double match_frequency;

    // Threat analysis
    result_priority_t threat_level;
    bool indicates_compromise;
    char threat_description[256];
} result_pattern_t;

// Aggregation statistics
typedef struct {
    _Atomic uint64_t total_results_processed;
    _Atomic uint64_t total_correlations_found;
    _Atomic uint64_t unique_targets_discovered;
    _Atomic uint64_t false_positives_filtered;
    _Atomic uint64_t high_priority_results;

    _Atomic double average_processing_time_ms;
    _Atomic double correlation_success_rate;
    _Atomic time_t last_processing_time;

    // Module-specific statistics
    struct {
        char module_name[RECON_MODULE_MAX_NAME_LEN];
        _Atomic uint64_t results_contributed;
        _Atomic uint64_t high_quality_results;
        _Atomic double average_confidence;
    } module_stats[16];
    uint32_t module_count;

    pthread_mutex_t stats_mutex;
} aggregation_statistics_t;

// Result database context
typedef struct {
    sqlite3 *db;
    char db_path[512];
    bool in_memory_db;
    bool persistent_storage;

    // Prepared statements
    sqlite3_stmt *insert_result_stmt;
    sqlite3_stmt *insert_correlation_stmt;
    sqlite3_stmt *query_correlations_stmt;
    sqlite3_stmt *update_result_stmt;
    sqlite3_stmt *search_results_stmt;

    // Database configuration
    uint32_t max_results_in_memory;
    time_t result_retention_days;
    bool auto_vacuum_enabled;

    pthread_mutex_t db_mutex;
} result_database_t;

// Real-time analytics engine
typedef struct {
    // Streaming analytics
    bool real_time_enabled;
    uint32_t processing_window_ms;
    uint32_t batch_size;

    // Analytics threads
    pthread_t analytics_thread;
    pthread_t correlation_thread;
    pthread_t pattern_thread;
    bool threads_running;

    // Processing queues
    enhanced_result_t **incoming_queue;
    uint32_t queue_size;
    _Atomic uint32_t queue_head;
    _Atomic uint32_t queue_tail;
    _Atomic uint32_t queue_count;

    // Pattern recognition
    result_pattern_t *patterns;
    uint32_t pattern_count;
    uint32_t max_patterns;

    // Anomaly detection
    bool anomaly_detection_enabled;
    double anomaly_threshold;
    uint32_t baseline_window_hours;

    pthread_mutex_t analytics_mutex;
    pthread_cond_t analytics_cond;
} analytics_engine_t;

// Main aggregator context
typedef struct {
    // Core components
    result_database_t database;
    analytics_engine_t analytics;
    aggregation_statistics_t statistics;

    // Result storage
    enhanced_result_t **results;
    uint32_t result_count;
    uint32_t max_results;
    pthread_rwlock_t results_rwlock;

    // Correlation groups
    correlation_group_t **groups;
    uint32_t group_count;
    uint32_t max_groups;
    pthread_mutex_t groups_mutex;

    // Configuration
    bool deduplication_enabled;
    bool correlation_enabled;
    bool pattern_analysis_enabled;
    bool real_time_processing;

    // Performance settings
    uint32_t max_processing_threads;
    uint32_t correlation_batch_size;
    uint32_t max_memory_usage_mb;

    // Filters and thresholds
    confidence_level_t min_confidence_threshold;
    result_priority_t min_priority_threshold;
    double false_positive_threshold;

    // Integration with DNS Enhanced
    struct dns_resolver_chain *dns_chain;
    bool dns_enrichment_enabled;

    // Export and reporting
    char export_directory[512];
    bool auto_export_enabled;
    uint32_t export_interval_minutes;

    // Emergency controls
    bool emergency_mode;
    uint32_t max_emergency_results;
    char emergency_export_path[512];
} result_aggregator_t;

// Function prototypes

// Aggregator lifecycle
int result_aggregator_init(result_aggregator_t *aggregator, const char *config_file);
int result_aggregator_start(result_aggregator_t *aggregator);
int result_aggregator_stop(result_aggregator_t *aggregator);
void result_aggregator_cleanup(result_aggregator_t *aggregator);

// Result processing
int aggregate_result(result_aggregator_t *aggregator, const recon_result_t *result, const char *source_module);
int process_result_batch(result_aggregator_t *aggregator, const recon_result_t *results, uint32_t count, const char *source_module);
enhanced_result_t *convert_to_enhanced_result(const recon_result_t *base_result, const char *source_module);

// Correlation and grouping
int correlate_results(result_aggregator_t *aggregator, enhanced_result_t *new_result);
correlation_group_t *find_or_create_correlation_group(result_aggregator_t *aggregator, correlation_type_t type, const char *correlation_key);
int add_result_to_group(correlation_group_t *group, enhanced_result_t *result);
int analyze_correlation_group(correlation_group_t *group);

// Deduplication
bool is_duplicate_result(const enhanced_result_t *result1, const enhanced_result_t *result2);
int deduplicate_results(result_aggregator_t *aggregator);
int merge_duplicate_results(enhanced_result_t *primary, const enhanced_result_t *duplicate);

// Confidence and validation
confidence_level_t calculate_result_confidence(const enhanced_result_t *result);
result_priority_t calculate_result_priority(const enhanced_result_t *result);
bool validate_result_against_baseline(const enhanced_result_t *result, result_aggregator_t *aggregator);
int update_result_confidence(enhanced_result_t *result, confidence_level_t new_confidence);

// Pattern analysis
int analyze_result_patterns(result_aggregator_t *aggregator);
int add_pattern_definition(result_aggregator_t *aggregator, const result_pattern_t *pattern);
bool match_result_against_patterns(const enhanced_result_t *result, result_pattern_t **patterns, uint32_t pattern_count);
int detect_anomalous_patterns(result_aggregator_t *aggregator, enhanced_result_t **anomalous_results, uint32_t *count);

// Database operations
int initialize_result_database(result_database_t *db, const char *db_path);
int store_result_in_database(result_database_t *db, const enhanced_result_t *result);
int query_results_from_database(result_database_t *db, const char *query, enhanced_result_t ***results, uint32_t *count);
int backup_database(result_database_t *db, const char *backup_path);

// Real-time analytics
void *real_time_analytics_thread(void *arg);
void *correlation_analytics_thread(void *arg);
void *pattern_analytics_thread(void *arg);
int enqueue_result_for_analytics(result_aggregator_t *aggregator, enhanced_result_t *result);

// Enrichment and enhancement
int enrich_result_with_dns_data(enhanced_result_t *result, struct dns_resolver_chain *dns_chain);
int enrich_result_with_geolocation(enhanced_result_t *result);
int enrich_result_with_threat_intelligence(enhanced_result_t *result);
int calculate_result_reliability_score(enhanced_result_t *result);

// Filtering and thresholds
bool passes_confidence_threshold(const enhanced_result_t *result, confidence_level_t threshold);
bool passes_priority_threshold(const enhanced_result_t *result, result_priority_t threshold);
int apply_result_filters(result_aggregator_t *aggregator, enhanced_result_t **filtered_results, uint32_t *count);

// Search and querying
enhanced_result_t **search_results_by_target(result_aggregator_t *aggregator, const char *target, uint32_t *count);
enhanced_result_t **search_results_by_service(result_aggregator_t *aggregator, const char *service, uint32_t *count);
enhanced_result_t **search_results_by_time_range(result_aggregator_t *aggregator, time_t start_time, time_t end_time, uint32_t *count);
correlation_group_t **search_correlation_groups(result_aggregator_t *aggregator, correlation_type_t type, uint32_t *count);

// Export and reporting
int export_results_to_json(result_aggregator_t *aggregator, const char *filename, enhanced_result_t **results, uint32_t count);
int export_results_to_csv(result_aggregator_t *aggregator, const char *filename, enhanced_result_t **results, uint32_t count);
int export_correlation_groups(result_aggregator_t *aggregator, const char *filename);
int generate_aggregation_report(result_aggregator_t *aggregator, const char *filename);

// Statistics and monitoring
int update_aggregation_statistics(result_aggregator_t *aggregator, const enhanced_result_t *result);
int get_aggregation_statistics(const result_aggregator_t *aggregator, aggregation_statistics_t *stats);
int print_aggregation_summary(const result_aggregator_t *aggregator);
double calculate_correlation_efficiency(const result_aggregator_t *aggregator);

// Utility functions
const char *correlation_type_to_string(correlation_type_t type);
const char *confidence_level_to_string(confidence_level_t level);
const char *result_priority_to_string(result_priority_t priority);
int print_enhanced_result(const enhanced_result_t *result);
int print_correlation_group(const correlation_group_t *group);

// Emergency operations
int enter_emergency_mode(result_aggregator_t *aggregator);
int exit_emergency_mode(result_aggregator_t *aggregator);
int emergency_export_all_results(result_aggregator_t *aggregator);
int purge_low_confidence_results(result_aggregator_t *aggregator);

// Configuration helpers
int load_aggregator_config(result_aggregator_t *aggregator, const char *config_file);
int save_aggregator_config(const result_aggregator_t *aggregator, const char *config_file);
int apply_default_aggregator_settings(result_aggregator_t *aggregator);

// Global aggregator instance
extern result_aggregator_t global_result_aggregator;

// Performance macros
#define AGGREGATOR_PERFORMANCE_CHECK(aggregator) \
    do { \
        if ((aggregator)->result_count > (aggregator)->max_results * 0.9) { \
            purge_low_confidence_results(aggregator); \
        } \
    } while(0)

#define AGGREGATOR_CORRELATION_GUARD(aggregator) \
    do { \
        if (!(aggregator)->correlation_enabled) { \
            return 0; \
        } \
    } while(0)

#endif // RECON_RESULT_AGGREGATOR_H
