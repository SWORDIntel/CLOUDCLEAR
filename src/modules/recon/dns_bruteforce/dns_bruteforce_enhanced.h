/*
 * CloudUnflare Enhanced - DNS Brute-Force Module v2.0
 *
 * Enhanced DNS subdomain enumeration with intelligent wordlists,
 * recursive enumeration, pattern-based discovery, and OPSEC compliance
 *
 * Features:
 * - Intelligent wordlist system with dynamic expansion
 * - Wildcard detection and filtering integration
 * - Recursive subdomain enumeration with depth control
 * - Pattern-based discovery (A-Z, 0-9, common patterns)
 * - Integration with existing dns_enhanced.h resolver chain
 * - OPSEC-compliant with anti-detection timing
 * - Performance target: 2000+ subdomains/second
 * - Memory efficient with streaming processing
 *
 * Agent Assignment: C-INTERNAL (primary implementation)
 * Integration: ARCHITECT (unified APIs)
 * Security: SECURITY (OPSEC compliance)
 * Optimization: OPTIMIZER (performance tuning)
 */

#ifndef DNS_BRUTEFORCE_ENHANCED_H
#define DNS_BRUTEFORCE_ENHANCED_H

#include "../common/recon_common.h"
#include "../../dns_enhanced.h"
#include "dns_bruteforce.h"

// Enhanced brute-force constants
#define ENHANCED_BRUTEFORCE_MAX_THREADS 50
#define ENHANCED_BRUTEFORCE_MAX_WORDLISTS 20
#define ENHANCED_BRUTEFORCE_MAX_PATTERNS 1000
#define ENHANCED_BRUTEFORCE_MAX_MUTATIONS 10000
#define ENHANCED_BRUTEFORCE_STREAMING_BUFFER_SIZE 8192
#define ENHANCED_BRUTEFORCE_PERFORMANCE_TARGET 2000  // subdomains/second
#define ENHANCED_BRUTEFORCE_MEMORY_THRESHOLD 1048576  // 1MB streaming threshold
#define ENHANCED_BRUTEFORCE_WILDCARD_SAMPLES 10
#define ENHANCED_BRUTEFORCE_MAX_RECURSIVE_DEPTH 5

// Advanced discovery strategies
typedef enum {
    DISCOVERY_STRATEGY_WORDLIST,      // Traditional wordlist enumeration
    DISCOVERY_STRATEGY_PATTERN,       // Pattern-based generation (A-Z, 0-9)
    DISCOVERY_STRATEGY_PERMUTATION,   // Subdomain permutations and mutations
    DISCOVERY_STRATEGY_RECURSIVE,     // Recursive enumeration of discovered subdomains
    DISCOVERY_STRATEGY_ALGORITHMIC,   // Algorithm-generated candidates
    DISCOVERY_STRATEGY_HYBRID,        // Combination of multiple strategies
    DISCOVERY_STRATEGY_ADAPTIVE       // ML-based adaptive discovery
} discovery_strategy_t;

// Enhanced wordlist types with prioritization
typedef enum {
    ENHANCED_WORDLIST_CORE,           // High-priority core subdomains (www, api, etc.)
    ENHANCED_WORDLIST_TECHNOLOGY,     // Technology-specific terms (jenkins, gitlab)
    ENHANCED_WORDLIST_INFRASTRUCTURE, // Infrastructure terms (prod, dev, staging)
    ENHANCED_WORDLIST_ORGANIZATION,   // Business/org terms (hr, finance, legal)
    ENHANCED_WORDLIST_GEOGRAPHIC,     // Geographic locations (us, eu, asia)
    ENHANCED_WORDLIST_SECURITY,       // Security-related terms (vpn, firewall, ids)
    ENHANCED_WORDLIST_DYNAMIC,        // Dynamically generated based on discoveries
    ENHANCED_WORDLIST_CUSTOM,         // User-provided custom wordlists
    ENHANCED_WORDLIST_PATTERN         // Pattern-generated candidates
} enhanced_wordlist_type_t;

// Pattern generation algorithms
typedef enum {
    PATTERN_ALGORITHM_ALPHANUMERIC,   // a-z, 0-9 combinations
    PATTERN_ALGORITHM_SEQUENTIAL,     // Sequential patterns (app1, app2, etc.)
    PATTERN_ALGORITHM_COMMON_PREFIXES,// Common prefixes (sub, dev, test)
    PATTERN_ALGORITHM_COMMON_SUFFIXES,// Common suffixes (01, prod, new)
    PATTERN_ALGORITHM_YEAR_BASED,     // Year-based patterns (2024, 2023)
    PATTERN_ALGORITHM_ENVIRONMENT,    // Environment patterns (prod, dev, qa)
    PATTERN_ALGORITHM_SERVICE_BASED,  // Service-based patterns (api, www, mail)
    PATTERN_ALGORITHM_HYBRID          // Combination of multiple algorithms
} pattern_algorithm_t;

// Enhanced subdomain result with additional metadata
typedef struct enhanced_subdomain_result {
    char subdomain[RECON_MAX_DOMAIN_LEN];
    char full_domain[RECON_MAX_DOMAIN_LEN];
    struct dual_stack_resolution resolution;
    struct ip_enrichment_data enrichment;
    struct cdn_detection cdn_info;
    dns_record_type_t record_type;
    uint32_t ttl;
    uint32_t response_time_ms;
    time_t discovered;
    discovery_strategy_t discovery_method;
    bool is_wildcard;
    bool is_cname;
    char cname_target[RECON_MAX_DOMAIN_LEN];
    uint32_t confidence_score;
    uint32_t depth_level;
    char parent_subdomain[RECON_MAX_DOMAIN_LEN];
} enhanced_subdomain_result_t;

// Intelligent wordlist configuration with dynamic loading
typedef struct enhanced_wordlist_config {
    char filename[256];
    enhanced_wordlist_type_t type;
    uint32_t priority;
    uint32_t word_count;
    uint32_t success_rate;
    bool is_loaded;
    bool is_streaming;
    char **words;
    FILE *stream_handle;
    uint32_t stream_position;
    time_t last_modified;
    time_t last_success;
    pthread_mutex_t wordlist_mutex;
} enhanced_wordlist_config_t;

// Advanced wildcard detection with pattern analysis
typedef struct enhanced_wildcard_detection {
    bool has_wildcard;
    char wildcard_ips[8][INET6_ADDRSTRLEN];
    int wildcard_ip_count;
    char wildcard_patterns[4][RECON_MAX_DOMAIN_LEN];
    int pattern_count;
    uint32_t wildcard_ttl_range[2];
    uint32_t confidence_score;
    bool affects_a_records;
    bool affects_aaaa_records;
    bool affects_cname_records;
    time_t detection_time;
} enhanced_wildcard_detection_t;

// Pattern generator configuration
typedef struct pattern_generator_config {
    pattern_algorithm_t algorithm;
    uint32_t min_length;
    uint32_t max_length;
    bool include_numbers;
    bool include_hyphens;
    bool include_underscores;
    char *prefix_list;
    char *suffix_list;
    uint32_t max_patterns;
} pattern_generator_config_t;

// OPSEC-compliant timing configuration
typedef struct enhanced_opsec_config {
    uint32_t base_delay_ms;
    uint32_t jitter_range_ms;
    uint32_t burst_limit;
    uint32_t burst_cooldown_ms;
    uint32_t session_timeout_s;
    bool randomize_resolver_order;
    bool use_multiple_sources;
    bool detect_rate_limiting;
    float paranoia_level;  // 1.0-10.0 scale
} enhanced_opsec_config_t;

// Performance monitoring and optimization
typedef struct performance_metrics {
    _Atomic uint64_t queries_sent;
    _Atomic uint64_t responses_received;
    _Atomic uint64_t wildcards_filtered;
    _Atomic uint64_t duplicates_filtered;
    _Atomic uint64_t total_response_time_ms;
    _Atomic uint32_t current_qps;
    _Atomic uint32_t peak_qps;
    time_t start_time;
    time_t last_update;
    pthread_mutex_t metrics_mutex;
} performance_metrics_t;

// Memory management for streaming operations
typedef struct memory_manager {
    uint64_t allocated_memory;
    uint64_t peak_memory;
    uint64_t memory_threshold;
    bool streaming_mode;
    uint32_t buffer_size;
    pthread_mutex_t memory_mutex;
} memory_manager_t;

// Enhanced brute-force context
typedef struct enhanced_bruteforce_context {
    recon_context_t base_ctx;

    // Configuration
    char target_domain[RECON_MAX_DOMAIN_LEN];
    discovery_strategy_t strategy;
    enhanced_wordlist_config_t wordlists[ENHANCED_BRUTEFORCE_MAX_WORDLISTS];
    uint32_t wordlist_count;
    pattern_generator_config_t pattern_config;
    enhanced_opsec_config_t opsec_config;

    // DNS integration
    struct dns_resolver_chain *resolver_chain;
    enhanced_wildcard_detection_t wildcard_info;

    // Results and processing
    enhanced_subdomain_result_t *results;
    uint32_t result_count;
    uint32_t max_results;
    uint32_t current_depth;
    uint32_t max_depth;

    // Performance and memory management
    performance_metrics_t metrics;
    memory_manager_t memory_mgr;

    // Threading and synchronization
    pthread_t worker_threads[ENHANCED_BRUTEFORCE_MAX_THREADS];
    uint32_t active_threads;
    bool stop_enumeration;
    pthread_mutex_t results_mutex;
    pthread_mutex_t work_queue_mutex;
    pthread_cond_t work_available_cond;

    // Work queue for streaming processing
    char **work_queue;
    uint32_t work_queue_size;
    uint32_t work_queue_head;
    uint32_t work_queue_tail;
    uint32_t work_queue_count;

    // Dynamic discovery state
    char **discovered_subdomains;
    uint32_t discovered_count;
    uint32_t recursive_candidates;

} enhanced_bruteforce_context_t;

// Thread argument structure for enhanced operations
typedef struct enhanced_thread_args {
    enhanced_bruteforce_context_t *ctx;
    uint32_t thread_id;
    uint32_t start_index;
    uint32_t end_index;
    discovery_strategy_t strategy;
} enhanced_thread_args_t;

// Work item for streaming processing
typedef struct work_item {
    char subdomain_candidate[RECON_MAX_DOMAIN_LEN];
    discovery_strategy_t method;
    uint32_t depth_level;
    char parent_domain[RECON_MAX_DOMAIN_LEN];
    uint32_t priority;
} work_item_t;

// Function prototypes for enhanced brute-force operations

// Core initialization and management
int enhanced_bruteforce_init_context(enhanced_bruteforce_context_t *ctx);
void enhanced_bruteforce_cleanup_context(enhanced_bruteforce_context_t *ctx);
int enhanced_bruteforce_set_target(enhanced_bruteforce_context_t *ctx, const char *domain);
int enhanced_bruteforce_configure_strategy(enhanced_bruteforce_context_t *ctx, discovery_strategy_t strategy);

// Intelligent wordlist management
int enhanced_bruteforce_load_wordlist(enhanced_wordlist_config_t *wordlist,
                                     const char *filename,
                                     enhanced_wordlist_type_t type,
                                     uint32_t priority);
int enhanced_bruteforce_stream_wordlist(enhanced_wordlist_config_t *wordlist);
void enhanced_bruteforce_unload_wordlist(enhanced_wordlist_config_t *wordlist);
int enhanced_bruteforce_merge_wordlists(enhanced_bruteforce_context_t *ctx,
                                       char ***merged_words,
                                       uint32_t *word_count);
int enhanced_bruteforce_prioritize_wordlists(enhanced_bruteforce_context_t *ctx);

// Advanced wildcard detection
int enhanced_bruteforce_detect_wildcards(enhanced_bruteforce_context_t *ctx);
bool enhanced_bruteforce_is_wildcard_response(const enhanced_bruteforce_context_t *ctx,
                                              const enhanced_subdomain_result_t *result);
int enhanced_bruteforce_analyze_wildcard_patterns(enhanced_bruteforce_context_t *ctx);
bool enhanced_bruteforce_filter_wildcard_result(const enhanced_bruteforce_context_t *ctx,
                                                const enhanced_subdomain_result_t *result);

// Pattern-based discovery
int enhanced_bruteforce_generate_patterns(enhanced_bruteforce_context_t *ctx,
                                         pattern_algorithm_t algorithm,
                                         char ***patterns,
                                         uint32_t *pattern_count);
int enhanced_bruteforce_generate_alphanumeric_patterns(const pattern_generator_config_t *config,
                                                      char ***patterns,
                                                      uint32_t *count);
int enhanced_bruteforce_generate_sequential_patterns(const pattern_generator_config_t *config,
                                                    const char *base_pattern,
                                                    char ***patterns,
                                                    uint32_t *count);
int enhanced_bruteforce_generate_permutations(const char *base_subdomain,
                                             char ***permutations,
                                             uint32_t *perm_count);

// Recursive enumeration
int enhanced_bruteforce_recursive_enumerate(enhanced_bruteforce_context_t *ctx,
                                           const char *found_subdomain,
                                           uint32_t current_depth);
int enhanced_bruteforce_discover_recursive_candidates(enhanced_bruteforce_context_t *ctx,
                                                    const enhanced_subdomain_result_t *result);
bool enhanced_bruteforce_should_recurse(const enhanced_bruteforce_context_t *ctx,
                                       const enhanced_subdomain_result_t *result);

// Enhanced DNS resolution with integration
int enhanced_bruteforce_resolve_subdomain(enhanced_bruteforce_context_t *ctx,
                                         const char *subdomain,
                                         enhanced_subdomain_result_t *result);
int enhanced_bruteforce_resolve_with_chain(enhanced_bruteforce_context_t *ctx,
                                          const char *full_domain,
                                          dns_record_type_t type,
                                          enhanced_subdomain_result_t *result);
int enhanced_bruteforce_enrich_result(enhanced_bruteforce_context_t *ctx,
                                     enhanced_subdomain_result_t *result);

// Core execution engine
int enhanced_bruteforce_execute(enhanced_bruteforce_context_t *ctx);
void *enhanced_bruteforce_worker_thread(void *arg);
int enhanced_bruteforce_process_work_queue(enhanced_bruteforce_context_t *ctx);
int enhanced_bruteforce_add_work_item(enhanced_bruteforce_context_t *ctx, const work_item_t *item);
bool enhanced_bruteforce_get_work_item(enhanced_bruteforce_context_t *ctx, work_item_t *item);

// Result management
int enhanced_bruteforce_add_result(enhanced_bruteforce_context_t *ctx,
                                  const enhanced_subdomain_result_t *result);
bool enhanced_bruteforce_is_duplicate_result(const enhanced_bruteforce_context_t *ctx,
                                            const enhanced_subdomain_result_t *result);
void enhanced_bruteforce_sort_results(enhanced_bruteforce_context_t *ctx);
void enhanced_bruteforce_filter_results(enhanced_bruteforce_context_t *ctx);
int enhanced_bruteforce_deduplicate_results(enhanced_bruteforce_context_t *ctx);

// OPSEC and anti-detection
void enhanced_bruteforce_apply_opsec_timing(const enhanced_opsec_config_t *config);
bool enhanced_bruteforce_check_rate_limiting(enhanced_bruteforce_context_t *ctx);
void enhanced_bruteforce_adjust_timing(enhanced_bruteforce_context_t *ctx, bool detected);
int enhanced_bruteforce_randomize_resolvers(enhanced_bruteforce_context_t *ctx);
void enhanced_bruteforce_implement_jitter(uint32_t base_delay_ms, uint32_t jitter_range_ms);

// Performance optimization
void enhanced_bruteforce_update_metrics(enhanced_bruteforce_context_t *ctx,
                                       bool success,
                                       uint32_t response_time_ms);
uint32_t enhanced_bruteforce_calculate_optimal_threads(const enhanced_bruteforce_context_t *ctx);
bool enhanced_bruteforce_should_enable_streaming(const enhanced_bruteforce_context_t *ctx);
int enhanced_bruteforce_optimize_memory_usage(enhanced_bruteforce_context_t *ctx);
uint32_t enhanced_bruteforce_get_current_qps(const enhanced_bruteforce_context_t *ctx);

// Memory management
int enhanced_bruteforce_init_memory_manager(memory_manager_t *mgr, uint64_t threshold);
void enhanced_bruteforce_cleanup_memory_manager(memory_manager_t *mgr);
bool enhanced_bruteforce_check_memory_threshold(const memory_manager_t *mgr);
int enhanced_bruteforce_enable_streaming_mode(enhanced_bruteforce_context_t *ctx);

// Advanced analysis and intelligence
int enhanced_bruteforce_analyze_naming_patterns(const enhanced_subdomain_result_t *results,
                                               uint32_t count,
                                               char ***suggested_patterns,
                                               uint32_t *pattern_count);
float enhanced_bruteforce_calculate_confidence_score(const enhanced_subdomain_result_t *result);
int enhanced_bruteforce_predict_subdomains(enhanced_bruteforce_context_t *ctx,
                                          const enhanced_subdomain_result_t *known_results,
                                          uint32_t result_count);

// Output and reporting
void enhanced_bruteforce_print_progress(const enhanced_bruteforce_context_t *ctx);
void enhanced_bruteforce_print_results(const enhanced_bruteforce_context_t *ctx);
void enhanced_bruteforce_print_statistics(const enhanced_bruteforce_context_t *ctx);
int enhanced_bruteforce_export_json(const enhanced_bruteforce_context_t *ctx, const char *filename);
int enhanced_bruteforce_export_csv(const enhanced_bruteforce_context_t *ctx, const char *filename);
int enhanced_bruteforce_export_subdomains_only(const enhanced_bruteforce_context_t *ctx, const char *filename);

// Configuration and validation
int enhanced_bruteforce_load_config(enhanced_bruteforce_context_t *ctx, const char *config_file);
int enhanced_bruteforce_validate_config(const enhanced_bruteforce_context_t *ctx);
bool enhanced_bruteforce_is_valid_subdomain_candidate(const char *subdomain);
void enhanced_bruteforce_sanitize_subdomain(char *subdomain);

// Utility functions
const char *discovery_strategy_to_string(discovery_strategy_t strategy);
const char *enhanced_wordlist_type_to_string(enhanced_wordlist_type_t type);
const char *pattern_algorithm_to_string(pattern_algorithm_t algorithm);
bool enhanced_bruteforce_is_high_value_subdomain(const char *subdomain);
uint32_t enhanced_bruteforce_estimate_completion_time(const enhanced_bruteforce_context_t *ctx);

// Default configurations
extern enhanced_wordlist_config_t default_enhanced_wordlists[];
extern int default_enhanced_wordlist_count;
extern pattern_generator_config_t default_pattern_configs[];
extern enhanced_opsec_config_t default_opsec_config;

#endif // DNS_BRUTEFORCE_ENHANCED_H