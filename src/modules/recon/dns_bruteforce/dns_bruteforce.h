/*
 * CloudUnflare Enhanced - DNS Brute-Force Module
 *
 * Enhanced DNS subdomain enumeration with intelligent wordlists,
 * permutation generation, and adaptive brute-forcing techniques
 *
 * Features:
 * - Multi-wordlist support with smart selection
 * - Permutation-based subdomain generation
 * - DNS wildcard detection and filtering
 * - Adaptive timing based on target response
 * - Pattern-based subdomain discovery
 * - OPSEC-compliant distributed scanning
 *
 * Agent Assignment: C-INTERNAL (primary implementation)
 * Wordlist Optimization: OPTIMIZER agent
 * Security Review: SECURITY agent
 */

#ifndef DNS_BRUTEFORCE_H
#define DNS_BRUTEFORCE_H

#include "../common/recon_common.h"
#include "dns_enhanced.h"

// DNS brute-force specific constants
#define BRUTEFORCE_MAX_WORDLIST_SIZE 100000
#define BRUTEFORCE_MAX_WORDLISTS 10
#define BRUTEFORCE_MAX_PERMUTATIONS 50000
#define BRUTEFORCE_MAX_SUBDOMAIN_DEPTH 5
#define BRUTEFORCE_MAX_CONCURRENT 100
#define BRUTEFORCE_DEFAULT_TIMEOUT 10
#define BRUTEFORCE_WILDCARD_SAMPLES 5

// Brute-force strategies
typedef enum {
    BRUTEFORCE_STRATEGY_BASIC,      // Simple wordlist enumeration
    BRUTEFORCE_STRATEGY_PERMUTATION, // Generate permutations
    BRUTEFORCE_STRATEGY_PATTERN,    // Pattern-based generation
    BRUTEFORCE_STRATEGY_HYBRID,     // Combination of all methods
    BRUTEFORCE_STRATEGY_ADAPTIVE    // Adaptive based on discoveries
} bruteforce_strategy_t;

// Wordlist types and priorities
typedef enum {
    WORDLIST_TYPE_COMMON,          // Common subdomains (high priority)
    WORDLIST_TYPE_TECHNOLOGY,      // Technology-specific terms
    WORDLIST_TYPE_ORGANIZATION,    // Organization/business terms
    WORDLIST_TYPE_GEOGRAPHIC,      // Geographic locations
    WORDLIST_TYPE_CUSTOM,          // User-provided wordlist
    WORDLIST_TYPE_GENERATED        // Algorithm-generated terms
} wordlist_type_t;

// Subdomain discovery result
typedef struct {
    char subdomain[RECON_MAX_DOMAIN_LEN];
    char full_domain[RECON_MAX_DOMAIN_LEN];
    char ip_address[INET6_ADDRSTRLEN];
    dns_record_type_t record_type;
    uint32_t ttl;
    uint32_t response_time_ms;
    time_t discovered;
    bool is_wildcard;
    bool is_cname;
    char cname_target[RECON_MAX_DOMAIN_LEN];
} subdomain_result_t;

// Wordlist configuration
typedef struct {
    char filename[256];
    wordlist_type_t type;
    uint32_t priority;
    uint32_t word_count;
    bool is_loaded;
    char **words;
    time_t last_modified;
} wordlist_config_t;

// Wildcard detection result
typedef struct {
    bool has_wildcard;
    char wildcard_ip[INET6_ADDRSTRLEN];
    char wildcard_pattern[RECON_MAX_DOMAIN_LEN];
    uint32_t wildcard_ttl;
    uint32_t confidence_score;
} wildcard_detection_t;

// Brute-force configuration
typedef struct {
    bruteforce_strategy_t strategy;
    wordlist_config_t wordlists[BRUTEFORCE_MAX_WORDLISTS];
    uint32_t wordlist_count;
    uint32_t max_threads;
    uint32_t timeout_seconds;
    uint32_t max_depth;
    bool detect_wildcards;
    bool use_permutations;
    bool recursive_enumeration;
    bool check_cname_targets;
    uint32_t delay_between_requests_ms;
    recon_opsec_config_t opsec;
} bruteforce_config_t;

// Brute-force context for operations
typedef struct {
    recon_context_t base_ctx;
    bruteforce_config_t config;
    char target_domain[RECON_MAX_DOMAIN_LEN];
    wildcard_detection_t wildcard_info;
    subdomain_result_t *results;
    uint32_t result_count;
    uint32_t max_results;
    uint32_t words_processed;
    uint32_t total_words;
    pthread_mutex_t results_mutex;
    pthread_mutex_t wordlist_mutex;
} bruteforce_context_t;

// Thread argument structure
typedef struct {
    bruteforce_context_t *ctx;
    uint32_t thread_id;
    uint32_t start_index;
    uint32_t end_index;
    char **current_wordlist;
} bruteforce_thread_args_t;

// Function prototypes

// Initialization and configuration
int bruteforce_init_context(bruteforce_context_t *ctx);
void bruteforce_cleanup_context(bruteforce_context_t *ctx);
int bruteforce_set_config(bruteforce_context_t *ctx, const bruteforce_config_t *config);
int bruteforce_set_target(bruteforce_context_t *ctx, const char *domain);

// Wordlist management
int bruteforce_load_wordlist(wordlist_config_t *wordlist, const char *filename, wordlist_type_t type);
void bruteforce_unload_wordlist(wordlist_config_t *wordlist);
int bruteforce_merge_wordlists(const wordlist_config_t *wordlists, uint32_t count, char ***merged_words, uint32_t *word_count);
int bruteforce_generate_permutations(const char *base_domain, const char **patterns, uint32_t pattern_count, char ***permutations, uint32_t *perm_count);

// Wildcard detection
int bruteforce_detect_wildcards(bruteforce_context_t *ctx);
bool bruteforce_is_wildcard_response(const bruteforce_context_t *ctx, const subdomain_result_t *result);
int bruteforce_test_random_subdomains(const char *domain, wildcard_detection_t *wildcard_info);

// Core brute-force operations
int bruteforce_execute(bruteforce_context_t *ctx);
void *bruteforce_worker_thread(void *arg);
int bruteforce_test_subdomain(bruteforce_context_t *ctx, const char *subdomain);
int bruteforce_recursive_enumerate(bruteforce_context_t *ctx, const char *found_subdomain);

// Result processing
int bruteforce_add_result(bruteforce_context_t *ctx, const subdomain_result_t *result);
bool bruteforce_is_duplicate_result(const bruteforce_context_t *ctx, const subdomain_result_t *result);
void bruteforce_sort_results(bruteforce_context_t *ctx);
void bruteforce_filter_results(bruteforce_context_t *ctx);

// Pattern generation and analysis
int bruteforce_generate_patterns(const char *domain, const subdomain_result_t *known_results, uint32_t result_count, char ***patterns, uint32_t *pattern_count);
int bruteforce_analyze_naming_patterns(const subdomain_result_t *results, uint32_t count, char ***suggested_words, uint32_t *word_count);
bool bruteforce_matches_pattern(const char *subdomain, const char *pattern);

// Adaptive strategies
void bruteforce_update_strategy(bruteforce_context_t *ctx);
void bruteforce_adjust_timing(bruteforce_context_t *ctx, uint32_t success_rate);
int bruteforce_prioritize_wordlists(bruteforce_context_t *ctx);

// Output and reporting
void bruteforce_print_progress(const bruteforce_context_t *ctx);
void bruteforce_print_results(const bruteforce_context_t *ctx);
int bruteforce_export_json(const bruteforce_context_t *ctx, const char *filename);
int bruteforce_export_csv(const bruteforce_context_t *ctx, const char *filename);
int bruteforce_export_subdomains_only(const bruteforce_context_t *ctx, const char *filename);

// DNS query helpers
int bruteforce_query_subdomain(const char *full_domain, dns_record_type_t type, subdomain_result_t *result);
int bruteforce_resolve_cname_chain(const char *domain, char *final_target, size_t target_size);
bool bruteforce_is_valid_dns_response(const subdomain_result_t *result);

// OPSEC and performance
void bruteforce_apply_rate_limiting(const bruteforce_context_t *ctx);
bool bruteforce_check_detection_threshold(const bruteforce_context_t *ctx);
void bruteforce_randomize_wordlist_order(char **words, uint32_t count);
uint32_t bruteforce_calculate_optimal_threads(const bruteforce_context_t *ctx);

// Utilities
const char *bruteforce_strategy_to_string(bruteforce_strategy_t strategy);
const char *wordlist_type_to_string(wordlist_type_t type);
bool bruteforce_is_valid_subdomain(const char *subdomain);
void bruteforce_sanitize_subdomain(char *subdomain);

#endif // DNS_BRUTEFORCE_H