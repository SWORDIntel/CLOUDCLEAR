/*
 * CloudClear - HTTP WAF Evasion Module
 *
 * Advanced Web Application Firewall (WAF) evasion techniques for HTTP banner grabbing
 * Inspired by research from WAF bypass methodologies and adapted for origin IP discovery
 *
 * Features:
 * - IP spoofing headers (X-Forwarded-For, X-Real-IP, X-Originating-IP, etc.)
 * - Chunked transfer encoding manipulation
 * - HTTP parameter pollution (HPP) techniques
 * - Header case mutation and obfuscation
 * - Character encoding variations
 * - Request smuggling prevention detection
 * - WAF fingerprinting and detection
 *
 * Use Case: Bypass CDN/WAF protection to reach origin servers for verification
 * Authorization: For use in authorized penetration testing and security assessments only
 *
 * Agent Assignment: SECURITY (primary implementation)
 * Research: Based on public WAF bypass research
 */

#ifndef HTTP_WAF_EVASION_H
#define HTTP_WAF_EVASION_H

#include "../common/recon_common.h"
#include <curl/curl.h>
#include <stdbool.h>

// WAF evasion constants
#define WAF_MAX_SPOOFED_IPS 10
#define WAF_MAX_HEADER_VARIANTS 20
#define WAF_MAX_ENCODING_LAYERS 5
#define WAF_CHUNK_SIZE_MIN 8
#define WAF_CHUNK_SIZE_MAX 512

// WAF detection signatures
#define WAF_MAX_SIGNATURES 50
#define WAF_SIGNATURE_LENGTH 256

// WAF types that can be detected
typedef enum {
    WAF_TYPE_UNKNOWN,
    WAF_TYPE_CLOUDFLARE,
    WAF_TYPE_AKAMAI,
    WAF_TYPE_IMPERVA,
    WAF_TYPE_AWS_WAF,
    WAF_TYPE_AZURE_WAF,
    WAF_TYPE_F5_BIG_IP,
    WAF_TYPE_BARRACUDA,
    WAF_TYPE_FORTINET,
    WAF_TYPE_SUCURI,
    WAF_TYPE_WORDFENCE,
    WAF_TYPE_MODSECURITY
} waf_type_t;

// Evasion technique types
typedef enum {
    EVASION_NONE = 0,
    EVASION_IP_SPOOFING = 1 << 0,           // X-Forwarded-For, X-Real-IP headers
    EVASION_CHUNKED_ENCODING = 1 << 1,      // Chunked transfer encoding
    EVASION_PARAMETER_POLLUTION = 1 << 2,   // HTTP parameter pollution
    EVASION_CASE_MUTATION = 1 << 3,         // Header name case variation
    EVASION_ENCODING_VARIATION = 1 << 4,    // Character encoding variations
    EVASION_NULL_BYTE_INJECTION = 1 << 5,   // Null byte in headers (careful!)
    EVASION_UNICODE_NORMALIZATION = 1 << 6, // Unicode character variants
    EVASION_HEADER_ORDERING = 1 << 7,       // Randomize header order
    EVASION_METHOD_OVERRIDE = 1 << 8,       // X-HTTP-Method-Override
    EVASION_ALL = 0xFFFFFFFF
} waf_evasion_technique_t;

// IP spoofing strategy
typedef enum {
    IP_SPOOF_RANDOM,           // Random IP addresses
    IP_SPOOF_INTERNAL,         // Internal IP ranges (10.x, 192.168.x, 172.16.x)
    IP_SPOOF_LOCALHOST,        // Localhost variants (127.0.0.1, ::1)
    IP_SPOOF_TRUSTED,          // Commonly trusted IPs (Google, Cloudflare DNS)
    IP_SPOOF_GEOGRAPHIC,       // IPs from specific geographic regions
    IP_SPOOF_CHAIN             // Chain of proxies simulation
} ip_spoof_strategy_t;

// Header case mutation strategy
typedef enum {
    CASE_MUTATION_NONE,        // No mutation
    CASE_MUTATION_LOWER,       // all lowercase
    CASE_MUTATION_UPPER,       // ALL UPPERCASE
    CASE_MUTATION_MIXED,       // MiXeD CaSe
    CASE_MUTATION_RANDOM,      // rAnDoM
    CASE_MUTATION_ALTERNATING  // AlTeRnAtInG
} case_mutation_strategy_t;

// WAF detection result
typedef struct {
    bool waf_detected;
    waf_type_t waf_type;
    char waf_name[128];
    char detection_method[256];
    double confidence_score;  // 0.0 to 1.0
    char waf_headers[10][256];
    uint32_t waf_header_count;
    char waf_fingerprint[64];
    bool rate_limiting_detected;
    bool blocking_detected;
} waf_detection_result_t;

// IP spoofing configuration
typedef struct {
    bool enabled;
    ip_spoof_strategy_t strategy;
    char spoofed_ips[WAF_MAX_SPOOFED_IPS][46]; // IPv4 + IPv6
    uint32_t spoofed_ip_count;
    bool use_x_forwarded_for;
    bool use_x_real_ip;
    bool use_x_originating_ip;
    bool use_x_remote_ip;
    bool use_x_remote_addr;
    bool use_x_client_ip;
    bool use_true_client_ip;
    bool use_cf_connecting_ip;
    bool use_forwarded;          // RFC 7239
    bool use_via;
    bool chain_proxies;          // Create proxy chain
    uint32_t chain_length;
} ip_spoofing_config_t;

// Chunked encoding configuration
typedef struct {
    bool enabled;
    uint32_t min_chunk_size;
    uint32_t max_chunk_size;
    bool randomize_chunk_sizes;
    bool add_chunk_extensions;
    bool use_invalid_chunk_encoding;  // For testing WAF robustness
} chunked_encoding_config_t;

// Parameter pollution configuration
typedef struct {
    bool enabled;
    bool duplicate_parameters;
    bool split_parameter_values;
    bool use_different_encodings;
    bool mix_get_post;
    uint32_t pollution_factor;   // How many times to pollute
} parameter_pollution_config_t;

// Header mutation configuration
typedef struct {
    bool enabled;
    case_mutation_strategy_t strategy;
    bool randomize_header_order;
    bool add_whitespace_variations;
    bool use_unicode_characters;
    bool use_obsolete_line_folding;
    double mutation_probability;  // 0.0 to 1.0
} header_mutation_config_t;

// Encoding variation configuration
typedef struct {
    bool enabled;
    bool use_url_encoding;
    bool use_double_encoding;
    bool use_unicode_encoding;
    bool use_hex_encoding;
    bool use_html_entities;
    bool mix_encoding_types;
    uint32_t encoding_layers;
} encoding_variation_config_t;

// Main WAF evasion configuration
typedef struct {
    uint32_t enabled_techniques;         // Bitmask of waf_evasion_technique_t
    ip_spoofing_config_t ip_spoofing;
    chunked_encoding_config_t chunked_encoding;
    parameter_pollution_config_t parameter_pollution;
    header_mutation_config_t header_mutation;
    encoding_variation_config_t encoding_variation;
    bool auto_detect_waf;
    bool adapt_to_waf_type;
    bool test_bypass_success;
    uint32_t max_evasion_attempts;
    uint32_t current_attempt;
} waf_evasion_config_t;

// WAF evasion context
typedef struct {
    waf_evasion_config_t config;
    waf_detection_result_t detection;
    uint32_t successful_bypasses;
    uint32_t failed_bypasses;
    uint32_t total_attempts;
    double bypass_success_rate;
    char last_error[256];
    pthread_mutex_t mutex;
} waf_evasion_context_t;

// Function prototypes

// Initialization and cleanup
int waf_evasion_init_context(waf_evasion_context_t *ctx);
void waf_evasion_cleanup_context(waf_evasion_context_t *ctx);
int waf_evasion_set_config(waf_evasion_context_t *ctx, const waf_evasion_config_t *config);

// WAF detection
int waf_detect_from_response(const char *headers, const char *body, waf_detection_result_t *result);
int waf_detect_from_headers(const char *headers, waf_detection_result_t *result);
waf_type_t waf_identify_type(const waf_detection_result_t *detection);
bool waf_is_cloudflare(const char *headers);
bool waf_is_akamai(const char *headers);
bool waf_is_aws_waf(const char *headers);
const char *waf_type_to_string(waf_type_t type);

// IP spoofing techniques
int waf_add_ip_spoofing_headers(struct curl_slist **headers, const ip_spoofing_config_t *config);
int waf_generate_spoofed_ip(char *ip_buffer, size_t buffer_size, ip_spoof_strategy_t strategy);
int waf_generate_random_ipv4(char *ip_buffer, size_t buffer_size);
int waf_generate_random_ipv6(char *ip_buffer, size_t buffer_size);
int waf_generate_internal_ip(char *ip_buffer, size_t buffer_size);
int waf_generate_trusted_ip(char *ip_buffer, size_t buffer_size);
int waf_build_proxy_chain(char *chain_buffer, size_t buffer_size, uint32_t chain_length);

// Chunked encoding techniques
int waf_enable_chunked_encoding(CURL *curl, const chunked_encoding_config_t *config);
int waf_prepare_chunked_data(const uint8_t *data, size_t data_size, uint8_t **chunked_data,
                             size_t *chunked_size, const chunked_encoding_config_t *config);
int waf_randomize_chunk_size(const chunked_encoding_config_t *config);

// HTTP parameter pollution
int waf_apply_parameter_pollution(char *url, size_t max_size, const parameter_pollution_config_t *config);
int waf_pollute_query_string(char *query, size_t max_size, const parameter_pollution_config_t *config);
int waf_duplicate_parameters(char *params, size_t max_size, uint32_t duplication_count);

// Header mutation techniques
int waf_mutate_header_case(char *header, const header_mutation_config_t *config);
int waf_randomize_header_order(struct curl_slist **headers);
int waf_add_header_variations(struct curl_slist **headers, const header_mutation_config_t *config);
case_mutation_strategy_t waf_select_random_case_strategy(void);

// Encoding variations
int waf_encode_header_value(const char *input, char *output, size_t output_size,
                            const encoding_variation_config_t *config);
int waf_url_encode_value(const char *input, char *output, size_t output_size);
int waf_double_encode_value(const char *input, char *output, size_t output_size);
int waf_unicode_encode_value(const char *input, char *output, size_t output_size);
int waf_hex_encode_value(const char *input, char *output, size_t output_size);

// Combined evasion application
int waf_apply_evasion_techniques(CURL *curl, struct curl_slist **headers,
                                 const waf_evasion_config_t *config);
int waf_apply_headers_evasion(struct curl_slist **headers, const waf_evasion_config_t *config);
int waf_apply_request_evasion(CURL *curl, const waf_evasion_config_t *config);

// Evasion testing and validation
bool waf_test_bypass_success(const char *response_headers, const char *response_body,
                            const waf_detection_result_t *initial_detection);
int waf_validate_evasion(const waf_evasion_context_t *ctx);
double waf_calculate_bypass_success_rate(const waf_evasion_context_t *ctx);

// Configuration presets
void waf_evasion_configure_light(waf_evasion_config_t *config);
void waf_evasion_configure_moderate(waf_evasion_config_t *config);
void waf_evasion_configure_aggressive(waf_evasion_config_t *config);
void waf_evasion_configure_for_waf_type(waf_evasion_config_t *config, waf_type_t waf_type);

// Utility functions
void waf_print_detection_result(const waf_detection_result_t *result);
void waf_print_evasion_stats(const waf_evasion_context_t *ctx);
const char *ip_spoof_strategy_to_string(ip_spoof_strategy_t strategy);
const char *case_mutation_strategy_to_string(case_mutation_strategy_t strategy);

// Random generation helpers
void waf_generate_random_bytes(uint8_t *buffer, size_t size);
uint32_t waf_generate_random_uint32(void);
double waf_generate_random_double(void);

#endif // HTTP_WAF_EVASION_H
