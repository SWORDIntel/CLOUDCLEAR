/*
 * CloudUnflare Enhanced - Cloudflare Radar Scan Module
 *
 * Implements comprehensive domain scanning using Cloudflare Radar API
 * https://radar.cloudflare.com/scan for detailed security analysis
 *
 * Features:
 * - Cloudflare Radar API integration for security scanning
 * - DNS, HTTP, SSL/TLS, and security analysis
 * - WHOIS and nameserver enumeration
 * - Technology stack detection
 * - OPSEC-compliant timing and rate limiting
 * - Thread-safe operations for multiple domains
 *
 * Security Review: SECURITY agent
 * Performance: OPTIMIZER agent
 */

#ifndef CLOUDFLARE_RADAR_H
#define CLOUDFLARE_RADAR_H

#include "../common/recon_common.h"
#include "dns_enhanced.h"
#include <time.h>

// Cloudflare Radar API constants
#define CLOUDFLARE_RADAR_API_BASE "https://radar.cloudflare.com/scan"
#define CLOUDFLARE_RADAR_API_TIMEOUT 120
#define CLOUDFLARE_RADAR_MAX_DOMAINS 100
#define CLOUDFLARE_RADAR_MAX_RESULTS 1000
#define CLOUDFLARE_RADAR_RATE_LIMIT_MS 2000
#define CLOUDFLARE_RADAR_MAX_RETRIES 3
#define CLOUDFLARE_RADAR_BUFFER_SIZE 262144  // 256KB for large responses

// Cloudflare Radar scan types
typedef enum {
    RADAR_SCAN_SECURITY,        // Security vulnerabilities
    RADAR_SCAN_DNS,             // DNS records and resolution
    RADAR_SCAN_HTTP,            // HTTP/HTTPS configuration
    RADAR_SCAN_SSL_TLS,         // SSL/TLS certificate analysis
    RADAR_SCAN_TECHNOLOGY,      // Technology stack detection
    RADAR_SCAN_PERFORMANCE,     // Performance metrics
    RADAR_SCAN_COMPREHENSIVE    // Full comprehensive scan
} radar_scan_type_t;

// Cloudflare Radar scan status
typedef enum {
    RADAR_STATUS_UNKNOWN,
    RADAR_STATUS_PENDING,
    RADAR_STATUS_IN_PROGRESS,
    RADAR_STATUS_COMPLETED,
    RADAR_STATUS_FAILED,
    RADAR_STATUS_TIMEOUT,
    RADAR_STATUS_ERROR
} radar_scan_status_t;

// DNS analysis result
typedef struct {
    char nameserver[RECON_MAX_DOMAIN_LEN];
    char ip_address[INET6_ADDRSTRLEN];
    uint32_t response_time_ms;
    bool dnssec_enabled;
    char record_types[256];  // Comma-separated list of supported record types
    time_t discovered;
} radar_dns_result_t;

// HTTP configuration result
typedef struct {
    uint16_t http_port;
    uint16_t https_port;
    bool http_enabled;
    bool https_enabled;
    bool redirect_http_to_https;
    char server_header[256];
    char location_header[512];
    uint32_t response_time_ms;
} radar_http_result_t;

// SSL/TLS certificate result
typedef struct {
    char certificate_subject[512];
    char certificate_issuer[512];
    char certificate_fingerprint[128];
    time_t valid_from;
    time_t valid_to;
    bool self_signed;
    bool expired;
    char cipher_suite[256];
    char tls_version[16];
    char san_list[1024];  // Subject Alternative Names
} radar_ssl_result_t;

// Security analysis result
typedef struct {
    bool vulnerable_to_dns_spoofing;
    bool vulnerable_to_dnssec_bypass;
    bool vulnerable_to_tls_downgrade;
    bool vulnerable_to_weak_cipher;
    char detected_vulnerabilities[512];
    uint32_t security_score;  // 0-100
} radar_security_result_t;

// Technology detection result
typedef struct {
    char technology_name[256];
    char version[64];
    char category[128];
    char confidence[64];
} radar_technology_t;

typedef struct {
    radar_technology_t *technologies;
    uint32_t tech_count;
    uint32_t max_tech_count;
} radar_technology_stack_t;

// Comprehensive Radar scan result
typedef struct {
    char domain[RECON_MAX_DOMAIN_LEN];
    radar_scan_type_t scan_type;
    radar_scan_status_t status;

    // DNS results
    radar_dns_result_t *dns_results;
    uint32_t dns_result_count;

    // HTTP results
    radar_http_result_t http_result;

    // SSL/TLS results
    radar_ssl_result_t ssl_result;

    // Security analysis
    radar_security_result_t security_result;

    // Technology stack
    radar_technology_stack_t technology_stack;

    // WHOIS and registration
    char registrar[256];
    time_t created_date;
    time_t expires_date;
    time_t updated_date;

    // Performance metrics
    uint32_t dns_query_time_ms;
    uint32_t http_response_time_ms;
    uint32_t ssl_handshake_time_ms;
    uint32_t total_scan_time_ms;

    // Metadata
    time_t scan_timestamp;
    char error_message[512];
    uint32_t retry_count;
} radar_scan_result_t;

// Radar scan configuration
typedef struct {
    radar_scan_type_t preferred_scan_type;
    uint32_t timeout_seconds;
    uint32_t max_retries;
    uint32_t delay_between_scans_ms;
    bool enable_comprehensive_scan;
    bool extract_technology_stack;
    bool analyze_security_posture;
    bool follow_redirects;
    recon_opsec_config_t opsec;
} radar_scan_config_t;

// Radar scan context for multi-threaded operations
typedef struct {
    recon_context_t base_ctx;
    radar_scan_config_t config;
    char domains[CLOUDFLARE_RADAR_MAX_DOMAINS][RECON_MAX_DOMAIN_LEN];
    uint32_t domain_count;
    radar_scan_result_t *results;
    uint32_t result_count;
    uint32_t max_results;
    pthread_mutex_t results_mutex;
    char api_cache[CLOUDFLARE_RADAR_BUFFER_SIZE];
} radar_scan_context_t;

// Function prototypes

// Initialization and configuration
int radar_scan_init_context(radar_scan_context_t *ctx);
void radar_scan_cleanup_context(radar_scan_context_t *ctx);
int radar_scan_set_config(radar_scan_context_t *ctx, const radar_scan_config_t *config);

// Domain management
int radar_scan_add_domain(radar_scan_context_t *ctx, const char *domain);
int radar_scan_add_domains(radar_scan_context_t *ctx, const char **domains, uint32_t domain_count);
int radar_scan_clear_domains(radar_scan_context_t *ctx);

// Scan operations
int radar_scan_execute_single(radar_scan_context_t *ctx, const char *domain, radar_scan_type_t scan_type);
int radar_scan_execute_comprehensive(radar_scan_context_t *ctx, const char *domain);
int radar_scan_execute_all(radar_scan_context_t *ctx);

// Multi-threaded scanning
void *radar_scan_worker_thread(void *arg);
int radar_scan_parallel_execute(radar_scan_context_t *ctx, uint32_t thread_count);

// API operations
int radar_scan_api_request(const char *domain, radar_scan_type_t scan_type, char *response_buffer, size_t buffer_size);
int radar_scan_api_validate_response(const char *response_data, size_t data_len);
int radar_scan_comprehensive(const char *domain, radar_scan_result_t *result);

// Result parsing and processing
int radar_scan_parse_response(const char *response_data, size_t data_len, radar_scan_result_t *result);
int radar_scan_extract_dns_results(const char *json_data, radar_dns_result_t **results, uint32_t *result_count);
int radar_scan_extract_http_config(const char *json_data, radar_http_result_t *result);
int radar_scan_extract_ssl_info(const char *json_data, radar_ssl_result_t *result);
int radar_scan_extract_security_analysis(const char *json_data, radar_security_result_t *result);
int radar_scan_extract_technology_stack(const char *json_data, radar_technology_stack_t *stack);
int radar_scan_extract_whois_data(const char *json_data, radar_scan_result_t *result);

// Result handling and export
void radar_scan_init_result(radar_scan_result_t *result, const char *domain);
int radar_scan_add_result(radar_scan_context_t *ctx, const radar_scan_result_t *result);
void radar_scan_print_results(const radar_scan_context_t *ctx);
int radar_scan_export_json(const radar_scan_context_t *ctx, const char *filename);
int radar_scan_export_csv(const radar_scan_context_t *ctx, const char *filename);

// OPSEC and evasion
void radar_scan_apply_timing_evasion(const recon_opsec_config_t *opsec);
bool radar_scan_check_rate_limits(const radar_scan_context_t *ctx);
void radar_scan_randomize_domain_order(char domains[][RECON_MAX_DOMAIN_LEN], uint32_t count);

// Utilities and debugging
void radar_scan_log_attempt(const char *domain, radar_scan_type_t scan_type);
void radar_scan_log_result(const radar_scan_result_t *result);
const char *radar_scan_status_to_string(radar_scan_status_t status);
const char *radar_scan_type_to_string(radar_scan_type_t type);
const char *radar_get_api_url(radar_scan_type_t scan_type);

// Memory management
int radar_scan_alloc_dns_results(radar_dns_result_t **results, uint32_t count);
void radar_scan_free_dns_results(radar_dns_result_t *results, uint32_t count);
void radar_scan_free_technology_stack(radar_technology_stack_t *stack);
void radar_scan_free_result(radar_scan_result_t *result);

#endif // CLOUDFLARE_RADAR_H
