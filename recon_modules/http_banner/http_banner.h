/*
 * CloudUnflare Enhanced - HTTP Banner Grabbing Module
 *
 * Advanced HTTP/HTTPS banner grabbing with SSL analysis,
 * header extraction, and service fingerprinting
 *
 * Features:
 * - HTTP/HTTPS banner collection
 * - SSL/TLS certificate analysis
 * - Server header fingerprinting
 * - Technology stack detection
 * - Security header analysis
 * - Custom header injection
 * - OPSEC-compliant user-agent rotation
 *
 * Agent Assignment: C-INTERNAL (primary implementation)
 * Security Analysis: SECURITY agent
 * Performance: OPTIMIZER agent
 */

#ifndef HTTP_BANNER_H
#define HTTP_BANNER_H

#include "../common/recon_common.h"
#include <curl/curl.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

// HTTP banner specific constants
#define HTTP_MAX_HEADERS 50
#define HTTP_MAX_HEADER_SIZE 1024
#define HTTP_MAX_RESPONSE_SIZE (1024 * 1024) // 1MB
#define HTTP_MAX_USER_AGENTS 20
#define HTTP_MAX_CUSTOM_HEADERS 10
#define HTTP_DEFAULT_TIMEOUT 30
#define HTTP_MAX_REDIRECTS 5

// HTTP methods for banner grabbing
typedef enum {
    HTTP_METHOD_GET,
    HTTP_METHOD_HEAD,
    HTTP_METHOD_OPTIONS,
    HTTP_METHOD_POST,
    HTTP_METHOD_PUT,
    HTTP_METHOD_DELETE,
    HTTP_METHOD_TRACE,
    HTTP_METHOD_CONNECT
} http_method_t;

// SSL/TLS versions
typedef enum {
    SSL_VERSION_UNKNOWN,
    SSL_VERSION_SSLV2,
    SSL_VERSION_SSLV3,
    SSL_VERSION_TLSV1_0,
    SSL_VERSION_TLSV1_1,
    SSL_VERSION_TLSV1_2,
    SSL_VERSION_TLSV1_3
} ssl_version_t;

// HTTP header structure
typedef struct {
    char name[256];
    char value[HTTP_MAX_HEADER_SIZE];
} http_header_t;

// SSL certificate information
typedef struct {
    char subject[512];
    char issuer[512];
    char serial_number[64];
    char fingerprint_sha256[65];
    char not_before[32];
    char not_after[32];
    char *san_list; // Subject Alternative Names
    bool is_self_signed;
    bool is_expired;
    bool is_wildcard;
    uint32_t key_size;
    char signature_algorithm[64];
} ssl_cert_info_t;

// SSL connection information
typedef struct {
    ssl_version_t version;
    char cipher_suite[128];
    char protocol[16];
    uint32_t key_exchange_bits;
    uint32_t auth_bits;
    bool supports_sni;
    bool supports_ocsp;
    ssl_cert_info_t certificate;
} ssl_info_t;

// HTTP response information
typedef struct {
    uint32_t status_code;
    char status_message[128];
    char server_header[256];
    char content_type[128];
    uint64_t content_length;
    http_header_t headers[HTTP_MAX_HEADERS];
    uint32_t header_count;
    char *body_preview; // First 1KB of body
    size_t body_preview_size;
    uint32_t response_time_ms;
    bool has_ssl;
    ssl_info_t ssl_info;
} http_response_t;

// Technology detection result
typedef struct {
    char technology[128];
    char version[64];
    char confidence_level[16]; // Low, Medium, High
    char detection_method[64]; // Header, Body, Cookie, etc.
} technology_detection_t;

// HTTP banner result
typedef struct {
    recon_target_t target;
    http_method_t method;
    char url[1024];
    http_response_t response;
    technology_detection_t technologies[20];
    uint32_t technology_count;
    char security_headers[10][256]; // Important security headers
    uint32_t security_header_count;
    bool supports_http2;
    bool supports_http3;
    char error_message[256];
    bool success;
    time_t timestamp;
} http_banner_result_t;

// HTTP banner configuration
typedef struct {
    http_method_t default_method;
    uint32_t timeout_seconds;
    uint32_t max_redirects;
    uint32_t delay_between_requests_ms;
    bool analyze_ssl;
    bool detect_technologies;
    bool check_security_headers;
    bool follow_redirects;
    bool verify_ssl_certs;
    char custom_headers[HTTP_MAX_CUSTOM_HEADERS][HTTP_MAX_HEADER_SIZE];
    uint32_t custom_header_count;
    char user_agents[HTTP_MAX_USER_AGENTS][256];
    uint32_t user_agent_count;
    recon_opsec_config_t opsec;
} http_banner_config_t;

// HTTP banner context
typedef struct {
    recon_context_t base_ctx;
    http_banner_config_t config;
    CURL *curl_handles[RECON_MAX_THREADS];
    http_banner_result_t *results;
    uint32_t result_count;
    uint32_t max_results;
    pthread_mutex_t results_mutex;
    pthread_mutex_t curl_mutex;
} http_banner_context_t;

// cURL response data structure
typedef struct {
    char *data;
    size_t size;
    size_t max_size;
} curl_response_data_t;

// Function prototypes

// Initialization and configuration
int http_banner_init_context(http_banner_context_t *ctx);
void http_banner_cleanup_context(http_banner_context_t *ctx);
int http_banner_set_config(http_banner_context_t *ctx, const http_banner_config_t *config);

// Core banner grabbing operations
int http_banner_grab_single(http_banner_context_t *ctx, const char *url, http_banner_result_t *result);
int http_banner_grab_multiple(http_banner_context_t *ctx, const char **urls, uint32_t url_count);
void *http_banner_worker_thread(void *arg);

// HTTP request building and execution
CURL *http_banner_create_curl_handle(const http_banner_config_t *config);
int http_banner_configure_request(CURL *curl, const char *url, const http_banner_config_t *config);
int http_banner_execute_request(CURL *curl, http_response_t *response);
size_t http_banner_write_callback(void *contents, size_t size, size_t nmemb, curl_response_data_t *data);
size_t http_banner_header_callback(char *buffer, size_t size, size_t nitems, http_response_t *response);

// SSL/TLS analysis
int http_banner_analyze_ssl(const char *hostname, uint16_t port, ssl_info_t *ssl_info);
int http_banner_extract_cert_info(X509 *cert, ssl_cert_info_t *cert_info);
ssl_version_t http_banner_detect_ssl_version(SSL *ssl);
int http_banner_test_ssl_ciphers(const char *hostname, uint16_t port, char ciphers[][128], uint32_t *cipher_count);

// Technology detection
int http_banner_detect_technologies(const http_response_t *response, technology_detection_t *technologies, uint32_t *tech_count);
bool http_banner_check_header_signature(const http_response_t *response, const char *tech_name, const char *pattern);
bool http_banner_check_body_signature(const char *body, const char *tech_name, const char *pattern);
int http_banner_load_technology_signatures(const char *signature_file);

// Security header analysis
int http_banner_analyze_security_headers(const http_response_t *response, char security_headers[][256], uint32_t *header_count);
bool http_banner_has_security_header(const http_response_t *response, const char *header_name);
int http_banner_rate_security_posture(const http_response_t *response);

// Header processing
int http_banner_parse_headers(const char *header_data, http_header_t *headers, uint32_t *header_count);
const char *http_banner_get_header_value(const http_response_t *response, const char *header_name);
bool http_banner_header_contains(const http_response_t *response, const char *header_name, const char *value);

// URL and target management
int http_banner_build_url(const recon_target_t *target, bool use_https, char *url, size_t url_size);
bool http_banner_is_valid_url(const char *url);
int http_banner_parse_url(const char *url, char *hostname, uint16_t *port, char *path, bool *is_https);

// User-agent and header rotation
const char *http_banner_get_random_user_agent(const http_banner_config_t *config);
int http_banner_add_custom_headers(CURL *curl, const http_banner_config_t *config);
void http_banner_randomize_headers(http_banner_config_t *config);

// Result processing and export
int http_banner_add_result(http_banner_context_t *ctx, const http_banner_result_t *result);
void http_banner_print_result(const http_banner_result_t *result);
void http_banner_print_summary(const http_banner_context_t *ctx);
int http_banner_export_json(const http_banner_context_t *ctx, const char *filename);
int http_banner_export_csv(const http_banner_context_t *ctx, const char *filename);

// OPSEC and evasion
void http_banner_apply_request_evasion(const http_banner_config_t *config);
bool http_banner_check_rate_limiting(const http_banner_context_t *ctx);
void http_banner_randomize_timing(const recon_opsec_config_t *opsec);

// Utilities and helpers
const char *http_method_to_string(http_method_t method);
const char *ssl_version_to_string(ssl_version_t version);
void http_banner_init_response(http_response_t *response);
void http_banner_cleanup_response(http_response_t *response);
void http_banner_init_result(http_banner_result_t *result);
void http_banner_cleanup_result(http_banner_result_t *result);

// Error handling and logging
void http_banner_log_request(const char *url, http_method_t method);
void http_banner_log_response(const http_response_t *response);
void http_banner_log_error(const char *url, const char *error);

#endif // HTTP_BANNER_H