/*
 * CloudClear - Advanced Reconnaissance Master Module
 *
 * Comprehensive CDN bypass and passive intelligence gathering module
 * Implements all advanced techniques for origin IP discovery
 *
 * Modules Included:
 * 1. SSL Certificate Enumeration & Correlation
 * 2. IPv6 Range Scanning
 * 3. DNS Cache Snooping
 * 4. Passive DNS Monitoring
 * 5. Regional Accessibility Testing
 * 6. Web Application Fingerprinting (Framework, CMS, JS libs)
 * 7. API Endpoint Discovery
 * 8. Directory Brute-forcing
 * 9. Email Server Enumeration
 * 10. Document Metadata Analysis
 * 11. Historical DNS Records Analysis
 */

#ifndef ADVANCED_RECON_H
#define ADVANCED_RECON_H

#include "../common/recon_common.h"
#include <curl/curl.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

// Module feature flags
#define FEATURE_SSL_CERT_ENUM 1
#define FEATURE_IPV6_SCANNING 1
#define FEATURE_DNS_CACHE_SNOOP 1
#define FEATURE_PASSIVE_DNS 1
#define FEATURE_REGIONAL_ACCESS_TEST 1
#define FEATURE_WEB_FINGERPRINT 1
#define FEATURE_API_DISCOVERY 1
#define FEATURE_DIR_BRUTEFORCE 1
#define FEATURE_EMAIL_ENUM 1
#define FEATURE_METADATA_ANALYSIS 1
#define FEATURE_HISTORICAL_DNS 1

// ============================================================================
// SSL CERTIFICATE ENUMERATION
// ============================================================================

typedef struct {
    char subject[512];
    char issuer[512];
    char fingerprint_sha256[128];
    char **san_list;
    uint32_t san_count;
    time_t not_before;
    time_t not_after;
    bool is_self_signed;
    char common_name[256];
} ssl_cert_result_t;

int ssl_cert_enumerate(const char *host, uint16_t port, ssl_cert_result_t *result);
int ssl_cert_find_origin_by_cert_match(const char *domain, const ssl_cert_result_t *cdn_cert,
                                       char **origin_ips, uint32_t *ip_count);

// ============================================================================
// IPv6 RANGE SCANNING
// ============================================================================

typedef struct {
    char ipv6_address[INET6_ADDRSTRLEN];
    char hostname[RECON_MAX_DOMAIN_LEN];
    uint16_t open_ports[100];
    uint32_t open_port_count;
    bool responds_to_ping;
    uint32_t response_time_ms;
} ipv6_scan_result_t;

int ipv6_scan_range(const char *ipv6_prefix, uint32_t prefix_len,
                   ipv6_scan_result_t **results, uint32_t *result_count);
int ipv6_discover_for_domain(const char *domain, ipv6_scan_result_t **results, uint32_t *result_count);

// ============================================================================
// DNS CACHE SNOOPING
// ============================================================================

typedef struct {
    char domain[RECON_MAX_DOMAIN_LEN];
    char nameserver[INET6_ADDRSTRLEN];
    bool cached;
    uint32_t ttl;
    char resolved_ip[INET6_ADDRSTRLEN];
    time_t cache_timestamp;
} dns_cache_snoop_result_t;

int dns_cache_snoop(const char *domain, const char **nameservers, uint32_t ns_count,
                   dns_cache_snoop_result_t **results, uint32_t *result_count);
int dns_cache_timing_attack(const char *domain, const char *nameserver, bool *is_cached);

// ============================================================================
// PASSIVE DNS MONITORING
// ============================================================================

typedef struct {
    char domain[RECON_MAX_DOMAIN_LEN];
    char ip_address[INET6_ADDRSTRLEN];
    time_t first_seen;
    time_t last_seen;
    uint32_t record_type;  // A, AAAA, CNAME, etc.
    char source[128];      // Data source
} passive_dns_record_t;

int passive_dns_query(const char *domain, passive_dns_record_t **records, uint32_t *record_count);
int passive_dns_historical_ips(const char *domain, char ***ip_list, uint32_t *ip_count);

// ============================================================================
// REGIONAL ACCESSIBILITY TESTING
// ============================================================================

typedef struct {
    char region[64];
    char country_code[8];
    char test_ip[INET6_ADDRSTRLEN];
    bool accessible;
    uint32_t response_time_ms;
    uint16_t http_status_code;
    char resolved_ip[INET6_ADDRSTRLEN];
    char error_message[256];
} regional_access_result_t;

int regional_access_test(const char *domain, regional_access_result_t **results, uint32_t *result_count);
int regional_dns_test(const char *domain, const char *region, char **resolved_ips, uint32_t *ip_count);

// ============================================================================
// WEB APPLICATION FINGERPRINTING
// ============================================================================

// Framework detection
typedef struct {
    char framework_name[128];
    char version[64];
    float confidence;
    char detection_method[256];
} framework_detection_t;

// CMS detection
typedef struct {
    char cms_name[128];
    char version[64];
    float confidence;
    char admin_path[256];
    bool admin_accessible;
} cms_detection_t;

// JavaScript library detection
typedef struct {
    char library_name[128];
    char version[64];
    char cdn_url[512];
    bool vulnerable;
    char known_vulnerabilities[512];
} js_library_detection_t;

// Combined web fingerprint result
typedef struct {
    char target_url[1024];

    // Server information
    char server_header[256];
    char x_powered_by[256];

    // Framework detection
    framework_detection_t *frameworks;
    uint32_t framework_count;

    // CMS detection
    cms_detection_t *cms_systems;
    uint32_t cms_count;

    // JavaScript libraries
    js_library_detection_t *js_libraries;
    uint32_t js_library_count;

    // Technologies
    char **technologies;
    uint32_t technology_count;

    // Security headers
    bool has_csp;
    bool has_hsts;
    bool has_cors;
    char security_headers[1024];
} web_fingerprint_result_t;

int web_fingerprint_scan(const char *url, web_fingerprint_result_t *result);
int web_detect_framework(const char *url, framework_detection_t **frameworks, uint32_t *count);
int web_detect_cms(const char *url, cms_detection_t **cms_systems, uint32_t *count);
int web_detect_js_libraries(const char *url, js_library_detection_t **libraries, uint32_t *count);

// ============================================================================
// API ENDPOINT DISCOVERY
// ============================================================================

typedef struct {
    char endpoint_path[512];
    char http_method[16];  // GET, POST, etc.
    uint16_t status_code;
    bool requires_auth;
    char content_type[128];
    uint32_t response_size;
    char api_version[64];
} api_endpoint_t;

typedef struct {
    char base_url[1024];
    api_endpoint_t *endpoints;
    uint32_t endpoint_count;
    char api_type[64];  // REST, GraphQL, SOAP, etc.
    char documentation_url[1024];
} api_discovery_result_t;

int api_discover_endpoints(const char *base_url, api_discovery_result_t *result);
int api_bruteforce_common_paths(const char *base_url, api_endpoint_t **endpoints, uint32_t *count);
int api_detect_graphql(const char *base_url, bool *has_graphql, char *introspection_url);
int api_detect_swagger(const char *base_url, bool *has_swagger, char *swagger_url);

// ============================================================================
// DIRECTORY BRUTE-FORCING
// ============================================================================

typedef struct {
    char path[512];
    uint16_t status_code;
    uint32_t content_length;
    char content_type[128];
    bool is_directory;
    bool requires_auth;
    char redirect_location[512];
} directory_result_t;

typedef struct {
    char base_url[1024];
    directory_result_t *directories;
    uint32_t directory_count;
    uint32_t total_requests;
    uint32_t found_count;
} dirb_scan_result_t;

int dirb_scan(const char *base_url, const char *wordlist_file, dirb_scan_result_t *result);
int dirb_scan_with_extensions(const char *base_url, const char **extensions,
                              uint32_t ext_count, dirb_scan_result_t *result);
int dirb_recursive_scan(const char *base_url, uint32_t max_depth, dirb_scan_result_t *result);

// ============================================================================
// EMAIL SERVER ENUMERATION
// ============================================================================

typedef struct {
    char mx_hostname[RECON_MAX_DOMAIN_LEN];
    char mx_ip[INET6_ADDRSTRLEN];
    uint16_t priority;
    uint16_t smtp_port;
    bool smtp_responsive;
    char smtp_banner[512];
    bool supports_starttls;
    bool supports_auth;
    char supported_auth_methods[256];
} mx_record_result_t;

typedef struct {
    char domain[RECON_MAX_DOMAIN_LEN];
    mx_record_result_t *mx_records;
    uint32_t mx_count;

    // SPF records
    bool has_spf;
    char spf_record[512];

    // DMARC records
    bool has_dmarc;
    char dmarc_record[512];

    // DKIM detection
    bool has_dkim;
    char dkim_selectors[512];
} email_enum_result_t;

int email_enumerate_mx_records(const char *domain, email_enum_result_t *result);
int email_test_smtp_server(const char *mx_host, uint16_t port, mx_record_result_t *result);
int email_discover_spf_record(const char *domain, char *spf_record, size_t max_len);
int email_discover_dmarc_record(const char *domain, char *dmarc_record, size_t max_len);
int email_bruteforce_dkim_selectors(const char *domain, char ***selectors, uint32_t *count);

// ============================================================================
// DOCUMENT METADATA ANALYSIS
// ============================================================================

typedef struct {
    char file_url[1024];
    char file_type[64];  // PDF, DOCX, XLSX, etc.

    // Metadata
    char author[256];
    char creator[256];
    char producer[256];
    time_t creation_date;
    time_t modification_date;

    // Extracted information
    char software_used[256];
    char company_name[256];
    char internal_paths[1024];
    char **email_addresses;
    uint32_t email_count;
    char **usernames;
    uint32_t username_count;
    char **internal_ips;
    uint32_t internal_ip_count;
} document_metadata_t;

int metadata_analyze_document(const char *url, document_metadata_t *result);
int metadata_extract_from_pdf(const char *file_path, document_metadata_t *result);
int metadata_scan_website_documents(const char *base_url, document_metadata_t **results, uint32_t *count);

// ============================================================================
// HISTORICAL DNS RECORDS ANALYSIS
// ============================================================================

typedef struct {
    char domain[RECON_MAX_DOMAIN_LEN];
    char ip_address[INET6_ADDRSTRLEN];
    time_t timestamp;
    char record_type[16];  // A, AAAA, CNAME, MX, etc.
    char source[128];
} historical_dns_record_t;

int historical_dns_query(const char *domain, historical_dns_record_t **records, uint32_t *count);
int historical_dns_find_origin_candidates(const char *domain, char ***ip_candidates, uint32_t *count);

// ============================================================================
// MASTER ADVANCED RECONNAISSANCE CONTEXT
// ============================================================================

typedef struct {
    recon_context_t base_ctx;

    // Feature enables
    bool enable_ssl_cert_enum;
    bool enable_ipv6_scan;
    bool enable_dns_cache_snoop;
    bool enable_passive_dns;
    bool enable_regional_test;
    bool enable_web_fingerprint;
    bool enable_api_discovery;
    bool enable_dir_bruteforce;
    bool enable_email_enum;
    bool enable_metadata_analysis;
    bool enable_historical_dns;

    // Configuration
    uint32_t max_threads;
    uint32_t timeout_seconds;
    bool use_opsec_delays;

    // Results aggregation
    void *results;  // Generic results pointer
    uint32_t total_findings;

    pthread_mutex_t results_mutex;
} advanced_recon_context_t;

// Master functions
int advanced_recon_init(advanced_recon_context_t *ctx);
void advanced_recon_cleanup(advanced_recon_context_t *ctx);
int advanced_recon_scan_target(advanced_recon_context_t *ctx, const char *target);
void advanced_recon_print_summary(const advanced_recon_context_t *ctx);

#endif // ADVANCED_RECON_H
