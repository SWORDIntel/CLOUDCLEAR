/*
 * CloudUnflare Enhanced - CVE-2025 Detection and IP Disclosure Module
 *
 * Detects and enumerates potential IP exposures through known 2025 CVEs:
 * - CVE-2025-4366: Pingora Request Smuggling (Cloudflare)
 * - WAF Bypass via Certificate Exploitation
 * - HTTP Header Smuggling Techniques
 *
 * For authorized penetration testing and security research only
 */

#ifndef CVE_2025_DETECTOR_H
#define CVE_2025_DETECTOR_H

#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include "../common/recon_common.h"

// CVE-2025 Detection constants
#define CVE_2025_4366_NAME "Pingora Request Smuggling"
#define CVE_2025_4366_DESCRIPTION "Cloudflare Pingora caching proxy vulnerable to request smuggling"
#define CVE_2025_4366_AFFECTED_VERSIONS "Pingora with caching support enabled (April 2025)"
#define CVE_2025_4366_CVSS_SCORE 7.5
#define CVE_2025_4366_PATCHED_DATE 1712938800  // April 12, 2025 06:44 UTC

#define CVE_2025_29927_NAME "Next.js Middleware Auth Bypass"
#define CVE_2025_29927_DESCRIPTION "Next.js middleware bypass vulnerability with CVSS 9.1"
#define CVE_2025_29927_CVSS_SCORE 9.1

#define CVE_DETECTION_MAX_TESTS 10
#define CVE_DETECTION_TIMEOUT 30

// CVE detection types
typedef enum {
    CVE_TYPE_REQUEST_SMUGGLING,
    CVE_TYPE_WAF_BYPASS,
    CVE_TYPE_HEADER_INJECTION,
    CVE_TYPE_CERTIFICATE_EXPLOIT,
    CVE_TYPE_DNS_LEAK,
    CVE_TYPE_UNKNOWN
} cve_detection_type_t;

// CVE vulnerability info
typedef struct {
    char cve_id[32];
    char name[256];
    char description[512];
    float cvss_score;
    time_t discovery_date;
    time_t patch_date;
    bool is_patched;
    uint32_t affected_versions;
} cve_vulnerability_t;

// Request smuggling detection parameters
typedef struct {
    bool vulnerable_to_cl_te;      // Content-Length/Transfer-Encoding
    bool vulnerable_to_te_cl;      // Transfer-Encoding/Content-Length
    bool vulnerable_to_te_te;      // Transfer-Encoding/Transfer-Encoding variants
    bool vulnerable_to_crlf_inject; // CRLF injection
    uint32_t response_time_ms;
    char detected_behavior[512];
} request_smuggling_test_t;

// WAF bypass detection parameters
typedef struct {
    bool bypass_via_cert_sharing;  // Shared certificate abuse (CVE-2025 pattern)
    bool bypass_via_alt_domain;    // Alternative domain with same origin
    bool bypass_via_header_injection;
    bool bypass_via_proxy_headers;
    char bypass_method[256];
    char origin_ip_candidate[INET6_ADDRSTRLEN];
    uint32_t confidence_score;     // 0-100
} waf_bypass_test_t;

// DNS leak detection parameters
typedef struct {
    bool leaked_via_dns_prefetch;
    bool leaked_via_dns_over_https;
    bool leaked_via_reverse_dns;
    char discovered_ip[INET6_ADDRSTRLEN];
    time_t discovery_time;
} dns_leak_test_t;

// Comprehensive CVE detection result
typedef struct {
    char target_domain[RECON_MAX_DOMAIN_LEN];
    cve_detection_type_t detection_type;

    // CVE information
    cve_vulnerability_t cve_info;

    // Test results
    request_smuggling_test_t smuggling_test;
    waf_bypass_test_t waf_bypass_test;
    dns_leak_test_t dns_leak_test;

    // Overall detection
    bool vulnerability_detected;
    bool ip_exposure_confirmed;
    char exposed_origin_ip[INET6_ADDRSTRLEN];
    float overall_risk_score;      // 0-100

    // Metadata
    time_t scan_timestamp;
    char error_message[512];
    uint32_t tests_performed;
    uint32_t successful_tests;
} cve_detection_result_t;

// CVE detection context
typedef struct {
    recon_context_t base_ctx;
    cve_vulnerability_t vulnerabilities[CVE_DETECTION_MAX_TESTS];
    uint32_t vulnerability_count;
    cve_detection_result_t *results;
    uint32_t result_count;
    uint32_t max_results;
    bool test_request_smuggling;
    bool test_waf_bypass;
    bool test_dns_leaks;
    pthread_mutex_t results_mutex;
} cve_detection_context_t;

// Function prototypes

// Initialization and configuration
int cve_detection_init_context(cve_detection_context_t *ctx);
void cve_detection_cleanup_context(cve_detection_context_t *ctx);

// CVE information
int cve_detection_load_vuln_database(cve_detection_context_t *ctx);
const cve_vulnerability_t *cve_get_vulnerability_info(const char *cve_id);
bool cve_is_vulnerable(const char *cve_id, const char *version);

// CVE-2025-4366 specific (Pingora Request Smuggling)
int cve_2025_4366_test_request_smuggling(const char *domain, request_smuggling_test_t *result);
int cve_2025_4366_detect_cl_te_vulnerability(const char *domain);
int cve_2025_4366_detect_te_cl_vulnerability(const char *domain);
int cve_2025_4366_detect_crlf_injection(const char *domain);

// CVE-2025 WAF Bypass Detection
int cve_2025_detect_waf_bypass_via_certificate(const char *domain, waf_bypass_test_t *result);
int cve_2025_detect_waf_bypass_via_alt_domain(const char *domain, const char *origin_ip, waf_bypass_test_t *result);
int cve_2025_detect_waf_bypass_via_headers(const char *domain, waf_bypass_test_t *result);

// DNS Leak Detection
int cve_2025_detect_dns_leaks(const char *domain, dns_leak_test_t *result);
int cve_2025_detect_dns_prefetch_leak(const char *domain, char *leaked_ip, size_t ip_size);
int cve_2025_detect_reverse_dns_leak(const char *domain, char *leaked_ip, size_t ip_size);

// Comprehensive detection
int cve_detection_scan_domain(cve_detection_context_t *ctx, const char *domain);
int cve_detection_scan_all_vulns(cve_detection_context_t *ctx, const char *domain);

// Result management
int cve_detection_add_result(cve_detection_context_t *ctx, const cve_detection_result_t *result);
void cve_detection_print_results(const cve_detection_context_t *ctx);
int cve_detection_export_json(const cve_detection_context_t *ctx, const char *filename);

// Utilities
const char *cve_detection_type_to_string(cve_detection_type_t type);
void cve_detection_calculate_risk_score(cve_detection_result_t *result);

#endif // CVE_2025_DETECTOR_H
