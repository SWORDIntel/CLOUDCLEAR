/*
 * CloudClear - CVE-2025 Vulnerability Detector
 *
 * Detects and analyzes 2025-era CVEs relevant to CDN bypass and infrastructure discovery
 * Focuses on vulnerabilities in popular CDN providers, WAFs, and cloud infrastructure
 *
 * Key CVE Categories:
 * - CDN origin IP exposure vulnerabilities
 * - DNS cache poisoning (CVE-2025-XXXX series)
 * - SSL/TLS certificate validation bypasses
 * - HTTP/2 and HTTP/3 implementation flaws
 * - Cloud metadata service exploits
 *
 * Security Level: CLASSIFIED
 * Agent: SECURITY + RESEARCHER coordination
 */

#ifndef CVE_2025_DETECTOR_H
#define CVE_2025_DETECTOR_H

#include "../common/recon_common.h"
#include <stddef.h>
#include <time.h>
#include <sys/types.h>

// CVE database version
#define CVE_2025_DB_VERSION "2025.01"
#define CVE_2025_MAX_CVES 500
#define CVE_2025_MAX_DESCRIPTION 512

// CVE severity levels (CVSS-based)
typedef enum {
    CVE_SEVERITY_NONE = 0,
    CVE_SEVERITY_LOW,        // CVSS 0.1-3.9
    CVE_SEVERITY_MEDIUM,     // CVSS 4.0-6.9
    CVE_SEVERITY_HIGH,       // CVSS 7.0-8.9
    CVE_SEVERITY_CRITICAL    // CVSS 9.0-10.0
} cve_severity_t;

// CVE exploitation status
typedef enum {
    CVE_EXPLOIT_UNKNOWN,
    CVE_EXPLOIT_NONE,           // No known exploit
    CVE_EXPLOIT_POC,            // Proof of concept exists
    CVE_EXPLOIT_ACTIVE,         // Active exploitation in the wild
    CVE_EXPLOIT_WEAPONIZED      // Weaponized in exploit kits
} cve_exploit_status_t;

// CVE categories relevant to CDN bypass
typedef enum {
    CVE_CAT_CDN_ORIGIN_LEAK,         // CDN origin IP exposure
    CVE_CAT_DNS_CACHE_POISON,        // DNS cache poisoning
    CVE_CAT_SSL_TLS_BYPASS,          // SSL/TLS validation bypass
    CVE_CAT_HTTP2_HTTP3_FLAW,        // HTTP/2, HTTP/3 flaws
    CVE_CAT_CLOUD_METADATA,          // Cloud metadata service exploits
    CVE_CAT_WAF_BYPASS,              // WAF bypass techniques
    CVE_CAT_SUBDOMAIN_TAKEOVER,      // Subdomain takeover
    CVE_CAT_CORS_MISCONFIGURATION,   // CORS policy issues
    CVE_CAT_HEADER_INJECTION,        // HTTP header injection
    CVE_CAT_RATE_LIMIT_BYPASS        // Rate limiting bypass
} cve_category_t;

// Affected vendor/product
typedef struct {
    char vendor[128];
    char product[128];
    char version_start[64];
    char version_end[64];
    bool all_versions;
} cve_affected_product_t;

// CVE entry in database
typedef struct {
    char cve_id[32];                          // e.g., "CVE-2025-12345"
    char title[256];
    char description[CVE_2025_MAX_DESCRIPTION];
    cve_severity_t severity;
    float cvss_score;
    cve_exploit_status_t exploit_status;
    cve_category_t category;
    cve_affected_product_t *affected_products;
    uint32_t affected_product_count;
    time_t disclosure_date;
    time_t last_updated;
    char references[512];                     // URLs to advisories
    char mitigation[512];
    bool affects_cdn_bypass;
} cve_entry_t;

// CVE detection result
typedef struct {
    cve_entry_t cve;
    bool vulnerable;
    float confidence;                         // 0.0-1.0
    char evidence[512];
    char detected_version[128];
    time_t detected_timestamp;
    char remediation_advice[512];
} cve_detection_result_t;

// CVE detection context
typedef struct {
    // CVE database
    cve_entry_t *cve_database;
    uint32_t cve_count;
    uint32_t max_cves;

    // Detection results
    cve_detection_result_t *results;
    uint32_t result_count;
    uint32_t max_results;

    // Statistics
    _Atomic uint32_t vulnerabilities_found;
    _Atomic uint32_t critical_vulnerabilities;
    _Atomic uint32_t exploitable_vulnerabilities;

    // Configuration
    bool check_cdn_origin_leak;
    bool check_dns_vulnerabilities;
    bool check_ssl_tls_issues;
    bool check_http_protocol_flaws;
    bool check_cloud_metadata;
    bool check_waf_bypasses;

    // Thread safety
    pthread_mutex_t detection_mutex;

    // Performance
    time_t last_db_update;
    uint32_t total_checks_performed;
} cve_detection_context_t;

// Function prototypes

// Initialization and cleanup
int cve_detection_init_context(cve_detection_context_t *ctx);
void cve_detection_cleanup_context(cve_detection_context_t *ctx);
int cve_detection_load_database(cve_detection_context_t *ctx, const char *db_file);
int cve_detection_update_database(cve_detection_context_t *ctx);

// Database management
int cve_detection_add_cve(cve_detection_context_t *ctx, const cve_entry_t *cve);
cve_entry_t *cve_detection_find_cve(const cve_detection_context_t *ctx, const char *cve_id);
int cve_detection_filter_by_category(const cve_detection_context_t *ctx,
                                     cve_category_t category,
                                     cve_entry_t **results,
                                     uint32_t *count);
int cve_detection_filter_by_severity(const cve_detection_context_t *ctx,
                                     cve_severity_t min_severity,
                                     cve_entry_t **results,
                                     uint32_t *count);

// Vulnerability detection
int cve_detection_scan_target(cve_detection_context_t *ctx,
                              const char *target,
                              const char *detected_technology,
                              const char *version);
int cve_detection_check_cdn_origin_leak(cve_detection_context_t *ctx,
                                        const char *target,
                                        const char *cdn_provider);
int cve_detection_check_dns_vulnerabilities(cve_detection_context_t *ctx,
                                            const char *target);
int cve_detection_check_ssl_tls_issues(cve_detection_context_t *ctx,
                                       const char *target,
                                       const char *tls_version,
                                       const char *cipher_suite);
int cve_detection_check_http_protocol_flaws(cve_detection_context_t *ctx,
                                            const char *target,
                                            const char *http_version);
int cve_detection_check_cloud_metadata_exposure(cve_detection_context_t *ctx,
                                                const char *target,
                                                const char *cloud_provider);

// Result handling
int cve_detection_add_result(cve_detection_context_t *ctx,
                             const cve_detection_result_t *result);
void cve_detection_print_results(const cve_detection_context_t *ctx);
int cve_detection_export_results_json(const cve_detection_context_t *ctx,
                                      const char *filename);
int cve_detection_export_results_csv(const cve_detection_context_t *ctx,
                                     const char *filename);

// Statistics and reporting
uint32_t cve_detection_get_vulnerability_count(const cve_detection_context_t *ctx);
uint32_t cve_detection_get_critical_count(const cve_detection_context_t *ctx);
uint32_t cve_detection_get_exploitable_count(const cve_detection_context_t *ctx);
void cve_detection_print_statistics(const cve_detection_context_t *ctx);

// Utility functions
const char *cve_severity_to_string(cve_severity_t severity);
const char *cve_exploit_status_to_string(cve_exploit_status_t status);
const char *cve_category_to_string(cve_category_t category);
float cve_calculate_risk_score(const cve_entry_t *cve);

// Built-in CVE database initialization
int cve_detection_init_builtin_database(cve_detection_context_t *ctx);

#endif // CVE_2025_DETECTOR_H
