/*
 * CloudClear - CVE-2025 Vulnerability Detector Implementation
 *
 * Implements vulnerability detection for CDN bypass and infrastructure discovery
 */

#include "cve_2025_detector.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "platform_compat.h"
#include <ctype.h>

// Initialize CVE detection context
int cve_detection_init_context(cve_detection_context_t *ctx) {
    if (!ctx) return -1;

    memset(ctx, 0, sizeof(cve_detection_context_t));

    // Allocate CVE database
    ctx->max_cves = CVE_2025_MAX_CVES;
    ctx->cve_database = calloc(ctx->max_cves, sizeof(cve_entry_t));
    if (!ctx->cve_database) {
        return -1;
    }

    // Allocate results array
    ctx->max_results = 1000;
    ctx->results = calloc(ctx->max_results, sizeof(cve_detection_result_t));
    if (!ctx->results) {
        free(ctx->cve_database);
        return -1;
    }

    // Initialize mutex
    if (pthread_mutex_init(&ctx->detection_mutex, NULL) != 0) {
        free(ctx->results);
        free(ctx->cve_database);
        return -1;
    }

    // Enable all checks by default
    ctx->check_cdn_origin_leak = true;
    ctx->check_dns_vulnerabilities = true;
    ctx->check_ssl_tls_issues = true;
    ctx->check_http_protocol_flaws = true;
    ctx->check_cloud_metadata = true;
    ctx->check_waf_bypasses = true;

    // Initialize atomic counters
    atomic_store(&ctx->vulnerabilities_found, 0);
    atomic_store(&ctx->critical_vulnerabilities, 0);
    atomic_store(&ctx->exploitable_vulnerabilities, 0);

    ctx->last_db_update = time(NULL);

    // Load built-in CVE database
    cve_detection_init_builtin_database(ctx);

    return 0;
}

// Cleanup CVE detection context
void cve_detection_cleanup_context(cve_detection_context_t *ctx) {
    if (!ctx) return;

    if (ctx->cve_database) {
        for (uint32_t i = 0; i < ctx->cve_count; i++) {
            if (ctx->cve_database[i].affected_products) {
                free(ctx->cve_database[i].affected_products);
            }
        }
        free(ctx->cve_database);
    }

    if (ctx->results) {
        free(ctx->results);
    }

    pthread_mutex_destroy(&ctx->detection_mutex);
}

// Add CVE to database
int cve_detection_add_cve(cve_detection_context_t *ctx, const cve_entry_t *cve) {
    if (!ctx || !cve) return -1;

    pthread_mutex_lock(&ctx->detection_mutex);

    if (ctx->cve_count >= ctx->max_cves) {
        pthread_mutex_unlock(&ctx->detection_mutex);
        return -1;
    }

    memcpy(&ctx->cve_database[ctx->cve_count], cve, sizeof(cve_entry_t));
    ctx->cve_count++;

    pthread_mutex_unlock(&ctx->detection_mutex);
    return 0;
}

// Find CVE by ID
cve_entry_t *cve_detection_find_cve(const cve_detection_context_t *ctx, const char *cve_id) {
    if (!ctx || !cve_id) return NULL;

    for (uint32_t i = 0; i < ctx->cve_count; i++) {
        if (strcasecmp(ctx->cve_database[i].cve_id, cve_id) == 0) {
            return &ctx->cve_database[i];
        }
    }

    return NULL;
}

// Check for CDN origin IP leak vulnerabilities
int cve_detection_check_cdn_origin_leak(cve_detection_context_t *ctx,
                                        const char *target,
                                        const char *cdn_provider) {
    if (!ctx || !target || !cdn_provider) return -1;
    if (!ctx->check_cdn_origin_leak) return 0;

    int vulnerabilities_found = 0;

    for (uint32_t i = 0; i < ctx->cve_count; i++) {
        cve_entry_t *cve = &ctx->cve_database[i];

        if (cve->category != CVE_CAT_CDN_ORIGIN_LEAK) continue;
        if (!cve->affects_cdn_bypass) continue;

        // Check if CVE affects this CDN provider
        for (uint32_t j = 0; j < cve->affected_product_count; j++) {
            if (strcasestr(cve->affected_products[j].vendor, cdn_provider) ||
                strcasestr(cve->affected_products[j].product, cdn_provider)) {

                // Create detection result
                cve_detection_result_t result = {0};
                memcpy(&result.cve, cve, sizeof(cve_entry_t));
                result.vulnerable = true;
                result.confidence = 0.85f;
                snprintf(result.evidence, sizeof(result.evidence),
                        "CDN provider %s may be affected by %s", cdn_provider, cve->cve_id);
                result.detected_timestamp = time(NULL);
                snprintf(result.remediation_advice, sizeof(result.remediation_advice),
                        "%s", cve->mitigation);

                cve_detection_add_result(ctx, &result);
                vulnerabilities_found++;

                atomic_fetch_add(&ctx->vulnerabilities_found, 1);
                if (cve->severity == CVE_SEVERITY_CRITICAL) {
                    atomic_fetch_add(&ctx->critical_vulnerabilities, 1);
                }
                if (cve->exploit_status >= CVE_EXPLOIT_POC) {
                    atomic_fetch_add(&ctx->exploitable_vulnerabilities, 1);
                }
            }
        }
    }

    return vulnerabilities_found;
}

// Check for DNS vulnerabilities
int cve_detection_check_dns_vulnerabilities(cve_detection_context_t *ctx, const char *target) {
    if (!ctx || !target) return -1;
    if (!ctx->check_dns_vulnerabilities) return 0;

    int vulnerabilities_found = 0;

    for (uint32_t i = 0; i < ctx->cve_count; i++) {
        cve_entry_t *cve = &ctx->cve_database[i];

        if (cve->category != CVE_CAT_DNS_CACHE_POISON) continue;

        // DNS vulnerabilities typically affect the infrastructure
        cve_detection_result_t result = {0};
        memcpy(&result.cve, cve, sizeof(cve_entry_t));
        result.vulnerable = true;
        result.confidence = 0.65f;  // Lower confidence without version detection
        snprintf(result.evidence, sizeof(result.evidence),
                "DNS infrastructure for %s may be affected by %s", target, cve->cve_id);
        result.detected_timestamp = time(NULL);
        snprintf(result.remediation_advice, sizeof(result.remediation_advice),
                "%s", cve->mitigation);

        cve_detection_add_result(ctx, &result);
        vulnerabilities_found++;
    }

    return vulnerabilities_found;
}

// Check for SSL/TLS issues
int cve_detection_check_ssl_tls_issues(cve_detection_context_t *ctx,
                                       const char *target,
                                       const char *tls_version,
                                       const char *cipher_suite) {
    if (!ctx || !target) return -1;
    if (!ctx->check_ssl_tls_issues) return 0;

    int vulnerabilities_found = 0;

    for (uint32_t i = 0; i < ctx->cve_count; i++) {
        cve_entry_t *cve = &ctx->cve_database[i];

        if (cve->category != CVE_CAT_SSL_TLS_BYPASS) continue;

        // Check if detected TLS version/cipher matches vulnerable configuration
        bool matches = false;
        if (tls_version && strcasestr(cve->description, tls_version)) {
            matches = true;
        }
        if (cipher_suite && strcasestr(cve->description, cipher_suite)) {
            matches = true;
        }

        if (matches || (!tls_version && !cipher_suite)) {
            cve_detection_result_t result = {0};
            memcpy(&result.cve, cve, sizeof(cve_entry_t));
            result.vulnerable = true;
            result.confidence = matches ? 0.90f : 0.60f;
            snprintf(result.evidence, sizeof(result.evidence),
                    "SSL/TLS configuration for %s may be affected by %s", target, cve->cve_id);
            if (tls_version) {
                snprintf(result.detected_version, sizeof(result.detected_version),
                        "%s", tls_version);
            }
            result.detected_timestamp = time(NULL);
            snprintf(result.remediation_advice, sizeof(result.remediation_advice),
                    "%s", cve->mitigation);

            cve_detection_add_result(ctx, &result);
            vulnerabilities_found++;
        }
    }

    return vulnerabilities_found;
}

// Add detection result
int cve_detection_add_result(cve_detection_context_t *ctx,
                             const cve_detection_result_t *result) {
    if (!ctx || !result) return -1;

    pthread_mutex_lock(&ctx->detection_mutex);

    if (ctx->result_count >= ctx->max_results) {
        pthread_mutex_unlock(&ctx->detection_mutex);
        return -1;
    }

    memcpy(&ctx->results[ctx->result_count], result, sizeof(cve_detection_result_t));
    ctx->result_count++;

    pthread_mutex_unlock(&ctx->detection_mutex);
    return 0;
}

// Print detection results
void cve_detection_print_results(const cve_detection_context_t *ctx) {
    if (!ctx) return;

    printf("\n=== CVE-2025 Vulnerability Detection Results ===\n");
    printf("Total Vulnerabilities Found: %u\n", atomic_load(&ctx->vulnerabilities_found));
    printf("Critical Vulnerabilities: %u\n", atomic_load(&ctx->critical_vulnerabilities));
    printf("Exploitable Vulnerabilities: %u\n", atomic_load(&ctx->exploitable_vulnerabilities));
    printf("\n");

    for (uint32_t i = 0; i < ctx->result_count; i++) {
        const cve_detection_result_t *result = &ctx->results[i];

        printf("[%u] %s - %s\n", i + 1, result->cve.cve_id, result->cve.title);
        printf("    Severity: %s (CVSS: %.1f)\n",
               cve_severity_to_string(result->cve.severity),
               result->cve.cvss_score);
        printf("    Category: %s\n", cve_category_to_string(result->cve.category));
        printf("    Exploit Status: %s\n", cve_exploit_status_to_string(result->cve.exploit_status));
        printf("    Confidence: %.0f%%\n", result->confidence * 100);
        printf("    Evidence: %s\n", result->evidence);
        if (strlen(result->remediation_advice) > 0) {
            printf("    Remediation: %s\n", result->remediation_advice);
        }
        printf("\n");
    }
}

// Utility: Severity to string
const char *cve_severity_to_string(cve_severity_t severity) {
    switch (severity) {
        case CVE_SEVERITY_NONE: return "NONE";
        case CVE_SEVERITY_LOW: return "LOW";
        case CVE_SEVERITY_MEDIUM: return "MEDIUM";
        case CVE_SEVERITY_HIGH: return "HIGH";
        case CVE_SEVERITY_CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

// Utility: Exploit status to string
const char *cve_exploit_status_to_string(cve_exploit_status_t status) {
    switch (status) {
        case CVE_EXPLOIT_UNKNOWN: return "UNKNOWN";
        case CVE_EXPLOIT_NONE: return "NO KNOWN EXPLOIT";
        case CVE_EXPLOIT_POC: return "POC AVAILABLE";
        case CVE_EXPLOIT_ACTIVE: return "ACTIVELY EXPLOITED";
        case CVE_EXPLOIT_WEAPONIZED: return "WEAPONIZED";
        default: return "UNKNOWN";
    }
}

// Utility: Category to string
const char *cve_category_to_string(cve_category_t category) {
    switch (category) {
        case CVE_CAT_CDN_ORIGIN_LEAK: return "CDN Origin IP Leak";
        case CVE_CAT_DNS_CACHE_POISON: return "DNS Cache Poisoning";
        case CVE_CAT_SSL_TLS_BYPASS: return "SSL/TLS Bypass";
        case CVE_CAT_HTTP2_HTTP3_FLAW: return "HTTP/2 or HTTP/3 Flaw";
        case CVE_CAT_CLOUD_METADATA: return "Cloud Metadata Exposure";
        case CVE_CAT_WAF_BYPASS: return "WAF Bypass";
        case CVE_CAT_SUBDOMAIN_TAKEOVER: return "Subdomain Takeover";
        case CVE_CAT_CORS_MISCONFIGURATION: return "CORS Misconfiguration";
        case CVE_CAT_HEADER_INJECTION: return "HTTP Header Injection";
        case CVE_CAT_RATE_LIMIT_BYPASS: return "Rate Limiting Bypass";
        default: return "UNKNOWN";
    }
}

// Initialize built-in CVE database with 2025 vulnerabilities
int cve_detection_init_builtin_database(cve_detection_context_t *ctx) {
    if (!ctx) return -1;

    // Example CVE-2025-1001: Cloudflare Origin IP Exposure via HTTP/3 Alt-Svc
    cve_entry_t cve1 = {
        .cve_id = "CVE-2025-1001",
        .title = "Cloudflare Origin IP Exposure via HTTP/3 Alt-Svc Header",
        .description = "HTTP/3 Alt-Svc header can leak origin IP addresses when improperly configured",
        .severity = CVE_SEVERITY_HIGH,
        .cvss_score = 7.5,
        .exploit_status = CVE_EXPLOIT_POC,
        .category = CVE_CAT_CDN_ORIGIN_LEAK,
        .affected_product_count = 1,
        .disclosure_date = time(NULL) - (30 * 24 * 3600),
        .affects_cdn_bypass = true
    };
    strncpy(cve1.references, "https://example.com/cve-2025-1001", sizeof(cve1.references) - 1);
    strncpy(cve1.mitigation, "Disable HTTP/3 Alt-Svc header or properly configure origin hiding", sizeof(cve1.mitigation) - 1);

    cve1.affected_products = calloc(1, sizeof(cve_affected_product_t));
    strncpy(cve1.affected_products[0].vendor, "Cloudflare", 127);
    strncpy(cve1.affected_products[0].product, "CDN", 127);
    cve1.affected_products[0].all_versions = true;

    cve_detection_add_cve(ctx, &cve1);

    // Example CVE-2025-1002: DNS Cache Poisoning via DNSSEC Validation Bypass
    cve_entry_t cve2 = {
        .cve_id = "CVE-2025-1002",
        .title = "DNS Cache Poisoning via DNSSEC Validation Bypass",
        .description = "DNSSEC validation can be bypassed allowing cache poisoning attacks",
        .severity = CVE_SEVERITY_CRITICAL,
        .cvss_score = 9.1,
        .exploit_status = CVE_EXPLOIT_ACTIVE,
        .category = CVE_CAT_DNS_CACHE_POISON,
        .disclosure_date = time(NULL) - (60 * 24 * 3600),
        .affects_cdn_bypass = true
    };
    strncpy(cve2.mitigation, "Update DNS resolver software and enable strict DNSSEC validation", sizeof(cve2.mitigation) - 1);

    cve_detection_add_cve(ctx, &cve2);

    // Add more CVEs as needed...

    printf("[CVE-2025] Loaded %u CVEs into detection database\n", ctx->cve_count);
    return 0;
}

// Get statistics
uint32_t cve_detection_get_vulnerability_count(const cve_detection_context_t *ctx) {
    return ctx ? atomic_load(&ctx->vulnerabilities_found) : 0;
}

uint32_t cve_detection_get_critical_count(const cve_detection_context_t *ctx) {
    return ctx ? atomic_load(&ctx->critical_vulnerabilities) : 0;
}

uint32_t cve_detection_get_exploitable_count(const cve_detection_context_t *ctx) {
    return ctx ? atomic_load(&ctx->exploitable_vulnerabilities) : 0;
}

// Scan target for vulnerabilities
int cve_detection_scan_target(cve_detection_context_t *ctx,
                              const char *target,
                              const char *detected_technology,
                              const char *version) {
    if (!ctx || !target) return -1;

    int vulnerabilities_found = 0;

    // Scan through CVE database for matches
    for (uint32_t i = 0; i < ctx->cve_count; i++) {
        cve_entry_t *cve = &ctx->cve_database[i];
        bool matches = false;

        // Check if technology matches
        if (detected_technology && cve->affected_products) {
            for (uint32_t j = 0; j < cve->affected_product_count; j++) {
                if (strcasestr(detected_technology, cve->affected_products[j].product) ||
                    strcasestr(cve->affected_products[j].product, detected_technology)) {
                    matches = true;
                    break;
                }
            }
        }

        // If no specific technology, check all CVEs that affect CDN bypass
        if (!detected_technology && cve->affects_cdn_bypass) {
            matches = true;
        }

        if (matches) {
            cve_detection_result_t result = {0};
            memcpy(&result.cve, cve, sizeof(cve_entry_t));
            result.vulnerable = true;
            result.confidence = detected_technology ? 0.75f : 0.50f;
            snprintf(result.evidence, sizeof(result.evidence),
                    "Target %s may be affected by %s", target, cve->cve_id);
            if (version) {
                snprintf(result.detected_version, sizeof(result.detected_version), "%s", version);
            }
            result.detected_timestamp = time(NULL);
            snprintf(result.remediation_advice, sizeof(result.remediation_advice),
                    "%s", cve->mitigation);

            cve_detection_add_result(ctx, &result);
            atomic_fetch_add(&ctx->vulnerabilities_found, 1);
            if (cve->severity == CVE_SEVERITY_CRITICAL) {
                atomic_fetch_add(&ctx->critical_vulnerabilities, 1);
            }
            if (cve->exploit_status >= CVE_EXPLOIT_POC) {
                atomic_fetch_add(&ctx->exploitable_vulnerabilities, 1);
            }
            vulnerabilities_found++;
        }
    }

    return vulnerabilities_found;
}

// Export results to JSON
int cve_detection_export_results_json(const cve_detection_context_t *ctx,
                                      const char *filename) {
    if (!ctx || !filename) return -1;

    FILE *fp = fopen(filename, "w");
    if (!fp) return -1;

    fprintf(fp, "{\n");
    fprintf(fp, "  \"cve_detection_results\": {\n");
    fprintf(fp, "    \"total_vulnerabilities\": %u,\n", atomic_load(&ctx->vulnerabilities_found));
    fprintf(fp, "    \"critical_count\": %u,\n", atomic_load(&ctx->critical_vulnerabilities));
    fprintf(fp, "    \"exploitable_count\": %u,\n", atomic_load(&ctx->exploitable_vulnerabilities));
    fprintf(fp, "    \"results\": [\n");

    for (uint32_t i = 0; i < ctx->result_count; i++) {
        const cve_detection_result_t *result = &ctx->results[i];
        fprintf(fp, "      {\n");
        fprintf(fp, "        \"cve_id\": \"%s\",\n", result->cve.cve_id);
        fprintf(fp, "        \"title\": \"%s\",\n", result->cve.title);
        fprintf(fp, "        \"severity\": \"%s\",\n", cve_severity_to_string(result->cve.severity));
        fprintf(fp, "        \"cvss_score\": %.1f,\n", result->cve.cvss_score);
        fprintf(fp, "        \"vulnerable\": %s,\n", result->vulnerable ? "true" : "false");
        fprintf(fp, "        \"confidence\": %.2f,\n", result->confidence);
        fprintf(fp, "        \"evidence\": \"%s\",\n", result->evidence);
        fprintf(fp, "        \"category\": \"%s\",\n", cve_category_to_string(result->cve.category));
        fprintf(fp, "        \"exploit_status\": \"%s\"\n", cve_exploit_status_to_string(result->cve.exploit_status));
        fprintf(fp, "      }%s\n", (i < ctx->result_count - 1) ? "," : "");
    }

    fprintf(fp, "    ]\n");
    fprintf(fp, "  }\n");
    fprintf(fp, "}\n");

    fclose(fp);
    return 0;
}
