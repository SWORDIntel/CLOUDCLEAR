/*
 * CloudClear - Unified Cloud Provider Detection Module
 *
 * Central interface for detecting all cloud service providers
 *
 * Supported Providers:
 * - Akamai Edge
 * - AWS (CloudFront, WAF, Shield, Route53, ELB, API Gateway, S3)
 * - Azure (Front Door, CDN, WAF, Application Gateway)
 * - GCP (Cloud CDN, Cloud Armor, Load Balancer)
 * - Cloudflare
 * - Fastly
 * - DigitalOcean
 * - Oracle Cloud
 * - Alibaba Cloud
 *
 * Intelligence Services:
 * - Shodan
 * - Censys
 * - VirusTotal
 */

#ifndef CLOUD_DETECTOR_H
#define CLOUD_DETECTOR_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#define CLOUD_MAX_PROVIDERS 20
#define CLOUD_MAX_SERVICES 50

typedef enum {
    CLOUD_PROVIDER_UNKNOWN,
    CLOUD_PROVIDER_AKAMAI,
    CLOUD_PROVIDER_AWS,
    CLOUD_PROVIDER_AZURE,
    CLOUD_PROVIDER_GCP,
    CLOUD_PROVIDER_CLOUDFLARE,
    CLOUD_PROVIDER_FASTLY,
    CLOUD_PROVIDER_DIGITALOCEAN,
    CLOUD_PROVIDER_ORACLE,
    CLOUD_PROVIDER_ALIBABA,
    CLOUD_PROVIDER_MAXCDN,
    CLOUD_PROVIDER_BUNNYCDN,
    CLOUD_PROVIDER_KEYCDN,
    CLOUD_PROVIDER_CLOUDFRONT
} cloud_provider_t;

typedef struct {
    cloud_provider_t provider;
    char provider_name[64];
    char service_name[128];
    uint32_t confidence;
    char detection_method[256];
    char details[512];
} cloud_service_detection_t;

typedef struct {
    char target_domain[256];
    char target_ip[46];

    // Detected providers
    cloud_provider_t providers[CLOUD_MAX_PROVIDERS];
    uint32_t provider_count;

    // Detected services
    cloud_service_detection_t services[CLOUD_MAX_SERVICES];
    uint32_t service_count;

    // Primary provider (highest confidence)
    cloud_provider_t primary_provider;
    uint32_t primary_confidence;

    // Detection flags
    bool cdn_detected;
    bool waf_detected;
    bool ddos_protection_detected;
    bool load_balancer_detected;

    // CDN/Edge information
    char edge_location[64];
    char cache_status[64];
    bool cache_hit;

    // WAF information
    char waf_vendor[64];
    bool waf_blocking;

    // Performance metrics
    time_t detection_start;
    time_t detection_end;
    uint32_t detection_time_ms;

    // Metadata
    time_t detected_at;
} cloud_detection_result_t;

typedef struct {
    // Enable/disable specific providers
    bool enable_akamai;
    bool enable_aws;
    bool enable_azure;
    bool enable_gcp;
    bool enable_cloudflare;
    bool enable_fastly;
    bool enable_digitalocean;
    bool enable_oracle;
    bool enable_alibaba;

    // Enable intelligence services
    bool enable_shodan;
    bool enable_censys;
    bool enable_virustotal;

    // Detection options
    bool use_dns_detection;
    bool use_http_detection;
    bool use_certificate_detection;
    bool use_ip_range_detection;

    // Performance options
    uint32_t max_detection_time_ms;
    bool parallel_detection;
    bool detailed_analysis;
} cloud_detection_config_t;

// Main detection functions
int cloud_detect_all(const char *target, cloud_detection_result_t *result,
                     cloud_detection_config_t *config);
int cloud_detect_from_headers(const char *headers, cloud_detection_result_t *result);
int cloud_detect_from_dns(const char *domain, cloud_detection_result_t *result);

// Provider-specific detection
bool cloud_detect_akamai(const char *target, cloud_detection_result_t *result);
bool cloud_detect_aws(const char *target, cloud_detection_result_t *result);
bool cloud_detect_azure(const char *target, cloud_detection_result_t *result);
bool cloud_detect_gcp(const char *target, cloud_detection_result_t *result);
bool cloud_detect_cloudflare(const char *target, cloud_detection_result_t *result);
bool cloud_detect_fastly(const char *target, cloud_detection_result_t *result);

// Service enumeration
int cloud_enumerate_services(cloud_detection_result_t *result);
int cloud_identify_primary_provider(cloud_detection_result_t *result);

// Intelligence enrichment
int cloud_enrich_with_shodan(const char *ip, cloud_detection_result_t *result);
int cloud_enrich_with_censys(const char *domain, cloud_detection_result_t *result);
int cloud_enrich_with_virustotal(const char *domain, cloud_detection_result_t *result);

// Utility functions
const char *cloud_provider_to_string(cloud_provider_t provider);
void cloud_print_detection_result(const cloud_detection_result_t *result);
void cloud_print_summary(const cloud_detection_result_t *result);
void cloud_export_json(const cloud_detection_result_t *result, char *json_output, size_t size);

// Configuration
void cloud_detection_config_default(cloud_detection_config_t *config);
void cloud_detection_config_all_enabled(cloud_detection_config_t *config);
void cloud_detection_config_fast(cloud_detection_config_t *config);

#endif // CLOUD_DETECTOR_H
