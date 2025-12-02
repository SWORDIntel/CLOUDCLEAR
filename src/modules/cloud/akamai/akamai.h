/*
 * CloudClear - Akamai Edge Integration
 *
 * Complete Akamai Edge detection and property intelligence
 *
 * Features:
 * - Akamai Edge DNS detection
 * - Property lookup and configuration analysis
 * - Edge hostname detection
 * - SureRoute mapping
 * - Ion property detection
 * - Kona Site Defender (WAF) integration
 * - Ghost/GTM detection
 *
 * Agent: CLOUD-INTEGRATION
 */

#ifndef AKAMAI_H
#define AKAMAI_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include <curl/curl.h>
#include "platform_compat.h"

// Akamai configuration constants
#define AKAMAI_MAX_PROPERTIES 100
#define AKAMAI_MAX_EDGE_HOSTNAMES 50
#define AKAMAI_MAX_HEADERS 30
#define AKAMAI_API_TIMEOUT 30
#define AKAMAI_RATE_LIMIT_MS 1000
#define AKAMAI_MAX_RETRIES 3
#define AKAMAI_MAX_CERT_SANS 50

// Akamai service types
typedef enum {
    AKAMAI_SERVICE_UNKNOWN,
    AKAMAI_SERVICE_CDN,
    AKAMAI_SERVICE_ION,
    AKAMAI_SERVICE_KONA_WAF,
    AKAMAI_SERVICE_PROLEXIC_DDOS,
    AKAMAI_SERVICE_BOT_MANAGER,
    AKAMAI_SERVICE_IMAGE_MANAGER,
    AKAMAI_SERVICE_MEDIA_DELIVERY,
    AKAMAI_SERVICE_DOWNLOAD_DELIVERY,
    AKAMAI_SERVICE_WEB_APP_ACCELERATOR,
    AKAMAI_SERVICE_API_ACCELERATION,
    AKAMAI_SERVICE_SUREROUTE,
    AKAMAI_SERVICE_SITESHIELD
} akamai_service_type_t;

// Akamai edge network types
typedef enum {
    AKAMAI_NETWORK_UNKNOWN,
    AKAMAI_NETWORK_PRODUCTION,
    AKAMAI_NETWORK_STAGING,
    AKAMAI_NETWORK_CHINA_CDN,
    AKAMAI_NETWORK_ENHANCED_TLS
} akamai_network_type_t;

// Akamai detection confidence
typedef enum {
    AKAMAI_CONFIDENCE_NONE = 0,
    AKAMAI_CONFIDENCE_LOW = 25,
    AKAMAI_CONFIDENCE_MEDIUM = 50,
    AKAMAI_CONFIDENCE_HIGH = 75,
    AKAMAI_CONFIDENCE_VERIFIED = 100
} akamai_confidence_t;

// Akamai header information
typedef struct {
    char name[128];
    char value[512];
} akamai_header_t;

// Akamai edge hostname information
typedef struct {
    char edge_hostname[256];
    char cname_target[256];
    char edge_ip[46];
    char ghost_location[64];
    char network_location[64];
    bool is_secure;
    bool is_enhanced_tls;
    uint32_t ttl;
} akamai_edge_hostname_t;

// Akamai property information
typedef struct {
    char property_name[256];
    char property_id[128];
    char contract_id[128];
    char group_id[128];
    akamai_service_type_t service_type;
    bool ion_enabled;
    bool sureroute_enabled;
    bool tiered_distribution;
    bool prefetch_enabled;
    char origin_hostname[256];
    char cp_code[32];
} akamai_property_t;

// Akamai WAF (Kona) information
typedef struct {
    bool waf_detected;
    char waf_version[64];
    char policy_id[128];
    char attack_groups[512];
    bool bot_manager_enabled;
    bool rate_limiting_enabled;
    bool client_reputation_enabled;
    uint32_t security_score;
} akamai_waf_info_t;

// Akamai SiteShield information
typedef struct {
    bool siteshield_detected;
    char map_id[128];
    char ip_ranges[10][46];
    uint32_t ip_range_count;
    bool acknowledgment_required;
} akamai_siteshield_t;

// Akamai detection result
typedef struct {
    bool akamai_detected;
    akamai_confidence_t confidence;
    char detection_method[256];

    // Network information
    akamai_network_type_t network_type;
    char edge_server_ip[46];
    char ghost_ip[46];
    char reference_id[128];
    char cache_status[64];

    // Edge hostnames
    akamai_edge_hostname_t edge_hostnames[AKAMAI_MAX_EDGE_HOSTNAMES];
    uint32_t edge_hostname_count;

    // Properties
    akamai_property_t properties[AKAMAI_MAX_PROPERTIES];
    uint32_t property_count;

    // Services
    akamai_service_type_t services[10];
    uint32_t service_count;

    // WAF/Security
    akamai_waf_info_t waf_info;
    akamai_siteshield_t siteshield;

    // HTTP headers
    akamai_header_t headers[AKAMAI_MAX_HEADERS];
    uint32_t header_count;

    // DNS information
    char cname_chain[10][256];
    uint32_t cname_chain_length;

    // Certificate information
    char cert_subject[256];
    char cert_san[AKAMAI_MAX_CERT_SANS][256];
    uint32_t cert_san_count;

    // Performance metrics
    uint32_t response_time_ms;
    bool cache_hit;
    char cache_key[256];

    // Metadata
    time_t detected_at;
    char target_domain[256];
} akamai_detection_result_t;

// Akamai API configuration
typedef struct {
    char client_token[256];
    char client_secret[256];
    char access_token[256];
    char base_url[512];
    bool credentials_configured;
} akamai_api_config_t;

// Akamai context
typedef struct {
    akamai_api_config_t api_config;
    akamai_detection_result_t last_result;
    pthread_mutex_t mutex;
    uint32_t detection_count;
    uint32_t api_call_count;
    char last_error[512];
} akamai_context_t;

// Initialization and cleanup
int akamai_init_context(akamai_context_t *ctx);
void akamai_cleanup_context(akamai_context_t *ctx);
int akamai_configure_api(akamai_context_t *ctx, const char *client_token,
                         const char *client_secret, const char *access_token);

// Detection functions
int akamai_detect(const char *domain, akamai_detection_result_t *result);
int akamai_detect_from_headers(const char *headers, akamai_detection_result_t *result);
int akamai_detect_from_dns(const char *domain, akamai_detection_result_t *result);
int akamai_detect_from_certificate(const char *domain, akamai_detection_result_t *result);
int akamai_comprehensive_detect(const char *domain, akamai_detection_result_t *result);

// Header detection
bool akamai_check_header_signature(const char *headers);
int akamai_parse_headers(const char *headers, akamai_detection_result_t *result);
bool akamai_is_ghost_header(const char *header_name);
bool akamai_is_cache_header(const char *header_name);

// DNS detection
bool akamai_check_cname_pattern(const char *cname);
int akamai_resolve_edge_hostnames(const char *domain, akamai_detection_result_t *result);
int akamai_trace_cname_chain(const char *domain, akamai_detection_result_t *result);

// IP range detection
bool akamai_is_edge_ip(const char *ip);
bool akamai_is_siteshield_ip(const char *ip);
int akamai_lookup_ip_geolocation(const char *ip, char *location, size_t location_size);

// Service detection
akamai_service_type_t akamai_identify_service(const akamai_detection_result_t *result);
bool akamai_detect_ion(const akamai_detection_result_t *result);
bool akamai_detect_kona_waf(const akamai_detection_result_t *result);
bool akamai_detect_bot_manager(const akamai_detection_result_t *result);
bool akamai_detect_sureroute(const akamai_detection_result_t *result);

// API functions (requires credentials)
int akamai_api_get_property_info(akamai_context_t *ctx, const char *hostname,
                                  akamai_property_t *property);
int akamai_api_list_edge_hostnames(akamai_context_t *ctx, const char *property_id,
                                    akamai_edge_hostname_t *edge_hostnames, uint32_t *count);
int akamai_api_get_cp_code_info(akamai_context_t *ctx, const char *cp_code,
                                 char *info, size_t info_size);

// WAF analysis
int akamai_analyze_waf(const char *domain, const char *headers,
                       akamai_waf_info_t *waf_info);
int akamai_detect_waf_rules(const char *response_body, char *rules, size_t rules_size);
int akamai_test_waf_bypass(const char *domain, bool *bypassable);

// Certificate analysis
int akamai_parse_certificate(const char *domain, akamai_detection_result_t *result);
bool akamai_is_akamai_certificate(const char *cert_subject);

// Utility functions
const char *akamai_service_type_to_string(akamai_service_type_t service);
const char *akamai_network_type_to_string(akamai_network_type_t network);
const char *akamai_confidence_to_string(akamai_confidence_t confidence);
void akamai_print_detection_result(const akamai_detection_result_t *result);
void akamai_print_property_info(const akamai_property_t *property);

// Advanced analysis
int akamai_fingerprint_configuration(const char *domain, char *fingerprint, size_t size);
int akamai_estimate_cache_behavior(const akamai_detection_result_t *result,
                                    char *behavior, size_t size);
int akamai_identify_origin_shield(const akamai_detection_result_t *result,
                                   char *shield_location, size_t size);

#endif // AKAMAI_H
