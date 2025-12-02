/*
 * CloudClear - AWS (Amazon Web Services) Integration
 *
 * Complete AWS service detection and intelligence
 *
 * Features:
 * - CloudFront CDN detection
 * - AWS WAF detection and rule analysis
 * - Route53 DNS intelligence
 * - AWS Shield (DDoS protection) detection
 * - Elastic Load Balancer detection
 * - API Gateway detection
 * - S3 bucket detection
 *
 * Agent: CLOUD-INTEGRATION
 */

#ifndef AWS_H
#define AWS_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "platform_compat.h"

// AWS configuration constants
#define AWS_MAX_DISTRIBUTIONS 50
#define AWS_MAX_HEADERS 30
#define AWS_MAX_WAF_RULES 100
#define AWS_API_TIMEOUT 30
#define AWS_RATE_LIMIT_MS 1000
#define AWS_MAX_RETRIES 3

// AWS service types
typedef enum {
    AWS_SERVICE_UNKNOWN,
    AWS_SERVICE_CLOUDFRONT,
    AWS_SERVICE_WAF,
    AWS_SERVICE_SHIELD,
    AWS_SERVICE_ROUTE53,
    AWS_SERVICE_ELB,
    AWS_SERVICE_ALB,
    AWS_SERVICE_NLB,
    AWS_SERVICE_API_GATEWAY,
    AWS_SERVICE_S3,
    AWS_SERVICE_GLOBAL_ACCELERATOR,
    AWS_SERVICE_LIGHTSAIL
} aws_service_type_t;

// AWS regions
typedef enum {
    AWS_REGION_UNKNOWN,
    AWS_REGION_US_EAST_1,
    AWS_REGION_US_EAST_2,
    AWS_REGION_US_WEST_1,
    AWS_REGION_US_WEST_2,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_EU_CENTRAL_1,
    AWS_REGION_AP_SOUTHEAST_1,
    AWS_REGION_AP_NORTHEAST_1,
    AWS_REGION_GLOBAL
} aws_region_t;

// AWS detection confidence
typedef enum {
    AWS_CONFIDENCE_NONE = 0,
    AWS_CONFIDENCE_LOW = 25,
    AWS_CONFIDENCE_MEDIUM = 50,
    AWS_CONFIDENCE_HIGH = 75,
    AWS_CONFIDENCE_VERIFIED = 100
} aws_confidence_t;

// CloudFront distribution information
typedef struct {
    char distribution_id[64];
    char domain_name[256];
    char origin_domain[256];
    char price_class[32];
    char edge_location[64];
    bool enabled;
    bool ipv6_enabled;
    bool http2_enabled;
    bool waf_enabled;
    char waf_web_acl_id[128];
    char ssl_certificate_arn[256];
    char comment[512];
} aws_cloudfront_distribution_t;

// AWS WAF information
typedef struct {
    bool waf_detected;
    char web_acl_id[128];
    char web_acl_name[256];
    char rule_ids[AWS_MAX_WAF_RULES][128];
    uint32_t rule_count;
    bool rate_limiting_enabled;
    bool geo_blocking_enabled;
    bool sql_injection_protection;
    bool xss_protection;
    char blocked_countries[50][3];
    uint32_t blocked_country_count;
} aws_waf_info_t;

// AWS Shield information
typedef struct {
    bool shield_detected;
    bool shield_advanced;
    bool ddos_protection_active;
    char protection_id[128];
} aws_shield_info_t;

// AWS Route53 information
typedef struct {
    char hosted_zone_id[64];
    char hosted_zone_name[256];
    uint32_t record_count;
    bool private_zone;
    char nameservers[10][256];
    uint32_t nameserver_count;
} aws_route53_info_t;

// AWS Load Balancer information
typedef struct {
    aws_service_type_t lb_type;
    char lb_name[256];
    char lb_arn[256];
    char dns_name[256];
    char vpc_id[64];
    aws_region_t region;
    bool internet_facing;
    char availability_zones[10][32];
    uint32_t az_count;
} aws_lb_info_t;

// AWS API Gateway information
typedef struct {
    char api_id[64];
    char api_name[256];
    char stage_name[64];
    char rest_api_id[64];
    char endpoint_type[32];
    aws_region_t region;
} aws_api_gateway_info_t;

// AWS S3 information
typedef struct {
    char bucket_name[256];
    aws_region_t region;
    bool website_hosting;
    bool public_access;
    char bucket_url[512];
} aws_s3_info_t;

// AWS detection result
typedef struct {
    bool aws_detected;
    aws_confidence_t confidence;
    char detection_method[256];

    // Detected services
    aws_service_type_t services[10];
    uint32_t service_count;

    // CloudFront
    aws_cloudfront_distribution_t cloudfront;
    char cloudfront_request_id[128];
    char cloudfront_viewer_country[3];
    char cloudfront_pop[16];
    bool cloudfront_cache_hit;

    // WAF
    aws_waf_info_t waf_info;

    // Shield
    aws_shield_info_t shield_info;

    // Route53
    aws_route53_info_t route53_info;

    // Load Balancer
    aws_lb_info_t lb_info;

    // API Gateway
    aws_api_gateway_info_t api_gateway_info;

    // S3
    aws_s3_info_t s3_info;

    // General information
    aws_region_t primary_region;
    char aws_headers[AWS_MAX_HEADERS][2][512];
    uint32_t header_count;

    // Metadata
    time_t detected_at;
    char target_domain[256];
    char target_ip[46];
} aws_detection_result_t;

// AWS API configuration
typedef struct {
    char access_key_id[128];
    char secret_access_key[256];
    char session_token[512];
    aws_region_t default_region;
    bool credentials_configured;
} aws_api_config_t;

// AWS context
typedef struct {
    aws_api_config_t api_config;
    aws_detection_result_t last_result;
    pthread_mutex_t mutex;
    uint32_t detection_count;
    uint32_t api_call_count;
    char last_error[512];
} aws_context_t;

// Initialization and cleanup
int aws_init_context(aws_context_t *ctx);
void aws_cleanup_context(aws_context_t *ctx);
int aws_configure_api(aws_context_t *ctx, const char *access_key_id,
                      const char *secret_access_key, const char *region);

// Detection functions
int aws_detect(const char *domain, aws_detection_result_t *result);
int aws_detect_from_headers(const char *headers, aws_detection_result_t *result);
int aws_detect_from_dns(const char *domain, aws_detection_result_t *result);
int aws_comprehensive_detect(const char *domain, aws_detection_result_t *result);

// CloudFront detection
bool aws_is_cloudfront_header(const char *header_name);
int aws_parse_cloudfront_headers(const char *headers, aws_detection_result_t *result);
bool aws_check_cloudfront_cname(const char *cname);
bool aws_is_cloudfront_ip(const char *ip);

// WAF detection
int aws_detect_waf(const char *domain, const char *headers, aws_waf_info_t *waf_info);
bool aws_is_waf_header(const char *header_name);
int aws_parse_waf_headers(const char *headers, aws_waf_info_t *waf_info);

// Shield detection
int aws_detect_shield(const char *domain, aws_shield_info_t *shield_info);

// Route53 detection
int aws_detect_route53(const char *domain, aws_route53_info_t *route53_info);
bool aws_is_route53_nameserver(const char *nameserver);

// Load Balancer detection
int aws_detect_load_balancer(const char *domain, aws_lb_info_t *lb_info);
bool aws_is_elb_domain(const char *domain);
bool aws_is_alb_domain(const char *domain);

// API Gateway detection
int aws_detect_api_gateway(const char *domain, aws_api_gateway_info_t *api_info);
bool aws_is_api_gateway_domain(const char *domain);

// S3 detection
int aws_detect_s3(const char *domain, aws_s3_info_t *s3_info);
bool aws_is_s3_domain(const char *domain);
bool aws_is_s3_website_domain(const char *domain);

// Service identification
aws_service_type_t aws_identify_service(const aws_detection_result_t *result);
bool aws_detect_multiple_services(const aws_detection_result_t *result);

// IP range detection
bool aws_is_aws_ip(const char *ip);
aws_region_t aws_ip_to_region(const char *ip);

// Utility functions
const char *aws_service_type_to_string(aws_service_type_t service);
const char *aws_region_to_string(aws_region_t region);
const char *aws_confidence_to_string(aws_confidence_t confidence);
void aws_print_detection_result(const aws_detection_result_t *result);
void aws_print_cloudfront_info(const aws_cloudfront_distribution_t *cf);

#endif // AWS_H
