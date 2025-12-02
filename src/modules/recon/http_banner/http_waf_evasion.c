/*
 * CloudClear - HTTP WAF Evasion Module Implementation
 *
 * Advanced Web Application Firewall evasion techniques
 * Adapted from public WAF bypass research for origin IP discovery
 *
 * IMPORTANT: For authorized security testing only
 */

#include "http_waf_evasion.h"
#include "../common/recon_opsec.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include "platform_compat.h"

// WAF signature database
static const char *cloudflare_signatures[] = {
    "cf-ray",
    "cloudflare",
    "__cfduid",
    "cf-cache-status",
    "cf-request-id"
};

static const char *akamai_signatures[] = {
    "akamai",
    "akamai-ghost",
    "akamai-x-cache",
    "akamai-grn"
};

static const char *aws_waf_signatures[] = {
    "x-amzn-requestid",
    "x-amz-cf-id",
    "x-amzn-trace-id"
};

static const char *imperva_signatures[] = {
    "x-iinfo",
    "incap_ses",
    "visid_incap",
    "imperva"
};

// Trusted IP addresses for spoofing
static const char *trusted_ips[] = {
    "8.8.8.8",           // Google DNS
    "8.8.4.4",           // Google DNS
    "1.1.1.1",           // Cloudflare DNS
    "1.0.0.1",           // Cloudflare DNS
    "208.67.222.222",    // OpenDNS
    "208.67.220.220"     // OpenDNS
};

// Initialize WAF evasion context
int waf_evasion_init_context(waf_evasion_context_t *ctx) {
    if (!ctx) return -1;

    memset(ctx, 0, sizeof(waf_evasion_context_t));

    if (pthread_mutex_init(&ctx->mutex, NULL) != 0) {
        return -1;
    }

    // Set default configuration
    waf_evasion_configure_moderate(&ctx->config);

    return 0;
}

// Cleanup WAF evasion context
void waf_evasion_cleanup_context(waf_evasion_context_t *ctx) {
    if (!ctx) return;

    pthread_mutex_destroy(&ctx->mutex);
    memset(ctx, 0, sizeof(waf_evasion_context_t));
}

// Set WAF evasion configuration
int waf_evasion_set_config(waf_evasion_context_t *ctx, const waf_evasion_config_t *config) {
    if (!ctx || !config) return -1;

    pthread_mutex_lock(&ctx->mutex);
    ctx->config = *config;
    pthread_mutex_unlock(&ctx->mutex);

    return 0;
}

// Detect WAF from response headers and body
int waf_detect_from_response(const char *headers, const char *body, waf_detection_result_t *result) {
    if (!headers || !result) return -1;

    memset(result, 0, sizeof(waf_detection_result_t));

    // Check headers for WAF signatures
    if (waf_is_cloudflare(headers)) {
        result->waf_detected = true;
        result->waf_type = WAF_TYPE_CLOUDFLARE;
        strcpy(result->waf_name, "Cloudflare");
        result->confidence_score = 0.95;
        strcpy(result->detection_method, "Header signature match");
    } else if (waf_is_akamai(headers)) {
        result->waf_detected = true;
        result->waf_type = WAF_TYPE_AKAMAI;
        strcpy(result->waf_name, "Akamai");
        result->confidence_score = 0.90;
        strcpy(result->detection_method, "Header signature match");
    } else if (waf_is_aws_waf(headers)) {
        result->waf_detected = true;
        result->waf_type = WAF_TYPE_AWS_WAF;
        strcpy(result->waf_name, "AWS WAF");
        result->confidence_score = 0.85;
        strcpy(result->detection_method, "Header signature match");
    }

    // Check for generic WAF indicators
    if (!result->waf_detected) {
        if (strstr(headers, "X-WAF") || strstr(headers, "X-Firewall")) {
            result->waf_detected = true;
            result->waf_type = WAF_TYPE_UNKNOWN;
            strcpy(result->waf_name, "Unknown WAF");
            result->confidence_score = 0.60;
            strcpy(result->detection_method, "Generic WAF header");
        }
    }

    // Check body for WAF indicators
    if (body && !result->waf_detected) {
        if (strstr(body, "Access Denied") || strstr(body, "Forbidden") ||
            strstr(body, "blocked") || strstr(body, "security policy")) {
            result->waf_detected = true;
            result->waf_type = WAF_TYPE_UNKNOWN;
            strcpy(result->waf_name, "Unknown WAF");
            result->confidence_score = 0.50;
            strcpy(result->detection_method, "Body content analysis");
            result->blocking_detected = true;
        }
    }

    return 0;
}

// Check if Cloudflare WAF is present
bool waf_is_cloudflare(const char *headers) {
    if (!headers) return false;

    for (size_t i = 0; i < sizeof(cloudflare_signatures) / sizeof(cloudflare_signatures[0]); i++) {
        if (strcasestr(headers, cloudflare_signatures[i]) != NULL) {
            return true;
        }
    }
    return false;
}

// Check if Akamai WAF is present
bool waf_is_akamai(const char *headers) {
    if (!headers) return false;

    for (size_t i = 0; i < sizeof(akamai_signatures) / sizeof(akamai_signatures[0]); i++) {
        if (strcasestr(headers, akamai_signatures[i]) != NULL) {
            return true;
        }
    }
    return false;
}

// Check if AWS WAF is present
bool waf_is_aws_waf(const char *headers) {
    if (!headers) return false;

    for (size_t i = 0; i < sizeof(aws_waf_signatures) / sizeof(aws_waf_signatures[0]); i++) {
        if (strcasestr(headers, aws_waf_signatures[i]) != NULL) {
            return true;
        }
    }
    return false;
}

// Add IP spoofing headers to evade WAF
int waf_add_ip_spoofing_headers(struct curl_slist **headers, const ip_spoofing_config_t *config) {
    if (!headers || !config || !config->enabled) return 0;

    char header_buffer[512];
    char spoofed_ip[46];

    // Generate spoofed IP based on strategy
    waf_generate_spoofed_ip(spoofed_ip, sizeof(spoofed_ip), config->strategy);

    // Add X-Forwarded-For header
    if (config->use_x_forwarded_for) {
        if (config->chain_proxies && config->chain_length > 1) {
            char chain[512];
            waf_build_proxy_chain(chain, sizeof(chain), config->chain_length);
            snprintf(header_buffer, sizeof(header_buffer), "X-Forwarded-For: %s", chain);
        } else {
            snprintf(header_buffer, sizeof(header_buffer), "X-Forwarded-For: %s", spoofed_ip);
        }
        *headers = curl_slist_append(*headers, header_buffer);
    }

    // Add X-Real-IP header
    if (config->use_x_real_ip) {
        snprintf(header_buffer, sizeof(header_buffer), "X-Real-IP: %s", spoofed_ip);
        *headers = curl_slist_append(*headers, header_buffer);
    }

    // Add X-Originating-IP header
    if (config->use_x_originating_ip) {
        snprintf(header_buffer, sizeof(header_buffer), "X-Originating-IP: %s", spoofed_ip);
        *headers = curl_slist_append(*headers, header_buffer);
    }

    // Add X-Remote-IP header
    if (config->use_x_remote_ip) {
        snprintf(header_buffer, sizeof(header_buffer), "X-Remote-IP: %s", spoofed_ip);
        *headers = curl_slist_append(*headers, header_buffer);
    }

    // Add X-Remote-Addr header
    if (config->use_x_remote_addr) {
        snprintf(header_buffer, sizeof(header_buffer), "X-Remote-Addr: %s", spoofed_ip);
        *headers = curl_slist_append(*headers, header_buffer);
    }

    // Add X-Client-IP header
    if (config->use_x_client_ip) {
        snprintf(header_buffer, sizeof(header_buffer), "X-Client-IP: %s", spoofed_ip);
        *headers = curl_slist_append(*headers, header_buffer);
    }

    // Add True-Client-IP header
    if (config->use_true_client_ip) {
        snprintf(header_buffer, sizeof(header_buffer), "True-Client-IP: %s", spoofed_ip);
        *headers = curl_slist_append(*headers, header_buffer);
    }

    // Add CF-Connecting-IP header (Cloudflare specific)
    if (config->use_cf_connecting_ip) {
        snprintf(header_buffer, sizeof(header_buffer), "CF-Connecting-IP: %s", spoofed_ip);
        *headers = curl_slist_append(*headers, header_buffer);
    }

    // Add Forwarded header (RFC 7239)
    if (config->use_forwarded) {
        snprintf(header_buffer, sizeof(header_buffer), "Forwarded: for=%s", spoofed_ip);
        *headers = curl_slist_append(*headers, header_buffer);
    }

    // Add Via header
    if (config->use_via) {
        snprintf(header_buffer, sizeof(header_buffer), "Via: 1.1 %s", spoofed_ip);
        *headers = curl_slist_append(*headers, header_buffer);
    }

    return 0;
}

// Generate spoofed IP address
int waf_generate_spoofed_ip(char *ip_buffer, size_t buffer_size, ip_spoof_strategy_t strategy) {
    if (!ip_buffer || buffer_size < 16) return -1;

    switch (strategy) {
        case IP_SPOOF_RANDOM:
            waf_generate_random_ipv4(ip_buffer, buffer_size);
            break;
        case IP_SPOOF_INTERNAL:
            waf_generate_internal_ip(ip_buffer, buffer_size);
            break;
        case IP_SPOOF_LOCALHOST:
            strcpy(ip_buffer, "127.0.0.1");
            break;
        case IP_SPOOF_TRUSTED:
            waf_generate_trusted_ip(ip_buffer, buffer_size);
            break;
        case IP_SPOOF_GEOGRAPHIC:
            // Default to random for now
            waf_generate_random_ipv4(ip_buffer, buffer_size);
            break;
        case IP_SPOOF_CHAIN:
            waf_generate_random_ipv4(ip_buffer, buffer_size);
            break;
        default:
            waf_generate_random_ipv4(ip_buffer, buffer_size);
            break;
    }

    return 0;
}

// Generate random IPv4 address
int waf_generate_random_ipv4(char *ip_buffer, size_t buffer_size) {
    if (!ip_buffer || buffer_size < 16) return -1;

    uint32_t random_val = waf_generate_random_uint32();
    uint8_t *bytes = (uint8_t *)&random_val;

    // Avoid reserved ranges
    if (bytes[0] == 0 || bytes[0] == 127 || bytes[0] >= 224) {
        bytes[0] = (waf_generate_random_uint32() % 200) + 1;
    }

    snprintf(ip_buffer, buffer_size, "%u.%u.%u.%u",
             bytes[0], bytes[1], bytes[2], bytes[3]);

    return 0;
}

// Generate internal IP address (RFC 1918)
int waf_generate_internal_ip(char *ip_buffer, size_t buffer_size) {
    if (!ip_buffer || buffer_size < 16) return -1;

    uint32_t choice = waf_generate_random_uint32() % 3;
    uint32_t random_val = waf_generate_random_uint32();
    uint8_t *bytes = (uint8_t *)&random_val;

    switch (choice) {
        case 0: // 10.0.0.0/8
            snprintf(ip_buffer, buffer_size, "10.%u.%u.%u",
                     bytes[0], bytes[1], bytes[2]);
            break;
        case 1: // 172.16.0.0/12
            snprintf(ip_buffer, buffer_size, "172.%u.%u.%u",
                     16 + (bytes[0] % 16), bytes[1], bytes[2]);
            break;
        case 2: // 192.168.0.0/16
            snprintf(ip_buffer, buffer_size, "192.168.%u.%u",
                     bytes[0], bytes[1]);
            break;
    }

    return 0;
}

// Generate trusted IP from list
int waf_generate_trusted_ip(char *ip_buffer, size_t buffer_size) {
    if (!ip_buffer || buffer_size < 16) return -1;

    uint32_t index = waf_generate_random_uint32() % (sizeof(trusted_ips) / sizeof(trusted_ips[0]));
    strncpy(ip_buffer, trusted_ips[index], buffer_size - 1);
    ip_buffer[buffer_size - 1] = '\0';

    return 0;
}

// Build proxy chain for X-Forwarded-For
int waf_build_proxy_chain(char *chain_buffer, size_t buffer_size, uint32_t chain_length) {
    if (!chain_buffer || buffer_size < 64 || chain_length == 0) return -1;

    chain_buffer[0] = '\0';

    for (uint32_t i = 0; i < chain_length; i++) {
        char ip[46];
        waf_generate_random_ipv4(ip, sizeof(ip));

        if (i > 0) {
            strncat(chain_buffer, ", ", buffer_size - strlen(chain_buffer) - 1);
        }
        strncat(chain_buffer, ip, buffer_size - strlen(chain_buffer) - 1);
    }

    return 0;
}

// Mutate header case for evasion
int waf_mutate_header_case(char *header, const header_mutation_config_t *config) {
    if (!header || !config || !config->enabled) return 0;

    size_t len = strlen(header);
    char *colon = strchr(header, ':');
    if (!colon) return -1;

    size_t header_name_len = colon - header;

    switch (config->strategy) {
        case CASE_MUTATION_LOWER:
            for (size_t i = 0; i < header_name_len; i++) {
                header[i] = tolower(header[i]);
            }
            break;

        case CASE_MUTATION_UPPER:
            for (size_t i = 0; i < header_name_len; i++) {
                header[i] = toupper(header[i]);
            }
            break;

        case CASE_MUTATION_MIXED:
            for (size_t i = 0; i < header_name_len; i++) {
                if (i % 2 == 0) {
                    header[i] = toupper(header[i]);
                } else {
                    header[i] = tolower(header[i]);
                }
            }
            break;

        case CASE_MUTATION_RANDOM:
            for (size_t i = 0; i < header_name_len; i++) {
                if (waf_generate_random_uint32() % 2 == 0) {
                    header[i] = toupper(header[i]);
                } else {
                    header[i] = tolower(header[i]);
                }
            }
            break;

        case CASE_MUTATION_ALTERNATING:
            for (size_t i = 0; i < header_name_len; i++) {
                if (i % 2 == 0) {
                    header[i] = tolower(header[i]);
                } else {
                    header[i] = toupper(header[i]);
                }
            }
            break;

        default:
            break;
    }

    return 0;
}

// Apply parameter pollution to URL
int waf_apply_parameter_pollution(char *url, size_t max_size, const parameter_pollution_config_t *config) {
    if (!url || !config || !config->enabled) return 0;

    char *query_start = strchr(url, '?');
    if (!query_start) return 0; // No query string

    return waf_pollute_query_string(query_start + 1, max_size - (query_start - url + 1), config);
}

// Pollute query string with duplicate parameters
int waf_pollute_query_string(char *query, size_t max_size, const parameter_pollution_config_t *config) {
    if (!query || !config || !config->enabled) return 0;

    char original_query[2048];
    strncpy(original_query, query, sizeof(original_query) - 1);
    original_query[sizeof(original_query) - 1] = '\0';

    if (config->duplicate_parameters) {
        for (uint32_t i = 0; i < config->pollution_factor && strlen(query) < max_size - 100; i++) {
            strncat(query, "&", max_size - strlen(query) - 1);
            strncat(query, original_query, max_size - strlen(query) - 1);
        }
    }

    return 0;
}

// URL encode a value
int waf_url_encode_value(const char *input, char *output, size_t output_size) {
    if (!input || !output || output_size == 0) return -1;

    size_t output_pos = 0;
    for (size_t i = 0; input[i] != '\0' && output_pos < output_size - 4; i++) {
        char c = input[i];
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            output[output_pos++] = c;
        } else {
            snprintf(output + output_pos, output_size - output_pos, "%%%02X", (unsigned char)c);
            output_pos += 3;
        }
    }
    output[output_pos] = '\0';

    return 0;
}

// Double URL encode a value
int waf_double_encode_value(const char *input, char *output, size_t output_size) {
    char temp[2048];

    if (waf_url_encode_value(input, temp, sizeof(temp)) != 0) {
        return -1;
    }

    return waf_url_encode_value(temp, output, output_size);
}

// Apply all evasion techniques to request
int waf_apply_evasion_techniques(CURL *curl, struct curl_slist **headers,
                                 const waf_evasion_config_t *config) {
    if (!curl || !headers || !config) return -1;

    // Apply IP spoofing headers
    if (config->enabled_techniques & EVASION_IP_SPOOFING) {
        waf_add_ip_spoofing_headers(headers, &config->ip_spoofing);
    }

    // Apply header mutations
    if (config->enabled_techniques & EVASION_CASE_MUTATION) {
        // This would be applied to existing headers
        waf_add_header_variations(headers, &config->header_mutation);
    }

    // Apply chunked encoding if enabled
    if (config->enabled_techniques & EVASION_CHUNKED_ENCODING) {
        curl_easy_setopt(curl, CURLOPT_HTTP_TRANSFER_DECODING, 0L);
        *headers = curl_slist_append(*headers, "Transfer-Encoding: chunked");
    }

    // Add method override header
    if (config->enabled_techniques & EVASION_METHOD_OVERRIDE) {
        *headers = curl_slist_append(*headers, "X-HTTP-Method-Override: GET");
    }

    return 0;
}

// Add header variations for evasion
int waf_add_header_variations(struct curl_slist **headers, const header_mutation_config_t *config) {
    if (!headers || !config || !config->enabled) return 0;

    // Add some common variations that WAFs might not inspect as thoroughly
    if (waf_generate_random_double() < config->mutation_probability) {
        *headers = curl_slist_append(*headers, "X-Requested-With: XMLHttpRequest");
    }

    if (waf_generate_random_double() < config->mutation_probability) {
        *headers = curl_slist_append(*headers, "X-Ajax-Request: true");
    }

    if (waf_generate_random_double() < config->mutation_probability) {
        char custom_header[256];
        snprintf(custom_header, sizeof(custom_header), "X-Custom-%u: probe", waf_generate_random_uint32());
        *headers = curl_slist_append(*headers, custom_header);
    }

    return 0;
}

// Configuration presets

void waf_evasion_configure_light(waf_evasion_config_t *config) {
    if (!config) return;

    memset(config, 0, sizeof(waf_evasion_config_t));

    config->enabled_techniques = EVASION_IP_SPOOFING;

    // Light IP spoofing only
    config->ip_spoofing.enabled = true;
    config->ip_spoofing.strategy = IP_SPOOF_RANDOM;
    config->ip_spoofing.use_x_forwarded_for = true;
    config->ip_spoofing.use_x_real_ip = true;
    config->ip_spoofing.chain_proxies = false;

    config->auto_detect_waf = true;
    config->max_evasion_attempts = 3;
}

void waf_evasion_configure_moderate(waf_evasion_config_t *config) {
    if (!config) return;

    waf_evasion_configure_light(config);

    config->enabled_techniques = EVASION_IP_SPOOFING | EVASION_CASE_MUTATION |
                                EVASION_HEADER_ORDERING;

    // Moderate IP spoofing
    config->ip_spoofing.strategy = IP_SPOOF_INTERNAL;
    config->ip_spoofing.use_x_originating_ip = true;
    config->ip_spoofing.use_x_client_ip = true;
    config->ip_spoofing.chain_proxies = true;
    config->ip_spoofing.chain_length = 2;

    // Header mutations
    config->header_mutation.enabled = true;
    config->header_mutation.strategy = CASE_MUTATION_RANDOM;
    config->header_mutation.randomize_header_order = true;
    config->header_mutation.mutation_probability = 0.3;

    config->max_evasion_attempts = 5;
}

void waf_evasion_configure_aggressive(waf_evasion_config_t *config) {
    if (!config) return;

    waf_evasion_configure_moderate(config);

    config->enabled_techniques = EVASION_ALL;

    // Aggressive IP spoofing
    config->ip_spoofing.use_x_remote_ip = true;
    config->ip_spoofing.use_x_remote_addr = true;
    config->ip_spoofing.use_true_client_ip = true;
    config->ip_spoofing.use_cf_connecting_ip = true;
    config->ip_spoofing.use_forwarded = true;
    config->ip_spoofing.use_via = true;
    config->ip_spoofing.chain_length = 3;

    // Chunked encoding
    config->chunked_encoding.enabled = true;
    config->chunked_encoding.min_chunk_size = 8;
    config->chunked_encoding.max_chunk_size = 256;
    config->chunked_encoding.randomize_chunk_sizes = true;

    // Parameter pollution
    config->parameter_pollution.enabled = true;
    config->parameter_pollution.duplicate_parameters = true;
    config->parameter_pollution.pollution_factor = 2;

    // Aggressive header mutation
    config->header_mutation.strategy = CASE_MUTATION_RANDOM;
    config->header_mutation.add_whitespace_variations = true;
    config->header_mutation.mutation_probability = 0.5;

    // Encoding variations
    config->encoding_variation.enabled = true;
    config->encoding_variation.use_url_encoding = true;
    config->encoding_variation.use_double_encoding = true;

    config->adapt_to_waf_type = true;
    config->test_bypass_success = true;
    config->max_evasion_attempts = 10;
}

// Configure for specific WAF type
void waf_evasion_configure_for_waf_type(waf_evasion_config_t *config, waf_type_t waf_type) {
    if (!config) return;

    switch (waf_type) {
        case WAF_TYPE_CLOUDFLARE:
            waf_evasion_configure_moderate(config);
            config->ip_spoofing.use_cf_connecting_ip = true;
            config->ip_spoofing.strategy = IP_SPOOF_TRUSTED;
            break;

        case WAF_TYPE_AKAMAI:
            waf_evasion_configure_aggressive(config);
            config->ip_spoofing.chain_length = 4;
            break;

        case WAF_TYPE_AWS_WAF:
            waf_evasion_configure_moderate(config);
            config->header_mutation.mutation_probability = 0.6;
            break;

        default:
            waf_evasion_configure_moderate(config);
            break;
    }
}

// Utility functions

const char *waf_type_to_string(waf_type_t type) {
    switch (type) {
        case WAF_TYPE_CLOUDFLARE: return "Cloudflare";
        case WAF_TYPE_AKAMAI: return "Akamai";
        case WAF_TYPE_IMPERVA: return "Imperva";
        case WAF_TYPE_AWS_WAF: return "AWS WAF";
        case WAF_TYPE_AZURE_WAF: return "Azure WAF";
        case WAF_TYPE_F5_BIG_IP: return "F5 BIG-IP";
        case WAF_TYPE_BARRACUDA: return "Barracuda";
        case WAF_TYPE_FORTINET: return "Fortinet";
        case WAF_TYPE_SUCURI: return "Sucuri";
        case WAF_TYPE_WORDFENCE: return "Wordfence";
        case WAF_TYPE_MODSECURITY: return "ModSecurity";
        default: return "Unknown";
    }
}

void waf_print_detection_result(const waf_detection_result_t *result) {
    if (!result) return;

    printf("\n=== WAF Detection Result ===\n");
    printf("WAF Detected: %s\n", result->waf_detected ? "Yes" : "No");

    if (result->waf_detected) {
        printf("WAF Type: %s\n", waf_type_to_string(result->waf_type));
        printf("WAF Name: %s\n", result->waf_name);
        printf("Confidence: %.2f%%\n", result->confidence_score * 100);
        printf("Detection Method: %s\n", result->detection_method);
        printf("Rate Limiting: %s\n", result->rate_limiting_detected ? "Detected" : "Not Detected");
        printf("Blocking: %s\n", result->blocking_detected ? "Detected" : "Not Detected");
    }
    printf("============================\n\n");
}

void waf_print_evasion_stats(const waf_evasion_context_t *ctx) {
    if (!ctx) return;

    printf("\n=== WAF Evasion Statistics ===\n");
    printf("Total Attempts: %u\n", ctx->total_attempts);
    printf("Successful Bypasses: %u\n", ctx->successful_bypasses);
    printf("Failed Bypasses: %u\n", ctx->failed_bypasses);
    printf("Success Rate: %.2f%%\n", waf_calculate_bypass_success_rate(ctx) * 100);
    printf("==============================\n\n");
}

double waf_calculate_bypass_success_rate(const waf_evasion_context_t *ctx) {
    if (!ctx || ctx->total_attempts == 0) return 0.0;
    return (double)ctx->successful_bypasses / ctx->total_attempts;
}

// Random generation helpers

void waf_generate_random_bytes(uint8_t *buffer, size_t size) {
    if (!buffer || size == 0) return;

    // Try to use getrandom() if available (cross-platform via platform_compat.h)
    ssize_t result = getrandom(buffer, size, 0);
    if (result == (ssize_t)size) {
        return;
    }

    // Fallback to rand()
    srand((unsigned int)time(NULL));
    for (size_t i = 0; i < size; i++) {
        buffer[i] = (uint8_t)(rand() % 256);
    }
}

uint32_t waf_generate_random_uint32(void) {
    uint32_t value;
    waf_generate_random_bytes((uint8_t *)&value, sizeof(value));
    return value;
}

double waf_generate_random_double(void) {
    uint32_t value = waf_generate_random_uint32();
    return (double)value / (double)UINT32_MAX;
}

const char *ip_spoof_strategy_to_string(ip_spoof_strategy_t strategy) {
    switch (strategy) {
        case IP_SPOOF_RANDOM: return "Random";
        case IP_SPOOF_INTERNAL: return "Internal";
        case IP_SPOOF_LOCALHOST: return "Localhost";
        case IP_SPOOF_TRUSTED: return "Trusted";
        case IP_SPOOF_GEOGRAPHIC: return "Geographic";
        case IP_SPOOF_CHAIN: return "Chain";
        default: return "Unknown";
    }
}

const char *case_mutation_strategy_to_string(case_mutation_strategy_t strategy) {
    switch (strategy) {
        case CASE_MUTATION_NONE: return "None";
        case CASE_MUTATION_LOWER: return "Lowercase";
        case CASE_MUTATION_UPPER: return "Uppercase";
        case CASE_MUTATION_MIXED: return "Mixed";
        case CASE_MUTATION_RANDOM: return "Random";
        case CASE_MUTATION_ALTERNATING: return "Alternating";
        default: return "Unknown";
    }
}
