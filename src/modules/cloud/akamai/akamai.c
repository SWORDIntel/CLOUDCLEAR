/*
 * CloudClear - Akamai Edge Integration Implementation
 *
 * Complete Akamai detection and intelligence gathering
 */

#include "akamai.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "platform_compat.h"

// Akamai header signatures
static const char *akamai_header_signatures[] = {
    "akamai-grn",
    "akamai-ghost",
    "akamai-x-cache",
    "akamai-x-cache-on",
    "akamai-x-cache-remote",
    "akamai-x-check-cacheable",
    "akamai-x-get-cache-key",
    "akamai-x-get-extracted-values",
    "akamai-x-get-request-id",
    "akamai-x-serial",
    "akamai-x-get-true-cache-key",
    "x-akamai-request-id",
    "x-akamai-session-info",
    "x-akamai-staging",
    NULL
};

// Akamai CNAME patterns
static const char *akamai_cname_patterns[] = {
    ".akamaiedge.net",
    ".akamaized.net",
    ".akamai.net",
    ".akamaitechnologies.com",
    ".akadns.net",
    ".akagtm.org",
    ".edgesuite.net",
    ".edgekey.net",
    ".srip.net",
    ".akamaitech.net",
    ".akamaihd.net",
    ".akamaistream.net",
    NULL
};

// Akamai certificate patterns
static const char *akamai_cert_patterns[] = {
    "akamai",
    "edgesuite",
    "edgekey",
    "akamaiedge",
    "akamaitechnologies",
    NULL
};

// Initialize Akamai context
int akamai_init_context(akamai_context_t *ctx) {
    if (!ctx) return -1;

    memset(ctx, 0, sizeof(akamai_context_t));

    if (pthread_mutex_init(&ctx->mutex, NULL) != 0) {
        return -1;
    }

    // Check for environment variables for API credentials
    const char *client_token = getenv("AKAMAI_CLIENT_TOKEN");
    const char *client_secret = getenv("AKAMAI_CLIENT_SECRET");
    const char *access_token = getenv("AKAMAI_ACCESS_TOKEN");

    if (client_token && client_secret && access_token) {
        akamai_configure_api(ctx, client_token, client_secret, access_token);
    }

    return 0;
}

// Cleanup Akamai context
void akamai_cleanup_context(akamai_context_t *ctx) {
    if (!ctx) return;

    pthread_mutex_destroy(&ctx->mutex);

    // Clear sensitive credentials from memory
    memset(&ctx->api_config, 0, sizeof(akamai_api_config_t));
    memset(ctx, 0, sizeof(akamai_context_t));
}

// Configure Akamai API credentials
int akamai_configure_api(akamai_context_t *ctx, const char *client_token,
                         const char *client_secret, const char *access_token) {
    if (!ctx) return -1;

    pthread_mutex_lock(&ctx->mutex);

    if (client_token) {
        strncpy(ctx->api_config.client_token, client_token,
                sizeof(ctx->api_config.client_token) - 1);
    }
    if (client_secret) {
        strncpy(ctx->api_config.client_secret, client_secret,
                sizeof(ctx->api_config.client_secret) - 1);
    }
    if (access_token) {
        strncpy(ctx->api_config.access_token, access_token,
                sizeof(ctx->api_config.access_token) - 1);
    }

    // Default API base URL
    strncpy(ctx->api_config.base_url, "https://akzz-XXXXXXXXXXXXXXXX-XXXXXXXXXXXXXXXX.luna.akamaiapis.net",
            sizeof(ctx->api_config.base_url) - 1);

    ctx->api_config.credentials_configured =
        (strlen(ctx->api_config.client_token) > 0 &&
         strlen(ctx->api_config.client_secret) > 0 &&
         strlen(ctx->api_config.access_token) > 0);

    pthread_mutex_unlock(&ctx->mutex);

    return 0;
}

// Check if headers contain Akamai signatures
bool akamai_check_header_signature(const char *headers) {
    if (!headers) return false;

    for (int i = 0; akamai_header_signatures[i] != NULL; i++) {
        if (strcasestr(headers, akamai_header_signatures[i]) != NULL) {
            return true;
        }
    }

    return false;
}

// Check if CNAME matches Akamai pattern
bool akamai_check_cname_pattern(const char *cname) {
    if (!cname) return false;

    for (int i = 0; akamai_cname_patterns[i] != NULL; i++) {
        if (strcasestr(cname, akamai_cname_patterns[i]) != NULL) {
            return true;
        }
    }

    return false;
}

// Parse Akamai headers from HTTP response
int akamai_parse_headers(const char *headers, akamai_detection_result_t *result) {
    if (!headers || !result) return -1;

    char *headers_copy = strdup(headers);
    if (!headers_copy) return -1;

    char *line = strtok(headers_copy, "\r\n");
    while (line && result->header_count < AKAMAI_MAX_HEADERS) {
        // Look for Akamai-specific headers
        for (int i = 0; akamai_header_signatures[i] != NULL; i++) {
            if (strncasecmp(line, akamai_header_signatures[i],
                          strlen(akamai_header_signatures[i])) == 0) {

                char *colon = strchr(line, ':');
                if (colon) {
                    size_t name_len = colon - line;
                    if (name_len < sizeof(result->headers[result->header_count].name)) {
                        strncpy(result->headers[result->header_count].name, line, name_len);
                        result->headers[result->header_count].name[name_len] = '\0';

                        // Skip colon and whitespace
                        colon++;
                        while (*colon == ' ' || *colon == '\t') colon++;

                        strncpy(result->headers[result->header_count].value, colon,
                               sizeof(result->headers[result->header_count].value) - 1);

                        result->header_count++;
                    }
                }
                break;
            }
        }

        // Parse specific header values
        if (strncasecmp(line, "akamai-grn:", 11) == 0) {
            sscanf(line + 11, " %127s", result->reference_id);
        } else if (strncasecmp(line, "x-cache:", 8) == 0) {
            sscanf(line + 8, " %63s", result->cache_status);
            if (strcasestr(line, "TCP_HIT") || strcasestr(line, "TCP_MEM_HIT")) {
                result->cache_hit = true;
            }
        } else if (strncasecmp(line, "server:", 7) == 0) {
            if (strcasestr(line, "AkamaiGHost")) {
                result->akamai_detected = true;
                if (result->confidence < AKAMAI_CONFIDENCE_HIGH) {
                    result->confidence = AKAMAI_CONFIDENCE_HIGH;
                }
            }
        }

        line = strtok(NULL, "\r\n");
    }

    free(headers_copy);
    return 0;
}

// Detect Akamai from HTTP headers
int akamai_detect_from_headers(const char *headers, akamai_detection_result_t *result) {
    if (!headers || !result) return -1;

    memset(result, 0, sizeof(akamai_detection_result_t));
    result->detected_at = time(NULL);

    // Check for Akamai header signatures
    if (akamai_check_header_signature(headers)) {
        result->akamai_detected = true;
        result->confidence = AKAMAI_CONFIDENCE_HIGH;
        strcpy(result->detection_method, "HTTP header signature analysis");

        // Parse all Akamai headers
        akamai_parse_headers(headers, result);

        return 0;
    }

    return -1;
}

// Resolve DNS and check for Akamai CNAME patterns
int akamai_detect_from_dns(const char *domain, akamai_detection_result_t *result) {
    if (!domain || !result) return -1;

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    // Get address info
    if (getaddrinfo(domain, NULL, &hints, &res) != 0) {
        return -1;
    }

    // Get canonical name (CNAME)
    if (res && res->ai_canonname) {
        if (akamai_check_cname_pattern(res->ai_canonname)) {
            result->akamai_detected = true;
            result->confidence = AKAMAI_CONFIDENCE_VERIFIED;
            strcpy(result->detection_method, "DNS CNAME pattern match");

            // Store CNAME chain
            if (result->cname_chain_length < 10) {
                strncpy(result->cname_chain[result->cname_chain_length],
                       res->ai_canonname, 255);
                result->cname_chain_length++;
            }
        }
    }

    // Get IP address
    if (res && res->ai_addr) {
        char ip_str[INET6_ADDRSTRLEN];
        void *addr;

        if (res->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
            addr = &(ipv4->sin_addr);
        } else {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)res->ai_addr;
            addr = &(ipv6->sin6_addr);
        }

        inet_ntop(res->ai_family, addr, ip_str, sizeof(ip_str));
        strncpy(result->edge_server_ip, ip_str, sizeof(result->edge_server_ip) - 1);

        // Check if IP is in Akamai range
        if (akamai_is_edge_ip(ip_str)) {
            result->akamai_detected = true;
            if (result->confidence < AKAMAI_CONFIDENCE_HIGH) {
                result->confidence = AKAMAI_CONFIDENCE_HIGH;
            }
        }
    }

    if (res) freeaddrinfo(res);

    return result->akamai_detected ? 0 : -1;
}

// Check if IP is in known Akamai edge IP ranges
bool akamai_is_edge_ip(const char *ip) {
    if (!ip) return false;

    // Akamai has thousands of edge servers
    // This is a simplified check for common ranges
    // In production, use the Akamai SiteShield IP list

    // Common Akamai ASNs: AS20940, AS16625, AS21342, AS16702, AS34164
    // IP ranges are too numerous to hardcode all of them
    // This would require an IP-to-ASN lookup service

    // For now, return false and rely on other detection methods
    // TODO: Implement proper ASN-based detection or use MaxMind GeoIP data
    return false;
}

// Detect Akamai services from headers and configuration
akamai_service_type_t akamai_identify_service(const akamai_detection_result_t *result) {
    if (!result || !result->akamai_detected) {
        return AKAMAI_SERVICE_UNKNOWN;
    }

    // Check for Ion
    if (result->properties[0].ion_enabled) {
        return AKAMAI_SERVICE_ION;
    }

    // Check for Kona WAF
    if (result->waf_info.waf_detected) {
        return AKAMAI_SERVICE_KONA_WAF;
    }

    // Check for SureRoute
    if (result->properties[0].sureroute_enabled) {
        return AKAMAI_SERVICE_SUREROUTE;
    }

    // Default to CDN
    return AKAMAI_SERVICE_CDN;
}

// Detect Ion service
bool akamai_detect_ion(const akamai_detection_result_t *result) {
    if (!result) return false;

    // Ion is detected through property configuration or specific headers
    for (uint32_t i = 0; i < result->header_count; i++) {
        if (strcasestr(result->headers[i].name, "ion") != NULL) {
            return true;
        }
    }

    return result->properties[0].ion_enabled;
}

// Detect Kona WAF
bool akamai_detect_kona_waf(const akamai_detection_result_t *result) {
    if (!result) return false;

    return result->waf_info.waf_detected;
}

// Comprehensive Akamai detection combining all methods
int akamai_comprehensive_detect(const char *domain, akamai_detection_result_t *result) {
    if (!domain || !result) return -1;

    memset(result, 0, sizeof(akamai_detection_result_t));
    strncpy(result->target_domain, domain, sizeof(result->target_domain) - 1);
    result->detected_at = time(NULL);

    // Try DNS detection first
    if (akamai_detect_from_dns(domain, result) == 0) {
        // DNS detection succeeded
        if (result->confidence >= AKAMAI_CONFIDENCE_VERIFIED) {
            return 0;
        }
    }

    // If not detected or low confidence, would need HTTP request
    // This requires curl which is not done here
    // Caller should use akamai_detect_from_headers separately

    return result->akamai_detected ? 0 : -1;
}

// Service type to string conversion
const char *akamai_service_type_to_string(akamai_service_type_t service) {
    switch (service) {
        case AKAMAI_SERVICE_CDN: return "Akamai CDN";
        case AKAMAI_SERVICE_ION: return "Akamai Ion";
        case AKAMAI_SERVICE_KONA_WAF: return "Kona Site Defender (WAF)";
        case AKAMAI_SERVICE_PROLEXIC_DDOS: return "Prolexic DDoS Protection";
        case AKAMAI_SERVICE_BOT_MANAGER: return "Bot Manager";
        case AKAMAI_SERVICE_IMAGE_MANAGER: return "Image Manager";
        case AKAMAI_SERVICE_MEDIA_DELIVERY: return "Media Delivery";
        case AKAMAI_SERVICE_DOWNLOAD_DELIVERY: return "Download Delivery";
        case AKAMAI_SERVICE_WEB_APP_ACCELERATOR: return "Web App Accelerator";
        case AKAMAI_SERVICE_API_ACCELERATION: return "API Acceleration";
        case AKAMAI_SERVICE_SUREROUTE: return "SureRoute";
        case AKAMAI_SERVICE_SITESHIELD: return "SiteShield";
        default: return "Unknown";
    }
}

// Network type to string
const char *akamai_network_type_to_string(akamai_network_type_t network) {
    switch (network) {
        case AKAMAI_NETWORK_PRODUCTION: return "Production";
        case AKAMAI_NETWORK_STAGING: return "Staging";
        case AKAMAI_NETWORK_CHINA_CDN: return "China CDN";
        case AKAMAI_NETWORK_ENHANCED_TLS: return "Enhanced TLS";
        default: return "Unknown";
    }
}

// Confidence to string
const char *akamai_confidence_to_string(akamai_confidence_t confidence) {
    if (confidence >= AKAMAI_CONFIDENCE_VERIFIED) return "Verified";
    if (confidence >= AKAMAI_CONFIDENCE_HIGH) return "High";
    if (confidence >= AKAMAI_CONFIDENCE_MEDIUM) return "Medium";
    if (confidence >= AKAMAI_CONFIDENCE_LOW) return "Low";
    return "None";
}

// Print detection result
void akamai_print_detection_result(const akamai_detection_result_t *result) {
    if (!result) return;

    printf("\n=== Akamai Detection Result ===\n");
    printf("Target: %s\n", result->target_domain);
    printf("Detected: %s\n", result->akamai_detected ? "Yes" : "No");

    if (!result->akamai_detected) {
        printf("===============================\n\n");
        return;
    }

    printf("Confidence: %s (%d%%)\n",
           akamai_confidence_to_string(result->confidence),
           result->confidence);
    printf("Detection Method: %s\n", result->detection_method);

    if (result->edge_server_ip[0]) {
        printf("Edge Server IP: %s\n", result->edge_server_ip);
    }

    if (result->reference_id[0]) {
        printf("Reference ID: %s\n", result->reference_id);
    }

    if (result->cache_status[0]) {
        printf("Cache Status: %s\n", result->cache_status);
        printf("Cache Hit: %s\n", result->cache_hit ? "Yes" : "No");
    }

    if (result->cname_chain_length > 0) {
        printf("\nCNAME Chain:\n");
        for (uint32_t i = 0; i < result->cname_chain_length; i++) {
            printf("  %u. %s\n", i + 1, result->cname_chain[i]);
        }
    }

    if (result->header_count > 0) {
        printf("\nAkamai Headers:\n");
        for (uint32_t i = 0; i < result->header_count; i++) {
            printf("  %s: %s\n",
                   result->headers[i].name,
                   result->headers[i].value);
        }
    }

    if (result->service_count > 0) {
        printf("\nDetected Services:\n");
        for (uint32_t i = 0; i < result->service_count; i++) {
            printf("  - %s\n", akamai_service_type_to_string(result->services[i]));
        }
    }

    if (result->waf_info.waf_detected) {
        printf("\nWAF Information:\n");
        printf("  Version: %s\n", result->waf_info.waf_version);
        printf("  Bot Manager: %s\n", result->waf_info.bot_manager_enabled ? "Yes" : "No");
        printf("  Rate Limiting: %s\n", result->waf_info.rate_limiting_enabled ? "Yes" : "No");
    }

    printf("===============================\n\n");
}

// Print property information
void akamai_print_property_info(const akamai_property_t *property) {
    if (!property) return;

    printf("\n=== Akamai Property Info ===\n");
    printf("Property Name: %s\n", property->property_name);
    printf("Property ID: %s\n", property->property_id);
    printf("Service: %s\n", akamai_service_type_to_string(property->service_type));
    printf("Ion Enabled: %s\n", property->ion_enabled ? "Yes" : "No");
    printf("SureRoute: %s\n", property->sureroute_enabled ? "Yes" : "No");
    printf("Tiered Distribution: %s\n", property->tiered_distribution ? "Yes" : "No");

    if (property->origin_hostname[0]) {
        printf("Origin: %s\n", property->origin_hostname);
    }

    if (property->cp_code[0]) {
        printf("CP Code: %s\n", property->cp_code);
    }

    printf("============================\n\n");
}
