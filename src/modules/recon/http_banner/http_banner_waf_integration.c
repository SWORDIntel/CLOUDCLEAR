/*
 * CloudClear - HTTP Banner Grabbing with WAF Evasion Integration
 *
 * Example implementation showing how to integrate WAF evasion techniques
 * with HTTP banner grabbing for enhanced origin IP verification
 *
 * Usage Example:
 * This module demonstrates how to:
 * 1. Detect if a WAF is present
 * 2. Apply appropriate evasion techniques
 * 3. Verify if the request reached the origin server
 * 4. Adapt evasion strategies based on WAF type
 */

#include "http_banner.h"
#include "http_waf_evasion.h"
#include <stdio.h>
#include <string.h>

/*
 * Enhanced HTTP banner grab with WAF evasion
 *
 * This function extends the standard HTTP banner grabbing with WAF detection
 * and evasion capabilities, useful for verifying origin IP addresses
 */
int http_banner_grab_with_waf_evasion(const char *url,
                                     http_banner_result_t *result,
                                     waf_evasion_context_t *waf_ctx) {
    if (!url || !result || !waf_ctx) return -1;

    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    CURLcode res;

    // Initialize result structure
    http_banner_init_result(result);
    strncpy(result->url, url, sizeof(result->url) - 1);
    result->timestamp = time(NULL);

    // Create cURL handle
    curl = curl_easy_init();
    if (!curl) {
        strcpy(result->error_message, "Failed to initialize cURL");
        return -1;
    }

    // Set basic cURL options
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    // Apply WAF evasion techniques
    int evasion_result = waf_apply_evasion_techniques(curl, &headers, &waf_ctx->config);
    if (evasion_result != 0) {
        recon_log_info("waf_evasion", "Failed to apply WAF evasion techniques");
    }

    // Set headers
    if (headers) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    // Perform request
    res = curl_easy_perform(curl);

    // Process response
    if (res != CURLE_OK) {
        snprintf(result->error_message, sizeof(result->error_message),
                "Request failed: %s", curl_easy_strerror(res));
        result->success = false;
    } else {
        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        result->response.status_code = (uint32_t)response_code;
        result->success = (response_code >= 200 && response_code < 400);

        // Update WAF evasion statistics
        pthread_mutex_lock(&waf_ctx->mutex);
        waf_ctx->total_attempts++;
        if (result->success) {
            waf_ctx->successful_bypasses++;
        } else {
            waf_ctx->failed_bypasses++;
        }
        waf_ctx->bypass_success_rate = waf_calculate_bypass_success_rate(waf_ctx);
        pthread_mutex_unlock(&waf_ctx->mutex);
    }

    // Cleanup
    if (headers) {
        curl_slist_free_all(headers);
    }
    curl_easy_cleanup(curl);

    return result->success ? 0 : -1;
}

/*
 * Verify if candidate IP is origin server using WAF evasion
 *
 * This function attempts to connect to a candidate origin IP and verify
 * if it's the real origin server by using WAF evasion techniques
 */
int http_verify_origin_ip_with_evasion(const char *candidate_ip,
                                       const char *target_domain,
                                       bool *is_origin,
                                       waf_evasion_context_t *waf_ctx) {
    if (!candidate_ip || !target_domain || !is_origin || !waf_ctx) return -1;

    char url[512];
    http_banner_result_t result;
    waf_detection_result_t waf_detection;

    *is_origin = false;

    // Build URL with candidate IP but Host header with domain
    snprintf(url, sizeof(url), "https://%s/", candidate_ip);

    // First attempt: detect WAF
    recon_log_info("origin_verify", "Testing candidate IP: %s for domain: %s",
                   candidate_ip, target_domain);

    // Perform banner grab with light evasion first
    waf_evasion_configure_light(&waf_ctx->config);
    int result_code = http_banner_grab_with_waf_evasion(url, &result, waf_ctx);

    if (result_code == 0 && result.success) {
        // Analyze response for WAF indicators
        char response_headers[4096] = {0};
        // Build headers string from result
        for (uint32_t i = 0; i < result.response.header_count; i++) {
            strncat(response_headers, result.response.headers[i].name,
                   sizeof(response_headers) - strlen(response_headers) - 1);
            strncat(response_headers, ": ",
                   sizeof(response_headers) - strlen(response_headers) - 1);
            strncat(response_headers, result.response.headers[i].value,
                   sizeof(response_headers) - strlen(response_headers) - 1);
            strncat(response_headers, "\r\n",
                   sizeof(response_headers) - strlen(response_headers) - 1);
        }

        waf_detect_from_response(response_headers, result.response.body_preview, &waf_detection);

        if (waf_detection.waf_detected) {
            recon_log_info("origin_verify", "WAF detected: %s - trying aggressive evasion",
                          waf_detection.waf_name);

            // WAF detected - try more aggressive evasion
            waf_evasion_configure_for_waf_type(&waf_ctx->config, waf_detection.waf_type);

            http_banner_cleanup_result(&result);
            result_code = http_banner_grab_with_waf_evasion(url, &result, waf_ctx);
        }

        // Check if we successfully reached origin
        if (result_code == 0 && result.success) {
            // Look for origin server indicators
            bool has_origin_indicators = false;

            // Check for different server header
            if (strlen(result.response.server_header) > 0 &&
                !waf_is_cloudflare(response_headers) &&
                !waf_is_akamai(response_headers)) {
                has_origin_indicators = true;
            }

            // Check for direct IP connection success
            if (result.response.status_code == 200) {
                has_origin_indicators = true;
            }

            *is_origin = has_origin_indicators;

            if (*is_origin) {
                recon_log_info("origin_verify",
                              "SUCCESS: Candidate IP %s appears to be origin server",
                              candidate_ip);
            }
        }
    }

    http_banner_cleanup_result(&result);
    return 0;
}

/*
 * Batch test multiple candidate IPs with adaptive WAF evasion
 */
int http_batch_verify_origins_with_evasion(const char **candidate_ips,
                                          uint32_t candidate_count,
                                          const char *target_domain,
                                          char verified_ips[][46],
                                          uint32_t *verified_count) {
    if (!candidate_ips || !target_domain || !verified_ips || !verified_count) return -1;

    waf_evasion_context_t waf_ctx;
    waf_evasion_init_context(&waf_ctx);

    *verified_count = 0;

    recon_log_info("batch_verify", "Testing %u candidate IPs for %s",
                   candidate_count, target_domain);

    for (uint32_t i = 0; i < candidate_count; i++) {
        bool is_origin = false;

        int result = http_verify_origin_ip_with_evasion(
            candidate_ips[i],
            target_domain,
            &is_origin,
            &waf_ctx
        );

        if (result == 0 && is_origin) {
            strncpy(verified_ips[*verified_count], candidate_ips[i], 45);
            verified_ips[*verified_count][45] = '\0';
            (*verified_count)++;
        }

        // OPSEC delay between requests
        usleep(2000000); // 2 seconds
    }

    // Print statistics
    waf_print_evasion_stats(&waf_ctx);

    waf_evasion_cleanup_context(&waf_ctx);

    recon_log_info("batch_verify", "Verification complete: %u origins found", *verified_count);
    return 0;
}

/*
 * Example usage function demonstrating the integration
 */
void example_usage_waf_evasion_integration(void) {
    printf("\n=== CloudClear WAF Evasion Integration Example ===\n\n");

    // Example 1: Simple WAF-aware banner grab
    printf("Example 1: Banner grab with automatic WAF detection and evasion\n");
    {
        waf_evasion_context_t waf_ctx;
        waf_evasion_init_context(&waf_ctx);

        http_banner_result_t result;
        const char *test_url = "https://example.com/";

        http_banner_grab_with_waf_evasion(test_url, &result, &waf_ctx);

        if (result.success) {
            printf("  Success! Status: %u\n", result.response.status_code);
            printf("  Server: %s\n", result.response.server_header);
        }

        http_banner_cleanup_result(&result);
        waf_evasion_cleanup_context(&waf_ctx);
    }

    // Example 2: Origin IP verification with aggressive evasion
    printf("\nExample 2: Verify candidate origin IP with aggressive WAF evasion\n");
    {
        waf_evasion_context_t waf_ctx;
        waf_evasion_init_context(&waf_ctx);
        waf_evasion_configure_aggressive(&waf_ctx.config);

        const char *candidate_ip = "203.0.113.10";
        const char *domain = "example.com";
        bool is_origin = false;

        http_verify_origin_ip_with_evasion(candidate_ip, domain, &is_origin, &waf_ctx);

        printf("  Candidate IP %s is %s origin server\n",
               candidate_ip, is_origin ? "likely the" : "NOT the");

        waf_evasion_cleanup_context(&waf_ctx);
    }

    // Example 3: Batch verification of multiple candidates
    printf("\nExample 3: Batch verification of candidate IPs\n");
    {
        const char *candidates[] = {
            "203.0.113.10",
            "203.0.113.20",
            "203.0.113.30"
        };
        uint32_t candidate_count = 3;

        char verified[10][46];
        uint32_t verified_count = 0;

        http_batch_verify_origins_with_evasion(
            candidates,
            candidate_count,
            "example.com",
            verified,
            &verified_count
        );

        printf("  Found %u verified origin IPs\n", verified_count);
        for (uint32_t i = 0; i < verified_count; i++) {
            printf("    - %s\n", verified[i]);
        }
    }

    printf("\n=== Integration Example Complete ===\n\n");
}

/*
 * Configuration helper: Set up WAF evasion based on OPSEC level
 */
int http_configure_waf_evasion_by_opsec_level(waf_evasion_config_t *waf_config,
                                              opsec_paranoia_level_t opsec_level) {
    if (!waf_config) return -1;

    switch (opsec_level) {
        case OPSEC_PARANOIA_NORMAL:
            waf_evasion_configure_light(waf_config);
            break;

        case OPSEC_PARANOIA_HIGH:
            waf_evasion_configure_moderate(waf_config);
            break;

        case OPSEC_PARANOIA_MAXIMUM:
        case OPSEC_PARANOIA_GHOST:
            waf_evasion_configure_aggressive(waf_config);
            break;

        default:
            waf_evasion_configure_moderate(waf_config);
            break;
    }

    return 0;
}
