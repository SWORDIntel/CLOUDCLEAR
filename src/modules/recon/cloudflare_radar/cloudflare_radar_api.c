/*
 * CloudUnflare Enhanced - Cloudflare Radar API Module
 *
 * Handles all API communications with Cloudflare Radar service
 * Implements HTTP requests, response validation, and error handling
 */

#include "cloudflare_radar.h"
#include "../common/recon_common.h"
#include <curl/curl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// Memory buffer for curl responses
typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} curl_response_buffer_t;

// Callback function for CURL to write response data
static size_t radar_curl_write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    curl_response_buffer_t *mem = (curl_response_buffer_t *)userp;

    char *ptr = realloc(mem->data, mem->size + realsize + 1);
    if (!ptr) {
        fprintf(stderr, "Error: Not enough memory for curl response\n");
        return 0;
    }

    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;

    return realsize;
}

/*
 * Perform HTTP GET request to Cloudflare Radar API
 * Returns: 0 on success, -1 on error
 */
int radar_scan_api_request(const char *domain, radar_scan_type_t scan_type,
                           char *response_buffer, size_t buffer_size) {
    if (!domain || !response_buffer || buffer_size == 0) {
        return -1;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Error: Failed to initialize CURL\n");
        return -1;
    }

    // Construct the API URL for domain scanning
    char api_url[1024];
    snprintf(api_url, sizeof(api_url), "%s?url=%s", CLOUDFLARE_RADAR_API_BASE, domain);

    // Initialize response buffer
    curl_response_buffer_t response = {
        .data = malloc(1),
        .size = 0,
        .capacity = CLOUDFLARE_RADAR_BUFFER_SIZE
    };

    if (!response.data) {
        curl_easy_cleanup(curl);
        return -1;
    }

    // Configure CURL options
    curl_easy_setopt(curl, CURLOPT_URL, api_url);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, CLOUDFLARE_RADAR_API_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, radar_curl_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "CloudUnflare-Enhanced/2.0");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    // Add rate limiting delay
    struct timespec delay;
    delay.tv_sec = CLOUDFLARE_RADAR_RATE_LIMIT_MS / 1000;
    delay.tv_nsec = (CLOUDFLARE_RADAR_RATE_LIMIT_MS % 1000) * 1000000;
    nanosleep(&delay, NULL);

    // Perform the request
    CURLcode res = curl_easy_perform(curl);

    int result = -1;
    if (res != CURLE_OK) {
        fprintf(stderr, "Error: CURL request failed: %s\n", curl_easy_strerror(res));
    } else {
        // Get HTTP response code
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

        if (http_code == 200) {
            // Copy response to buffer
            size_t copy_size = response.size < buffer_size - 1 ? response.size : buffer_size - 1;
            memcpy(response_buffer, response.data, copy_size);
            response_buffer[copy_size] = '\0';
            result = 0;
        } else {
            fprintf(stderr, "Error: HTTP response code %ld\n", http_code);
        }
    }

    // Cleanup
    free(response.data);
    curl_easy_cleanup(curl);

    return result;
}

/*
 * Validate API response format
 * Returns: 0 if valid, -1 if invalid
 */
int radar_scan_api_validate_response(const char *response_data, size_t data_len) {
    if (!response_data || data_len == 0) {
        return -1;
    }

    // Check for JSON structure (basic validation)
    if (response_data[0] != '{' && response_data[0] != '[') {
        fprintf(stderr, "Error: Response is not valid JSON\n");
        return -1;
    }

    // Check for common error indicators
    if (strstr(response_data, "\"error\"") != NULL) {
        // Check if error value is non-null
        if (strstr(response_data, "\"error\":null") == NULL) {
            fprintf(stderr, "Error: API response contains error field\n");
            return -1;
        }
    }

    return 0;
}

/*
 * Get API URL for specific scan type
 */
const char *radar_get_api_url(radar_scan_type_t scan_type) {
    switch (scan_type) {
        case RADAR_SCAN_SECURITY:
            return CLOUDFLARE_RADAR_API_BASE "?type=security";
        case RADAR_SCAN_DNS:
            return CLOUDFLARE_RADAR_API_BASE "?type=dns";
        case RADAR_SCAN_HTTP:
            return CLOUDFLARE_RADAR_API_BASE "?type=http";
        case RADAR_SCAN_SSL_TLS:
            return CLOUDFLARE_RADAR_API_BASE "?type=ssl_tls";
        case RADAR_SCAN_TECHNOLOGY:
            return CLOUDFLARE_RADAR_API_BASE "?type=technology";
        case RADAR_SCAN_PERFORMANCE:
            return CLOUDFLARE_RADAR_API_BASE "?type=performance";
        case RADAR_SCAN_COMPREHENSIVE:
            return CLOUDFLARE_RADAR_API_BASE "?type=comprehensive";
        default:
            return CLOUDFLARE_RADAR_API_BASE;
    }
}

/*
 * Perform comprehensive scan for a domain
 * This function orchestrates multiple API requests to get all available data
 * Returns: 0 on success, -1 on error
 */
int radar_scan_comprehensive(const char *domain, radar_scan_result_t *result) {
    if (!domain || !result) {
        return -1;
    }

    char response_buffer[CLOUDFLARE_RADAR_BUFFER_SIZE];
    int retries = 0;
    int ret;

    while (retries < CLOUDFLARE_RADAR_MAX_RETRIES) {
        ret = radar_scan_api_request(domain, RADAR_SCAN_COMPREHENSIVE,
                                    response_buffer, sizeof(response_buffer));

        if (ret == 0 && radar_scan_api_validate_response(response_buffer, strlen(response_buffer)) == 0) {
            // Successfully retrieved and validated response
            strncpy(result->domain, domain, sizeof(result->domain) - 1);
            result->status = RADAR_STATUS_COMPLETED;
            result->retry_count = retries;
            return 0;
        }

        retries++;
        if (retries < CLOUDFLARE_RADAR_MAX_RETRIES) {
            // Exponential backoff: wait before retry
            uint32_t wait_ms = CLOUDFLARE_RADAR_RATE_LIMIT_MS * (1 << retries);
            struct timespec delay;
            delay.tv_sec = wait_ms / 1000;
            delay.tv_nsec = (wait_ms % 1000) * 1000000;
            nanosleep(&delay, NULL);
        }
    }

    result->status = RADAR_STATUS_FAILED;
    result->retry_count = retries;
    snprintf(result->error_message, sizeof(result->error_message),
             "Failed after %d retries", CLOUDFLARE_RADAR_MAX_RETRIES);

    return -1;
}

/*
 * Get scan status for a domain
 */
radar_scan_status_t radar_scan_get_status(const char *domain) {
    if (!domain) {
        return RADAR_STATUS_ERROR;
    }

    char response_buffer[1024];
    char url[512];

    snprintf(url, sizeof(url), "%s/status?domain=%s", CLOUDFLARE_RADAR_API_BASE, domain);

    CURL *curl = curl_easy_init();
    if (!curl) {
        return RADAR_STATUS_ERROR;
    }

    curl_response_buffer_t response = {
        .data = malloc(1),
        .size = 0
    };

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, radar_curl_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);

    CURLcode res = curl_easy_perform(curl);

    radar_scan_status_t status = RADAR_STATUS_ERROR;
    if (res == CURLE_OK) {
        if (strstr(response.data, "completed") != NULL) {
            status = RADAR_STATUS_COMPLETED;
        } else if (strstr(response.data, "pending") != NULL) {
            status = RADAR_STATUS_PENDING;
        } else if (strstr(response.data, "in_progress") != NULL) {
            status = RADAR_STATUS_IN_PROGRESS;
        } else if (strstr(response.data, "failed") != NULL) {
            status = RADAR_STATUS_FAILED;
        }
    }

    free(response.data);
    curl_easy_cleanup(curl);

    return status;
}
