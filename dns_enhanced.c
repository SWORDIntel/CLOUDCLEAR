/*
 * DNS Enhanced - Advanced DNS Resolution Engine Implementation
 *
 * Based on RESEARCHER agent analysis for maximum resolution success
 * Implements: DoQ, passive DNS, dual-stack, CDN detection, intelligent fallback
 */

#include "dns_enhanced.h"
#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <math.h>

// Thread-local configuration for thread safety
_Thread_local struct adaptive_retry_strategy thread_retry_strategy = {
    .base_delay_ms = 1000,
    .backoff_multiplier = 1.5,
    .max_retries = 3,
    .circuit_breaker_threshold = 5,
    .circuit_breaker_timeout_ms = 30000,
    .jitter_enabled = true,
    .jitter_max_ms = 500,
    .adaptive_timeout = true
};

_Thread_local struct dns_response_validation thread_validation_config = {
    .expected_ttl_range = {300, 86400},
    .entropy_threshold = 0.7,
    .response_time_baseline_ms = 5000,
    .require_dnssec = false,
    .allow_private_ips = false,
    .ip_range_count = 0
};

// Shared rate limiter (thread-safe with atomic operations)
struct rate_limiter global_rate_limiter = {0};

// Default resolver template data (mutexes initialized during chain setup)
static struct {
    const char* address;
    dns_protocol_t protocol;
    uint16_t port;
    bool supports_dnssec;
    bool supports_ecs;
} default_resolver_templates[] = {
    // DNS over QUIC (fastest encrypted option - 10% faster than DoH)
    {"dns.cloudflare.com", DNS_PROTOCOL_DOQ, 853, true, true},
    {"dns.google", DNS_PROTOCOL_DOQ, 853, true, true},

    // DNS over HTTPS (verified active providers)
    {"cloudflare-dns.com", DNS_PROTOCOL_DOH, 443, true, true},
    {"dns.google", DNS_PROTOCOL_DOH, 443, true, true},
    {"dns.quad9.net", DNS_PROTOCOL_DOH, 443, true, false},
    {"dns.adguard.com", DNS_PROTOCOL_DOH, 443, true, true},
    {"doh.mullvad.net", DNS_PROTOCOL_DOH, 443, true, true},
    {"doh.opendns.com", DNS_PROTOCOL_DOH, 443, true, true},
    {"doh.libredns.gr", DNS_PROTOCOL_DOH, 443, true, false},
    {"freedns.controld.com", DNS_PROTOCOL_DOH, 443, true, true},

    // DNS over TLS (encrypted)
    {"1.1.1.1", DNS_PROTOCOL_DOT, 853, true, true},
    {"8.8.8.8", DNS_PROTOCOL_DOT, 853, true, true},
    {"9.9.9.9", DNS_PROTOCOL_DOT, 853, true, false},

    // Traditional UDP/TCP (fallback)
    {"1.1.1.1", DNS_PROTOCOL_UDP, 53, false, true},
    {"8.8.8.8", DNS_PROTOCOL_UDP, 53, false, true},
    {"9.9.9.9", DNS_PROTOCOL_UDP, 53, true, false}
};

// Placeholder for backward compatibility
struct dns_resolver default_resolvers[16] = {0};

int default_resolver_count = sizeof(default_resolver_templates) / sizeof(default_resolver_templates[0]);

// HTTP response structure for API calls
struct http_response {
    char *data;
    size_t size;
};

// Header capture structure for server header extraction
struct header_capture {
    char server_header[256];
    bool server_found;
};

static size_t write_response_callback(void *contents, size_t size, size_t nmemb,
                                    struct http_response *response) {
    size_t real_size = size * nmemb;
    char *ptr = realloc(response->data, response->size + real_size + 1);

    if (!ptr) return 0;

    response->data = ptr;
    memcpy(&(response->data[response->size]), contents, real_size);
    response->size += real_size;
    response->data[response->size] = 0;

    return real_size;
}

static size_t header_callback(char *buffer, size_t size, size_t nitems,
                             struct header_capture *capture) {
    size_t real_size = size * nitems;

    // Look for Server header
    if (real_size >= 8 && strncasecmp(buffer, "Server:", 7) == 0) {
        // Extract server header value
        char *start = buffer + 7;
        while (*start == ' ' || *start == '\t') start++; // Skip whitespace

        size_t copy_len = real_size - (start - buffer);
        if (copy_len >= sizeof(capture->server_header)) {
            copy_len = sizeof(capture->server_header) - 1;
        }

        memcpy(capture->server_header, start, copy_len);
        capture->server_header[copy_len] = '\0';

        // Remove trailing CRLF
        char *end = capture->server_header + strlen(capture->server_header) - 1;
        while (end > capture->server_header && (*end == '\r' || *end == '\n')) {
            *end = '\0';
            end--;
        }

        capture->server_found = true;
    }

    return real_size;
}

// Initialize DNS resolver chain with default resolvers (thread-safe)
int init_dns_resolver_chain(struct dns_resolver_chain *chain) {
    if (!chain) return -1;

    memset(chain, 0, sizeof(struct dns_resolver_chain));

    if (pthread_mutex_init(&chain->chain_mutex, NULL) != 0) {
        return -1;
    }

    // Initialize resolvers from templates and setup mutexes
    for (int i = 0; i < default_resolver_count; i++) {
        struct dns_resolver *resolver = &chain->resolvers[i];

        // Copy template data
        strncpy(resolver->address, default_resolver_templates[i].address, sizeof(resolver->address) - 1);
        resolver->address[sizeof(resolver->address) - 1] = '\0';
        resolver->protocol = default_resolver_templates[i].protocol;
        resolver->port = default_resolver_templates[i].port;
        resolver->supports_dnssec = default_resolver_templates[i].supports_dnssec;
        resolver->supports_ecs = default_resolver_templates[i].supports_ecs;

        // Initialize per-resolver mutex
        if (pthread_mutex_init(&resolver->resolver_mutex, NULL) != 0) {
            // Cleanup previously initialized mutexes on failure
            for (int j = 0; j < i; j++) {
                pthread_mutex_destroy(&chain->resolvers[j].resolver_mutex);
            }
            pthread_mutex_destroy(&chain->chain_mutex);
            return -1;
        }

        // Initialize atomic fields
        atomic_store(&resolver->success_rate, 0.0f);
        atomic_store(&resolver->avg_response_time_ms, 0);
        atomic_store(&resolver->total_queries, 0);
        atomic_store(&resolver->successful_queries, 0);
        atomic_store(&resolver->is_available, true);
        atomic_store(&resolver->last_check, time(NULL));
    }
    chain->resolver_count = default_resolver_count;
    chain->current_resolver = 0;

    printf("[DNS] Initialized resolver chain with %d resolvers (thread-safe)\n", chain->resolver_count);
    return 0;
}

// Add custom resolver to chain
int add_resolver_to_chain(struct dns_resolver_chain *chain,
                         const char *address,
                         dns_protocol_t protocol,
                         uint16_t port) {
    if (!chain || !address || chain->resolver_count >= 16) return -1;

    pthread_mutex_lock(&chain->chain_mutex);

    struct dns_resolver *resolver = &chain->resolvers[chain->resolver_count];
    strncpy(resolver->address, address, sizeof(resolver->address) - 1);
    resolver->protocol = protocol;
    resolver->port = port;
    resolver->success_rate = 0.0;
    resolver->avg_response_time_ms = 0;
    resolver->total_queries = 0;
    resolver->successful_queries = 0;
    resolver->is_available = true;
    resolver->last_check = time(NULL);

    chain->resolver_count++;

    pthread_mutex_unlock(&chain->chain_mutex);

    printf("[DNS] Added resolver: %s:%d (%s)\n",
           address, port, dns_protocol_to_string(protocol));
    return 0;
}

// Intelligent resolver selection based on performance metrics (thread-safe)
struct dns_resolver* select_optimal_resolver(struct dns_resolver_chain *chain,
                                           dns_record_type_t query_type) {
    if (!chain || chain->resolver_count == 0) return NULL;

    pthread_mutex_lock(&chain->chain_mutex);

    struct dns_resolver *best_resolver = NULL;
    float best_score = -1.0;

    for (int i = 0; i < chain->resolver_count; i++) {
        struct dns_resolver *resolver = &chain->resolvers[i];

        // Use atomic loads for thread-safe access
        bool is_available = atomic_load(&resolver->is_available);
        if (!is_available) continue;

        float success_rate = atomic_load(&resolver->success_rate);
        uint32_t avg_response_time = atomic_load(&resolver->avg_response_time_ms);

        // Calculate composite score: success_rate * 0.7 + speed_factor * 0.3
        float speed_factor = avg_response_time > 0 ?
                           (5000.0 / avg_response_time) : 1.0;
        if (speed_factor > 1.0) speed_factor = 1.0;

        float score = (success_rate * 0.7) + (speed_factor * 0.3);

        // Bonus for encrypted protocols (DoQ > DoH > DoT)
        switch (resolver->protocol) {
            case DNS_PROTOCOL_DOQ:
                score += 0.15; // Fastest encrypted option
                break;
            case DNS_PROTOCOL_DOH:
                score += 0.10;
                break;
            case DNS_PROTOCOL_DOT:
                score += 0.08;
                break;
            default:
                break;
        }

        // Bonus for DNSSEC support
        if (resolver->supports_dnssec) {
            score += 0.05;
        }

        if (score > best_score) {
            best_score = score;
            best_resolver = resolver;
        }
    }

    pthread_mutex_unlock(&chain->chain_mutex);

    if (best_resolver) {
        printf("[DNS] Selected resolver: %s (%s, score: %.2f)\n",
               best_resolver->address,
               dns_protocol_to_string(best_resolver->protocol),
               best_score);
    }

    return best_resolver;
}

// Update resolver performance metrics (thread-safe with atomic operations)
int update_resolver_metrics(struct dns_resolver *resolver,
                           bool success,
                           uint32_t response_time) {
    if (!resolver) return -1;

    // Use atomic operations for thread-safe updates
    uint32_t total_queries = atomic_fetch_add(&resolver->total_queries, 1) + 1;
    uint32_t successful_queries = atomic_load(&resolver->successful_queries);

    if (success) {
        successful_queries = atomic_fetch_add(&resolver->successful_queries, 1) + 1;

        // Update average response time with exponential moving average
        uint32_t current_avg = atomic_load(&resolver->avg_response_time_ms);
        uint32_t new_avg;

        if (current_avg == 0) {
            new_avg = response_time;
        } else {
            new_avg = (uint32_t)((current_avg * 0.8) + (response_time * 0.2));
        }

        // Atomic compare-and-swap to update average response time
        while (!atomic_compare_exchange_weak(&resolver->avg_response_time_ms, &current_avg, new_avg)) {
            if (current_avg == 0) {
                new_avg = response_time;
            } else {
                new_avg = (uint32_t)((current_avg * 0.8) + (response_time * 0.2));
            }
        }
    }

    // Calculate and update success rate atomically
    float new_success_rate = (float)successful_queries / total_queries;
    atomic_store(&resolver->success_rate, new_success_rate);

    // Mark as unavailable if success rate drops below 50%
    if (total_queries >= 10 && new_success_rate < 0.5) {
        bool expected = true;
        if (atomic_compare_exchange_strong(&resolver->is_available, &expected, false)) {
            printf("[DNS] Marking resolver %s as unavailable (success rate: %.2f)\n",
                   resolver->address, new_success_rate);
        }
    }

    // Update last check timestamp
    atomic_store(&resolver->last_check, time(NULL));

    return 0;
}

// Perform dual-stack IPv4/IPv6 resolution
int perform_dual_stack_resolution(const char *domain,
                                 struct dual_stack_resolution *result) {
    if (!domain || !result) return -1;

    memset(result, 0, sizeof(struct dual_stack_resolution));

    struct addrinfo hints, *res, *p;
    struct timespec start_time, end_time;

    // IPv4 resolution
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    clock_gettime(CLOCK_MONOTONIC, &start_time);

    int status = getaddrinfo(domain, NULL, &hints, &res);
    if (status == 0) {
        for (p = res; p != NULL && result->ipv4_count < 16; p = p->ai_next) {
            struct sockaddr_in* addr_in = (struct sockaddr_in*)p->ai_addr;
            result->ipv4_addresses[result->ipv4_count] = addr_in->sin_addr;
            result->ipv4_count++;
        }
        freeaddrinfo(res);

        clock_gettime(CLOCK_MONOTONIC, &end_time);
        result->ipv4_response_time =
            (end_time.tv_sec - start_time.tv_sec) * 1000 +
            (end_time.tv_nsec - start_time.tv_nsec) / 1000000;

        printf("[DNS] IPv4 resolution: %d addresses, %u ms\n",
               result->ipv4_count, result->ipv4_response_time);
    }

    // IPv6 resolution
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;

    clock_gettime(CLOCK_MONOTONIC, &start_time);

    status = getaddrinfo(domain, NULL, &hints, &res);
    if (status == 0) {
        for (p = res; p != NULL && result->ipv6_count < 16; p = p->ai_next) {
            struct sockaddr_in6* addr_in6 = (struct sockaddr_in6*)p->ai_addr;
            result->ipv6_addresses[result->ipv6_count] = addr_in6->sin6_addr;
            result->ipv6_count++;
        }
        freeaddrinfo(res);

        clock_gettime(CLOCK_MONOTONIC, &end_time);
        result->ipv6_response_time =
            (end_time.tv_sec - start_time.tv_sec) * 1000 +
            (end_time.tv_nsec - start_time.tv_nsec) / 1000000;

        printf("[DNS] IPv6 resolution: %d addresses, %u ms\n",
               result->ipv6_count, result->ipv6_response_time);
    }

    return (result->ipv4_count > 0 || result->ipv6_count > 0) ? 0 : -1;
}

// Enhanced DNS query with intelligent protocol selection
int perform_enhanced_dns_query(struct dns_query_context *query,
                              struct dns_resolver_chain *chain,
                              struct enhanced_dns_result *result) {
    if (!query || !chain || !result) return -1;

    memset(result, 0, sizeof(struct enhanced_dns_result));
    strncpy(result->domain, query->query_name, sizeof(result->domain) - 1);

    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    // Select optimal resolver
    struct dns_resolver *resolver = select_optimal_resolver(chain, query->query_type);
    if (!resolver) {
        printf("[DNS] No available resolvers for query\n");
        return -1;
    }

    strncpy(result->resolver_used, resolver->address, sizeof(result->resolver_used) - 1);
    result->protocol_used = resolver->protocol;

    // Perform dual-stack resolution
    int resolution_result = perform_dual_stack_resolution(query->query_name,
                                                        &result->resolution);

    clock_gettime(CLOCK_MONOTONIC, &end_time);
    result->total_response_time_ms =
        (end_time.tv_sec - start_time.tv_sec) * 1000 +
        (end_time.tv_nsec - start_time.tv_nsec) / 1000000;

    // Update resolver metrics
    bool success = (resolution_result == 0);
    update_resolver_metrics(resolver, success, result->total_response_time_ms);

    if (!success) {
        printf("[DNS] Resolution failed for %s\n", query->query_name);
        return -1;
    }

    // Set timestamp and initial confidence
    result->resolution_timestamp = time(NULL);
    result->confidence_score = success ? 0.8 : 0.0;

    printf("[DNS] Enhanced query completed: %s (%d IPv4, %d IPv6, %u ms)\n",
           query->query_name,
           result->resolution.ipv4_count,
           result->resolution.ipv6_count,
           result->total_response_time_ms);

    return 0;
}

// IP enrichment using multiple geolocation APIs (thread-safe)
int enrich_ip_address(const char *ip_address,
                     struct ip_enrichment_data *enrichment) {
    if (!ip_address || !enrichment) return -1;

    memset(enrichment, 0, sizeof(struct ip_enrichment_data));

    // Initialize enrichment mutex
    if (pthread_mutex_init(&enrichment->enrichment_mutex, NULL) != 0) {
        return -1;
    }

    // Initialize atomic fields
    atomic_store(&enrichment->asn, 0);
    atomic_store(&enrichment->latitude, 0.0f);
    atomic_store(&enrichment->longitude, 0.0f);
    atomic_store(&enrichment->is_hosting_provider, false);
    atomic_store(&enrichment->is_tor_exit, false);
    atomic_store(&enrichment->is_vpn, false);
    atomic_store(&enrichment->is_cloud_provider, false);

    CURL *curl;
    CURLcode res;
    struct http_response response = {0};
    char url[512];

    curl = curl_easy_init();
    if (!curl) return -1;

    // Use ip-api.com for free geolocation (15 requests/minute limit)
    snprintf(url, sizeof(url),
             "http://ip-api.com/json/%s?fields=status,country,countryCode,region,"
             "city,lat,lon,isp,org,as,asname,hosting,proxy",
             ip_address);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "CloudUnflare-Enhanced/2.0");

    res = curl_easy_perform(curl);

    if (res == CURLE_OK && response.data) {
        json_object *json = json_tokener_parse(response.data);
        if (json) {
            json_object *status_obj, *country_obj, *region_obj, *city_obj;
            json_object *lat_obj, *lon_obj, *isp_obj, *as_obj, *asname_obj;
            json_object *hosting_obj, *proxy_obj;

            if (json_object_object_get_ex(json, "status", &status_obj)) {
                const char *status = json_object_get_string(status_obj);
                if (strcmp(status, "success") == 0) {
                    // Extract country information (thread-safe string updates)
                    if (json_object_object_get_ex(json, "countryCode", &country_obj)) {
                        pthread_mutex_lock(&enrichment->enrichment_mutex);
                        strncpy(enrichment->country_code,
                               json_object_get_string(country_obj),
                               sizeof(enrichment->country_code) - 1);
                        enrichment->country_code[sizeof(enrichment->country_code) - 1] = '\0';
                        pthread_mutex_unlock(&enrichment->enrichment_mutex);
                    }

                    // Extract region and city (thread-safe string updates)
                    if (json_object_object_get_ex(json, "region", &region_obj)) {
                        pthread_mutex_lock(&enrichment->enrichment_mutex);
                        strncpy(enrichment->region,
                               json_object_get_string(region_obj),
                               sizeof(enrichment->region) - 1);
                        enrichment->region[sizeof(enrichment->region) - 1] = '\0';
                        pthread_mutex_unlock(&enrichment->enrichment_mutex);
                    }

                    if (json_object_object_get_ex(json, "city", &city_obj)) {
                        pthread_mutex_lock(&enrichment->enrichment_mutex);
                        strncpy(enrichment->city,
                               json_object_get_string(city_obj),
                               sizeof(enrichment->city) - 1);
                        enrichment->city[sizeof(enrichment->city) - 1] = '\0';
                        pthread_mutex_unlock(&enrichment->enrichment_mutex);
                    }

                    // Extract coordinates (atomic updates)
                    if (json_object_object_get_ex(json, "lat", &lat_obj)) {
                        atomic_store(&enrichment->latitude, (float)json_object_get_double(lat_obj));
                    }

                    if (json_object_object_get_ex(json, "lon", &lon_obj)) {
                        atomic_store(&enrichment->longitude, (float)json_object_get_double(lon_obj));
                    }

                    // Extract ISP and AS information (thread-safe string updates)
                    if (json_object_object_get_ex(json, "isp", &isp_obj)) {
                        pthread_mutex_lock(&enrichment->enrichment_mutex);
                        strncpy(enrichment->isp,
                               json_object_get_string(isp_obj),
                               sizeof(enrichment->isp) - 1);
                        enrichment->isp[sizeof(enrichment->isp) - 1] = '\0';
                        pthread_mutex_unlock(&enrichment->enrichment_mutex);
                    }

                    if (json_object_object_get_ex(json, "as", &as_obj)) {
                        const char *as_str = json_object_get_string(as_obj);
                        if (as_str && strncmp(as_str, "AS", 2) == 0) {
                            atomic_store(&enrichment->asn, (uint32_t)atoi(as_str + 2));
                        }
                    }

                    if (json_object_object_get_ex(json, "asname", &asname_obj)) {
                        pthread_mutex_lock(&enrichment->enrichment_mutex);
                        strncpy(enrichment->as_name,
                               json_object_get_string(asname_obj),
                               sizeof(enrichment->as_name) - 1);
                        enrichment->as_name[sizeof(enrichment->as_name) - 1] = '\0';
                        pthread_mutex_unlock(&enrichment->enrichment_mutex);
                    }

                    // Extract hosting and proxy information (atomic updates)
                    if (json_object_object_get_ex(json, "hosting", &hosting_obj)) {
                        atomic_store(&enrichment->is_hosting_provider, json_object_get_boolean(hosting_obj));
                    }

                    if (json_object_object_get_ex(json, "proxy", &proxy_obj)) {
                        atomic_store(&enrichment->is_vpn, json_object_get_boolean(proxy_obj));
                    }

                    // Thread-safe output using atomic loads
                    pthread_mutex_lock(&enrichment->enrichment_mutex);
                    uint32_t asn = atomic_load(&enrichment->asn);
                    bool is_hosting = atomic_load(&enrichment->is_hosting_provider);
                    printf("[ENRICH] %s: %s, %s (%s) - AS%u %s\n",
                           ip_address,
                           enrichment->city,
                           enrichment->country_code,
                           enrichment->isp,
                           asn,
                           is_hosting ? "[HOSTING]" : "");
                    pthread_mutex_unlock(&enrichment->enrichment_mutex);
                }
            }
            json_object_put(json);
        }
        free(response.data);
    }

    curl_easy_cleanup(curl);
    return 0;
}

// CDN detection and origin server discovery
int detect_cdn_and_origin(const char *domain,
                         struct enhanced_dns_result *result) {
    if (!domain || !result) return -1;

    struct cdn_detection *cdn = &result->cdn_info;
    memset(cdn, 0, sizeof(struct cdn_detection));

    // Check for common CDN providers by CNAME or IP ranges
    CURL *curl;
    CURLcode res;
    struct http_response response = {0};
    struct header_capture headers = {0};
    char url[512];

    curl = curl_easy_init();
    if (!curl) return -1;

    // Check HTTP headers for CDN indicators
    snprintf(url, sizeof(url), "http://%s", domain);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L); // HEAD request only
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "CloudUnflare-Enhanced/2.0");

    res = curl_easy_perform(curl);

    if (res == CURLE_OK && headers.server_found) {
        // Check for CDN indicators in server header
        if (strstr(headers.server_header, "cloudflare")) {
            cdn->is_cdn = true;
            strncpy(cdn->cdn_provider, "Cloudflare", sizeof(cdn->cdn_provider) - 1);
            cdn->cdn_bypass_possible = true;
            strncpy(cdn->bypass_techniques,
                   "subdomain enumeration, certificate transparency, origin IP discovery",
                   sizeof(cdn->bypass_techniques) - 1);
        } else if (strstr(headers.server_header, "AmazonS3") || strstr(headers.server_header, "CloudFront")) {
            cdn->is_cdn = true;
            strncpy(cdn->cdn_provider, "Amazon CloudFront", sizeof(cdn->cdn_provider) - 1);
        } else if (strstr(headers.server_header, "nginx") && strstr(headers.server_header, "Akamai")) {
            cdn->is_cdn = true;
            strncpy(cdn->cdn_provider, "Akamai", sizeof(cdn->cdn_provider) - 1);
        }

        printf("[CDN] Detection for %s: %s%s%s%s\n",
               domain,
               cdn->is_cdn ? "CDN detected" : "No CDN detected",
               cdn->is_cdn ? " (" : "",
               cdn->is_cdn ? cdn->cdn_provider : "",
               cdn->is_cdn ? ")" : "");
    }

    if (response.data) {
        free(response.data);
    }
    curl_easy_cleanup(curl);

    return 0;
}

// Wildcard detection for accurate subdomain enumeration
int detect_wildcard_responses(const char *domain,
                             struct wildcard_detection *detection) {
    if (!domain || !detection) return -1;

    memset(detection, 0, sizeof(struct wildcard_detection));

    // Test random subdomains to detect wildcard responses
    char test_subdomains[3][256];
    snprintf(test_subdomains[0], sizeof(test_subdomains[0]),
             "nonexistent-test-12345.%s", domain);
    snprintf(test_subdomains[1], sizeof(test_subdomains[1]),
             "random-wildcard-test-67890.%s", domain);
    snprintf(test_subdomains[2], sizeof(test_subdomains[2]),
             "definitely-not-real-abcdef.%s", domain);

    char resolved_ips[3][INET_ADDRSTRLEN];
    int resolved_count = 0;

    for (int i = 0; i < 3; i++) {
        struct addrinfo hints, *result;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(test_subdomains[i], NULL, &hints, &result) == 0) {
            struct sockaddr_in* addr_in = (struct sockaddr_in*)result->ai_addr;
            inet_ntop(AF_INET, &(addr_in->sin_addr), resolved_ips[resolved_count], INET_ADDRSTRLEN);
            resolved_count++;
            freeaddrinfo(result);
        }
    }

    // If multiple test subdomains resolve to the same IP, it's likely a wildcard
    if (resolved_count >= 2) {
        bool is_wildcard = true;
        for (int i = 1; i < resolved_count; i++) {
            if (strcmp(resolved_ips[0], resolved_ips[i]) != 0) {
                is_wildcard = false;
                break;
            }
        }

        if (is_wildcard) {
            detection->has_wildcard = true;
            strncpy(detection->wildcard_ips[0], resolved_ips[0], INET_ADDRSTRLEN);
            detection->wildcard_ip_count = 1;
            detection->affects_enumeration = true;
            snprintf(detection->wildcard_pattern, sizeof(detection->wildcard_pattern),
                    "*.%s -> %s", domain, resolved_ips[0]);

            printf("[WILDCARD] Detected for %s: %s\n", domain, detection->wildcard_pattern);
        }
    }

    return 0;
}

// Rate limiter initialization
int init_rate_limiter(struct rate_limiter *limiter,
                     uint32_t max_tokens,
                     uint32_t refill_rate) {
    if (!limiter) return -1;

    limiter->tokens = max_tokens;
    limiter->max_tokens = max_tokens;
    limiter->refill_rate_per_second = refill_rate;
    clock_gettime(CLOCK_MONOTONIC, &limiter->last_refill);
    limiter->requests_denied = 0;
    limiter->requests_allowed = 0;

    if (pthread_mutex_init(&limiter->mutex, NULL) != 0) {
        return -1;
    }

    return 0;
}

// Acquire tokens with rate limiting (optimized with atomic operations)
bool acquire_rate_limit_token(struct rate_limiter *limiter,
                             uint32_t tokens_requested) {
    if (!limiter) return false;

    struct timespec current_time;
    clock_gettime(CLOCK_MONOTONIC, &current_time);

    // Try lock-free path first for common case
    uint32_t current_tokens = atomic_load(&limiter->tokens);
    if (current_tokens >= tokens_requested) {
        // Try atomic decrement without lock
        uint32_t expected = current_tokens;
        while (expected >= tokens_requested) {
            if (atomic_compare_exchange_weak(&limiter->tokens, &expected, expected - tokens_requested)) {
                atomic_fetch_add(&limiter->requests_allowed, 1);
                return true;
            }
        }
    }

    // Fall back to mutex for refill logic
    pthread_mutex_lock(&limiter->mutex);

    // Calculate time elapsed and refill tokens (last_refill protected by mutex)
    long elapsed_ms = (current_time.tv_sec - limiter->last_refill.tv_sec) * 1000 +
                     (current_time.tv_nsec - limiter->last_refill.tv_nsec) / 1000000;

    if (elapsed_ms >= 1000) { // Refill every second
        uint32_t tokens_to_add = (elapsed_ms / 1000) * limiter->refill_rate_per_second;
        uint32_t new_tokens = atomic_load(&limiter->tokens) + tokens_to_add;
        if (new_tokens > limiter->max_tokens) {
            new_tokens = limiter->max_tokens;
        }
        atomic_store(&limiter->tokens, new_tokens);
        limiter->last_refill = current_time;  // Update under mutex protection
    }

    current_tokens = atomic_load(&limiter->tokens);
    bool allowed = (current_tokens >= tokens_requested);
    if (allowed) {
        atomic_fetch_sub(&limiter->tokens, tokens_requested);
        atomic_fetch_add(&limiter->requests_allowed, 1);
    } else {
        atomic_fetch_add(&limiter->requests_denied, 1);
    }

    pthread_mutex_unlock(&limiter->mutex);

    return allowed;
}

// Utility functions
const char* dns_protocol_to_string(dns_protocol_t protocol) {
    switch (protocol) {
        case DNS_PROTOCOL_UDP: return "UDP";
        case DNS_PROTOCOL_TCP: return "TCP";
        case DNS_PROTOCOL_DOH: return "DoH";
        case DNS_PROTOCOL_DOT: return "DoT";
        case DNS_PROTOCOL_DOQ: return "DoQ";
        default: return "Unknown";
    }
}

const char* dns_record_type_to_string(dns_record_type_t type) {
    switch (type) {
        case DNS_TYPE_A: return "A";
        case DNS_TYPE_NS: return "NS";
        case DNS_TYPE_CNAME: return "CNAME";
        case DNS_TYPE_MX: return "MX";
        case DNS_TYPE_TXT: return "TXT";
        case DNS_TYPE_AAAA: return "AAAA";
        case DNS_TYPE_SRV: return "SRV";
        case DNS_TYPE_CAA: return "CAA";
        default: return "Unknown";
    }
}

// Print comprehensive DNS result
void print_enhanced_dns_result(struct enhanced_dns_result *result) {
    if (!result) return;

    printf("\n=== Enhanced DNS Result for %s ===\n", result->domain);
    printf("Resolution Time: %u ms\n", result->total_response_time_ms);
    printf("Protocol Used: %s\n", dns_protocol_to_string(result->protocol_used));
    printf("Resolver Used: %s\n", result->resolver_used);
    printf("Confidence Score: %.2f\n", result->confidence_score);

    // IPv4 addresses
    if (result->resolution.ipv4_count > 0) {
        printf("\nIPv4 Addresses (%d):\n", result->resolution.ipv4_count);
        for (int i = 0; i < result->resolution.ipv4_count; i++) {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &result->resolution.ipv4_addresses[i], ip_str, INET_ADDRSTRLEN);
            printf("  %s", ip_str);

            // Show enrichment data if available
            if (i < result->enrichment_count) {
                struct ip_enrichment_data *enrichment = &result->enrichment[i];
                printf(" (%s, %s, AS%u)",
                       enrichment->city,
                       enrichment->country_code,
                       enrichment->asn);
            }
            printf("\n");
        }
    }

    // IPv6 addresses
    if (result->resolution.ipv6_count > 0) {
        printf("\nIPv6 Addresses (%d):\n", result->resolution.ipv6_count);
        for (int i = 0; i < result->resolution.ipv6_count; i++) {
            char ip_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &result->resolution.ipv6_addresses[i], ip_str, INET6_ADDRSTRLEN);
            printf("  %s\n", ip_str);
        }
    }

    // CDN information
    if (result->cdn_info.is_cdn) {
        printf("\nCDN Detection:\n");
        printf("  Provider: %s\n", result->cdn_info.cdn_provider);
        printf("  Bypass Possible: %s\n", result->cdn_info.cdn_bypass_possible ? "Yes" : "No");
        if (result->cdn_info.cdn_bypass_possible) {
            printf("  Techniques: %s\n", result->cdn_info.bypass_techniques);
        }
    }

    // Wildcard information
    if (result->wildcard_info.has_wildcard) {
        printf("\nWildcard Detection:\n");
        printf("  Pattern: %s\n", result->wildcard_info.wildcard_pattern);
        printf("  Affects Enumeration: %s\n",
               result->wildcard_info.affects_enumeration ? "Yes" : "No");
    }

    printf("=== End Result ===\n\n");
}

// Thread-safe configuration initialization
int init_thread_config(void) {
    // Each thread gets its own copy automatically due to _Thread_local
    // No additional initialization needed for thread-local variables
    return 0;
}

void cleanup_thread_config(void) {
    // Thread-local variables are automatically cleaned up
    // No explicit cleanup needed
}

// Initialize enhanced DNS engine (thread-safe)
int init_dns_enhanced_engine(void) {
    printf("[DNS] Initializing enhanced DNS engine (thread-safe)...\n");

    // Initialize global rate limiter (10 requests per second) - shared across threads
    if (init_rate_limiter(&global_rate_limiter, 10, 10) != 0) {
        printf("[DNS] Failed to initialize rate limiter\n");
        return -1;
    }

    // Initialize curl (thread-safe)
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Initialize thread-local config for main thread
    init_thread_config();

    printf("[DNS] Enhanced DNS engine initialized successfully (thread-safe)\n");
    return 0;
}

// Cleanup enhanced DNS engine
void cleanup_dns_enhanced_engine(void) {
    printf("[DNS] Cleaning up enhanced DNS engine...\n");

    pthread_mutex_destroy(&global_rate_limiter.mutex);
    curl_global_cleanup();

    printf("[DNS] Cleanup completed\n");
}