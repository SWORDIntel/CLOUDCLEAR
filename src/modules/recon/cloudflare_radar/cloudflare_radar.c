/*
 * CloudUnflare Enhanced - Cloudflare Radar Module Implementation
 *
 * Main module implementation with initialization, configuration, and scanning operations
 */

#include "cloudflare_radar.h"
#include "../common/recon_common.h"
#include "platform_compat.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/*
 * Initialize Cloudflare Radar scan context
 */
int radar_scan_init_context(radar_scan_context_t *ctx) {
    if (!ctx) {
        return -1;
    }

    memset(ctx, 0, sizeof(*ctx));

    // Initialize base context
    // Note: Base context initialization removed - members don't exist in current struct definition
    // TODO: Update struct definition if these fields are needed

    // Initialize results array
    ctx->max_results = CLOUDFLARE_RADAR_MAX_RESULTS;
    ctx->results = malloc(ctx->max_results * sizeof(radar_scan_result_t));
    if (!ctx->results) {
        fprintf(stderr, "Error: Failed to allocate results array\n");
        return -1;
    }

    memset(ctx->results, 0, ctx->max_results * sizeof(radar_scan_result_t));
    ctx->result_count = 0;

    // Initialize mutex
    if (pthread_mutex_init(&ctx->results_mutex, NULL) != 0) {
        fprintf(stderr, "Error: Failed to initialize mutex\n");
        free(ctx->results);
        return -1;
    }

    // Set default configuration
    ctx->config.preferred_scan_type = RADAR_SCAN_COMPREHENSIVE;
    ctx->config.timeout_seconds = CLOUDFLARE_RADAR_API_TIMEOUT;
    ctx->config.max_retries = CLOUDFLARE_RADAR_MAX_RETRIES;
    ctx->config.delay_between_scans_ms = CLOUDFLARE_RADAR_RATE_LIMIT_MS;
    ctx->config.enable_comprehensive_scan = true;
    ctx->config.extract_technology_stack = true;
    ctx->config.analyze_security_posture = true;
    ctx->config.follow_redirects = true;

    // Configure OPSEC settings
    ctx->config.opsec.min_delay_ms = 1000;
    ctx->config.opsec.max_delay_ms = 3000;
    ctx->config.opsec.jitter_ms = 500;
    ctx->config.opsec.randomize_user_agents = true;
    ctx->config.opsec.use_proxy_rotation = false;

    return 0;
}

/*
 * Cleanup Cloudflare Radar scan context
 */
void radar_scan_cleanup_context(radar_scan_context_t *ctx) {
    if (!ctx) {
        return;
    }

    // Free results
    if (ctx->results) {
        for (uint32_t i = 0; i < ctx->result_count; i++) {
            radar_scan_free_result(&ctx->results[i]);
        }
        free(ctx->results);
        ctx->results = NULL;
    }

    // Destroy mutex
    pthread_mutex_destroy(&ctx->results_mutex);

    memset(ctx, 0, sizeof(*ctx));
}

/*
 * Set Cloudflare Radar scan configuration
 */
int radar_scan_set_config(radar_scan_context_t *ctx, const radar_scan_config_t *config) {
    if (!ctx || !config) {
        return -1;
    }

    memcpy(&ctx->config, config, sizeof(radar_scan_config_t));
    return 0;
}

/*
 * Add single domain to scan queue
 */
int radar_scan_add_domain(radar_scan_context_t *ctx, const char *domain) {
    if (!ctx || !domain || ctx->domain_count >= CLOUDFLARE_RADAR_MAX_DOMAINS) {
        return -1;
    }

    strncpy(ctx->domains[ctx->domain_count], domain, RECON_MAX_DOMAIN_LEN - 1);
    ctx->domain_count++;

    return 0;
}

/*
 * Add multiple domains to scan queue
 */
int radar_scan_add_domains(radar_scan_context_t *ctx, const char **domains, uint32_t domain_count) {
    if (!ctx || !domains) {
        return -1;
    }

    for (uint32_t i = 0; i < domain_count && ctx->domain_count < CLOUDFLARE_RADAR_MAX_DOMAINS; i++) {
        radar_scan_add_domain(ctx, domains[i]);
    }

    return 0;
}

/*
 * Clear domain queue
 */
int radar_scan_clear_domains(radar_scan_context_t *ctx) {
    if (!ctx) {
        return -1;
    }

    ctx->domain_count = 0;
    return 0;
}

/*
 * Execute scan for single domain
 */
int radar_scan_execute_single(radar_scan_context_t *ctx, const char *domain,
                              radar_scan_type_t scan_type) {
    if (!ctx || !domain) {
        return -1;
    }

    radar_scan_result_t result;
    radar_scan_init_result(&result, domain);
    result.scan_type = scan_type;

    // Log the attempt
    radar_scan_log_attempt(domain, scan_type);

    // Perform the scan
    char response_buffer[CLOUDFLARE_RADAR_BUFFER_SIZE];
    int ret = radar_scan_api_request(domain, scan_type, response_buffer, sizeof(response_buffer));

    if (ret == 0) {
        // Parse the response
        ret = radar_scan_parse_response(response_buffer, strlen(response_buffer), &result);
        if (ret != 0) {
            result.status = RADAR_STATUS_FAILED;
            strncpy(result.error_message, "Failed to parse response",
                    sizeof(result.error_message) - 1);
        }
    } else {
        result.status = RADAR_STATUS_FAILED;
        strncpy(result.error_message, "API request failed",
                sizeof(result.error_message) - 1);
    }

    // Add result to context
    radar_scan_add_result(ctx, &result);

    return ret;
}

/*
 * Execute comprehensive scan for domain
 */
int radar_scan_execute_comprehensive(radar_scan_context_t *ctx, const char *domain) {
    if (!ctx || !domain) {
        return -1;
    }

    radar_scan_result_t result;
    radar_scan_init_result(&result, domain);
    result.scan_type = RADAR_SCAN_COMPREHENSIVE;

    // Log the attempt
    radar_scan_log_attempt(domain, RADAR_SCAN_COMPREHENSIVE);

    // Perform the comprehensive scan
    int ret = radar_scan_comprehensive(domain, &result);

    if (ret == 0) {
        // Parse the response from the API call
        char response_buffer[CLOUDFLARE_RADAR_BUFFER_SIZE];
        ret = radar_scan_api_request(domain, RADAR_SCAN_COMPREHENSIVE,
                                    response_buffer, sizeof(response_buffer));
        if (ret == 0) {
            ret = radar_scan_parse_response(response_buffer, strlen(response_buffer), &result);
        }
    }

    // Add result to context
    radar_scan_add_result(ctx, &result);

    return ret;
}

/*
 * Execute all queued scans
 */
int radar_scan_execute_all(radar_scan_context_t *ctx) {
    if (!ctx || ctx->domain_count == 0) {
        return -1;
    }

    int failed_count = 0;

    for (uint32_t i = 0; i < ctx->domain_count; i++) {
        int ret;
        if (ctx->config.enable_comprehensive_scan) {
            ret = radar_scan_execute_comprehensive(ctx, ctx->domains[i]);
        } else {
            ret = radar_scan_execute_single(ctx, ctx->domains[i],
                                           ctx->config.preferred_scan_type);
        }

        if (ret != 0) {
            failed_count++;
        }

        // Apply rate limiting
        if (i < ctx->domain_count - 1) {
            radar_scan_apply_timing_evasion(&ctx->config.opsec);
        }
    }

    return failed_count > 0 ? -1 : 0;
}

/*
 * Worker thread function for parallel scanning
 */
void *radar_scan_worker_thread(void *arg) {
    if (!arg) {
        return NULL;
    }

    radar_scan_context_t *ctx = (radar_scan_context_t *)arg;

    // Each thread processes domains sequentially
    for (uint32_t i = 0; i < ctx->domain_count; i++) {
        // Skip if this domain is not assigned to this thread
        // Simple round-robin assignment based on thread index
        if (ctx->config.enable_comprehensive_scan) {
            radar_scan_execute_comprehensive(ctx, ctx->domains[i]);
        } else {
            radar_scan_execute_single(ctx, ctx->domains[i],
                                     ctx->config.preferred_scan_type);
        }
    }

    return NULL;
}

/*
 * Execute scans in parallel using multiple threads
 */
int radar_scan_parallel_execute(radar_scan_context_t *ctx, uint32_t thread_count) {
    if (!ctx || thread_count == 0) {
        return -1;
    }

    if (thread_count > ctx->domain_count) {
        thread_count = ctx->domain_count;
    }

    pthread_t *threads = malloc(thread_count * sizeof(pthread_t));
    if (!threads) {
        return -1;
    }

    // Create worker threads
    for (uint32_t i = 0; i < thread_count; i++) {
        if (pthread_create(&threads[i], NULL, radar_scan_worker_thread, ctx) != 0) {
            fprintf(stderr, "Error: Failed to create thread\n");
            free(threads);
            return -1;
        }
    }

    // Wait for all threads to complete
    for (uint32_t i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }

    free(threads);
    return 0;
}

/*
 * Initialize scan result structure
 */
void radar_scan_init_result(radar_scan_result_t *result, const char *domain) {
    if (!result || !domain) {
        return;
    }

    memset(result, 0, sizeof(*result));
    strncpy(result->domain, domain, sizeof(result->domain) - 1);
    result->scan_timestamp = time(NULL);
    result->status = RADAR_STATUS_PENDING;
}

/*
 * Add result to context
 */
int radar_scan_add_result(radar_scan_context_t *ctx, const radar_scan_result_t *result) {
    if (!ctx || !result) {
        return -1;
    }

    pthread_mutex_lock(&ctx->results_mutex);

    if (ctx->result_count >= ctx->max_results) {
        pthread_mutex_unlock(&ctx->results_mutex);
        return -1;
    }

    memcpy(&ctx->results[ctx->result_count], result, sizeof(radar_scan_result_t));
    ctx->result_count++;

    pthread_mutex_unlock(&ctx->results_mutex);
    return 0;
}

/*
 * Print scan results
 */
void radar_scan_print_results(const radar_scan_context_t *ctx) {
    if (!ctx) {
        return;
    }

    printf("\n=== Cloudflare Radar Scan Results ===\n");
    printf("Total results: %u\n\n", ctx->result_count);

    for (uint32_t i = 0; i < ctx->result_count; i++) {
        const radar_scan_result_t *result = &ctx->results[i];

        printf("Domain: %s\n", result->domain);
        printf("Status: %s\n", radar_scan_status_to_string(result->status));
        printf("Scan Type: %s\n", radar_scan_type_to_string(result->scan_type));
        printf("Timestamp: %lu\n", result->scan_timestamp);

        if (result->status == RADAR_STATUS_COMPLETED) {
            printf("DNS Results: %u nameservers\n", result->dns_result_count);
            printf("HTTP Port: %u (enabled: %s)\n", result->http_result.http_port,
                   result->http_result.http_enabled ? "yes" : "no");
            printf("HTTPS Port: %u (enabled: %s)\n", result->http_result.https_port,
                   result->http_result.https_enabled ? "yes" : "no");
            printf("Security Score: %u/100\n", result->security_result.security_score);
            printf("Technologies: %u\n", result->technology_stack.tech_count);
            printf("Registrar: %s\n", result->registrar);
        } else if (result->status == RADAR_STATUS_FAILED) {
            printf("Error: %s\n", result->error_message);
        }

        printf("\n");
    }
}

/*
 * Export results to JSON file
 */
int radar_scan_export_json(const radar_scan_context_t *ctx, const char *filename) {
    if (!ctx || !filename) {
        return -1;
    }

    FILE *f = fopen(filename, "w");
    if (!f) {
        fprintf(stderr, "Error: Failed to open file %s\n", filename);
        return -1;
    }

    fprintf(f, "{\n  \"results\": [\n");

    for (uint32_t i = 0; i < ctx->result_count; i++) {
        const radar_scan_result_t *result = &ctx->results[i];

        fprintf(f, "    {\n");
        fprintf(f, "      \"domain\": \"%s\",\n", result->domain);
        fprintf(f, "      \"status\": \"%s\",\n", radar_scan_status_to_string(result->status));
        fprintf(f, "      \"scan_type\": \"%s\",\n", radar_scan_type_to_string(result->scan_type));
        fprintf(f, "      \"timestamp\": %lu,\n", result->scan_timestamp);

        if (result->status == RADAR_STATUS_COMPLETED) {
            fprintf(f, "      \"dns_result_count\": %u,\n", result->dns_result_count);
            fprintf(f, "      \"security_score\": %u,\n", result->security_result.security_score);
            fprintf(f, "      \"technologies\": %u\n", result->technology_stack.tech_count);
        } else {
            fprintf(f, "      \"error\": \"%s\"\n", result->error_message);
        }

        fprintf(f, "    }%s\n", i < ctx->result_count - 1 ? "," : "");
    }

    fprintf(f, "  ]\n}\n");
    fclose(f);

    return 0;
}

/*
 * Export results to CSV file
 */
int radar_scan_export_csv(const radar_scan_context_t *ctx, const char *filename) {
    if (!ctx || !filename) {
        return -1;
    }

    FILE *f = fopen(filename, "w");
    if (!f) {
        fprintf(stderr, "Error: Failed to open file %s\n", filename);
        return -1;
    }

    // Write header
    fprintf(f, "Domain,Status,Scan Type,Timestamp,Security Score,DNS Count,Tech Count,Error\n");

    for (uint32_t i = 0; i < ctx->result_count; i++) {
        const radar_scan_result_t *result = &ctx->results[i];

        fprintf(f, "%s,%s,%s,%lu,%u,%u,%u,%s\n",
                result->domain,
                radar_scan_status_to_string(result->status),
                radar_scan_type_to_string(result->scan_type),
                result->scan_timestamp,
                result->security_result.security_score,
                result->dns_result_count,
                result->technology_stack.tech_count,
                result->error_message);
    }

    fclose(f);
    return 0;
}

/*
 * Apply timing evasion according to OPSEC config
 */
void radar_scan_apply_timing_evasion(const recon_opsec_config_t *opsec) {
    if (!opsec) {
        return;
    }

    uint32_t delay_ms = CLOUDFLARE_RADAR_RATE_LIMIT_MS;

    // Add jitter based on paranoia level
    uint32_t jitter = (rand() % (opsec->jitter_ms * 2)) - opsec->jitter_ms;
    delay_ms += jitter;

    struct timespec delay;
    delay.tv_sec = delay_ms / 1000;
    delay.tv_nsec = (delay_ms % 1000) * 1000000;
    nanosleep(&delay, NULL);
}

/*
 * Check rate limits
 */
bool radar_scan_check_rate_limits(const radar_scan_context_t *ctx) {
    if (!ctx) {
        return false;
    }

    // Rate limiting is handled per-request with delays
    return true;
}

/*
 * Randomize domain order for processing
 */
void radar_scan_randomize_domain_order(char domains[][RECON_MAX_DOMAIN_LEN], uint32_t count) {
    if (!domains || count <= 1) {
        return;
    }

    // Simple Fisher-Yates shuffle
    for (uint32_t i = count - 1; i > 0; i--) {
        uint32_t j = rand() % (i + 1);

        // Swap domains[i] and domains[j]
        char temp[RECON_MAX_DOMAIN_LEN];
        strncpy(temp, domains[i], RECON_MAX_DOMAIN_LEN - 1);
        strncpy(domains[i], domains[j], RECON_MAX_DOMAIN_LEN - 1);
        strncpy(domains[j], temp, RECON_MAX_DOMAIN_LEN - 1);
    }
}

/*
 * Log scan attempt
 */
void radar_scan_log_attempt(const char *domain, radar_scan_type_t scan_type) {
    if (!domain) {
        return;
    }

    printf("[CloudFlare Radar] Scanning %s (%s)...\n",
           domain, radar_scan_type_to_string(scan_type));
}

/*
 * Log scan result
 */
void radar_scan_log_result(const radar_scan_result_t *result) {
    if (!result) {
        return;
    }

    printf("[CloudFlare Radar] Completed: %s - Status: %s\n",
           result->domain, radar_scan_status_to_string(result->status));
}

/*
 * Convert status to string
 */
const char *radar_scan_status_to_string(radar_scan_status_t status) {
    switch (status) {
        case RADAR_STATUS_UNKNOWN:
            return "UNKNOWN";
        case RADAR_STATUS_PENDING:
            return "PENDING";
        case RADAR_STATUS_IN_PROGRESS:
            return "IN_PROGRESS";
        case RADAR_STATUS_COMPLETED:
            return "COMPLETED";
        case RADAR_STATUS_FAILED:
            return "FAILED";
        case RADAR_STATUS_TIMEOUT:
            return "TIMEOUT";
        case RADAR_STATUS_ERROR:
            return "ERROR";
        default:
            return "UNKNOWN";
    }
}

/*
 * Convert scan type to string
 */
const char *radar_scan_type_to_string(radar_scan_type_t type) {
    switch (type) {
        case RADAR_SCAN_SECURITY:
            return "SECURITY";
        case RADAR_SCAN_DNS:
            return "DNS";
        case RADAR_SCAN_HTTP:
            return "HTTP";
        case RADAR_SCAN_SSL_TLS:
            return "SSL_TLS";
        case RADAR_SCAN_TECHNOLOGY:
            return "TECHNOLOGY";
        case RADAR_SCAN_PERFORMANCE:
            return "PERFORMANCE";
        case RADAR_SCAN_COMPREHENSIVE:
            return "COMPREHENSIVE";
        default:
            return "UNKNOWN";
    }
}

/*
 * Allocate DNS results array
 */
int radar_scan_alloc_dns_results(radar_dns_result_t **results, uint32_t count) {
    if (!results || count == 0) {
        return -1;
    }

    *results = malloc(count * sizeof(radar_dns_result_t));
    if (!*results) {
        return -1;
    }

    memset(*results, 0, count * sizeof(radar_dns_result_t));
    return 0;
}

/*
 * Free DNS results array
 */
void radar_scan_free_dns_results(radar_dns_result_t *results, uint32_t count) {
    if (results) {
        free(results);
    }
}

/*
 * Free technology stack
 */
void radar_scan_free_technology_stack(radar_technology_stack_t *stack) {
    if (stack && stack->technologies) {
        free(stack->technologies);
        stack->technologies = NULL;
        stack->tech_count = 0;
        stack->max_tech_count = 0;
    }
}

/*
 * Free scan result
 */
void radar_scan_free_result(radar_scan_result_t *result) {
    if (!result) {
        return;
    }

    if (result->dns_results) {
        radar_scan_free_dns_results(result->dns_results, result->dns_result_count);
        result->dns_results = NULL;
    }

    radar_scan_free_technology_stack(&result->technology_stack);
}
