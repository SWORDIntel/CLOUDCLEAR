/*
 * CloudUnflare Enhanced - DNS Brute-Force Implementation v2.0
 *
 * Enhanced DNS subdomain enumeration with intelligent wordlists,
 * recursive enumeration, pattern-based discovery, and OPSEC compliance
 *
 * Performance Target: 2000+ subdomains/second
 * Thread Architecture: 50 optimized worker threads
 * Memory Management: Streaming processing for large wordlists
 * OPSEC Compliance: Anti-detection timing and behavior
 *
 * Agent: C-INTERNAL (primary implementation)
 */

#include "dns_bruteforce_enhanced.h"
#include "platform_compat.h"
#include <math.h>
#ifndef _WIN32
    #include <sys/time.h>
    #include <regex.h>
#endif

// Global configuration defaults
enhanced_opsec_config_t default_opsec_config = {
    .base_delay_ms = 100,
    .jitter_range_ms = 50,
    .burst_limit = 10,
    .burst_cooldown_ms = 1000,
    .session_timeout_s = 300,
    .randomize_resolver_order = true,
    .use_multiple_sources = true,
    .detect_rate_limiting = true,
    .paranoia_level = 5.0
};

// High-value subdomain patterns for prioritization
static const char *high_value_subdomains[] = {
    "admin", "api", "www", "mail", "ftp", "ssh", "vpn", "staging", "dev", "test",
    "prod", "production", "jenkins", "gitlab", "database", "db", "mysql", "postgres",
    "redis", "elastic", "kibana", "grafana", "prometheus", "monitoring", "logs",
    "backup", "file", "files", "upload", "downloads", "cdn", "static", "assets",
    "blog", "forum", "shop", "store", "payment", "billing", "invoice", "support",
    "help", "docs", "documentation", "wiki", "portal", "dashboard", "panel",
    "control", "manage", "management", "config", "configuration", "settings"
};

static const int high_value_subdomain_count = sizeof(high_value_subdomains) / sizeof(char*);

// Core initialization and management functions

int enhanced_bruteforce_init_context(enhanced_bruteforce_context_t *ctx) {
    if (!ctx) return -1;

    memset(ctx, 0, sizeof(enhanced_bruteforce_context_t));

    // Initialize base reconnaissance context
    if (recon_init_context(&ctx->base_ctx, RECON_MODE_ACTIVE) != 0) {
        return -1;
    }

    // Initialize mutexes
    if (pthread_mutex_init(&ctx->results_mutex, NULL) != 0) {
        recon_cleanup_context(&ctx->base_ctx);
        return -1;
    }

    if (pthread_mutex_init(&ctx->work_queue_mutex, NULL) != 0) {
        pthread_mutex_destroy(&ctx->results_mutex);
        recon_cleanup_context(&ctx->base_ctx);
        return -1;
    }

    if (pthread_cond_init(&ctx->work_available_cond, NULL) != 0) {
        pthread_mutex_destroy(&ctx->work_queue_mutex);
        pthread_mutex_destroy(&ctx->results_mutex);
        recon_cleanup_context(&ctx->base_ctx);
        return -1;
    }

    // Initialize performance metrics
    if (pthread_mutex_init(&ctx->metrics.metrics_mutex, NULL) != 0) {
        pthread_cond_destroy(&ctx->work_available_cond);
        pthread_mutex_destroy(&ctx->work_queue_mutex);
        pthread_mutex_destroy(&ctx->results_mutex);
        recon_cleanup_context(&ctx->base_ctx);
        return -1;
    }

    // Initialize memory manager
    if (enhanced_bruteforce_init_memory_manager(&ctx->memory_mgr,
                                               ENHANCED_BRUTEFORCE_MEMORY_THRESHOLD) != 0) {
        pthread_mutex_destroy(&ctx->metrics.metrics_mutex);
        pthread_cond_destroy(&ctx->work_available_cond);
        pthread_mutex_destroy(&ctx->work_queue_mutex);
        pthread_mutex_destroy(&ctx->results_mutex);
        recon_cleanup_context(&ctx->base_ctx);
        return -1;
    }

    // Set default configuration
    ctx->strategy = DISCOVERY_STRATEGY_HYBRID;
    ctx->max_depth = ENHANCED_BRUTEFORCE_MAX_RECURSIVE_DEPTH;
    ctx->max_results = 10000;
    ctx->opsec_config = default_opsec_config;

    // Allocate results array
    ctx->results = calloc(ctx->max_results, sizeof(enhanced_subdomain_result_t));
    if (!ctx->results) {
        enhanced_bruteforce_cleanup_context(ctx);
        return -1;
    }

    // Initialize work queue
    ctx->work_queue_size = ENHANCED_BRUTEFORCE_STREAMING_BUFFER_SIZE;
    ctx->work_queue = calloc(ctx->work_queue_size, sizeof(char*));
    if (!ctx->work_queue) {
        enhanced_bruteforce_cleanup_context(ctx);
        return -1;
    }

    for (uint32_t i = 0; i < ctx->work_queue_size; i++) {
        ctx->work_queue[i] = malloc(RECON_MAX_DOMAIN_LEN);
        if (!ctx->work_queue[i]) {
            enhanced_bruteforce_cleanup_context(ctx);
            return -1;
        }
    }

    // Initialize DNS resolver chain
    ctx->resolver_chain = malloc(sizeof(struct dns_resolver_chain));
    if (!ctx->resolver_chain) {
        enhanced_bruteforce_cleanup_context(ctx);
        return -1;
    }

    if (init_dns_resolver_chain(ctx->resolver_chain) != 0) {
        enhanced_bruteforce_cleanup_context(ctx);
        return -1;
    }

    // Add default resolvers for enhanced performance
    add_resolver_to_chain(ctx->resolver_chain, "8.8.8.8", DNS_PROTOCOL_UDP, 53);
    add_resolver_to_chain(ctx->resolver_chain, "1.1.1.1", DNS_PROTOCOL_UDP, 53);
    add_resolver_to_chain(ctx->resolver_chain, "9.9.9.9", DNS_PROTOCOL_UDP, 53);
    add_resolver_to_chain(ctx->resolver_chain, "208.67.222.222", DNS_PROTOCOL_UDP, 53);

    // Initialize metrics timestamp
    ctx->metrics.start_time = time(NULL);

    recon_log_info("enhanced_bruteforce", "Context initialized successfully");
    return 0;
}

void enhanced_bruteforce_cleanup_context(enhanced_bruteforce_context_t *ctx) {
    if (!ctx) return;

    // Stop all threads
    ctx->stop_enumeration = true;

    // Wait for threads to complete
    for (uint32_t i = 0; i < ctx->active_threads; i++) {
        pthread_join(ctx->worker_threads[i], NULL);
    }

    // Cleanup results
    if (ctx->results) {
        free(ctx->results);
    }

    // Cleanup work queue
    if (ctx->work_queue) {
        for (uint32_t i = 0; i < ctx->work_queue_size; i++) {
            if (ctx->work_queue[i]) {
                free(ctx->work_queue[i]);
            }
        }
        free(ctx->work_queue);
    }

    // Cleanup discovered subdomains
    if (ctx->discovered_subdomains) {
        for (uint32_t i = 0; i < ctx->discovered_count; i++) {
            if (ctx->discovered_subdomains[i]) {
                free(ctx->discovered_subdomains[i]);
            }
        }
        free(ctx->discovered_subdomains);
    }

    // Cleanup wordlists
    for (uint32_t i = 0; i < ctx->wordlist_count; i++) {
        enhanced_bruteforce_unload_wordlist(&ctx->wordlists[i]);
    }

    // Cleanup resolver chain
    if (ctx->resolver_chain) {
        free(ctx->resolver_chain);
    }

    // Cleanup memory manager
    enhanced_bruteforce_cleanup_memory_manager(&ctx->memory_mgr);

    // Cleanup mutexes and conditions
    pthread_mutex_destroy(&ctx->metrics.metrics_mutex);
    pthread_cond_destroy(&ctx->work_available_cond);
    pthread_mutex_destroy(&ctx->work_queue_mutex);
    pthread_mutex_destroy(&ctx->results_mutex);

    // Cleanup base context
    recon_cleanup_context(&ctx->base_ctx);
}

int enhanced_bruteforce_set_target(enhanced_bruteforce_context_t *ctx, const char *domain) {
    if (!ctx || !domain) return -1;

    if (strlen(domain) >= RECON_MAX_DOMAIN_LEN) {
        recon_log_error("enhanced_bruteforce", domain, "Domain name too long");
        return -1;
    }

    strncpy(ctx->target_domain, domain, RECON_MAX_DOMAIN_LEN - 1);
    ctx->target_domain[RECON_MAX_DOMAIN_LEN - 1] = '\0';

    recon_log_info("enhanced_bruteforce", "Target domain set");
    return 0;
}

// Intelligent wordlist management

int enhanced_bruteforce_load_wordlist(enhanced_wordlist_config_t *wordlist,
                                     const char *filename,
                                     enhanced_wordlist_type_t type,
                                     uint32_t priority) {
    if (!wordlist || !filename) return -1;

    memset(wordlist, 0, sizeof(enhanced_wordlist_config_t));

    strncpy(wordlist->filename, filename, sizeof(wordlist->filename) - 1);
    wordlist->type = type;
    wordlist->priority = priority;

    if (pthread_mutex_init(&wordlist->wordlist_mutex, NULL) != 0) {
        return -1;
    }

    FILE *file = fopen(filename, "r");
    if (!file) {
        recon_log_error("enhanced_bruteforce", filename, "Failed to open wordlist file");
        pthread_mutex_destroy(&wordlist->wordlist_mutex);
        return -1;
    }

    // Count lines first
    char line[256];
    uint32_t line_count = 0;
    while (fgets(line, sizeof(line), file)) {
        line_count++;
    }
    rewind(file);

    if (line_count == 0) {
        fclose(file);
        pthread_mutex_destroy(&wordlist->wordlist_mutex);
        return -1;
    }

    // Check if we should use streaming mode for large wordlists
    if (line_count > ENHANCED_BRUTEFORCE_STREAMING_BUFFER_SIZE) {
        wordlist->is_streaming = true;
        wordlist->stream_handle = file;
        wordlist->word_count = line_count;
        wordlist->is_loaded = true;
        recon_log_info("enhanced_bruteforce", "Wordlist loaded in streaming mode");
        return 0;
    }

    // Load entire wordlist into memory for smaller files
    wordlist->words = malloc(line_count * sizeof(char*));
    if (!wordlist->words) {
        fclose(file);
        pthread_mutex_destroy(&wordlist->wordlist_mutex);
        return -1;
    }

    uint32_t loaded_count = 0;
    while (fgets(line, sizeof(line), file) && loaded_count < line_count) {
        // Remove newline and whitespace
        char *newline = strchr(line, '\n');
        if (newline) *newline = '\0';

        char *carriage = strchr(line, '\r');
        if (carriage) *carriage = '\0';

        // Skip empty lines and comments
        if (strlen(line) == 0 || line[0] == '#') continue;

        // Validate subdomain format
        if (!enhanced_bruteforce_is_valid_subdomain_candidate(line)) continue;

        wordlist->words[loaded_count] = malloc(strlen(line) + 1);
        if (!wordlist->words[loaded_count]) {
            // Cleanup on failure
            for (uint32_t i = 0; i < loaded_count; i++) {
                free(wordlist->words[i]);
            }
            free(wordlist->words);
            fclose(file);
            pthread_mutex_destroy(&wordlist->wordlist_mutex);
            return -1;
        }

        strcpy(wordlist->words[loaded_count], line);
        loaded_count++;
    }

    fclose(file);
    wordlist->word_count = loaded_count;
    wordlist->is_loaded = true;
    wordlist->is_streaming = false;

    recon_log_info("enhanced_bruteforce", "Wordlist loaded successfully");
    return 0;
}

void enhanced_bruteforce_unload_wordlist(enhanced_wordlist_config_t *wordlist) {
    if (!wordlist) return;

    pthread_mutex_lock(&wordlist->wordlist_mutex);

    if (wordlist->words) {
        for (uint32_t i = 0; i < wordlist->word_count; i++) {
            if (wordlist->words[i]) {
                free(wordlist->words[i]);
            }
        }
        free(wordlist->words);
        wordlist->words = NULL;
    }

    if (wordlist->stream_handle) {
        fclose(wordlist->stream_handle);
        wordlist->stream_handle = NULL;
    }

    wordlist->word_count = 0;
    wordlist->is_loaded = false;
    wordlist->is_streaming = false;

    pthread_mutex_unlock(&wordlist->wordlist_mutex);
    pthread_mutex_destroy(&wordlist->wordlist_mutex);
}

// Advanced wildcard detection

int enhanced_bruteforce_detect_wildcards(enhanced_bruteforce_context_t *ctx) {
    if (!ctx) return -1;

    recon_log_info("enhanced_bruteforce", "Starting wildcard detection");

    // Test random subdomains to detect wildcard responses
    const char *test_subdomains[] = {
        "asdfghjklqwertyuiop",
        "randomtestsubdomain12345",
        "nonexistentsubdomain999",
        "thisshouldnotexist",
        "wildcardtest123456",
        "detectwildcard789",
        "fakesub1234567890",
        "randomstring987654",
        "testwildcard555",
        "shouldnotresolve"
    };

    enhanced_subdomain_result_t test_results[ENHANCED_BRUTEFORCE_WILDCARD_SAMPLES];
    int successful_tests = 0;

    for (int i = 0; i < ENHANCED_BRUTEFORCE_WILDCARD_SAMPLES && i < 10; i++) {
        if (enhanced_bruteforce_resolve_subdomain(ctx, test_subdomains[i], &test_results[successful_tests]) == 0) {
            successful_tests++;
        }

        // Apply OPSEC timing between tests
        enhanced_bruteforce_apply_opsec_timing(&ctx->opsec_config);
    }

    if (successful_tests == 0) {
        ctx->wildcard_info.has_wildcard = false;
        recon_log_info("enhanced_bruteforce", "No wildcard detected");
        return 0;
    }

    // Analyze results for wildcard patterns
    bool has_wildcard = false;
    char first_ip[INET6_ADDRSTRLEN];
    strcpy(first_ip, test_results[0].resolution.ipv4_addresses[0].s_addr ?
           inet_ntoa(test_results[0].resolution.ipv4_addresses[0]) : "");

    // Check if all test subdomains resolve to the same IP
    int matching_ips = 1;
    for (int i = 1; i < successful_tests; i++) {
        char current_ip[INET6_ADDRSTRLEN];
        strcpy(current_ip, test_results[i].resolution.ipv4_addresses[0].s_addr ?
               inet_ntoa(test_results[i].resolution.ipv4_addresses[0]) : "");

        if (strcmp(first_ip, current_ip) == 0) {
            matching_ips++;
        }
    }

    // If 80% or more resolve to the same IP, consider it a wildcard
    if ((float)matching_ips / successful_tests >= 0.8) {
        has_wildcard = true;
        strcpy(ctx->wildcard_info.wildcard_ips[0], first_ip);
        ctx->wildcard_info.wildcard_ip_count = 1;
        ctx->wildcard_info.confidence_score = (matching_ips * 100) / successful_tests;
    }

    ctx->wildcard_info.has_wildcard = has_wildcard;
    ctx->wildcard_info.affects_a_records = has_wildcard;
    ctx->wildcard_info.detection_time = time(NULL);

    if (has_wildcard) {
        recon_log_info("enhanced_bruteforce", "Wildcard detected - filtering enabled");
    } else {
        recon_log_info("enhanced_bruteforce", "No wildcard pattern detected");
    }

    return 0;
}

bool enhanced_bruteforce_is_wildcard_response(const enhanced_bruteforce_context_t *ctx,
                                              const enhanced_subdomain_result_t *result) {
    if (!ctx || !result || !ctx->wildcard_info.has_wildcard) {
        return false;
    }

    // Check if result IP matches known wildcard IPs
    for (int i = 0; i < ctx->wildcard_info.wildcard_ip_count; i++) {
        char result_ip[INET6_ADDRSTRLEN];
        if (result->resolution.ipv4_count > 0) {
            strcpy(result_ip, inet_ntoa(result->resolution.ipv4_addresses[0]));
            if (strcmp(result_ip, ctx->wildcard_info.wildcard_ips[i]) == 0) {
                return true;
            }
        }
    }

    return false;
}

// Pattern-based discovery

int enhanced_bruteforce_generate_alphanumeric_patterns(const pattern_generator_config_t *config,
                                                      char ***patterns,
                                                      uint32_t *count) {
    if (!config || !patterns || !count) return -1;

    uint32_t estimated_patterns = 0;

    // Calculate estimated pattern count
    for (uint32_t len = config->min_length; len <= config->max_length; len++) {
        uint32_t base = 26; // a-z
        if (config->include_numbers) base += 10; // 0-9
        estimated_patterns += (uint32_t)pow(base, len);

        // Limit to prevent memory explosion
        if (estimated_patterns > config->max_patterns) {
            estimated_patterns = config->max_patterns;
            break;
        }
    }

    *patterns = malloc(estimated_patterns * sizeof(char*));
    if (!*patterns) return -1;

    uint32_t pattern_count = 0;
    char charset[64] = "abcdefghijklmnopqrstuvwxyz";

    if (config->include_numbers) {
        strcat(charset, "0123456789");
    }

    int charset_len = strlen(charset);

    // Generate patterns for each length
    for (uint32_t len = config->min_length; len <= config->max_length && pattern_count < config->max_patterns; len++) {
        // Simple single character patterns first
        if (len == 1) {
            for (int i = 0; i < charset_len && pattern_count < config->max_patterns; i++) {
                (*patterns)[pattern_count] = malloc(2);
                if (!(*patterns)[pattern_count]) break;

                (*patterns)[pattern_count][0] = charset[i];
                (*patterns)[pattern_count][1] = '\0';
                pattern_count++;
            }
        }
        // Common 2-character patterns
        else if (len == 2) {
            // Common prefixes
            const char *common_prefixes[] = {"db", "fs", "ns", "mx", "dc", "ad", "lb", "fw"};
            int prefix_count = sizeof(common_prefixes) / sizeof(char*);

            for (int i = 0; i < prefix_count && pattern_count < config->max_patterns; i++) {
                (*patterns)[pattern_count] = malloc(3);
                if (!(*patterns)[pattern_count]) break;

                strcpy((*patterns)[pattern_count], common_prefixes[i]);
                pattern_count++;
            }

            // Add numbered variants (01-99)
            for (int i = 1; i <= 99 && pattern_count < config->max_patterns; i++) {
                (*patterns)[pattern_count] = malloc(4);
                if (!(*patterns)[pattern_count]) break;

                snprintf((*patterns)[pattern_count], 4, "%02d", i);
                pattern_count++;
            }
        }
        // Limit longer patterns to prevent explosion
        else if (len == 3 && pattern_count < config->max_patterns - 100) {
            // Common 3-character patterns
            const char *common_3char[] = {"www", "api", "ftp", "ssh", "vpn", "cdn", "img", "css", "dev", "app"};
            int three_char_count = sizeof(common_3char) / sizeof(char*);

            for (int i = 0; i < three_char_count && pattern_count < config->max_patterns; i++) {
                (*patterns)[pattern_count] = malloc(4);
                if (!(*patterns)[pattern_count]) break;

                strcpy((*patterns)[pattern_count], common_3char[i]);
                pattern_count++;
            }
        }
    }

    *count = pattern_count;
    recon_log_info("enhanced_bruteforce", "Generated alphanumeric patterns");
    return 0;
}

int enhanced_bruteforce_generate_sequential_patterns(const pattern_generator_config_t *config,
                                                    const char *base_pattern,
                                                    char ***patterns,
                                                    uint32_t *count) {
    if (!config || !base_pattern || !patterns || !count) return -1;

    uint32_t max_sequential = 100; // Limit sequential generation
    if (config->max_patterns < max_sequential) {
        max_sequential = config->max_patterns;
    }

    *patterns = malloc(max_sequential * sizeof(char*));
    if (!*patterns) return -1;

    uint32_t pattern_count = 0;

    // Generate numbered sequences
    for (uint32_t i = 1; i <= max_sequential && pattern_count < config->max_patterns; i++) {
        // Try different numbering formats
        char numbered_pattern[128];

        // Format: base1, base2, etc.
        snprintf(numbered_pattern, sizeof(numbered_pattern), "%s%u", base_pattern, i);
        if (strlen(numbered_pattern) <= config->max_length) {
            (*patterns)[pattern_count] = malloc(strlen(numbered_pattern) + 1);
            if ((*patterns)[pattern_count]) {
                strcpy((*patterns)[pattern_count], numbered_pattern);
                pattern_count++;
            }
        }

        // Format: base01, base02, etc. (zero-padded)
        if (pattern_count < config->max_patterns && i <= 99) {
            snprintf(numbered_pattern, sizeof(numbered_pattern), "%s%02u", base_pattern, i);
            if (strlen(numbered_pattern) <= config->max_length) {
                (*patterns)[pattern_count] = malloc(strlen(numbered_pattern) + 1);
                if ((*patterns)[pattern_count]) {
                    strcpy((*patterns)[pattern_count], numbered_pattern);
                    pattern_count++;
                }
            }
        }
    }

    *count = pattern_count;
    recon_log_info("enhanced_bruteforce", "Generated sequential patterns");
    return 0;
}

// Enhanced DNS resolution with integration

int enhanced_bruteforce_resolve_subdomain(enhanced_bruteforce_context_t *ctx,
                                         const char *subdomain,
                                         enhanced_subdomain_result_t *result) {
    if (!ctx || !subdomain || !result) return -1;

    memset(result, 0, sizeof(enhanced_subdomain_result_t));

    // Build full domain name
    snprintf(result->full_domain, sizeof(result->full_domain), "%s.%s", subdomain, ctx->target_domain);
    strncpy(result->subdomain, subdomain, sizeof(result->subdomain) - 1);

    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);

    // Use enhanced DNS resolution with the resolver chain
    struct dns_query_context query_ctx;
    memset(&query_ctx, 0, sizeof(query_ctx));

    strncpy(query_ctx.query_name, result->full_domain, sizeof(query_ctx.query_name) - 1);
    query_ctx.query_type = DNS_TYPE_A;
    query_ctx.preferred_protocol = DNS_PROTOCOL_UDP;
    query_ctx.timeout.tv_sec = 5;
    query_ctx.retry_count = 2;

    struct enhanced_dns_result dns_result;
    memset(&dns_result, 0, sizeof(dns_result));

    int resolution_result = perform_enhanced_dns_query(&query_ctx, ctx->resolver_chain, &dns_result);

    gettimeofday(&end_time, NULL);
    result->response_time_ms = ((end_time.tv_sec - start_time.tv_sec) * 1000) +
                              ((end_time.tv_usec - start_time.tv_usec) / 1000);

    if (resolution_result == 0 && dns_result.resolution.ipv4_count > 0) {
        // Copy resolution results
        result->resolution = dns_result.resolution;
        result->enrichment = dns_result.enrichment[0];
        result->cdn_info = dns_result.cdn_info;
        result->record_type = DNS_TYPE_A;
        result->discovered = time(NULL);
        result->confidence_score = 95; // High confidence for direct DNS resolution

        // Update performance metrics
        enhanced_bruteforce_update_metrics(ctx, true, result->response_time_ms);

        return 0;
    }

    // Update metrics for failed resolution
    enhanced_bruteforce_update_metrics(ctx, false, result->response_time_ms);
    return -1;
}

// Core execution engine

int enhanced_bruteforce_execute(enhanced_bruteforce_context_t *ctx) {
    if (!ctx) return -1;

    recon_log_info("enhanced_bruteforce", "Starting enhanced DNS brute-force enumeration");

    // Step 1: Detect wildcards
    if (enhanced_bruteforce_detect_wildcards(ctx) != 0) {
        recon_log_error("enhanced_bruteforce", ctx->target_domain, "Wildcard detection failed");
        return -1;
    }

    // Step 2: Calculate optimal thread count based on system and configuration
    uint32_t optimal_threads = enhanced_bruteforce_calculate_optimal_threads(ctx);
    ctx->active_threads = optimal_threads;

    recon_log_info("enhanced_bruteforce", "Using optimal thread count");

    // Step 3: Populate work queue with initial candidates
    uint32_t initial_candidates = 0;

    // Add high-value subdomains first
    for (int i = 0; i < high_value_subdomain_count; i++) {
        work_item_t item;
        memset(&item, 0, sizeof(item));

        strncpy(item.subdomain_candidate, high_value_subdomains[i],
                sizeof(item.subdomain_candidate) - 1);
        item.method = DISCOVERY_STRATEGY_WORDLIST;
        item.depth_level = 0;
        item.priority = 100; // High priority

        if (enhanced_bruteforce_add_work_item(ctx, &item) == 0) {
            initial_candidates++;
        }
    }

    // Add wordlist candidates
    for (uint32_t w = 0; w < ctx->wordlist_count; w++) {
        enhanced_wordlist_config_t *wordlist = &ctx->wordlists[w];
        if (!wordlist->is_loaded) continue;

        if (wordlist->is_streaming) {
            // For streaming wordlists, add first batch
            char line[256];
            uint32_t added = 0;

            pthread_mutex_lock(&wordlist->wordlist_mutex);
            rewind(wordlist->stream_handle);

            while (fgets(line, sizeof(line), wordlist->stream_handle) &&
                   added < ENHANCED_BRUTEFORCE_STREAMING_BUFFER_SIZE / 4) {

                // Clean up line
                char *newline = strchr(line, '\n');
                if (newline) *newline = '\0';

                if (strlen(line) == 0 || line[0] == '#') continue;

                work_item_t item;
                memset(&item, 0, sizeof(item));

                strncpy(item.subdomain_candidate, line, sizeof(item.subdomain_candidate) - 1);
                item.method = DISCOVERY_STRATEGY_WORDLIST;
                item.depth_level = 0;
                item.priority = wordlist->priority;

                if (enhanced_bruteforce_add_work_item(ctx, &item) == 0) {
                    added++;
                    initial_candidates++;
                }
            }

            pthread_mutex_unlock(&wordlist->wordlist_mutex);
        } else {
            // For in-memory wordlists, add all words
            for (uint32_t i = 0; i < wordlist->word_count; i++) {
                work_item_t item;
                memset(&item, 0, sizeof(item));

                strncpy(item.subdomain_candidate, wordlist->words[i],
                        sizeof(item.subdomain_candidate) - 1);
                item.method = DISCOVERY_STRATEGY_WORDLIST;
                item.depth_level = 0;
                item.priority = wordlist->priority;

                if (enhanced_bruteforce_add_work_item(ctx, &item) == 0) {
                    initial_candidates++;
                }
            }
        }
    }

    // Generate pattern-based candidates
    char **patterns = NULL;
    uint32_t pattern_count = 0;

    if (enhanced_bruteforce_generate_alphanumeric_patterns(&ctx->pattern_config,
                                                          &patterns, &pattern_count) == 0) {
        for (uint32_t i = 0; i < pattern_count; i++) {
            work_item_t item;
            memset(&item, 0, sizeof(item));

            strncpy(item.subdomain_candidate, patterns[i], sizeof(item.subdomain_candidate) - 1);
            item.method = DISCOVERY_STRATEGY_PATTERN;
            item.depth_level = 0;
            item.priority = 50; // Medium priority

            if (enhanced_bruteforce_add_work_item(ctx, &item) == 0) {
                initial_candidates++;
            }

            free(patterns[i]);
        }

        if (patterns) free(patterns);
    }

    recon_log_info("enhanced_bruteforce", "Work queue populated with initial candidates");

    // Step 4: Launch worker threads
    enhanced_thread_args_t thread_args[ENHANCED_BRUTEFORCE_MAX_THREADS];

    for (uint32_t i = 0; i < ctx->active_threads; i++) {
        thread_args[i].ctx = ctx;
        thread_args[i].thread_id = i;
        thread_args[i].strategy = ctx->strategy;

        if (pthread_create(&ctx->worker_threads[i], NULL,
                          enhanced_bruteforce_worker_thread, &thread_args[i]) != 0) {
            recon_log_error("enhanced_bruteforce", "thread", "Failed to create worker thread");
            ctx->active_threads = i; // Adjust to actually created threads
            break;
        }
    }

    recon_log_info("enhanced_bruteforce", "Worker threads launched");

    // Step 5: Monitor progress and performance
    time_t last_progress = time(NULL);
    uint32_t last_result_count = 0;

    while (ctx->work_queue_count > 0 || ctx->active_threads > 0) {
        sleep(1);

        time_t current_time = time(NULL);

        // Print progress every 10 seconds
        if (current_time - last_progress >= 10) {
            uint32_t current_qps = enhanced_bruteforce_get_current_qps(ctx);

            recon_log_info("enhanced_bruteforce", "Progress update");
            printf("Results: %u, QPS: %u, Queue: %u\n",
                   ctx->result_count, current_qps, ctx->work_queue_count);

            last_progress = current_time;
            last_result_count = ctx->result_count;
        }

        // Check for rate limiting
        if (enhanced_bruteforce_check_rate_limiting(ctx)) {
            enhanced_bruteforce_adjust_timing(ctx, true);
        }

        // Stop if enumeration is complete
        if (ctx->stop_enumeration) break;
    }

    // Step 6: Wait for all threads to complete
    for (uint32_t i = 0; i < ctx->active_threads; i++) {
        pthread_join(ctx->worker_threads[i], NULL);
    }

    // Step 7: Post-process results
    enhanced_bruteforce_filter_results(ctx);
    enhanced_bruteforce_deduplicate_results(ctx);
    enhanced_bruteforce_sort_results(ctx);

    recon_log_info("enhanced_bruteforce", "Enhanced DNS brute-force enumeration completed");
    return ctx->result_count;
}

void *enhanced_bruteforce_worker_thread(void *arg) {
    enhanced_thread_args_t *args = (enhanced_thread_args_t *)arg;
    enhanced_bruteforce_context_t *ctx = args->ctx;
    uint32_t thread_id = args->thread_id;

    recon_log_debug("enhanced_bruteforce", "Worker thread started");

    while (!ctx->stop_enumeration) {
        work_item_t work_item;

        // Get work item from queue
        if (!enhanced_bruteforce_get_work_item(ctx, &work_item)) {
            // No work available, wait a bit
            usleep(100000); // 100ms
            continue;
        }

        // Process the subdomain candidate
        enhanced_subdomain_result_t result;

        if (enhanced_bruteforce_resolve_subdomain(ctx, work_item.subdomain_candidate, &result) == 0) {
            // Check if it's a wildcard response
            if (!enhanced_bruteforce_is_wildcard_response(ctx, &result)) {
                // Set additional metadata
                result.discovery_method = work_item.method;
                result.depth_level = work_item.depth_level;
                strncpy(result.parent_subdomain, work_item.parent_domain,
                        sizeof(result.parent_subdomain) - 1);

                // Add to results
                if (enhanced_bruteforce_add_result(ctx, &result) == 0) {
                    // If recursive enumeration is enabled and this is a good candidate
                    if (ctx->strategy == DISCOVERY_STRATEGY_RECURSIVE ||
                        ctx->strategy == DISCOVERY_STRATEGY_HYBRID) {

                        if (enhanced_bruteforce_should_recurse(ctx, &result)) {
                            enhanced_bruteforce_recursive_enumerate(ctx,
                                                                   work_item.subdomain_candidate,
                                                                   work_item.depth_level + 1);
                        }
                    }
                }
            } else {
                // Update wildcard filter count
                atomic_fetch_add(&ctx->metrics.wildcards_filtered, 1);
            }
        }

        // Apply OPSEC timing between requests
        enhanced_bruteforce_apply_opsec_timing(&ctx->opsec_config);
    }

    recon_log_debug("enhanced_bruteforce", "Worker thread completed");
    return NULL;
}

// Work queue management

int enhanced_bruteforce_add_work_item(enhanced_bruteforce_context_t *ctx, const work_item_t *item) {
    if (!ctx || !item) return -1;

    pthread_mutex_lock(&ctx->work_queue_mutex);

    if (ctx->work_queue_count >= ctx->work_queue_size) {
        pthread_mutex_unlock(&ctx->work_queue_mutex);
        return -1; // Queue full
    }

    // Add item to queue
    strncpy(ctx->work_queue[ctx->work_queue_tail], item->subdomain_candidate, RECON_MAX_DOMAIN_LEN - 1);
    ctx->work_queue_tail = (ctx->work_queue_tail + 1) % ctx->work_queue_size;
    ctx->work_queue_count++;

    pthread_cond_signal(&ctx->work_available_cond);
    pthread_mutex_unlock(&ctx->work_queue_mutex);

    return 0;
}

bool enhanced_bruteforce_get_work_item(enhanced_bruteforce_context_t *ctx, work_item_t *item) {
    if (!ctx || !item) return false;

    pthread_mutex_lock(&ctx->work_queue_mutex);

    if (ctx->work_queue_count == 0) {
        pthread_mutex_unlock(&ctx->work_queue_mutex);
        return false;
    }

    // Get item from queue
    strncpy(item->subdomain_candidate, ctx->work_queue[ctx->work_queue_head], RECON_MAX_DOMAIN_LEN - 1);
    ctx->work_queue_head = (ctx->work_queue_head + 1) % ctx->work_queue_size;
    ctx->work_queue_count--;

    pthread_mutex_unlock(&ctx->work_queue_mutex);

    return true;
}

// Result management

int enhanced_bruteforce_add_result(enhanced_bruteforce_context_t *ctx,
                                  const enhanced_subdomain_result_t *result) {
    if (!ctx || !result) return -1;

    pthread_mutex_lock(&ctx->results_mutex);

    if (ctx->result_count >= ctx->max_results) {
        pthread_mutex_unlock(&ctx->results_mutex);
        return -1;
    }

    // Check for duplicates
    if (enhanced_bruteforce_is_duplicate_result(ctx, result)) {
        atomic_fetch_add(&ctx->metrics.duplicates_filtered, 1);
        pthread_mutex_unlock(&ctx->results_mutex);
        return 0; // Not an error, just filtered
    }

    ctx->results[ctx->result_count] = *result;
    ctx->result_count++;

    pthread_mutex_unlock(&ctx->results_mutex);

    return 0;
}

bool enhanced_bruteforce_is_duplicate_result(const enhanced_bruteforce_context_t *ctx,
                                            const enhanced_subdomain_result_t *result) {
    if (!ctx || !result) return false;

    for (uint32_t i = 0; i < ctx->result_count; i++) {
        if (strcmp(ctx->results[i].full_domain, result->full_domain) == 0) {
            return true;
        }
    }

    return false;
}

void enhanced_bruteforce_filter_results(enhanced_bruteforce_context_t *ctx) {
    if (!ctx) return;

    pthread_mutex_lock(&ctx->results_mutex);

    uint32_t filtered_count = 0;

    for (uint32_t i = 0; i < ctx->result_count; i++) {
        enhanced_subdomain_result_t *result = &ctx->results[i];

        // Filter out wildcard responses
        if (enhanced_bruteforce_is_wildcard_response(ctx, result)) {
            continue;
        }

        // Filter out low confidence results
        if (result->confidence_score < 50) {
            continue;
        }

        // Keep the result
        if (filtered_count != i) {
            ctx->results[filtered_count] = *result;
        }
        filtered_count++;
    }

    ctx->result_count = filtered_count;
    pthread_mutex_unlock(&ctx->results_mutex);
}

int enhanced_bruteforce_deduplicate_results(enhanced_bruteforce_context_t *ctx) {
    if (!ctx) return -1;

    pthread_mutex_lock(&ctx->results_mutex);

    uint32_t unique_count = 0;

    for (uint32_t i = 0; i < ctx->result_count; i++) {
        bool is_duplicate = false;

        // Check against already processed unique results
        for (uint32_t j = 0; j < unique_count; j++) {
            if (strcmp(ctx->results[i].full_domain, ctx->results[j].full_domain) == 0) {
                is_duplicate = true;
                break;
            }
        }

        if (!is_duplicate) {
            if (unique_count != i) {
                ctx->results[unique_count] = ctx->results[i];
            }
            unique_count++;
        }
    }

    uint32_t removed = ctx->result_count - unique_count;
    ctx->result_count = unique_count;

    pthread_mutex_unlock(&ctx->results_mutex);

    return removed;
}

void enhanced_bruteforce_sort_results(enhanced_bruteforce_context_t *ctx) {
    if (!ctx || ctx->result_count <= 1) return;

    pthread_mutex_lock(&ctx->results_mutex);

    // Simple bubble sort by subdomain name (can be optimized later)
    for (uint32_t i = 0; i < ctx->result_count - 1; i++) {
        for (uint32_t j = 0; j < ctx->result_count - i - 1; j++) {
            if (strcmp(ctx->results[j].subdomain, ctx->results[j + 1].subdomain) > 0) {
                enhanced_subdomain_result_t temp = ctx->results[j];
                ctx->results[j] = ctx->results[j + 1];
                ctx->results[j + 1] = temp;
            }
        }
    }

    pthread_mutex_unlock(&ctx->results_mutex);
}

// OPSEC and anti-detection

void enhanced_bruteforce_apply_opsec_timing(const enhanced_opsec_config_t *config) {
    if (!config) return;

    uint32_t delay_ms = config->base_delay_ms;

    // Add jitter if configured
    if (config->jitter_range_ms > 0) {
        uint32_t jitter = rand() % config->jitter_range_ms;
        delay_ms += jitter;
    }

    // Scale by paranoia level (1.0 = normal, 10.0 = maximum stealth)
    delay_ms = (uint32_t)(delay_ms * config->paranoia_level);

    usleep(delay_ms * 1000); // Convert to microseconds
}

bool enhanced_bruteforce_check_rate_limiting(enhanced_bruteforce_context_t *ctx) {
    if (!ctx) return false;

    uint32_t current_qps = enhanced_bruteforce_get_current_qps(ctx);
    uint32_t success_rate = 0;

    if (ctx->metrics.queries_sent > 0) {
        success_rate = (ctx->metrics.responses_received * 100) / ctx->metrics.queries_sent;
    }

    // Detect rate limiting indicators:
    // 1. Sudden drop in success rate
    // 2. Responses taking much longer
    // 3. Current QPS much lower than peak

    if (success_rate < 50 || current_qps < (ctx->metrics.peak_qps / 4)) {
        return true;
    }

    return false;
}

void enhanced_bruteforce_adjust_timing(enhanced_bruteforce_context_t *ctx, bool detected) {
    if (!ctx) return;

    if (detected) {
        // Increase delays and reduce aggressiveness
        ctx->opsec_config.base_delay_ms *= 2;
        ctx->opsec_config.jitter_range_ms *= 2;
        ctx->opsec_config.paranoia_level = fmin(ctx->opsec_config.paranoia_level * 1.5, 10.0);

        recon_log_info("enhanced_bruteforce", "Rate limiting detected - adjusting timing");
    } else {
        // Gradually reduce delays if not detected
        ctx->opsec_config.base_delay_ms = (uint32_t)(ctx->opsec_config.base_delay_ms * 0.9);
        ctx->opsec_config.jitter_range_ms = (uint32_t)(ctx->opsec_config.jitter_range_ms * 0.9);
        ctx->opsec_config.paranoia_level = fmax(ctx->opsec_config.paranoia_level * 0.95, 1.0);
    }
}

// Performance optimization and monitoring

void enhanced_bruteforce_update_metrics(enhanced_bruteforce_context_t *ctx,
                                       bool success,
                                       uint32_t response_time_ms) {
    if (!ctx) return;

    atomic_fetch_add(&ctx->metrics.queries_sent, 1);

    if (success) {
        atomic_fetch_add(&ctx->metrics.responses_received, 1);
    }

    atomic_fetch_add(&ctx->metrics.total_response_time_ms, response_time_ms);

    // Update QPS calculation
    time_t current_time = time(NULL);
    if (current_time != ctx->metrics.last_update) {
        uint64_t queries_in_last_second = atomic_load(&ctx->metrics.queries_sent) -
                                          (atomic_load(&ctx->metrics.queries_sent) - 1);
        atomic_store(&ctx->metrics.current_qps, (uint32_t)queries_in_last_second);

        if (ctx->metrics.current_qps > ctx->metrics.peak_qps) {
            atomic_store(&ctx->metrics.peak_qps, ctx->metrics.current_qps);
        }

        ctx->metrics.last_update = current_time;
    }
}

uint32_t enhanced_bruteforce_calculate_optimal_threads(const enhanced_bruteforce_context_t *ctx) {
    if (!ctx) return 1;

    // Start with system capabilities
    uint32_t cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);
    uint32_t optimal_threads = cpu_cores * 2; // Network I/O bound, so 2x cores

    // Apply constraints
    if (optimal_threads > ENHANCED_BRUTEFORCE_MAX_THREADS) {
        optimal_threads = ENHANCED_BRUTEFORCE_MAX_THREADS;
    }

    // Adjust based on OPSEC configuration
    if (ctx->opsec_config.paranoia_level > 7.0) {
        optimal_threads = optimal_threads / 4; // Very stealthy
    } else if (ctx->opsec_config.paranoia_level > 5.0) {
        optimal_threads = optimal_threads / 2; // Moderate stealth
    }

    // Ensure minimum threads
    if (optimal_threads < 1) optimal_threads = 1;
    if (optimal_threads > 50) optimal_threads = 50;

    return optimal_threads;
}

uint32_t enhanced_bruteforce_get_current_qps(const enhanced_bruteforce_context_t *ctx) {
    if (!ctx) return 0;
    return atomic_load(&ctx->metrics.current_qps);
}

// Memory management

int enhanced_bruteforce_init_memory_manager(memory_manager_t *mgr, uint64_t threshold) {
    if (!mgr) return -1;

    memset(mgr, 0, sizeof(memory_manager_t));

    mgr->memory_threshold = threshold;
    mgr->buffer_size = ENHANCED_BRUTEFORCE_STREAMING_BUFFER_SIZE;

    if (pthread_mutex_init(&mgr->memory_mutex, NULL) != 0) {
        return -1;
    }

    return 0;
}

void enhanced_bruteforce_cleanup_memory_manager(memory_manager_t *mgr) {
    if (!mgr) return;

    pthread_mutex_destroy(&mgr->memory_mutex);
}

bool enhanced_bruteforce_check_memory_threshold(const memory_manager_t *mgr) {
    if (!mgr) return false;

    return mgr->allocated_memory > mgr->memory_threshold;
}

// Recursive enumeration

int enhanced_bruteforce_recursive_enumerate(enhanced_bruteforce_context_t *ctx,
                                           const char *found_subdomain,
                                           uint32_t current_depth) {
    if (!ctx || !found_subdomain || current_depth >= ctx->max_depth) {
        return 0;
    }

    // Generate recursive candidates based on the found subdomain
    const char *recursive_prefixes[] = {"dev", "test", "staging", "prod", "www", "api", "admin"};
    const int prefix_count = sizeof(recursive_prefixes) / sizeof(char*);

    for (int i = 0; i < prefix_count; i++) {
        work_item_t item;
        memset(&item, 0, sizeof(item));

        snprintf(item.subdomain_candidate, sizeof(item.subdomain_candidate),
                "%s.%s", recursive_prefixes[i], found_subdomain);
        item.method = DISCOVERY_STRATEGY_RECURSIVE;
        item.depth_level = current_depth;
        item.priority = 75; // High priority for recursive discoveries
        strncpy(item.parent_domain, found_subdomain, sizeof(item.parent_domain) - 1);

        enhanced_bruteforce_add_work_item(ctx, &item);
    }

    return prefix_count;
}

bool enhanced_bruteforce_should_recurse(const enhanced_bruteforce_context_t *ctx,
                                       const enhanced_subdomain_result_t *result) {
    if (!ctx || !result) return false;

    // Don't recurse if we're at max depth
    if (result->depth_level >= ctx->max_depth) return false;

    // Don't recurse on wildcard responses
    if (enhanced_bruteforce_is_wildcard_response(ctx, result)) return false;

    // Don't recurse on low confidence results
    if (result->confidence_score < 70) return false;

    // Prefer to recurse on high-value subdomains
    if (enhanced_bruteforce_is_high_value_subdomain(result->subdomain)) return true;

    // Recurse on subdomains that look like they might have sub-subdomains
    const char *recursive_indicators[] = {"api", "service", "app", "web", "portal", "platform"};
    const int indicator_count = sizeof(recursive_indicators) / sizeof(char*);

    for (int i = 0; i < indicator_count; i++) {
        if (strstr(result->subdomain, recursive_indicators[i]) != NULL) {
            return true;
        }
    }

    return false;
}

// Utility functions

bool enhanced_bruteforce_is_valid_subdomain_candidate(const char *subdomain) {
    if (!subdomain || strlen(subdomain) == 0) return false;

    // Check length
    if (strlen(subdomain) > 63) return false; // DNS label limit

    // Check for valid characters (alphanumeric and hyphens)
    for (const char *p = subdomain; *p; p++) {
        if (!isalnum(*p) && *p != '-' && *p != '_') {
            return false;
        }
    }

    // Can't start or end with hyphen
    if (subdomain[0] == '-' || subdomain[strlen(subdomain) - 1] == '-') {
        return false;
    }

    return true;
}

void enhanced_bruteforce_sanitize_subdomain(char *subdomain) {
    if (!subdomain) return;

    // Convert to lowercase
    for (char *p = subdomain; *p; p++) {
        *p = tolower(*p);
    }

    // Remove invalid characters
    char *write_pos = subdomain;
    for (char *read_pos = subdomain; *read_pos; read_pos++) {
        if (isalnum(*read_pos) || *read_pos == '-' || *read_pos == '_') {
            *write_pos++ = *read_pos;
        }
    }
    *write_pos = '\0';
}

bool enhanced_bruteforce_is_high_value_subdomain(const char *subdomain) {
    if (!subdomain) return false;

    for (int i = 0; i < high_value_subdomain_count; i++) {
        if (strcmp(subdomain, high_value_subdomains[i]) == 0) {
            return true;
        }
    }

    return false;
}

// Output and reporting

void enhanced_bruteforce_print_results(const enhanced_bruteforce_context_t *ctx) {
    if (!ctx) return;

    printf("\n=== Enhanced DNS Brute-Force Results ===\n");
    printf("Target: %s\n", ctx->target_domain);
    printf("Subdomains found: %u\n", ctx->result_count);
    printf("Wildcard detected: %s\n", ctx->wildcard_info.has_wildcard ? "Yes" : "No");

    if (ctx->wildcard_info.has_wildcard) {
        printf("Wildcard IP: %s\n", ctx->wildcard_info.wildcard_ips[0]);
        printf("Confidence: %u%%\n", ctx->wildcard_info.confidence_score);
    }

    printf("\nDiscovered Subdomains:\n");
    printf("%-30s %-15s %-12s %-10s %s\n", "Subdomain", "IP Address", "Method", "Confidence", "Response Time");
    printf("%-30s %-15s %-12s %-10s %s\n", "----------", "----------", "------", "----------", "-------------");

    for (uint32_t i = 0; i < ctx->result_count; i++) {
        const enhanced_subdomain_result_t *result = &ctx->results[i];

        char ip_str[INET6_ADDRSTRLEN] = "N/A";
        if (result->resolution.ipv4_count > 0) {
            strcpy(ip_str, inet_ntoa(result->resolution.ipv4_addresses[0]));
        }

        const char *method_str = discovery_strategy_to_string(result->discovery_method);

        printf("%-30s %-15s %-12s %-10u %ums\n",
               result->full_domain, ip_str, method_str,
               result->confidence_score, result->response_time_ms);
    }

    printf("\n=== Performance Statistics ===\n");
    enhanced_bruteforce_print_statistics(ctx);
    printf("========================================\n\n");
}

void enhanced_bruteforce_print_statistics(const enhanced_bruteforce_context_t *ctx) {
    if (!ctx) return;

    uint64_t total_queries = atomic_load(&ctx->metrics.queries_sent);
    uint64_t successful_queries = atomic_load(&ctx->metrics.responses_received);
    uint64_t wildcards_filtered = atomic_load(&ctx->metrics.wildcards_filtered);
    uint64_t duplicates_filtered = atomic_load(&ctx->metrics.duplicates_filtered);
    uint32_t current_qps = atomic_load(&ctx->metrics.current_qps);
    uint32_t peak_qps = atomic_load(&ctx->metrics.peak_qps);

    time_t elapsed_time = time(NULL) - ctx->metrics.start_time;

    printf("Total queries sent: %lu\n", total_queries);
    printf("Successful responses: %lu\n", successful_queries);
    printf("Success rate: %.1f%%\n", total_queries > 0 ? (float)(successful_queries * 100) / total_queries : 0.0);
    printf("Wildcards filtered: %lu\n", wildcards_filtered);
    printf("Duplicates filtered: %lu\n", duplicates_filtered);
    printf("Current QPS: %u\n", current_qps);
    printf("Peak QPS: %u\n", peak_qps);
    printf("Average QPS: %.1f\n", elapsed_time > 0 ? (float)total_queries / elapsed_time : 0.0);
    printf("Elapsed time: %ld seconds\n", elapsed_time);

    if (total_queries > 0) {
        uint64_t avg_response_time = atomic_load(&ctx->metrics.total_response_time_ms) / total_queries;
        printf("Average response time: %lu ms\n", avg_response_time);
    }
}

// String conversion utilities

const char *discovery_strategy_to_string(discovery_strategy_t strategy) {
    switch (strategy) {
        case DISCOVERY_STRATEGY_WORDLIST: return "WORDLIST";
        case DISCOVERY_STRATEGY_PATTERN: return "PATTERN";
        case DISCOVERY_STRATEGY_PERMUTATION: return "PERMUTATION";
        case DISCOVERY_STRATEGY_RECURSIVE: return "RECURSIVE";
        case DISCOVERY_STRATEGY_ALGORITHMIC: return "ALGORITHMIC";
        case DISCOVERY_STRATEGY_HYBRID: return "HYBRID";
        case DISCOVERY_STRATEGY_ADAPTIVE: return "ADAPTIVE";
        default: return "UNKNOWN";
    }
}

const char *enhanced_wordlist_type_to_string(enhanced_wordlist_type_t type) {
    switch (type) {
        case ENHANCED_WORDLIST_CORE: return "CORE";
        case ENHANCED_WORDLIST_TECHNOLOGY: return "TECHNOLOGY";
        case ENHANCED_WORDLIST_INFRASTRUCTURE: return "INFRASTRUCTURE";
        case ENHANCED_WORDLIST_ORGANIZATION: return "ORGANIZATION";
        case ENHANCED_WORDLIST_GEOGRAPHIC: return "GEOGRAPHIC";
        case ENHANCED_WORDLIST_SECURITY: return "SECURITY";
        case ENHANCED_WORDLIST_DYNAMIC: return "DYNAMIC";
        case ENHANCED_WORDLIST_CUSTOM: return "CUSTOM";
        case ENHANCED_WORDLIST_PATTERN: return "PATTERN";
        default: return "UNKNOWN";
    }
}

const char *pattern_algorithm_to_string(pattern_algorithm_t algorithm) {
    switch (algorithm) {
        case PATTERN_ALGORITHM_ALPHANUMERIC: return "ALPHANUMERIC";
        case PATTERN_ALGORITHM_SEQUENTIAL: return "SEQUENTIAL";
        case PATTERN_ALGORITHM_COMMON_PREFIXES: return "COMMON_PREFIXES";
        case PATTERN_ALGORITHM_COMMON_SUFFIXES: return "COMMON_SUFFIXES";
        case PATTERN_ALGORITHM_YEAR_BASED: return "YEAR_BASED";
        case PATTERN_ALGORITHM_ENVIRONMENT: return "ENVIRONMENT";
        case PATTERN_ALGORITHM_SERVICE_BASED: return "SERVICE_BASED";
        case PATTERN_ALGORITHM_HYBRID: return "HYBRID";
        default: return "UNKNOWN";
    }
}
