/*
 * CloudUnflare Enhanced - Advanced OPSEC Framework Implementation
 *
 * Nation-state level operational security implementation
 * Comprehensive anti-detection and evasion capabilities
 *
 * Agent: SECURITY (primary implementation)
 * Coordination: C-INTERNAL, GHOST-PROTOCOL, NSA-TTP
 */

#include "recon_opsec.h"
#include <math.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>

// User-Agent rotation pool for traffic obfuscation
static const char *user_agent_pool[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
};

static const size_t user_agent_pool_size = sizeof(user_agent_pool) / sizeof(user_agent_pool[0]);

// Honeypot detection signatures
static const char *honeypot_signatures[] = {
    "X-Honeypot-Detection",
    "X-Canary-Token",
    "X-Trap-ID",
    "honeypot",
    "canary",
    "deception",
    "tarpit"
};

static const size_t honeypot_signature_count = sizeof(honeypot_signatures) / sizeof(honeypot_signatures[0]);

// Initialize OPSEC context with specified paranoia level
int opsec_init_context(opsec_context_t *ctx, opsec_paranoia_level_t paranoia) {
    if (!ctx) return -1;

    memset(ctx, 0, sizeof(opsec_context_t));

    // Initialize mutexes
    if (pthread_mutex_init(&ctx->detection_mutex, NULL) != 0) {
        return -1;
    }
    if (pthread_mutex_init(&ctx->proxy_mutex, NULL) != 0) {
        pthread_mutex_destroy(&ctx->detection_mutex);
        return -1;
    }

    // Configure paranoia level
    opsec_configure_paranoia_level(ctx, paranoia);

    // Initialize detection events storage
    ctx->max_detection_events = 1000;
    ctx->detection_events = calloc(ctx->max_detection_events, sizeof(detection_event_t));
    if (!ctx->detection_events) {
        opsec_cleanup_context(ctx);
        return -1;
    }

    // Initialize proxy chain storage
    ctx->config.max_chain_length = 5;
    ctx->config.proxy_chain = calloc(ctx->config.max_chain_length, sizeof(proxy_node_t));
    if (!ctx->config.proxy_chain) {
        opsec_cleanup_context(ctx);
        return -1;
    }

    // Initialize atomic variables
    atomic_store(&ctx->active_operations, 0);
    atomic_store(&ctx->completed_operations, 0);
    atomic_store(&ctx->failed_operations, 0);
    atomic_store(&ctx->current_risk_score, 0.0);
    atomic_store(&ctx->detection_event_count, 0);

    // Set initial timing state
    ctx->last_operation_time = time(NULL);
    ctx->burst_start_time = time(NULL);

    return 0;
}

// Cleanup OPSEC context
void opsec_cleanup_context(opsec_context_t *ctx) {
    if (!ctx) return;

    // Execute emergency cleanup if needed
    if (ctx->emergency_mode_active) {
        opsec_execute_emergency_cleanup(ctx);
    }

    // Free allocated memory
    if (ctx->detection_events) {
        free(ctx->detection_events);
    }
    if (ctx->config.proxy_chain) {
        free(ctx->config.proxy_chain);
    }

    // Destroy mutexes
    pthread_mutex_destroy(&ctx->detection_mutex);
    pthread_mutex_destroy(&ctx->proxy_mutex);

    // Clear sensitive data
    memset(ctx, 0, sizeof(opsec_context_t));
}

// Configure paranoia level
int opsec_configure_paranoia_level(opsec_context_t *ctx, opsec_paranoia_level_t level) {
    if (!ctx) return -1;

    ctx->config.paranoia_level = level;

    switch (level) {
        case OPSEC_PARANOIA_NORMAL:
            opsec_configure_normal_paranoia(&ctx->config);
            break;
        case OPSEC_PARANOIA_HIGH:
            opsec_configure_high_paranoia(&ctx->config);
            break;
        case OPSEC_PARANOIA_MAXIMUM:
            opsec_configure_maximum_paranoia(&ctx->config);
            break;
        case OPSEC_PARANOIA_GHOST:
            opsec_configure_ghost_paranoia(&ctx->config);
            break;
        default:
            return -1;
    }

    return 0;
}

// Calculate current risk score based on operational metrics
double opsec_calculate_risk_score(const opsec_context_t *ctx) {
    if (!ctx) return 1.0;

    double risk_score = 0.0;
    time_t current_time = time(NULL);

    // Base risk from failed operations
    uint32_t failed = atomic_load(&ctx->failed_operations);
    uint32_t total = atomic_load(&ctx->completed_operations) + failed;
    if (total > 0) {
        double failure_rate = (double)failed / total;
        risk_score += failure_rate * 0.3;
    }

    // Risk from detection events in last hour
    uint32_t recent_detections = 0;
    for (uint32_t i = 0; i < atomic_load(&ctx->detection_event_count); i++) {
        if (current_time - ctx->detection_events[i].timestamp < 3600) {
            recent_detections++;
        }
    }
    risk_score += (double)recent_detections * 0.1;

    // Risk from operation frequency
    uint32_t active_ops = atomic_load(&ctx->active_operations);
    if (active_ops > ctx->config.timing.burst_limit) {
        risk_score += 0.2;
    }

    // Risk from time since last operation (too frequent)
    if (current_time - ctx->last_operation_time < ctx->config.timing.base_delay_ms / 1000) {
        risk_score += 0.15;
    }

    // Cap risk score at 1.0
    return (risk_score > 1.0) ? 1.0 : risk_score;
}

// Assess risk level from score
risk_level_t opsec_assess_risk_level(double risk_score) {
    if (risk_score < 0.2) return RISK_LEVEL_MINIMAL;
    if (risk_score < 0.4) return RISK_LEVEL_LOW;
    if (risk_score < 0.6) return RISK_LEVEL_MODERATE;
    if (risk_score < 0.8) return RISK_LEVEL_HIGH;
    return RISK_LEVEL_CRITICAL;
}

// Update risk score
int opsec_update_risk_score(opsec_context_t *ctx, double risk_delta) {
    if (!ctx) return -1;

    double current_risk = atomic_load(&ctx->current_risk_score);
    double new_risk = current_risk + risk_delta;

    // Clamp between 0.0 and 1.0
    if (new_risk < 0.0) new_risk = 0.0;
    if (new_risk > 1.0) new_risk = 1.0;

    atomic_store(&ctx->current_risk_score, new_risk);

    // Check if we need to trigger emergency mode
    if (new_risk >= ctx->config.risk_threshold_abort && !ctx->emergency_mode_active) {
        opsec_activate_emergency_mode(ctx);
    }

    return 0;
}

// Check if operation should be aborted
bool opsec_should_abort_operation(const opsec_context_t *ctx) {
    if (!ctx) return true;

    double risk_score = opsec_calculate_risk_score(ctx);
    return (risk_score >= ctx->config.risk_threshold_abort) || ctx->emergency_mode_active;
}

// Check if delays should be increased
bool opsec_should_increase_delays(const opsec_context_t *ctx) {
    if (!ctx) return true;

    double risk_score = opsec_calculate_risk_score(ctx);
    return (risk_score >= ctx->config.risk_threshold_slowdown);
}

// Apply adaptive delay based on current risk level
void opsec_apply_adaptive_delay(opsec_context_t *ctx) {
    if (!ctx) return;

    uint32_t delay_ms = opsec_calculate_optimal_delay(ctx);

    // Add human behavior simulation if enabled
    if (ctx->config.timing.use_human_behavior_simulation) {
        opsec_simulate_human_behavior(ctx);
    }

    // Apply the delay
    if (delay_ms > 0) {
        usleep(delay_ms * 1000);
    }

    ctx->last_operation_time = time(NULL);
}

// Calculate optimal delay based on risk and configuration
uint32_t opsec_calculate_optimal_delay(const opsec_context_t *ctx) {
    if (!ctx) return 5000;

    double risk_score = opsec_calculate_risk_score(ctx);
    risk_level_t risk_level = opsec_assess_risk_level(risk_score);

    uint32_t base_delay = ctx->config.timing.base_delay_ms;

    // Adjust delay based on risk level
    switch (risk_level) {
        case RISK_LEVEL_MINIMAL:
            break; // Use base delay
        case RISK_LEVEL_LOW:
            base_delay = (uint32_t)(base_delay * 1.5);
            break;
        case RISK_LEVEL_MODERATE:
            base_delay = (uint32_t)(base_delay * 2.0);
            break;
        case RISK_LEVEL_HIGH:
            base_delay = (uint32_t)(base_delay * 3.0);
            break;
        case RISK_LEVEL_CRITICAL:
            base_delay = (uint32_t)(base_delay * 5.0);
            break;
    }

    // Add jitter
    uint32_t jitter = 0;
    if (ctx->config.timing.jitter_range_ms > 0) {
        uint8_t random_bytes[4];
        opsec_generate_secure_random(random_bytes, sizeof(random_bytes));
        uint32_t random_value = *(uint32_t*)random_bytes;
        jitter = random_value % ctx->config.timing.jitter_range_ms;
    }

    return base_delay + jitter;
}

// Simulate human behavior patterns
void opsec_simulate_human_behavior(opsec_context_t *ctx) {
    if (!ctx) return;

    time_t current_time = time(NULL);

    // Simulate work hours (less activity at night)
    struct tm *local_time = localtime(&current_time);
    if (local_time->tm_hour < 8 || local_time->tm_hour > 22) {
        // Night hours - add extra delay
        usleep(2000000); // 2 seconds
    }

    // Simulate lunch break behavior
    if (local_time->tm_hour == 12) {
        usleep(5000000); // 5 seconds
    }

    // Random micro-breaks
    uint8_t random_byte;
    opsec_generate_secure_random(&random_byte, 1);
    if (random_byte % 100 < 5) { // 5% chance
        usleep((random_byte % 10 + 1) * 1000000); // 1-10 second break
    }
}

// Randomize timing pattern to avoid detection
int opsec_randomize_timing_pattern(timing_config_t *timing) {
    if (!timing) return -1;

    uint8_t random_bytes[16];
    opsec_generate_secure_random(random_bytes, sizeof(random_bytes));

    // Randomize base delay within reasonable bounds
    uint32_t base_variation = (*(uint32_t*)&random_bytes[0]) % (timing->base_delay_ms / 2);
    timing->base_delay_ms = timing->base_delay_ms + base_variation - (base_variation / 2);

    // Randomize jitter range
    uint32_t jitter_variation = (*(uint32_t*)&random_bytes[4]) % (timing->jitter_range_ms / 2);
    timing->jitter_range_ms = timing->jitter_range_ms + jitter_variation - (jitter_variation / 2);

    // Randomize burst limits
    uint32_t burst_variation = (*(uint32_t*)&random_bytes[8]) % 5;
    timing->burst_limit = timing->burst_limit + burst_variation - 2;
    if (timing->burst_limit < 1) timing->burst_limit = 1;

    return 0;
}

// Obfuscate HTTP headers
int opsec_obfuscate_http_headers(char *headers, size_t max_size, const traffic_obfuscation_t *config) {
    if (!headers || !config || max_size < 512) return -1;

    char temp_headers[4096];
    strcpy(temp_headers, headers);

    // Add User-Agent if configured
    if (config->vary_user_agents) {
        char user_agent[256];
        opsec_randomize_user_agent(user_agent, sizeof(user_agent));
        snprintf(temp_headers + strlen(temp_headers), sizeof(temp_headers) - strlen(temp_headers),
                "User-Agent: %s\r\n", user_agent);
    }

    // Add randomized Accept headers
    if (config->randomize_accept_headers) {
        const char *accept_patterns[] = {
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "application/json,text/plain,*/*",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
        };

        uint8_t random_byte;
        opsec_generate_secure_random(&random_byte, 1);
        const char *accept = accept_patterns[random_byte % 4];

        snprintf(temp_headers + strlen(temp_headers), sizeof(temp_headers) - strlen(temp_headers),
                "Accept: %s\r\n", accept);
    }

    // Add dummy headers for obfuscation
    if (config->add_dummy_headers) {
        const char *dummy_headers[] = {
            "X-Requested-With: XMLHttpRequest",
            "Cache-Control: no-cache",
            "Pragma: no-cache",
            "DNT: 1",
            "Upgrade-Insecure-Requests: 1"
        };

        uint8_t random_byte;
        opsec_generate_secure_random(&random_byte, 1);
        int num_dummies = (random_byte % 3) + 1;

        for (int i = 0; i < num_dummies; i++) {
            const char *dummy = dummy_headers[random_byte % 5];
            snprintf(temp_headers + strlen(temp_headers), sizeof(temp_headers) - strlen(temp_headers),
                    "%s\r\n", dummy);
        }
    }

    // Spoof referer if configured
    if (config->spoof_referer_headers) {
        const char *referers[] = {
            "https://www.google.com/",
            "https://www.bing.com/",
            "https://duckduckgo.com/",
            "https://search.yahoo.com/",
            "https://www.startpage.com/"
        };

        uint8_t random_byte;
        opsec_generate_secure_random(&random_byte, 1);
        const char *referer = referers[random_byte % 5];

        snprintf(temp_headers + strlen(temp_headers), sizeof(temp_headers) - strlen(temp_headers),
                "Referer: %s\r\n", referer);
    }

    // Copy back to original buffer
    if (strlen(temp_headers) < max_size) {
        strcpy(headers, temp_headers);
        return 0;
    }

    return -1;
}

// Randomize User-Agent string
int opsec_randomize_user_agent(char *user_agent, size_t max_size) {
    if (!user_agent || max_size < 256) return -1;

    uint8_t random_byte;
    opsec_generate_secure_random(&random_byte, 1);

    const char *selected_ua = user_agent_pool[random_byte % user_agent_pool_size];
    strncpy(user_agent, selected_ua, max_size - 1);
    user_agent[max_size - 1] = '\0';

    return 0;
}

// Add traffic padding to avoid size-based detection
int opsec_add_traffic_padding(uint8_t *buffer, size_t *size, size_t max_size) {
    if (!buffer || !size || *size >= max_size) return -1;

    uint8_t random_bytes[4];
    opsec_generate_secure_random(random_bytes, sizeof(random_bytes));

    uint32_t padding_size = (*(uint32_t*)random_bytes) % 256; // 0-255 bytes padding

    if (*size + padding_size > max_size) {
        padding_size = max_size - *size;
    }

    // Add random padding bytes
    for (uint32_t i = 0; i < padding_size; i++) {
        buffer[*size + i] = random_bytes[i % 4];
    }

    *size += padding_size;
    return 0;
}

// Detect honeypot characteristics
bool opsec_detect_honeypot(const char *target, const char *response_data, size_t response_size) {
    if (!target || !response_data) return false;

    // Check for honeypot signatures in response
    for (size_t i = 0; i < honeypot_signature_count; i++) {
        if (strstr(response_data, honeypot_signatures[i]) != NULL) {
            return true;
        }
    }

    // Check for suspicious response characteristics
    if (response_size == 0 || response_size > 1024 * 1024) { // Too small or too large
        return true;
    }

    // Check for generic/template responses
    if (strstr(response_data, "default") && strstr(response_data, "apache")) {
        return true;
    }

    return false;
}

// Detect rate limiting
bool opsec_detect_rate_limiting(const opsec_context_t *ctx) {
    if (!ctx) return false;

    // Check for rapid increase in failed operations
    uint32_t failed = atomic_load(&ctx->failed_operations);
    uint32_t total = atomic_load(&ctx->completed_operations) + failed;

    if (total > 10) {
        double failure_rate = (double)failed / total;
        if (failure_rate > 0.5) { // More than 50% failure rate
            return true;
        }
    }

    return false;
}

// Log detection event
int opsec_log_detection_event(opsec_context_t *ctx, pattern_detection_type_t type,
                             const char *target, double risk_increase, const char *description) {
    if (!ctx || !target || !description) return -1;

    pthread_mutex_lock(&ctx->detection_mutex);

    uint32_t event_count = atomic_load(&ctx->detection_event_count);
    if (event_count >= ctx->max_detection_events) {
        pthread_mutex_unlock(&ctx->detection_mutex);
        return -1; // Event log full
    }

    detection_event_t *event = &ctx->detection_events[event_count];
    event->timestamp = time(NULL);
    event->pattern_type = type;
    strncpy(event->target, target, RECON_MAX_DOMAIN_LEN - 1);
    event->risk_increase = risk_increase;
    strncpy(event->description, description, 255);
    event->triggered_evasion = false;

    atomic_store(&ctx->detection_event_count, event_count + 1);

    pthread_mutex_unlock(&ctx->detection_mutex);

    // Update risk score
    opsec_update_risk_score(ctx, risk_increase);

    return 0;
}

// Trigger evasion response
int opsec_trigger_evasion_response(opsec_context_t *ctx, pattern_detection_type_t detected_pattern) {
    if (!ctx) return -1;

    switch (detected_pattern) {
        case PATTERN_DETECTION_TIMING:
            // Randomize timing pattern
            opsec_randomize_timing_pattern(&ctx->config.timing);
            break;

        case PATTERN_DETECTION_SOURCE:
            // Rotate proxy chain
            opsec_rotate_proxy_chain(ctx);
            break;

        case PATTERN_DETECTION_USERAGENT:
            // Force User-Agent rotation
            ctx->config.obfuscation.vary_user_agents = true;
            break;

        case PATTERN_DETECTION_VOLUME:
            // Reduce operation frequency
            ctx->config.timing.base_delay_ms *= 2;
            break;

        default:
            // Generic response - increase all delays
            ctx->config.timing.base_delay_ms = (uint32_t)(ctx->config.timing.base_delay_ms * 1.5);
            break;
    }

    return 0;
}

// Activate emergency mode
void opsec_activate_emergency_mode(opsec_context_t *ctx) {
    if (!ctx || ctx->emergency_mode_active) return;

    ctx->emergency_mode_active = true;
    ctx->circuit_breaker_tripped = true;
    ctx->last_emergency_trigger = time(NULL);

    // Log emergency activation
    opsec_log_detection_event(ctx, PATTERN_DETECTION_VOLUME, "EMERGENCY",
                             1.0, "Emergency mode activated due to high risk score");

    // Trigger cleanup if configured
    if (ctx->config.enable_emergency_cleanup) {
        opsec_execute_emergency_cleanup(ctx);
    }
}

// Execute emergency cleanup procedures
void opsec_execute_emergency_cleanup(opsec_context_t *ctx) {
    if (!ctx) return;

    // Clear sensitive memory
    if (ctx->detection_events) {
        memset(ctx->detection_events, 0, ctx->max_detection_events * sizeof(detection_event_t));
    }

    // Reset counters
    atomic_store(&ctx->detection_event_count, 0);
    atomic_store(&ctx->current_risk_score, 0.0);

    // Execute external cleanup script if provided
    if (strlen(ctx->config.emergency_cleanup_script) > 0) {
        // This would execute the cleanup script in a real implementation
        // For security, we just log the intent here
        recon_log_info("opsec", "Emergency cleanup script execution requested");
    }
}

// Generate cryptographically secure random data
void opsec_generate_secure_random(uint8_t *buffer, size_t size) {
    if (!buffer || size == 0) return;

    // Try getrandom() first (Linux 3.17+)
    if (syscall(SYS_getrandom, buffer, size, 0) == (ssize_t)size) {
        return;
    }

    // Fallback to OpenSSL
    if (RAND_bytes(buffer, size) == 1) {
        return;
    }

    // Final fallback to /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t bytes_read = read(fd, buffer, size);
        close(fd);
        if (bytes_read == (ssize_t)size) {
            return;
        }
    }

    // Emergency fallback - not cryptographically secure
    srand(time(NULL));
    for (size_t i = 0; i < size; i++) {
        buffer[i] = rand() % 256;
    }
}

// Configuration presets for different paranoia levels

void opsec_configure_normal_paranoia(enhanced_opsec_config_t *config) {
    if (!config) return;

    config->paranoia_level = OPSEC_PARANOIA_NORMAL;

    // Timing configuration
    config->timing.base_delay_ms = 1000;
    config->timing.jitter_range_ms = 500;
    config->timing.burst_limit = 10;
    config->timing.burst_recovery_ms = 5000;
    config->timing.use_human_behavior_simulation = false;

    // Traffic obfuscation
    config->obfuscation.randomize_packet_sizes = false;
    config->obfuscation.vary_user_agents = true;
    config->obfuscation.add_dummy_headers = false;
    config->obfuscation.spoof_referer_headers = false;

    // Risk thresholds
    config->risk_threshold_abort = 0.8;
    config->risk_threshold_slowdown = 0.6;

    // Counter-surveillance
    config->surveillance.detect_honeypots = true;
    config->surveillance.detect_rate_limiting = true;
    config->surveillance.anomaly_threshold = 5;

    // Session management
    config->max_operations_per_session = 100;
    config->session_timeout_seconds = 3600;
    config->enable_circuit_breaker = true;
}

void opsec_configure_high_paranoia(enhanced_opsec_config_t *config) {
    if (!config) return;

    // Start with normal configuration
    opsec_configure_normal_paranoia(config);

    config->paranoia_level = OPSEC_PARANOIA_HIGH;

    // Enhanced timing
    config->timing.base_delay_ms = 2000;
    config->timing.jitter_range_ms = 1000;
    config->timing.burst_limit = 5;
    config->timing.use_human_behavior_simulation = true;

    // Enhanced obfuscation
    config->obfuscation.randomize_packet_sizes = true;
    config->obfuscation.add_dummy_headers = true;
    config->obfuscation.spoof_referer_headers = true;
    config->obfuscation.randomize_accept_headers = true;

    // Stricter risk thresholds
    config->risk_threshold_abort = 0.6;
    config->risk_threshold_slowdown = 0.4;

    // Enhanced surveillance detection
    config->surveillance.detect_geo_blocking = true;
    config->surveillance.detect_behavioral_analysis = true;
    config->surveillance.anomaly_threshold = 3;

    // More conservative session limits
    config->max_operations_per_session = 50;
    config->session_timeout_seconds = 1800;
    config->proxy_rotation_interval = 25;
}

void opsec_configure_maximum_paranoia(enhanced_opsec_config_t *config) {
    if (!config) return;

    // Start with high configuration
    opsec_configure_high_paranoia(config);

    config->paranoia_level = OPSEC_PARANOIA_MAXIMUM;

    // Maximum timing delays
    config->timing.base_delay_ms = 5000;
    config->timing.jitter_range_ms = 3000;
    config->timing.burst_limit = 3;
    config->timing.use_poisson_distribution = true;

    // Maximum obfuscation
    config->obfuscation.fragment_large_requests = true;
    config->obfuscation.use_keep_alive_variation = true;
    config->obfuscation.padding_size_range = 1024;

    // Paranoid risk thresholds
    config->risk_threshold_abort = 0.4;
    config->risk_threshold_slowdown = 0.2;

    // Maximum surveillance detection
    config->surveillance.monitor_response_anomalies = true;
    config->surveillance.check_certificate_transparency = true;
    config->surveillance.suspicion_score_limit = 0.3;

    // Extreme session limits
    config->max_operations_per_session = 20;
    config->session_timeout_seconds = 900;
    config->proxy_rotation_interval = 10;
    config->use_distributed_scanning = true;
    config->use_decoy_requests = true;
    config->decoy_request_ratio = 3;
}

void opsec_configure_ghost_paranoia(enhanced_opsec_config_t *config) {
    if (!config) return;

    // Start with maximum configuration
    opsec_configure_maximum_paranoia(config);

    config->paranoia_level = OPSEC_PARANOIA_GHOST;

    // Ghost-level timing
    config->timing.base_delay_ms = 10000;
    config->timing.jitter_range_ms = 5000;
    config->timing.burst_limit = 1;
    config->timing.session_length_variance_pct = 50;

    // Ghost-level obfuscation
    config->spoof_source_information = true;
    config->randomize_scan_order = true;

    // Paranoid risk thresholds
    config->risk_threshold_abort = 0.2;
    config->risk_threshold_slowdown = 0.1;

    // Ultra-conservative session limits
    config->max_operations_per_session = 10;
    config->session_timeout_seconds = 600;
    config->inter_session_delay_ms = 30000;
    config->proxy_rotation_interval = 5;
    config->decoy_request_ratio = 5;

    // Emergency measures
    config->enable_emergency_cleanup = true;
    config->dormant_timeout_seconds = 300;
}

// String conversion functions
const char *opsec_paranoia_level_to_string(opsec_paranoia_level_t level) {
    switch (level) {
        case OPSEC_PARANOIA_NORMAL: return "NORMAL";
        case OPSEC_PARANOIA_HIGH: return "HIGH";
        case OPSEC_PARANOIA_MAXIMUM: return "MAXIMUM";
        case OPSEC_PARANOIA_GHOST: return "GHOST";
        default: return "UNKNOWN";
    }
}

const char *opsec_risk_level_to_string(risk_level_t level) {
    switch (level) {
        case RISK_LEVEL_MINIMAL: return "MINIMAL";
        case RISK_LEVEL_LOW: return "LOW";
        case RISK_LEVEL_MODERATE: return "MODERATE";
        case RISK_LEVEL_HIGH: return "HIGH";
        case RISK_LEVEL_CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

const char *opsec_pattern_type_to_string(pattern_detection_type_t type) {
    switch (type) {
        case PATTERN_DETECTION_TIMING: return "TIMING";
        case PATTERN_DETECTION_VOLUME: return "VOLUME";
        case PATTERN_DETECTION_SEQUENCE: return "SEQUENCE";
        case PATTERN_DETECTION_SOURCE: return "SOURCE";
        case PATTERN_DETECTION_USERAGENT: return "USERAGENT";
        case PATTERN_DETECTION_TLS: return "TLS";
        case PATTERN_DETECTION_DNS: return "DNS";
        default: return "UNKNOWN";
    }
}

// Print performance metrics
void opsec_print_performance_metrics(const opsec_context_t *ctx) {
    if (!ctx) return;

    printf("\n=== OPSEC Performance Metrics ===\n");
    printf("Paranoia Level: %s\n", opsec_paranoia_level_to_string(ctx->config.paranoia_level));
    printf("Current Risk Score: %.3f\n", atomic_load(&ctx->current_risk_score));
    printf("Active Operations: %u\n", atomic_load(&ctx->active_operations));
    printf("Completed Operations: %u\n", atomic_load(&ctx->completed_operations));
    printf("Failed Operations: %u\n", atomic_load(&ctx->failed_operations));
    printf("Detection Events: %u\n", atomic_load(&ctx->detection_event_count));
    printf("Emergency Mode: %s\n", ctx->emergency_mode_active ? "ACTIVE" : "INACTIVE");
    printf("Circuit Breaker: %s\n", ctx->circuit_breaker_tripped ? "TRIPPED" : "NORMAL");

    double success_rate = opsec_calculate_evasion_success_rate(ctx);
    printf("Evasion Success Rate: %.1f%%\n", success_rate * 100);

    printf("==================================\n\n");
}

// Calculate evasion success rate
double opsec_calculate_evasion_success_rate(const opsec_context_t *ctx) {
    if (!ctx) return 0.0;

    uint32_t total_evasions = ctx->successful_evasions + ctx->failed_evasions;
    if (total_evasions == 0) return 1.0;

    return (double)ctx->successful_evasions / total_evasions;
}

// Stub implementations for missing OPSEC functions

int opsec_analyze_response_anomalies(const char *response, size_t size, double *anomaly_score) {
    (void)response;
    (void)size;
    if (anomaly_score) *anomaly_score = 0.0;
    return 0; // No anomalies detected (stub)
}

bool opsec_detect_geo_blocking(const char *response_data, size_t response_size) {
    (void)response_data;
    (void)response_size;
    return false; // No geo-blocking detected (stub)
}

int opsec_fragment_request(const uint8_t *data, size_t data_size, uint8_t **fragments, uint32_t *fragment_count) {
    (void)data;
    (void)data_size;
    (void)fragments;
    (void)fragment_count;
    return -1; // Not implemented (stub)
}
