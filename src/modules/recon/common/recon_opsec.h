/*
 * CloudUnflare Enhanced - Advanced OPSEC Framework
 *
 * Nation-state level operational security framework for reconnaissance modules
 * Implements comprehensive anti-detection, evasion, and counter-surveillance
 *
 * Security Level: CLASSIFIED
 * Agent: SECURITY (primary implementation)
 * Coordination: C-INTERNAL, GHOST-PROTOCOL, NSA-TTP
 *
 * Features:
 * - Multi-level paranoia settings (NORMAL, HIGH, MAXIMUM, GHOST)
 * - Real-time detection risk assessment (0.0-1.0 scale)
 * - Traffic pattern obfuscation and timing randomization
 * - Proxy chain support with rotation and health monitoring
 * - Counter-surveillance and honeypot detection
 * - Automated evasion response and emergency cleanup
 * - Adaptive behavior based on threat level
 */

#ifndef RECON_OPSEC_H
#define RECON_OPSEC_H

#include <stddef.h>
#include <time.h>
#include "recon_common.h"
#include "platform_compat.h"
#include <openssl/rand.h>

// OPSEC paranoia levels
typedef enum {
    OPSEC_PARANOIA_NORMAL,     // Standard operational security
    OPSEC_PARANOIA_HIGH,       // Enhanced counter-detection
    OPSEC_PARANOIA_MAXIMUM,    // Nation-state level evasion
    OPSEC_PARANOIA_GHOST       // Invisible mode - maximum stealth
} opsec_paranoia_level_t;

// Detection risk levels
typedef enum {
    RISK_LEVEL_MINIMAL,    // 0.0-0.2: Safe to proceed
    RISK_LEVEL_LOW,        // 0.2-0.4: Caution advised
    RISK_LEVEL_MODERATE,   // 0.4-0.6: Increase delays
    RISK_LEVEL_HIGH,       // 0.6-0.8: Extreme caution
    RISK_LEVEL_CRITICAL    // 0.8-1.0: Abort operation
} risk_level_t;

// Proxy types for chain rotation
typedef enum {
    PROXY_TYPE_HTTP,
    PROXY_TYPE_HTTPS,
    PROXY_TYPE_SOCKS4,
    PROXY_TYPE_SOCKS5,
    PROXY_TYPE_TOR_BRIDGE,
    PROXY_TYPE_VPN_TUNNEL
} proxy_type_t;

// Traffic analysis patterns to avoid
typedef enum {
    PATTERN_DETECTION_TIMING,      // Regular timing intervals
    PATTERN_DETECTION_VOLUME,      // Consistent request volumes
    PATTERN_DETECTION_SEQUENCE,    // Predictable request sequences
    PATTERN_DETECTION_SOURCE,      // Source IP clustering
    PATTERN_DETECTION_USERAGENT,   // User-Agent fingerprinting
    PATTERN_DETECTION_TLS,         // TLS fingerprinting
    PATTERN_DETECTION_DNS          // DNS query patterns
} pattern_detection_type_t;

// Proxy chain node
typedef struct {
    char address[INET6_ADDRSTRLEN];
    uint16_t port;
    proxy_type_t type;
    char username[128];
    char password[128];
    bool authenticated;
    uint32_t latency_ms;
    uint32_t success_rate;
    time_t last_used;
    time_t last_health_check;
    bool operational;
    char country_code[3];
    double trust_score;
} proxy_node_t;

// Advanced timing configuration
typedef struct {
    uint32_t base_delay_ms;
    uint32_t jitter_range_ms;
    uint32_t burst_limit;
    uint32_t burst_recovery_ms;
    double timing_entropy;
    bool use_poisson_distribution;
    bool use_human_behavior_simulation;
    uint32_t session_length_variance_pct;
} timing_config_t;

// Traffic obfuscation settings
typedef struct {
    bool randomize_packet_sizes;
    bool fragment_large_requests;
    bool add_dummy_headers;
    bool vary_user_agents;
    bool spoof_referer_headers;
    bool randomize_accept_headers;
    bool use_keep_alive_variation;
    uint32_t padding_size_range;
} traffic_obfuscation_t;

// Counter-surveillance configuration
typedef struct {
    bool detect_honeypots;
    bool detect_rate_limiting;
    bool detect_geo_blocking;
    bool detect_behavioral_analysis;
    bool monitor_response_anomalies;
    bool check_certificate_transparency;
    uint32_t anomaly_threshold;
    double suspicion_score_limit;
} counter_surveillance_t;

// Enhanced OPSEC configuration
typedef struct {
    opsec_paranoia_level_t paranoia_level;
    timing_config_t timing;
    traffic_obfuscation_t obfuscation;
    counter_surveillance_t surveillance;

    // Proxy chain configuration
    proxy_node_t *proxy_chain;
    uint32_t proxy_chain_length;
    uint32_t max_chain_length;
    uint32_t proxy_rotation_interval;
    bool enable_proxy_health_checks;

    // Detection risk management
    double current_risk_score;
    double risk_threshold_abort;
    double risk_threshold_slowdown;
    uint32_t risk_assessment_interval;
    bool adaptive_behavior_enabled;

    // Emergency response
    bool enable_circuit_breaker;
    bool enable_emergency_cleanup;
    char emergency_cleanup_script[512];
    uint32_t max_failed_operations;
    uint32_t dormant_timeout_seconds;

    // Advanced evasion
    bool use_distributed_scanning;
    bool randomize_scan_order;
    bool use_decoy_requests;
    uint32_t decoy_request_ratio;
    bool spoof_source_information;

    // Session management
    uint32_t max_operations_per_session;
    uint32_t session_timeout_seconds;
    uint32_t inter_session_delay_ms;
    bool randomize_session_characteristics;
} enhanced_opsec_config_t;

// Detection event logging
typedef struct {
    time_t timestamp;
    pattern_detection_type_t pattern_type;
    char target[RECON_MAX_DOMAIN_LEN];
    double risk_increase;
    char description[256];
    bool triggered_evasion;
    char evasion_action[128];
} detection_event_t;

// OPSEC context for tracking operations
typedef struct {
    enhanced_opsec_config_t config;

    // Runtime state
    _Atomic uint32_t active_operations;
    _Atomic uint32_t completed_operations;
    _Atomic uint32_t failed_operations;
    _Atomic double current_risk_score;

    // Detection tracking
    detection_event_t *detection_events;
    uint32_t max_detection_events;
    _Atomic uint32_t detection_event_count;
    pthread_mutex_t detection_mutex;

    // Proxy management
    pthread_mutex_t proxy_mutex;
    uint32_t current_proxy_index;
    time_t last_proxy_rotation;

    // Timing state
    time_t last_operation_time;
    uint32_t operations_in_current_burst;
    time_t burst_start_time;

    // Emergency state
    bool emergency_mode_active;
    bool circuit_breaker_tripped;
    time_t last_emergency_trigger;

    // Performance metrics
    uint64_t total_evasion_time_ms;
    uint32_t successful_evasions;
    uint32_t failed_evasions;
} opsec_context_t;

// Function prototypes

// Initialization and configuration
int opsec_init_context(opsec_context_t *ctx, opsec_paranoia_level_t paranoia);
void opsec_cleanup_context(opsec_context_t *ctx);
int opsec_configure_paranoia_level(opsec_context_t *ctx, opsec_paranoia_level_t level);

// Risk assessment and management
double opsec_calculate_risk_score(const opsec_context_t *ctx);
risk_level_t opsec_assess_risk_level(double risk_score);
int opsec_update_risk_score(opsec_context_t *ctx, double risk_delta);
bool opsec_should_abort_operation(const opsec_context_t *ctx);
bool opsec_should_increase_delays(const opsec_context_t *ctx);

// Timing and evasion
void opsec_apply_adaptive_delay(opsec_context_t *ctx);
uint32_t opsec_calculate_optimal_delay(const opsec_context_t *ctx);
void opsec_simulate_human_behavior(opsec_context_t *ctx);
int opsec_randomize_timing_pattern(timing_config_t *timing);

// Proxy management functions
bool opsec_should_rotate_proxy(const opsec_context_t *ctx);
proxy_node_t* opsec_get_current_proxy(const opsec_context_t *ctx);

// Traffic obfuscation
int opsec_obfuscate_http_headers(char *headers, size_t max_size, const traffic_obfuscation_t *config);
int opsec_randomize_user_agent(char *user_agent, size_t max_size);
int opsec_add_traffic_padding(uint8_t *buffer, size_t *size, size_t max_size);
int opsec_fragment_request(const uint8_t *data, size_t data_size, uint8_t **fragments, uint32_t *fragment_count);

// Proxy chain management
int opsec_init_proxy_chain(opsec_context_t *ctx, const char *proxy_list_file);
int opsec_add_proxy_node(opsec_context_t *ctx, const char *address, uint16_t port, proxy_type_t type);
int opsec_rotate_proxy_chain(opsec_context_t *ctx);
bool opsec_health_check_proxy(proxy_node_t *proxy);
int opsec_establish_proxy_connection(const proxy_node_t *proxy, const char *target_host, uint16_t target_port);

// Counter-surveillance
bool opsec_detect_honeypot(const char *target, const char *response_data, size_t response_size);
bool opsec_detect_rate_limiting(const opsec_context_t *ctx);
bool opsec_detect_geo_blocking(const char *response_data, size_t response_size);
double opsec_calculate_suspicion_score(const opsec_context_t *ctx);
int opsec_analyze_response_anomalies(const char *response, size_t size, double *anomaly_score);

// Detection event handling
int opsec_log_detection_event(opsec_context_t *ctx, pattern_detection_type_t type,
                             const char *target, double risk_increase, const char *description);
int opsec_trigger_evasion_response(opsec_context_t *ctx, pattern_detection_type_t detected_pattern);
void opsec_activate_emergency_mode(opsec_context_t *ctx);
void opsec_execute_emergency_cleanup(opsec_context_t *ctx);

// Advanced evasion techniques
int opsec_generate_decoy_requests(const char *target, uint32_t count);
int opsec_distribute_scan_across_sources(const char **targets, uint32_t target_count);
int opsec_randomize_operation_sequence(void **operations, uint32_t count);
int opsec_spoof_source_characteristics(opsec_context_t *ctx);

// Session management
int opsec_start_new_session(opsec_context_t *ctx);
int opsec_end_current_session(opsec_context_t *ctx);
bool opsec_should_rotate_session(const opsec_context_t *ctx);
int opsec_apply_inter_session_delay(opsec_context_t *ctx);

// Utility functions
const char *opsec_paranoia_level_to_string(opsec_paranoia_level_t level);
const char *opsec_risk_level_to_string(risk_level_t level);
const char *opsec_pattern_type_to_string(pattern_detection_type_t type);
void opsec_generate_secure_random(uint8_t *buffer, size_t size);
uint64_t opsec_get_high_resolution_time(void);

// Performance monitoring
void opsec_print_performance_metrics(const opsec_context_t *ctx);
int opsec_export_detection_events(const opsec_context_t *ctx, const char *filename);
double opsec_calculate_evasion_success_rate(const opsec_context_t *ctx);

// Configuration presets
void opsec_configure_normal_paranoia(enhanced_opsec_config_t *config);
void opsec_configure_high_paranoia(enhanced_opsec_config_t *config);
void opsec_configure_maximum_paranoia(enhanced_opsec_config_t *config);
void opsec_configure_ghost_paranoia(enhanced_opsec_config_t *config);

#endif // RECON_OPSEC_H
