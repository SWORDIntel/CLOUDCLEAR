/*
 * CloudUnflare Enhanced - Reconnaissance Common Header
 *
 * Common definitions, structures, and utilities for API-free reconnaissance modules
 * Designed for OPSEC-compliant passive and active reconnaissance
 *
 * Phase 1 Modules:
 * - DNS Zone Transfer (AXFR/IXFR)
 * - Enhanced DNS Brute-Force
 * - HTTP Banner Grabbing
 * - Port Scanning (TCP SYN/UDP/Connect)
 *
 * Agent Coordination:
 * - C-INTERNAL: Core implementation
 * - ARCHITECT: Integration design
 * - SECURITY: OPSEC compliance
 * - OPTIMIZER: Performance tuning
 */

#ifndef RECON_COMMON_H
#define RECON_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include "platform_compat.h"
#include "config.h"

// Maximum limits for reconnaissance operations
#define RECON_MAX_TARGETS 1000
#define RECON_MAX_PORTS 65535
#define RECON_MAX_THREADS 50
#define RECON_MAX_TIMEOUT 30
#define RECON_MAX_RETRIES 3
#define RECON_BUFFER_SIZE 4096
#define RECON_MAX_BANNER_SIZE 1024
#define RECON_MAX_DOMAIN_LEN 256

// Reconnaissance operation types
typedef enum {
    RECON_TYPE_DNS_ZONE_TRANSFER,
    RECON_TYPE_DNS_BRUTEFORCE,
    RECON_TYPE_HTTP_BANNER,
    RECON_TYPE_PORT_SCAN_TCP,
    RECON_TYPE_PORT_SCAN_UDP,
    RECON_TYPE_PORT_SCAN_SYN,
    RECON_TYPE_SSL_ANALYSIS
} recon_operation_t;

// Reconnaissance scan modes
typedef enum {
    RECON_MODE_PASSIVE,      // No direct target interaction
    RECON_MODE_ACTIVE,       // Direct target interaction
    RECON_MODE_AGGRESSIVE,   // Fast, noisy scanning
    RECON_MODE_STEALTH       // Slow, OPSEC-compliant scanning
} recon_mode_t;

// Target specification structure
typedef struct {
    char hostname[RECON_MAX_DOMAIN_LEN];
    char ip_address[INET6_ADDRSTRLEN];
    uint16_t port;
    bool is_ipv6;
    time_t last_scanned;
    recon_operation_t scan_type;
} recon_target_t;

// Reconnaissance result structure
typedef struct {
    recon_target_t target;
    bool success;
    char banner[RECON_MAX_BANNER_SIZE];
    char service_version[256];
    char ssl_version[64];
    char ssl_cipher[128];
    uint32_t response_time_ms;
    time_t timestamp;
    char additional_info[512];
} recon_result_t;

// Thread-safe reconnaissance context
typedef struct {
    pthread_mutex_t mutex;
    _Atomic uint32_t active_threads;
    _Atomic uint32_t completed_scans;
    _Atomic uint32_t failed_scans;
    _Atomic uint64_t total_response_time;
    recon_mode_t scan_mode;
    uint32_t max_threads;
    uint32_t timeout_seconds;
    uint32_t delay_between_requests_ms;
    bool stop_scanning;
} recon_context_t;

// OPSEC evasion configuration
typedef struct {
    uint32_t min_delay_ms;
    uint32_t max_delay_ms;
    uint32_t jitter_ms;
    uint32_t max_requests_per_session;
    uint32_t session_timeout_seconds;
    bool randomize_user_agents;
    bool use_proxy_rotation;
    bool spoof_source_ports;
} recon_opsec_config_t;

// Function prototypes for common reconnaissance utilities

// Initialization and cleanup
int recon_init_context(recon_context_t *ctx, recon_mode_t mode);
void recon_cleanup_context(recon_context_t *ctx);

// Target management
int recon_add_target(recon_target_t *target, const char *hostname, uint16_t port);
bool recon_is_valid_target(const recon_target_t *target);
int recon_resolve_target(recon_target_t *target);

// OPSEC and evasion
void recon_apply_opsec_delay(const recon_opsec_config_t *config);
void recon_randomize_timing(uint32_t base_delay_ms, uint32_t jitter_ms);
int recon_check_detection_risk(const recon_context_t *ctx);

// Result handling
void recon_init_result(recon_result_t *result, const recon_target_t *target);
void recon_log_result(const recon_result_t *result);
void recon_export_results(const recon_result_t *results, size_t count, const char *format);

// Performance monitoring
double recon_calculate_success_rate(const recon_context_t *ctx);
uint32_t recon_get_average_response_time(const recon_context_t *ctx);
void recon_print_statistics(const recon_context_t *ctx);

// Error handling and logging
void recon_log_error(const char *operation, const char *target, const char *error);
void recon_log_info(const char *operation, const char *message);
void recon_log_debug(const char *operation, const char *details);

// Network utilities
int recon_create_socket(int family, int type, int protocol);
int recon_set_socket_timeout(int sockfd, uint32_t timeout_seconds);
int recon_connect_with_timeout(int sockfd, const struct sockaddr *addr, socklen_t addrlen, uint32_t timeout_seconds);

// String utilities
void recon_sanitize_string(char *str, size_t max_len);
bool recon_is_valid_hostname(const char *hostname);
bool recon_is_valid_ip(const char *ip_str);

// Threading utilities
int recon_create_thread_pool(pthread_t *threads, size_t count, void *(*start_routine)(void *), void *arg);
void recon_wait_for_threads(pthread_t *threads, size_t count);

#endif // RECON_COMMON_H