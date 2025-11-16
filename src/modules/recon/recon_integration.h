/*
 * CloudUnflare Enhanced - Reconnaissance Integration Master Header
 *
 * Main integration interface for seamless reconnaissance module integration
 * with CloudUnflare Enhanced v2.0. Provides unified API for all reconnaissance
 * capabilities while maintaining zero performance impact on core functions.
 *
 * Agent: ARCHITECT (integration architecture)
 * Performance Target: 10,000+ queries/second aggregate
 * Memory Limit: <500MB total usage
 * Thread Limit: 50 threads (shared with main application)
 */

#ifndef RECON_INTEGRATION_H
#define RECON_INTEGRATION_H

#include "common/recon_module_interface.h"
#include "common/recon_integration_manager.h"
#include "common/recon_config_manager.h"
#include "common/recon_result_aggregator.h"
#include "common/recon_opsec.h"
#include "../dns_enhanced.h"
#include "../config.h"

// Integration API version
#define RECON_INTEGRATION_API_VERSION "1.0.0"
#define RECON_INTEGRATION_COMPATIBLE_CLOUDUNFLARE_VERSION "2.0-Enhanced"

// Integration status for CloudUnflare main application
typedef enum {
    RECON_INTEGRATION_DISABLED,
    RECON_INTEGRATION_INITIALIZING,
    RECON_INTEGRATION_READY,
    RECON_INTEGRATION_ACTIVE,
    RECON_INTEGRATION_DEGRADED,
    RECON_INTEGRATION_EMERGENCY_HALT,
    RECON_INTEGRATION_SHUTTING_DOWN
} recon_integration_status_t;

// Master integration context
typedef struct {
    // Component managers
    integration_manager_t integration_manager;
    config_manager_t config_manager;
    result_aggregator_t result_aggregator;
    module_registry_t module_registry;
    opsec_context_t opsec_context;

    // Integration state
    recon_integration_status_t status;
    bool initialized;
    bool auto_start_enabled;
    bool performance_monitoring_enabled;

    // CloudUnflare integration points
    struct dns_resolver_chain *shared_dns_chain;
    pthread_t *shared_thread_pool;
    uint32_t available_threads;
    void **shared_memory_pools;

    // Performance isolation
    bool performance_isolation_active;
    double baseline_performance;
    double performance_degradation_threshold;

    // Emergency controls
    bool emergency_halt_capable;
    char emergency_halt_reason[256];
    time_t emergency_halt_time;

    // Statistics
    time_t integration_start_time;
    _Atomic uint64_t total_operations_processed;
    _Atomic uint64_t successful_operations;
    _Atomic uint64_t failed_operations;

    pthread_mutex_t master_mutex;
} recon_master_context_t;

// Simplified API for CloudUnflare main application integration
typedef struct {
    // Basic reconnaissance functions
    int (*dns_zone_transfer)(const char *domain, char ***records, uint32_t *record_count);
    int (*dns_bruteforce)(const char *domain, const char *wordlist, char ***subdomains, uint32_t *subdomain_count);
    int (*http_banner_grab)(const char *target, uint16_t port, char *banner, size_t banner_size);
    int (*port_scan)(const char *target, uint16_t *ports, uint32_t port_count, bool *open_ports);

    // Batch operations
    int (*batch_dns_enumeration)(const char **domains, uint32_t domain_count, recon_result_t **results, uint32_t *result_count);
    int (*batch_port_scanning)(const char **targets, uint32_t target_count, uint16_t *ports, uint32_t port_count, recon_result_t **results, uint32_t *result_count);

    // Configuration and control
    int (*set_opsec_level)(opsec_paranoia_level_t level);
    int (*set_scan_mode)(recon_mode_t mode);
    int (*set_thread_limit)(uint32_t max_threads);
    int (*emergency_halt)(void);

    // Status and monitoring
    recon_integration_status_t (*get_status)(void);
    int (*get_performance_metrics)(char **metrics_json);
    bool (*is_operational)(void);
} recon_simple_api_t;

// Function prototypes for main CloudUnflare integration

// Master initialization and lifecycle
int recon_integration_init(recon_master_context_t *context, const char *config_file);
int recon_integration_start(recon_master_context_t *context);
int recon_integration_stop(recon_master_context_t *context);
void recon_integration_cleanup(recon_master_context_t *context);

// CloudUnflare integration points
int recon_integrate_with_cloudunflare(recon_master_context_t *context,
                                     struct dns_resolver_chain *dns_chain,
                                     pthread_t *thread_pool,
                                     uint32_t thread_count,
                                     void **memory_pools);

int recon_share_cloudunflare_resources(recon_master_context_t *context);
int recon_isolate_performance_impact(recon_master_context_t *context);

// Simple API implementation
recon_simple_api_t *recon_get_simple_api(void);
int recon_enable_simple_api(recon_master_context_t *context);
int recon_disable_simple_api(recon_master_context_t *context);

// Module registration and management
int recon_register_all_modules(recon_master_context_t *context);
int recon_start_module(recon_master_context_t *context, const char *module_name);
int recon_stop_module(recon_master_context_t *context, const char *module_name);
int recon_restart_module(recon_master_context_t *context, const char *module_name);

// Configuration management
int recon_load_configuration(recon_master_context_t *context, const char *config_file);
int recon_apply_opsec_configuration(recon_master_context_t *context, opsec_paranoia_level_t level);
int recon_update_configuration(recon_master_context_t *context, const char *section, const char *key, const char *value);

// Performance monitoring and control
int recon_monitor_performance_impact(recon_master_context_t *context);
bool recon_is_performance_acceptable(const recon_master_context_t *context);
int recon_trigger_performance_protection(recon_master_context_t *context);
int recon_get_performance_report(const recon_master_context_t *context, char **report);

// Result management
int recon_get_all_results(recon_master_context_t *context, recon_result_t **results, uint32_t *count);
int recon_get_results_by_target(recon_master_context_t *context, const char *target, recon_result_t **results, uint32_t *count);
int recon_export_results(recon_master_context_t *context, const char *filename, const char *format);

// Emergency operations
int recon_trigger_emergency_halt(recon_master_context_t *context, const char *reason);
int recon_recover_from_emergency(recon_master_context_t *context);
bool recon_is_emergency_halt_active(const recon_master_context_t *context);

// Status and diagnostics
recon_integration_status_t recon_get_integration_status(const recon_master_context_t *context);
int recon_health_check(recon_master_context_t *context);
int recon_generate_status_report(const recon_master_context_t *context, char **report);
int recon_run_diagnostics(recon_master_context_t *context);

// Utility functions
const char *recon_integration_status_to_string(recon_integration_status_t status);
int recon_print_integration_summary(const recon_master_context_t *context);
bool recon_is_compatible_with_cloudunflare(const char *cloudunflare_version);

// Global master context
extern recon_master_context_t global_recon_context;

// Main integration macros for CloudUnflare main application

// Initialize reconnaissance modules
#define RECON_INIT(config_file) \
    recon_integration_init(&global_recon_context, config_file)

// Start reconnaissance subsystem
#define RECON_START() \
    recon_integration_start(&global_recon_context)

// Stop reconnaissance subsystem
#define RECON_STOP() \
    recon_integration_stop(&global_recon_context)

// Check if reconnaissance is operational
#define RECON_IS_READY() \
    (recon_get_integration_status(&global_recon_context) == RECON_INTEGRATION_ACTIVE)

// Performance guard - halt if performance impact too high
#define RECON_PERFORMANCE_GUARD() \
    do { \
        if (!recon_is_performance_acceptable(&global_recon_context)) { \
            recon_trigger_performance_protection(&global_recon_context); \
        } \
    } while(0)

// Emergency halt if needed
#define RECON_EMERGENCY_HALT(reason) \
    recon_trigger_emergency_halt(&global_recon_context, reason)

// Phase 1 module specific macros for easy integration

// DNS Zone Transfer
#define RECON_DNS_ZONE_TRANSFER(domain, records, count) \
    recon_get_simple_api()->dns_zone_transfer(domain, records, count)

// DNS Brute Force
#define RECON_DNS_BRUTEFORCE(domain, wordlist, subdomains, count) \
    recon_get_simple_api()->dns_bruteforce(domain, wordlist, subdomains, count)

// HTTP Banner Grabbing
#define RECON_HTTP_BANNER(target, port, banner, size) \
    recon_get_simple_api()->http_banner_grab(target, port, banner, size)

// Port Scanning
#define RECON_PORT_SCAN(target, ports, port_count, open_ports) \
    recon_get_simple_api()->port_scan(target, ports, port_count, open_ports)

// Cloudflare Radar Scanning
#define RECON_CLOUDFLARE_RADAR_SCAN(domain, scan_type) \
    radar_scan_execute_single(&global_radar_context, domain, scan_type)

#define RECON_CLOUDFLARE_RADAR_COMPREHENSIVE(domain) \
    radar_scan_execute_comprehensive(&global_radar_context, domain)

// Conditional compilation support
#ifdef RECON_MODULES_ENABLED
    #define RECON_MODULE_AVAILABLE 1
    #define RECON_FEATURE_AVAILABLE(feature) (FEATURE_##feature)
#else
    #define RECON_MODULE_AVAILABLE 0
    #define RECON_FEATURE_AVAILABLE(feature) 0
#endif

// Integration verification
static inline bool recon_verify_integration(void) {
    return (RECON_MODULE_AVAILABLE &&
            recon_is_compatible_with_cloudunflare(CLOUDUNFLARE_VERSION) &&
            recon_get_integration_status(&global_recon_context) != RECON_INTEGRATION_DISABLED);
}

// Compile-time integration checks
#if defined(RECON_MODULES_ENABLED) && !defined(CLOUDUNFLARE_VERSION)
    #error "CLOUDUNFLARE_VERSION must be defined when RECON_MODULES_ENABLED is set"
#endif

#if defined(RECON_MODULES_ENABLED) && (MAX_CONCURRENT_THREADS < RECON_MAX_CONCURRENT_OPERATIONS)
    #warning "MAX_CONCURRENT_THREADS may be insufficient for reconnaissance operations"
#endif

#endif // RECON_INTEGRATION_H