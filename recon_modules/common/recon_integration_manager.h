/*
 * CloudUnflare Enhanced - Reconnaissance Integration Manager
 *
 * Manages seamless integration of reconnaissance modules with CloudUnflare's
 * existing infrastructure, ensuring zero performance impact and production-grade reliability
 *
 * Agent: ARCHITECT (integration design)
 * Coordination: OPTIMIZER, SECURITY, C-INTERNAL
 * Integration Target: Zero performance impact on CloudUnflare v2.0 core functions
 */

#ifndef RECON_INTEGRATION_MANAGER_H
#define RECON_INTEGRATION_MANAGER_H

#include "recon_module_interface.h"
#include "../../dns_enhanced.h"
#include "../../config.h"
#include <sys/epoll.h>
#include <sys/eventfd.h>

// Integration subsystem identifiers
typedef enum {
    INTEGRATION_DNS_ENHANCED,
    INTEGRATION_THREAD_POOL,
    INTEGRATION_MEMORY_POOL,
    INTEGRATION_OPSEC_FRAMEWORK,
    INTEGRATION_RATE_LIMITER,
    INTEGRATION_RESULT_AGGREGATOR,
    INTEGRATION_CONFIGURATION,
    INTEGRATION_MONITORING
} integration_subsystem_t;

// Integration status tracking
typedef enum {
    INTEGRATION_STATUS_DISABLED,
    INTEGRATION_STATUS_INITIALIZING,
    INTEGRATION_STATUS_ACTIVE,
    INTEGRATION_STATUS_DEGRADED,
    INTEGRATION_STATUS_FAILED,
    INTEGRATION_STATUS_EMERGENCY_HALT
} integration_status_t;

// Resource allocation strategy
typedef enum {
    RESOURCE_STRATEGY_CONSERVATIVE, // Minimal resource usage
    RESOURCE_STRATEGY_BALANCED,     // Balanced performance/resources
    RESOURCE_STRATEGY_AGGRESSIVE,   // Maximum performance
    RESOURCE_STRATEGY_ADAPTIVE      // Dynamic adjustment
} resource_allocation_strategy_t;

// Integration subsystem configuration
typedef struct {
    integration_subsystem_t subsystem;
    integration_status_t status;
    bool enabled;
    uint32_t priority;
    uint32_t max_memory_mb;
    uint32_t max_threads;
    uint32_t max_operations_per_second;
    resource_allocation_strategy_t strategy;
    void *subsystem_specific_config;
} integration_subsystem_config_t;

// CloudUnflare integration points
typedef struct {
    // DNS Enhanced integration
    struct dns_resolver_chain *main_dns_chain;
    struct rate_limiter *dns_rate_limiter;
    struct adaptive_retry_strategy *dns_retry_strategy;

    // Thread pool integration
    pthread_t *main_thread_pool;
    uint32_t main_thread_count;
    uint32_t available_threads;
    pthread_mutex_t thread_allocation_mutex;

    // Memory pool integration
    void **memory_pools;
    uint32_t pool_count;
    size_t total_allocated;
    size_t memory_limit;
    pthread_mutex_t memory_mutex;

    // Configuration integration
    char *config_file_path;
    time_t config_last_modified;
    bool config_hot_reload_enabled;

    // Monitoring integration
    FILE *main_log_file;
    int metrics_fd;
    bool metrics_enabled;

    // Event system integration
    int epoll_fd;
    int event_fd;
    struct epoll_event *events;
    uint32_t max_events;
} cloudunflare_integration_points_t;

// Integration manager context
typedef struct {
    // Core integration
    cloudunflare_integration_points_t integration_points;
    module_registry_t *module_registry;
    opsec_context_t *global_opsec_context;

    // Subsystem management
    integration_subsystem_config_t subsystems[8];
    uint32_t active_subsystems;
    pthread_mutex_t subsystem_mutex;

    // Resource management
    resource_allocation_strategy_t resource_strategy;
    _Atomic uint64_t total_memory_allocated;
    _Atomic uint32_t total_threads_allocated;
    _Atomic uint32_t total_operations_active;

    // Performance isolation
    bool performance_isolation_enabled;
    uint32_t core_function_priority_boost;
    uint32_t recon_module_priority_limit;

    // Emergency controls
    bool emergency_halt_enabled;
    double performance_degradation_threshold;
    uint32_t consecutive_failures_threshold;
    time_t last_emergency_halt;

    // Real-time monitoring
    _Atomic uint64_t core_operations_completed;
    _Atomic uint64_t recon_operations_completed;
    _Atomic double core_average_response_time;
    _Atomic double recon_average_response_time;

    // Integration state
    integration_status_t overall_status;
    time_t integration_start_time;
    bool hot_reload_supported;
    pthread_t integration_monitor_thread;
    bool monitor_thread_running;
} integration_manager_t;

// Performance impact metrics
typedef struct {
    double baseline_performance;
    double current_performance;
    double performance_impact_percent;
    uint32_t core_function_slowdown_ms;
    uint32_t memory_overhead_mb;
    uint32_t thread_overhead_count;
    bool impact_acceptable;
} performance_impact_metrics_t;

// Function prototypes

// Integration manager lifecycle
int integration_manager_init(integration_manager_t *manager, const char *config_file);
int integration_manager_start(integration_manager_t *manager);
int integration_manager_stop(integration_manager_t *manager);
void integration_manager_cleanup(integration_manager_t *manager);

// Subsystem integration
int integration_manager_enable_subsystem(integration_manager_t *manager, integration_subsystem_t subsystem);
int integration_manager_disable_subsystem(integration_manager_t *manager, integration_subsystem_t subsystem);
integration_status_t integration_manager_get_subsystem_status(const integration_manager_t *manager, integration_subsystem_t subsystem);

// DNS Enhanced integration
int integrate_dns_enhanced_system(integration_manager_t *manager, struct dns_resolver_chain *chain);
int recon_dns_enhanced_query(integration_manager_t *manager, const char *domain, dns_record_type_t type, struct enhanced_dns_result *result);
int share_dns_resolver_chain(integration_manager_t *manager, recon_module_t *module);

// Thread pool integration
int integrate_thread_pool(integration_manager_t *manager, pthread_t *threads, uint32_t count);
int allocate_threads_for_module(integration_manager_t *manager, recon_module_t *module, uint32_t requested_threads);
int release_threads_from_module(integration_manager_t *manager, recon_module_t *module, uint32_t thread_count);
uint32_t get_available_thread_count(const integration_manager_t *manager);

// Memory pool integration
int integrate_memory_pools(integration_manager_t *manager, void **pools, uint32_t pool_count);
void *allocate_recon_memory(integration_manager_t *manager, size_t size, const char *module_name);
int release_recon_memory(integration_manager_t *manager, void *ptr, const char *module_name);
size_t get_available_memory(const integration_manager_t *manager);

// OPSEC framework integration
int integrate_opsec_framework(integration_manager_t *manager, opsec_context_t *opsec_ctx);
int apply_opsec_to_module(integration_manager_t *manager, recon_module_t *module);
int synchronize_opsec_state(integration_manager_t *manager);

// Configuration integration
int integrate_configuration_system(integration_manager_t *manager, const char *config_file);
int propagate_config_changes(integration_manager_t *manager);
int hot_reload_configuration(integration_manager_t *manager);
int validate_integration_config(const integration_manager_t *manager);

// Performance monitoring and impact assessment
int measure_performance_impact(integration_manager_t *manager, performance_impact_metrics_t *metrics);
int monitor_core_function_performance(integration_manager_t *manager);
bool is_performance_impact_acceptable(const integration_manager_t *manager);
int apply_performance_isolation(integration_manager_t *manager);

// Resource allocation and management
int allocate_resources_for_module(integration_manager_t *manager, recon_module_t *module, const recon_module_config_t *config);
int release_resources_from_module(integration_manager_t *manager, recon_module_t *module);
int adjust_resource_allocation(integration_manager_t *manager, resource_allocation_strategy_t strategy);
int enforce_resource_limits(integration_manager_t *manager);

// Event system integration
int integrate_event_system(integration_manager_t *manager);
int register_module_events(integration_manager_t *manager, recon_module_t *module);
int handle_integration_events(integration_manager_t *manager);
void *integration_event_loop(void *arg);

// Emergency controls and circuit breakers
int trigger_emergency_halt(integration_manager_t *manager, const char *reason);
int recover_from_emergency_halt(integration_manager_t *manager);
bool should_trigger_circuit_breaker(const integration_manager_t *manager);
int activate_performance_protection(integration_manager_t *manager);

// Module coordination
int coordinate_module_startup(integration_manager_t *manager, recon_module_t *module);
int coordinate_module_shutdown(integration_manager_t *manager, recon_module_t *module);
int balance_module_loads(integration_manager_t *manager);
int optimize_module_placement(integration_manager_t *manager);

// Result aggregation and correlation
int integrate_result_aggregation(integration_manager_t *manager);
int correlate_results_with_core_data(integration_manager_t *manager, recon_result_t *results, uint32_t count);
int merge_results_with_dns_data(integration_manager_t *manager, recon_result_t *recon_results, struct enhanced_dns_result *dns_results);

// Monitoring and diagnostics
void *integration_monitor_thread_func(void *arg);
int generate_integration_report(const integration_manager_t *manager, char **report, size_t *report_size);
int export_performance_metrics(const integration_manager_t *manager, const char *filename);
int diagnose_integration_issues(const integration_manager_t *manager);

// Utility functions
const char *integration_status_to_string(integration_status_t status);
const char *integration_subsystem_to_string(integration_subsystem_t subsystem);
const char *resource_strategy_to_string(resource_allocation_strategy_t strategy);
int print_integration_status(const integration_manager_t *manager);
int validate_integration_health(const integration_manager_t *manager);

// Configuration helpers
int load_integration_config(const char *config_file, integration_manager_t *manager);
int save_integration_config(const integration_manager_t *manager, const char *config_file);
int apply_default_integration_settings(integration_manager_t *manager);

// Global integration manager instance
extern integration_manager_t global_integration_manager;

// Integration macros for performance
#define RECON_INTEGRATION_GUARD(manager) \
    do { \
        if ((manager)->overall_status != INTEGRATION_STATUS_ACTIVE) { \
            return -1; \
        } \
    } while(0)

#define RECON_PERFORMANCE_CHECK(manager) \
    do { \
        if (!is_performance_impact_acceptable(manager)) { \
            trigger_emergency_halt(manager, "Performance impact exceeded threshold"); \
            return -1; \
        } \
    } while(0)

#endif // RECON_INTEGRATION_MANAGER_H