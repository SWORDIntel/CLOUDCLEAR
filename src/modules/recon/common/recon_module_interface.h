/*
 * CloudUnflare Enhanced - Unified Reconnaissance Module Interface
 *
 * Universal API for all reconnaissance modules providing seamless integration
 * with CloudUnflare Enhanced v2.0's 50-thread architecture and OPSEC framework
 *
 * Agent: ARCHITECT (primary design)
 * Coordination: C-INTERNAL, SECURITY, OPTIMIZER
 * Performance Target: 10,000+ queries/second aggregate
 */

#ifndef RECON_MODULE_INTERFACE_H
#define RECON_MODULE_INTERFACE_H

#include "recon_common.h"
#include "recon_opsec.h"
#include "../dns_enhanced.h"
#include "platform_compat.h"

// Module identification and versioning
#define RECON_MODULE_API_VERSION "1.0"
#define RECON_MODULE_MAX_NAME_LEN 64
#define RECON_MODULE_MAX_DESC_LEN 256

// Module capabilities flags
typedef enum {
    MODULE_CAP_PASSIVE_SCAN      = 1 << 0,  // Passive reconnaissance only
    MODULE_CAP_ACTIVE_SCAN       = 1 << 1,  // Active target interaction
    MODULE_CAP_THREADED          = 1 << 2,  // Multi-threading support
    MODULE_CAP_OPSEC_COMPLIANT   = 1 << 3,  // Full OPSEC framework integration
    MODULE_CAP_REAL_TIME         = 1 << 4,  // Real-time processing capability
    MODULE_CAP_BULK_PROCESSING   = 1 << 5,  // Batch processing support
    MODULE_CAP_ADAPTIVE_TIMING   = 1 << 6,  // Adaptive delay support
    MODULE_CAP_PROXY_AWARE       = 1 << 7,  // Proxy chain support
    MODULE_CAP_RATE_LIMITED      = 1 << 8,  // Built-in rate limiting
    MODULE_CAP_DNS_INTEGRATION   = 1 << 9,  // DNS Enhanced integration
    MODULE_CAP_RESULT_CORRELATION = 1 << 10 // Cross-module result correlation
} module_capability_flags_t;

// Module execution states
typedef enum {
    MODULE_STATE_UNINITIALIZED,
    MODULE_STATE_INITIALIZING,
    MODULE_STATE_READY,
    MODULE_STATE_RUNNING,
    MODULE_STATE_PAUSED,
    MODULE_STATE_STOPPING,
    MODULE_STATE_STOPPED,
    MODULE_STATE_ERROR,
    MODULE_STATE_EMERGENCY_HALT
} module_state_t;

// Module priority levels for resource allocation
typedef enum {
    MODULE_PRIORITY_LOW = 1,
    MODULE_PRIORITY_NORMAL = 5,
    MODULE_PRIORITY_HIGH = 10,
    MODULE_PRIORITY_CRITICAL = 20
} module_priority_t;

// Universal module configuration
typedef struct {
    // Module identification
    char name[RECON_MODULE_MAX_NAME_LEN];
    char description[RECON_MODULE_MAX_DESC_LEN];
    char version[16];
    uint32_t capabilities;
    module_priority_t priority;

    // Performance configuration
    uint32_t max_threads;
    uint32_t max_concurrent_operations;
    uint32_t timeout_seconds;
    uint32_t max_retries;
    uint32_t memory_limit_mb;

    // OPSEC integration
    opsec_paranoia_level_t opsec_level;
    bool opsec_enabled;
    uint32_t min_delay_ms;
    uint32_t max_delay_ms;

    // Rate limiting
    uint32_t max_requests_per_second;
    uint32_t burst_limit;
    uint32_t rate_limit_window_seconds;

    // Integration settings
    bool dns_enhanced_integration;
    bool proxy_chain_enabled;
    bool result_correlation_enabled;
    bool real_time_processing;
} recon_module_config_t;

// Module performance metrics (thread-safe)
typedef struct {
    _Atomic uint64_t operations_started;
    _Atomic uint64_t operations_completed;
    _Atomic uint64_t operations_failed;
    _Atomic uint64_t total_response_time_ms;
    _Atomic uint64_t bytes_processed;
    _Atomic uint32_t active_threads;
    _Atomic uint32_t peak_threads;
    _Atomic double success_rate;
    _Atomic time_t last_operation_time;
    pthread_mutex_t metrics_mutex;
} module_performance_metrics_t;

// Module resource usage tracking
typedef struct {
    _Atomic uint64_t memory_allocated;
    _Atomic uint64_t memory_peak;
    _Atomic uint32_t open_sockets;
    _Atomic uint32_t dns_queries;
    _Atomic uint32_t http_requests;
    _Atomic uint32_t proxy_connections;
    _Atomic double cpu_usage_percent;
} module_resource_usage_t;

// Module operation context
typedef struct {
    uint64_t operation_id;
    recon_target_t target;
    void *module_specific_data;
    opsec_context_t *opsec_ctx;
    struct dns_resolver_chain *dns_chain;
    struct timespec start_time;
    uint32_t retry_count;
    bool high_priority;
    void (*completion_callback)(struct recon_module_operation *, recon_result_t *);
} recon_module_operation_t;

// Module instance structure
typedef struct recon_module {
    // Module identification and configuration
    recon_module_config_t config;
    module_state_t state;
    pthread_mutex_t state_mutex;

    // Performance and resource tracking
    module_performance_metrics_t metrics;
    module_resource_usage_t resources;

    // Threading and synchronization
    pthread_t *worker_threads;
    uint32_t thread_count;
    pthread_mutex_t thread_pool_mutex;
    pthread_cond_t work_available;
    bool shutdown_requested;

    // Operation queue
    recon_module_operation_t **operation_queue;
    uint32_t queue_size;
    _Atomic uint32_t queue_head;
    _Atomic uint32_t queue_tail;
    _Atomic uint32_t queue_count;
    pthread_mutex_t queue_mutex;

    // Module-specific function pointers
    int (*init)(struct recon_module *module);
    int (*execute_operation)(struct recon_module *module, recon_module_operation_t *operation, recon_result_t *result);
    int (*pause)(struct recon_module *module);
    int (*resume)(struct recon_module *module);
    int (*stop)(struct recon_module *module);
    void (*cleanup)(struct recon_module *module);
    int (*configure)(struct recon_module *module, const recon_module_config_t *config);
    int (*health_check)(struct recon_module *module);

    // Integration callbacks
    void (*on_result_ready)(struct recon_module *module, recon_result_t *result);
    void (*on_error)(struct recon_module *module, const char *error_message);
    void (*on_state_change)(struct recon_module *module, module_state_t old_state, module_state_t new_state);

    // Module-specific private data
    void *private_data;
    size_t private_data_size;
} recon_module_t;

// Module registry for centralized management
typedef struct {
    recon_module_t **modules;
    uint32_t module_count;
    uint32_t max_modules;
    pthread_mutex_t registry_mutex;

    // Global configuration
    recon_module_config_t default_config;
    opsec_context_t *global_opsec_ctx;
    struct dns_resolver_chain *global_dns_chain;

    // Global performance tracking
    _Atomic uint64_t total_operations;
    _Atomic uint64_t total_results;
    _Atomic uint32_t active_modules;
    time_t start_time;
} module_registry_t;

// Function prototypes for module interface

// Module lifecycle management
int recon_module_create(recon_module_t **module, const char *name, uint32_t capabilities);
int recon_module_init(recon_module_t *module, const recon_module_config_t *config);
int recon_module_start(recon_module_t *module);
int recon_module_pause(recon_module_t *module);
int recon_module_resume(recon_module_t *module);
int recon_module_stop(recon_module_t *module);
int recon_module_destroy(recon_module_t *module);

// Module state management
module_state_t recon_module_get_state(const recon_module_t *module);
int recon_module_set_state(recon_module_t *module, module_state_t new_state);
bool recon_module_is_operational(const recon_module_t *module);
int recon_module_health_check(recon_module_t *module);

// Operation queue management
int recon_module_queue_operation(recon_module_t *module, const recon_module_operation_t *operation);
int recon_module_dequeue_operation(recon_module_t *module, recon_module_operation_t **operation);
uint32_t recon_module_get_queue_size(const recon_module_t *module);
int recon_module_clear_queue(recon_module_t *module);

// Configuration management
int recon_module_configure(recon_module_t *module, const recon_module_config_t *config);
int recon_module_get_config(const recon_module_t *module, recon_module_config_t *config);
int recon_module_update_opsec_level(recon_module_t *module, opsec_paranoia_level_t level);

// Performance monitoring
int recon_module_get_metrics(const recon_module_t *module, module_performance_metrics_t *metrics);
int recon_module_get_resource_usage(const recon_module_t *module, module_resource_usage_t *usage);
double recon_module_get_success_rate(const recon_module_t *module);
uint32_t recon_module_get_average_response_time(const recon_module_t *module);

// Thread pool management
int recon_module_resize_thread_pool(recon_module_t *module, uint32_t new_size);
void *recon_module_worker_thread(void *arg);
int recon_module_distribute_work(recon_module_t *module);

// Registry management
int module_registry_init(module_registry_t *registry, uint32_t max_modules);
int module_registry_register(module_registry_t *registry, recon_module_t *module);
int module_registry_unregister(module_registry_t *registry, const char *module_name);
recon_module_t *module_registry_find(const module_registry_t *registry, const char *module_name);
int module_registry_start_all(module_registry_t *registry);
int module_registry_stop_all(module_registry_t *registry);
void module_registry_cleanup(module_registry_t *registry);

// Integration utilities
int recon_module_integrate_dns_enhanced(recon_module_t *module, struct dns_resolver_chain *chain);
int recon_module_integrate_opsec(recon_module_t *module, opsec_context_t *opsec_ctx);
int recon_module_setup_proxy_chain(recon_module_t *module, proxy_node_t *proxies, uint32_t count);

// Result correlation and aggregation
int recon_results_correlate(recon_result_t *results, uint32_t count, recon_result_t **correlated, uint32_t *correlated_count);
int recon_results_aggregate(const recon_result_t *results, uint32_t count, char **summary, size_t *summary_size);
int recon_results_export(const recon_result_t *results, uint32_t count, const char *format, const char *filename);

// Utility functions
const char *module_state_to_string(module_state_t state);
const char *module_capability_to_string(module_capability_flags_t cap);
bool module_has_capability(const recon_module_t *module, module_capability_flags_t cap);
int recon_module_print_status(const recon_module_t *module);
int recon_module_print_performance(const recon_module_t *module);

// Default configurations
extern recon_module_config_t recon_module_default_config;
extern module_registry_t global_module_registry;

// Thread-local module context
extern _Thread_local recon_module_t *current_module;
extern _Thread_local recon_module_operation_t *current_operation;

#endif // RECON_MODULE_INTERFACE_H