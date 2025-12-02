/*
 * CloudUnflare Enhanced v2.0 - Performance Integration Header
 *
 * Unified interface for all performance optimization modules
 * Designed for seamless integration with existing CloudUnflare codebase
 *
 * Performance Architecture:
 * - Thread Pool: Intel Meteor Lake P-core/E-core optimization
 * - Memory Pool: <500MB with cache-aligned allocation
 * - SIMD Utils: AVX2 vectorization for 4-8x speedup
 * - Lock-Free: Zero-contention data structures
 * - CPU Affinity: Hybrid architecture scheduling
 * - Performance Monitor: Real-time metrics and thermal management
 *
 * Agent: OPTIMIZER (integration architecture)
 * Coordination: C-INTERNAL, ARCHITECT, SECURITY
 */

#ifndef PERFORMANCE_INTEGRATION_H
#define PERFORMANCE_INTEGRATION_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "platform_compat.h"
#include "../config.h"

#ifdef __cplusplus
extern "C" {
#endif

// Performance module feature flags
#define PERF_FEATURE_THREAD_POOL    (1 << 0)
#define PERF_FEATURE_MEMORY_POOL    (1 << 1)
#define PERF_FEATURE_SIMD_UTILS     (1 << 2)
#define PERF_FEATURE_LOCKFREE       (1 << 3)
#define PERF_FEATURE_CPU_AFFINITY   (1 << 4)
#define PERF_FEATURE_MONITORING     (1 << 5)

#define PERF_FEATURE_ALL            0x3F

// Performance initialization configuration
typedef struct {
    uint32_t enabled_features;          // Bitmask of PERF_FEATURE_* flags
    uint32_t max_threads;              // Thread pool size (default: 50)
    size_t memory_pool_size_mb;        // Memory pool size (default: 400MB)
    bool enable_numa_awareness;        // NUMA-aware allocation
    bool enable_huge_pages;            // Use huge pages for memory pool
    bool enable_work_stealing;         // Work stealing in thread pool
    bool enable_thermal_monitoring;    // Thermal throttling protection
    bool enable_adaptive_scaling;      // Adaptive performance scaling
} performance_config_t;

// Performance statistics structure
typedef struct {
    // Thread pool statistics
    uint64_t threads_created;
    uint64_t tasks_submitted;
    uint64_t tasks_completed;
    uint64_t p_core_utilization_ns;
    uint64_t e_core_utilization_ns;

    // Memory pool statistics
    uint64_t memory_allocated_mb;
    uint64_t memory_peak_mb;
    uint64_t fast_path_allocations;
    uint64_t cache_hit_rate_percent;

    // SIMD statistics
    bool simd_avx2_available;
    bool simd_fma_available;
    uint64_t simd_operations_performed;

    // Lock-free statistics
    uint64_t lockfree_operations;
    uint64_t cas_failures;

    // CPU affinity statistics
    uint64_t thread_migrations;
    uint64_t p_core_assignments;
    uint64_t e_core_assignments;

    // Performance monitoring
    float current_cpu_utilization;
    float current_memory_utilization;
    float peak_temperature_celsius;
    bool thermal_throttling_active;
} performance_stats_t;

// =============================================================================
// UNIFIED PERFORMANCE SYSTEM API
// =============================================================================

/**
 * Initialize the complete performance optimization system
 *
 * @param config Performance configuration (NULL for defaults)
 * @return 0 on success, -1 on failure
 */
int performance_system_init(const performance_config_t *config);

/**
 * Get performance system statistics
 *
 * @param stats Pointer to statistics structure to fill
 */
void performance_system_get_stats(performance_stats_t *stats);

/**
 * Print comprehensive performance report
 */
void performance_system_print_report(void);

/**
 * Shutdown performance system and clean up resources
 */
void performance_system_shutdown(void);

/**
 * Check if specific performance feature is available
 *
 * @param feature Feature flag to check
 * @return true if available, false otherwise
 */
bool performance_system_has_feature(uint32_t feature);

// =============================================================================
// THREAD POOL OPTIMIZATION API
// =============================================================================

// Core types for thread assignment
typedef enum {
    CORE_TYPE_UNKNOWN = 0,
    CORE_TYPE_P_CORE = 1,    // Performance cores
    CORE_TYPE_E_CORE = 2     // Efficiency cores
} core_type_t;

// Task priority levels
typedef enum {
    TASK_PRIORITY_LOW = 0,
    TASK_PRIORITY_NORMAL = 1,
    TASK_PRIORITY_HIGH = 2,
    TASK_PRIORITY_CRITICAL = 3
} task_priority_t;

/**
 * Submit task to optimized thread pool
 *
 * @param function Task function to execute
 * @param argument Argument to pass to function
 * @param priority Task priority level
 * @param preferred_core Preferred core type (P-core/E-core)
 * @return 0 on success, -1 on failure
 */
int optimized_thread_pool_submit(void (*function)(void*), void *argument,
                                task_priority_t priority, core_type_t preferred_core);

/**
 * Wait for all submitted tasks to complete
 */
void optimized_thread_pool_wait_all(void);

/**
 * Get thread pool performance statistics
 */
void optimized_thread_pool_get_stats(void);

// Convenience functions for common task types
int submit_compute_task(void (*function)(void*), void *argument);
int submit_io_task(void (*function)(void*), void *argument);
int submit_high_priority_task(void (*function)(void*), void *argument);

// =============================================================================
// MEMORY POOL OPTIMIZATION API
// =============================================================================

/**
 * Optimized memory allocation with cache alignment
 *
 * @param size Size in bytes to allocate
 * @return Pointer to allocated memory, NULL on failure
 */
void* optimized_malloc(size_t size);

/**
 * Cache-aligned memory allocation
 *
 * @param size Size in bytes to allocate
 * @param alignment Alignment requirement (default: 64 bytes)
 * @return Pointer to aligned memory, NULL on failure
 */
void* optimized_aligned_malloc(size_t size, size_t alignment);

/**
 * Free memory allocated by optimized allocators
 *
 * @param ptr Pointer to memory to free
 */
void optimized_free(void *ptr);

/**
 * Get memory pool performance statistics
 */
void optimized_memory_pool_get_stats(void);

// =============================================================================
// SIMD OPTIMIZATION API
// =============================================================================

/**
 * Initialize SIMD capabilities detection
 *
 * @return true if AVX2 is available, false otherwise
 */
bool simd_init(void);

/**
 * Optimized string length calculation using SIMD
 *
 * @param str String to measure
 * @return Length of string
 */
size_t simd_strlen(const char *str);

/**
 * Optimized string comparison using SIMD
 *
 * @param str1 First string
 * @param str2 Second string
 * @return Comparison result (like strcmp)
 */
int simd_strcmp(const char *str1, const char *str2);

/**
 * Optimized case-insensitive string comparison using SIMD
 *
 * @param str1 First string
 * @param str2 Second string
 * @return Comparison result (like strcasecmp)
 */
int simd_strcasecmp(const char *str1, const char *str2);

/**
 * Optimized memory comparison using SIMD
 *
 * @param ptr1 First memory region
 * @param ptr2 Second memory region
 * @param size Size to compare
 * @return Comparison result (like memcmp)
 */
int simd_memcmp(const void *ptr1, const void *ptr2, size_t size);

/**
 * Optimized hash function using SIMD
 *
 * @param data Data to hash
 * @param size Size of data
 * @param seed Hash seed
 * @return 64-bit hash value
 */
uint64_t simd_hash64(const void *data, size_t size, uint64_t seed);

/**
 * Optimized DNS domain name normalization (lowercase)
 *
 * @param domain Domain name to normalize (modified in-place)
 * @param length Length of domain name
 */
void simd_normalize_domain(char *domain, size_t length);

/**
 * Optimized DNS label validation using SIMD
 *
 * @param label DNS label to validate
 * @param length Length of label
 * @return true if valid, false otherwise
 */
bool simd_validate_dns_label(const char *label, size_t length);

/**
 * Get SIMD performance statistics
 */
void simd_get_performance_stats(void);

// =============================================================================
// LOCK-FREE DATA STRUCTURES API
// =============================================================================

// Opaque lock-free queue structure
typedef struct lockfree_queue lockfree_queue_t;

// Opaque lock-free stack structure
typedef struct lockfree_stack lockfree_stack_t;

/**
 * Create lock-free queue
 *
 * @return Pointer to queue, NULL on failure
 */
lockfree_queue_t* lockfree_queue_create(void);

/**
 * Enqueue item to lock-free queue
 *
 * @param queue Queue instance
 * @param data Data to enqueue
 * @return true on success, false on failure
 */
bool lockfree_queue_enqueue(lockfree_queue_t *queue, void *data);

/**
 * Dequeue item from lock-free queue
 *
 * @param queue Queue instance
 * @return Dequeued data, NULL if empty
 */
void* lockfree_queue_dequeue(lockfree_queue_t *queue);

/**
 * Get approximate queue size
 *
 * @param queue Queue instance
 * @return Approximate number of items
 */
uint64_t lockfree_queue_size(lockfree_queue_t *queue);

/**
 * Destroy lock-free queue
 *
 * @param queue Queue instance
 */
void lockfree_queue_destroy(lockfree_queue_t *queue);

/**
 * Create lock-free stack
 *
 * @return Pointer to stack, NULL on failure
 */
lockfree_stack_t* lockfree_stack_create(void);

/**
 * Push item to lock-free stack
 *
 * @param stack Stack instance
 * @param data Data to push
 * @return true on success, false on failure
 */
bool lockfree_stack_push(lockfree_stack_t *stack, void *data);

/**
 * Pop item from lock-free stack
 *
 * @param stack Stack instance
 * @return Popped data, NULL if empty
 */
void* lockfree_stack_pop(lockfree_stack_t *stack);

/**
 * Destroy lock-free stack
 *
 * @param stack Stack instance
 */
void lockfree_stack_destroy(lockfree_stack_t *stack);

/**
 * Get lock-free data structure performance statistics
 */
void lockfree_get_performance_stats(void);

// =============================================================================
// CPU AFFINITY OPTIMIZATION API
// =============================================================================

// Workload types for optimal core assignment
typedef enum {
    WORKLOAD_TYPE_UNKNOWN = 0,
    WORKLOAD_TYPE_COMPUTE_INTENSIVE = 1,  // CPU-bound, benefits from P-cores
    WORKLOAD_TYPE_IO_BOUND = 2,           // I/O-bound, suitable for E-cores
    WORKLOAD_TYPE_MEMORY_BOUND = 3,       // Memory-bound, mixed allocation
    WORKLOAD_TYPE_NETWORK_BOUND = 4       // Network I/O, E-cores preferred
} workload_type_t;

/**
 * Initialize CPU affinity management system
 *
 * @return 0 on success, -1 on failure
 */
int cpu_affinity_init(void);

/**
 * Set thread affinity to specific core
 *
 * @param thread Thread to set affinity for
 * @param core_id CPU core ID (0-19 for Meteor Lake)
 * @return 0 on success, -1 on failure
 */
int cpu_affinity_set_thread_core(pthread_t thread, int core_id);

/**
 * Set thread affinity based on workload type
 *
 * @param thread Thread to set affinity for
 * @param workload_type Type of workload
 * @return 0 on success, -1 on failure
 */
int cpu_affinity_set_workload_optimal(pthread_t thread, workload_type_t workload_type);

/**
 * Set thread for compute-intensive workload (P-cores preferred)
 *
 * @param thread Thread to set affinity for
 * @return 0 on success, -1 on failure
 */
int cpu_affinity_set_compute_intensive(pthread_t thread);

/**
 * Set thread for I/O-bound workload (E-cores preferred)
 *
 * @param thread Thread to set affinity for
 * @return 0 on success, -1 on failure
 */
int cpu_affinity_set_io_bound(pthread_t thread);

/**
 * Set thread for network-bound workload (E-cores preferred)
 *
 * @param thread Thread to set affinity for
 * @return 0 on success, -1 on failure
 */
int cpu_affinity_set_network_bound(pthread_t thread);

/**
 * Get CPU affinity performance statistics
 */
void cpu_affinity_get_stats(void);

/**
 * Shutdown CPU affinity management
 */
void cpu_affinity_shutdown(void);

// =============================================================================
// PERFORMANCE MONITORING API
// =============================================================================

// System resource usage structure
typedef struct {
    float cpu_utilization_percent;
    float memory_utilization_percent;
    uint64_t network_rx_bytes_per_sec;
    uint64_t network_tx_bytes_per_sec;
    uint64_t dns_queries_per_sec;
    uint64_t http_requests_per_sec;
    uint64_t reconnaissance_ops_per_sec;
    float average_response_time_ms;
    uint64_t timestamp_ns;
} system_resource_usage_t;

/**
 * Initialize performance monitoring system
 *
 * @return 0 on success, -1 on failure
 */
int performance_monitor_init(void);

/**
 * Get current system resource usage
 *
 * @return Current resource usage statistics
 */
system_resource_usage_t performance_monitor_get_current_usage(void);

/**
 * Check if system is thermal throttling
 *
 * @return true if throttling, false otherwise
 */
bool performance_monitor_is_thermal_throttling(void);

/**
 * Update DNS queries per second metric
 *
 * @param queries_per_sec Current DNS query rate
 */
void performance_monitor_update_dns_queries(uint64_t queries_per_sec);

/**
 * Update HTTP requests per second metric
 *
 * @param requests_per_sec Current HTTP request rate
 */
void performance_monitor_update_http_requests(uint64_t requests_per_sec);

/**
 * Update reconnaissance operations per second metric
 *
 * @param ops_per_sec Current reconnaissance operation rate
 */
void performance_monitor_update_recon_ops(uint64_t ops_per_sec);

/**
 * Update average response time metric
 *
 * @param avg_response_time_ms Average response time in milliseconds
 */
void performance_monitor_update_response_time(float avg_response_time_ms);

/**
 * Get performance monitoring statistics
 */
void performance_monitor_get_stats(void);

/**
 * Shutdown performance monitoring system
 */
void performance_monitor_shutdown(void);

// =============================================================================
// INTEGRATION HELPERS AND MACROS
// =============================================================================

/**
 * Macro for easy task submission with automatic core type selection
 */
#define SUBMIT_TASK_AUTO(func, arg, workload) \
    do { \
        core_type_t core = (workload == WORKLOAD_TYPE_COMPUTE_INTENSIVE) ? \
                          CORE_TYPE_P_CORE : CORE_TYPE_E_CORE; \
        optimized_thread_pool_submit(func, arg, TASK_PRIORITY_NORMAL, core); \
    } while(0)

/**
 * Macro for high-priority compute task submission
 */
#define SUBMIT_COMPUTE_TASK_HIGH(func, arg) \
    optimized_thread_pool_submit(func, arg, TASK_PRIORITY_HIGH, CORE_TYPE_P_CORE)

/**
 * Macro for I/O task submission
 */
#define SUBMIT_IO_TASK(func, arg) \
    optimized_thread_pool_submit(func, arg, TASK_PRIORITY_NORMAL, CORE_TYPE_E_CORE)

/**
 * Optimized string operations with SIMD fallback
 */
#define OPTIMIZED_STRLEN(str) simd_strlen(str)
#define OPTIMIZED_STRCMP(s1, s2) simd_strcmp(s1, s2)
#define OPTIMIZED_STRCASECMP(s1, s2) simd_strcasecmp(s1, s2)
#define OPTIMIZED_MEMCMP(p1, p2, size) simd_memcmp(p1, p2, size)

/**
 * Optimized memory operations
 */
#define OPTIMIZED_MALLOC(size) optimized_malloc(size)
#define OPTIMIZED_ALIGNED_MALLOC(size) optimized_aligned_malloc(size, 64)
#define OPTIMIZED_FREE(ptr) optimized_free(ptr)

/**
 * Performance monitoring updates
 */
#define UPDATE_DNS_METRICS(qps) performance_monitor_update_dns_queries(qps)
#define UPDATE_HTTP_METRICS(rps) performance_monitor_update_http_requests(rps)
#define UPDATE_RECON_METRICS(ops) performance_monitor_update_recon_ops(ops)
#define UPDATE_RESPONSE_TIME(ms) performance_monitor_update_response_time(ms)

// =============================================================================
// DEFAULT CONFIGURATION
// =============================================================================

/**
 * Get default performance configuration for CloudUnflare Enhanced v2.0
 *
 * @return Default configuration structure
 */
static inline performance_config_t performance_get_default_config(void) {
    performance_config_t config = {
        .enabled_features = PERF_FEATURE_ALL,
        .max_threads = 50,
        .memory_pool_size_mb = 400,
        .enable_numa_awareness = true,
        .enable_huge_pages = true,
        .enable_work_stealing = true,
        .enable_thermal_monitoring = true,
        .enable_adaptive_scaling = true
    };
    return config;
}

#ifdef __cplusplus
}
#endif

#endif // PERFORMANCE_INTEGRATION_H