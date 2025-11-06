/*
 * CloudUnflare Enhanced v2.0 - Performance Integration Implementation
 *
 * Unified performance system implementation
 * Coordinates all performance optimization modules
 *
 * Agent: OPTIMIZER (final integration)
 * Coordination: C-INTERNAL, ARCHITECT, SECURITY
 */

#include "performance_integration.h"
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>

// Global performance system state
static struct {
    bool initialized;
    performance_config_t config;
    uint32_t active_features;
    uint64_t initialization_time_ns;
} g_performance_system = {0};

// Forward declarations for external module functions
extern int optimized_thread_pool_init(int num_threads, bool enable_work_stealing, bool enable_numa);
extern void optimized_thread_pool_shutdown(void);
extern int optimized_memory_pool_init(size_t total_size, bool enable_numa, bool enable_huge_pages);
extern void optimized_memory_pool_shutdown(void);

// High-precision timing
static uint64_t get_monotonic_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// Initialize the complete performance optimization system
int performance_system_init(const performance_config_t *config) {
    if (g_performance_system.initialized) {
        printf("[OPTIMIZER] Performance system already initialized\n");
        return 0;
    }

    uint64_t start_time = get_monotonic_time_ns();

    // Use provided config or defaults
    if (config) {
        g_performance_system.config = *config;
    } else {
        g_performance_system.config = performance_get_default_config();
    }

    uint32_t features = g_performance_system.config.enabled_features;
    g_performance_system.active_features = 0;

    printf("[OPTIMIZER] Initializing CloudUnflare Enhanced v2.0 Performance System\n");
    printf("[OPTIMIZER] Target: 10,000+ queries/second, <500MB memory, Intel Meteor Lake optimized\n");

    // Initialize SIMD utilities first (required by other modules)
    if (features & PERF_FEATURE_SIMD_UTILS) {
        if (simd_init()) {
            g_performance_system.active_features |= PERF_FEATURE_SIMD_UTILS;
            printf("[OPTIMIZER] ✓ SIMD optimization enabled (AVX2)\n");
        } else {
            printf("[OPTIMIZER] ✗ SIMD optimization unavailable (no AVX2)\n");
        }
    }

    // Initialize CPU affinity management
    if (features & PERF_FEATURE_CPU_AFFINITY) {
        if (cpu_affinity_init() == 0) {
            g_performance_system.active_features |= PERF_FEATURE_CPU_AFFINITY;
            printf("[OPTIMIZER] ✓ CPU affinity management enabled (P-core/E-core)\n");
        } else {
            printf("[OPTIMIZER] ✗ CPU affinity management failed\n");
        }
    }

    // Initialize memory pool
    if (features & PERF_FEATURE_MEMORY_POOL) {
        size_t pool_size = g_performance_system.config.memory_pool_size_mb * 1024 * 1024;
        if (optimized_memory_pool_init(pool_size,
                                      g_performance_system.config.enable_numa_awareness,
                                      g_performance_system.config.enable_huge_pages) == 0) {
            g_performance_system.active_features |= PERF_FEATURE_MEMORY_POOL;
            printf("[OPTIMIZER] ✓ Memory pool enabled (%zu MB)\n",
                   g_performance_system.config.memory_pool_size_mb);
        } else {
            printf("[OPTIMIZER] ✗ Memory pool initialization failed\n");
        }
    }

    // Initialize thread pool
    if (features & PERF_FEATURE_THREAD_POOL) {
        if (optimized_thread_pool_init(g_performance_system.config.max_threads,
                                      g_performance_system.config.enable_work_stealing,
                                      g_performance_system.config.enable_numa_awareness) == 0) {
            g_performance_system.active_features |= PERF_FEATURE_THREAD_POOL;
            printf("[OPTIMIZER] ✓ Thread pool enabled (%u threads)\n",
                   g_performance_system.config.max_threads);
        } else {
            printf("[OPTIMIZER] ✗ Thread pool initialization failed\n");
        }
    }

    // Initialize lock-free data structures
    if (features & PERF_FEATURE_LOCKFREE) {
        // Initialize hazard pointer system (from lockfree_queue.c)
        extern bool lockfree_hazard_init(void);
        if (lockfree_hazard_init()) {
            g_performance_system.active_features |= PERF_FEATURE_LOCKFREE;
            printf("[OPTIMIZER] ✓ Lock-free data structures enabled\n");
        } else {
            printf("[OPTIMIZER] ✗ Lock-free initialization failed\n");
        }
    }

    // Initialize performance monitoring
    if (features & PERF_FEATURE_MONITORING) {
        if (performance_monitor_init() == 0) {
            g_performance_system.active_features |= PERF_FEATURE_MONITORING;
            printf("[OPTIMIZER] ✓ Performance monitoring enabled\n");
        } else {
            printf("[OPTIMIZER] ✗ Performance monitoring failed\n");
        }
    }

    g_performance_system.initialization_time_ns = get_monotonic_time_ns() - start_time;
    g_performance_system.initialized = true;

    printf("[OPTIMIZER] Performance system initialized in %.2f ms\n",
           g_performance_system.initialization_time_ns / 1000000.0);
    printf("[OPTIMIZER] Active features: 0x%02X (requested: 0x%02X)\n",
           g_performance_system.active_features, features);

    return 0;
}

// Get performance system statistics
void performance_system_get_stats(performance_stats_t *stats) {
    if (!stats || !g_performance_system.initialized) {
        return;
    }

    memset(stats, 0, sizeof(performance_stats_t));

    // Thread pool statistics
    if (g_performance_system.active_features & PERF_FEATURE_THREAD_POOL) {
        // These would be retrieved from the actual thread pool implementation
        stats->threads_created = g_performance_system.config.max_threads;
        // Additional stats would be filled by actual implementation
    }

    // Memory pool statistics
    if (g_performance_system.active_features & PERF_FEATURE_MEMORY_POOL) {
        stats->memory_allocated_mb = g_performance_system.config.memory_pool_size_mb;
        // Additional stats would be filled by actual implementation
    }

    // SIMD statistics
    if (g_performance_system.active_features & PERF_FEATURE_SIMD_UTILS) {
        stats->simd_avx2_available = true;
        stats->simd_fma_available = true;
    }

    // Performance monitoring statistics
    if (g_performance_system.active_features & PERF_FEATURE_MONITORING) {
        system_resource_usage_t usage = performance_monitor_get_current_usage();
        stats->current_cpu_utilization = usage.cpu_utilization_percent;
        stats->current_memory_utilization = usage.memory_utilization_percent;
        stats->thermal_throttling_active = performance_monitor_is_thermal_throttling();
    }
}

// Print comprehensive performance report
void performance_system_print_report(void) {
    if (!g_performance_system.initialized) {
        printf("[OPTIMIZER] Performance system not initialized\n");
        return;
    }

    printf("\n");
    printf("================================================================\n");
    printf("CloudUnflare Enhanced v2.0 - OPTIMIZER Performance Report\n");
    printf("================================================================\n");

    printf("System Status: %s\n", g_performance_system.initialized ? "ACTIVE" : "INACTIVE");
    printf("Initialization Time: %.2f ms\n",
           g_performance_system.initialization_time_ns / 1000000.0);
    printf("Active Features: 0x%02X\n", g_performance_system.active_features);

    printf("\nFeature Status:\n");
    printf("  Thread Pool (P-core/E-core): %s\n",
           (g_performance_system.active_features & PERF_FEATURE_THREAD_POOL) ? "✓ ENABLED" : "✗ DISABLED");
    printf("  Memory Pool (<500MB): %s\n",
           (g_performance_system.active_features & PERF_FEATURE_MEMORY_POOL) ? "✓ ENABLED" : "✗ DISABLED");
    printf("  SIMD Acceleration (AVX2): %s\n",
           (g_performance_system.active_features & PERF_FEATURE_SIMD_UTILS) ? "✓ ENABLED" : "✗ DISABLED");
    printf("  Lock-Free Structures: %s\n",
           (g_performance_system.active_features & PERF_FEATURE_LOCKFREE) ? "✓ ENABLED" : "✗ DISABLED");
    printf("  CPU Affinity (Meteor Lake): %s\n",
           (g_performance_system.active_features & PERF_FEATURE_CPU_AFFINITY) ? "✓ ENABLED" : "✗ DISABLED");
    printf("  Performance Monitoring: %s\n",
           (g_performance_system.active_features & PERF_FEATURE_MONITORING) ? "✓ ENABLED" : "✗ DISABLED");

    printf("\nConfiguration:\n");
    printf("  Max Threads: %u\n", g_performance_system.config.max_threads);
    printf("  Memory Pool: %zu MB\n", g_performance_system.config.memory_pool_size_mb);
    printf("  NUMA Awareness: %s\n", g_performance_system.config.enable_numa_awareness ? "enabled" : "disabled");
    printf("  Huge Pages: %s\n", g_performance_system.config.enable_huge_pages ? "enabled" : "disabled");
    printf("  Work Stealing: %s\n", g_performance_system.config.enable_work_stealing ? "enabled" : "disabled");
    printf("  Thermal Monitoring: %s\n", g_performance_system.config.enable_thermal_monitoring ? "enabled" : "disabled");

    // Get detailed statistics from each module
    if (g_performance_system.active_features & PERF_FEATURE_THREAD_POOL) {
        printf("\n");
        optimized_thread_pool_get_stats();
    }

    if (g_performance_system.active_features & PERF_FEATURE_MEMORY_POOL) {
        printf("\n");
        optimized_memory_pool_get_stats();
    }

    if (g_performance_system.active_features & PERF_FEATURE_SIMD_UTILS) {
        printf("\n");
        simd_get_performance_stats();
    }

    if (g_performance_system.active_features & PERF_FEATURE_LOCKFREE) {
        printf("\n");
        lockfree_get_performance_stats();
    }

    if (g_performance_system.active_features & PERF_FEATURE_CPU_AFFINITY) {
        printf("\n");
        cpu_affinity_get_stats();
    }

    if (g_performance_system.active_features & PERF_FEATURE_MONITORING) {
        printf("\n");
        performance_monitor_get_stats();
    }

    printf("\n");
    printf("Performance Targets Status:\n");
    if (g_performance_system.active_features & PERF_FEATURE_MONITORING) {
        system_resource_usage_t usage = performance_monitor_get_current_usage();

        printf("  DNS Queries/Second: %lu", usage.dns_queries_per_sec);
        if (usage.dns_queries_per_sec >= 2500) {
            printf(" ✓ TARGET MET\n");
        } else {
            printf(" (target: 2500+)\n");
        }

        printf("  Total Operations/Second: %lu",
               usage.dns_queries_per_sec + usage.http_requests_per_sec + usage.reconnaissance_ops_per_sec);
        uint64_t total_ops = usage.dns_queries_per_sec + usage.http_requests_per_sec + usage.reconnaissance_ops_per_sec;
        if (total_ops >= 10000) {
            printf(" ✓ TARGET MET\n");
        } else {
            printf(" (target: 10000+)\n");
        }

        printf("  Memory Usage: %.1f MB", usage.memory_utilization_percent * g_performance_system.config.memory_pool_size_mb / 100.0f);
        if (usage.memory_utilization_percent * g_performance_system.config.memory_pool_size_mb / 100.0f < 500.0f) {
            printf(" ✓ TARGET MET\n");
        } else {
            printf(" (target: <500MB)\n");
        }

        printf("  Response Time: %.2f ms", usage.average_response_time_ms);
        if (usage.average_response_time_ms < 100.0f) {
            printf(" ✓ TARGET MET\n");
        } else {
            printf(" (target: <100ms)\n");
        }

        printf("  Thermal Status: %s\n",
               performance_monitor_is_thermal_throttling() ? "⚠️ THROTTLING" : "✓ NORMAL");
    } else {
        printf("  Performance monitoring disabled - targets unknown\n");
    }

    printf("\n================================================================\n");
}

// Check if specific performance feature is available
bool performance_system_has_feature(uint32_t feature) {
    if (!g_performance_system.initialized) {
        return false;
    }

    return (g_performance_system.active_features & feature) != 0;
}

// Shutdown performance system and clean up resources
void performance_system_shutdown(void) {
    if (!g_performance_system.initialized) {
        return;
    }

    printf("[OPTIMIZER] Shutting down performance system...\n");

    // Print final performance report
    performance_system_print_report();

    // Shutdown modules in reverse order of initialization
    if (g_performance_system.active_features & PERF_FEATURE_MONITORING) {
        performance_monitor_shutdown();
    }

    if (g_performance_system.active_features & PERF_FEATURE_THREAD_POOL) {
        optimized_thread_pool_shutdown();
    }

    if (g_performance_system.active_features & PERF_FEATURE_MEMORY_POOL) {
        optimized_memory_pool_shutdown();
    }

    if (g_performance_system.active_features & PERF_FEATURE_CPU_AFFINITY) {
        cpu_affinity_shutdown();
    }

    // Reset global state
    memset(&g_performance_system, 0, sizeof(g_performance_system));

    printf("[OPTIMIZER] Performance system shutdown complete\n");
}

// Convenience function to initialize with CloudUnflare optimized defaults
int performance_system_init_cloudunflare_optimized(void) {
    performance_config_t config = performance_get_default_config();

    // CloudUnflare-specific optimizations
    config.max_threads = 50;                    // Optimal for reconnaissance workloads
    config.memory_pool_size_mb = 400;          // Leave 100MB for system
    config.enable_numa_awareness = true;       // Single-socket systems still benefit
    config.enable_huge_pages = true;           // Reduce TLB pressure
    config.enable_work_stealing = true;        // Balance DNS/HTTP/reconnaissance loads
    config.enable_thermal_monitoring = true;   // Prevent throttling during intense scans
    config.enable_adaptive_scaling = true;     // Adjust based on workload

    return performance_system_init(&config);
}

// Integrated performance test function
void performance_system_run_benchmark(void) {
    if (!g_performance_system.initialized) {
        printf("[OPTIMIZER] Performance system not initialized\n");
        return;
    }

    printf("\n[OPTIMIZER] Running CloudUnflare Enhanced v2.0 Performance Benchmark\n");
    printf("====================================================================\n");

    // Test SIMD operations
    if (performance_system_has_feature(PERF_FEATURE_SIMD_UTILS)) {
        printf("Testing SIMD string operations...\n");

        const char *test_domains[] = {
            "example.com", "google.com", "cloudflare.com", "github.com", "stackoverflow.com"
        };

        uint64_t start_time = get_monotonic_time_ns();
        for (int i = 0; i < 10000; i++) {
            for (int j = 0; j < 5; j++) {
                size_t len = simd_strlen(test_domains[j]);
                (void)len; // Suppress unused variable warning
            }
        }
        uint64_t simd_time = get_monotonic_time_ns() - start_time;

        printf("  SIMD string operations: %.2f ms (50,000 operations)\n",
               simd_time / 1000000.0);
    }

    // Test memory pool allocation
    if (performance_system_has_feature(PERF_FEATURE_MEMORY_POOL)) {
        printf("Testing memory pool allocation...\n");

        uint64_t start_time = get_monotonic_time_ns();
        void *ptrs[1000];
        for (int i = 0; i < 1000; i++) {
            ptrs[i] = optimized_malloc(1024);
        }
        for (int i = 0; i < 1000; i++) {
            optimized_free(ptrs[i]);
        }
        uint64_t alloc_time = get_monotonic_time_ns() - start_time;

        printf("  Memory pool operations: %.2f ms (2,000 alloc/free pairs)\n",
               alloc_time / 1000000.0);
    }

    // Test lock-free operations
    if (performance_system_has_feature(PERF_FEATURE_LOCKFREE)) {
        printf("Testing lock-free data structures...\n");

        lockfree_queue_t *queue = lockfree_queue_create();
        if (queue) {
            uint64_t start_time = get_monotonic_time_ns();

            // Test enqueue/dequeue operations
            for (int i = 0; i < 10000; i++) {
                lockfree_queue_enqueue(queue, (void*)(uintptr_t)i);
            }
            for (int i = 0; i < 10000; i++) {
                lockfree_queue_dequeue(queue);
            }

            uint64_t lockfree_time = get_monotonic_time_ns() - start_time;
            printf("  Lock-free queue operations: %.2f ms (20,000 operations)\n",
                   lockfree_time / 1000000.0);

            lockfree_queue_destroy(queue);
        }
    }

    printf("Benchmark complete.\n");
    printf("====================================================================\n");
}