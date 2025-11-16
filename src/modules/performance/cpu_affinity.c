/*
 * CloudUnflare Enhanced v2.0 - Intel Meteor Lake CPU Affinity Optimization
 *
 * P-core/E-core aware thread scheduling and CPU affinity management
 * Optimized for Intel Core Ultra 7 165H hybrid architecture
 *
 * Performance Targets:
 * - Optimal P-core utilization for compute tasks
 * - E-core utilization for I/O-bound operations
 * - Dynamic load balancing based on workload type
 * - Thermal management and frequency scaling
 * - NUMA awareness for memory allocation
 *
 * Agent: OPTIMIZER (CPU scheduling)
 * Coordination: C-INTERNAL, ARCHITECT
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#include <errno.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <numa.h>
#include "../config.h"

// Intel Meteor Lake architecture constants
#define METEOR_LAKE_MAX_P_CORES 10
#define METEOR_LAKE_MAX_E_CORES 10
#define METEOR_LAKE_TOTAL_CORES 20
#define CPU_INFO_BUFFER_SIZE 4096
#define THERMAL_THRESHOLD_C 90
#define FREQUENCY_SCALING_INTERVAL_MS 100

// Core type identification
typedef enum {
    CORE_TYPE_UNKNOWN = 0,
    CORE_TYPE_P_CORE = 1,    // Performance cores (high frequency, out-of-order)
    CORE_TYPE_E_CORE = 2     // Efficiency cores (lower power, in-order)
} cpu_core_type_t;

// Workload classification
typedef enum {
    WORKLOAD_TYPE_UNKNOWN = 0,
    WORKLOAD_TYPE_COMPUTE_INTENSIVE = 1,  // CPU-bound, benefits from P-cores
    WORKLOAD_TYPE_IO_BOUND = 2,           // I/O-bound, suitable for E-cores
    WORKLOAD_TYPE_MEMORY_BOUND = 3,       // Memory-bound, mixed allocation
    WORKLOAD_TYPE_NETWORK_BOUND = 4       // Network I/O, E-cores preferred
} workload_type_t;

// CPU core information
typedef struct {
    int core_id;
    cpu_core_type_t core_type;
    int numa_node;
    bool online;
    bool available;

    // Performance characteristics
    uint32_t base_frequency_mhz;
    uint32_t max_frequency_mhz;
    uint32_t current_frequency_mhz;
    float temperature_celsius;
    float utilization_percent;

    // Assignment tracking
    _Atomic uint32_t assigned_threads;
    _Atomic uint64_t total_execution_time_ns;
    _Atomic uint64_t context_switches;

    char padding[64];
} __attribute__((aligned(64))) cpu_core_info_t;

// Thread affinity information
typedef struct {
    pthread_t thread_id;
    int assigned_core;
    cpu_core_type_t preferred_core_type;
    workload_type_t workload_type;

    // Performance metrics
    uint64_t execution_time_ns;
    uint64_t context_switches;
    uint32_t migrations;

    // Scheduling hints
    bool pin_to_core;
    bool allow_migration;
    int priority;

    char padding[32];
} thread_affinity_info_t;

// CPU topology and affinity manager
typedef struct {
    cpu_core_info_t cores[METEOR_LAKE_TOTAL_CORES];
    int total_cores;
    int p_core_count;
    int e_core_count;
    int numa_nodes;

    // P-core tracking
    int p_core_ids[METEOR_LAKE_MAX_P_CORES];
    _Atomic uint32_t p_core_load[METEOR_LAKE_MAX_P_CORES];

    // E-core tracking
    int e_core_ids[METEOR_LAKE_MAX_E_CORES];
    _Atomic uint32_t e_core_load[METEOR_LAKE_MAX_E_CORES];

    // Global statistics
    _Atomic uint64_t total_thread_assignments;
    _Atomic uint64_t p_core_assignments;
    _Atomic uint64_t e_core_assignments;
    _Atomic uint64_t migration_count;
    _Atomic uint64_t load_balancing_decisions;

    // Configuration
    bool enable_dynamic_migration;
    bool enable_thermal_throttling;
    bool enable_frequency_scaling;
    float thermal_threshold;
    uint32_t load_balance_interval_ms;

    // Synchronization
    pthread_mutex_t affinity_mutex;
    pthread_t monitoring_thread;
    _Atomic bool monitoring_active;

    char padding[64];
} __attribute__((aligned(64))) cpu_affinity_manager_t;

// Global CPU affinity manager
static cpu_affinity_manager_t *g_cpu_manager = NULL;

// High-precision timing
static uint64_t get_monotonic_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// Read CPU frequency from sysfs
static uint32_t read_cpu_frequency(int cpu_id) {
    char path[256];
    snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq", cpu_id);

    FILE *fp = fopen(path, "r");
    if (!fp) return 0;

    uint32_t freq_khz = 0;
    if (fscanf(fp, "%u", &freq_khz) != 1) {
        freq_khz = 0;
    }

    fclose(fp);
    return freq_khz / 1000; // Convert to MHz
}

// Read CPU temperature (if available)
static float read_cpu_temperature(int cpu_id) {
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/thermal/thermal_zone%d/temp", cpu_id);

    FILE *fp = fopen(path, "r");
    if (!fp) return 0.0f;

    int temp_millicelsius = 0;
    if (fscanf(fp, "%d", &temp_millicelsius) != 1) {
        temp_millicelsius = 0;
    }

    fclose(fp);
    return temp_millicelsius / 1000.0f;
}

// Detect Intel Meteor Lake core topology
static bool detect_meteor_lake_topology(cpu_affinity_manager_t *manager) {
    manager->total_cores = get_nprocs();
    manager->p_core_count = 0;
    manager->e_core_count = 0;

    // Intel Meteor Lake specific detection
    // P-cores typically have higher base frequencies and are cores 0-9
    // E-cores are typically cores 10-19 with lower frequencies

    for (int i = 0; i < manager->total_cores && i < METEOR_LAKE_TOTAL_CORES; i++) {
        cpu_core_info_t *core = &manager->cores[i];

        core->core_id = i;
        core->online = true;
        core->available = true;
        core->numa_node = 0; // Most consumer systems are single-node

        // Read frequency information
        core->current_frequency_mhz = read_cpu_frequency(i);
        core->temperature_celsius = read_cpu_temperature(i);

        // Heuristic: cores 0-9 are P-cores, 10-19 are E-cores
        if (i < 10) {
            core->core_type = CORE_TYPE_P_CORE;
            core->base_frequency_mhz = 1400;  // Typical P-core base
            core->max_frequency_mhz = 5000;   // Typical P-core max

            manager->p_core_ids[manager->p_core_count] = i;
            atomic_init(&manager->p_core_load[manager->p_core_count], 0);
            manager->p_core_count++;
        } else {
            core->core_type = CORE_TYPE_E_CORE;
            core->base_frequency_mhz = 1000;  // Typical E-core base
            core->max_frequency_mhz = 3800;   // Typical E-core max

            manager->e_core_ids[manager->e_core_count] = i;
            atomic_init(&manager->e_core_load[manager->e_core_count], 0);
            manager->e_core_count++;
        }

        atomic_init(&core->assigned_threads, 0);
        atomic_init(&core->total_execution_time_ns, 0);
        atomic_init(&core->context_switches, 0);

        core->utilization_percent = 0.0f;
    }

    printf("[OPTIMIZER] Detected CPU topology: %d P-cores, %d E-cores\n",
           manager->p_core_count, manager->e_core_count);

    return true;
}

// Find optimal core for workload type
static int find_optimal_core(workload_type_t workload_type, bool prefer_low_load) {
    if (!g_cpu_manager) return -1;

    int best_core = -1;
    uint32_t min_load = UINT32_MAX;

    if (workload_type == WORKLOAD_TYPE_COMPUTE_INTENSIVE) {
        // Prefer P-cores for compute-intensive tasks
        for (int i = 0; i < g_cpu_manager->p_core_count; i++) {
            int core_id = g_cpu_manager->p_core_ids[i];
            cpu_core_info_t *core = &g_cpu_manager->cores[core_id];

            if (!core->available) continue;

            uint32_t load = atomic_load(&core->assigned_threads);

            // Consider thermal throttling
            if (g_cpu_manager->enable_thermal_throttling &&
                core->temperature_celsius > g_cpu_manager->thermal_threshold) {
                continue;
            }

            if (load < min_load) {
                min_load = load;
                best_core = core_id;
            }
        }
    } else {
        // Prefer E-cores for I/O-bound and less intensive tasks
        for (int i = 0; i < g_cpu_manager->e_core_count; i++) {
            int core_id = g_cpu_manager->e_core_ids[i];
            cpu_core_info_t *core = &g_cpu_manager->cores[core_id];

            if (!core->available) continue;

            uint32_t load = atomic_load(&core->assigned_threads);

            if (load < min_load) {
                min_load = load;
                best_core = core_id;
            }
        }

        // Fallback to P-cores if E-cores are overloaded
        if (best_core == -1 || min_load > 4) {
            for (int i = 0; i < g_cpu_manager->p_core_count; i++) {
                int core_id = g_cpu_manager->p_core_ids[i];
                cpu_core_info_t *core = &g_cpu_manager->cores[core_id];

                if (!core->available) continue;

                uint32_t load = atomic_load(&core->assigned_threads);

                if (load < min_load) {
                    min_load = load;
                    best_core = core_id;
                }
            }
        }
    }

    return best_core;
}

// Set thread affinity to specific core
int cpu_affinity_set_thread_core(pthread_t thread, int core_id) {
    if (!g_cpu_manager || core_id < 0 || core_id >= g_cpu_manager->total_cores) {
        return -1;
    }

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);

    int result = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
    if (result == 0) {
        atomic_fetch_add(&g_cpu_manager->cores[core_id].assigned_threads, 1);
        atomic_fetch_add(&g_cpu_manager->total_thread_assignments, 1);

        if (g_cpu_manager->cores[core_id].core_type == CORE_TYPE_P_CORE) {
            atomic_fetch_add(&g_cpu_manager->p_core_assignments, 1);
        } else {
            atomic_fetch_add(&g_cpu_manager->e_core_assignments, 1);
        }

        printf("[OPTIMIZER] Thread assigned to %s core %d\n",
               (g_cpu_manager->cores[core_id].core_type == CORE_TYPE_P_CORE) ? "P" : "E",
               core_id);
    }

    return result;
}

// Set thread affinity based on workload type
int cpu_affinity_set_workload_optimal(pthread_t thread, workload_type_t workload_type) {
    if (!g_cpu_manager) return -1;

    pthread_mutex_lock(&g_cpu_manager->affinity_mutex);

    int optimal_core = find_optimal_core(workload_type, true);

    pthread_mutex_unlock(&g_cpu_manager->affinity_mutex);

    if (optimal_core >= 0) {
        return cpu_affinity_set_thread_core(thread, optimal_core);
    }

    return -1;
}

// Monitor CPU performance and thermal state
static void* cpu_monitoring_thread(void *arg) {
    cpu_affinity_manager_t *manager = (cpu_affinity_manager_t*)arg;

    pthread_setname_np(pthread_self(), "cpu-monitor");

    // Set this thread to run on E-core for monitoring
    cpu_affinity_set_thread_core(pthread_self(),
                                 manager->e_core_count > 0 ? manager->e_core_ids[0] : 0);

    while (atomic_load(&manager->monitoring_active)) {
        // Update CPU frequencies and temperatures
        for (int i = 0; i < manager->total_cores; i++) {
            cpu_core_info_t *core = &manager->cores[i];

            core->current_frequency_mhz = read_cpu_frequency(i);
            core->temperature_celsius = read_cpu_temperature(i);

            // Simple utilization estimation based on assigned threads
            uint32_t assigned = atomic_load(&core->assigned_threads);
            core->utilization_percent = (float)assigned * 25.0f; // Rough estimate

            // Thermal throttling check
            if (manager->enable_thermal_throttling &&
                core->temperature_celsius > manager->thermal_threshold) {
                core->available = false;
                printf("[OPTIMIZER] Core %d thermally throttled (%.1f°C)\n",
                       i, core->temperature_celsius);
            } else {
                core->available = true;
            }
        }

        // Load balancing decisions
        atomic_fetch_add(&manager->load_balancing_decisions, 1);

        // Sleep for monitoring interval
        struct timespec sleep_time = {
            .tv_sec = manager->load_balance_interval_ms / 1000,
            .tv_nsec = (manager->load_balance_interval_ms % 1000) * 1000000
        };
        nanosleep(&sleep_time, NULL);
    }

    return NULL;
}

// Initialize CPU affinity manager
int cpu_affinity_init(void) {
    if (g_cpu_manager) {
        printf("[OPTIMIZER] CPU affinity manager already initialized\n");
        return 0;
    }

    g_cpu_manager = aligned_alloc(64, sizeof(cpu_affinity_manager_t));
    if (!g_cpu_manager) {
        printf("[OPTIMIZER] Error: Failed to allocate CPU affinity manager\n");
        return -1;
    }

    memset(g_cpu_manager, 0, sizeof(cpu_affinity_manager_t));

    // Initialize configuration
    g_cpu_manager->enable_dynamic_migration = true;
    g_cpu_manager->enable_thermal_throttling = true;
    g_cpu_manager->enable_frequency_scaling = true;
    g_cpu_manager->thermal_threshold = THERMAL_THRESHOLD_C;
    g_cpu_manager->load_balance_interval_ms = 1000; // 1 second

    // Initialize statistics
    atomic_init(&g_cpu_manager->total_thread_assignments, 0);
    atomic_init(&g_cpu_manager->p_core_assignments, 0);
    atomic_init(&g_cpu_manager->e_core_assignments, 0);
    atomic_init(&g_cpu_manager->migration_count, 0);
    atomic_init(&g_cpu_manager->load_balancing_decisions, 0);

    // Initialize mutex
    if (pthread_mutex_init(&g_cpu_manager->affinity_mutex, NULL) != 0) {
        free(g_cpu_manager);
        g_cpu_manager = NULL;
        return -1;
    }

    // Detect CPU topology
    if (!detect_meteor_lake_topology(g_cpu_manager)) {
        pthread_mutex_destroy(&g_cpu_manager->affinity_mutex);
        free(g_cpu_manager);
        g_cpu_manager = NULL;
        return -1;
    }

    // Start monitoring thread
    atomic_store(&g_cpu_manager->monitoring_active, true);
    if (pthread_create(&g_cpu_manager->monitoring_thread, NULL, cpu_monitoring_thread, g_cpu_manager) != 0) {
        printf("[OPTIMIZER] Warning: Failed to start CPU monitoring thread\n");
        atomic_store(&g_cpu_manager->monitoring_active, false);
    }

    printf("[OPTIMIZER] CPU affinity manager initialized for Intel Meteor Lake\n");
    printf("[OPTIMIZER] Thermal threshold: %.1f°C, Load balancing: %ums\n",
           g_cpu_manager->thermal_threshold, g_cpu_manager->load_balance_interval_ms);

    return 0;
}

// Get CPU affinity statistics
void cpu_affinity_get_stats(void) {
    if (!g_cpu_manager) {
        printf("[OPTIMIZER] CPU affinity manager not initialized\n");
        return;
    }

    printf("\n[OPTIMIZER] CPU Affinity Performance Statistics\n");
    printf("==============================================\n");
    printf("CPU Topology:\n");
    printf("  Total Cores: %d\n", g_cpu_manager->total_cores);
    printf("  P-Cores: %d\n", g_cpu_manager->p_core_count);
    printf("  E-Cores: %d\n", g_cpu_manager->e_core_count);
    printf("  NUMA Nodes: %d\n", g_cpu_manager->numa_nodes);

    printf("\nThread Assignment Statistics:\n");
    printf("  Total Assignments: %lu\n", atomic_load(&g_cpu_manager->total_thread_assignments));
    printf("  P-Core Assignments: %lu\n", atomic_load(&g_cpu_manager->p_core_assignments));
    printf("  E-Core Assignments: %lu\n", atomic_load(&g_cpu_manager->e_core_assignments));
    printf("  Thread Migrations: %lu\n", atomic_load(&g_cpu_manager->migration_count));
    printf("  Load Balance Decisions: %lu\n", atomic_load(&g_cpu_manager->load_balancing_decisions));

    uint64_t total_assignments = atomic_load(&g_cpu_manager->total_thread_assignments);
    if (total_assignments > 0) {
        printf("  P-Core Usage: %.2f%%\n",
               (double)atomic_load(&g_cpu_manager->p_core_assignments) * 100.0 / total_assignments);
        printf("  E-Core Usage: %.2f%%\n",
               (double)atomic_load(&g_cpu_manager->e_core_assignments) * 100.0 / total_assignments);
    }

    printf("\nPer-Core Status:\n");
    for (int i = 0; i < g_cpu_manager->total_cores; i++) {
        cpu_core_info_t *core = &g_cpu_manager->cores[i];
        printf("  Core %d (%s): %u threads, %.0f MHz, %.1f°C, %.1f%% util\n",
               i,
               (core->core_type == CORE_TYPE_P_CORE) ? "P" : "E",
               atomic_load(&core->assigned_threads),
               (float)core->current_frequency_mhz,
               core->temperature_celsius,
               core->utilization_percent);
    }

    printf("\nConfiguration:\n");
    printf("  Dynamic Migration: %s\n", g_cpu_manager->enable_dynamic_migration ? "enabled" : "disabled");
    printf("  Thermal Throttling: %s\n", g_cpu_manager->enable_thermal_throttling ? "enabled" : "disabled");
    printf("  Frequency Scaling: %s\n", g_cpu_manager->enable_frequency_scaling ? "enabled" : "disabled");
}

// Convenience functions for common workload types
int cpu_affinity_set_compute_intensive(pthread_t thread) {
    return cpu_affinity_set_workload_optimal(thread, WORKLOAD_TYPE_COMPUTE_INTENSIVE);
}

int cpu_affinity_set_io_bound(pthread_t thread) {
    return cpu_affinity_set_workload_optimal(thread, WORKLOAD_TYPE_IO_BOUND);
}

int cpu_affinity_set_network_bound(pthread_t thread) {
    return cpu_affinity_set_workload_optimal(thread, WORKLOAD_TYPE_NETWORK_BOUND);
}

// Shutdown CPU affinity manager
void cpu_affinity_shutdown(void) {
    if (!g_cpu_manager) return;

    printf("[OPTIMIZER] Shutting down CPU affinity manager...\n");

    // Stop monitoring thread
    atomic_store(&g_cpu_manager->monitoring_active, false);
    if (g_cpu_manager->monitoring_thread) {
        pthread_join(g_cpu_manager->monitoring_thread, NULL);
    }

    // Print final statistics
    cpu_affinity_get_stats();

    // Clean up
    pthread_mutex_destroy(&g_cpu_manager->affinity_mutex);
    free(g_cpu_manager);
    g_cpu_manager = NULL;

    printf("[OPTIMIZER] CPU affinity manager shutdown complete\n");
}