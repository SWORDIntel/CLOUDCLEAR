/*
 * CloudUnflare Enhanced v2.0 - Performance Monitoring and Thermal Management
 *
 * Real-time performance metrics, thermal monitoring, and adaptive scaling
 * Designed for Intel Meteor Lake with comprehensive system monitoring
 *
 * Performance Targets:
 * - Real-time performance metrics collection
 * - Thermal throttling prevention
 * - Adaptive performance scaling
 * - Memory bandwidth monitoring
 * - Network throughput tracking
 * - Resource utilization optimization
 *
 * Agent: OPTIMIZER (performance monitoring)
 * Coordination: C-INTERNAL, ARCHITECT
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include "../config.h"

// Performance monitoring constants
#define PERF_MONITOR_MAX_METRICS 64
#define PERF_MONITOR_HISTORY_SIZE 1000
#define PERF_MONITOR_SAMPLE_INTERVAL_MS 100
#define THERMAL_MONITOR_INTERVAL_MS 500
#define MEMORY_MONITOR_INTERVAL_MS 1000
#define NETWORK_MONITOR_INTERVAL_MS 250

// Thermal management constants
#define THERMAL_ZONE_MAX 16
#define THERMAL_CRITICAL_TEMP 95.0f
#define THERMAL_WARNING_TEMP 85.0f
#define THERMAL_THROTTLE_TEMP 90.0f

// Performance metric types
typedef enum {
    METRIC_TYPE_COUNTER = 0,     // Monotonically increasing
    METRIC_TYPE_GAUGE = 1,       // Current value
    METRIC_TYPE_HISTOGRAM = 2,   // Distribution of values
    METRIC_TYPE_RATE = 3         // Rate of change
} metric_type_t;

// Performance metric
typedef struct {
    char name[64];
    metric_type_t type;
    _Atomic uint64_t value;
    _Atomic uint64_t min_value;
    _Atomic uint64_t max_value;
    _Atomic uint64_t sum_value;
    _Atomic uint64_t sample_count;
    uint64_t history[PERF_MONITOR_HISTORY_SIZE];
    _Atomic uint32_t history_index;
    uint64_t last_update_time_ns;
    bool enabled;
} performance_metric_t;

// Thermal zone information
typedef struct {
    int zone_id;
    char type[32];
    float temperature_celsius;
    float critical_temp;
    float warning_temp;
    bool active;
    bool throttling;
    uint64_t last_update_time_ns;
} thermal_zone_t;

// System resource usage
typedef struct {
    // CPU utilization
    float cpu_utilization_percent;
    float p_core_utilization_percent;
    float e_core_utilization_percent;
    uint64_t context_switches_per_sec;
    uint64_t interrupts_per_sec;

    // Memory usage
    uint64_t memory_total_kb;
    uint64_t memory_used_kb;
    uint64_t memory_free_kb;
    uint64_t memory_cached_kb;
    uint64_t memory_buffers_kb;
    float memory_utilization_percent;

    // Network throughput
    uint64_t network_rx_bytes_per_sec;
    uint64_t network_tx_bytes_per_sec;
    uint64_t network_packets_per_sec;

    // I/O performance
    uint64_t disk_read_bytes_per_sec;
    uint64_t disk_write_bytes_per_sec;
    uint64_t disk_iops;

    // Application-specific
    uint64_t dns_queries_per_sec;
    uint64_t http_requests_per_sec;
    uint64_t reconnaissance_ops_per_sec;
    float average_response_time_ms;

    uint64_t timestamp_ns;
} system_resource_usage_t;

// Performance monitoring configuration
typedef struct {
    bool enable_cpu_monitoring;
    bool enable_thermal_monitoring;
    bool enable_memory_monitoring;
    bool enable_network_monitoring;
    bool enable_adaptive_scaling;

    uint32_t sample_interval_ms;
    uint32_t thermal_check_interval_ms;
    uint32_t history_retention_count;

    float thermal_throttle_threshold;
    float thermal_warning_threshold;
    float memory_warning_threshold;
    float cpu_warning_threshold;
} performance_config_t;

// Main performance monitor structure
typedef struct {
    performance_metric_t metrics[PERF_MONITOR_MAX_METRICS];
    uint32_t metric_count;

    thermal_zone_t thermal_zones[THERMAL_ZONE_MAX];
    uint32_t thermal_zone_count;

    system_resource_usage_t current_usage;
    system_resource_usage_t previous_usage;
    system_resource_usage_t peak_usage;

    performance_config_t config;

    // Monitoring threads
    pthread_t monitoring_thread;
    pthread_t thermal_thread;
    pthread_t adaptive_thread;

    // Synchronization
    pthread_mutex_t monitor_mutex;
    _Atomic bool monitoring_active;

    // Performance statistics
    _Atomic uint64_t total_samples;
    _Atomic uint64_t thermal_events;
    _Atomic uint64_t throttling_events;
    _Atomic uint64_t adaptive_scaling_events;

    char padding[64];
} __attribute__((aligned(64))) performance_monitor_t;

// Global performance monitor
static performance_monitor_t *g_perf_monitor = NULL;

// High-precision timing
static uint64_t get_monotonic_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// Read integer value from file
static int64_t read_int_from_file(const char *filepath) {
    FILE *fp = fopen(filepath, "r");
    if (!fp) return -1;

    int64_t value = -1;
    if (fscanf(fp, "%ld", &value) != 1) {
        value = -1;
    }

    fclose(fp);
    return value;
}

// Read string from file
static bool read_string_from_file(const char *filepath, char *buffer, size_t buffer_size) {
    FILE *fp = fopen(filepath, "r");
    if (!fp) return false;

    bool success = (fgets(buffer, buffer_size, fp) != NULL);
    if (success) {
        // Remove trailing newline
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len - 1] == '\n') {
            buffer[len - 1] = '\0';
        }
    }

    fclose(fp);
    return success;
}

// Initialize thermal zone monitoring
static bool init_thermal_zones(performance_monitor_t *monitor) {
    monitor->thermal_zone_count = 0;

    for (int i = 0; i < THERMAL_ZONE_MAX; i++) {
        char temp_path[256];
        char type_path[256];
        snprintf(temp_path, sizeof(temp_path), "/sys/class/thermal/thermal_zone%d/temp", i);
        snprintf(type_path, sizeof(type_path), "/sys/class/thermal/thermal_zone%d/type", i);

        // Check if thermal zone exists
        if (access(temp_path, R_OK) != 0) {
            break;
        }

        thermal_zone_t *zone = &monitor->thermal_zones[monitor->thermal_zone_count];
        zone->zone_id = i;
        zone->active = true;
        zone->throttling = false;
        zone->critical_temp = THERMAL_CRITICAL_TEMP;
        zone->warning_temp = THERMAL_WARNING_TEMP;

        // Read thermal zone type
        if (!read_string_from_file(type_path, zone->type, sizeof(zone->type))) {
            snprintf(zone->type, sizeof(zone->type), "zone%d", i);
        }

        monitor->thermal_zone_count++;
    }

    printf("[OPTIMIZER] Initialized %u thermal zones\n", monitor->thermal_zone_count);
    return monitor->thermal_zone_count > 0;
}

// Read system memory information
static void read_memory_info(system_resource_usage_t *usage) {
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp) return;

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "MemTotal: %lu kB", &usage->memory_total_kb) == 1) continue;
        if (sscanf(line, "MemFree: %lu kB", &usage->memory_free_kb) == 1) continue;
        if (sscanf(line, "Cached: %lu kB", &usage->memory_cached_kb) == 1) continue;
        if (sscanf(line, "Buffers: %lu kB", &usage->memory_buffers_kb) == 1) continue;
    }

    fclose(fp);

    usage->memory_used_kb = usage->memory_total_kb - usage->memory_free_kb;
    usage->memory_utilization_percent = (float)usage->memory_used_kb * 100.0f / usage->memory_total_kb;
}

// Read CPU statistics
static void read_cpu_stats(system_resource_usage_t *usage) {
    FILE *fp = fopen("/proc/stat", "r");
    if (!fp) return;

    char line[256];
    uint64_t user, nice, system, idle, iowait, irq, softirq, steal;

    if (fgets(line, sizeof(line), fp) &&
        sscanf(line, "cpu %lu %lu %lu %lu %lu %lu %lu %lu",
               &user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal) == 8) {

        uint64_t total = user + nice + system + idle + iowait + irq + softirq + steal;
        uint64_t active = total - idle - iowait;

        usage->cpu_utilization_percent = (float)active * 100.0f / total;
    }

    // Read context switches and interrupts
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "ctxt %lu", &usage->context_switches_per_sec) == 1) continue;
        if (sscanf(line, "intr %lu", &usage->interrupts_per_sec) == 1) continue;
    }

    fclose(fp);
}

// Read network statistics
static void read_network_stats(system_resource_usage_t *usage) {
    FILE *fp = fopen("/proc/net/dev", "r");
    if (!fp) return;

    char line[512];
    uint64_t rx_bytes = 0, tx_bytes = 0, rx_packets = 0, tx_packets = 0;

    // Skip header lines
    fgets(line, sizeof(line), fp);
    fgets(line, sizeof(line), fp);

    while (fgets(line, sizeof(line), fp)) {
        char interface[32];
        uint64_t rx_b, rx_p, tx_b, tx_p;
        uint64_t dummy[12]; // Other fields we don't need

        if (sscanf(line, "%31s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
                   interface, &rx_b, &rx_p, &dummy[0], &dummy[1], &dummy[2], &dummy[3], &dummy[4],
                   &dummy[5], &tx_b, &tx_p, &dummy[6], &dummy[7], &dummy[8], &dummy[9], &dummy[10],
                   &dummy[11]) >= 11) {

            // Skip loopback interface
            if (strncmp(interface, "lo:", 3) == 0) continue;

            rx_bytes += rx_b;
            tx_bytes += tx_b;
            rx_packets += rx_p;
            tx_packets += tx_p;
        }
    }

    fclose(fp);

    usage->network_rx_bytes_per_sec = rx_bytes;
    usage->network_tx_bytes_per_sec = tx_bytes;
    usage->network_packets_per_sec = rx_packets + tx_packets;
}

// Update thermal zones
static void update_thermal_zones(performance_monitor_t *monitor) {
    for (uint32_t i = 0; i < monitor->thermal_zone_count; i++) {
        thermal_zone_t *zone = &monitor->thermal_zones[i];

        char temp_path[256];
        snprintf(temp_path, sizeof(temp_path), "/sys/class/thermal/thermal_zone%d/temp", zone->zone_id);

        int64_t temp_millicelsius = read_int_from_file(temp_path);
        if (temp_millicelsius >= 0) {
            zone->temperature_celsius = temp_millicelsius / 1000.0f;
            zone->last_update_time_ns = get_monotonic_time_ns();

            // Check for thermal events
            if (zone->temperature_celsius >= zone->critical_temp) {
                zone->throttling = true;
                atomic_fetch_add(&monitor->throttling_events, 1);
                printf("[OPTIMIZER] CRITICAL: Thermal zone %d reached %.1f°C\n",
                       zone->zone_id, zone->temperature_celsius);
            } else if (zone->temperature_celsius >= zone->warning_temp) {
                atomic_fetch_add(&monitor->thermal_events, 1);
                if (!zone->throttling) {
                    printf("[OPTIMIZER] WARNING: Thermal zone %d at %.1f°C\n",
                           zone->zone_id, zone->temperature_celsius);
                }
            } else {
                zone->throttling = false;
            }
        }
    }
}

// Calculate rate of change
static uint64_t calculate_rate(uint64_t current, uint64_t previous, uint64_t time_diff_ns) {
    if (time_diff_ns == 0 || current < previous) return 0;

    uint64_t diff = current - previous;
    return (diff * 1000000000ULL) / time_diff_ns; // Convert to per-second rate
}

// Main performance monitoring thread
static void* performance_monitoring_thread(void *arg) {
    performance_monitor_t *monitor = (performance_monitor_t*)arg;

    pthread_setname_np(pthread_self(), "perf-monitor");

    while (atomic_load(&monitor->monitoring_active)) {
        uint64_t start_time = get_monotonic_time_ns();

        pthread_mutex_lock(&monitor->monitor_mutex);

        // Save previous values for rate calculations
        system_resource_usage_t prev_usage = monitor->current_usage;

        // Update current system resource usage
        read_memory_info(&monitor->current_usage);
        read_cpu_stats(&monitor->current_usage);
        read_network_stats(&monitor->current_usage);

        monitor->current_usage.timestamp_ns = start_time;

        // Calculate rates if we have previous data
        if (prev_usage.timestamp_ns > 0) {
            uint64_t time_diff = start_time - prev_usage.timestamp_ns;

            monitor->current_usage.network_rx_bytes_per_sec =
                calculate_rate(monitor->current_usage.network_rx_bytes_per_sec,
                              prev_usage.network_rx_bytes_per_sec, time_diff);

            monitor->current_usage.network_tx_bytes_per_sec =
                calculate_rate(monitor->current_usage.network_tx_bytes_per_sec,
                              prev_usage.network_tx_bytes_per_sec, time_diff);

            monitor->current_usage.context_switches_per_sec =
                calculate_rate(monitor->current_usage.context_switches_per_sec,
                              prev_usage.context_switches_per_sec, time_diff);

            monitor->current_usage.interrupts_per_sec =
                calculate_rate(monitor->current_usage.interrupts_per_sec,
                              prev_usage.interrupts_per_sec, time_diff);
        }

        // Update peak usage tracking
        if (monitor->current_usage.cpu_utilization_percent > monitor->peak_usage.cpu_utilization_percent) {
            monitor->peak_usage.cpu_utilization_percent = monitor->current_usage.cpu_utilization_percent;
        }

        if (monitor->current_usage.memory_utilization_percent > monitor->peak_usage.memory_utilization_percent) {
            monitor->peak_usage.memory_utilization_percent = monitor->current_usage.memory_utilization_percent;
        }

        atomic_fetch_add(&monitor->total_samples, 1);

        pthread_mutex_unlock(&monitor->monitor_mutex);

        // Sleep for configured interval
        uint64_t elapsed_ns = get_monotonic_time_ns() - start_time;
        uint64_t sleep_ns = (uint64_t)monitor->config.sample_interval_ms * 1000000ULL;

        if (elapsed_ns < sleep_ns) {
            struct timespec sleep_time = {
                .tv_sec = (sleep_ns - elapsed_ns) / 1000000000ULL,
                .tv_nsec = (sleep_ns - elapsed_ns) % 1000000000ULL
            };
            nanosleep(&sleep_time, NULL);
        }
    }

    return NULL;
}

// Thermal monitoring thread
static void* thermal_monitoring_thread(void *arg) {
    performance_monitor_t *monitor = (performance_monitor_t*)arg;

    pthread_setname_np(pthread_self(), "thermal-monitor");

    while (atomic_load(&monitor->monitoring_active)) {
        update_thermal_zones(monitor);

        struct timespec sleep_time = {
            .tv_sec = monitor->config.thermal_check_interval_ms / 1000,
            .tv_nsec = (monitor->config.thermal_check_interval_ms % 1000) * 1000000
        };
        nanosleep(&sleep_time, NULL);
    }

    return NULL;
}

// Initialize performance monitor
int performance_monitor_init(void) {
    if (g_perf_monitor) {
        printf("[OPTIMIZER] Performance monitor already initialized\n");
        return 0;
    }

    g_perf_monitor = aligned_alloc(64, sizeof(performance_monitor_t));
    if (!g_perf_monitor) {
        printf("[OPTIMIZER] Error: Failed to allocate performance monitor\n");
        return -1;
    }

    memset(g_perf_monitor, 0, sizeof(performance_monitor_t));

    // Initialize configuration with defaults
    g_perf_monitor->config.enable_cpu_monitoring = true;
    g_perf_monitor->config.enable_thermal_monitoring = true;
    g_perf_monitor->config.enable_memory_monitoring = true;
    g_perf_monitor->config.enable_network_monitoring = true;
    g_perf_monitor->config.enable_adaptive_scaling = true;

    g_perf_monitor->config.sample_interval_ms = PERF_MONITOR_SAMPLE_INTERVAL_MS;
    g_perf_monitor->config.thermal_check_interval_ms = THERMAL_MONITOR_INTERVAL_MS;
    g_perf_monitor->config.history_retention_count = PERF_MONITOR_HISTORY_SIZE;

    g_perf_monitor->config.thermal_throttle_threshold = THERMAL_THROTTLE_TEMP;
    g_perf_monitor->config.thermal_warning_threshold = THERMAL_WARNING_TEMP;
    g_perf_monitor->config.memory_warning_threshold = 85.0f;
    g_perf_monitor->config.cpu_warning_threshold = 90.0f;

    // Initialize synchronization
    if (pthread_mutex_init(&g_perf_monitor->monitor_mutex, NULL) != 0) {
        free(g_perf_monitor);
        g_perf_monitor = NULL;
        return -1;
    }

    // Initialize thermal zones
    init_thermal_zones(g_perf_monitor);

    // Initialize statistics
    atomic_init(&g_perf_monitor->total_samples, 0);
    atomic_init(&g_perf_monitor->thermal_events, 0);
    atomic_init(&g_perf_monitor->throttling_events, 0);
    atomic_init(&g_perf_monitor->adaptive_scaling_events, 0);

    // Start monitoring threads
    atomic_store(&g_perf_monitor->monitoring_active, true);

    if (pthread_create(&g_perf_monitor->monitoring_thread, NULL,
                       performance_monitoring_thread, g_perf_monitor) != 0) {
        printf("[OPTIMIZER] Error: Failed to create performance monitoring thread\n");
        pthread_mutex_destroy(&g_perf_monitor->monitor_mutex);
        free(g_perf_monitor);
        g_perf_monitor = NULL;
        return -1;
    }

    if (pthread_create(&g_perf_monitor->thermal_thread, NULL,
                       thermal_monitoring_thread, g_perf_monitor) != 0) {
        printf("[OPTIMIZER] Warning: Failed to create thermal monitoring thread\n");
    }

    printf("[OPTIMIZER] Performance monitor initialized\n");
    printf("[OPTIMIZER] Monitoring: CPU=%s, Thermal=%s, Memory=%s, Network=%s\n",
           g_perf_monitor->config.enable_cpu_monitoring ? "yes" : "no",
           g_perf_monitor->config.enable_thermal_monitoring ? "yes" : "no",
           g_perf_monitor->config.enable_memory_monitoring ? "yes" : "no",
           g_perf_monitor->config.enable_network_monitoring ? "yes" : "no");

    return 0;
}

// Get current system resource usage
system_resource_usage_t performance_monitor_get_current_usage(void) {
    if (!g_perf_monitor) {
        system_resource_usage_t empty = {0};
        return empty;
    }

    pthread_mutex_lock(&g_perf_monitor->monitor_mutex);
    system_resource_usage_t usage = g_perf_monitor->current_usage;
    pthread_mutex_unlock(&g_perf_monitor->monitor_mutex);

    return usage;
}

// Check thermal status
bool performance_monitor_is_thermal_throttling(void) {
    if (!g_perf_monitor) return false;

    for (uint32_t i = 0; i < g_perf_monitor->thermal_zone_count; i++) {
        if (g_perf_monitor->thermal_zones[i].throttling) {
            return true;
        }
    }

    return false;
}

// Get performance statistics
void performance_monitor_get_stats(void) {
    if (!g_perf_monitor) {
        printf("[OPTIMIZER] Performance monitor not initialized\n");
        return;
    }

    pthread_mutex_lock(&g_perf_monitor->monitor_mutex);

    printf("\n[OPTIMIZER] Performance Monitor Statistics\n");
    printf("=========================================\n");

    printf("Monitoring Status:\n");
    printf("  Total Samples: %lu\n", atomic_load(&g_perf_monitor->total_samples));
    printf("  Thermal Events: %lu\n", atomic_load(&g_perf_monitor->thermal_events));
    printf("  Throttling Events: %lu\n", atomic_load(&g_perf_monitor->throttling_events));
    printf("  Adaptive Scaling Events: %lu\n", atomic_load(&g_perf_monitor->adaptive_scaling_events));

    printf("\nCurrent System Usage:\n");
    system_resource_usage_t *usage = &g_perf_monitor->current_usage;
    printf("  CPU Utilization: %.2f%%\n", usage->cpu_utilization_percent);
    printf("  Memory Utilization: %.2f%% (%.1f MB / %.1f MB)\n",
           usage->memory_utilization_percent,
           usage->memory_used_kb / 1024.0f,
           usage->memory_total_kb / 1024.0f);
    printf("  Network RX: %.2f MB/s\n", usage->network_rx_bytes_per_sec / (1024.0f * 1024.0f));
    printf("  Network TX: %.2f MB/s\n", usage->network_tx_bytes_per_sec / (1024.0f * 1024.0f));
    printf("  Context Switches: %lu/s\n", usage->context_switches_per_sec);
    printf("  Interrupts: %lu/s\n", usage->interrupts_per_sec);

    printf("\nPeak Usage:\n");
    system_resource_usage_t *peak = &g_perf_monitor->peak_usage;
    printf("  Peak CPU: %.2f%%\n", peak->cpu_utilization_percent);
    printf("  Peak Memory: %.2f%%\n", peak->memory_utilization_percent);

    printf("\nThermal Status:\n");
    for (uint32_t i = 0; i < g_perf_monitor->thermal_zone_count; i++) {
        thermal_zone_t *zone = &g_perf_monitor->thermal_zones[i];
        printf("  Zone %d (%s): %.1f°C %s\n",
               zone->zone_id, zone->type, zone->temperature_celsius,
               zone->throttling ? "[THROTTLING]" : "");
    }

    pthread_mutex_unlock(&g_perf_monitor->monitor_mutex);
}

// Update application-specific metrics
void performance_monitor_update_dns_queries(uint64_t queries_per_sec) {
    if (!g_perf_monitor) return;

    pthread_mutex_lock(&g_perf_monitor->monitor_mutex);
    g_perf_monitor->current_usage.dns_queries_per_sec = queries_per_sec;
    pthread_mutex_unlock(&g_perf_monitor->monitor_mutex);
}

void performance_monitor_update_http_requests(uint64_t requests_per_sec) {
    if (!g_perf_monitor) return;

    pthread_mutex_lock(&g_perf_monitor->monitor_mutex);
    g_perf_monitor->current_usage.http_requests_per_sec = requests_per_sec;
    pthread_mutex_unlock(&g_perf_monitor->monitor_mutex);
}

void performance_monitor_update_recon_ops(uint64_t ops_per_sec) {
    if (!g_perf_monitor) return;

    pthread_mutex_lock(&g_perf_monitor->monitor_mutex);
    g_perf_monitor->current_usage.reconnaissance_ops_per_sec = ops_per_sec;
    pthread_mutex_unlock(&g_perf_monitor->monitor_mutex);
}

void performance_monitor_update_response_time(float avg_response_time_ms) {
    if (!g_perf_monitor) return;

    pthread_mutex_lock(&g_perf_monitor->monitor_mutex);
    g_perf_monitor->current_usage.average_response_time_ms = avg_response_time_ms;
    pthread_mutex_unlock(&g_perf_monitor->monitor_mutex);
}

// Shutdown performance monitor
void performance_monitor_shutdown(void) {
    if (!g_perf_monitor) return;

    printf("[OPTIMIZER] Shutting down performance monitor...\n");

    // Stop monitoring threads
    atomic_store(&g_perf_monitor->monitoring_active, false);

    if (g_perf_monitor->monitoring_thread) {
        pthread_join(g_perf_monitor->monitoring_thread, NULL);
    }

    if (g_perf_monitor->thermal_thread) {
        pthread_join(g_perf_monitor->thermal_thread, NULL);
    }

    // Print final statistics
    performance_monitor_get_stats();

    // Clean up
    pthread_mutex_destroy(&g_perf_monitor->monitor_mutex);
    free(g_perf_monitor);
    g_perf_monitor = NULL;

    printf("[OPTIMIZER] Performance monitor shutdown complete\n");
}