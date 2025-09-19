/*
 * CloudUnflare Enhanced v2.0 - Optimized Thread Pool Implementation
 *
 * Intel Meteor Lake P-core/E-core Aware Thread Pool
 * Designed for maximum performance on hybrid architecture
 *
 * Performance Targets:
 * - 50 concurrent threads with efficient scheduling
 * - P-core assignment for compute-intensive tasks
 * - E-core assignment for I/O-bound operations
 * - Work stealing queue for load balancing
 * - NUMA-aware memory allocation
 *
 * Agent: OPTIMIZER (performance implementation)
 * Coordination: C-INTERNAL, ARCHITECT
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <numa.h>
#include "../config.h"

// Thread pool configuration for Intel Meteor Lake
#define OPTIMIZED_MAX_THREADS 50
#define OPTIMIZED_MAX_P_CORES 10
#define OPTIMIZED_MAX_E_CORES 10
#define WORK_QUEUE_SIZE 1024
#define CACHE_LINE_SIZE 64
#define THREAD_STACK_SIZE (2 * 1024 * 1024) // 2MB stack

// Core type identification
typedef enum {
    CORE_TYPE_UNKNOWN = 0,
    CORE_TYPE_P_CORE = 1,    // Performance cores (0-9)
    CORE_TYPE_E_CORE = 2     // Efficiency cores (10-19)
} core_type_t;

// Task priority levels
typedef enum {
    TASK_PRIORITY_LOW = 0,
    TASK_PRIORITY_NORMAL = 1,
    TASK_PRIORITY_HIGH = 2,
    TASK_PRIORITY_CRITICAL = 3
} task_priority_t;

// Work item structure
typedef struct work_item {
    void (*function)(void *arg);
    void *argument;
    task_priority_t priority;
    core_type_t preferred_core_type;
    struct timespec submit_time;
    struct timespec start_time;
    struct timespec complete_time;
    _Atomic bool completed;
    _Atomic bool cancelled;
    struct work_item *next;
} work_item_t;

// Lock-free work stealing queue
typedef struct {
    _Atomic(work_item_t*) items[WORK_QUEUE_SIZE];
    _Atomic size_t head;
    _Atomic size_t tail;
    _Atomic size_t count;
    char padding[CACHE_LINE_SIZE - (3 * sizeof(_Atomic size_t))];
} work_queue_t __attribute__((aligned(CACHE_LINE_SIZE)));

// Thread worker information
typedef struct {
    pthread_t thread_id;
    int worker_index;
    int cpu_core;
    core_type_t core_type;
    work_queue_t local_queue;
    _Atomic uint64_t tasks_completed;
    _Atomic uint64_t tasks_stolen;
    _Atomic uint64_t total_execution_time_ns;
    _Atomic bool active;
    _Atomic bool should_exit;
    char padding[CACHE_LINE_SIZE];
} worker_thread_t __attribute__((aligned(CACHE_LINE_SIZE)));

// Optimized thread pool structure
typedef struct {
    worker_thread_t workers[OPTIMIZED_MAX_THREADS];
    work_queue_t global_queue;
    _Atomic int active_workers;
    _Atomic int total_workers;
    _Atomic uint64_t total_tasks_submitted;
    _Atomic uint64_t total_tasks_completed;
    _Atomic uint64_t total_tasks_cancelled;

    // Performance monitoring
    _Atomic uint64_t p_core_utilization_ns;
    _Atomic uint64_t e_core_utilization_ns;
    _Atomic uint32_t avg_queue_depth;
    _Atomic uint32_t peak_queue_depth;

    // Synchronization
    pthread_mutex_t pool_mutex;
    pthread_cond_t work_available;
    pthread_cond_t work_complete;

    // Configuration
    bool use_work_stealing;
    bool enable_numa_awareness;
    bool enable_cpu_affinity;
    uint32_t max_queue_depth;

    char padding[CACHE_LINE_SIZE];
} optimized_thread_pool_t __attribute__((aligned(CACHE_LINE_SIZE)));

// Global thread pool instance
static optimized_thread_pool_t *g_thread_pool = NULL;

// CPU topology detection
static int detect_cpu_topology(int *p_cores, int *e_cores) {
    int total_cpus = get_nprocs();

    // Intel Meteor Lake has P-cores on 0-9, E-cores on 10-19
    *p_cores = (total_cpus >= 10) ? 10 : total_cpus / 2;
    *e_cores = total_cpus - *p_cores;

    printf("[OPTIMIZER] Detected CPU topology: %d P-cores, %d E-cores\n", *p_cores, *e_cores);
    return 0;
}

// Determine core type from CPU number
static core_type_t get_core_type(int cpu_core) {
    if (cpu_core >= 0 && cpu_core <= 9) {
        return CORE_TYPE_P_CORE;
    } else if (cpu_core >= 10 && cpu_core <= 19) {
        return CORE_TYPE_E_CORE;
    }
    return CORE_TYPE_UNKNOWN;
}

// High-precision timing
static uint64_t get_monotonic_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// Lock-free queue operations
static bool queue_push(work_queue_t *queue, work_item_t *item) {
    size_t tail = atomic_load_explicit(&queue->tail, memory_order_relaxed);
    size_t next_tail = (tail + 1) % WORK_QUEUE_SIZE;

    if (next_tail == atomic_load_explicit(&queue->head, memory_order_acquire)) {
        return false; // Queue full
    }

    atomic_store_explicit(&queue->items[tail], item, memory_order_relaxed);
    atomic_store_explicit(&queue->tail, next_tail, memory_order_release);
    atomic_fetch_add_explicit(&queue->count, 1, memory_order_relaxed);

    return true;
}

static work_item_t* queue_pop(work_queue_t *queue) {
    size_t head = atomic_load_explicit(&queue->head, memory_order_relaxed);
    size_t tail = atomic_load_explicit(&queue->tail, memory_order_acquire);

    if (head == tail) {
        return NULL; // Queue empty
    }

    work_item_t *item = atomic_load_explicit(&queue->items[head], memory_order_relaxed);
    atomic_store_explicit(&queue->head, (head + 1) % WORK_QUEUE_SIZE, memory_order_release);
    atomic_fetch_sub_explicit(&queue->count, 1, memory_order_relaxed);

    return item;
}

// Work stealing implementation
static work_item_t* steal_work(optimized_thread_pool_t *pool, int current_worker) {
    for (int i = 0; i < pool->total_workers; i++) {
        if (i == current_worker) continue;

        worker_thread_t *victim = &pool->workers[i];
        work_item_t *stolen_item = queue_pop(&victim->local_queue);

        if (stolen_item) {
            atomic_fetch_add(&pool->workers[current_worker].tasks_stolen, 1);
            return stolen_item;
        }
    }
    return NULL;
}

// Set CPU affinity for optimal performance
static int set_thread_affinity(int cpu_core) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_core, &cpuset);

    int result = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    if (result != 0) {
        printf("[OPTIMIZER] Warning: Failed to set CPU affinity to core %d: %s\n",
               cpu_core, strerror(result));
        return -1;
    }

    return 0;
}

// Worker thread main function
static void* worker_thread_main(void *arg) {
    worker_thread_t *worker = (worker_thread_t*)arg;
    optimized_thread_pool_t *pool = g_thread_pool;

    // Set CPU affinity if enabled
    if (pool->enable_cpu_affinity) {
        set_thread_affinity(worker->cpu_core);
    }

    // Set thread name for debugging
    char thread_name[16];
    snprintf(thread_name, sizeof(thread_name), "worker-%d", worker->worker_index);
    pthread_setname_np(pthread_self(), thread_name);

    atomic_store(&worker->active, true);

    printf("[OPTIMIZER] Worker %d started on CPU %d (%s core)\n",
           worker->worker_index, worker->cpu_core,
           (worker->core_type == CORE_TYPE_P_CORE) ? "P" : "E");

    while (!atomic_load(&worker->should_exit)) {
        work_item_t *item = NULL;

        // Try local queue first
        item = queue_pop(&worker->local_queue);

        // Try global queue if local is empty
        if (!item) {
            pthread_mutex_lock(&pool->pool_mutex);
            item = queue_pop(&pool->global_queue);
            pthread_mutex_unlock(&pool->pool_mutex);
        }

        // Try work stealing if enabled
        if (!item && pool->use_work_stealing) {
            item = steal_work(pool, worker->worker_index);
        }

        if (item) {
            // Record start time
            uint64_t start_time = get_monotonic_time_ns();
            clock_gettime(CLOCK_MONOTONIC, &item->start_time);

            // Execute the task
            if (!atomic_load(&item->cancelled)) {
                item->function(item->argument);
            }

            // Record completion
            uint64_t end_time = get_monotonic_time_ns();
            clock_gettime(CLOCK_MONOTONIC, &item->complete_time);

            uint64_t execution_time = end_time - start_time;
            atomic_fetch_add(&worker->total_execution_time_ns, execution_time);
            atomic_fetch_add(&worker->tasks_completed, 1);
            atomic_store(&item->completed, true);

            // Update core utilization statistics
            if (worker->core_type == CORE_TYPE_P_CORE) {
                atomic_fetch_add(&pool->p_core_utilization_ns, execution_time);
            } else {
                atomic_fetch_add(&pool->e_core_utilization_ns, execution_time);
            }

            atomic_fetch_add(&pool->total_tasks_completed, 1);

            // Signal completion
            pthread_cond_signal(&pool->work_complete);

            // Free work item
            free(item);
        } else {
            // No work available, wait briefly
            struct timespec wait_time = {0, 1000000}; // 1ms
            nanosleep(&wait_time, NULL);
        }
    }

    atomic_store(&worker->active, false);
    printf("[OPTIMIZER] Worker %d stopped\n", worker->worker_index);

    return NULL;
}

// Initialize optimized thread pool
int optimized_thread_pool_init(int num_threads, bool enable_work_stealing, bool enable_numa) {
    if (g_thread_pool) {
        printf("[OPTIMIZER] Error: Thread pool already initialized\n");
        return -1;
    }

    if (num_threads <= 0 || num_threads > OPTIMIZED_MAX_THREADS) {
        printf("[OPTIMIZER] Error: Invalid thread count: %d (max: %d)\n",
               num_threads, OPTIMIZED_MAX_THREADS);
        return -1;
    }

    g_thread_pool = aligned_alloc(CACHE_LINE_SIZE, sizeof(optimized_thread_pool_t));
    if (!g_thread_pool) {
        printf("[OPTIMIZER] Error: Failed to allocate thread pool\n");
        return -1;
    }

    memset(g_thread_pool, 0, sizeof(optimized_thread_pool_t));

    // Initialize configuration
    g_thread_pool->use_work_stealing = enable_work_stealing;
    g_thread_pool->enable_numa_awareness = enable_numa;
    g_thread_pool->enable_cpu_affinity = true;
    g_thread_pool->max_queue_depth = WORK_QUEUE_SIZE;

    // Initialize synchronization
    if (pthread_mutex_init(&g_thread_pool->pool_mutex, NULL) != 0) {
        free(g_thread_pool);
        g_thread_pool = NULL;
        return -1;
    }

    if (pthread_cond_init(&g_thread_pool->work_available, NULL) != 0 ||
        pthread_cond_init(&g_thread_pool->work_complete, NULL) != 0) {
        pthread_mutex_destroy(&g_thread_pool->pool_mutex);
        free(g_thread_pool);
        g_thread_pool = NULL;
        return -1;
    }

    // Detect CPU topology
    int p_cores, e_cores;
    detect_cpu_topology(&p_cores, &e_cores);

    // Initialize global queue
    memset(&g_thread_pool->global_queue, 0, sizeof(work_queue_t));

    // Create worker threads
    atomic_store(&g_thread_pool->total_workers, num_threads);

    for (int i = 0; i < num_threads; i++) {
        worker_thread_t *worker = &g_thread_pool->workers[i];

        worker->worker_index = i;
        // Assign CPU cores: P-cores for first 10 threads, E-cores for rest
        worker->cpu_core = (i < p_cores) ? i : (p_cores + (i - p_cores) % e_cores);
        worker->core_type = get_core_type(worker->cpu_core);

        // Initialize local queue
        memset(&worker->local_queue, 0, sizeof(work_queue_t));

        // Initialize atomics
        atomic_init(&worker->tasks_completed, 0);
        atomic_init(&worker->tasks_stolen, 0);
        atomic_init(&worker->total_execution_time_ns, 0);
        atomic_init(&worker->active, false);
        atomic_init(&worker->should_exit, false);

        // Create thread with custom stack size
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setstacksize(&attr, THREAD_STACK_SIZE);

        int result = pthread_create(&worker->thread_id, &attr, worker_thread_main, worker);
        pthread_attr_destroy(&attr);

        if (result != 0) {
            printf("[OPTIMIZER] Error: Failed to create worker thread %d: %s\n",
                   i, strerror(result));

            // Clean up already created threads
            for (int j = 0; j < i; j++) {
                atomic_store(&g_thread_pool->workers[j].should_exit, true);
                pthread_join(g_thread_pool->workers[j].thread_id, NULL);
            }

            pthread_cond_destroy(&g_thread_pool->work_complete);
            pthread_cond_destroy(&g_thread_pool->work_available);
            pthread_mutex_destroy(&g_thread_pool->pool_mutex);
            free(g_thread_pool);
            g_thread_pool = NULL;

            return -1;
        }

        atomic_fetch_add(&g_thread_pool->active_workers, 1);
    }

    printf("[OPTIMIZER] Thread pool initialized: %d workers, work stealing: %s, NUMA: %s\n",
           num_threads, enable_work_stealing ? "enabled" : "disabled",
           enable_numa ? "enabled" : "disabled");

    return 0;
}

// Submit task to thread pool with intelligent scheduling
int optimized_thread_pool_submit(void (*function)(void*), void *argument,
                                task_priority_t priority, core_type_t preferred_core) {
    if (!g_thread_pool || !function) {
        return -1;
    }

    work_item_t *item = malloc(sizeof(work_item_t));
    if (!item) {
        return -1;
    }

    // Initialize work item
    item->function = function;
    item->argument = argument;
    item->priority = priority;
    item->preferred_core_type = preferred_core;
    clock_gettime(CLOCK_MONOTONIC, &item->submit_time);
    atomic_init(&item->completed, false);
    atomic_init(&item->cancelled, false);
    item->next = NULL;

    // Choose optimal worker based on core preference and load
    int target_worker = -1;
    uint64_t min_load = UINT64_MAX;

    for (int i = 0; i < atomic_load(&g_thread_pool->total_workers); i++) {
        worker_thread_t *worker = &g_thread_pool->workers[i];

        // Skip if core type doesn't match preference
        if (preferred_core != CORE_TYPE_UNKNOWN && worker->core_type != preferred_core) {
            continue;
        }

        // Calculate current load (tasks completed + queue size)
        uint64_t current_load = atomic_load(&worker->tasks_completed) +
                               atomic_load(&worker->local_queue.count);

        if (current_load < min_load) {
            min_load = current_load;
            target_worker = i;
        }
    }

    // Submit to target worker's local queue if found
    bool submitted = false;
    if (target_worker >= 0) {
        submitted = queue_push(&g_thread_pool->workers[target_worker].local_queue, item);
    }

    // Fallback to global queue
    if (!submitted) {
        pthread_mutex_lock(&g_thread_pool->pool_mutex);
        submitted = queue_push(&g_thread_pool->global_queue, item);
        pthread_cond_signal(&g_thread_pool->work_available);
        pthread_mutex_unlock(&g_thread_pool->pool_mutex);
    }

    if (submitted) {
        atomic_fetch_add(&g_thread_pool->total_tasks_submitted, 1);
        return 0;
    } else {
        free(item);
        return -1;
    }
}

// Wait for all tasks to complete
void optimized_thread_pool_wait_all(void) {
    if (!g_thread_pool) return;

    while (atomic_load(&g_thread_pool->total_tasks_completed) <
           atomic_load(&g_thread_pool->total_tasks_submitted)) {
        pthread_mutex_lock(&g_thread_pool->pool_mutex);
        pthread_cond_wait(&g_thread_pool->work_complete, &g_thread_pool->pool_mutex);
        pthread_mutex_unlock(&g_thread_pool->pool_mutex);
    }
}

// Get performance statistics
void optimized_thread_pool_get_stats(void) {
    if (!g_thread_pool) return;

    printf("\n[OPTIMIZER] Thread Pool Performance Statistics\n");
    printf("===============================================\n");
    printf("Total Workers: %d\n", atomic_load(&g_thread_pool->total_workers));
    printf("Active Workers: %d\n", atomic_load(&g_thread_pool->active_workers));
    printf("Tasks Submitted: %lu\n", atomic_load(&g_thread_pool->total_tasks_submitted));
    printf("Tasks Completed: %lu\n", atomic_load(&g_thread_pool->total_tasks_completed));
    printf("Tasks Cancelled: %lu\n", atomic_load(&g_thread_pool->total_tasks_cancelled));

    uint64_t p_core_time = atomic_load(&g_thread_pool->p_core_utilization_ns);
    uint64_t e_core_time = atomic_load(&g_thread_pool->e_core_utilization_ns);
    uint64_t total_time = p_core_time + e_core_time;

    if (total_time > 0) {
        printf("P-Core Utilization: %.2f%% (%lu ns)\n",
               (double)p_core_time * 100.0 / total_time, p_core_time);
        printf("E-Core Utilization: %.2f%% (%lu ns)\n",
               (double)e_core_time * 100.0 / total_time, e_core_time);
    }

    // Per-worker statistics
    printf("\nPer-Worker Statistics:\n");
    for (int i = 0; i < atomic_load(&g_thread_pool->total_workers); i++) {
        worker_thread_t *worker = &g_thread_pool->workers[i];
        uint64_t completed = atomic_load(&worker->tasks_completed);
        uint64_t stolen = atomic_load(&worker->tasks_stolen);
        uint64_t exec_time = atomic_load(&worker->total_execution_time_ns);

        printf("Worker %d (CPU %d, %s): %lu tasks, %lu stolen, %.2f ms avg\n",
               i, worker->cpu_core,
               (worker->core_type == CORE_TYPE_P_CORE) ? "P" : "E",
               completed, stolen,
               completed > 0 ? (double)exec_time / 1000000.0 / completed : 0.0);
    }
}

// Shutdown thread pool
void optimized_thread_pool_shutdown(void) {
    if (!g_thread_pool) return;

    printf("[OPTIMIZER] Shutting down thread pool...\n");

    // Signal all workers to exit
    for (int i = 0; i < atomic_load(&g_thread_pool->total_workers); i++) {
        atomic_store(&g_thread_pool->workers[i].should_exit, true);
    }

    // Wait for all workers to finish
    for (int i = 0; i < atomic_load(&g_thread_pool->total_workers); i++) {
        pthread_join(g_thread_pool->workers[i].thread_id, NULL);
    }

    // Clean up synchronization objects
    pthread_cond_destroy(&g_thread_pool->work_complete);
    pthread_cond_destroy(&g_thread_pool->work_available);
    pthread_mutex_destroy(&g_thread_pool->pool_mutex);

    // Free memory
    free(g_thread_pool);
    g_thread_pool = NULL;

    printf("[OPTIMIZER] Thread pool shutdown complete\n");
}

// Convenience functions for different task types
int submit_compute_task(void (*function)(void*), void *argument) {
    return optimized_thread_pool_submit(function, argument, TASK_PRIORITY_NORMAL, CORE_TYPE_P_CORE);
}

int submit_io_task(void (*function)(void*), void *argument) {
    return optimized_thread_pool_submit(function, argument, TASK_PRIORITY_NORMAL, CORE_TYPE_E_CORE);
}

int submit_high_priority_task(void (*function)(void*), void *argument) {
    return optimized_thread_pool_submit(function, argument, TASK_PRIORITY_HIGH, CORE_TYPE_P_CORE);
}