/*
 * CloudUnflare Enhanced v2.0 - Optimized Memory Pool Implementation
 *
 * Cache-aligned memory pool with NUMA awareness
 * Designed for minimal allocation overhead and maximum performance
 *
 * Performance Targets:
 * - <500MB total memory usage
 * - <50% heap fragmentation
 * - Cache-line aligned allocations
 * - NUMA-aware memory placement
 * - Lock-free fast path allocation
 *
 * Agent: OPTIMIZER (memory management)
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
#include "platform_compat.h"
#include <errno.h>
#ifdef _WIN32
    /* NUMA not available on Windows - use fallback */
    #define numa_available() (-1)
    #define numa_node_of_cpu(cpu) (0)
    #define numa_run_on_node(node) (0)
#else
    #include <numa.h>
#endif
#include "../config.h"

// Memory pool configuration
#define MEMORY_POOL_MAX_SIZE (500 * 1024 * 1024)  // 500MB total limit
#define CACHE_LINE_SIZE 64
#define PAGE_SIZE 4096
#define HUGE_PAGE_SIZE (2 * 1024 * 1024)  // 2MB huge pages

// Memory block sizes (powers of 2 for efficient allocation)
#define MIN_BLOCK_SIZE 32
#define MAX_BLOCK_SIZE (64 * 1024)  // 64KB
#define NUM_SIZE_CLASSES 12

// Pool statistics and monitoring
#define MEMORY_STATS_INTERVAL_SEC 60

// Memory block header
typedef struct memory_block {
    uint32_t size;
    uint32_t magic;
    uint64_t alloc_time_ns;
    struct memory_block *next;
    char padding[CACHE_LINE_SIZE - sizeof(uint32_t) * 2 - sizeof(uint64_t) - sizeof(void*)];
} __attribute__((aligned(CACHE_LINE_SIZE))) memory_block_t;

// Free list for each size class
typedef struct {
    _Atomic(memory_block_t*) head;
    _Atomic uint64_t total_blocks;
    _Atomic uint64_t free_blocks;
    _Atomic uint64_t allocations;
    _Atomic uint64_t deallocations;
    pthread_mutex_t mutex;
    char padding[CACHE_LINE_SIZE];
} __attribute__((aligned(CACHE_LINE_SIZE))) free_list_t;

// Memory pool arena
typedef struct {
    void *base_address;
    size_t total_size;
    size_t used_size;
    _Atomic size_t current_offset;
    int numa_node;
    bool use_huge_pages;
    pthread_mutex_t arena_mutex;
    char padding[CACHE_LINE_SIZE];
} __attribute__((aligned(CACHE_LINE_SIZE))) memory_arena_t;

// Main memory pool structure
typedef struct {
    memory_arena_t arenas[8];  // Support up to 8 NUMA nodes
    free_list_t size_classes[NUM_SIZE_CLASSES];
    uint32_t size_class_sizes[NUM_SIZE_CLASSES];

    // Global statistics
    _Atomic uint64_t total_allocated_bytes;
    _Atomic uint64_t total_freed_bytes;
    _Atomic uint64_t peak_memory_usage;
    _Atomic uint64_t current_memory_usage;
    _Atomic uint64_t fragmentation_waste;
    _Atomic uint32_t active_allocations;

    // Performance metrics
    _Atomic uint64_t fast_path_allocations;
    _Atomic uint64_t slow_path_allocations;
    _Atomic uint64_t cache_hits;
    _Atomic uint64_t cache_misses;

    // Configuration
    bool enable_numa_awareness;
    bool enable_huge_pages;
    bool enable_memory_tracking;
    uint32_t max_arenas;

    // Synchronization
    pthread_mutex_t pool_mutex;

    char padding[CACHE_LINE_SIZE];
} __attribute__((aligned(CACHE_LINE_SIZE))) optimized_memory_pool_t;

// Global memory pool instance
static optimized_memory_pool_t *g_memory_pool = NULL;
static const uint32_t MEMORY_MAGIC = 0xDEADBEEF;

// Get high-precision timestamp
static uint64_t get_monotonic_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// Calculate size class index
static int get_size_class_index(size_t size) {
    if (size <= MIN_BLOCK_SIZE) return 0;

    int index = 0;
    size_t class_size = MIN_BLOCK_SIZE;

    while (class_size < size && index < NUM_SIZE_CLASSES - 1) {
        class_size *= 2;
        index++;
    }

    return index;
}

// Round up to nearest power of 2
static size_t round_up_to_power_of_2(size_t size) {
    if (size == 0) return MIN_BLOCK_SIZE;

    size--;
    size |= size >> 1;
    size |= size >> 2;
    size |= size >> 4;
    size |= size >> 8;
    size |= size >> 16;
    size |= size >> 32;
    size++;

    return (size < MIN_BLOCK_SIZE) ? MIN_BLOCK_SIZE : size;
}

// Get optimal NUMA node for current thread
static int get_optimal_numa_node(void) {
    if (!g_memory_pool->enable_numa_awareness) {
        return 0;
    }

    int cpu = sched_getcpu();
    if (cpu < 0) return 0;

    return numa_node_of_cpu(cpu);
}

// Allocate memory arena with optional huge pages
static int allocate_arena(memory_arena_t *arena, size_t size, int numa_node) {
    arena->total_size = size;
    arena->used_size = 0;
    arena->numa_node = numa_node;
    arena->use_huge_pages = g_memory_pool->enable_huge_pages;
    atomic_init(&arena->current_offset, 0);

    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    if (arena->use_huge_pages) {
        flags |= MAP_HUGETLB;
    }

    // Try NUMA-aware allocation
    if (g_memory_pool->enable_numa_awareness && numa_node >= 0) {
        struct bitmask *nodes = numa_allocate_nodemask();
        numa_bitmask_clearall(nodes);
        numa_bitmask_setbit(nodes, numa_node);
        numa_set_membind(nodes);
        numa_free_nodemask(nodes);
    }

    arena->base_address = mmap(NULL, size, PROT_READ | PROT_WRITE, flags, -1, 0);

    if (arena->base_address == MAP_FAILED) {
        // Fallback without huge pages
        if (arena->use_huge_pages) {
            arena->use_huge_pages = false;
            flags &= ~MAP_HUGETLB;
            arena->base_address = mmap(NULL, size, PROT_READ | PROT_WRITE, flags, -1, 0);
        }
    }

    if (arena->base_address == MAP_FAILED) {
        printf("[OPTIMIZER] Error: Failed to allocate memory arena: %s\n", strerror(errno));
        return -1;
    }

    // Initialize arena mutex
    if (pthread_mutex_init(&arena->arena_mutex, NULL) != 0) {
        munmap(arena->base_address, size);
        return -1;
    }

    printf("[OPTIMIZER] Allocated arena: %lu MB on NUMA node %d (huge pages: %s)\n",
           size / (1024 * 1024), numa_node, arena->use_huge_pages ? "yes" : "no");

    return 0;
}

// Allocate from arena (bump allocator)
static void* arena_allocate(memory_arena_t *arena, size_t size, size_t alignment) {
    if (!arena->base_address) return NULL;

    // Align size to cache line boundary
    size_t aligned_size = (size + alignment - 1) & ~(alignment - 1);

    size_t current_offset = atomic_load(&arena->current_offset);
    size_t new_offset = current_offset + aligned_size;

    if (new_offset > arena->total_size) {
        return NULL; // Arena exhausted
    }

    // Atomic compare-and-swap to claim memory
    if (!atomic_compare_exchange_weak(&arena->current_offset, &current_offset, new_offset)) {
        return NULL; // Another thread claimed this memory
    }

    arena->used_size = new_offset;
    return (char*)arena->base_address + current_offset;
}

// Initialize memory pool
int optimized_memory_pool_init(size_t total_size, bool enable_numa, bool enable_huge_pages) {
    if (g_memory_pool) {
        printf("[OPTIMIZER] Error: Memory pool already initialized\n");
        return -1;
    }

    if (total_size > MEMORY_POOL_MAX_SIZE) {
        printf("[OPTIMIZER] Warning: Requested size %lu MB exceeds limit, using %lu MB\n",
               total_size / (1024 * 1024), MEMORY_POOL_MAX_SIZE / (1024 * 1024));
        total_size = MEMORY_POOL_MAX_SIZE;
    }

    g_memory_pool = aligned_alloc(CACHE_LINE_SIZE, sizeof(optimized_memory_pool_t));
    if (!g_memory_pool) {
        printf("[OPTIMIZER] Error: Failed to allocate memory pool structure\n");
        return -1;
    }

    memset(g_memory_pool, 0, sizeof(optimized_memory_pool_t));

    // Initialize configuration
    g_memory_pool->enable_numa_awareness = enable_numa && numa_available() >= 0;
    g_memory_pool->enable_huge_pages = enable_huge_pages;
    g_memory_pool->enable_memory_tracking = true;
    g_memory_pool->max_arenas = g_memory_pool->enable_numa_awareness ? numa_num_configured_nodes() : 1;

    // Initialize size classes
    for (int i = 0; i < NUM_SIZE_CLASSES; i++) {
        g_memory_pool->size_class_sizes[i] = MIN_BLOCK_SIZE << i;
        atomic_init(&g_memory_pool->size_classes[i].head, NULL);
        atomic_init(&g_memory_pool->size_classes[i].total_blocks, 0);
        atomic_init(&g_memory_pool->size_classes[i].free_blocks, 0);
        atomic_init(&g_memory_pool->size_classes[i].allocations, 0);
        atomic_init(&g_memory_pool->size_classes[i].deallocations, 0);

        if (pthread_mutex_init(&g_memory_pool->size_classes[i].mutex, NULL) != 0) {
            // Clean up previous mutexes
            for (int j = 0; j < i; j++) {
                pthread_mutex_destroy(&g_memory_pool->size_classes[j].mutex);
            }
            free(g_memory_pool);
            g_memory_pool = NULL;
            return -1;
        }
    }

    // Initialize global mutex
    if (pthread_mutex_init(&g_memory_pool->pool_mutex, NULL) != 0) {
        for (int i = 0; i < NUM_SIZE_CLASSES; i++) {
            pthread_mutex_destroy(&g_memory_pool->size_classes[i].mutex);
        }
        free(g_memory_pool);
        g_memory_pool = NULL;
        return -1;
    }

    // Initialize arenas
    size_t arena_size = total_size / g_memory_pool->max_arenas;
    for (uint32_t i = 0; i < g_memory_pool->max_arenas; i++) {
        int numa_node = g_memory_pool->enable_numa_awareness ? i : -1;

        if (allocate_arena(&g_memory_pool->arenas[i], arena_size, numa_node) != 0) {
            printf("[OPTIMIZER] Warning: Failed to allocate arena %u\n", i);
            // Continue with fewer arenas
            g_memory_pool->max_arenas = i;
            break;
        }
    }

    if (g_memory_pool->max_arenas == 0) {
        printf("[OPTIMIZER] Error: Failed to allocate any memory arenas\n");
        pthread_mutex_destroy(&g_memory_pool->pool_mutex);
        for (int i = 0; i < NUM_SIZE_CLASSES; i++) {
            pthread_mutex_destroy(&g_memory_pool->size_classes[i].mutex);
        }
        free(g_memory_pool);
        g_memory_pool = NULL;
        return -1;
    }

    // Initialize statistics
    atomic_init(&g_memory_pool->total_allocated_bytes, 0);
    atomic_init(&g_memory_pool->total_freed_bytes, 0);
    atomic_init(&g_memory_pool->peak_memory_usage, 0);
    atomic_init(&g_memory_pool->current_memory_usage, 0);
    atomic_init(&g_memory_pool->fragmentation_waste, 0);
    atomic_init(&g_memory_pool->active_allocations, 0);
    atomic_init(&g_memory_pool->fast_path_allocations, 0);
    atomic_init(&g_memory_pool->slow_path_allocations, 0);
    atomic_init(&g_memory_pool->cache_hits, 0);
    atomic_init(&g_memory_pool->cache_misses, 0);

    printf("[OPTIMIZER] Memory pool initialized: %lu MB across %u arenas\n",
           total_size / (1024 * 1024), g_memory_pool->max_arenas);
    printf("[OPTIMIZER] NUMA awareness: %s, Huge pages: %s\n",
           g_memory_pool->enable_numa_awareness ? "enabled" : "disabled",
           g_memory_pool->enable_huge_pages ? "enabled" : "disabled");

    return 0;
}

// Fast path allocation from free list
static void* fast_path_allocate(int size_class_index, size_t size) {
    free_list_t *free_list = &g_memory_pool->size_classes[size_class_index];

    // Try lock-free fast path first
    memory_block_t *block = atomic_load(&free_list->head);

    while (block) {
        memory_block_t *next = block->next;
        if (atomic_compare_exchange_weak(&free_list->head, &block, next)) {
            // Successfully claimed block
            atomic_fetch_sub(&free_list->free_blocks, 1);
            atomic_fetch_add(&free_list->allocations, 1);
            atomic_fetch_add(&g_memory_pool->fast_path_allocations, 1);
            atomic_fetch_add(&g_memory_pool->cache_hits, 1);

            // Update statistics
            atomic_fetch_add(&g_memory_pool->current_memory_usage, size);
            atomic_fetch_add(&g_memory_pool->active_allocations, 1);

            block->alloc_time_ns = get_monotonic_time_ns();
            return (char*)block + sizeof(memory_block_t);
        }
        block = atomic_load(&free_list->head);
    }

    return NULL; // No free blocks available
}

// Slow path allocation from arena
static void* slow_path_allocate(size_t size) {
    atomic_fetch_add(&g_memory_pool->slow_path_allocations, 1);
    atomic_fetch_add(&g_memory_pool->cache_misses, 1);

    // Get optimal arena
    int numa_node = get_optimal_numa_node();
    memory_arena_t *arena = &g_memory_pool->arenas[numa_node % g_memory_pool->max_arenas];

    size_t total_size = sizeof(memory_block_t) + size;
    void *raw_memory = arena_allocate(arena, total_size, CACHE_LINE_SIZE);

    if (!raw_memory) {
        // Try other arenas
        for (uint32_t i = 0; i < g_memory_pool->max_arenas; i++) {
            if (i == (uint32_t)(numa_node % g_memory_pool->max_arenas)) continue;

            arena = &g_memory_pool->arenas[i];
            raw_memory = arena_allocate(arena, total_size, CACHE_LINE_SIZE);
            if (raw_memory) break;
        }
    }

    if (!raw_memory) {
        printf("[OPTIMIZER] Error: Memory pool exhausted\n");
        return NULL;
    }

    // Initialize block header
    memory_block_t *block = (memory_block_t*)raw_memory;
    block->size = size;
    block->magic = MEMORY_MAGIC;
    block->alloc_time_ns = get_monotonic_time_ns();
    block->next = NULL;

    // Update statistics
    atomic_fetch_add(&g_memory_pool->total_allocated_bytes, size);
    atomic_fetch_add(&g_memory_pool->current_memory_usage, size);
    atomic_fetch_add(&g_memory_pool->active_allocations, 1);

    uint64_t current_usage = atomic_load(&g_memory_pool->current_memory_usage);
    uint64_t peak_usage = atomic_load(&g_memory_pool->peak_memory_usage);
    if (current_usage > peak_usage) {
        atomic_store(&g_memory_pool->peak_memory_usage, current_usage);
    }

    return (char*)block + sizeof(memory_block_t);
}

// Main allocation function
void* optimized_malloc(size_t size) {
    if (!g_memory_pool || size == 0) {
        return NULL;
    }

    if (size > MAX_BLOCK_SIZE) {
        printf("[OPTIMIZER] Warning: Large allocation requested: %lu bytes\n", size);
        return malloc(size); // Fallback to system allocator
    }

    // Round up to appropriate size class
    size_t actual_size = round_up_to_power_of_2(size);
    int size_class_index = get_size_class_index(actual_size);

    // Try fast path first
    void *ptr = fast_path_allocate(size_class_index, actual_size);
    if (ptr) {
        return ptr;
    }

    // Fall back to slow path
    return slow_path_allocate(actual_size);
}

// Free memory back to pool
void optimized_free(void *ptr) {
    if (!ptr || !g_memory_pool) {
        return;
    }

    // Get block header
    memory_block_t *block = (memory_block_t*)((char*)ptr - sizeof(memory_block_t));

    // Validate magic number
    if (block->magic != MEMORY_MAGIC) {
        printf("[OPTIMIZER] Error: Invalid memory block or corruption detected\n");
        return;
    }

    // Determine size class
    int size_class_index = get_size_class_index(block->size);
    free_list_t *free_list = &g_memory_pool->size_classes[size_class_index];

    // Clear block data for security
    memset(ptr, 0, block->size);

    // Add to free list (lock-free)
    memory_block_t *head = atomic_load(&free_list->head);
    do {
        block->next = head;
    } while (!atomic_compare_exchange_weak(&free_list->head, &head, block));

    // Update statistics
    atomic_fetch_add(&free_list->free_blocks, 1);
    atomic_fetch_add(&free_list->deallocations, 1);
    atomic_fetch_add(&g_memory_pool->total_freed_bytes, block->size);
    atomic_fetch_sub(&g_memory_pool->current_memory_usage, block->size);
    atomic_fetch_sub(&g_memory_pool->active_allocations, 1);
}

// Cache-aligned allocation
void* optimized_aligned_malloc(size_t size, size_t alignment) {
    if (alignment < CACHE_LINE_SIZE) {
        alignment = CACHE_LINE_SIZE;
    }

    // Allocate extra space for alignment
    size_t aligned_size = size + alignment - 1;
    void *ptr = optimized_malloc(aligned_size);

    if (!ptr) return NULL;

    // Align pointer
    uintptr_t aligned_ptr = (uintptr_t)ptr;
    aligned_ptr = (aligned_ptr + alignment - 1) & ~(alignment - 1);

    return (void*)aligned_ptr;
}

// Get memory pool statistics
void optimized_memory_pool_get_stats(void) {
    if (!g_memory_pool) return;

    printf("\n[OPTIMIZER] Memory Pool Performance Statistics\n");
    printf("=============================================\n");

    uint64_t total_allocated = atomic_load(&g_memory_pool->total_allocated_bytes);
    uint64_t total_freed = atomic_load(&g_memory_pool->total_freed_bytes);
    uint64_t current_usage = atomic_load(&g_memory_pool->current_memory_usage);
    uint64_t peak_usage = atomic_load(&g_memory_pool->peak_memory_usage);
    uint32_t active_allocs = atomic_load(&g_memory_pool->active_allocations);

    printf("Total Allocated: %.2f MB\n", total_allocated / (1024.0 * 1024.0));
    printf("Total Freed: %.2f MB\n", total_freed / (1024.0 * 1024.0));
    printf("Current Usage: %.2f MB\n", current_usage / (1024.0 * 1024.0));
    printf("Peak Usage: %.2f MB\n", peak_usage / (1024.0 * 1024.0));
    printf("Active Allocations: %u\n", active_allocs);

    if (peak_usage > 0) {
        printf("Memory Efficiency: %.2f%%\n", (double)current_usage * 100.0 / peak_usage);
    }

    uint64_t fast_path = atomic_load(&g_memory_pool->fast_path_allocations);
    uint64_t slow_path = atomic_load(&g_memory_pool->slow_path_allocations);
    uint64_t cache_hits = atomic_load(&g_memory_pool->cache_hits);
    uint64_t cache_misses = atomic_load(&g_memory_pool->cache_misses);

    if ((fast_path + slow_path) > 0) {
        printf("Fast Path Allocations: %.2f%% (%lu)\n",
               (double)fast_path * 100.0 / (fast_path + slow_path), fast_path);
        printf("Cache Hit Rate: %.2f%% (%lu hits, %lu misses)\n",
               (double)cache_hits * 100.0 / (cache_hits + cache_misses), cache_hits, cache_misses);
    }

    // Per-size-class statistics
    printf("\nSize Class Statistics:\n");
    for (int i = 0; i < NUM_SIZE_CLASSES; i++) {
        free_list_t *list = &g_memory_pool->size_classes[i];
        uint64_t allocs = atomic_load(&list->allocations);
        uint64_t deallocs = atomic_load(&list->deallocations);
        uint64_t free_blocks = atomic_load(&list->free_blocks);

        if (allocs > 0) {
            printf("Size %u: %lu allocs, %lu deallocs, %lu free\n",
                   g_memory_pool->size_class_sizes[i], allocs, deallocs, free_blocks);
        }
    }

    // Arena statistics
    printf("\nArena Statistics:\n");
    for (uint32_t i = 0; i < g_memory_pool->max_arenas; i++) {
        memory_arena_t *arena = &g_memory_pool->arenas[i];
        printf("Arena %u (NUMA %d): %.2f%% used (%.2f MB / %.2f MB)\n",
               i, arena->numa_node,
               (double)arena->used_size * 100.0 / arena->total_size,
               arena->used_size / (1024.0 * 1024.0),
               arena->total_size / (1024.0 * 1024.0));
    }
}

// Shutdown memory pool
void optimized_memory_pool_shutdown(void) {
    if (!g_memory_pool) return;

    printf("[OPTIMIZER] Shutting down memory pool...\n");

    // Print final statistics
    optimized_memory_pool_get_stats();

    // Free arenas
    for (uint32_t i = 0; i < g_memory_pool->max_arenas; i++) {
        memory_arena_t *arena = &g_memory_pool->arenas[i];
        if (arena->base_address) {
            munmap(arena->base_address, arena->total_size);
            pthread_mutex_destroy(&arena->arena_mutex);
        }
    }

    // Destroy mutexes
    pthread_mutex_destroy(&g_memory_pool->pool_mutex);
    for (int i = 0; i < NUM_SIZE_CLASSES; i++) {
        pthread_mutex_destroy(&g_memory_pool->size_classes[i].mutex);
    }

    // Free pool structure
    free(g_memory_pool);
    g_memory_pool = NULL;

    printf("[OPTIMIZER] Memory pool shutdown complete\n");
}
