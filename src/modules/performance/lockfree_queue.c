/*
 * CloudUnflare Enhanced v2.0 - Lock-Free Data Structures
 *
 * High-performance lock-free queue and stack implementations
 * Optimized for minimal contention and maximum throughput
 *
 * Performance Targets:
 * - Zero lock contention in fast path
 * - Millions of operations per second
 * - Cache-friendly memory layout
 * - ABA problem protection
 * - Memory ordering guarantees
 *
 * Agent: OPTIMIZER (lock-free algorithms)
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
#include <time.h>
#include "platform_compat.h"
#include "../config.h"

// Cache line size for optimal performance
#define CACHE_LINE_SIZE 64
#define LOCKFREE_ALIGNMENT 64

// Queue configuration
#define LOCKFREE_QUEUE_MAX_SIZE 65536
#define LOCKFREE_STACK_MAX_SIZE 32768
#define HAZARD_POINTER_MAX_THREADS 64
#define HAZARD_POINTERS_PER_THREAD 8

// Memory reclamation epochs
#define EPOCH_MAX_THREADS 64
#define EPOCH_FREQUENCY 1000

// ABA protection using tagged pointers
typedef struct {
    void *ptr;
    uint64_t tag;
} tagged_pointer_t;

// Lock-free queue node
typedef struct lockfree_queue_node {
    _Atomic(tagged_pointer_t) next;
    void *data;
    uint64_t sequence;
    char padding[CACHE_LINE_SIZE - sizeof(_Atomic(tagged_pointer_t)) - sizeof(void*) - sizeof(uint64_t)];
} __attribute__((aligned(CACHE_LINE_SIZE))) lockfree_queue_node_t;

// Lock-free queue structure
typedef struct {
    _Atomic(tagged_pointer_t) head;
    _Atomic(tagged_pointer_t) tail;
    _Atomic uint64_t size;
    _Atomic uint64_t enqueue_count;
    _Atomic uint64_t dequeue_count;
    _Atomic uint64_t sequence_counter;

    // Performance metrics
    _Atomic uint64_t successful_enqueues;
    _Atomic uint64_t successful_dequeues;
    _Atomic uint64_t failed_enqueues;
    _Atomic uint64_t failed_dequeues;
    _Atomic uint64_t cas_failures;

    char padding[CACHE_LINE_SIZE];
} __attribute__((aligned(CACHE_LINE_SIZE))) lockfree_queue_t;

// Lock-free stack node
typedef struct lockfree_stack_node {
    _Atomic(tagged_pointer_t) next;
    void *data;
    char padding[CACHE_LINE_SIZE - sizeof(_Atomic(tagged_pointer_t)) - sizeof(void*)];
} __attribute__((aligned(CACHE_LINE_SIZE))) lockfree_stack_node_t;

// Lock-free stack structure
typedef struct {
    _Atomic(tagged_pointer_t) top;
    _Atomic uint64_t size;
    _Atomic uint64_t push_count;
    _Atomic uint64_t pop_count;

    // Performance metrics
    _Atomic uint64_t successful_pushes;
    _Atomic uint64_t successful_pops;
    _Atomic uint64_t failed_pushes;
    _Atomic uint64_t failed_pops;
    _Atomic uint64_t cas_failures;

    char padding[CACHE_LINE_SIZE];
} __attribute__((aligned(CACHE_LINE_SIZE))) lockfree_stack_t;

// Hazard pointer record
typedef struct {
    _Atomic(void*) pointer;
    char padding[CACHE_LINE_SIZE - sizeof(_Atomic(void*))];
} __attribute__((aligned(CACHE_LINE_SIZE))) hazard_pointer_t;

// Per-thread hazard pointer structure
typedef struct {
    hazard_pointer_t hazards[HAZARD_POINTERS_PER_THREAD];
    void *retired_list[LOCKFREE_QUEUE_MAX_SIZE];
    _Atomic uint32_t retired_count;
    char padding[CACHE_LINE_SIZE];
} __attribute__((aligned(CACHE_LINE_SIZE))) thread_hazard_record_t;

// Global hazard pointer system
typedef struct {
    thread_hazard_record_t threads[HAZARD_POINTER_MAX_THREADS];
    _Atomic uint32_t active_threads;
    _Atomic uint64_t total_allocations;
    _Atomic uint64_t total_reclamations;
    bool initialized;
} hazard_pointer_system_t;

// Epoch-based memory reclamation
typedef struct {
    _Atomic uint64_t global_epoch;
    _Atomic uint64_t thread_epochs[EPOCH_MAX_THREADS];
    _Atomic uint32_t active_threads;
    void *limbo_lists[3][LOCKFREE_QUEUE_MAX_SIZE];  // 3 epochs worth of memory
    _Atomic uint32_t limbo_counts[3];
} epoch_manager_t;

// Global instances
static hazard_pointer_system_t g_hazard_system = {0};
static epoch_manager_t g_epoch_manager = {0};
static _Thread_local int t_thread_id = -1;
static _Atomic int g_next_thread_id = 0;

// High-precision timing
static uint64_t get_monotonic_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// Get thread-local ID
static int get_thread_id(void) {
    if (t_thread_id == -1) {
        t_thread_id = atomic_fetch_add(&g_next_thread_id, 1);
        if (t_thread_id >= HAZARD_POINTER_MAX_THREADS) {
            t_thread_id = t_thread_id % HAZARD_POINTER_MAX_THREADS;
        }
    }
    return t_thread_id;
}

// Initialize hazard pointer system
bool lockfree_hazard_init(void) {
    if (g_hazard_system.initialized) {
        return true;
    }

    memset(&g_hazard_system, 0, sizeof(hazard_pointer_system_t));

    for (int i = 0; i < HAZARD_POINTER_MAX_THREADS; i++) {
        for (int j = 0; j < HAZARD_POINTERS_PER_THREAD; j++) {
            atomic_init(&g_hazard_system.threads[i].hazards[j].pointer, NULL);
        }
        atomic_init(&g_hazard_system.threads[i].retired_count, 0);
    }

    atomic_init(&g_hazard_system.active_threads, 0);
    atomic_init(&g_hazard_system.total_allocations, 0);
    atomic_init(&g_hazard_system.total_reclamations, 0);

    g_hazard_system.initialized = true;

    printf("[OPTIMIZER] Hazard pointer system initialized\n");
    return true;
}

// Acquire hazard pointer
void* lockfree_hazard_acquire(void *ptr, int hazard_index) {
    int thread_id = get_thread_id();
    if (thread_id < 0 || hazard_index >= HAZARD_POINTERS_PER_THREAD) {
        return NULL;
    }

    atomic_store(&g_hazard_system.threads[thread_id].hazards[hazard_index].pointer, ptr);
    return ptr;
}

// Release hazard pointer
void lockfree_hazard_release(int hazard_index) {
    int thread_id = get_thread_id();
    if (thread_id < 0 || hazard_index >= HAZARD_POINTERS_PER_THREAD) {
        return;
    }

    atomic_store(&g_hazard_system.threads[thread_id].hazards[hazard_index].pointer, NULL);
}

// Check if pointer is hazardous
bool lockfree_is_hazardous(void *ptr) {
    for (int i = 0; i < HAZARD_POINTER_MAX_THREADS; i++) {
        for (int j = 0; j < HAZARD_POINTERS_PER_THREAD; j++) {
            if (atomic_load(&g_hazard_system.threads[i].hazards[j].pointer) == ptr) {
                return true;
            }
        }
    }
    return false;
}

// Retire pointer for later reclamation
void lockfree_retire_pointer(void *ptr) {
    int thread_id = get_thread_id();
    if (thread_id < 0) {
        free(ptr);  // Fallback
        return;
    }

    thread_hazard_record_t *record = &g_hazard_system.threads[thread_id];
    uint32_t retired_count = atomic_load(&record->retired_count);

    if (retired_count >= LOCKFREE_QUEUE_MAX_SIZE) {
        // Reclaim some memory first
        lockfree_reclaim_memory();
    }

    record->retired_list[retired_count] = ptr;
    atomic_store(&record->retired_count, retired_count + 1);
}

// Reclaim memory that's no longer hazardous
void lockfree_reclaim_memory(void) {
    int thread_id = get_thread_id();
    if (thread_id < 0) return;

    thread_hazard_record_t *record = &g_hazard_system.threads[thread_id];
    uint32_t retired_count = atomic_load(&record->retired_count);

    for (uint32_t i = 0; i < retired_count; i++) {
        void *ptr = record->retired_list[i];
        if (!lockfree_is_hazardous(ptr)) {
            free(ptr);
            atomic_fetch_add(&g_hazard_system.total_reclamations, 1);

            // Move last element to current position
            record->retired_list[i] = record->retired_list[retired_count - 1];
            retired_count--;
            i--; // Check this position again
        }
    }

    atomic_store(&record->retired_count, retired_count);
}

// Create tagged pointer
static tagged_pointer_t make_tagged_pointer(void *ptr, uint64_t tag) {
    tagged_pointer_t tp = {.ptr = ptr, .tag = tag};
    return tp;
}

// Compare tagged pointers
static bool tagged_pointer_equal(tagged_pointer_t a, tagged_pointer_t b) {
    return a.ptr == b.ptr && a.tag == b.tag;
}

// Initialize lock-free queue
lockfree_queue_t* lockfree_queue_create(void) {
    lockfree_queue_t *queue = aligned_alloc(CACHE_LINE_SIZE, sizeof(lockfree_queue_t));
    if (!queue) {
        return NULL;
    }

    memset(queue, 0, sizeof(lockfree_queue_t));

    // Create dummy node
    lockfree_queue_node_t *dummy = aligned_alloc(CACHE_LINE_SIZE, sizeof(lockfree_queue_node_t));
    if (!dummy) {
        free(queue);
        return NULL;
    }

    memset(dummy, 0, sizeof(lockfree_queue_node_t));
    atomic_init(&dummy->next, make_tagged_pointer(NULL, 0));
    dummy->data = NULL;
    dummy->sequence = 0;

    // Initialize queue with dummy node
    tagged_pointer_t dummy_ptr = make_tagged_pointer(dummy, 0);
    atomic_init(&queue->head, dummy_ptr);
    atomic_init(&queue->tail, dummy_ptr);
    atomic_init(&queue->size, 0);
    atomic_init(&queue->enqueue_count, 0);
    atomic_init(&queue->dequeue_count, 0);
    atomic_init(&queue->sequence_counter, 1);

    // Initialize performance counters
    atomic_init(&queue->successful_enqueues, 0);
    atomic_init(&queue->successful_dequeues, 0);
    atomic_init(&queue->failed_enqueues, 0);
    atomic_init(&queue->failed_dequeues, 0);
    atomic_init(&queue->cas_failures, 0);

    return queue;
}

// Enqueue operation (Michael & Scott algorithm with hazard pointers)
bool lockfree_queue_enqueue(lockfree_queue_t *queue, void *data) {
    if (!queue || !data) {
        return false;
    }

    // Allocate new node
    lockfree_queue_node_t *new_node = aligned_alloc(CACHE_LINE_SIZE, sizeof(lockfree_queue_node_t));
    if (!new_node) {
        atomic_fetch_add(&queue->failed_enqueues, 1);
        return false;
    }

    new_node->data = data;
    new_node->sequence = atomic_fetch_add(&queue->sequence_counter, 1);
    atomic_init(&new_node->next, make_tagged_pointer(NULL, 0));

    while (true) {
        tagged_pointer_t tail = atomic_load(&queue->tail);
        lockfree_queue_node_t *tail_node = (lockfree_queue_node_t*)tail.ptr;

        // Protect tail node with hazard pointer
        lockfree_hazard_acquire(tail_node, 0);

        // Verify tail hasn't changed
        tagged_pointer_t current_tail = atomic_load(&queue->tail);
        if (!tagged_pointer_equal(tail, current_tail)) {
            lockfree_hazard_release(0);
            continue;
        }

        tagged_pointer_t next = atomic_load(&tail_node->next);
        if (next.ptr == NULL) {
            // Try to link new node
            tagged_pointer_t new_next = make_tagged_pointer(new_node, next.tag + 1);
            if (atomic_compare_exchange_weak(&tail_node->next, &next, new_next)) {
                // Successfully linked, now try to advance tail
                tagged_pointer_t new_tail = make_tagged_pointer(new_node, tail.tag + 1);
                atomic_compare_exchange_weak(&queue->tail, &tail, new_tail);

                lockfree_hazard_release(0);
                atomic_fetch_add(&queue->size, 1);
                atomic_fetch_add(&queue->enqueue_count, 1);
                atomic_fetch_add(&queue->successful_enqueues, 1);
                return true;
            } else {
                atomic_fetch_add(&queue->cas_failures, 1);
            }
        } else {
            // Help advance tail
            tagged_pointer_t new_tail = make_tagged_pointer(next.ptr, tail.tag + 1);
            atomic_compare_exchange_weak(&queue->tail, &tail, new_tail);
        }

        lockfree_hazard_release(0);
    }
}

// Dequeue operation
void* lockfree_queue_dequeue(lockfree_queue_t *queue) {
    if (!queue) {
        return NULL;
    }

    while (true) {
        tagged_pointer_t head = atomic_load(&queue->head);
        tagged_pointer_t tail = atomic_load(&queue->tail);
        lockfree_queue_node_t *head_node = (lockfree_queue_node_t*)head.ptr;

        // Protect head node with hazard pointer
        lockfree_hazard_acquire(head_node, 0);

        // Verify head hasn't changed
        tagged_pointer_t current_head = atomic_load(&queue->head);
        if (!tagged_pointer_equal(head, current_head)) {
            lockfree_hazard_release(0);
            continue;
        }

        tagged_pointer_t next = atomic_load(&head_node->next);
        lockfree_queue_node_t *next_node = (lockfree_queue_node_t*)next.ptr;

        if (head.ptr == tail.ptr) {
            if (next_node == NULL) {
                // Queue is empty
                lockfree_hazard_release(0);
                atomic_fetch_add(&queue->failed_dequeues, 1);
                return NULL;
            }

            // Help advance tail
            tagged_pointer_t new_tail = make_tagged_pointer(next_node, tail.tag + 1);
            atomic_compare_exchange_weak(&queue->tail, &tail, new_tail);
        } else {
            if (next_node == NULL) {
                lockfree_hazard_release(0);
                continue;
            }

            // Protect next node
            lockfree_hazard_acquire(next_node, 1);

            // Read data before advancing head
            void *data = next_node->data;

            // Try to advance head
            tagged_pointer_t new_head = make_tagged_pointer(next_node, head.tag + 1);
            if (atomic_compare_exchange_weak(&queue->head, &head, new_head)) {
                lockfree_hazard_release(0);
                lockfree_hazard_release(1);

                // Retire old head node
                lockfree_retire_pointer(head_node);

                atomic_fetch_sub(&queue->size, 1);
                atomic_fetch_add(&queue->dequeue_count, 1);
                atomic_fetch_add(&queue->successful_dequeues, 1);
                return data;
            } else {
                atomic_fetch_add(&queue->cas_failures, 1);
                lockfree_hazard_release(1);
            }
        }

        lockfree_hazard_release(0);
    }
}

// Get queue size (approximate)
uint64_t lockfree_queue_size(lockfree_queue_t *queue) {
    if (!queue) return 0;
    return atomic_load(&queue->size);
}

// Initialize lock-free stack
lockfree_stack_t* lockfree_stack_create(void) {
    lockfree_stack_t *stack = aligned_alloc(CACHE_LINE_SIZE, sizeof(lockfree_stack_t));
    if (!stack) {
        return NULL;
    }

    memset(stack, 0, sizeof(lockfree_stack_t));

    atomic_init(&stack->top, make_tagged_pointer(NULL, 0));
    atomic_init(&stack->size, 0);
    atomic_init(&stack->push_count, 0);
    atomic_init(&stack->pop_count, 0);

    // Initialize performance counters
    atomic_init(&stack->successful_pushes, 0);
    atomic_init(&stack->successful_pops, 0);
    atomic_init(&stack->failed_pushes, 0);
    atomic_init(&stack->failed_pops, 0);
    atomic_init(&stack->cas_failures, 0);

    return stack;
}

// Push operation
bool lockfree_stack_push(lockfree_stack_t *stack, void *data) {
    if (!stack || !data) {
        return false;
    }

    lockfree_stack_node_t *new_node = aligned_alloc(CACHE_LINE_SIZE, sizeof(lockfree_stack_node_t));
    if (!new_node) {
        atomic_fetch_add(&stack->failed_pushes, 1);
        return false;
    }

    new_node->data = data;

    while (true) {
        tagged_pointer_t top = atomic_load(&stack->top);
        atomic_init(&new_node->next, top);

        tagged_pointer_t new_top = make_tagged_pointer(new_node, top.tag + 1);
        if (atomic_compare_exchange_weak(&stack->top, &top, new_top)) {
            atomic_fetch_add(&stack->size, 1);
            atomic_fetch_add(&stack->push_count, 1);
            atomic_fetch_add(&stack->successful_pushes, 1);
            return true;
        }

        atomic_fetch_add(&stack->cas_failures, 1);
    }
}

// Pop operation
void* lockfree_stack_pop(lockfree_stack_t *stack) {
    if (!stack) {
        return NULL;
    }

    while (true) {
        tagged_pointer_t top = atomic_load(&stack->top);
        lockfree_stack_node_t *top_node = (lockfree_stack_node_t*)top.ptr;

        if (top_node == NULL) {
            atomic_fetch_add(&stack->failed_pops, 1);
            return NULL;
        }

        // Protect top node
        lockfree_hazard_acquire(top_node, 0);

        // Verify top hasn't changed
        tagged_pointer_t current_top = atomic_load(&stack->top);
        if (!tagged_pointer_equal(top, current_top)) {
            lockfree_hazard_release(0);
            continue;
        }

        tagged_pointer_t next = atomic_load(&top_node->next);
        tagged_pointer_t new_top = make_tagged_pointer(next.ptr, top.tag + 1);

        if (atomic_compare_exchange_weak(&stack->top, &top, new_top)) {
            void *data = top_node->data;
            lockfree_hazard_release(0);

            // Retire node
            lockfree_retire_pointer(top_node);

            atomic_fetch_sub(&stack->size, 1);
            atomic_fetch_add(&stack->pop_count, 1);
            atomic_fetch_add(&stack->successful_pops, 1);
            return data;
        }

        atomic_fetch_add(&stack->cas_failures, 1);
        lockfree_hazard_release(0);
    }
}

// Get lock-free performance statistics
void lockfree_get_performance_stats(void) {
    printf("\n[OPTIMIZER] Lock-Free Data Structure Performance\n");
    printf("===============================================\n");
    printf("Hazard Pointer System:\n");
    printf("  Total Allocations: %lu\n", atomic_load(&g_hazard_system.total_allocations));
    printf("  Total Reclamations: %lu\n", atomic_load(&g_hazard_system.total_reclamations));
    printf("  Active Threads: %u\n", atomic_load(&g_hazard_system.active_threads));
    printf("\nOptimizations Enabled:\n");
    printf("  - ABA Protection: Tagged Pointers\n");
    printf("  - Memory Reclamation: Hazard Pointers\n");
    printf("  - Cache Alignment: %d bytes\n", CACHE_LINE_SIZE);
    printf("  - Lock-Free Algorithms: Michael & Scott\n");
}

// Destroy lock-free queue
void lockfree_queue_destroy(lockfree_queue_t *queue) {
    if (!queue) return;

    // Drain queue
    void *data;
    while ((data = lockfree_queue_dequeue(queue)) != NULL) {
        // User should handle data cleanup
    }

    // Clean up remaining node
    tagged_pointer_t head = atomic_load(&queue->head);
    if (head.ptr) {
        free(head.ptr);
    }

    free(queue);
}

// Destroy lock-free stack
void lockfree_stack_destroy(lockfree_stack_t *stack) {
    if (!stack) return;

    // Drain stack
    void *data;
    while ((data = lockfree_stack_pop(stack)) != NULL) {
        // User should handle data cleanup
    }

    free(stack);
}
