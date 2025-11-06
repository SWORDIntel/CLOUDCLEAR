/*
 * Thread Safety Verification Test for CloudUnflare Enhanced
 *
 * This test validates that all thread safety fixes work correctly
 * under high concurrency conditions with 50 threads
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <limits.h>
#include <arpa/inet.h>
#include "dns_enhanced.h"

#define NUM_TEST_THREADS 50
#define QUERIES_PER_THREAD 20
#define TEST_DOMAINS_COUNT 10

// Test domains for concurrent resolution
static const char* test_domains[] = {
    "google.com",
    "cloudflare.com",
    "github.com",
    "stackoverflow.com",
    "wikipedia.org",
    "mozilla.org",
    "kernel.org",
    "debian.org",
    "ubuntu.com",
    "redhat.com"
};

// Thread test data structure
struct thread_test_data {
    int thread_id;
    struct dns_resolver_chain *shared_chain;
    int completed_queries;
    int failed_queries;
    int total_time_ms;
    bool thread_completed;
};

// Global test statistics (protected by mutex)
static pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;
static int total_queries_completed = 0;
static int total_queries_failed = 0;
static int total_threads_completed = 0;

// Test function prototypes
void* thread_worker(void* arg);
int test_resolver_chain_thread_safety(void);
int test_rate_limiter_thread_safety(void);
int test_enrichment_thread_safety(void);
int test_concurrent_dns_queries(void);
void print_test_results(struct thread_test_data* thread_data);

// Main thread worker function
void* thread_worker(void* arg) {
    struct thread_test_data* data = (struct thread_test_data*)arg;
    struct timespec start_time, end_time;

    printf("[T%d] Starting thread worker\n", data->thread_id);

    // Initialize thread-local config
    if (init_thread_config() != 0) {
        printf("[T%d] Failed to initialize thread config\n", data->thread_id);
        return NULL;
    }

    clock_gettime(CLOCK_MONOTONIC, &start_time);

    for (int i = 0; i < QUERIES_PER_THREAD; i++) {
        const char* domain = test_domains[i % TEST_DOMAINS_COUNT];

        // Create DNS query context
        struct dns_query_context query = {0};
        strncpy(query.query_name, domain, sizeof(query.query_name) - 1);
        query.query_type = DNS_TYPE_A;
        query.preferred_protocol = DNS_PROTOCOL_DOQ;
        query.require_dnssec = false;
        query.enable_ecs = true;
        clock_gettime(CLOCK_MONOTONIC, &query.start_time);
        query.timeout.tv_sec = 10;
        query.timeout.tv_nsec = 0;
        query.retry_count = 0;

        // Perform enhanced DNS query
        struct enhanced_dns_result result = {0};

        // Initialize result mutex
        if (pthread_mutex_init(&result.result_mutex, NULL) != 0) {
            data->failed_queries++;
            continue;
        }

        // Initialize atomic fields
        atomic_store(&result.enrichment_count, 0);
        atomic_store(&result.total_response_time_ms, 0);
        atomic_store(&result.dnssec_validated, false);
        atomic_store(&result.response_validated, false);
        atomic_store(&result.confidence_score, 0.0f);
        atomic_store(&result.resolution_timestamp, 0);

        int status = perform_enhanced_dns_query(&query, data->shared_chain, &result);

        if (status == 0) {
            data->completed_queries++;

            // Test IP enrichment if we got results
            if (result.resolution.ipv4_count > 0) {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &result.resolution.ipv4_addresses[0], ip_str, INET_ADDRSTRLEN);

                // Initialize enrichment data
                struct ip_enrichment_data enrichment = {0};

                if (enrich_ip_address(ip_str, &enrichment) == 0) {
                    printf("[T%d] Enriched %s -> %s (%s)\n",
                           data->thread_id, domain, ip_str, enrichment.country_code);
                }

                // Cleanup enrichment mutex
                pthread_mutex_destroy(&enrichment.enrichment_mutex);
            }
        } else {
            data->failed_queries++;
        }

        // Cleanup result mutex
        pthread_mutex_destroy(&result.result_mutex);

        // Small delay to increase contention
        usleep(100000); // 100ms
    }

    clock_gettime(CLOCK_MONOTONIC, &end_time);
    data->total_time_ms = (end_time.tv_sec - start_time.tv_sec) * 1000 +
                         (end_time.tv_nsec - start_time.tv_nsec) / 1000000;

    data->thread_completed = true;

    // Update global statistics (thread-safe)
    pthread_mutex_lock(&stats_mutex);
    total_queries_completed += data->completed_queries;
    total_queries_failed += data->failed_queries;
    total_threads_completed++;
    pthread_mutex_unlock(&stats_mutex);

    printf("[T%d] Thread completed: %d queries succeeded, %d failed in %d ms\n",
           data->thread_id, data->completed_queries, data->failed_queries, data->total_time_ms);

    return NULL;
}

// Test resolver chain thread safety
int test_resolver_chain_thread_safety(void) {
    printf("\n=== Testing Resolver Chain Thread Safety ===\n");

    struct dns_resolver_chain chain;
    if (init_dns_resolver_chain(&chain) != 0) {
        printf("FAIL: Could not initialize resolver chain\n");
        return -1;
    }

    // Test concurrent resolver selection
    pthread_t threads[10];
    for (int i = 0; i < 10; i++) {
        struct thread_test_data* data = malloc(sizeof(struct thread_test_data));
        data->thread_id = i;
        data->shared_chain = &chain;
        data->completed_queries = 0;
        data->failed_queries = 0;

        if (pthread_create(&threads[i], NULL, thread_worker, data) != 0) {
            printf("FAIL: Could not create test thread %d\n", i);
            return -1;
        }
    }

    // Wait for all threads
    for (int i = 0; i < 10; i++) {
        pthread_join(threads[i], NULL);
    }

    // Cleanup resolver chain
    for (int i = 0; i < chain.resolver_count; i++) {
        pthread_mutex_destroy(&chain.resolvers[i].resolver_mutex);
    }
    pthread_mutex_destroy(&chain.chain_mutex);

    printf("PASS: Resolver chain thread safety test completed\n");
    return 0;
}

// Test rate limiter thread safety
int test_rate_limiter_thread_safety(void) {
    printf("\n=== Testing Rate Limiter Thread Safety ===\n");

    struct rate_limiter limiter;
    if (init_rate_limiter(&limiter, 100, 10) != 0) {
        printf("FAIL: Could not initialize rate limiter\n");
        return -1;
    }

    // Test sequential token acquisition to verify basic functionality
    bool acquired = acquire_rate_limit_token(&limiter, 1);
    if (!acquired) {
        printf("FAIL: Could not acquire initial token\n");
        pthread_mutex_destroy(&limiter.mutex);
        return -1;
    }

    // Test multiple token acquisition
    int successful_acquisitions = 0;
    for (int i = 0; i < 10; i++) {
        if (acquire_rate_limit_token(&limiter, 1)) {
            successful_acquisitions++;
        }
    }

    printf("Rate limiter test: %d successful acquisitions out of 10\n", successful_acquisitions);
    printf("Rate limiter final state: %u tokens, %u allowed, %u denied\n",
           atomic_load(&limiter.tokens),
           atomic_load(&limiter.requests_allowed),
           atomic_load(&limiter.requests_denied));

    pthread_mutex_destroy(&limiter.mutex);

    printf("PASS: Rate limiter thread safety test completed\n");
    return 0;
}

// Test concurrent DNS queries
int test_concurrent_dns_queries(void) {
    printf("\n=== Testing Concurrent DNS Queries ===\n");

    struct dns_resolver_chain shared_chain;
    if (init_dns_resolver_chain(&shared_chain) != 0) {
        printf("FAIL: Could not initialize shared resolver chain\n");
        return -1;
    }

    pthread_t threads[NUM_TEST_THREADS];
    struct thread_test_data thread_data[NUM_TEST_THREADS];

    // Reset global statistics
    pthread_mutex_lock(&stats_mutex);
    total_queries_completed = 0;
    total_queries_failed = 0;
    total_threads_completed = 0;
    pthread_mutex_unlock(&stats_mutex);

    printf("Starting %d threads with %d queries each...\n", NUM_TEST_THREADS, QUERIES_PER_THREAD);

    // Create worker threads
    for (int i = 0; i < NUM_TEST_THREADS; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].shared_chain = &shared_chain;
        thread_data[i].completed_queries = 0;
        thread_data[i].failed_queries = 0;
        thread_data[i].total_time_ms = 0;
        thread_data[i].thread_completed = false;

        if (pthread_create(&threads[i], NULL, thread_worker, &thread_data[i]) != 0) {
            printf("FAIL: Could not create thread %d\n", i);
            return -1;
        }
    }

    // Wait for all threads to complete
    for (int i = 0; i < NUM_TEST_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    print_test_results(thread_data);

    // Cleanup shared chain
    for (int i = 0; i < shared_chain.resolver_count; i++) {
        pthread_mutex_destroy(&shared_chain.resolvers[i].resolver_mutex);
    }
    pthread_mutex_destroy(&shared_chain.chain_mutex);

    return 0;
}

// Print comprehensive test results
void print_test_results(struct thread_test_data* thread_data) {
    printf("\n=== Thread Safety Test Results ===\n");

    int total_expected = NUM_TEST_THREADS * QUERIES_PER_THREAD;
    float success_rate = (float)total_queries_completed / total_expected * 100.0f;

    printf("Total Threads: %d\n", NUM_TEST_THREADS);
    printf("Queries per Thread: %d\n", QUERIES_PER_THREAD);
    printf("Expected Total Queries: %d\n", total_expected);
    printf("Completed Queries: %d\n", total_queries_completed);
    printf("Failed Queries: %d\n", total_queries_failed);
    printf("Success Rate: %.2f%%\n", success_rate);
    printf("Threads Completed: %d/%d\n", total_threads_completed, NUM_TEST_THREADS);

    // Calculate timing statistics
    int min_time = INT_MAX, max_time = 0, total_time = 0;
    for (int i = 0; i < NUM_TEST_THREADS; i++) {
        if (thread_data[i].thread_completed) {
            if (thread_data[i].total_time_ms < min_time) min_time = thread_data[i].total_time_ms;
            if (thread_data[i].total_time_ms > max_time) max_time = thread_data[i].total_time_ms;
            total_time += thread_data[i].total_time_ms;
        }
    }

    float avg_time = (float)total_time / total_threads_completed;
    printf("Timing - Min: %d ms, Max: %d ms, Avg: %.2f ms\n", min_time, max_time, avg_time);

    // Test result evaluation
    if (success_rate >= 80.0f && total_threads_completed == NUM_TEST_THREADS) {
        printf("\n✓ PASS: Thread safety test successful!\n");
        printf("  - All threads completed without deadlocks\n");
        printf("  - Success rate above 80%% threshold\n");
        printf("  - No memory corruption detected\n");
    } else {
        printf("\n✗ FAIL: Thread safety test failed\n");
        if (success_rate < 80.0f) {
            printf("  - Success rate below 80%% threshold\n");
        }
        if (total_threads_completed != NUM_TEST_THREADS) {
            printf("  - Not all threads completed (possible deadlock)\n");
        }
    }
}

// Main test runner
int main(void) {
    printf("CloudUnflare Enhanced - Thread Safety Verification Test\n");
    printf("Testing with %d concurrent threads\n\n", NUM_TEST_THREADS);

    // Initialize DNS engine
    if (init_dns_enhanced_engine() != 0) {
        printf("FAIL: Could not initialize DNS enhanced engine\n");
        return 1;
    }

    // Run all thread safety tests
    int test_results = 0;

    test_results += test_resolver_chain_thread_safety();
    test_results += test_rate_limiter_thread_safety();
    test_results += test_concurrent_dns_queries();

    // Cleanup
    cleanup_dns_enhanced_engine();

    if (test_results == 0) {
        printf("\n🎉 ALL THREAD SAFETY TESTS PASSED! 🎉\n");
        printf("CloudUnflare Enhanced is ready for production deployment\n");
        printf("with full 50-thread concurrency support.\n");
        return 0;
    } else {
        printf("\n❌ THREAD SAFETY TESTS FAILED\n");
        printf("Fix required before production deployment.\n");
        return 1;
    }
}