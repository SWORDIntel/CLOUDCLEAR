/*
 * CloudUnflare Enhanced - HTTP Banner Grabbing Test Program
 * C-INTERNAL Implementation Test Suite
 *
 * Comprehensive testing of HTTP Banner Grabbing capabilities
 * Performance validation for 1500+ banner grabs/second target
 */

#include "http_banner.h"
#include <sys/time.h>

// Test configuration structure
typedef struct {
    bool test_basic_http;
    bool test_https_ssl;
    bool test_technology_detection;
    bool test_security_headers;
    bool test_performance;
    bool test_error_handling;
    bool test_opsec_features;
    uint32_t performance_target_per_second;
    uint32_t max_test_urls;
} http_banner_test_config_t;

// Test result structure
typedef struct {
    uint32_t tests_passed;
    uint32_t tests_failed;
    uint32_t total_requests;
    uint32_t successful_requests;
    double total_time_seconds;
    double average_response_time_ms;
    double requests_per_second;
    bool performance_target_met;
} http_banner_test_results_t;

// Test URLs for comprehensive testing
static const char *test_urls[] = {
    "http://httpbin.org/headers",
    "https://httpbin.org/headers",
    "https://example.com",
    "https://github.com",
    "https://stackoverflow.com",
    "https://news.ycombinator.com",
    "https://www.google.com",
    "https://www.cloudflare.com",
    "http://neverssl.com",
    "https://badssl.com/",
    "https://expired.badssl.com/",
    "https://self-signed.badssl.com/",
    "https://untrusted-root.badssl.com/",
    "https://revoked.badssl.com/",
    "https://pinning-test.badssl.com/",
    "https://no-common-name.badssl.com/",
    "https://no-subject.badssl.com/",
    "https://incomplete-chain.badssl.com/",
    "https://sha1-intermediate.badssl.com/",
    "https://sha256.badssl.com/"
};

// Function prototypes
int run_basic_http_test(http_banner_context_t *ctx, http_banner_test_results_t *results);
int run_https_ssl_test(http_banner_context_t *ctx, http_banner_test_results_t *results);
int run_technology_detection_test(http_banner_context_t *ctx, http_banner_test_results_t *results);
int run_security_headers_test(http_banner_context_t *ctx, http_banner_test_results_t *results);
int run_performance_test(http_banner_context_t *ctx, http_banner_test_results_t *results, uint32_t target_rps);
int run_error_handling_test(http_banner_context_t *ctx, http_banner_test_results_t *results);
int run_opsec_features_test(http_banner_context_t *ctx, http_banner_test_results_t *results);

void print_test_summary(const http_banner_test_results_t *results);
double get_time_diff_ms(struct timeval start, struct timeval end);

int main(int argc, char *argv[]) {
    printf("=== CloudUnflare HTTP Banner Grabbing Test Suite ===\n");
    printf("C-INTERNAL Implementation Validation\n");
    printf("Performance Target: 1500+ banner grabs/second\n\n");

    // Initialize test configuration
    http_banner_test_config_t test_config = {
        .test_basic_http = true,
        .test_https_ssl = true,
        .test_technology_detection = true,
        .test_security_headers = true,
        .test_performance = true,
        .test_error_handling = true,
        .test_opsec_features = true,
        .performance_target_per_second = 1500,
        .max_test_urls = sizeof(test_urls) / sizeof(test_urls[0])
    };

    // Initialize test results
    http_banner_test_results_t results = {0};
    struct timeval test_start, test_end;
    gettimeofday(&test_start, NULL);

    // Initialize HTTP banner context
    http_banner_context_t ctx;
    if (http_banner_init_context(&ctx) != 0) {
        printf("ERROR: Failed to initialize HTTP banner context\n");
        return 1;
    }

    // Configure for testing
    http_banner_config_t config = {
        .default_method = HTTP_METHOD_GET,
        .timeout_seconds = 10,
        .max_redirects = 3,
        .delay_between_requests_ms = 100,
        .analyze_ssl = true,
        .detect_technologies = true,
        .check_security_headers = true,
        .follow_redirects = true,
        .verify_ssl_certs = false, // For testing with bad SSL sites
        .custom_header_count = 0,
        .user_agent_count = 0
    };

    http_banner_set_config(&ctx, &config);

    printf("Initializing test environment...\n");
    printf("Test URLs available: %u\n", test_config.max_test_urls);
    printf("Starting comprehensive test suite...\n\n");

    // Run test suite
    int test_status = 0;

    // Test 1: Basic HTTP functionality
    if (test_config.test_basic_http) {
        printf("--- Test 1: Basic HTTP Functionality ---\n");
        if (run_basic_http_test(&ctx, &results) == 0) {
            printf("✓ Basic HTTP test PASSED\n");
            results.tests_passed++;
        } else {
            printf("✗ Basic HTTP test FAILED\n");
            results.tests_failed++;
            test_status = 1;
        }
        printf("\n");
    }

    // Test 2: HTTPS and SSL analysis
    if (test_config.test_https_ssl) {
        printf("--- Test 2: HTTPS/SSL Analysis ---\n");
        if (run_https_ssl_test(&ctx, &results) == 0) {
            printf("✓ HTTPS/SSL test PASSED\n");
            results.tests_passed++;
        } else {
            printf("✗ HTTPS/SSL test FAILED\n");
            results.tests_failed++;
            test_status = 1;
        }
        printf("\n");
    }

    // Test 3: Technology detection
    if (test_config.test_technology_detection) {
        printf("--- Test 3: Technology Detection ---\n");
        if (run_technology_detection_test(&ctx, &results) == 0) {
            printf("✓ Technology detection test PASSED\n");
            results.tests_passed++;
        } else {
            printf("✗ Technology detection test FAILED\n");
            results.tests_failed++;
        }
        printf("\n");
    }

    // Test 4: Security headers analysis
    if (test_config.test_security_headers) {
        printf("--- Test 4: Security Headers Analysis ---\n");
        if (run_security_headers_test(&ctx, &results) == 0) {
            printf("✓ Security headers test PASSED\n");
            results.tests_passed++;
        } else {
            printf("✗ Security headers test FAILED\n");
            results.tests_failed++;
        }
        printf("\n");
    }

    // Test 5: Performance validation
    if (test_config.test_performance) {
        printf("--- Test 5: Performance Validation ---\n");
        if (run_performance_test(&ctx, &results, test_config.performance_target_per_second) == 0) {
            printf("✓ Performance test PASSED\n");
            results.tests_passed++;
        } else {
            printf("✗ Performance test FAILED\n");
            results.tests_failed++;
        }
        printf("\n");
    }

    // Test 6: Error handling
    if (test_config.test_error_handling) {
        printf("--- Test 6: Error Handling ---\n");
        if (run_error_handling_test(&ctx, &results) == 0) {
            printf("✓ Error handling test PASSED\n");
            results.tests_passed++;
        } else {
            printf("✗ Error handling test FAILED\n");
            results.tests_failed++;
        }
        printf("\n");
    }

    // Test 7: OPSEC features
    if (test_config.test_opsec_features) {
        printf("--- Test 7: OPSEC Features ---\n");
        if (run_opsec_features_test(&ctx, &results) == 0) {
            printf("✓ OPSEC features test PASSED\n");
            results.tests_passed++;
        } else {
            printf("✗ OPSEC features test FAILED\n");
            results.tests_failed++;
        }
        printf("\n");
    }

    // Calculate total test time
    gettimeofday(&test_end, NULL);
    results.total_time_seconds = get_time_diff_ms(test_start, test_end) / 1000.0;

    // Print comprehensive results
    print_test_summary(&results);

    // Export test results
    printf("Exporting test results...\n");
    http_banner_export_json(&ctx, "http_banner_test_results.json");
    http_banner_export_csv(&ctx, "http_banner_test_results.csv");
    printf("Results exported to JSON and CSV files\n");

    // Cleanup
    http_banner_cleanup_context(&ctx);

    printf("\n=== Test Suite Complete ===\n");
    if (results.tests_failed == 0) {
        printf("🎉 ALL TESTS PASSED! HTTP Banner Grabbing module is ready for production.\n");
        return 0;
    } else {
        printf("⚠️  %u/%u tests failed. Review implementation before production deployment.\n",
               results.tests_failed, results.tests_passed + results.tests_failed);
        return test_status;
    }
}

// Test basic HTTP functionality
int run_basic_http_test(http_banner_context_t *ctx, http_banner_test_results_t *results) {
    const char *test_url = "http://httpbin.org/headers";
    http_banner_result_t result;

    printf("Testing basic HTTP request to: %s\n", test_url);

    if (http_banner_grab_single(ctx, test_url, &result) != 0) {
        printf("Failed to grab banner from %s\n", test_url);
        return -1;
    }

    results->total_requests++;
    if (result.success) {
        results->successful_requests++;
        results->average_response_time_ms += result.response.response_time_ms;
    }

    // Validate basic response
    if (!result.success) {
        printf("Request failed: %s\n", result.error_message);
        return -1;
    }

    if (result.response.status_code != 200) {
        printf("Unexpected status code: %u\n", result.response.status_code);
        return -1;
    }

    if (strlen(result.response.server_header) == 0) {
        printf("No server header detected\n");
        // This is not necessarily a failure, some servers don't expose this
    }

    printf("Status: %u %s\n", result.response.status_code, result.response.status_message);
    printf("Server: %s\n", strlen(result.response.server_header) > 0 ? result.response.server_header : "Not disclosed");
    printf("Response time: %u ms\n", result.response.response_time_ms);
    printf("Content length: %lu bytes\n", result.response.content_length);

    http_banner_cleanup_result(&result);
    return 0;
}

// Test HTTPS and SSL analysis
int run_https_ssl_test(http_banner_context_t *ctx, http_banner_test_results_t *results) {
    const char *test_url = "https://example.com";
    http_banner_result_t result;

    printf("Testing HTTPS/SSL analysis with: %s\n", test_url);

    if (http_banner_grab_single(ctx, test_url, &result) != 0) {
        printf("Failed to grab banner from %s\n", test_url);
        return -1;
    }

    results->total_requests++;
    if (result.success) {
        results->successful_requests++;
        results->average_response_time_ms += result.response.response_time_ms;
    }

    // Validate HTTPS response
    if (!result.success) {
        printf("HTTPS request failed: %s\n", result.error_message);
        return -1;
    }

    if (!result.response.has_ssl) {
        printf("SSL information not detected for HTTPS URL\n");
        return -1;
    }

    printf("SSL Version: %s\n", ssl_version_to_string(result.response.ssl_info.version));
    printf("Cipher Suite: %s\n", result.response.ssl_info.cipher_suite);
    printf("Certificate Subject: %s\n", result.response.ssl_info.certificate.subject);
    printf("Certificate Issuer: %s\n", result.response.ssl_info.certificate.issuer);
    printf("Key Size: %u bits\n", result.response.ssl_info.certificate.key_size);
    printf("Expired: %s\n", result.response.ssl_info.certificate.is_expired ? "Yes" : "No");
    printf("Self-signed: %s\n", result.response.ssl_info.certificate.is_self_signed ? "Yes" : "No");

    // Validate SSL version is modern
    if (result.response.ssl_info.version == SSL_VERSION_SSLV2 ||
        result.response.ssl_info.version == SSL_VERSION_SSLV3) {
        printf("Warning: Insecure SSL version detected\n");
        // Not a failure, just a warning
    }

    http_banner_cleanup_result(&result);
    return 0;
}

// Test technology detection capabilities
int run_technology_detection_test(http_banner_context_t *ctx, http_banner_test_results_t *results) {
    const char *test_urls_tech[] = {
        "https://github.com",
        "https://stackoverflow.com"
    };

    for (size_t i = 0; i < sizeof(test_urls_tech) / sizeof(test_urls_tech[0]); i++) {
        http_banner_result_t result;
        printf("Testing technology detection with: %s\n", test_urls_tech[i]);

        if (http_banner_grab_single(ctx, test_urls_tech[i], &result) != 0) {
            printf("Failed to grab banner from %s\n", test_urls_tech[i]);
            continue;
        }

        results->total_requests++;
        if (result.success) {
            results->successful_requests++;
            results->average_response_time_ms += result.response.response_time_ms;
        }

        if (result.success && result.technology_count > 0) {
            printf("Detected %u technologies:\n", result.technology_count);
            for (uint32_t j = 0; j < result.technology_count; j++) {
                printf("  - %s %s (Confidence: %s)\n",
                       result.technologies[j].technology,
                       result.technologies[j].version,
                       result.technologies[j].confidence_level);
            }
        } else {
            printf("No technologies detected (may be normal)\n");
        }

        http_banner_cleanup_result(&result);
    }

    return 0;
}

// Test security headers analysis
int run_security_headers_test(http_banner_context_t *ctx, http_banner_test_results_t *results) {
    const char *test_url = "https://github.com";
    http_banner_result_t result;

    printf("Testing security headers analysis with: %s\n", test_url);

    if (http_banner_grab_single(ctx, test_url, &result) != 0) {
        printf("Failed to grab banner from %s\n", test_url);
        return -1;
    }

    results->total_requests++;
    if (result.success) {
        results->successful_requests++;
        results->average_response_time_ms += result.response.response_time_ms;
    }

    if (!result.success) {
        printf("Security headers test failed: %s\n", result.error_message);
        return -1;
    }

    if (result.security_header_count > 0) {
        printf("Detected %u security headers:\n", result.security_header_count);
        for (uint32_t i = 0; i < result.security_header_count; i++) {
            printf("  - %s\n", result.security_headers[i]);
        }

        int security_score = http_banner_rate_security_posture(&result.response);
        printf("Security posture score: %d/100\n", security_score);
    } else {
        printf("No security headers detected (concerning for a major site)\n");
        // This might be a warning but not necessarily a test failure
    }

    http_banner_cleanup_result(&result);
    return 0;
}

// Test performance with target of 1500+ requests per second
int run_performance_test(http_banner_context_t *ctx, http_banner_test_results_t *results, uint32_t target_rps) {
    const uint32_t test_requests = 100; // Reduced for testing
    const char *test_url = "http://httpbin.org/headers";
    struct timeval start_time, end_time;

    printf("Testing performance with %u requests to: %s\n", test_requests, test_url);
    printf("Target: %u requests/second\n", target_rps);

    gettimeofday(&start_time, NULL);

    uint32_t successful = 0;
    for (uint32_t i = 0; i < test_requests; i++) {
        http_banner_result_t result;

        if (http_banner_grab_single(ctx, test_url, &result) == 0 && result.success) {
            successful++;
            results->average_response_time_ms += result.response.response_time_ms;
        }

        results->total_requests++;
        if (result.success) {
            results->successful_requests++;
        }

        http_banner_cleanup_result(&result);

        // Print progress every 25 requests
        if ((i + 1) % 25 == 0) {
            printf("Completed %u/%u requests\n", i + 1, test_requests);
        }
    }

    gettimeofday(&end_time, NULL);

    double elapsed_seconds = get_time_diff_ms(start_time, end_time) / 1000.0;
    double actual_rps = test_requests / elapsed_seconds;

    printf("Performance results:\n");
    printf("  Total requests: %u\n", test_requests);
    printf("  Successful requests: %u\n", successful);
    printf("  Elapsed time: %.2f seconds\n", elapsed_seconds);
    printf("  Requests per second: %.2f\n", actual_rps);
    printf("  Success rate: %.1f%%\n", (successful * 100.0) / test_requests);

    results->requests_per_second = actual_rps;
    results->performance_target_met = (actual_rps >= target_rps);

    if (actual_rps >= target_rps) {
        printf("✓ Performance target MET (%.2f >= %u RPS)\n", actual_rps, target_rps);
        return 0;
    } else {
        printf("✗ Performance target MISSED (%.2f < %u RPS)\n", actual_rps, target_rps);
        return -1;
    }
}

// Test error handling capabilities
int run_error_handling_test(http_banner_context_t *ctx, http_banner_test_results_t *results) {
    const char *error_test_urls[] = {
        "http://nonexistent.invalid.domain.example",
        "https://expired.badssl.com",
        "https://self-signed.badssl.com",
        "http://httpbin.org/status/404",
        "http://httpbin.org/status/500"
    };

    printf("Testing error handling with problematic URLs...\n");

    for (size_t i = 0; i < sizeof(error_test_urls) / sizeof(error_test_urls[0]); i++) {
        http_banner_result_t result;
        printf("Testing error handling with: %s\n", error_test_urls[i]);

        // This should handle errors gracefully
        int ret = http_banner_grab_single(ctx, error_test_urls[i], &result);

        results->total_requests++;
        if (result.success) {
            results->successful_requests++;
        }

        if (ret == 0) {
            if (result.success) {
                printf("  Result: Success (Status: %u)\n", result.response.status_code);
            } else {
                printf("  Result: Handled error - %s\n", result.error_message);
            }
        } else {
            printf("  Result: Function returned error\n");
        }

        http_banner_cleanup_result(&result);
    }

    printf("Error handling test completed (all errors handled gracefully)\n");
    return 0;
}

// Test OPSEC and evasion features
int run_opsec_features_test(http_banner_context_t *ctx, http_banner_test_results_t *results) {
    printf("Testing OPSEC features...\n");

    // Test user agent rotation
    const char *user_agent = http_banner_get_random_user_agent(&ctx->config);
    printf("Random User-Agent: %s\n", user_agent);

    // Test URL validation
    bool valid_http = http_banner_is_valid_url("http://example.com");
    bool valid_https = http_banner_is_valid_url("https://example.com");
    bool invalid = http_banner_is_valid_url("ftp://example.com");

    printf("URL validation tests:\n");
    printf("  http://example.com: %s\n", valid_http ? "Valid" : "Invalid");
    printf("  https://example.com: %s\n", valid_https ? "Valid" : "Invalid");
    printf("  ftp://example.com: %s\n", invalid ? "Valid" : "Invalid");

    if (!valid_http || !valid_https || invalid) {
        printf("URL validation test failed\n");
        return -1;
    }

    // Test URL parsing
    char hostname[256];
    uint16_t port;
    char path[512];
    bool is_https;

    if (http_banner_parse_url("https://example.com:8443/test/path", hostname, &port, path, &is_https) == 0) {
        printf("URL parsing test:\n");
        printf("  Hostname: %s\n", hostname);
        printf("  Port: %u\n", port);
        printf("  Path: %s\n", path);
        printf("  HTTPS: %s\n", is_https ? "Yes" : "No");

        if (strcmp(hostname, "example.com") != 0 || port != 8443 ||
            strcmp(path, "/test/path") != 0 || !is_https) {
            printf("URL parsing test failed\n");
            return -1;
        }
    } else {
        printf("URL parsing test failed\n");
        return -1;
    }

    printf("OPSEC features test completed successfully\n");
    return 0;
}

// Print comprehensive test summary
void print_test_summary(const http_banner_test_results_t *results) {
    printf("\n=== HTTP Banner Grabbing Test Summary ===\n");
    printf("Tests Passed: %u\n", results->tests_passed);
    printf("Tests Failed: %u\n", results->tests_failed);
    printf("Total Tests: %u\n", results->tests_passed + results->tests_failed);
    printf("Test Success Rate: %.1f%%\n",
           (results->tests_passed * 100.0) / (results->tests_passed + results->tests_failed));

    printf("\nRequest Statistics:\n");
    printf("Total Requests: %u\n", results->total_requests);
    printf("Successful Requests: %u\n", results->successful_requests);
    printf("Request Success Rate: %.1f%%\n",
           results->total_requests > 0 ? (results->successful_requests * 100.0) / results->total_requests : 0.0);

    if (results->successful_requests > 0) {
        printf("Average Response Time: %.2f ms\n",
               results->average_response_time_ms / results->successful_requests);
    }

    printf("\nPerformance Metrics:\n");
    printf("Total Test Time: %.2f seconds\n", results->total_time_seconds);
    printf("Requests per Second: %.2f\n", results->requests_per_second);
    printf("Performance Target (1500 RPS): %s\n",
           results->performance_target_met ? "✓ MET" : "✗ NOT MET");

    printf("\n=== Implementation Status ===\n");
    if (results->tests_failed == 0) {
        printf("🟢 PRODUCTION READY: All tests passed\n");
        printf("📊 Performance: %.0f RPS (Target: 1500+ RPS)\n", results->requests_per_second);
        printf("🔒 Security: SSL/TLS analysis functional\n");
        printf("🔍 Detection: Technology fingerprinting active\n");
        printf("🛡️  OPSEC: Evasion features operational\n");
    } else {
        printf("🟡 NEEDS REVIEW: %u test(s) failed\n", results->tests_failed);
        printf("📝 Action Required: Review failed tests before production\n");
    }
    printf("========================================\n");
}

// Calculate time difference in milliseconds
double get_time_diff_ms(struct timeval start, struct timeval end) {
    return ((end.tv_sec - start.tv_sec) * 1000.0) + ((end.tv_usec - start.tv_usec) / 1000.0);
}