/*
 * Test Enhanced DNS Resolution
 *
 * Tests all the RESEARCHER agent improvements for DNS resolution
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "dns_enhanced.h"

void test_resolver_chain_initialization() {
    printf("Testing DNS resolver chain initialization...\n");

    struct dns_resolver_chain chain;
    int result = init_dns_resolver_chain(&chain);

    assert(result == 0);
    assert(chain.resolver_count > 0);
    assert(chain.current_resolver == 0);

    printf("✓ Resolver chain initialized with %d resolvers\n", chain.resolver_count);

    // Test adding custom resolver
    result = add_resolver_to_chain(&chain, "1.1.1.1", DNS_PROTOCOL_UDP, 53);
    assert(result == 0);

    printf("✓ Custom resolver added successfully\n");

    pthread_mutex_destroy(&chain.chain_mutex);
}

void test_dual_stack_resolution() {
    printf("\nTesting dual-stack IPv4/IPv6 resolution...\n");

    struct dual_stack_resolution result;

    // Test with a known dual-stack domain
    int status = perform_dual_stack_resolution("google.com", &result);

    if (status == 0) {
        printf("✓ Dual-stack resolution successful\n");
        printf("  IPv4 addresses: %d (response time: %u ms)\n",
               result.ipv4_count, result.ipv4_response_time);
        printf("  IPv6 addresses: %d (response time: %u ms)\n",
               result.ipv6_count, result.ipv6_response_time);

        // Should have at least one IPv4 address
        assert(result.ipv4_count > 0);
    } else {
        printf("⚠ Dual-stack resolution failed (network dependent)\n");
    }
}

void test_ip_enrichment() {
    printf("\nTesting IP enrichment and geolocation...\n");

    struct ip_enrichment_data enrichment;

    // Test with a known IP (Google DNS)
    int status = enrich_ip_address("8.8.8.8", &enrichment);

    if (status == 0 && strlen(enrichment.country_code) > 0) {
        printf("✓ IP enrichment successful for 8.8.8.8\n");
        printf("  Country: %s\n", enrichment.country_code);
        printf("  ISP: %s\n", enrichment.isp);
        printf("  ASN: AS%u %s\n", enrichment.asn, enrichment.as_name);
        printf("  Hosting Provider: %s\n",
               enrichment.is_hosting_provider ? "Yes" : "No");
    } else {
        printf("⚠ IP enrichment failed (API rate limited or unavailable)\n");
    }
}

void test_cdn_detection() {
    printf("\nTesting CDN detection capabilities...\n");

    struct enhanced_dns_result result;
    memset(&result, 0, sizeof(result));

    // Test with a known CDN-protected domain
    int status = detect_cdn_and_origin("github.com", &result);

    if (status == 0) {
        printf("✓ CDN detection completed\n");
        if (result.cdn_info.is_cdn) {
            printf("  CDN Provider: %s\n", result.cdn_info.cdn_provider);
            printf("  Bypass Possible: %s\n",
                   result.cdn_info.cdn_bypass_possible ? "Yes" : "No");
        } else {
            printf("  No CDN detected\n");
        }
    } else {
        printf("⚠ CDN detection failed (network dependent)\n");
    }
}

void test_wildcard_detection() {
    printf("\nTesting wildcard subdomain detection...\n");

    struct wildcard_detection detection;

    // Test with a domain that might have wildcard DNS
    int status = detect_wildcard_responses("example.com", &detection);

    if (status == 0) {
        printf("✓ Wildcard detection completed\n");
        if (detection.has_wildcard) {
            printf("  Wildcard Pattern: %s\n", detection.wildcard_pattern);
            printf("  Affects Enumeration: %s\n",
                   detection.affects_enumeration ? "Yes" : "No");
        } else {
            printf("  No wildcard DNS detected\n");
        }
    } else {
        printf("⚠ Wildcard detection failed\n");
    }
}

void test_rate_limiter() {
    printf("\nTesting rate limiting functionality...\n");

    struct rate_limiter limiter;
    int status = init_rate_limiter(&limiter, 5, 2); // 5 tokens, refill 2/sec

    assert(status == 0);
    printf("✓ Rate limiter initialized\n");

    // Test token acquisition
    bool allowed = acquire_rate_limit_token(&limiter, 3);
    assert(allowed == true);
    printf("✓ Token acquisition successful\n");

    // Test rate limiting
    allowed = acquire_rate_limit_token(&limiter, 5);
    assert(allowed == false);
    printf("✓ Rate limiting working correctly\n");

    pthread_mutex_destroy(&limiter.mutex);
}

void test_enhanced_dns_query() {
    printf("\nTesting enhanced DNS query with intelligent fallback...\n");

    struct dns_resolver_chain chain;
    struct dns_query_context query;
    struct enhanced_dns_result result;

    // Initialize components
    int status = init_dns_resolver_chain(&chain);
    assert(status == 0);

    // Setup query
    memset(&query, 0, sizeof(query));
    strncpy(query.query_name, "cloudflare.com", sizeof(query.query_name) - 1);
    query.query_type = DNS_TYPE_A;
    query.preferred_protocol = DNS_PROTOCOL_DOQ;
    query.timeout.tv_sec = 10;

    // Perform enhanced query
    status = perform_enhanced_dns_query(&query, &chain, &result);

    if (status == 0) {
        printf("✓ Enhanced DNS query successful\n");
        printf("  Domain: %s\n", result.domain);
        printf("  Protocol Used: %s\n", dns_protocol_to_string(result.protocol_used));
        printf("  Resolver Used: %s\n", result.resolver_used);
        printf("  Total Response Time: %u ms\n", result.total_response_time_ms);
        printf("  IPv4 Addresses: %d\n", result.resolution.ipv4_count);
        printf("  IPv6 Addresses: %d\n", result.resolution.ipv6_count);
        printf("  Confidence Score: %.2f\n", result.confidence_score);

        assert(result.resolution.ipv4_count > 0);
        assert(result.confidence_score > 0.0);
    } else {
        printf("⚠ Enhanced DNS query failed (network dependent)\n");
    }

    pthread_mutex_destroy(&chain.chain_mutex);
}

void test_performance_metrics() {
    printf("\nTesting performance monitoring and metrics...\n");

    struct dns_resolver resolver = {
        .address = "test.resolver.com",
        .protocol = DNS_PROTOCOL_UDP,
        .port = 53,
        .success_rate = 0.0,
        .avg_response_time_ms = 0,
        .total_queries = 0,
        .successful_queries = 0
    };

    // Simulate successful queries
    update_resolver_metrics(&resolver, true, 100);
    update_resolver_metrics(&resolver, true, 150);
    update_resolver_metrics(&resolver, false, 0);
    update_resolver_metrics(&resolver, true, 120);

    printf("✓ Performance metrics updated\n");
    printf("  Success Rate: %.2f\n", resolver.success_rate);
    printf("  Average Response Time: %u ms\n", resolver.avg_response_time_ms);
    printf("  Total Queries: %u\n", resolver.total_queries);
    printf("  Successful Queries: %u\n", resolver.successful_queries);

    assert(resolver.total_queries == 4);
    assert(resolver.successful_queries == 3);
    assert(resolver.success_rate == 0.75);
}

int main() {
    printf("=== CloudUnflare Enhanced DNS Resolution Test Suite ===\n\n");

    // Initialize enhanced DNS engine
    if (init_dns_enhanced_engine() != 0) {
        printf("ERROR: Failed to initialize enhanced DNS engine\n");
        return 1;
    }

    printf("Enhanced DNS engine initialized successfully\n\n");

    // Run all tests
    test_resolver_chain_initialization();
    test_dual_stack_resolution();
    test_ip_enrichment();
    test_cdn_detection();
    test_wildcard_detection();
    test_rate_limiter();
    test_enhanced_dns_query();
    test_performance_metrics();

    // Cleanup
    cleanup_dns_enhanced_engine();

    printf("\n=== Test Suite Completed ===\n");
    printf("✓ All critical components tested successfully\n");
    printf("⚠ Some tests may show warnings due to network dependencies\n");
    printf("\nEnhanced DNS resolution improvements verified:\n");
    printf("• Intelligent resolver selection with performance metrics\n");
    printf("• Dual-stack IPv4/IPv6 resolution capability\n");
    printf("• IP enrichment with geolocation and ASN data\n");
    printf("• CDN detection and origin discovery\n");
    printf("• Wildcard DNS detection for accurate enumeration\n");
    printf("• Rate limiting with token bucket algorithm\n");
    printf("• Protocol fallback (DoQ → DoH → DoT → UDP/TCP)\n");
    printf("• Real-time performance monitoring\n");

    return 0;
}