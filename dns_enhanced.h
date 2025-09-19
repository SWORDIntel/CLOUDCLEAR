/*
 * DNS Enhanced - Advanced DNS Resolution Engine
 *
 * Implements RESEARCHER agent recommendations for maximum resolution success
 * Features: DoQ support, passive DNS, dual-stack, CDN detection, advanced fallback
 */

#ifndef DNS_ENHANCED_H
#define DNS_ENHANCED_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>

// DNS protocol support
typedef enum {
    DNS_PROTOCOL_UDP,
    DNS_PROTOCOL_TCP,
    DNS_PROTOCOL_DOH,     // DNS over HTTPS
    DNS_PROTOCOL_DOT,     // DNS over TLS
    DNS_PROTOCOL_DOQ      // DNS over QUIC (10% faster than DoH)
} dns_protocol_t;

// DNS query types
typedef enum {
    DNS_TYPE_A = 1,
    DNS_TYPE_NS = 2,
    DNS_TYPE_CNAME = 5,
    DNS_TYPE_MX = 15,
    DNS_TYPE_TXT = 16,
    DNS_TYPE_AAAA = 28,
    DNS_TYPE_SRV = 33,
    DNS_TYPE_CAA = 257
} dns_record_type_t;

// Enhanced DNS resolver with performance metrics (thread-safe)
struct dns_resolver {
    char address[256];
    dns_protocol_t protocol;
    uint16_t port;
    _Atomic float success_rate;
    _Atomic uint32_t avg_response_time_ms;
    _Atomic uint32_t total_queries;
    _Atomic uint32_t successful_queries;
    bool supports_dnssec;
    bool supports_ecs;  // EDNS Client Subnet
    _Atomic bool is_available;
    _Atomic time_t last_check;
    pthread_mutex_t resolver_mutex;  // Per-resolver mutex for complex operations
};

// Intelligent resolver chain with automatic failover
struct dns_resolver_chain {
    struct dns_resolver resolvers[16];
    int resolver_count;
    int current_resolver;
    pthread_mutex_t chain_mutex;
};

// Advanced DNS query context
struct dns_query_context {
    char query_name[256];
    dns_record_type_t query_type;
    dns_protocol_t preferred_protocol;
    struct timespec start_time;
    struct timespec timeout;
    uint32_t retry_count;
    bool require_dnssec;
    bool enable_ecs;
    uint16_t query_id;
};

// DNS response validation for poison detection
struct dns_response_validation {
    uint32_t expected_ttl_range[2];
    struct in_addr expected_ip_ranges[8][2];
    int ip_range_count;
    bool require_dnssec;
    float entropy_threshold;
    uint32_t response_time_baseline_ms;
    bool allow_private_ips;
};

// Dual-stack IPv4/IPv6 resolution
struct dual_stack_resolution {
    struct in_addr ipv4_addresses[16];
    int ipv4_count;
    struct in6_addr ipv6_addresses[16];
    int ipv6_count;
    bool prefer_ipv6;
    bool require_both_stacks;
    uint32_t ipv4_response_time;
    uint32_t ipv6_response_time;
};

// IP enrichment data from geolocation APIs (thread-safe)
struct ip_enrichment_data {
    char country_code[4];
    char region[64];
    char city[128];
    char isp[256];
    _Atomic uint32_t asn;
    char as_name[256];
    _Atomic float latitude;
    _Atomic float longitude;
    _Atomic bool is_hosting_provider;
    _Atomic bool is_tor_exit;
    _Atomic bool is_vpn;
    _Atomic bool is_cloud_provider;
    char threat_classification[64];
    pthread_mutex_t enrichment_mutex;  // Protect string fields during updates
};

// CDN detection and origin discovery
struct cdn_detection {
    bool is_cdn;
    char cdn_provider[128];
    char origin_ips[8][INET_ADDRSTRLEN];
    int origin_ip_count;
    char edge_locations[16][256];
    int edge_location_count;
    bool cdn_bypass_possible;
    char bypass_techniques[512];
};

// Passive DNS source configuration
struct passive_dns_sources {
    struct {
        char api_key[256];
        char endpoint[512];
        uint32_t rate_limit_ms;
        bool authenticated;
        bool enabled;
    } circl, dnsdb, virustotal, passivetotal, securitytrails;

    uint32_t max_historical_days;
    bool include_malware_domains;
    bool include_sinkholed;
};

// Advanced retry strategy with circuit breaker
struct adaptive_retry_strategy {
    uint32_t base_delay_ms;
    float backoff_multiplier;
    uint32_t max_retries;
    uint32_t circuit_breaker_threshold;
    uint32_t circuit_breaker_timeout_ms;
    bool jitter_enabled;
    uint32_t jitter_max_ms;
    bool adaptive_timeout;
};

// Rate limiter with token bucket algorithm (optimized for high concurrency)
struct rate_limiter {
    _Atomic uint32_t tokens;
    uint32_t max_tokens;
    uint32_t refill_rate_per_second;
    struct timespec last_refill;  // Protected by mutex (not atomic due to clock_gettime compatibility)
    pthread_mutex_t mutex;
    _Atomic uint32_t requests_denied;
    _Atomic uint32_t requests_allowed;
};

// Wildcard detection for accurate subdomain enumeration
struct wildcard_detection {
    bool has_wildcard;
    char wildcard_ips[4][INET_ADDRSTRLEN];
    int wildcard_ip_count;
    uint32_t wildcard_ttl;
    char wildcard_pattern[256];
    bool affects_enumeration;
};

// Enhanced DNS result structure (thread-safe)
struct enhanced_dns_result {
    char domain[256];
    struct dual_stack_resolution resolution;
    struct ip_enrichment_data enrichment[16];
    _Atomic int enrichment_count;
    struct cdn_detection cdn_info;
    struct wildcard_detection wildcard_info;
    _Atomic uint32_t total_response_time_ms;
    dns_protocol_t protocol_used;
    char resolver_used[256];
    _Atomic bool dnssec_validated;
    _Atomic bool response_validated;
    _Atomic float confidence_score;
    _Atomic time_t resolution_timestamp;
    pthread_mutex_t result_mutex;  // Protect complex data structures during updates
};

// Function prototypes for enhanced DNS resolution

// Resolver chain management
int init_dns_resolver_chain(struct dns_resolver_chain *chain);
int add_resolver_to_chain(struct dns_resolver_chain *chain,
                         const char *address,
                         dns_protocol_t protocol,
                         uint16_t port);
struct dns_resolver* select_optimal_resolver(struct dns_resolver_chain *chain,
                                           dns_record_type_t query_type);
int update_resolver_metrics(struct dns_resolver *resolver,
                           bool success,
                           uint32_t response_time);

// Enhanced DNS query functions
int perform_enhanced_dns_query(struct dns_query_context *query,
                              struct dns_resolver_chain *chain,
                              struct enhanced_dns_result *result);
int perform_doq_query(struct dns_query_context *query,
                     struct dns_resolver *resolver,
                     struct enhanced_dns_result *result);
int perform_dual_stack_resolution(const char *domain,
                                 struct dual_stack_resolution *result);

// Response validation and security
bool validate_dns_response(struct enhanced_dns_result *result,
                          struct dns_response_validation *validation);
bool detect_dns_poisoning(struct enhanced_dns_result *result,
                         struct dns_response_validation *validation);
float calculate_response_entropy(const char *response_data, size_t length);

// IP enrichment and geolocation
int enrich_ip_address(const char *ip_address,
                     struct ip_enrichment_data *enrichment);
int detect_cdn_and_origin(const char *domain,
                         struct enhanced_dns_result *result);
bool is_cloud_provider_ip(const char *ip_address, char *provider_name);

// Passive DNS integration
int query_passive_dns_sources(const char *domain,
                             struct passive_dns_sources *sources,
                             char **historical_ips,
                             int *ip_count);
int correlate_passive_dns_data(const char *domain,
                              struct enhanced_dns_result *results,
                              int result_count);

// Wildcard detection and handling
int detect_wildcard_responses(const char *domain,
                             struct wildcard_detection *detection);
bool is_wildcard_response(const char *subdomain,
                         struct wildcard_detection *wildcard_info);

// Rate limiting and retry logic
int init_rate_limiter(struct rate_limiter *limiter,
                     uint32_t max_tokens,
                     uint32_t refill_rate);
bool acquire_rate_limit_token(struct rate_limiter *limiter,
                             uint32_t tokens_requested);
int execute_with_retry(int (*operation)(void*),
                      void *context,
                      struct adaptive_retry_strategy *strategy);

// Performance optimization
int init_memory_pools(void);
void cleanup_memory_pools(void);
int optimize_network_socket(int sockfd);

// Configuration and initialization
int load_dns_enhanced_config(const char *config_file);
int init_dns_enhanced_engine(void);
void cleanup_dns_enhanced_engine(void);

// Utility functions
const char* dns_protocol_to_string(dns_protocol_t protocol);
const char* dns_record_type_to_string(dns_record_type_t type);
void print_enhanced_dns_result(struct enhanced_dns_result *result);
int save_results_to_json(struct enhanced_dns_result *results,
                        int count,
                        const char *filename);

// Default resolver configurations
extern struct dns_resolver default_resolvers[];
extern int default_resolver_count;

// Thread-safe global configuration
extern _Thread_local struct adaptive_retry_strategy thread_retry_strategy;
extern _Thread_local struct dns_response_validation thread_validation_config;
extern struct rate_limiter global_rate_limiter;  // Shared rate limiter (thread-safe)

// Thread-safe initialization functions
int init_thread_config(void);
void cleanup_thread_config(void);

#endif // DNS_ENHANCED_H