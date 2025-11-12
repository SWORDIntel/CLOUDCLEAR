# Enhanced DNS API Reference

## 🔧 DNS Enhanced API Documentation

Complete API reference for the Enhanced DNS Resolution Engine with all RESEARCHER agent improvements.

## 📚 Core API Functions

### DNS Resolver Chain Management

#### `init_dns_resolver_chain()`
Initialize DNS resolver chain with default high-performance resolvers.

```c
int init_dns_resolver_chain(struct dns_resolver_chain *chain);
```

**Parameters:**
- `chain`: Pointer to resolver chain structure

**Returns:**
- `0`: Success
- `-1`: Initialization failed

**Example:**
```c
struct dns_resolver_chain chain;
if (init_dns_resolver_chain(&chain) == 0) {
    printf("Resolver chain initialized with %d resolvers\n", chain.resolver_count);
}
```

#### `add_resolver_to_chain()`
Add custom DNS resolver to the chain.

```c
int add_resolver_to_chain(struct dns_resolver_chain *chain,
                         const char *address,
                         dns_protocol_t protocol,
                         uint16_t port);
```

**Parameters:**
- `chain`: Target resolver chain
- `address`: Resolver IP address or hostname
- `protocol`: DNS protocol (DoQ/DoH/DoT/UDP/TCP)
- `port`: Resolver port number

**Example:**
```c
// Add custom DoQ resolver
add_resolver_to_chain(&chain, "dns.custom.com", DNS_PROTOCOL_DOQ, 853);
```

#### `select_optimal_resolver()`
Intelligently select the best resolver based on performance metrics.

```c
struct dns_resolver* select_optimal_resolver(struct dns_resolver_chain *chain,
                                           dns_record_type_t query_type);
```

**Parameters:**
- `chain`: Resolver chain to select from
- `query_type`: Type of DNS query (A, AAAA, CNAME, etc.)

**Returns:**
- Pointer to optimal resolver or `NULL` if none available

**Selection Algorithm:**
```c
// Composite score calculation:
score = (success_rate * 0.7) + (speed_factor * 0.3) + protocol_bonus

// Protocol bonuses:
// DoQ: +0.15 (fastest encrypted)
// DoH: +0.10 (reliable encrypted)
// DoT: +0.08 (traditional encrypted)
// UDP/TCP: +0.00 (baseline)
```

### Enhanced DNS Queries

#### `perform_enhanced_dns_query()`
Execute advanced DNS query with intelligent fallback and enrichment.

```c
int perform_enhanced_dns_query(struct dns_query_context *query,
                              struct dns_resolver_chain *chain,
                              struct enhanced_dns_result *result);
```

**Parameters:**
- `query`: DNS query configuration
- `chain`: Resolver chain for intelligent selection
- `result`: Structure to store comprehensive results

**Query Context Structure:**
```c
struct dns_query_context {
    char query_name[256];              // Domain to query
    dns_record_type_t query_type;      // A, AAAA, CNAME, MX, etc.
    dns_protocol_t preferred_protocol; // Preferred protocol
    struct timespec timeout;          // Query timeout
    uint32_t retry_count;             // Current retry attempt
    bool require_dnssec;              // DNSSEC validation required
    bool enable_ecs;                  // EDNS Client Subnet
    uint16_t query_id;                // Query identifier
};
```

**Example:**
```c
struct dns_query_context query = {
    .query_type = DNS_TYPE_A,
    .preferred_protocol = DNS_PROTOCOL_DOQ,
    .timeout = {.tv_sec = 10, .tv_nsec = 0},
    .require_dnssec = false,
    .enable_ecs = true
};
strncpy(query.query_name, "example.com", sizeof(query.query_name));

struct enhanced_dns_result result;
if (perform_enhanced_dns_query(&query, &chain, &result) == 0) {
    printf("Resolution successful: %d IPv4, %d IPv6 addresses\n",
           result.resolution.ipv4_count, result.resolution.ipv6_count);
}
```

#### `perform_dual_stack_resolution()`
Perform simultaneous IPv4 and IPv6 resolution with performance metrics.

```c
int perform_dual_stack_resolution(const char *domain,
                                 struct dual_stack_resolution *result);
```

**Result Structure:**
```c
struct dual_stack_resolution {
    struct in_addr ipv4_addresses[16];    // IPv4 addresses
    int ipv4_count;                       // Number of IPv4 addresses
    struct in6_addr ipv6_addresses[16];   // IPv6 addresses
    int ipv6_count;                       // Number of IPv6 addresses
    bool prefer_ipv6;                     // IPv6 preference flag
    bool require_both_stacks;             // Require both protocols
    uint32_t ipv4_response_time;          // IPv4 resolution time (ms)
    uint32_t ipv6_response_time;          // IPv6 resolution time (ms)
};
```

### IP Intelligence and Enrichment

#### `enrich_ip_address()`
Gather comprehensive intelligence about an IP address.

```c
int enrich_ip_address(const char *ip_address,
                     struct ip_enrichment_data *enrichment);
```

**Enrichment Data Structure:**
```c
struct ip_enrichment_data {
    char country_code[4];          // ISO country code (US, UK, etc.)
    char region[64];               // State/Province
    char city[128];                // City name
    char isp[256];                 // Internet Service Provider
    uint32_t asn;                  // Autonomous System Number
    char as_name[256];             // AS organization name
    float latitude;                // Geographic latitude
    float longitude;               // Geographic longitude
    bool is_hosting_provider;      // Commercial hosting detection
    bool is_tor_exit;              // Tor exit node detection
    bool is_vpn;                   // VPN/Proxy detection
    bool is_cloud_provider;        // Cloud service detection
    char threat_classification[64]; // Threat intelligence data
};
```

**Example:**
```c
struct ip_enrichment_data enrichment;
if (enrich_ip_address("8.8.8.8", &enrichment) == 0) {
    printf("IP: %s (%s, %s) - AS%u %s\n",
           "8.8.8.8", enrichment.city, enrichment.country_code,
           enrichment.asn, enrichment.as_name);
    if (enrichment.is_hosting_provider) {
        printf("Detected as hosting provider\n");
    }
}
```

### CDN Detection and Analysis

#### `detect_cdn_and_origin()`
Identify CDN usage and discover origin servers.

```c
int detect_cdn_and_origin(const char *domain,
                         struct enhanced_dns_result *result);
```

**CDN Detection Structure:**
```c
struct cdn_detection {
    bool is_cdn;                          // CDN detected flag
    char cdn_provider[128];               // CDN provider name
    char origin_ips[8][INET_ADDRSTRLEN]; // Discovered origin IPs
    int origin_ip_count;                  // Number of origin IPs
    char edge_locations[16][256];         // Edge server locations
    int edge_location_count;              // Number of edge locations
    bool cdn_bypass_possible;             // Bypass feasibility
    char bypass_techniques[512];          // Recommended techniques
};
```

**Supported CDN Providers:**
- CloudFlare - Advanced bypass techniques
- AWS CloudFront - Origin bucket discovery
- Akamai - Edge server identification
- Azure CDN - Front Door analysis
- Google Cloud CDN - Load balancer detection

### Wildcard Detection

#### `detect_wildcard_responses()`
Identify wildcard DNS configurations for accurate enumeration.

```c
int detect_wildcard_responses(const char *domain,
                             struct wildcard_detection *detection);
```

**Wildcard Structure:**
```c
struct wildcard_detection {
    bool has_wildcard;                    // Wildcard DNS detected
    char wildcard_ips[4][INET_ADDRSTRLEN]; // Wildcard IP addresses
    int wildcard_ip_count;                // Number of wildcard IPs
    uint32_t wildcard_ttl;                // Wildcard record TTL
    char wildcard_pattern[256];           // Detected pattern
    bool affects_enumeration;             // Impact on subdomain enum
};
```

**Detection Algorithm:**
```c
// Test random subdomains:
// 1. nonexistent-test-12345.domain.com
// 2. random-wildcard-test-67890.domain.com
// 3. definitely-not-real-abcdef.domain.com

// If multiple resolve to same IP = wildcard detected
```

### Rate Limiting and OPSEC

#### `init_rate_limiter()`
Initialize token bucket rate limiter for OPSEC compliance.

```c
int init_rate_limiter(struct rate_limiter *limiter,
                     uint32_t max_tokens,
                     uint32_t refill_rate);
```

#### `acquire_rate_limit_token()`
Acquire tokens for rate-limited operations.

```c
bool acquire_rate_limit_token(struct rate_limiter *limiter,
                             uint32_t tokens_requested);
```

**Rate Limiter Structure:**
```c
struct rate_limiter {
    uint32_t tokens;                    // Current available tokens
    uint32_t max_tokens;               // Maximum token capacity
    uint32_t refill_rate_per_second;   // Token refill rate
    struct timespec last_refill;       // Last refill timestamp
    pthread_mutex_t mutex;             // Thread safety
    uint32_t requests_denied;          // Denied request counter
    uint32_t requests_allowed;         // Allowed request counter
};
```

**Example:**
```c
struct rate_limiter limiter;
init_rate_limiter(&limiter, 10, 2); // 10 tokens max, 2/sec refill

if (acquire_rate_limit_token(&limiter, 1)) {
    // Proceed with rate-limited operation
    perform_dns_query(...);
} else {
    // Rate limited - wait or skip
    printf("Rate limited, waiting...\n");
    usleep(500000); // 500ms delay
}
```

## 📊 Data Structures Reference

### Enhanced DNS Result

```c
struct enhanced_dns_result {
    char domain[256];                      // Queried domain
    struct dual_stack_resolution resolution; // IPv4/IPv6 results
    struct ip_enrichment_data enrichment[16]; // IP intelligence
    int enrichment_count;                  // Number of enriched IPs
    struct cdn_detection cdn_info;         // CDN analysis
    struct wildcard_detection wildcard_info; // Wildcard detection
    uint32_t total_response_time_ms;       // Total resolution time
    dns_protocol_t protocol_used;          // Actual protocol used
    char resolver_used[256];               // Resolver that succeeded
    bool dnssec_validated;                 // DNSSEC validation status
    bool response_validated;               // Response validation status
    float confidence_score;                // Data confidence (0.0-1.0)
    time_t resolution_timestamp;           // Resolution timestamp
};
```

### DNS Resolver Metrics

```c
struct dns_resolver {
    char address[256];              // Resolver address
    dns_protocol_t protocol;        // Protocol (DoQ/DoH/DoT/UDP/TCP)
    uint16_t port;                  // Port number
    float success_rate;             // Success rate (0.0-1.0)
    uint32_t avg_response_time_ms;  // Average response time
    uint32_t total_queries;         // Total query count
    uint32_t successful_queries;    // Successful query count
    bool supports_dnssec;           // DNSSEC support
    bool supports_ecs;              // EDNS Client Subnet support
    bool is_available;              // Current availability
    time_t last_check;              // Last health check
};
```

## 🔍 Utility Functions

### Protocol and Type Conversion

```c
const char* dns_protocol_to_string(dns_protocol_t protocol);
const char* dns_record_type_to_string(dns_record_type_t type);
```

### Result Display and Export

```c
void print_enhanced_dns_result(struct enhanced_dns_result *result);
int save_results_to_json(struct enhanced_dns_result *results,
                        int count,
                        const char *filename);
```

### Configuration Management

```c
int load_dns_enhanced_config(const char *config_file);
int init_dns_enhanced_engine(void);
void cleanup_dns_enhanced_engine(void);
```

## 🚀 Performance Optimization

### Memory Management

```c
// Memory pools for frequent allocations
int init_memory_pools(void);
void cleanup_memory_pools(void);

// Secure memory management
struct secure_buffer* allocate_secure_buffer(size_t size);
void secure_wipe_buffer(struct secure_buffer *buf);
```

### Network Optimization

```c
int optimize_network_socket(int sockfd);
```

**Socket Optimizations:**
- TCP_NODELAY for reduced latency
- SO_KEEPALIVE for connection health
- Buffer size optimization
- Timeout configuration

## 📈 Error Handling

### Return Codes

```c
#define DNS_SUCCESS           0    // Operation successful
#define DNS_ERROR_INVALID    -1    // Invalid parameters
#define DNS_ERROR_NETWORK    -2    // Network connectivity issue
#define DNS_ERROR_TIMEOUT    -3    // Operation timed out
#define DNS_ERROR_NO_MEMORY  -4    // Memory allocation failed
#define DNS_ERROR_NO_RESOLVER -5   // No available resolvers
#define DNS_ERROR_RATE_LIMITED -6  // Rate limit exceeded
```

### Error Context

```c
struct dns_error_context {
    int error_code;                // Error code
    char error_message[256];       // Human-readable message
    char resolver_address[256];    // Resolver that failed
    uint32_t retry_count;          // Number of retries attempted
    time_t error_timestamp;        // When error occurred
};
```

## 🔧 Advanced Configuration

### Compile-time Options

```c
// Feature toggles in config.h
#define FEATURE_CERTIFICATE_TRANSPARENCY 1
#define FEATURE_SUBDOMAIN_ENUMERATION 1
#define FEATURE_IP_HISTORY_LOOKUP 1
#define FEATURE_PROXY_CHAINS 1
#define FEATURE_THREAT_MONITORING 1
#define FEATURE_INTELLIGENCE_CORRELATION 1

// Performance tuning
#define MAX_CONCURRENT_THREADS 50
#define DEFAULT_THREAD_COUNT 10
#define MAX_DNS_TIMEOUT 30
#define CONNECTION_POOL_SIZE 20
```

### Runtime Configuration

```c
// Environment variable controls
CLOUDUNFLARE_PROTOCOL=doq           // Force specific protocol
CLOUDUNFLARE_TIMEOUT=10             // DNS timeout (seconds)
CLOUDUNFLARE_RETRIES=3              // Maximum retries
CLOUDUNFLARE_RATE_LIMIT=1000        // Rate limit (ms)
CLOUDUNFLARE_STEALTH=true           // Stealth mode
CLOUDUNFLARE_IPV6_PREFER=true       // Prefer IPv6
```

---

*This API provides enterprise-grade DNS reconnaissance capabilities with comprehensive intelligence gathering and nation-state level operational security features.*