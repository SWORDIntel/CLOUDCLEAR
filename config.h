/*
 * CloudUnflare Enhanced - Configuration Header
 *
 * Enhanced security and performance configuration
 * Based on RESEARCHER and NSA agent recommendations
 */

#ifndef CONFIG_H
#define CONFIG_H

// Version and build information
#define CLOUDUNFLARE_VERSION "2.0-Enhanced"
#define BUILD_DATE __DATE__
#define BUILD_TIME __TIME__

// Performance tuning
#define MAX_CONCURRENT_THREADS 50
#define DEFAULT_THREAD_COUNT 10
#define MAX_DNS_TIMEOUT 30
#define MAX_HTTP_TIMEOUT 45
#define CONNECTION_POOL_SIZE 20

// OPSEC and evasion settings
#define MAX_REQUESTS_PER_CIRCUIT 100
#define MIN_REQUEST_DELAY_MS 1000
#define MAX_REQUEST_DELAY_MS 5000
#define JITTER_BASE_MS 500
#define JITTER_RANGE_MS 2000

// Detection thresholds
#define FAILURE_THRESHOLD 5
#define ANOMALY_THRESHOLD 8
#define DORMANT_TIMEOUT_SEC 1800
#define CRITICAL_DETECTION_SCORE 0.8
#define SESSION_TIMEOUT_SEC 600

// Buffer sizes
#define MAX_DOMAIN_LENGTH 256
#define MAX_SUBDOMAIN_LENGTH 512
#define MAX_URL_LENGTH 1024
#define MAX_RESPONSE_SIZE (1024 * 1024) // 1MB
#define HTTP_HEADER_BUFFER_SIZE 4096

// Certificate Transparency settings
#define MAX_CT_ENTRIES 100
#define CT_QUERY_TIMEOUT 30
#define CT_RATE_LIMIT_DELAY 2000

// Subdomain enumeration
#define MAX_SUBDOMAIN_WORDLIST 10000
#define SUBDOMAIN_CHUNK_SIZE 100
#define SUBDOMAIN_THREAD_TIMEOUT 300

// Security features
#define ENABLE_SECURE_MEMORY 1
#define ENABLE_CANARY_PROTECTION 1
#define ENABLE_EMERGENCY_CLEANUP 1
#define ENABLE_ANTI_DEBUG 1
#define ENABLE_OPERATION_LOGGING 0  // Disable for OPSEC

// Proxy and evasion
#define MAX_PROXY_CHAIN_LENGTH 3
#define PROXY_ROTATION_INTERVAL 100
#define USER_AGENT_ROTATION_INTERVAL 25
#define DNS_PROVIDER_ROTATION_INTERVAL 50

// Intelligence correlation
#define MAX_INTEL_SOURCES 10
#define CONFIDENCE_WEIGHT_THRESHOLD 0.7
#define CORRELATION_TIMEOUT_SEC 120
#define MAX_CORRELATION_DEPTH 5

// API rate limiting
#define VIEWDNS_RATE_LIMIT_MS 3000
#define COMPLETEDNS_RATE_LIMIT_MS 2500
#define CRT_SH_RATE_LIMIT_MS 2000
#define SHODAN_RATE_LIMIT_MS 1000

// Memory management
#define SECURE_HEAP_SIZE (10 * 1024 * 1024) // 10MB
#define MAX_TEMP_FILES 100
#define MAX_MEMORY_REGIONS 100
#define MEMORY_ALIGNMENT 32

// Network settings
#define DEFAULT_DNS_PORT 53
#define DOH_DEFAULT_PORT 443
#define SOCKS5_DEFAULT_PORT 1080
#define HTTP_PROXY_DEFAULT_PORT 8080

// Error handling
#define MAX_RETRY_ATTEMPTS 3
#define RETRY_BACKOFF_MS 1000
#define CIRCUIT_REBUILD_THRESHOLD 10
#define HEALTH_CHECK_INTERVAL 60

// Feature flags
#define FEATURE_CERTIFICATE_TRANSPARENCY 1
#define FEATURE_SUBDOMAIN_ENUMERATION 1
#define FEATURE_IP_HISTORY_LOOKUP 1
#define FEATURE_PROXY_CHAINS 1
#define FEATURE_THREAT_MONITORING 1
#define FEATURE_INTELLIGENCE_CORRELATION 1
#define FEATURE_MULTI_THREADING 1
#define FEATURE_ADAPTIVE_EVASION 1

// Debug and logging (disable in production)
#ifdef DEBUG
#define DEBUG_LEVEL 2
#define ENABLE_VERBOSE_LOGGING 1
#define ENABLE_PERFORMANCE_METRICS 1
#else
#define DEBUG_LEVEL 0
#define ENABLE_VERBOSE_LOGGING 0
#define ENABLE_PERFORMANCE_METRICS 0
#endif

// Compiler optimizations
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define FORCE_INLINE __attribute__((always_inline)) inline
#define NOINLINE __attribute__((noinline))

// Memory barriers for security
#define MEMORY_BARRIER() __asm__ __volatile__("" ::: "memory")
#define COMPILER_BARRIER() __asm__ __volatile__("" ::: "memory")

// Default wordlists and resources
#define DEFAULT_SUBDOMAIN_WORDLIST_PATH "./subdomains.txt"
#define DEFAULT_PROXY_LIST_PATH "./proxies.txt"
#define DEFAULT_USER_AGENT_LIST_PATH "./user-agents.txt"

// API endpoints and URLs
#define CRT_SH_API_URL "https://crt.sh/?q=%%.%s&output=json"
#define VIEWDNS_API_URL "https://viewdns.info/iphistory/?domain=%s"
#define COMPLETEDNS_API_URL "https://completedns.com/dns-history/ajax/?domain=%s"

// DNS-over-HTTPS providers - Verified Active
// Major Providers - Confirmed Working
#define DOH_CLOUDFLARE "https://cloudflare-dns.com/dns-query"
#define DOH_CLOUDFLARE_SECURITY "https://security.cloudflare-dns.com/dns-query"
#define DOH_CLOUDFLARE_FAMILY "https://family.cloudflare-dns.com/dns-query"
#define DOH_GOOGLE "https://dns.google/dns-query"
#define DOH_QUAD9 "https://dns.quad9.net/dns-query"
#define DOH_OPENDNS "https://doh.opendns.com/dns-query"
#define DOH_OPENDNS_FAMILY "https://doh.familyshield.opendns.com/dns-query"

// AdGuard Family - All Variants Active
#define DOH_ADGUARD "https://dns.adguard.com/dns-query"
#define DOH_ADGUARD_FAMILY "https://dns-family.adguard.com/dns-query"
#define DOH_ADGUARD_UNFILTERED "https://dns-unfiltered.adguard.com/dns-query"

// Mullvad VPN - Confirmed Active
#define DOH_MULLVAD "https://doh.mullvad.net/dns-query"
#define DOH_MULLVAD_ADBLOCK "https://adblock.doh.mullvad.net/dns-query"

// ControlD - All Filter Levels Active
#define DOH_CONTROLD "https://freedns.controld.com/p0"
#define DOH_CONTROLD_MALWARE "https://freedns.controld.com/p1"
#define DOH_CONTROLD_MALWARE_ADS "https://freedns.controld.com/p2"
#define DOH_CONTROLD_MALWARE_ADS_SOCIAL "https://freedns.controld.com/p3"

// CleanBrowsing - All Filter Types Active
#define DOH_CLEANBROWSING "https://doh.cleanbrowsing.org/doh/security-filter/"
#define DOH_CLEANBROWSING_FAMILY "https://doh.cleanbrowsing.org/doh/family-filter/"
#define DOH_CLEANBROWSING_ADULT "https://doh.cleanbrowsing.org/doh/adult-filter/"

// NextDNS - Active (requires config ID)
#define DOH_NEXTDNS "https://dns.nextdns.io/"

// LibreDNS - Confirmed Active
#define DOH_LIBREDNS "https://doh.libredns.gr/dns-query"
#define DOH_LIBREDNS_ADBLOCK "https://doh.libredns.gr/ads"

// Secondary Providers - Likely Active
#define DOH_SNOPYTA "https://fi.doh.dns.snopyta.org/dns-query"
#define DOH_POWERDNS "https://doh.powerdns.org"
#define DOH_APPLIED_PRIVACY "https://doh.applied-privacy.net/query"
#define DOH_DNS_SB "https://doh.dns.sb/dns-query"
#define DOH_DNS_SB_NO_FILTER "https://doh.sb/dns-query"

// Pi-DNS - Multiple Regional Endpoints
#define DOH_PI_DNS "https://doh.pi-dns.com/dns-query"
#define DOH_PI_DNS_NO_ECS "https://doh.centraleu.pi-dns.com/dns-query"
#define DOH_PI_DNS_EASTUS "https://doh.eastus.pi-dns.com/dns-query"
#define DOH_PI_DNS_WESTUS "https://doh.westus.pi-dns.com/dns-query"

// CIRA Canadian Shield - All Variants
#define DOH_CIRA "https://private.canadianshield.cira.ca/dns-query"
#define DOH_CIRA_FAMILY "https://family.canadianshield.cira.ca/dns-query"
#define DOH_CIRA_SECURITY "https://protected.canadianshield.cira.ca/dns-query"

// Exit codes
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define EXIT_INVALID_ARGS 2
#define EXIT_NETWORK_ERROR 3
#define EXIT_MEMORY_ERROR 4
#define EXIT_PERMISSION_ERROR 5
#define EXIT_COMPROMISED 6

#endif // CONFIG_H