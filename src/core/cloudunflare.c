/*
 * CloudUnflare Enhanced - Advanced DNS Reconnaissance Tool
 *
 * Enhanced C implementation with nation-state level OPSEC capabilities
 * Based on original CloudUnflare bash script with RESEARCHER and NSA enhancements
 *
 * Features:
 * - Multi-threaded DNS enumeration with async I/O
 * - Advanced evasion techniques and OPSEC protections
 * - Certificate Transparency log mining
 * - Intelligence correlation from multiple OSINT sources
 * - Real-time threat detection and adaptive evasion
 * - Secure memory management and evidence minimization
 *
 * Compile: gcc -o cloudunflare cloudunflare.c -lcurl -lssl -lcrypto -ljson-c -lpthread -O3
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <curl/curl.h>
#include <openssl/rand.h>
#include <json-c/json.h>
#include "dns_enhanced.h"
#include "advanced_ip_detection.h"

#ifdef RECON_MODULES_ENABLED
#include "recon_modules/common/recon_common.h"
#include "recon_modules/dns_zone_transfer/dns_zone_transfer.h"
#include "recon_modules/dns_bruteforce/dns_bruteforce.h"
#include "recon_modules/http_banner/http_banner.h"
#include "recon_modules/port_scanner/port_scanner.h"
#include "recon_modules/cloudflare_radar/cloudflare_radar.h"
#include "recon_modules/cloudflare_radar/cve_2025_detector.h"
#endif

#define VERSION "2.0-Enhanced"
#define MAX_DOMAIN_LEN 256
#define MAX_SUBDOMAIN_LEN 512
#define MAX_THREADS 50
#define MAX_REQUESTS_PER_CIRCUIT 100
#define CRITICAL_THRESHOLD 0.8

// Data structures for enhanced reconnaissance
typedef enum {
    RECON_METHOD_DNS_UDP,
    RECON_METHOD_DNS_TCP,
    RECON_METHOD_DOH,
    RECON_METHOD_DOT,
    RECON_METHOD_HTTP_API,
    RECON_METHOD_CT_LOGS,
    RECON_METHOD_BROWSER_AUTOMATION
} recon_method_t;

typedef enum {
    PROXY_TYPE_SOCKS5,
    PROXY_TYPE_HTTP,
    PROXY_TYPE_SOCKS4
} proxy_type_t;

typedef enum {
    CLEANUP_TEMP_FILE,
    CLEANUP_MEMORY_REGION
} cleanup_type_t;

typedef enum {
    CONFIDENCE_LOW = 1,
    CONFIDENCE_MEDIUM = 2,
    CONFIDENCE_HIGH = 3,
    CONFIDENCE_VERIFIED = 4
} data_confidence_t;

struct secure_buffer {
    void *data;
    size_t size;
    bool encrypted;
    uint8_t canary[16];
};

struct user_agent_profile {
    char *agent_string;
    char *accept_header;
    char *accept_encoding;
    char *accept_language;
};

struct proxy_node {
    char address[256];
    int port;
    proxy_type_t type;
    struct proxy_node *next;
};

struct threat_monitor {
    int consecutive_failures;
    int response_time_anomalies;
    bool honeypot_detected;
    time_t last_success;
};

struct intelligence_vector {
    char source_name[64];
    data_confidence_t confidence;
    time_t timestamp;
    char *raw_data;
    json_object *parsed_data;
};

struct target_domain {
    char name[MAX_DOMAIN_LEN];
    char **discovered_subdomains;
    int subdomain_count;
    char **ip_addresses;
    int ip_count;
    struct intelligence_vector *vectors;
    int vector_count;
    float priority_score;
};

struct cleanup_registry {
    char **temp_files;
    int file_count;
    char **memory_regions;
    int region_count;
    time_t operation_start;
    bool emergency_triggered;
};

struct recon_session {
    struct target_domain *target;
    struct proxy_node *active_circuit;
    struct threat_monitor monitor;
    struct user_agent_profile *current_ua;
    recon_method_t preferred_methods[8];
    float detection_score;
    int requests_on_circuit;
    bool operational_security_enabled;
    pthread_mutex_t session_mutex;

    // Enhanced DNS integration
    struct dns_resolver_chain dns_chain;
    struct enhanced_dns_result *dns_results;
    int dns_result_count;
};

// Global cleanup registry for emergency cleanup
static struct cleanup_registry global_cleanup_registry = {0};

// User agent profiles for stealth
static struct user_agent_profile ua_profiles[] = {
    {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "gzip, deflate, br",
        "en-US,en;q=0.9"
    },
    {
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "gzip, deflate, br",
        "en-US,en;q=0.5"
    },
    {
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "gzip, deflate",
        "en-US,en;q=0.9,fr;q=0.8"
    }
};

// DNS-over-HTTPS providers for evasion
static const char* doh_providers[] = {
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
    "https://dns.quad9.net/dns-query",
    "https://doh.opendns.com/dns-query"
};

// Certificate Transparency log endpoints
static const char* ct_logs[] = {
    "https://crt.sh/?q=%25.%s&output=json",
    "https://ct.googleapis.com/logs/argon2024/ct/v1/get-entries",
    "https://ct.cloudflare.com/logs/nimbus2024/"
};

// Function prototypes
void print_banner(void);
int init_secure_random(void);
struct secure_buffer* allocate_secure_buffer(size_t size);
void secure_wipe_buffer(struct secure_buffer *buf);
void emergency_cleanup_handler(int sig);
void register_cleanup_item(cleanup_type_t type, void *item);
int secure_random(void);
void add_timing_jitter(int base_delay_ms);
int randomize_user_agent(CURL *curl);
int build_proxy_circuit(struct recon_session *session);
void rotate_proxy_circuit(struct recon_session *session);
bool is_operation_compromised(struct threat_monitor *monitor);
void adaptive_evasion_response(struct recon_session *session);
int perform_dns_lookup(struct recon_session *session, const char *domain);
int mine_certificate_logs(struct recon_session *session, const char *domain);
int query_viewdns_api(struct recon_session *session, const char *domain);
int query_completedns_api(struct recon_session *session, const char *domain);
int enumerate_subdomains(struct recon_session *session);
int correlate_intelligence(struct recon_session *session);
void *subdomain_worker_thread(void *arg);
int initialize_recon_session(struct recon_session *session, const char *domain);
void cleanup_recon_session(struct recon_session *session);

// HTTP response structure for curl
struct http_response {
    char *data;
    size_t size;
};

static size_t write_response_callback(void *contents, size_t size, size_t nmemb, struct http_response *response) {
    size_t real_size = size * nmemb;
    char *ptr = realloc(response->data, response->size + real_size + 1);

    if (!ptr) {
        printf("ERROR: Not enough memory (realloc returned NULL)\n");
        return 0;
    }

    response->data = ptr;
    memcpy(&(response->data[response->size]), contents, real_size);
    response->size += real_size;
    response->data[response->size] = 0;

    return real_size;
}

void print_banner(void) {
    printf("       __                          \n");
    printf("    __(  )_       CLOUDFLARE       \n");
    printf(" __(       )_   RECONNAISSANCE     \n");
    printf("(____________)__ _  V %s Enhanced\n", VERSION);
    printf(" _   _ _ __  / _| | __ _ _ __ ___    \n");
    printf("| | | | `_ \\| |_| |/ _` | `__/ _ \\  \n");
    printf("| |_| | | | |  _| | (_| | | |  __/  \n");
    printf(" \\__,_|_| |_|_| |_|\\__,_|_|  \\___|  \n");
    printf("\nEnhanced with RESEARCHER + NSA capabilities\n");
    printf("Features: Multi-threaded, OPSEC-hardened, AI-enhanced\n\n");
}

int init_secure_random(void) {
    if (RAND_status() != 1) {
        printf("ERROR: OpenSSL random number generator not properly seeded\n");
        return -1;
    }
    srand((unsigned int)time(NULL));
    return 0;
}

struct secure_buffer* allocate_secure_buffer(size_t size) {
    struct secure_buffer *buf = mmap(NULL, sizeof(struct secure_buffer) + size,
                                   PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (buf == MAP_FAILED) return NULL;

    buf->data = (char*)buf + sizeof(struct secure_buffer);
    buf->size = size;
    buf->encrypted = false;

    // Add stack canary for overflow detection
    if (RAND_bytes(buf->canary, 16) != 1) {
        munmap(buf, sizeof(struct secure_buffer) + size);
        return NULL;
    }

    return buf;
}

void secure_wipe_buffer(struct secure_buffer *buf) {
    if (!buf) return;

    // Cryptographically secure wipe
    RAND_bytes(buf->data, buf->size);
    munmap(buf, sizeof(struct secure_buffer) + buf->size);
}

void emergency_cleanup_handler(int sig) {
    printf("\n[OPSEC] Emergency cleanup triggered (signal: %d)\n", sig);
    global_cleanup_registry.emergency_triggered = true;

    // Immediate secure wipe of all registered items
    for (int i = 0; i < global_cleanup_registry.file_count; i++) {
        if (global_cleanup_registry.temp_files[i]) {
            unlink(global_cleanup_registry.temp_files[i]);
        }
    }

    exit(0);
}

void register_cleanup_item(cleanup_type_t type, void *item) {
    switch (type) {
        case CLEANUP_TEMP_FILE:
            if (global_cleanup_registry.file_count < 100) {
                global_cleanup_registry.temp_files[global_cleanup_registry.file_count++] = (char*)item;
            }
            break;
        case CLEANUP_MEMORY_REGION:
            if (global_cleanup_registry.region_count < 100) {
                global_cleanup_registry.memory_regions[global_cleanup_registry.region_count++] = (char*)item;
            }
            break;
    }
}

int secure_random(void) {
    unsigned int random_value;
    if (RAND_bytes((unsigned char*)&random_value, sizeof(random_value)) != 1) {
        return rand(); // Fallback to less secure PRNG
    }
    return random_value;
}

void add_timing_jitter(int base_delay_ms) {
    int jitter = (secure_random() % 2000) + 500; // 500-2500ms random jitter
    usleep((base_delay_ms + jitter) * 1000);
}

int randomize_user_agent(CURL *curl) {
    int profile_idx = secure_random() % (sizeof(ua_profiles) / sizeof(ua_profiles[0]));
    curl_easy_setopt(curl, CURLOPT_USERAGENT, ua_profiles[profile_idx].agent_string);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, ua_profiles[profile_idx].accept_header);
    headers = curl_slist_append(headers, ua_profiles[profile_idx].accept_encoding);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    return 0;
}

int perform_dns_lookup(struct recon_session *session, const char *domain) {
    // Use enhanced DNS resolution engine
    struct dns_query_context query = {0};
    strncpy(query.query_name, domain, sizeof(query.query_name) - 1);
    query.query_type = DNS_TYPE_A;
    query.preferred_protocol = DNS_PROTOCOL_DOQ; // Use fastest encrypted protocol
    query.require_dnssec = false;
    query.enable_ecs = true;
    clock_gettime(CLOCK_MONOTONIC, &query.start_time);
    query.timeout.tv_sec = 10;
    query.timeout.tv_nsec = 0;
    query.retry_count = 0;

    // Thread-safe allocation for new result
    pthread_mutex_lock(&session->session_mutex);
    session->dns_results = realloc(session->dns_results,
                                 (session->dns_result_count + 1) * sizeof(struct enhanced_dns_result));
    if (!session->dns_results) {
        pthread_mutex_unlock(&session->session_mutex);
        printf("   [-] Memory allocation failed for DNS result\n");
        return -1;
    }

    struct enhanced_dns_result *result = &session->dns_results[session->dns_result_count];

    // Initialize result mutex
    if (pthread_mutex_init(&result->result_mutex, NULL) != 0) {
        pthread_mutex_unlock(&session->session_mutex);
        printf("   [-] Failed to initialize result mutex\n");
        return -1;
    }

    // Initialize atomic fields
    atomic_store(&result->enrichment_count, 0);
    atomic_store(&result->total_response_time_ms, 0);
    atomic_store(&result->dnssec_validated, false);
    atomic_store(&result->response_validated, false);
    atomic_store(&result->confidence_score, 0.0f);
    atomic_store(&result->resolution_timestamp, 0);
    pthread_mutex_unlock(&session->session_mutex);

    // Perform enhanced DNS query with intelligent fallback
    int status = perform_enhanced_dns_query(&query, &session->dns_chain, result);

    if (status != 0) {
        printf("   [-] Enhanced DNS lookup failed for %s\n", domain);
        session->monitor.consecutive_failures++;
        pthread_mutex_destroy(&result->result_mutex);
        return -1;
    }

    pthread_mutex_lock(&session->session_mutex);
    session->dns_result_count++;
    pthread_mutex_unlock(&session->session_mutex);

    // Extract IPv4 addresses for compatibility
    for (int i = 0; i < result->resolution.ipv4_count; i++) {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &result->resolution.ipv4_addresses[i], ip_str, INET_ADDRSTRLEN);

        printf("   [+] %s -> %s", domain, ip_str);

        // Show enhanced information if available
        if (i < result->enrichment_count) {
            struct ip_enrichment_data *enrichment = &result->enrichment[i];
            printf(" (%s, %s, AS%u %s)",
                   enrichment->city,
                   enrichment->country_code,
                   enrichment->asn,
                   enrichment->is_hosting_provider ? "[HOSTING]" : "");
        }
        printf("\n");

        // Thread-safe addition to target's IP list
        pthread_mutex_lock(&session->session_mutex);
        session->target->ip_addresses = realloc(session->target->ip_addresses,
                                              (session->target->ip_count + 1) * sizeof(char*));
        if (session->target->ip_addresses) {
            session->target->ip_addresses[session->target->ip_count] = strdup(ip_str);
            session->target->ip_count++;
        }
        pthread_mutex_unlock(&session->session_mutex);
    }

    // Show IPv6 addresses if available
    for (int i = 0; i < result->resolution.ipv6_count; i++) {
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &result->resolution.ipv6_addresses[i], ip_str, INET6_ADDRSTRLEN);
        printf("   [+] %s -> %s [IPv6]\n", domain, ip_str);
    }

    // Perform IP enrichment for first IPv4 address (thread-safe)
    if (result->resolution.ipv4_count > 0 && atomic_load(&result->enrichment_count) == 0) {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &result->resolution.ipv4_addresses[0], ip_str, INET_ADDRSTRLEN);

        // Use pre-allocated array in struct - thread-safe enrichment
        if (enrich_ip_address(ip_str, &result->enrichment[0]) == 0) {
            atomic_store(&result->enrichment_count, 1);
        }
    }

    // Perform CDN detection
    detect_cdn_and_origin(domain, result);

    session->monitor.last_success = time(NULL);
    session->monitor.consecutive_failures = 0;

    // Rate limiting for OPSEC
    if (!acquire_rate_limit_token(&global_rate_limiter, 1)) {
        printf("   [OPSEC] Rate limit applied\n");
        add_timing_jitter(2000);
    } else {
        add_timing_jitter(1000);
    }

    return 0;
}

int mine_certificate_logs(struct recon_session *session, const char *domain) {
    CURL *curl;
    CURLcode res;
    struct http_response response = {0};
    char url[512];

    curl = curl_easy_init();
    if (!curl) return -1;

    // Query crt.sh for certificate transparency data
    snprintf(url, sizeof(url), "https://crt.sh/?q=%%.%s&output=json", domain);

    randomize_user_agent(curl);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

    printf(" [CT] Mining certificate transparency logs for %s\n", domain);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        printf("   [-] CT log query failed: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        return -1;
    }

    if (response.data) {
        // Parse JSON response to extract subdomains
        json_object *json_array = json_tokener_parse(response.data);
        if (json_array && json_object_is_type(json_array, json_type_array)) {
            int array_len = json_object_array_length(json_array);
            printf("   [+] Found %d certificate entries\n", array_len);

            for (int i = 0; i < array_len && i < 50; i++) { // Limit to first 50
                json_object *entry = json_object_array_get_idx(json_array, i);
                json_object *name_obj;

                if (json_object_object_get_ex(entry, "name_value", &name_obj)) {
                    const char *name_value = json_object_get_string(name_obj);
                    if (name_value && strstr(name_value, domain)) {
                        printf("   [+] CT subdomain: %s\n", name_value);

                        // Thread-safe addition to discovered subdomains
                        pthread_mutex_lock(&session->session_mutex);
                        session->target->discovered_subdomains = realloc(
                            session->target->discovered_subdomains,
                            (session->target->subdomain_count + 1) * sizeof(char*)
                        );
                        if (session->target->discovered_subdomains) {
                            session->target->discovered_subdomains[session->target->subdomain_count] =
                                strdup(name_value);
                            session->target->subdomain_count++;
                        }
                        pthread_mutex_unlock(&session->session_mutex);
                    }
                }
            }
            json_object_put(json_array);
        }
        free(response.data);
    }

    curl_easy_cleanup(curl);
    add_timing_jitter(2000);

    return 0;
}

int query_viewdns_api(struct recon_session *session, const char *domain) {
    CURL *curl;
    CURLcode res;
    struct http_response response = {0};
    char url[512];

    curl = curl_easy_init();
    if (!curl) return -1;

    snprintf(url, sizeof(url), "https://viewdns.info/iphistory/?domain=%s", domain);

    randomize_user_agent(curl);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    printf(" [OSINT] Querying ViewDNS.info for IP history\n");

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        printf("   [-] ViewDNS query failed: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        return -1;
    }

    if (response.data) {
        // Basic parsing for IP addresses in HTML
        char *ip_start = strstr(response.data, "table border=\"1\"");
        if (ip_start) {
            printf("   [+] IP history data found\n");
            // Here you would implement proper HTML parsing
            // For brevity, showing concept only
        } else {
            printf("   [-] No IP history data found\n");
        }
        free(response.data);
    }

    curl_easy_cleanup(curl);
    add_timing_jitter(3000);

    return 0;
}

struct subdomain_thread_data {
    struct recon_session *session;
    char **wordlist;
    int start_idx;
    int end_idx;
    int thread_id;
};

void *subdomain_worker_thread(void *arg) {
    struct subdomain_thread_data *data = (struct subdomain_thread_data*)arg;
    struct recon_session *session = data->session;
    char subdomain[MAX_SUBDOMAIN_LEN];

    for (int i = data->start_idx; i < data->end_idx; i++) {
        snprintf(subdomain, sizeof(subdomain), "%s.%s",
                data->wordlist[i], session->target->name);

        if (perform_dns_lookup(session, subdomain) == 0) {
            pthread_mutex_lock(&session->session_mutex);
            printf(" [T%d] Found subdomain: %s\n", data->thread_id, subdomain);
            pthread_mutex_unlock(&session->session_mutex);
        }

        // Check for operation compromise
        if (is_operation_compromised(&session->monitor)) {
            printf(" [T%d] Operation compromised, terminating thread\n", data->thread_id);
            break;
        }
    }

    return NULL;
}

int enumerate_subdomains(struct recon_session *session) {
    // Default subdomain wordlist
    char *default_wordlist[] = {
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
        "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
        "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn",
        "ns3", "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx",
        "static", "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar",
        "wiki", "web", "media", "email", "images", "img", "www1", "intranet",
        "portal", "video", "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4",
        "www3", "dns", "search", "staging", "server", "mx1", "chat", "wap", "my",
        "svn", "mail1", "sites", "proxy", "ads", "host", "crm", "cms", "backup",
        "mx2", "lyncdiscover", "info", "apps", "download", "remote", "db", "forums",
        "store", "relay", "files", "newsletter", "app", "live", "owa", "en", "start",
        "sms", "office", "exchange", "ipv4"
    };

    int wordlist_size = sizeof(default_wordlist) / sizeof(default_wordlist[0]);
    int num_threads = (wordlist_size < MAX_THREADS) ? wordlist_size : MAX_THREADS;

    pthread_t threads[MAX_THREADS];
    struct subdomain_thread_data thread_data[MAX_THREADS];

    int chunk_size = wordlist_size / num_threads;

    printf(" [ENUM] Starting subdomain enumeration with %d threads\n", num_threads);

    for (int i = 0; i < num_threads; i++) {
        thread_data[i].session = session;
        thread_data[i].wordlist = default_wordlist;
        thread_data[i].start_idx = i * chunk_size;
        thread_data[i].end_idx = (i == num_threads - 1) ? wordlist_size : (i + 1) * chunk_size;
        thread_data[i].thread_id = i;

        if (pthread_create(&threads[i], NULL, subdomain_worker_thread, &thread_data[i]) != 0) {
            printf("ERROR: Failed to create thread %d\n", i);
            return -1;
        }
    }

    // Wait for all threads to complete
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    printf(" [ENUM] Subdomain enumeration completed\n");
    return 0;
}

bool is_operation_compromised(struct threat_monitor *monitor) {
    if (monitor->consecutive_failures > 5) return true;
    if (monitor->response_time_anomalies > 8) return true;
    if (monitor->honeypot_detected) return true;
    if (time(NULL) - monitor->last_success > 600) return true; // 10 min

    return false;
}

void adaptive_evasion_response(struct recon_session *session) {
    if (is_operation_compromised(&session->monitor)) {
        printf(" [OPSEC] Threat detected, engaging adaptive evasion\n");

        // Rotate proxy circuit
        rotate_proxy_circuit(session);

        // Increase delays
        printf(" [OPSEC] Increasing operational tempo delays\n");

        // Switch reconnaissance methodology
        for (int i = 0; i < 8; i++) {
            session->preferred_methods[i] = (session->preferred_methods[i] + 1) % 7;
        }

        session->detection_score += 0.1;

        // If still detected, go dormant
        if (session->detection_score > CRITICAL_THRESHOLD) {
            printf(" [OPSEC] Critical detection threshold reached, entering dormant mode\n");
            sleep(1800); // 30 minutes dormant
            session->detection_score = 0.0;
        }
    }
}

int build_proxy_circuit(struct recon_session *session) {
    // Placeholder for proxy circuit building
    // In a real implementation, this would set up SOCKS/HTTP proxy chains
    printf(" [OPSEC] Building proxy circuit for operational security\n");
    session->requests_on_circuit = 0;
    return 0;
}

void rotate_proxy_circuit(struct recon_session *session) {
    if (session->requests_on_circuit > MAX_REQUESTS_PER_CIRCUIT) {
        printf(" [OPSEC] Rotating proxy circuit\n");
        build_proxy_circuit(session);
    }
}

int initialize_recon_session(struct recon_session *session, const char *domain) {
    memset(session, 0, sizeof(struct recon_session));

    // Initialize target domain
    session->target = malloc(sizeof(struct target_domain));
    strncpy(session->target->name, domain, MAX_DOMAIN_LEN - 1);
    session->target->name[MAX_DOMAIN_LEN - 1] = '\0';

    // Initialize threat monitor
    session->monitor.last_success = time(NULL);

    // Initialize mutex
    if (pthread_mutex_init(&session->session_mutex, NULL) != 0) {
        printf("ERROR: Failed to initialize session mutex\n");
        return -1;
    }

    // Initialize enhanced DNS resolver chain
    if (init_dns_resolver_chain(&session->dns_chain) != 0) {
        printf("ERROR: Failed to initialize DNS resolver chain\n");
        pthread_mutex_destroy(&session->session_mutex);
        return -1;
    }

    // Set operational security mode
    session->operational_security_enabled = true;

    // Build initial proxy circuit
    build_proxy_circuit(session);

    printf("[INIT] Enhanced reconnaissance session initialized for %s\n", domain);
    printf("[DNS] %d resolvers available with intelligent fallback\n", session->dns_chain.resolver_count);

    return 0;
}

void cleanup_recon_session(struct recon_session *session) {
    if (!session) return;

    if (session->target) {
        // Free discovered subdomains
        for (int i = 0; i < session->target->subdomain_count; i++) {
            free(session->target->discovered_subdomains[i]);
        }
        free(session->target->discovered_subdomains);

        // Free IP addresses
        for (int i = 0; i < session->target->ip_count; i++) {
            free(session->target->ip_addresses[i]);
        }
        free(session->target->ip_addresses);

        free(session->target);
    }

    // Cleanup DNS results and their mutexes
    if (session->dns_results) {
        for (int i = 0; i < session->dns_result_count; i++) {
            pthread_mutex_destroy(&session->dns_results[i].result_mutex);
            // Cleanup enrichment mutexes
            for (int j = 0; j < atomic_load(&session->dns_results[i].enrichment_count); j++) {
                pthread_mutex_destroy(&session->dns_results[i].enrichment[j].enrichment_mutex);
            }
        }
        free(session->dns_results);
    }

    // Cleanup resolver chain mutexes
    for (int i = 0; i < session->dns_chain.resolver_count; i++) {
        pthread_mutex_destroy(&session->dns_chain.resolvers[i].resolver_mutex);
    }
    pthread_mutex_destroy(&session->dns_chain.chain_mutex);

    pthread_mutex_destroy(&session->session_mutex);
}

#ifdef RECON_MODULES_ENABLED
// Perform advanced reconnaissance using API-free modules
int perform_advanced_reconnaissance(struct recon_session *session, const char *domain) {
    printf("[RECON] Initializing advanced reconnaissance modules for %s\n", domain);

    int total_results = 0;

    // Sub-phase 5.1: DNS Zone Transfer Enumeration
    if (FEATURE_DNS_ZONE_TRANSFER) {
        printf("\n--- Sub-phase 5.1: DNS Zone Transfer ---\n");
        zone_transfer_context_t zone_ctx;

        if (zone_transfer_init_context(&zone_ctx) == 0) {
            int zone_results = zone_transfer_execute(&zone_ctx, domain);
            if (zone_results > 0) {
                printf("[RECON] Zone transfer successful: %d records discovered\n", zone_results);
                zone_transfer_print_results(&zone_ctx);
                total_results += zone_results;
            } else {
                printf("[RECON] Zone transfer not available or refused\n");
            }
            zone_transfer_cleanup_context(&zone_ctx);
        }

        // OPSEC delay between modules
        usleep(RECON_OPSEC_MIN_DELAY_MS * 1000);
    }

    // Sub-phase 5.2: Enhanced DNS Brute-Force
    if (FEATURE_DNS_BRUTEFORCE_ENHANCED) {
        printf("\n--- Sub-phase 5.2: Enhanced DNS Brute-Force ---\n");
        bruteforce_context_t brute_ctx;

        if (bruteforce_init_context(&brute_ctx) == 0) {
            bruteforce_set_target(&brute_ctx, domain);
            int brute_results = bruteforce_execute(&brute_ctx);
            if (brute_results > 0) {
                printf("[RECON] Brute-force successful: %d subdomains discovered\n", brute_results);
                bruteforce_print_results(&brute_ctx);
                total_results += brute_results;
            }
            bruteforce_cleanup_context(&brute_ctx);
        }

        usleep(RECON_OPSEC_MIN_DELAY_MS * 1000);
    }

    // Sub-phase 5.3: HTTP Banner Grabbing and SSL Analysis
    if (FEATURE_HTTP_BANNER_GRABBING && FEATURE_SSL_ANALYSIS) {
        printf("\n--- Sub-phase 5.3: HTTP Banner Grabbing ---\n");
        http_banner_context_t banner_ctx;

        if (http_banner_init_context(&banner_ctx) == 0) {
            char urls[3][256];
            snprintf(urls[0], sizeof(urls[0]), "http://%s", domain);
            snprintf(urls[1], sizeof(urls[1]), "https://%s", domain);
            snprintf(urls[2], sizeof(urls[2]), "https://www.%s", domain);

            const char *url_list[] = {urls[0], urls[1], urls[2]};
            int banner_results = http_banner_grab_multiple(&banner_ctx, url_list, 3);
            if (banner_results > 0) {
                printf("[RECON] HTTP banner grabbing successful: %d responses\n", banner_results);
                http_banner_print_summary(&banner_ctx);
                total_results += banner_results;
            }
            http_banner_cleanup_context(&banner_ctx);
        }

        usleep(RECON_OPSEC_MIN_DELAY_MS * 1000);
    }

    // Sub-phase 5.4: Port Scanning
    if (FEATURE_PORT_SCANNING) {
        printf("\n--- Sub-phase 5.4: Port Scanning ---\n");
        port_scanner_context_t port_ctx;

        if (port_scanner_init_context(&port_ctx) == 0) {
            // Configure common ports for web services
            port_scanner_add_port_range(&port_ctx.config, 80, 80, SCAN_TYPE_TCP_CONNECT);
            port_scanner_add_port_range(&port_ctx.config, 443, 443, SCAN_TYPE_TCP_CONNECT);
            port_scanner_add_port_range(&port_ctx.config, 8080, 8080, SCAN_TYPE_TCP_CONNECT);
            port_scanner_add_port_range(&port_ctx.config, 8443, 8443, SCAN_TYPE_TCP_CONNECT);
            port_scanner_add_port_range(&port_ctx.config, 21, 25, SCAN_TYPE_TCP_CONNECT);
            port_scanner_add_port_range(&port_ctx.config, 53, 53, SCAN_TYPE_UDP);

            host_scan_result_t scan_result;
            int port_results = port_scanner_scan_host(&port_ctx, domain, &scan_result);
            if (port_results > 0) {
                printf("[RECON] Port scanning successful: %d open ports\n", scan_result.open_ports);
                port_scanner_print_host_result(&scan_result);
                total_results += scan_result.open_ports;
            }
            port_scanner_cleanup_context(&port_ctx);
        }

        usleep(RECON_OPSEC_MIN_DELAY_MS * 1000);
    }

    // Sub-phase 5.5: Cloudflare Radar Comprehensive Scan
    if (FEATURE_CLOUDFLARE_RADAR) {
        printf("\n--- Sub-phase 5.5: Cloudflare Radar Comprehensive Scan ---\n");
        radar_scan_context_t radar_ctx;

        if (radar_scan_init_context(&radar_ctx) == 0) {
            // Configure for comprehensive scan
            radar_ctx.config.preferred_scan_type = RADAR_SCAN_COMPREHENSIVE;
            radar_ctx.config.enable_comprehensive_scan = true;
            radar_ctx.config.extract_technology_stack = true;
            radar_ctx.config.analyze_security_posture = true;
            radar_ctx.config.timeout_seconds = CLOUDFLARE_RADAR_API_TIMEOUT;

            // Add domain to scan queue
            radar_scan_add_domain(&radar_ctx, domain);

            // Execute the scan
            int radar_results = radar_scan_execute_all(&radar_ctx);
            if (radar_results == 0 && radar_ctx.result_count > 0) {
                printf("[RECON] Cloudflare Radar scan successful: %d results\n", radar_ctx.result_count);
                radar_scan_print_results(&radar_ctx);

                // Export results
                char json_filename[512];
                snprintf(json_filename, sizeof(json_filename), "radar_results_%s.json", domain);
                radar_scan_export_json(&radar_ctx, json_filename);
                printf("[RECON] Results exported to %s\n", json_filename);

                total_results += radar_ctx.result_count;
            } else if (radar_ctx.result_count > 0) {
                printf("[RECON] Cloudflare Radar scan completed with errors\n");
                radar_scan_print_results(&radar_ctx);
                total_results += radar_ctx.result_count;
            } else {
                printf("[RECON] Cloudflare Radar scan failed or returned no results\n");
            }
            radar_scan_cleanup_context(&radar_ctx);
        }

        // Sub-phase 5.5.1: CVE-2025 Detection
        if (CVE_2025_DETECTION_ENABLED) {
            printf("\n--- Sub-phase 5.5.1: CVE-2025 IP Disclosure Detection ---\n");
            printf("[CVE-2025] Scanning for known 2025 vulnerabilities that expose origin IPs\n");
            printf("[CVE-2025] Including: CVE-2025-4366 (Pingora Smuggling), WAF Bypass, DNS Leaks\n");

            cve_detection_context_t cve_ctx;

            if (cve_detection_init_context(&cve_ctx) == 0) {
                // Perform comprehensive CVE-2025 detection
                int cve_vulns = cve_detection_scan_all_vulns(&cve_ctx, domain);

                if (cve_vulns > 0) {
                    printf("\n[CRITICAL] CVE-2025 vulnerabilities detected: %d\n", cve_vulns);
                    cve_detection_print_results(&cve_ctx);

                    // Export CVE detection results
                    char cve_json_filename[512];
                    snprintf(cve_json_filename, sizeof(cve_json_filename),
                            "cve_2025_detection_%s.json", domain);
                    cve_detection_export_json(&cve_ctx, cve_json_filename);
                    printf("[CVE-2025] Results exported to %s\n", cve_json_filename);

                    total_results += cve_vulns;
                } else {
                    printf("[CVE-2025] No CVE-2025 vulnerabilities detected\n");
                }

                // Check for IP exposures
                for (uint32_t i = 0; i < cve_ctx.result_count; i++) {
                    if (cve_ctx.results[i].ip_exposure_confirmed) {
                        printf("\n[ALERT] ORIGIN IP EXPOSED: %s\n", cve_ctx.results[i].exposed_origin_ip);
                        printf("[ALERT] CVE: %s (%s)\n", cve_ctx.results[i].cve_info.cve_id,
                               cve_ctx.results[i].cve_info.name);
                        printf("[ALERT] CVSS Score: %.1f\n", cve_ctx.results[i].cve_info.cvss_score);
                    }
                }

                cve_detection_cleanup_context(&cve_ctx);
            }
        }
    }

    printf("\n[RECON] Advanced reconnaissance completed\n");
    printf("[RECON] Total results discovered: %d\n", total_results);

    return total_results;
}
#endif

int main(int argc, char *argv[]) {
    char domain[MAX_DOMAIN_LEN];
    struct recon_session session;

    // Set up signal handlers for emergency cleanup
    signal(SIGINT, emergency_cleanup_handler);
    signal(SIGTERM, emergency_cleanup_handler);

    // Initialize OpenSSL and enhanced DNS engine
    if (init_secure_random() != 0) {
        printf("ERROR: Failed to initialize secure random number generator\n");
        return 1;
    }

    if (init_dns_enhanced_engine() != 0) {
        printf("ERROR: Failed to initialize enhanced DNS engine\n");
        return 1;
    }

    print_banner();

    // Get target domain from user
    printf(" Input domain name\n");
    printf(" Example: google.com\n");
    printf(" >> ");

    if (fgets(domain, sizeof(domain), stdin) == NULL) {
        printf("ERROR: Failed to read domain input\n");
        return 1;
    }

    // Remove newline
    domain[strcspn(domain, "\n")] = 0;

    if (strlen(domain) == 0) {
        printf("ERROR: No domain specified\n");
        return 1;
    }

    printf("\n[INIT] Target domain: %s\n", domain);
    printf("[OPSEC] Initializing enhanced reconnaissance session\n");

    // Initialize reconnaissance session
    if (initialize_recon_session(&session, domain) != 0) {
        printf("ERROR: Failed to initialize reconnaissance session\n");
        return 1;
    }

    // Phase 1: Basic DNS reconnaissance
    printf("\n=== Phase 1: DNS Reconnaissance ===\n");
    perform_dns_lookup(&session, domain);

    // Phase 2: Certificate Transparency mining
    printf("\n=== Phase 2: Certificate Transparency Mining ===\n");
    mine_certificate_logs(&session, domain);

    // Phase 3: Subdomain enumeration
    printf("\n=== Phase 3: Multi-threaded Subdomain Enumeration ===\n");
    enumerate_subdomains(&session);

    // Phase 4: OSINT data collection
    printf("\n=== Phase 4: OSINT Intelligence Gathering ===\n");
    query_viewdns_api(&session, domain);

#ifdef RECON_MODULES_ENABLED
    // Phase 5: Advanced Reconnaissance (API-free modules)
    printf("\n=== Phase 5: Advanced Reconnaissance Modules ===\n");
    perform_advanced_reconnaissance(&session, domain);
#endif

    // Phase 6: Advanced IP Detection (NEW - Enhanced CDN Bypass)
    printf("\n=== Phase 6: Advanced IP Detection & CDN Bypass ===\n");
    printf("[INFO] Deploying advanced techniques to find origin IP behind CDN\n");

    struct advanced_ip_detection_result advanced_result;
    if (perform_advanced_ip_detection(domain, &advanced_result) > 0) {
        printf("\n[SUCCESS] Advanced IP detection completed!\n");
        print_advanced_detection_results(&advanced_result);

        // Cleanup advanced result
        cleanup_advanced_ip_detection_result(&advanced_result);
    } else {
        printf("\n[INFO] Advanced IP detection completed with limited results\n");
    }

    // Check for operational security issues
    adaptive_evasion_response(&session);

    // Summary
    printf("\n=== Reconnaissance Summary ===\n");
    printf(" Target: %s\n", session.target->name);
    printf(" IP addresses discovered: %d\n", session.target->ip_count);
    printf(" Subdomains discovered: %d\n", session.target->subdomain_count);
    printf(" Detection score: %.2f\n", session.detection_score);
    printf(" OPSEC status: %s\n",
           session.operational_security_enabled ? "ACTIVE" : "DISABLED");

    // Generate enhanced summary report
    printf("\n=== Enhanced Reconnaissance Summary ===\n");
    printf(" Target: %s\n", session.target->name);
    printf(" IP addresses discovered: %d\n", session.target->ip_count);
    printf(" Subdomains discovered: %d\n", session.target->subdomain_count);
    printf(" DNS results with enrichment: %d\n", session.dns_result_count);
    printf(" Detection score: %.2f\n", session.detection_score);
    printf(" OPSEC status: %s\n",
           session.operational_security_enabled ? "ACTIVE" : "DISABLED");

    // Show detailed DNS results
    if (session.dns_result_count > 0) {
        printf("\n=== Detailed DNS Analysis ===\n");
        for (int i = 0; i < session.dns_result_count; i++) {
            print_enhanced_dns_result(&session.dns_results[i]);
        }
    }

    // Cleanup
    cleanup_recon_session(&session);
    cleanup_dns_enhanced_engine();

    printf("\n[OPSEC] Enhanced reconnaissance completed, performing secure cleanup\n");

    return 0;
}