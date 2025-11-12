/*
 * Advanced IP Detection Module
 * Enhanced techniques to discover origin IPs behind Cloudflare and other CDNs
 *
 * Techniques Implemented:
 * 1. SSL Certificate Comparison - Direct IP testing with cert matching
 * 2. Advanced MX Record Enumeration - Mail server infrastructure analysis
 * 3. Expanded SRV Record Discovery - 15+ service types
 * 4. Cloudflare-Specific Bypass Techniques - Origin IP discovery
 * 5. IP Block/ASN Clustering - Infrastructure analysis
 * 6. Enhanced Reverse DNS - PTR record intelligence
 * 7. Passive DNS Integration - Historical IP data
 * 8. WHOIS Netblock Discovery - IP ownership chains
 * 9. HTTP Header Analysis - Origin server detection
 * 10. Subdomain SSL Certificate SNI Testing
 */

#ifndef ADVANCED_IP_DETECTION_H
#define ADVANCED_IP_DETECTION_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include "dns_enhanced.h"

// SSL Certificate Information
struct ssl_certificate_info {
    char subject[256];
    char issuer[256];
    char common_name[256];
    char **san_entries;  // Subject Alternative Names
    int san_count;
    char serial_number[128];
    char fingerprint_sha256[65];
    time_t not_before;
    time_t not_after;
    bool is_wildcard;
    bool self_signed;
};

// Origin IP Candidate
struct origin_ip_candidate {
    char ip_address[INET6_ADDRSTRLEN];
    float confidence_score;  // 0.0 to 1.0
    char discovery_method[128];
    struct ssl_certificate_info *cert_info;
    char **supporting_evidence;
    int evidence_count;
    uint32_t asn;
    char asn_name[256];
    char hosting_provider[256];
    time_t discovered_at;
    bool verified;
};

// MX Record Information
struct mx_record_info {
    char hostname[256];
    uint16_t priority;
    char ip_addresses[8][INET_ADDRSTRLEN];
    int ip_count;
    char reverse_dns[8][256];
    int reverse_dns_count;
    uint32_t asn;
    char asn_name[256];
    bool likely_origin_network;
};

// SRV Record Information
struct srv_record_info {
    char service_name[128];  // e.g., "_sip._tcp", "_xmpp._tcp"
    char target_host[256];
    uint16_t port;
    uint16_t priority;
    uint16_t weight;
    char ip_addresses[4][INET_ADDRSTRLEN];
    int ip_count;
};

// ASN/Network Block Information
struct asn_network_info {
    uint32_t asn;
    char asn_name[256];
    char ip_range[64];  // CIDR notation
    int discovered_ip_count;
    char **discovered_ips;
    float confidence_as_origin;
    char organization[256];
    char country[4];
};

// Passive DNS Record
struct passive_dns_record {
    char ip_address[INET_ADDRSTRLEN];
    time_t first_seen;
    time_t last_seen;
    char source[64];
    bool before_cdn;  // Was this IP used before CDN adoption?
};

// Cloudflare-Specific Bypass Information
struct cloudflare_bypass_info {
    bool direct_connect_possible;
    char bypass_subdomains[16][256];
    int bypass_subdomain_count;
    char origin_ips[8][INET_ADDRSTRLEN];
    int origin_ip_count;
    char suggested_techniques[512];
};

// HTTP Header Analysis Result
struct http_header_analysis {
    char server_header[256];
    char x_powered_by[256];
    char via_header[256];
    char x_real_ip[INET_ADDRSTRLEN];
    char x_forwarded_for[INET_ADDRSTRLEN];
    char cf_ray[64];
    char cf_connecting_ip[INET_ADDRSTRLEN];
    bool behind_cloudflare;
    bool behind_cdn;
    char cdn_provider[128];
};

// WHOIS Information
struct whois_info {
    char netblock[64];  // CIDR notation
    char organization[256];
    char abuse_contact[256];
    char country[4];
    char allocated_date[32];
    char **related_netblocks;
    int related_netblock_count;
};

// Comprehensive IP Detection Result
struct advanced_ip_detection_result {
    char target_domain[256];

    // Origin IP Candidates
    struct origin_ip_candidate *candidates;
    int candidate_count;
    _Atomic int candidate_capacity;
    pthread_mutex_t candidates_mutex;

    // Mail Server Analysis
    struct mx_record_info *mx_records;
    int mx_record_count;

    // Service Discovery
    struct srv_record_info *srv_records;
    int srv_record_count;

    // Network Infrastructure
    struct asn_network_info *asn_networks;
    int asn_network_count;

    // Historical Data
    struct passive_dns_record *passive_dns_records;
    int passive_dns_count;

    // Cloudflare-Specific
    struct cloudflare_bypass_info cloudflare_bypass;

    // HTTP Analysis
    struct http_header_analysis header_analysis;

    // WHOIS Data
    struct whois_info *whois_data;
    int whois_data_count;

    // Overall Assessment
    char most_likely_origin_ip[INET_ADDRSTRLEN];
    float origin_ip_confidence;
    char **bypass_recommendations;
    int bypass_recommendation_count;

    time_t scan_timestamp;
    uint32_t total_techniques_attempted;
    uint32_t successful_techniques;
};

// Function Prototypes

// Main detection function
int perform_advanced_ip_detection(const char *domain,
                                 struct advanced_ip_detection_result *result);

// SSL Certificate Analysis
int test_direct_ip_connection(const char *ip_address,
                             const char *domain,
                             struct ssl_certificate_info *cert_info);
int compare_ssl_certificates(struct ssl_certificate_info *cert1,
                            struct ssl_certificate_info *cert2,
                            float *similarity_score);
int enumerate_and_test_ips(const char *domain,
                          struct advanced_ip_detection_result *result);

// MX Record Enumeration
int enumerate_mx_records(const char *domain,
                        struct mx_record_info **mx_records,
                        int *count);
int analyze_mail_server_infrastructure(const char *domain,
                                      struct advanced_ip_detection_result *result);

// SRV Record Discovery
int discover_srv_records(const char *domain,
                        struct srv_record_info **srv_records,
                        int *count);
const char** get_common_srv_services(int *count);

// Cloudflare-Specific Bypass
int detect_cloudflare_bypass_subdomains(const char *domain,
                                       struct cloudflare_bypass_info *bypass_info);
int test_cloudflare_origin_exposure(const char *domain,
                                   struct cloudflare_bypass_info *bypass_info);
int probe_cloudflare_api_endpoints(const char *domain,
                                  struct cloudflare_bypass_info *bypass_info);

// ASN/Network Analysis
int cluster_ips_by_asn(struct advanced_ip_detection_result *result);
int query_asn_information(const char *ip_address,
                         struct asn_network_info *asn_info);
int discover_related_ip_blocks(uint32_t asn,
                              char ***ip_ranges,
                              int *count);

// Reverse DNS Intelligence
int perform_reverse_dns_lookup(const char *ip_address,
                              char *hostname,
                              size_t hostname_size);
int analyze_ptr_records(struct advanced_ip_detection_result *result);
int discover_related_hosts_via_ptr(const char *ip_address,
                                   char ***related_hosts,
                                   int *count);

// Passive DNS Integration
int query_passive_dns_historical(const char *domain,
                                struct passive_dns_record **records,
                                int *count);
int identify_pre_cdn_ips(struct passive_dns_record *records,
                        int count,
                        char ***pre_cdn_ips,
                        int *ip_count);

// WHOIS Netblock Discovery
int perform_whois_lookup(const char *ip_address,
                        struct whois_info *whois);
int discover_organization_netblocks(const char *organization,
                                   struct whois_info **netblocks,
                                   int *count);

// HTTP Header Analysis
int analyze_http_headers(const char *domain,
                        struct http_header_analysis *analysis);
int test_http_header_injection(const char *domain,
                              struct http_header_analysis *analysis);
int extract_origin_hints_from_headers(struct http_header_analysis *analysis,
                                     char **ip_hints,
                                     int *count);

// SNI Testing
int test_sni_certificates(const char *domain,
                         char **ip_addresses,
                         int ip_count,
                         struct origin_ip_candidate **candidates,
                         int *candidate_count);

// IPv4 Range Scanning
int scan_ipv4_range_for_domain(const char *domain,
                              const char *ip_range_cidr,
                              struct origin_ip_candidate **candidates,
                              int *candidate_count);

// Subdomain Certificate Correlation
int correlate_subdomain_certificates(const char *domain,
                                    char **subdomains,
                                    int subdomain_count,
                                    struct origin_ip_candidate **candidates,
                                    int *candidate_count);

// Evidence Scoring
float calculate_origin_ip_confidence(struct origin_ip_candidate *candidate);
void rank_origin_ip_candidates(struct advanced_ip_detection_result *result);
void generate_bypass_recommendations(struct advanced_ip_detection_result *result);

// Reporting
void print_advanced_detection_results(struct advanced_ip_detection_result *result);
void print_origin_ip_candidates(struct advanced_ip_detection_result *result);
void print_bypass_techniques(struct advanced_ip_detection_result *result);
int export_results_to_json(struct advanced_ip_detection_result *result,
                          const char *filename);

// Cleanup
void cleanup_advanced_ip_detection_result(struct advanced_ip_detection_result *result);
void cleanup_ssl_certificate_info(struct ssl_certificate_info *cert_info);

// Utility Functions
bool is_ip_in_cloudflare_range(const char *ip_address);
bool is_ip_in_cdn_range(const char *ip_address, char *cdn_name);
int resolve_hostname_all_records(const char *hostname,
                                 char ***ip_addresses,
                                 int *count);

// Thread-safe candidate addition
int add_origin_candidate(struct advanced_ip_detection_result *result,
                        const char *ip_address,
                        const char *discovery_method,
                        float confidence);

#endif // ADVANCED_IP_DETECTION_H
