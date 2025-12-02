/*
 * CloudUnflare Enhanced - Port Scanner Module
 *
 * Advanced port scanning with TCP SYN, UDP, and Connect scan capabilities
 * Includes service detection, OS fingerprinting, and stealth techniques
 *
 * Features:
 * - TCP SYN scanning (stealth)
 * - TCP Connect scanning (reliable)
 * - UDP scanning with payload probes
 * - Service version detection
 * - OS fingerprinting via TCP/IP stack analysis
 * - Port range optimization
 * - OPSEC timing and evasion
 *
 * Agent Assignment: C-INTERNAL (primary implementation)
 * Security Review: SECURITY agent
 * Performance: OPTIMIZER agent
 */

#ifndef PORT_SCANNER_H
#define PORT_SCANNER_H

#include "../common/recon_common.h"
#include "platform_compat.h"

#ifndef _WIN32
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
    #include <netinet/ip.h>
    #include <netinet/ip_icmp.h>
    #ifdef __linux__
        #include <linux/if_packet.h>
        #include <net/ethernet.h>
    #endif
#else
    /* Windows: Raw socket headers not available, define minimal structures */
    #define ETH_ALEN 6
    #define IPPROTO_RAW 255
#endif

// Port scanner specific constants
#ifndef PORT_SCANNER_MAX_PORTS
#define PORT_SCANNER_MAX_PORTS 65535
#endif
#define PORT_SCANNER_MAX_RANGES 20
#define PORT_SCANNER_MAX_PAYLOADS 50
#define PORT_SCANNER_DEFAULT_TIMEOUT 5
#define PORT_SCANNER_MAX_RETRIES 3
#define PORT_SCANNER_BANNER_SIZE 1024
#define PORT_SCANNER_OS_FINGERPRINT_SIZE 512

// Scan types
typedef enum {
    SCAN_TYPE_TCP_SYN,      // TCP SYN scan (stealth)
    SCAN_TYPE_TCP_CONNECT,  // TCP Connect scan (reliable)
    SCAN_TYPE_TCP_ACK,      // TCP ACK scan (firewall detection)
    SCAN_TYPE_TCP_FIN,      // TCP FIN scan (stealth)
    SCAN_TYPE_TCP_NULL,     // TCP NULL scan (stealth)
    SCAN_TYPE_TCP_XMAS,     // TCP XMAS scan (stealth)
    SCAN_TYPE_UDP,          // UDP scan
    SCAN_TYPE_ICMP_PING,    // ICMP ping scan
    SCAN_TYPE_ARP_PING      // ARP ping scan (local network)
} scan_type_t;

// Port states
typedef enum {
    PORT_STATE_UNKNOWN,
    PORT_STATE_OPEN,
    PORT_STATE_CLOSED,
    PORT_STATE_FILTERED,
    PORT_STATE_UNFILTERED,
    PORT_STATE_OPEN_FILTERED // UDP scan result
} port_state_t;

// Service detection confidence
typedef enum {
    SERVICE_CONFIDENCE_LOW,
    SERVICE_CONFIDENCE_MEDIUM,
    SERVICE_CONFIDENCE_HIGH,
    SERVICE_CONFIDENCE_CERTAIN
} service_confidence_t;

// Port range specification
typedef struct {
    uint16_t start_port;
    uint16_t end_port;
    scan_type_t scan_type;
    uint32_t priority;
} port_range_t;

// Service information
typedef struct {
    char service_name[64];
    char version[128];
    char product[128];
    char extra_info[256];
    service_confidence_t confidence;
    char banner[PORT_SCANNER_BANNER_SIZE];
    bool banner_grabbed;
} service_info_t;

// OS fingerprint information
typedef struct {
    char os_name[128];
    char os_version[64];
    char device_type[64];
    char vendor[128];
    uint32_t confidence_score;
    char fingerprint_details[PORT_SCANNER_OS_FINGERPRINT_SIZE];
    bool uptime_detected;
    uint32_t uptime_seconds;
} os_fingerprint_t;

// Port scan result
typedef struct {
    uint16_t port;
    scan_type_t scan_type;
    port_state_t state;
    char protocol[8]; // "tcp" or "udp"
    uint32_t response_time_ms;
    service_info_t service;
    bool has_service_info;
    char raw_banner[PORT_SCANNER_BANNER_SIZE];
    time_t scanned_at;
} port_result_t;

// Host scan result
typedef struct {
    recon_target_t target;
    bool host_up;
    port_result_t *ports;
    uint32_t port_count;
    uint32_t open_ports;
    uint32_t closed_ports;
    uint32_t filtered_ports;
    os_fingerprint_t os_info;
    bool has_os_info;
    uint32_t total_scan_time_ms;
    time_t scan_started;
    time_t scan_completed;
} host_scan_result_t;

// UDP probe payload
typedef struct {
    uint16_t port;
    char *payload;
    size_t payload_size;
    char *expected_response;
    size_t expected_response_size;
} udp_probe_t;

// Port scanner configuration
typedef struct {
    scan_type_t default_scan_type;
    port_range_t port_ranges[PORT_SCANNER_MAX_RANGES];
    uint32_t range_count;
    uint32_t timeout_seconds;
    uint32_t max_retries;
    uint32_t max_threads;
    uint32_t delay_between_probes_ms;
    bool detect_services;
    bool grab_banners;
    bool fingerprint_os;
    bool ping_before_scan;
    bool randomize_ports;
    udp_probe_t udp_probes[PORT_SCANNER_MAX_PAYLOADS];
    uint32_t udp_probe_count;
    recon_opsec_config_t opsec;
} port_scanner_config_t;

// Port scanner context
typedef struct {
    recon_context_t base_ctx;
    port_scanner_config_t config;
    host_scan_result_t *results;
    uint32_t result_count;
    uint32_t max_results;
    int raw_socket_tcp;
    int raw_socket_udp;
    int raw_socket_icmp;
    pthread_mutex_t results_mutex;
    pthread_mutex_t socket_mutex;
} port_scanner_context_t;

// TCP header for raw socket operations
struct tcp_header {
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t sequence;
    uint32_t acknowledge;
    uint8_t header_length:4;
    uint8_t reserved:4;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
};

// Function prototypes

// Initialization and configuration
int port_scanner_init_context(port_scanner_context_t *ctx);
void port_scanner_cleanup_context(port_scanner_context_t *ctx);
int port_scanner_set_config(port_scanner_context_t *ctx, const port_scanner_config_t *config);

// Socket management
int port_scanner_create_raw_sockets(port_scanner_context_t *ctx);
void port_scanner_close_raw_sockets(port_scanner_context_t *ctx);
int port_scanner_set_socket_options(int sockfd, scan_type_t scan_type);

// Core scanning operations
int port_scanner_scan_host(port_scanner_context_t *ctx, const char *hostname, host_scan_result_t *result);
int port_scanner_scan_multiple_hosts(port_scanner_context_t *ctx, const char **hostnames, uint32_t host_count);
void *port_scanner_worker_thread(void *arg);

// Individual scan methods
int port_scanner_tcp_syn_scan(port_scanner_context_t *ctx, const recon_target_t *target, uint16_t port, port_result_t *result);
int port_scanner_tcp_connect_scan(port_scanner_context_t *ctx, const recon_target_t *target, uint16_t port, port_result_t *result);
int port_scanner_udp_scan(port_scanner_context_t *ctx, const recon_target_t *target, uint16_t port, port_result_t *result);
int port_scanner_tcp_ack_scan(port_scanner_context_t *ctx, const recon_target_t *target, uint16_t port, port_result_t *result);

// Host discovery
bool port_scanner_ping_host(const recon_target_t *target, uint32_t timeout_ms);
bool port_scanner_icmp_ping(const recon_target_t *target, uint32_t timeout_ms);
bool port_scanner_arp_ping(const recon_target_t *target, uint32_t timeout_ms);
bool port_scanner_tcp_ping(const recon_target_t *target, uint16_t port, uint32_t timeout_ms);

// Raw packet crafting
int port_scanner_craft_tcp_packet(const recon_target_t *target, uint16_t sport, uint16_t dport, uint8_t flags, char *packet, size_t *packet_size);
int port_scanner_craft_udp_packet(const recon_target_t *target, uint16_t sport, uint16_t dport, const char *payload, size_t payload_size, char *packet, size_t *packet_size);
uint16_t port_scanner_calculate_checksum(const void *data, size_t length);

// Service detection and banner grabbing
int port_scanner_detect_service(const recon_target_t *target, uint16_t port, service_info_t *service);
int port_scanner_grab_banner(const recon_target_t *target, uint16_t port, char *banner, size_t banner_size);
int port_scanner_send_service_probe(int sockfd, const char *probe, size_t probe_size);
bool port_scanner_match_service_signature(const char *banner, const char *service_name, const char *pattern);

// OS fingerprinting
int port_scanner_fingerprint_os(port_scanner_context_t *ctx, const recon_target_t *target, os_fingerprint_t *os_info);
int port_scanner_tcp_fingerprint(const recon_target_t *target, os_fingerprint_t *os_info);
int port_scanner_analyze_tcp_options(const char *packet, size_t packet_size, os_fingerprint_t *os_info);
int port_scanner_detect_uptime(const recon_target_t *target, uint32_t *uptime_seconds);

// Port range management
int port_scanner_add_port_range(port_scanner_config_t *config, uint16_t start, uint16_t end, scan_type_t type);
int port_scanner_get_port_list(const port_scanner_config_t *config, uint16_t **ports, uint32_t *port_count);
void port_scanner_randomize_port_order(uint16_t *ports, uint32_t count);
void port_scanner_optimize_port_ranges(port_scanner_config_t *config);

// UDP payload management
int port_scanner_load_udp_probes(port_scanner_config_t *config, const char *probe_file);
const udp_probe_t *port_scanner_get_udp_probe(const port_scanner_config_t *config, uint16_t port);
int port_scanner_add_udp_probe(port_scanner_config_t *config, uint16_t port, const char *payload, size_t payload_size);

// Result processing
int port_scanner_add_port_result(host_scan_result_t *host_result, const port_result_t *port_result);
void port_scanner_sort_results(host_scan_result_t *host_result);
void port_scanner_filter_results(host_scan_result_t *host_result, port_state_t filter_state);
void port_scanner_calculate_statistics(host_scan_result_t *host_result);

// Output and reporting
void port_scanner_print_host_result(const host_scan_result_t *result);
void port_scanner_print_summary(const port_scanner_context_t *ctx);
int port_scanner_export_xml(const port_scanner_context_t *ctx, const char *filename);
int port_scanner_export_json(const port_scanner_context_t *ctx, const char *filename);
int port_scanner_export_csv(const port_scanner_context_t *ctx, const char *filename);

// OPSEC and stealth
void port_scanner_apply_timing_evasion(const port_scanner_config_t *config);
bool port_scanner_check_detection_risk(const port_scanner_context_t *ctx);
void port_scanner_spoof_source_port(uint16_t *source_port);
void port_scanner_decoy_scan(port_scanner_context_t *ctx, const recon_target_t *target, const char **decoy_ips, uint32_t decoy_count);

// Utilities and helpers
const char *scan_type_to_string(scan_type_t type);
const char *port_state_to_string(port_state_t state);
const char *service_confidence_to_string(service_confidence_t confidence);
bool port_scanner_is_privileged_port(uint16_t port);
bool port_scanner_requires_root(scan_type_t scan_type);
uint16_t port_scanner_get_random_source_port(void);

// Error handling and logging
void port_scanner_log_scan_start(const char *hostname, scan_type_t type, uint32_t port_count);
void port_scanner_log_scan_complete(const char *hostname, uint32_t open_ports, uint32_t total_time_ms);
void port_scanner_log_port_result(const char *hostname, const port_result_t *result);

#endif // PORT_SCANNER_H
