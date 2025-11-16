/*
 * CloudUnflare Enhanced - DNS Zone Transfer Module
 *
 * Implements AXFR (Full Zone Transfer) and IXFR (Incremental Zone Transfer)
 * for comprehensive DNS zone enumeration with OPSEC compliance
 *
 * Features:
 * - AXFR/IXFR support with fallback mechanisms
 * - Multi-server zone transfer attempts
 * - DNS record extraction and analysis
 * - OPSEC-compliant timing and detection evasion
 * - Thread-safe operations for multiple zones
 *
 * Agent Assignment: C-INTERNAL (primary implementation)
 * Security Review: SECURITY agent
 * Performance: OPTIMIZER agent
 */

#ifndef DNS_ZONE_TRANSFER_H
#define DNS_ZONE_TRANSFER_H

#include "../common/recon_common.h"
#include "dns_enhanced.h"

// Zone transfer specific constants
#define ZONE_TRANSFER_MAX_SERVERS 10
#define ZONE_TRANSFER_MAX_RECORDS 10000
#define ZONE_TRANSFER_TIMEOUT 60
#define ZONE_TRANSFER_BUFFER_SIZE 65536
#define ZONE_TRANSFER_MAX_RETRIES 3

// Zone transfer types
typedef enum {
    ZONE_TRANSFER_AXFR,  // Full zone transfer
    ZONE_TRANSFER_IXFR,  // Incremental zone transfer
    ZONE_TRANSFER_AUTO   // Try IXFR first, fallback to AXFR
} zone_transfer_type_t;

// Zone transfer status
typedef enum {
    ZONE_STATUS_UNKNOWN,
    ZONE_STATUS_REFUSED,
    ZONE_STATUS_TIMEOUT,
    ZONE_STATUS_SUCCESS,
    ZONE_STATUS_PARTIAL,
    ZONE_STATUS_ERROR
} zone_transfer_status_t;

// DNS server information for zone transfers
typedef struct {
    char hostname[RECON_MAX_DOMAIN_LEN];
    char ip_address[INET6_ADDRSTRLEN];
    uint16_t port;
    bool supports_axfr;
    bool supports_ixfr;
    zone_transfer_status_t last_status;
    uint32_t response_time_ms;
    time_t last_attempt;
} zone_server_t;

// DNS zone record structure
typedef struct {
    char name[RECON_MAX_DOMAIN_LEN];
    dns_record_type_t type;
    uint32_t ttl;
    char rdata[1024];
    uint16_t rdlength;
    time_t discovered;
} zone_record_t;

// Zone transfer result
typedef struct {
    char zone_name[RECON_MAX_DOMAIN_LEN];
    zone_transfer_type_t transfer_type;
    zone_transfer_status_t status;
    zone_server_t server;
    zone_record_t *records;
    uint32_t record_count;
    uint32_t total_transfer_size;
    uint32_t transfer_time_ms;
    time_t timestamp;
    char error_message[256];
} zone_transfer_result_t;

// Zone transfer configuration
typedef struct {
    zone_transfer_type_t preferred_type;
    uint32_t timeout_seconds;
    uint32_t max_retries;
    uint32_t delay_between_attempts_ms;
    bool try_all_servers;
    bool extract_subdomains;
    bool validate_records;
    recon_opsec_config_t opsec;
} zone_transfer_config_t;

// Zone transfer context for multi-threaded operations
typedef struct {
    recon_context_t base_ctx;
    zone_transfer_config_t config;
    zone_server_t servers[ZONE_TRANSFER_MAX_SERVERS];
    uint32_t server_count;
    zone_transfer_result_t *results;
    uint32_t result_count;
    uint32_t max_results;
    pthread_mutex_t results_mutex;
} zone_transfer_context_t;

// Function prototypes

// Initialization and configuration
int zone_transfer_init_context(zone_transfer_context_t *ctx);
void zone_transfer_cleanup_context(zone_transfer_context_t *ctx);
int zone_transfer_set_config(zone_transfer_context_t *ctx, const zone_transfer_config_t *config);

// Server discovery and management
int zone_transfer_discover_servers(zone_transfer_context_t *ctx, const char *domain);
int zone_transfer_add_server(zone_transfer_context_t *ctx, const char *hostname, uint16_t port);
bool zone_transfer_test_server_capability(zone_server_t *server, const char *domain);

// Zone transfer operations
int zone_transfer_attempt_axfr(zone_transfer_context_t *ctx, const char *domain, zone_server_t *server);
int zone_transfer_attempt_ixfr(zone_transfer_context_t *ctx, const char *domain, zone_server_t *server, uint32_t serial);
int zone_transfer_execute(zone_transfer_context_t *ctx, const char *domain);

// Multi-threaded zone transfer
void *zone_transfer_worker_thread(void *arg);
int zone_transfer_parallel_execute(zone_transfer_context_t *ctx, const char **domains, uint32_t domain_count);

// Record processing and analysis
int zone_transfer_parse_records(const char *raw_data, size_t data_len, zone_record_t **records, uint32_t *record_count);
int zone_transfer_extract_subdomains(const zone_record_t *records, uint32_t record_count, char ***subdomains, uint32_t *subdomain_count);
bool zone_transfer_validate_record(const zone_record_t *record);

// Result handling and export
void zone_transfer_init_result(zone_transfer_result_t *result, const char *domain);
int zone_transfer_add_result(zone_transfer_context_t *ctx, const zone_transfer_result_t *result);
void zone_transfer_print_results(const zone_transfer_context_t *ctx);
int zone_transfer_export_json(const zone_transfer_context_t *ctx, const char *filename);
int zone_transfer_export_csv(const zone_transfer_context_t *ctx, const char *filename);

// DNS protocol helpers
int zone_transfer_create_axfr_query(const char *domain, uint8_t *buffer, size_t buffer_size);
int zone_transfer_create_ixfr_query(const char *domain, uint32_t serial, uint8_t *buffer, size_t buffer_size);
int zone_transfer_send_query(int sockfd, const uint8_t *query, size_t query_len);
int zone_transfer_receive_response(int sockfd, uint8_t *buffer, size_t buffer_size, uint32_t timeout_ms);

// OPSEC and evasion
void zone_transfer_apply_timing_evasion(const recon_opsec_config_t *opsec);
bool zone_transfer_check_detection_risk(const zone_transfer_context_t *ctx);
void zone_transfer_randomize_server_order(zone_server_t *servers, uint32_t count);

// Utilities and debugging
void zone_transfer_log_attempt(const char *domain, const zone_server_t *server, zone_transfer_type_t type);
void zone_transfer_log_result(const zone_transfer_result_t *result);
const char *zone_transfer_status_to_string(zone_transfer_status_t status);
const char *zone_transfer_type_to_string(zone_transfer_type_t type);

#endif // DNS_ZONE_TRANSFER_H