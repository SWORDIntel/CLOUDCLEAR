/*
 * CloudUnflare Enhanced - DNS Zone Transfer Implementation
 *
 * Implements AXFR/IXFR zone transfer capabilities
 * Template for C-INTERNAL agent implementation
 */

#include "dns_zone_transfer.h"
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

// Initialize zone transfer context
int zone_transfer_init_context(zone_transfer_context_t *ctx) {
    if (!ctx) return -1;

    memset(ctx, 0, sizeof(zone_transfer_context_t));

    // Initialize base reconnaissance context
    if (recon_init_context(&ctx->base_ctx, RECON_MODE_ACTIVE) != 0) {
        return -1;
    }

    // Initialize results mutex
    if (pthread_mutex_init(&ctx->results_mutex, NULL) != 0) {
        recon_cleanup_context(&ctx->base_ctx);
        return -1;
    }

    // Set default configuration
    ctx->config.preferred_type = ZONE_TRANSFER_AUTO;
    ctx->config.timeout_seconds = ZONE_TRANSFER_TIMEOUT;
    ctx->config.max_retries = ZONE_TRANSFER_MAX_RETRIES;
    ctx->config.delay_between_attempts_ms = 2000;
    ctx->config.try_all_servers = true;
    ctx->config.extract_subdomains = true;
    ctx->config.validate_records = true;

    // Initialize OPSEC configuration
    ctx->config.opsec.min_delay_ms = 1000;
    ctx->config.opsec.max_delay_ms = 5000;
    ctx->config.opsec.jitter_ms = 1000;
    ctx->config.opsec.max_requests_per_session = 10;

    ctx->max_results = 100;
    ctx->results = calloc(ctx->max_results, sizeof(zone_transfer_result_t));
    if (!ctx->results) {
        zone_transfer_cleanup_context(ctx);
        return -1;
    }

    return 0;
}

// Cleanup zone transfer context
void zone_transfer_cleanup_context(zone_transfer_context_t *ctx) {
    if (!ctx) return;

    // Cleanup results
    if (ctx->results) {
        for (uint32_t i = 0; i < ctx->result_count; i++) {
            if (ctx->results[i].records) {
                free(ctx->results[i].records);
            }
        }
        free(ctx->results);
    }

    pthread_mutex_destroy(&ctx->results_mutex);
    recon_cleanup_context(&ctx->base_ctx);
}

// Discover authoritative name servers for domain
int zone_transfer_discover_servers(zone_transfer_context_t *ctx, const char *domain) {
    if (!ctx || !domain) return -1;

    recon_log_info("zone_transfer", "Discovering authoritative name servers");

    ctx->server_count = 0;

    // Simplified name server discovery without enhanced DNS resolver
    // In production, this would query actual NS records for the domain

    // Common patterns for authoritative name servers
    char ns_patterns[][256] = {
        "ns1.%s", "ns2.%s", "ns3.%s", "ns4.%s",
        "ns.%s", "dns.%s", "a.ns.%s", "b.ns.%s",
        "auth1.%s", "auth2.%s", "primary.%s", "secondary.%s"
    };

    int pattern_count = sizeof(ns_patterns) / sizeof(ns_patterns[0]);

    for (int i = 0; i < pattern_count && ctx->server_count < ZONE_TRANSFER_MAX_SERVERS; i++) {
        char ns_hostname[RECON_MAX_DOMAIN_LEN];
        snprintf(ns_hostname, sizeof(ns_hostname), ns_patterns[i], domain);

        // Try to resolve the name server hostname using basic gethostbyname
        struct hostent *host_entry = gethostbyname(ns_hostname);
        if (host_entry) {
            // Successfully resolved name server, add it
            if (zone_transfer_add_server(ctx, ns_hostname, 53) == 0) {
                recon_log_info("zone_transfer", "Added authoritative name server");
            }
        }
    }

    // Also try some common external DNS servers that might have zone info
    if (ctx->server_count == 0) {
        recon_log_info("zone_transfer", "No authoritative servers found, trying common servers");
        zone_transfer_add_server(ctx, "ns1.google.com", 53);
        zone_transfer_add_server(ctx, "ns2.google.com", 53);
    }

    recon_log_info("zone_transfer", "Name server discovery completed");
    return ctx->server_count;
}

// Add server to zone transfer context
int zone_transfer_add_server(zone_transfer_context_t *ctx, const char *hostname, uint16_t port) {
    if (!ctx || !hostname || ctx->server_count >= ZONE_TRANSFER_MAX_SERVERS) {
        return -1;
    }

    zone_server_t *server = &ctx->servers[ctx->server_count];
    memset(server, 0, sizeof(zone_server_t));

    strncpy(server->hostname, hostname, RECON_MAX_DOMAIN_LEN - 1);
    server->port = port;
    server->supports_axfr = false; // Will be tested
    server->supports_ixfr = false; // Will be tested
    server->last_status = ZONE_STATUS_UNKNOWN;

    // Resolve hostname to IP
    recon_target_t target;
    if (recon_add_target(&target, hostname, port) == 0) {
        snprintf(server->ip_address, INET6_ADDRSTRLEN, "%s", target.ip_address);
    }

    ctx->server_count++;
    return 0;
}

// Test server's zone transfer capabilities
bool zone_transfer_test_server_capability(zone_server_t *server, const char *domain) {
    if (!server || !domain) return false;

    recon_log_debug("zone_transfer", "Testing server capabilities");

    server->supports_axfr = false;
    server->supports_ixfr = false;
    server->last_status = ZONE_STATUS_UNKNOWN;

    // Create a test socket for capability checking
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        recon_log_error("zone_transfer", server->hostname, "Failed to create test socket");
        return false;
    }

    // Set socket timeout
    struct timeval tv;
    tv.tv_sec = 10; // 10 second timeout for capability test
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    // Resolve server hostname to IP if needed
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server->port);

    if (strlen(server->ip_address) > 0) {
        // Use existing IP address
        if (inet_pton(AF_INET, server->ip_address, &server_addr.sin_addr) != 1) {
            close(sockfd);
            return false;
        }
    } else {
        // Resolve hostname to IP
        struct hostent *host_entry = gethostbyname(server->hostname);
        if (!host_entry) {
            close(sockfd);
            recon_log_error("zone_transfer", server->hostname, "Failed to resolve hostname");
            return false;
        }
        memcpy(&server_addr.sin_addr.s_addr, host_entry->h_addr_list[0], host_entry->h_length);
        inet_ntop(AF_INET, &server_addr.sin_addr, server->ip_address, INET_ADDRSTRLEN);
    }

    // Test TCP connection (required for zone transfers)
    clock_t start_time = clock();
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sockfd);
        server->last_status = ZONE_STATUS_TIMEOUT;
        recon_log_debug("zone_transfer", "Server connection failed");
        return false;
    }

    // Create a minimal AXFR query to test capability
    uint8_t axfr_query[512];
    int query_len = zone_transfer_create_axfr_query(domain, axfr_query, sizeof(axfr_query));
    if (query_len <= 0) {
        close(sockfd);
        return false;
    }

    // Send the test query
    if (zone_transfer_send_query(sockfd, axfr_query, query_len) != 0) {
        close(sockfd);
        server->last_status = ZONE_STATUS_ERROR;
        return false;
    }

    // Try to receive response
    uint8_t response_buffer[1024];
    int response_len = zone_transfer_receive_response(sockfd, response_buffer,
                                                      sizeof(response_buffer), 5000);

    clock_t end_time = clock();
    server->response_time_ms = (uint32_t)((end_time - start_time) * 1000 / CLOCKS_PER_SEC);
    server->last_attempt = time(NULL);

    close(sockfd);

    if (response_len > 0) {
        // Parse DNS response header to check for zone transfer support
        if (response_len >= 12) { // Minimum DNS header size
            uint16_t flags = ntohs(*(uint16_t*)(response_buffer + 2));
            uint8_t rcode = flags & 0x0F;

            if (rcode == 0) { // NOERROR - server supports zone transfers
                server->supports_axfr = true;
                server->last_status = ZONE_STATUS_SUCCESS;
                recon_log_debug("zone_transfer", "Server supports AXFR");

                // Test IXFR capability (simplified check)
                // In practice, we would send an IXFR query
                server->supports_ixfr = false; // Most servers don't support IXFR

                return true;
            } else if (rcode == 5) { // REFUSED
                server->last_status = ZONE_STATUS_REFUSED;
                recon_log_debug("zone_transfer", "Server refused zone transfer");
            } else {
                server->last_status = ZONE_STATUS_ERROR;
                recon_log_debug("zone_transfer", "Server returned DNS error");
            }
        }
    } else {
        server->last_status = ZONE_STATUS_TIMEOUT;
        recon_log_debug("zone_transfer", "Server response timeout");
    }

    return false;
}

// Execute zone transfer for domain
int zone_transfer_execute(zone_transfer_context_t *ctx, const char *domain) {
    if (!ctx || !domain) return -1;

    recon_log_info("zone_transfer", "Starting zone transfer execution");

    // Discover servers if none configured
    if (ctx->server_count == 0) {
        if (zone_transfer_discover_servers(ctx, domain) <= 0) {
            recon_log_error("zone_transfer", domain, "No authoritative servers found");
            return -1;
        }
    }

    int successful_transfers = 0;

    // Try each server
    for (uint32_t i = 0; i < ctx->server_count; i++) {
        zone_server_t *server = &ctx->servers[i];

        // Test server capability first
        if (!zone_transfer_test_server_capability(server, domain)) {
            recon_log_info("zone_transfer", "Server does not support zone transfers");
            continue;
        }

        // Apply OPSEC delay between attempts
        if (i > 0) {
            zone_transfer_apply_timing_evasion(&ctx->config.opsec);
        }

        // Attempt zone transfer based on configuration
        int result = -1;
        if (ctx->config.preferred_type == ZONE_TRANSFER_AXFR ||
            ctx->config.preferred_type == ZONE_TRANSFER_AUTO) {
            result = zone_transfer_attempt_axfr(ctx, domain, server);
        }

        if (result != 0 && ctx->config.preferred_type == ZONE_TRANSFER_AUTO) {
            // Fallback to IXFR if AXFR failed
            result = zone_transfer_attempt_ixfr(ctx, domain, server, 0);
        }

        if (result == 0) {
            successful_transfers++;
            if (!ctx->config.try_all_servers) {
                break; // Stop after first successful transfer
            }
        }
    }

    recon_log_info("zone_transfer",
                   successful_transfers > 0 ? "Zone transfer completed" : "Zone transfer failed");

    return successful_transfers;
}

// Attempt AXFR zone transfer
int zone_transfer_attempt_axfr(zone_transfer_context_t *ctx, const char *domain, zone_server_t *server) {
    if (!ctx || !domain || !server) return -1;

    zone_transfer_log_attempt(domain, server, ZONE_TRANSFER_AXFR);

    zone_transfer_result_t result;
    zone_transfer_init_result(&result, domain);
    result.transfer_type = ZONE_TRANSFER_AXFR;
    result.server = *server;

    clock_t start_time = clock();

    // Create TCP socket for zone transfer
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        snprintf(result.error_message, sizeof(result.error_message), "Failed to create socket: %s", strerror(errno));
        result.status = ZONE_STATUS_ERROR;
        zone_transfer_add_result(ctx, &result);
        return -1;
    }

    // Set socket timeouts
    struct timeval tv;
    tv.tv_sec = ctx->config.timeout_seconds;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    // Setup server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server->port);

    if (inet_pton(AF_INET, server->ip_address, &server_addr.sin_addr) != 1) {
        snprintf(result.error_message, sizeof(result.error_message), "Invalid server IP address: %s", server->ip_address);
        result.status = ZONE_STATUS_ERROR;
        close(sockfd);
        zone_transfer_add_result(ctx, &result);
        return -1;
    }

    // Connect to server
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        snprintf(result.error_message, sizeof(result.error_message), "Connection failed: %s", strerror(errno));
        result.status = ZONE_STATUS_TIMEOUT;
        close(sockfd);
        zone_transfer_add_result(ctx, &result);
        return -1;
    }

    // Create AXFR query
    uint8_t query_buffer[512];
    int query_len = zone_transfer_create_axfr_query(domain, query_buffer, sizeof(query_buffer));
    if (query_len <= 0) {
        snprintf(result.error_message, sizeof(result.error_message), "Failed to create AXFR query");
        result.status = ZONE_STATUS_ERROR;
        close(sockfd);
        zone_transfer_add_result(ctx, &result);
        return -1;
    }

    // Send AXFR query
    if (zone_transfer_send_query(sockfd, query_buffer, query_len) != 0) {
        snprintf(result.error_message, sizeof(result.error_message), "Failed to send AXFR query");
        result.status = ZONE_STATUS_ERROR;
        close(sockfd);
        zone_transfer_add_result(ctx, &result);
        return -1;
    }

    // Receive zone transfer data
    uint8_t *zone_data = malloc(ZONE_TRANSFER_BUFFER_SIZE);
    if (!zone_data) {
        snprintf(result.error_message, sizeof(result.error_message), "Memory allocation failed");
        result.status = ZONE_STATUS_ERROR;
        close(sockfd);
        zone_transfer_add_result(ctx, &result);
        return -1;
    }

    uint32_t total_received = 0;
    bool transfer_complete = false;
    uint32_t soa_count = 0; // SOA records mark start and end of zone transfer
    (void)soa_count; // Reserved for SOA counting implementation

    while (!transfer_complete && total_received < ZONE_TRANSFER_BUFFER_SIZE - 1024) {
        int bytes_received = zone_transfer_receive_response(sockfd,
                                                           zone_data + total_received,
                                                           ZONE_TRANSFER_BUFFER_SIZE - total_received,
                                                           ctx->config.timeout_seconds * 1000);

        if (bytes_received <= 0) {
            if (total_received == 0) {
                snprintf(result.error_message, sizeof(result.error_message), "No data received from server");
                result.status = ZONE_STATUS_TIMEOUT;
            } else {
                // Partial transfer received
                result.status = ZONE_STATUS_PARTIAL;
                transfer_complete = true;
            }
            break;
        }

        total_received += bytes_received;

        // Simple check for zone transfer completion
        // In a real implementation, we would properly parse DNS records
        // and count SOA records to determine completion
        if (total_received >= 12) { // Minimum for DNS header
            // Check if we received a proper DNS response
            uint16_t flags = ntohs(*(uint16_t*)(zone_data + 2));
            uint8_t rcode = flags & 0x0F;

            if (rcode == 5) { // REFUSED
                snprintf(result.error_message, sizeof(result.error_message), "Zone transfer refused by server");
                result.status = ZONE_STATUS_REFUSED;
                break;
            } else if (rcode != 0) { // Other error
                snprintf(result.error_message, sizeof(result.error_message), "DNS error code: %d", rcode);
                result.status = ZONE_STATUS_ERROR;
                break;
            }
        }

        // For demonstration, assume transfer is complete after receiving some data
        if (total_received > 100) {
            transfer_complete = true;
            result.status = ZONE_STATUS_SUCCESS;
        }
    }

    close(sockfd);

    clock_t end_time = clock();
    result.transfer_time_ms = (uint32_t)((end_time - start_time) * 1000 / CLOCKS_PER_SEC);
    result.total_transfer_size = total_received;
    result.timestamp = time(NULL);

    // Parse received zone data into records
    if (result.status == ZONE_STATUS_SUCCESS || result.status == ZONE_STATUS_PARTIAL) {
        zone_record_t *records = NULL;
        uint32_t record_count = 0;

        if (zone_transfer_parse_records((char*)zone_data, total_received, &records, &record_count) == 0) {
            result.records = records;
            result.record_count = record_count;
        } else {
            // Failed to parse records, but we got data
            result.record_count = 0;
            if (result.status == ZONE_STATUS_SUCCESS) {
                result.status = ZONE_STATUS_PARTIAL;
                snprintf(result.error_message, sizeof(result.error_message), "Failed to parse zone records");
            }
        }
    }

    free(zone_data);

    // Update server metrics
    server->last_status = result.status;
    server->response_time_ms = result.transfer_time_ms;
    server->last_attempt = time(NULL);

    zone_transfer_add_result(ctx, &result);

    return (result.status == ZONE_STATUS_SUCCESS) ? 0 : -1;
}

// Attempt IXFR zone transfer
int zone_transfer_attempt_ixfr(zone_transfer_context_t *ctx, const char *domain,
                               zone_server_t *server, uint32_t serial) {
    if (!ctx || !domain || !server) return -1;

    zone_transfer_log_attempt(domain, server, ZONE_TRANSFER_IXFR);

    zone_transfer_result_t result;
    zone_transfer_init_result(&result, domain);
    result.transfer_type = ZONE_TRANSFER_IXFR;
    result.server = *server;

    clock_t start_time = clock();

    // Create TCP socket for zone transfer
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        snprintf(result.error_message, sizeof(result.error_message), "Failed to create socket: %s", strerror(errno));
        result.status = ZONE_STATUS_ERROR;
        zone_transfer_add_result(ctx, &result);
        return -1;
    }

    // Set socket timeouts
    struct timeval tv;
    tv.tv_sec = ctx->config.timeout_seconds;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    // Setup server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server->port);

    if (inet_pton(AF_INET, server->ip_address, &server_addr.sin_addr) != 1) {
        snprintf(result.error_message, sizeof(result.error_message), "Invalid server IP address: %s", server->ip_address);
        result.status = ZONE_STATUS_ERROR;
        close(sockfd);
        zone_transfer_add_result(ctx, &result);
        return -1;
    }

    // Connect to server
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        snprintf(result.error_message, sizeof(result.error_message), "Connection failed: %s", strerror(errno));
        result.status = ZONE_STATUS_TIMEOUT;
        close(sockfd);
        zone_transfer_add_result(ctx, &result);
        return -1;
    }

    // Create IXFR query
    uint8_t query_buffer[512];
    int query_len = zone_transfer_create_ixfr_query(domain, serial, query_buffer, sizeof(query_buffer));
    if (query_len <= 0) {
        snprintf(result.error_message, sizeof(result.error_message), "Failed to create IXFR query");
        result.status = ZONE_STATUS_ERROR;
        close(sockfd);
        zone_transfer_add_result(ctx, &result);
        return -1;
    }

    // Send IXFR query
    if (zone_transfer_send_query(sockfd, query_buffer, query_len) != 0) {
        snprintf(result.error_message, sizeof(result.error_message), "Failed to send IXFR query");
        result.status = ZONE_STATUS_ERROR;
        close(sockfd);
        zone_transfer_add_result(ctx, &result);
        return -1;
    }

    // Receive IXFR response
    uint8_t response_buffer[ZONE_TRANSFER_BUFFER_SIZE];
    int response_len = zone_transfer_receive_response(sockfd, response_buffer,
                                                     sizeof(response_buffer),
                                                     ctx->config.timeout_seconds * 1000);

    close(sockfd);

    clock_t end_time = clock();
    result.transfer_time_ms = (uint32_t)((end_time - start_time) * 1000 / CLOCKS_PER_SEC);
    result.timestamp = time(NULL);

    if (response_len <= 0) {
        snprintf(result.error_message, sizeof(result.error_message), "No response received from server");
        result.status = ZONE_STATUS_TIMEOUT;
        zone_transfer_add_result(ctx, &result);
        return -1;
    }

    result.total_transfer_size = response_len;

    // Parse DNS response header
    if (response_len >= 12) {
        uint16_t flags = ntohs(*(uint16_t*)(response_buffer + 2));
        uint8_t rcode = flags & 0x0F;

        if (rcode == 5) { // REFUSED
            snprintf(result.error_message, sizeof(result.error_message), "IXFR refused by server (not supported)");
            result.status = ZONE_STATUS_REFUSED;
        } else if (rcode == 4) { // NOTIMP
            snprintf(result.error_message, sizeof(result.error_message), "IXFR not implemented by server");
            result.status = ZONE_STATUS_REFUSED;
        } else if (rcode != 0) {
            snprintf(result.error_message, sizeof(result.error_message), "DNS error code: %d", rcode);
            result.status = ZONE_STATUS_ERROR;
        } else {
            // IXFR succeeded - parse incremental changes
            zone_record_t *records = NULL;
            uint32_t record_count = 0;

            if (zone_transfer_parse_records((char*)response_buffer, response_len, &records, &record_count) == 0) {
                result.records = records;
                result.record_count = record_count;
                result.status = ZONE_STATUS_SUCCESS;

                char msg[256];
                snprintf(msg, sizeof(msg), "IXFR completed successfully (%u records)", record_count);
                recon_log_info("zone_transfer", msg);
            } else {
                result.status = ZONE_STATUS_PARTIAL;
                snprintf(result.error_message, sizeof(result.error_message), "Failed to parse IXFR records");
            }
        }
    } else {
        snprintf(result.error_message, sizeof(result.error_message), "Invalid DNS response received");
        result.status = ZONE_STATUS_ERROR;
    }

    // Update server metrics
    server->last_status = result.status;
    server->response_time_ms = result.transfer_time_ms;
    server->last_attempt = time(NULL);

    zone_transfer_add_result(ctx, &result);

    return (result.status == ZONE_STATUS_SUCCESS) ? 0 : -1;
}

// Initialize zone transfer result
void zone_transfer_init_result(zone_transfer_result_t *result, const char *domain) {
    if (!result || !domain) return;

    memset(result, 0, sizeof(zone_transfer_result_t));
    strncpy(result->zone_name, domain, RECON_MAX_DOMAIN_LEN - 1);
    result->status = ZONE_STATUS_UNKNOWN;
    result->timestamp = time(NULL);
}

// Add result to context
int zone_transfer_add_result(zone_transfer_context_t *ctx, const zone_transfer_result_t *result) {
    if (!ctx || !result) return -1;

    pthread_mutex_lock(&ctx->results_mutex);

    if (ctx->result_count >= ctx->max_results) {
        pthread_mutex_unlock(&ctx->results_mutex);
        return -1;
    }

    ctx->results[ctx->result_count] = *result;
    ctx->result_count++;

    pthread_mutex_unlock(&ctx->results_mutex);

    zone_transfer_log_result(result);
    return 0;
}

// Apply timing evasion
void zone_transfer_apply_timing_evasion(const recon_opsec_config_t *opsec) {
    recon_apply_opsec_delay(opsec);
}

// Log zone transfer attempt
void zone_transfer_log_attempt(const char *domain, const zone_server_t *server, zone_transfer_type_t type) {
    char message[512];
    snprintf(message, sizeof(message), "Attempting %s for %s via %s (%s:%u)",
             zone_transfer_type_to_string(type), domain, server->hostname,
             server->ip_address, server->port);
    recon_log_info("zone_transfer", message);
}

// Log zone transfer result
void zone_transfer_log_result(const zone_transfer_result_t *result) {
    char message[512];
    snprintf(message, sizeof(message), "%s for %s: %s (%u records, %ums)",
             zone_transfer_type_to_string(result->transfer_type),
             result->zone_name,
             zone_transfer_status_to_string(result->status),
             result->record_count,
             result->transfer_time_ms);
    recon_log_info("zone_transfer", message);
}

// Convert zone transfer type to string
const char *zone_transfer_type_to_string(zone_transfer_type_t type) {
    switch (type) {
        case ZONE_TRANSFER_AXFR: return "AXFR";
        case ZONE_TRANSFER_IXFR: return "IXFR";
        case ZONE_TRANSFER_AUTO: return "AUTO";
        default: return "UNKNOWN";
    }
}

// Convert zone transfer status to string
const char *zone_transfer_status_to_string(zone_transfer_status_t status) {
    switch (status) {
        case ZONE_STATUS_UNKNOWN: return "UNKNOWN";
        case ZONE_STATUS_REFUSED: return "REFUSED";
        case ZONE_STATUS_TIMEOUT: return "TIMEOUT";
        case ZONE_STATUS_SUCCESS: return "SUCCESS";
        case ZONE_STATUS_PARTIAL: return "PARTIAL";
        case ZONE_STATUS_ERROR: return "ERROR";
        default: return "INVALID";
    }
}

// Print zone transfer results
void zone_transfer_print_results(const zone_transfer_context_t *ctx) {
    if (!ctx) return;

    printf("\n=== Zone Transfer Results ===\n");
    printf("Total Attempts: %u\n", ctx->result_count);

    for (uint32_t i = 0; i < ctx->result_count; i++) {
        const zone_transfer_result_t *result = &ctx->results[i];
        printf("\nZone: %s\n", result->zone_name);
        printf("  Type: %s\n", zone_transfer_type_to_string(result->transfer_type));
        printf("  Status: %s\n", zone_transfer_status_to_string(result->status));
        printf("  Server: %s (%s:%u)\n", result->server.hostname,
               result->server.ip_address, result->server.port);
        printf("  Records: %u\n", result->record_count);
        printf("  Transfer Time: %ums\n", result->transfer_time_ms);
        if (strlen(result->error_message) > 0) {
            printf("  Error: %s\n", result->error_message);
        }
    }
    printf("============================\n\n");
}

// DNS protocol helper implementations

// Create AXFR DNS query packet
int zone_transfer_create_axfr_query(const char *domain, uint8_t *buffer, size_t buffer_size) {
    if (!domain || !buffer || buffer_size < 64) return -1;

    memset(buffer, 0, buffer_size);

    // DNS header (12 bytes)
    uint16_t *header = (uint16_t*)buffer;
    header[0] = htons(0x1234); // Random query ID
    header[1] = htons(0x0100); // Standard query, recursion desired
    header[2] = htons(1);      // Questions count
    header[3] = htons(0);      // Answer count
    header[4] = htons(0);      // Authority count
    header[5] = htons(0);      // Additional count

    // Encode domain name in DNS format
    uint8_t *ptr = buffer + 12;
    const char *label_start = domain;
    const char *dot = domain;

    while (*dot) {
        if (*dot == '.' || *(dot + 1) == '\0') {
            size_t label_len = dot - label_start;
            if (*(dot + 1) == '\0' && *dot != '.') label_len++; // Include last character

            if (label_len > 63 || ptr + label_len + 1 >= buffer + buffer_size - 5) {
                return -1; // Label too long or buffer too small
            }

            *ptr++ = (uint8_t)label_len;
            memcpy(ptr, label_start, label_len);
            ptr += label_len;

            if (*dot == '.') {
                label_start = dot + 1;
            }
        }
        dot++;
    }

    *ptr++ = 0; // Null terminator for domain name

    // QTYPE: AXFR (252)
    *(uint16_t*)ptr = htons(252);
    ptr += 2;

    // QCLASS: IN (1)
    *(uint16_t*)ptr = htons(1);
    ptr += 2;

    return ptr - buffer;
}

// Create IXFR DNS query packet with serial number
int zone_transfer_create_ixfr_query(const char *domain, uint32_t serial, uint8_t *buffer, size_t buffer_size) {
    if (!domain || !buffer || buffer_size < 128) return -1;

    memset(buffer, 0, buffer_size);

    // DNS header (12 bytes)
    uint16_t *header = (uint16_t*)buffer;
    header[0] = htons(0x1235); // Random query ID
    header[1] = htons(0x0100); // Standard query, recursion desired
    header[2] = htons(1);      // Questions count
    header[3] = htons(0);      // Answer count
    header[4] = htons(1);      // Authority count (SOA record with serial)
    header[5] = htons(0);      // Additional count

    // Encode domain name in DNS format
    uint8_t *ptr = buffer + 12;
    const char *label_start = domain;
    const char *dot = domain;

    while (*dot) {
        if (*dot == '.' || *(dot + 1) == '\0') {
            size_t label_len = dot - label_start;
            if (*(dot + 1) == '\0' && *dot != '.') label_len++; // Include last character

            if (label_len > 63 || ptr + label_len + 1 >= buffer + buffer_size - 64) {
                return -1; // Label too long or buffer too small
            }

            *ptr++ = (uint8_t)label_len;
            memcpy(ptr, label_start, label_len);
            ptr += label_len;

            if (*dot == '.') {
                label_start = dot + 1;
            }
        }
        dot++;
    }

    *ptr++ = 0; // Null terminator for domain name

    // QTYPE: IXFR (251)
    *(uint16_t*)ptr = htons(251);
    ptr += 2;

    // QCLASS: IN (1)
    *(uint16_t*)ptr = htons(1);
    ptr += 2;

    // Authority section: SOA record with serial number for IXFR
    // Domain name (compressed pointer to question)
    *(uint16_t*)ptr = htons(0xC00C); // Compression pointer to offset 12
    ptr += 2;

    // TYPE: SOA (6)
    *(uint16_t*)ptr = htons(6);
    ptr += 2;

    // CLASS: IN (1)
    *(uint16_t*)ptr = htons(1);
    ptr += 2;

    // TTL: 0
    *(uint32_t*)ptr = htonl(0);
    ptr += 4;

    // RDLENGTH: 22 bytes for minimal SOA
    *(uint16_t*)ptr = htons(22);
    ptr += 2;

    // SOA RDATA: minimal SOA with serial number
    // MNAME: . (root)
    *ptr++ = 0;
    // RNAME: . (root)
    *ptr++ = 0;
    // SERIAL: provided serial number
    *(uint32_t*)ptr = htonl(serial);
    ptr += 4;
    // REFRESH: 3600
    *(uint32_t*)ptr = htonl(3600);
    ptr += 4;
    // RETRY: 1800
    *(uint32_t*)ptr = htonl(1800);
    ptr += 4;
    // EXPIRE: 604800
    *(uint32_t*)ptr = htonl(604800);
    ptr += 4;
    // MINIMUM: 86400
    *(uint32_t*)ptr = htonl(86400);
    ptr += 4;

    return ptr - buffer;
}

// Send DNS query over TCP with length prefix
int zone_transfer_send_query(int sockfd, const uint8_t *query, size_t query_len) {
    if (sockfd < 0 || !query || query_len == 0 || query_len > 65535) return -1;

    // TCP DNS queries are prefixed with 2-byte length
    uint8_t length_prefix[2];
    length_prefix[0] = (query_len >> 8) & 0xFF;
    length_prefix[1] = query_len & 0xFF;

    // Send length prefix
    ssize_t sent = send(sockfd, length_prefix, 2, MSG_NOSIGNAL);
    if (sent != 2) {
        return -1;
    }

    // Send query data
    sent = send(sockfd, query, query_len, MSG_NOSIGNAL);
    if (sent != (ssize_t)query_len) {
        return -1;
    }

    return 0;
}

// Receive DNS response over TCP with length prefix
int zone_transfer_receive_response(int sockfd, uint8_t *buffer, size_t buffer_size, uint32_t timeout_ms) {
    if (sockfd < 0 || !buffer || buffer_size < 2) return -1;

    // Set receive timeout
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Receive length prefix (2 bytes)
    uint8_t length_prefix[2];
    ssize_t received = recv(sockfd, length_prefix, 2, MSG_WAITALL);
    if (received != 2) {
        return -1;
    }

    // Calculate response length
    uint16_t response_len = (length_prefix[0] << 8) | length_prefix[1];
    if (response_len == 0 || response_len > buffer_size) {
        return -1;
    }

    // Receive response data
    received = recv(sockfd, buffer, response_len, MSG_WAITALL);
    if (received != response_len) {
        return -1;
    }

    return received;
}

// Parse DNS zone transfer records from raw data
int zone_transfer_parse_records(const char *raw_data, size_t data_len, zone_record_t **records, uint32_t *record_count) {
    if (!raw_data || data_len < 12 || !records || !record_count) return -1;

    *records = NULL;
    *record_count = 0;

    // Check if we have a valid DNS response
    if (data_len < 12) return -1;

    const uint8_t *data = (const uint8_t*)raw_data;
    uint16_t ancount = ntohs(*(uint16_t*)(data + 6)); // Answer count

    if (ancount == 0) return 0; // No records to parse

    // Allocate memory for records
    zone_record_t *parsed_records = calloc(ancount, sizeof(zone_record_t));
    if (!parsed_records) return -1;

    // Skip DNS header and question section
    const uint8_t *ptr = data + 12;
    const uint8_t *end = data + data_len;

    // Skip question section
    uint16_t qdcount = ntohs(*(uint16_t*)(data + 4));
    for (uint16_t i = 0; i < qdcount && ptr < end; i++) {
        // Skip QNAME
        while (ptr < end && *ptr != 0) {
            if ((*ptr & 0xC0) == 0xC0) {
                ptr += 2; // Compressed name
                break;
            } else {
                ptr += *ptr + 1; // Label length + label
            }
        }
        if (ptr < end && *ptr == 0) ptr++; // Skip null terminator
        ptr += 4; // Skip QTYPE and QCLASS
    }

    // Parse answer section
    uint32_t parsed_count = 0;
    for (uint16_t i = 0; i < ancount && ptr < end && parsed_count < ancount; i++) {
        zone_record_t *record = &parsed_records[parsed_count];
        record->discovered = time(NULL);

        // Parse NAME (simplified - handle compression in full implementation)
        char name_buffer[RECON_MAX_DOMAIN_LEN];
        int name_len = 0;

        if ((*ptr & 0xC0) == 0xC0) {
            // Compressed name - simplified handling
            strcpy(name_buffer, "compressed.name");
            ptr += 2;
        } else {
            // Uncompressed name
            const uint8_t *name_start = ptr;
            (void)name_start; // Reserved for name validation
            while (ptr < end && *ptr != 0) {
                uint8_t label_len = *ptr++;
                if (ptr + label_len > end) break;

                if (name_len + label_len + 1 < (int)sizeof(name_buffer)) {
                    if (name_len > 0) name_buffer[name_len++] = '.';
                    memcpy(name_buffer + name_len, ptr, label_len);
                    name_len += label_len;
                }
                ptr += label_len;
            }
            if (ptr < end && *ptr == 0) ptr++; // Skip null terminator
            name_buffer[name_len] = '\0';
        }

        snprintf(record->name, RECON_MAX_DOMAIN_LEN, "%s", name_buffer);

        if (ptr + 10 > end) break; // Need at least TYPE, CLASS, TTL, RDLENGTH

        // Parse TYPE
        uint16_t type = ntohs(*(uint16_t*)ptr);
        ptr += 2;
        record->type = (dns_record_type_t)type;

        // Skip CLASS
        ptr += 2;

        // Parse TTL
        record->ttl = ntohl(*(uint32_t*)ptr);
        ptr += 4;

        // Parse RDLENGTH
        record->rdlength = ntohs(*(uint16_t*)ptr);
        ptr += 2;

        // Parse RDATA (simplified)
        if (ptr + record->rdlength <= end) {
            size_t copy_len = (record->rdlength < sizeof(record->rdata) - 1) ?
                             record->rdlength : sizeof(record->rdata) - 1;

            if (type == DNS_TYPE_A && record->rdlength == 4) {
                // Format A record as IP address
                snprintf(record->rdata, sizeof(record->rdata), "%d.%d.%d.%d",
                        ptr[0], ptr[1], ptr[2], ptr[3]);
            } else if (type == DNS_TYPE_AAAA && record->rdlength == 16) {
                // Format AAAA record as IPv6 address
                char ipv6_str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, ptr, ipv6_str, INET6_ADDRSTRLEN);
                strncpy(record->rdata, ipv6_str, sizeof(record->rdata) - 1);
            } else {
                // Copy raw data for other record types
                memcpy(record->rdata, ptr, copy_len);
                record->rdata[copy_len] = '\0';
            }

            ptr += record->rdlength;
            parsed_count++;
        } else {
            break; // Malformed record
        }
    }

    *records = parsed_records;
    *record_count = parsed_count;

    return 0;
}

// Multi-threaded zone transfer worker
void *zone_transfer_worker_thread(void *arg) {
    if (!arg) return NULL;

    zone_transfer_context_t *ctx = (zone_transfer_context_t*)arg;
    (void)ctx; // Reserved for parallel zone transfer implementation

    // This would be used for parallel zone transfers across multiple domains
    // For now, return success
    return NULL;
}

// Set zone transfer configuration
int zone_transfer_set_config(zone_transfer_context_t *ctx, const zone_transfer_config_t *config) {
    if (!ctx || !config) return -1;

    ctx->config = *config;
    return 0;
}

// Export results to JSON format
int zone_transfer_export_json(const zone_transfer_context_t *ctx, const char *filename) {
    if (!ctx || !filename) return -1;

    FILE *fp = fopen(filename, "w");
    if (!fp) return -1;

    fprintf(fp, "{\n");
    fprintf(fp, "  \"zone_transfer_results\": [\n");

    for (uint32_t i = 0; i < ctx->result_count; i++) {
        const zone_transfer_result_t *result = &ctx->results[i];

        fprintf(fp, "    {\n");
        fprintf(fp, "      \"zone_name\": \"%s\",\n", result->zone_name);
        fprintf(fp, "      \"transfer_type\": \"%s\",\n", zone_transfer_type_to_string(result->transfer_type));
        fprintf(fp, "      \"status\": \"%s\",\n", zone_transfer_status_to_string(result->status));
        fprintf(fp, "      \"server\": {\n");
        fprintf(fp, "        \"hostname\": \"%s\",\n", result->server.hostname);
        fprintf(fp, "        \"ip_address\": \"%s\",\n", result->server.ip_address);
        fprintf(fp, "        \"port\": %u\n", result->server.port);
        fprintf(fp, "      },\n");
        fprintf(fp, "      \"record_count\": %u,\n", result->record_count);
        fprintf(fp, "      \"transfer_time_ms\": %u,\n", result->transfer_time_ms);
        fprintf(fp, "      \"timestamp\": %ld", (long)result->timestamp);

        if (strlen(result->error_message) > 0) {
            fprintf(fp, ",\n      \"error_message\": \"%s\"", result->error_message);
        }

        fprintf(fp, "\n    }");
        if (i < ctx->result_count - 1) fprintf(fp, ",");
        fprintf(fp, "\n");
    }

    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");

    fclose(fp);
    return 0;
}

// Export results to CSV format
int zone_transfer_export_csv(const zone_transfer_context_t *ctx, const char *filename) {
    if (!ctx || !filename) return -1;

    FILE *fp = fopen(filename, "w");
    if (!fp) return -1;

    // CSV header
    fprintf(fp, "Zone,Type,Status,Server,IP,Port,Records,TransferTime,Timestamp,Error\n");

    for (uint32_t i = 0; i < ctx->result_count; i++) {
        const zone_transfer_result_t *result = &ctx->results[i];

        fprintf(fp, "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",%u,%u,%u,%ld,\"%s\"\n",
                result->zone_name,
                zone_transfer_type_to_string(result->transfer_type),
                zone_transfer_status_to_string(result->status),
                result->server.hostname,
                result->server.ip_address,
                result->server.port,
                result->record_count,
                result->transfer_time_ms,
                (long)result->timestamp,
                result->error_message);
    }

    fclose(fp);
    return 0;
}

// OPSEC and evasion functions
bool zone_transfer_check_detection_risk(const zone_transfer_context_t *ctx) {
    if (!ctx) return true;

    // Check if we've made too many requests too quickly
    uint32_t recent_attempts = 0;
    time_t current_time = time(NULL);

    for (uint32_t i = 0; i < ctx->result_count; i++) {
        if (current_time - ctx->results[i].timestamp < 60) { // Last minute
            recent_attempts++;
        }
    }

    return recent_attempts > ctx->config.opsec.max_requests_per_session;
}

// Randomize server order for OPSEC
void zone_transfer_randomize_server_order(zone_server_t *servers, uint32_t count) {
    if (!servers || count <= 1) return;

    srand(time(NULL));

    for (uint32_t i = count - 1; i > 0; i--) {
        uint32_t j = rand() % (i + 1);
        if (i != j) {
            zone_server_t temp = servers[i];
            servers[i] = servers[j];
            servers[j] = temp;
        }
    }
}

// Validate DNS record
bool zone_transfer_validate_record(const zone_record_t *record) {
    if (!record) return false;

    // Basic validation checks
    if (strlen(record->name) == 0) return false;
    if (record->rdlength == 0) return false;
    if (record->ttl > 86400 * 365) return false; // TTL > 1 year is suspicious

    return true;
}

// Extract subdomains from zone records
int zone_transfer_extract_subdomains(const zone_record_t *records, uint32_t record_count,
                                    char ***subdomains, uint32_t *subdomain_count) {
    if (!records || record_count == 0 || !subdomains || !subdomain_count) return -1;

    // Allocate array for subdomain pointers
    char **extracted = malloc(record_count * sizeof(char*));
    if (!extracted) return -1;

    uint32_t count = 0;

    for (uint32_t i = 0; i < record_count; i++) {
        const zone_record_t *record = &records[i];

        // Skip non-name records
        if (record->type != DNS_TYPE_A && record->type != DNS_TYPE_AAAA &&
            record->type != DNS_TYPE_CNAME) {
            continue;
        }

        // Check if this subdomain is already in our list
        bool duplicate = false;
        for (uint32_t j = 0; j < count; j++) {
            if (strcmp(extracted[j], record->name) == 0) {
                duplicate = true;
                break;
            }
        }

        if (!duplicate) {
            extracted[count] = strdup(record->name);
            if (extracted[count]) {
                count++;
            }
        }
    }

    *subdomains = extracted;
    *subdomain_count = count;

    return 0;
}