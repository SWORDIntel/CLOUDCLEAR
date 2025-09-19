/*
 * CloudUnflare Enhanced - Port Scanner Implementation
 *
 * Advanced port scanning with TCP/UDP capabilities
 * Template for C-INTERNAL agent implementation
 */

#include "port_scanner.h"

// Initialize port scanner context
int port_scanner_init_context(port_scanner_context_t *ctx) {
    if (!ctx) return -1;

    memset(ctx, 0, sizeof(port_scanner_context_t));

    // Initialize base reconnaissance context
    if (recon_init_context(&ctx->base_ctx, RECON_MODE_ACTIVE) != 0) {
        return -1;
    }

    // Initialize mutexes
    if (pthread_mutex_init(&ctx->results_mutex, NULL) != 0) {
        recon_cleanup_context(&ctx->base_ctx);
        return -1;
    }

    if (pthread_mutex_init(&ctx->socket_mutex, NULL) != 0) {
        pthread_mutex_destroy(&ctx->results_mutex);
        recon_cleanup_context(&ctx->base_ctx);
        return -1;
    }

    // Set default configuration
    ctx->config.default_scan_type = SCAN_TYPE_TCP_CONNECT;
    ctx->config.timeout_seconds = PORT_SCANNER_DEFAULT_TIMEOUT;
    ctx->config.max_retries = PORT_SCANNER_MAX_RETRIES;
    ctx->config.max_threads = 10;
    ctx->config.detect_services = true;
    ctx->config.grab_banners = true;
    ctx->config.ping_before_scan = true;
    ctx->config.delay_between_probes_ms = 100;

    // Initialize raw sockets (will fail without root)
    ctx->raw_socket_tcp = -1;
    ctx->raw_socket_udp = -1;
    ctx->raw_socket_icmp = -1;

    ctx->max_results = 10;
    ctx->results = calloc(ctx->max_results, sizeof(host_scan_result_t));
    if (!ctx->results) {
        port_scanner_cleanup_context(ctx);
        return -1;
    }

    return 0;
}

// Cleanup port scanner context
void port_scanner_cleanup_context(port_scanner_context_t *ctx) {
    if (!ctx) return;

    if (ctx->results) {
        for (uint32_t i = 0; i < ctx->result_count; i++) {
            if (ctx->results[i].ports) {
                free(ctx->results[i].ports);
            }
        }
        free(ctx->results);
    }

    port_scanner_close_raw_sockets(ctx);

    pthread_mutex_destroy(&ctx->results_mutex);
    pthread_mutex_destroy(&ctx->socket_mutex);
    recon_cleanup_context(&ctx->base_ctx);
}

// Scan single host
int port_scanner_scan_host(port_scanner_context_t *ctx, const char *hostname, host_scan_result_t *result) {
    if (!ctx || !hostname || !result) return -1;

    recon_log_info("port_scanner", "Starting port scan");

    memset(result, 0, sizeof(host_scan_result_t));

    // Set up target
    if (recon_add_target(&result->target, hostname, 80) != 0) {
        return -1;
    }

    result->scan_started = time(NULL);

    // TODO: C-INTERNAL agent implementation
    // 1. Ping host to check if it's up
    // 2. Get list of ports to scan from configuration
    // 3. Launch worker threads for port scanning
    // 4. Collect and analyze results
    // 5. Perform service detection on open ports
    // 6. Generate final scan report

    // Placeholder: Add some example port results
    result->ports = calloc(6, sizeof(port_result_t));
    if (!result->ports) return -1;

    // Port 80 - HTTP
    result->ports[0].port = 80;
    result->ports[0].scan_type = SCAN_TYPE_TCP_CONNECT;
    result->ports[0].state = PORT_STATE_OPEN;
    strcpy(result->ports[0].protocol, "tcp");
    result->ports[0].response_time_ms = 50;
    strcpy(result->ports[0].service.service_name, "http");
    strcpy(result->ports[0].service.version, "nginx 1.18.0");
    result->ports[0].has_service_info = true;

    // Port 443 - HTTPS
    result->ports[1].port = 443;
    result->ports[1].scan_type = SCAN_TYPE_TCP_CONNECT;
    result->ports[1].state = PORT_STATE_OPEN;
    strcpy(result->ports[1].protocol, "tcp");
    result->ports[1].response_time_ms = 75;
    strcpy(result->ports[1].service.service_name, "https");
    strcpy(result->ports[1].service.version, "nginx 1.18.0");
    result->ports[1].has_service_info = true;

    // Port 22 - SSH
    result->ports[2].port = 22;
    result->ports[2].scan_type = SCAN_TYPE_TCP_CONNECT;
    result->ports[2].state = PORT_STATE_OPEN;
    strcpy(result->ports[2].protocol, "tcp");
    result->ports[2].response_time_ms = 25;
    strcpy(result->ports[2].service.service_name, "ssh");
    strcpy(result->ports[2].service.version, "OpenSSH 8.2");
    result->ports[2].has_service_info = true;

    // Some closed ports
    result->ports[3].port = 21;
    result->ports[3].state = PORT_STATE_CLOSED;
    result->ports[4].port = 25;
    result->ports[4].state = PORT_STATE_CLOSED;
    result->ports[5].port = 53;
    result->ports[5].state = PORT_STATE_FILTERED;

    result->port_count = 6;
    result->open_ports = 3;
    result->closed_ports = 2;
    result->filtered_ports = 1;
    result->host_up = true;
    result->scan_completed = time(NULL);
    result->total_scan_time_ms = 2000;

    recon_log_info("port_scanner", "Port scan completed");
    return result->open_ports;
}

// Print host scan result
void port_scanner_print_host_result(const host_scan_result_t *result) {
    if (!result) return;

    printf("\n=== Port Scan Results ===\n");
    printf("Host: %s (%s)\n", result->target.hostname, result->target.ip_address);
    printf("Status: %s\n", result->host_up ? "Up" : "Down");
    printf("Open ports: %u\n", result->open_ports);
    printf("Scan time: %ums\n", result->total_scan_time_ms);

    printf("\nPort Details:\n");
    for (uint32_t i = 0; i < result->port_count; i++) {
        const port_result_t *port = &result->ports[i];
        printf("  %u/%s\t%s", port->port, port->protocol, port_state_to_string(port->state));

        if (port->state == PORT_STATE_OPEN && port->has_service_info) {
            printf("\t%s %s", port->service.service_name, port->service.version);
        }
        printf("\n");
    }
    printf("========================\n\n");
}

// Add port range to configuration
int port_scanner_add_port_range(port_scanner_config_t *config, uint16_t start, uint16_t end, scan_type_t type) {
    if (!config || config->range_count >= PORT_SCANNER_MAX_RANGES) {
        return -1;
    }

    port_range_t *range = &config->port_ranges[config->range_count];
    range->start_port = start;
    range->end_port = end;
    range->scan_type = type;
    range->priority = 1;

    config->range_count++;
    return 0;
}

// Close raw sockets
void port_scanner_close_raw_sockets(port_scanner_context_t *ctx) {
    if (!ctx) return;

    if (ctx->raw_socket_tcp >= 0) {
        close(ctx->raw_socket_tcp);
        ctx->raw_socket_tcp = -1;
    }
    if (ctx->raw_socket_udp >= 0) {
        close(ctx->raw_socket_udp);
        ctx->raw_socket_udp = -1;
    }
    if (ctx->raw_socket_icmp >= 0) {
        close(ctx->raw_socket_icmp);
        ctx->raw_socket_icmp = -1;
    }
}

// Convert scan type to string
const char *scan_type_to_string(scan_type_t type) {
    switch (type) {
        case SCAN_TYPE_TCP_SYN: return "TCP SYN";
        case SCAN_TYPE_TCP_CONNECT: return "TCP Connect";
        case SCAN_TYPE_TCP_ACK: return "TCP ACK";
        case SCAN_TYPE_TCP_FIN: return "TCP FIN";
        case SCAN_TYPE_TCP_NULL: return "TCP NULL";
        case SCAN_TYPE_TCP_XMAS: return "TCP XMAS";
        case SCAN_TYPE_UDP: return "UDP";
        case SCAN_TYPE_ICMP_PING: return "ICMP Ping";
        case SCAN_TYPE_ARP_PING: return "ARP Ping";
        default: return "Unknown";
    }
}

// Convert port state to string
const char *port_state_to_string(port_state_t state) {
    switch (state) {
        case PORT_STATE_OPEN: return "open";
        case PORT_STATE_CLOSED: return "closed";
        case PORT_STATE_FILTERED: return "filtered";
        case PORT_STATE_UNFILTERED: return "unfiltered";
        case PORT_STATE_OPEN_FILTERED: return "open|filtered";
        default: return "unknown";
    }
}

// Check if scan type requires root privileges
bool port_scanner_requires_root(scan_type_t scan_type) {
    switch (scan_type) {
        case SCAN_TYPE_TCP_SYN:
        case SCAN_TYPE_TCP_FIN:
        case SCAN_TYPE_TCP_NULL:
        case SCAN_TYPE_TCP_XMAS:
        case SCAN_TYPE_ICMP_PING:
        case SCAN_TYPE_ARP_PING:
            return true;
        default:
            return false;
    }
}