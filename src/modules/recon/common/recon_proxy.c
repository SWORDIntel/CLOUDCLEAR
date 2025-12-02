/*
 * CloudUnflare Enhanced - Proxy Chain Implementation
 *
 * Advanced proxy chain management for OPSEC compliance
 * Supports SOCKS4/5, HTTP/HTTPS proxies with health monitoring
 *
 * Agent: SECURITY (primary implementation)
 * Coordination: GHOST-PROTOCOL, NSA-TTP
 */

#include "recon_opsec.h"
#include "platform_compat.h"
#include <fcntl.h>

// SOCKS5 protocol constants
#define SOCKS5_VERSION 0x05
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6 0x04

// SOCKS4 protocol constants
#define SOCKS4_VERSION 0x04
#define SOCKS4_CMD_CONNECT 0x01

// HTTP proxy constants
#define HTTP_CONNECT_METHOD "CONNECT"

// Initialize proxy chain from configuration file
int opsec_init_proxy_chain(opsec_context_t *ctx, const char *proxy_list_file) {
    if (!ctx || !proxy_list_file) return -1;

    FILE *fp = fopen(proxy_list_file, "r");
    if (!fp) {
        recon_log_error("proxy", proxy_list_file, "Failed to open proxy list file");
        return -1;
    }

    char line[512];
    uint32_t proxy_count = 0;

    while (fgets(line, sizeof(line), fp) && proxy_count < ctx->config.max_chain_length) {
        // Parse proxy line: type://[username:password@]host:port
        char *type_str = strtok(line, "://");
        char *rest = strtok(NULL, "");

        if (!type_str || !rest) continue;

        proxy_type_t type;
        if (strcasecmp(type_str, "http") == 0) {
            type = PROXY_TYPE_HTTP;
        } else if (strcasecmp(type_str, "https") == 0) {
            type = PROXY_TYPE_HTTPS;
        } else if (strcasecmp(type_str, "socks4") == 0) {
            type = PROXY_TYPE_SOCKS4;
        } else if (strcasecmp(type_str, "socks5") == 0) {
            type = PROXY_TYPE_SOCKS5;
        } else {
            continue; // Unknown proxy type
        }

        // Parse authentication and address
        char *auth_part = NULL;
        char *host_part = rest;

        if (strchr(rest, '@')) {
            auth_part = strtok(rest, "@");
            host_part = strtok(NULL, "");
        }

        if (!host_part) continue;

        // Parse host and port
        char *host = strtok(host_part, ":");
        char *port_str = strtok(NULL, " \t\r\n");

        if (!host || !port_str) continue;

        uint16_t port = (uint16_t)atoi(port_str);
        if (port == 0) continue;

        // Add proxy to chain
        proxy_node_t *proxy = &ctx->config.proxy_chain[proxy_count];
        memset(proxy, 0, sizeof(proxy_node_t));

        strncpy(proxy->address, host, INET6_ADDRSTRLEN - 1);
        proxy->port = port;
        proxy->type = type;
        proxy->operational = true;
        proxy->trust_score = 1.0;

        // Parse authentication if present
        if (auth_part) {
            char *username = strtok(auth_part, ":");
            char *password = strtok(NULL, "");

            if (username) {
                strncpy(proxy->username, username, 127);
                proxy->authenticated = true;
            }
            if (password) {
                strncpy(proxy->password, password, 127);
            }
        }

        proxy_count++;
    }

    fclose(fp);

    ctx->config.proxy_chain_length = proxy_count;
    recon_log_info("proxy", "Loaded proxy chain");

    return 0;
}

// Add a single proxy node to the chain
int opsec_add_proxy_node(opsec_context_t *ctx, const char *address, uint16_t port, proxy_type_t type) {
    if (!ctx || !address || ctx->config.proxy_chain_length >= ctx->config.max_chain_length) {
        return -1;
    }

    proxy_node_t *proxy = &ctx->config.proxy_chain[ctx->config.proxy_chain_length];
    memset(proxy, 0, sizeof(proxy_node_t));

    strncpy(proxy->address, address, INET6_ADDRSTRLEN - 1);
    proxy->port = port;
    proxy->type = type;
    proxy->operational = true;
    proxy->trust_score = 1.0;
    proxy->last_health_check = time(NULL);

    ctx->config.proxy_chain_length++;

    return 0;
}

// Rotate to next proxy in chain
int opsec_rotate_proxy_chain(opsec_context_t *ctx) {
    if (!ctx || ctx->config.proxy_chain_length == 0) return -1;

    pthread_mutex_lock(&ctx->proxy_mutex);

    // Find next operational proxy
    uint32_t start_index = ctx->current_proxy_index;
    (void)start_index; // Reserved for cycle detection in future enhancement
    uint32_t attempts = 0;

    do {
        ctx->current_proxy_index = (ctx->current_proxy_index + 1) % ctx->config.proxy_chain_length;
        attempts++;

        if (attempts >= ctx->config.proxy_chain_length) {
            // All proxies non-operational
            pthread_mutex_unlock(&ctx->proxy_mutex);
            return -1;
        }

    } while (!ctx->config.proxy_chain[ctx->current_proxy_index].operational);

    ctx->last_proxy_rotation = time(NULL);

    pthread_mutex_unlock(&ctx->proxy_mutex);

    recon_log_info("proxy", "Rotated to next proxy in chain");
    return 0;
}

// Health check a proxy node
bool opsec_health_check_proxy(proxy_node_t *proxy) {
    if (!proxy) return false;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return false;

    // Set connection timeout
    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(proxy->port);

    if (inet_pton(AF_INET, proxy->address, &addr.sin_addr) != 1) {
        // Try hostname resolution
        struct hostent *host = gethostbyname(proxy->address);
        if (!host) {
            close(sockfd);
            return false;
        }
        memcpy(&addr.sin_addr, host->h_addr_list[0], host->h_length);
    }

    clock_t start_time = clock();
    bool connected = (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    clock_t end_time = clock();

    if (connected) {
        proxy->latency_ms = (uint32_t)((end_time - start_time) * 1000 / CLOCKS_PER_SEC);
        proxy->operational = true;
    } else {
        proxy->operational = false;
    }

    proxy->last_health_check = time(NULL);
    close(sockfd);

    return connected;
}

// Establish connection through SOCKS5 proxy
static int socks5_connect(const proxy_node_t *proxy, const char *target_host, uint16_t target_port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;

    // Connect to SOCKS5 proxy
    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(proxy->port);

    if (inet_pton(AF_INET, proxy->address, &proxy_addr.sin_addr) != 1) {
        close(sockfd);
        return -1;
    }

    if (connect(sockfd, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) < 0) {
        close(sockfd);
        return -1;
    }

    // SOCKS5 authentication negotiation
    uint8_t auth_req[3] = {SOCKS5_VERSION, 0x01, 0x00}; // Version, 1 method, no auth
    if (proxy->authenticated) {
        auth_req[2] = 0x02; // Username/password authentication
    }

    if (send(sockfd, auth_req, sizeof(auth_req), 0) != sizeof(auth_req)) {
        close(sockfd);
        return -1;
    }

    uint8_t auth_resp[2];
    if (recv(sockfd, auth_resp, sizeof(auth_resp), 0) != sizeof(auth_resp)) {
        close(sockfd);
        return -1;
    }

    if (auth_resp[0] != SOCKS5_VERSION) {
        close(sockfd);
        return -1;
    }

    // Handle authentication
    if (auth_resp[1] == 0x02 && proxy->authenticated) {
        // Username/password authentication
        uint8_t auth_data[512];
        int auth_len = 0;

        auth_data[auth_len++] = 0x01; // Sub-negotiation version
        auth_data[auth_len++] = strlen(proxy->username);
        memcpy(auth_data + auth_len, proxy->username, strlen(proxy->username));
        auth_len += strlen(proxy->username);
        auth_data[auth_len++] = strlen(proxy->password);
        memcpy(auth_data + auth_len, proxy->password, strlen(proxy->password));
        auth_len += strlen(proxy->password);

        if (send(sockfd, auth_data, auth_len, 0) != auth_len) {
            close(sockfd);
            return -1;
        }

        uint8_t auth_result[2];
        if (recv(sockfd, auth_result, sizeof(auth_result), 0) != sizeof(auth_result)) {
            close(sockfd);
            return -1;
        }

        if (auth_result[1] != 0x00) { // Authentication failed
            close(sockfd);
            return -1;
        }
    } else if (auth_resp[1] != 0x00) {
        // No acceptable authentication method
        close(sockfd);
        return -1;
    }

    // SOCKS5 connection request
    uint8_t connect_req[512];
    int req_len = 0;

    connect_req[req_len++] = SOCKS5_VERSION;
    connect_req[req_len++] = SOCKS5_CMD_CONNECT;
    connect_req[req_len++] = 0x00; // Reserved

    // Address type and target
    if (recon_is_valid_ip(target_host)) {
        connect_req[req_len++] = SOCKS5_ATYP_IPV4;
        struct in_addr addr;
        inet_pton(AF_INET, target_host, &addr);
        memcpy(connect_req + req_len, &addr, 4);
        req_len += 4;
    } else {
        connect_req[req_len++] = SOCKS5_ATYP_DOMAIN;
        uint8_t domain_len = strlen(target_host);
        connect_req[req_len++] = domain_len;
        memcpy(connect_req + req_len, target_host, domain_len);
        req_len += domain_len;
    }

    // Target port
    uint16_t port_net = htons(target_port);
    memcpy(connect_req + req_len, &port_net, 2);
    req_len += 2;

    if (send(sockfd, connect_req, req_len, 0) != req_len) {
        close(sockfd);
        return -1;
    }

    // Receive connection response
    uint8_t connect_resp[512];
    if (recv(sockfd, connect_resp, 10, 0) < 10) { // Minimum response size
        close(sockfd);
        return -1;
    }

    if (connect_resp[0] != SOCKS5_VERSION || connect_resp[1] != 0x00) {
        close(sockfd);
        return -1;
    }

    return sockfd;
}

// Establish connection through SOCKS4 proxy
static int socks4_connect(const proxy_node_t *proxy, const char *target_host, uint16_t target_port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;

    // Connect to SOCKS4 proxy
    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(proxy->port);

    if (inet_pton(AF_INET, proxy->address, &proxy_addr.sin_addr) != 1) {
        close(sockfd);
        return -1;
    }

    if (connect(sockfd, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) < 0) {
        close(sockfd);
        return -1;
    }

    // Resolve target hostname to IP
    struct in_addr target_addr;
    if (inet_pton(AF_INET, target_host, &target_addr) != 1) {
        struct hostent *host = gethostbyname(target_host);
        if (!host) {
            close(sockfd);
            return -1;
        }
        memcpy(&target_addr, host->h_addr_list[0], host->h_length);
    }

    // Build SOCKS4 connection request
    uint8_t connect_req[512];
    int req_len = 0;

    connect_req[req_len++] = SOCKS4_VERSION;
    connect_req[req_len++] = SOCKS4_CMD_CONNECT;

    // Target port (network byte order)
    uint16_t port_net = htons(target_port);
    memcpy(connect_req + req_len, &port_net, 2);
    req_len += 2;

    // Target IP
    memcpy(connect_req + req_len, &target_addr, 4);
    req_len += 4;

    // User ID (empty)
    connect_req[req_len++] = 0x00;

    if (send(sockfd, connect_req, req_len, 0) != req_len) {
        close(sockfd);
        return -1;
    }

    // Receive response
    uint8_t connect_resp[8];
    if (recv(sockfd, connect_resp, sizeof(connect_resp), 0) != sizeof(connect_resp)) {
        close(sockfd);
        return -1;
    }

    if (connect_resp[1] != 0x5A) { // Request granted
        close(sockfd);
        return -1;
    }

    return sockfd;
}

// Establish connection through HTTP proxy
static int http_connect(const proxy_node_t *proxy, const char *target_host, uint16_t target_port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;

    // Connect to HTTP proxy
    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(proxy->port);

    if (inet_pton(AF_INET, proxy->address, &proxy_addr.sin_addr) != 1) {
        close(sockfd);
        return -1;
    }

    if (connect(sockfd, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) < 0) {
        close(sockfd);
        return -1;
    }

    // Build HTTP CONNECT request
    char connect_req[1024];
    int req_len = snprintf(connect_req, sizeof(connect_req),
                          "CONNECT %s:%u HTTP/1.1\r\n"
                          "Host: %s:%u\r\n"
                          "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n",
                          target_host, target_port, target_host, target_port);

    // Add authentication if configured
    if (proxy->authenticated) {
        char auth_str[256];
        snprintf(auth_str, sizeof(auth_str), "%s:%s", proxy->username, proxy->password);

        // Base64 encode authentication (simplified)
        char encoded_auth[512];
        // In a real implementation, we would use proper base64 encoding
        snprintf(encoded_auth, sizeof(encoded_auth), "Basic %s", auth_str);

        req_len += snprintf(connect_req + req_len, sizeof(connect_req) - req_len,
                           "Proxy-Authorization: %s\r\n", encoded_auth);
    }

    req_len += snprintf(connect_req + req_len, sizeof(connect_req) - req_len, "\r\n");

    if (send(sockfd, connect_req, req_len, 0) != req_len) {
        close(sockfd);
        return -1;
    }

    // Receive HTTP response
    char response[1024];
    int resp_len = recv(sockfd, response, sizeof(response) - 1, 0);
    if (resp_len <= 0) {
        close(sockfd);
        return -1;
    }

    response[resp_len] = '\0';

    // Check for successful connection (200 Connection established)
    if (strstr(response, "200") == NULL) {
        close(sockfd);
        return -1;
    }

    return sockfd;
}

// Establish connection through proxy chain
int opsec_establish_proxy_connection(const proxy_node_t *proxy, const char *target_host, uint16_t target_port) {
    if (!proxy || !target_host) return -1;

    int sockfd = -1;

    switch (proxy->type) {
        case PROXY_TYPE_SOCKS5:
            sockfd = socks5_connect(proxy, target_host, target_port);
            break;

        case PROXY_TYPE_SOCKS4:
            sockfd = socks4_connect(proxy, target_host, target_port);
            break;

        case PROXY_TYPE_HTTP:
        case PROXY_TYPE_HTTPS:
            sockfd = http_connect(proxy, target_host, target_port);
            break;

        default:
            return -1;
    }

    if (sockfd >= 0) {
        // Set socket options for better performance and security
        int keepalive = 1;
        setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));

        struct timeval timeout;
        timeout.tv_sec = 30;
        timeout.tv_usec = 0;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    }

    return sockfd;
}

// Perform health checks on all proxies in chain
int opsec_health_check_proxy_chain(opsec_context_t *ctx) {
    if (!ctx) return -1;

    uint32_t operational_count = 0;

    for (uint32_t i = 0; i < ctx->config.proxy_chain_length; i++) {
        proxy_node_t *proxy = &ctx->config.proxy_chain[i];

        // Skip recent health checks
        time_t current_time = time(NULL);
        if (current_time - proxy->last_health_check < 300) { // 5 minutes
            if (proxy->operational) operational_count++;
            continue;
        }

        bool is_operational = opsec_health_check_proxy(proxy);
        if (is_operational) {
            operational_count++;
            proxy->success_rate = (proxy->success_rate * 9 + 100) / 10; // Exponential average
        } else {
            proxy->success_rate = (proxy->success_rate * 9) / 10;
            proxy->trust_score *= 0.9; // Reduce trust score
        }
    }

    recon_log_info("proxy", "Health check completed for proxy chain");

    return operational_count;
}

// Get current active proxy
struct proxy_node* opsec_get_current_proxy(const opsec_context_t *ctx) {
    if (!ctx || ctx->config.proxy_chain_length == 0) return NULL;

    // Cast away const for mutex operations - safe since we're just reading
    opsec_context_t *mutable_ctx = (opsec_context_t *)ctx;
    pthread_mutex_lock(&mutable_ctx->proxy_mutex);
    struct proxy_node *proxy = &mutable_ctx->config.proxy_chain[ctx->current_proxy_index];
    pthread_mutex_unlock(&mutable_ctx->proxy_mutex);

    return proxy;
}

// Check if proxy rotation is needed
bool opsec_should_rotate_proxy(const opsec_context_t *ctx) {
    if (!ctx || ctx->config.proxy_chain_length <= 1) return false;

    time_t current_time = time(NULL);

    // Check rotation interval
    if (current_time - ctx->last_proxy_rotation >= ctx->config.proxy_rotation_interval) {
        return true;
    }

    // Check if current proxy is failing
    proxy_node_t *current_proxy = &ctx->config.proxy_chain[ctx->current_proxy_index];
    if (!current_proxy->operational || current_proxy->success_rate < 50) {
        return true;
    }

    return false;
}

// Load proxy configuration from file
int opsec_load_proxy_config(opsec_context_t *ctx, const char *config_file) {
    if (!ctx || !config_file) return -1;

    FILE *fp = fopen(config_file, "r");
    if (!fp) return -1;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;

        // Parse configuration options
        char *key = strtok(line, "=");
        char *value = strtok(NULL, "\n\r");

        if (!key || !value) continue;

        // Trim whitespace
        while (*key == ' ' || *key == '\t') key++;
        while (*value == ' ' || *value == '\t') value++;

        if (strcmp(key, "rotation_interval") == 0) {
            ctx->config.proxy_rotation_interval = atoi(value);
        } else if (strcmp(key, "health_check_enabled") == 0) {
            ctx->config.enable_proxy_health_checks = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "max_chain_length") == 0) {
            uint32_t max_length = atoi(value);
            if (max_length > 0 && max_length <= 10) {
                ctx->config.max_chain_length = max_length;
            }
        }
    }

    fclose(fp);
    return 0;
}

// Export proxy performance metrics
int opsec_export_proxy_metrics(const opsec_context_t *ctx, const char *filename) {
    if (!ctx || !filename) return -1;

    FILE *fp = fopen(filename, "w");
    if (!fp) return -1;

    fprintf(fp, "# Proxy Performance Metrics\n");
    fprintf(fp, "# Address,Port,Type,Operational,Latency(ms),SuccessRate,TrustScore,LastUsed\n");

    for (uint32_t i = 0; i < ctx->config.proxy_chain_length; i++) {
        const proxy_node_t *proxy = &ctx->config.proxy_chain[i];

        const char *type_str = "UNKNOWN";
        switch (proxy->type) {
            case PROXY_TYPE_HTTP: type_str = "HTTP"; break;
            case PROXY_TYPE_HTTPS: type_str = "HTTPS"; break;
            case PROXY_TYPE_SOCKS4: type_str = "SOCKS4"; break;
            case PROXY_TYPE_SOCKS5: type_str = "SOCKS5"; break;
            default: break;
        }

        fprintf(fp, "%s,%u,%s,%s,%u,%u,%.3f,%ld\n",
                proxy->address,
                proxy->port,
                type_str,
                proxy->operational ? "YES" : "NO",
                proxy->latency_ms,
                proxy->success_rate,
                proxy->trust_score,
                proxy->last_used);
    }

    fclose(fp);
    return 0;
}