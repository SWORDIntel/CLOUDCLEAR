/*
 * CloudUnflare Enhanced - Reconnaissance Common Implementation
 *
 * Common utilities and functions for API-free reconnaissance modules
 * Thread-safe operations with OPSEC compliance
 */

#include "recon_common.h"
#include <errno.h>
#include <sys/time.h>
#include <fcntl.h>

// Initialize reconnaissance context
int recon_init_context(recon_context_t *ctx, recon_mode_t mode) {
    if (!ctx) return -1;

    memset(ctx, 0, sizeof(recon_context_t));

    if (pthread_mutex_init(&ctx->mutex, NULL) != 0) {
        return -1;
    }

    ctx->scan_mode = mode;
    ctx->max_threads = (mode == RECON_MODE_STEALTH) ? 5 : RECON_MAX_THREADS;
    ctx->timeout_seconds = RECON_MAX_TIMEOUT;
    ctx->delay_between_requests_ms = (mode == RECON_MODE_STEALTH) ? 5000 : 1000;
    ctx->stop_scanning = false;

    atomic_init(&ctx->active_threads, 0);
    atomic_init(&ctx->completed_scans, 0);
    atomic_init(&ctx->failed_scans, 0);
    atomic_init(&ctx->total_response_time, 0);

    return 0;
}

// Cleanup reconnaissance context
void recon_cleanup_context(recon_context_t *ctx) {
    if (!ctx) return;

    ctx->stop_scanning = true;

    // Wait for active threads to complete
    while (atomic_load(&ctx->active_threads) > 0) {
        usleep(100000); // 100ms
    }

    pthread_mutex_destroy(&ctx->mutex);
}

// Add target to reconnaissance list
int recon_add_target(recon_target_t *target, const char *hostname, uint16_t port) {
    if (!target || !hostname) return -1;

    memset(target, 0, sizeof(recon_target_t));
    strncpy(target->hostname, hostname, RECON_MAX_DOMAIN_LEN - 1);
    target->port = port;
    target->last_scanned = 0;

    // Attempt to resolve hostname to IP
    return recon_resolve_target(target);
}

// Resolve target hostname to IP address
int recon_resolve_target(recon_target_t *target) {
    if (!target) return -1;

    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(target->hostname, NULL, &hints, &result);
    if (status != 0) {
        recon_log_error("resolve_target", target->hostname, gai_strerror(status));
        return -1;
    }

    if (result->ai_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)result->ai_addr;
        inet_ntop(AF_INET, &addr_in->sin_addr, target->ip_address, INET_ADDRSTRLEN);
        target->is_ipv6 = false;
    } else if (result->ai_family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)result->ai_addr;
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, target->ip_address, INET6_ADDRSTRLEN);
        target->is_ipv6 = true;
    } else {
        freeaddrinfo(result);
        return -1;
    }

    freeaddrinfo(result);
    return 0;
}

// Apply OPSEC delay between operations
void recon_apply_opsec_delay(const recon_opsec_config_t *config) {
    if (!config) return;

    uint32_t delay = config->min_delay_ms;
    if (config->max_delay_ms > config->min_delay_ms) {
        uint32_t range = config->max_delay_ms - config->min_delay_ms;
        delay += rand() % range;
    }

    if (config->jitter_ms > 0) {
        uint32_t jitter = rand() % config->jitter_ms;
        delay += jitter;
    }

    usleep(delay * 1000); // Convert to microseconds
}

// Calculate success rate
double recon_calculate_success_rate(const recon_context_t *ctx) {
    if (!ctx) return 0.0;

    uint32_t completed = atomic_load(&ctx->completed_scans);
    uint32_t failed = atomic_load(&ctx->failed_scans);
    uint32_t total = completed + failed;

    if (total == 0) return 0.0;

    return ((double)completed / total) * 100.0;
}

// Get average response time
uint32_t recon_get_average_response_time(const recon_context_t *ctx) {
    if (!ctx) return 0;

    uint32_t completed = atomic_load(&ctx->completed_scans);
    uint64_t total_time = atomic_load(&ctx->total_response_time);

    if (completed == 0) return 0;

    return (uint32_t)(total_time / completed);
}

// Print reconnaissance statistics
void recon_print_statistics(const recon_context_t *ctx) {
    if (!ctx) return;

    printf("\n=== Reconnaissance Statistics ===\n");
    printf("Completed Scans: %u\n", atomic_load(&ctx->completed_scans));
    printf("Failed Scans: %u\n", atomic_load(&ctx->failed_scans));
    printf("Success Rate: %.2f%%\n", recon_calculate_success_rate(ctx));
    printf("Average Response Time: %ums\n", recon_get_average_response_time(ctx));
    printf("Active Threads: %u\n", atomic_load(&ctx->active_threads));
    printf("================================\n\n");
}

// Validate target
bool recon_is_valid_target(const recon_target_t *target) {
    if (!target) return false;

    return (strlen(target->hostname) > 0 &&
            (strlen(target->ip_address) > 0 || recon_is_valid_hostname(target->hostname)));
}

// Check if hostname is valid
bool recon_is_valid_hostname(const char *hostname) {
    if (!hostname || strlen(hostname) == 0) return false;

    // Basic hostname validation
    size_t len = strlen(hostname);
    if (len > RECON_MAX_DOMAIN_LEN - 1) return false;

    for (size_t i = 0; i < len; i++) {
        char c = hostname[i];
        if (!(isalnum(c) || c == '.' || c == '-' || c == '_')) {
            return false;
        }
    }

    return true;
}

// Check if IP address is valid
bool recon_is_valid_ip(const char *ip_str) {
    if (!ip_str) return false;

    struct sockaddr_in sa4;
    struct sockaddr_in6 sa6;

    return (inet_pton(AF_INET, ip_str, &sa4.sin_addr) == 1) ||
           (inet_pton(AF_INET6, ip_str, &sa6.sin6_addr) == 1);
}

// Create socket with specified parameters
int recon_create_socket(int family, int type, int protocol) {
    int sockfd = socket(family, type, protocol);
    if (sockfd < 0) {
        recon_log_error("create_socket", "socket creation", strerror(errno));
        return -1;
    }

    return sockfd;
}

// Set socket timeout
int recon_set_socket_timeout(int sockfd, uint32_t timeout_seconds) {
    struct timeval timeout;
    timeout.tv_sec = timeout_seconds;
    timeout.tv_usec = 0;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        recon_log_error("set_socket_timeout", "SO_RCVTIMEO", strerror(errno));
        return -1;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        recon_log_error("set_socket_timeout", "SO_SNDTIMEO", strerror(errno));
        return -1;
    }

    return 0;
}

// Connect with timeout
int recon_connect_with_timeout(int sockfd, const struct sockaddr *addr, socklen_t addrlen, uint32_t timeout_seconds) {
    // Set socket to non-blocking
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0) return -1;

    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) return -1;

    int result = connect(sockfd, addr, addrlen);
    if (result == 0) {
        // Connection succeeded immediately
        fcntl(sockfd, F_SETFL, flags); // Restore blocking mode
        return 0;
    }

    if (errno != EINPROGRESS) {
        fcntl(sockfd, F_SETFL, flags);
        return -1;
    }

    // Wait for connection to complete
    fd_set write_fds;
    struct timeval timeout;

    FD_ZERO(&write_fds);
    FD_SET(sockfd, &write_fds);

    timeout.tv_sec = timeout_seconds;
    timeout.tv_usec = 0;

    result = select(sockfd + 1, NULL, &write_fds, NULL, &timeout);

    fcntl(sockfd, F_SETFL, flags); // Restore original flags

    if (result <= 0) return -1; // Timeout or error

    // Check if connection was successful
    int error;
    socklen_t error_len = sizeof(error);
    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &error_len) < 0) return -1;

    return (error == 0) ? 0 : -1;
}

// Sanitize string for safe output
void recon_sanitize_string(char *str, size_t max_len) {
    if (!str) return;

    size_t len = strnlen(str, max_len);
    for (size_t i = 0; i < len; i++) {
        if (!isprint(str[i]) || str[i] == '\n' || str[i] == '\r') {
            str[i] = '.';
        }
    }
}

// Logging functions
void recon_log_error(const char *operation, const char *target, const char *error) {
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    time_str[strlen(time_str) - 1] = '\0'; // Remove newline

    fprintf(stderr, "[%s] ERROR %s (%s): %s\n", time_str, operation, target ? target : "unknown", error);
}

void recon_log_info(const char *operation, const char *message) {
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    time_str[strlen(time_str) - 1] = '\0';

    printf("[%s] INFO %s: %s\n", time_str, operation, message);
}

void recon_log_debug(const char *operation, const char *details) {
#ifdef DEBUG
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    time_str[strlen(time_str) - 1] = '\0';

    printf("[%s] DEBUG %s: %s\n", time_str, operation, details);
#else
    (void)operation; // Suppress unused warning in non-debug builds
    (void)details;   // Suppress unused warning in non-debug builds
#endif
}

// Create thread pool
int recon_create_thread_pool(pthread_t *threads, size_t count, void *(*start_routine)(void *), void *arg) {
    if (!threads || !start_routine) return -1;

    for (size_t i = 0; i < count; i++) {
        if (pthread_create(&threads[i], NULL, start_routine, arg) != 0) {
            recon_log_error("create_thread_pool", "pthread_create", strerror(errno));
            return -1;
        }
    }

    return 0;
}

// Wait for threads to complete
void recon_wait_for_threads(pthread_t *threads, size_t count) {
    if (!threads) return;

    for (size_t i = 0; i < count; i++) {
        pthread_join(threads[i], NULL);
    }
}