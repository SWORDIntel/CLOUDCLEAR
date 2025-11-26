/*
 * CloudUnflare Enhanced - HTTP Banner Grabbing Implementation
 *
 * Advanced HTTP/HTTPS banner grabbing with SSL analysis
 * Template for C-INTERNAL agent implementation
 */

#include "http_banner.h"

// Initialize HTTP banner context
int http_banner_init_context(http_banner_context_t *ctx) {
    if (!ctx) return -1;

    memset(ctx, 0, sizeof(http_banner_context_t));

    // Initialize base reconnaissance context
    if (recon_init_context(&ctx->base_ctx, RECON_MODE_ACTIVE) != 0) {
        return -1;
    }

    // Initialize mutexes
    if (pthread_mutex_init(&ctx->results_mutex, NULL) != 0) {
        recon_cleanup_context(&ctx->base_ctx);
        return -1;
    }

    if (pthread_mutex_init(&ctx->curl_mutex, NULL) != 0) {
        pthread_mutex_destroy(&ctx->results_mutex);
        recon_cleanup_context(&ctx->base_ctx);
        return -1;
    }

    // Set default configuration
    ctx->config.default_method = HTTP_METHOD_GET;
    ctx->config.timeout_seconds = HTTP_DEFAULT_TIMEOUT;
    ctx->config.max_redirects = HTTP_MAX_REDIRECTS;
    ctx->config.analyze_ssl = true;
    ctx->config.detect_technologies = true;
    ctx->config.follow_redirects = true;
    ctx->config.verify_ssl_certs = false; // For reconnaissance

    // Initialize cURL
    curl_global_init(CURL_GLOBAL_DEFAULT);

    ctx->max_results = 100;
    ctx->results = calloc(ctx->max_results, sizeof(http_banner_result_t));
    if (!ctx->results) {
        http_banner_cleanup_context(ctx);
        return -1;
    }

    return 0;
}

// Cleanup HTTP banner context
void http_banner_cleanup_context(http_banner_context_t *ctx) {
    if (!ctx) return;

    if (ctx->results) {
        for (uint32_t i = 0; i < ctx->result_count; i++) {
            http_banner_cleanup_result(&ctx->results[i]);
        }
        free(ctx->results);
    }

    // Cleanup cURL handles
    for (int i = 0; i < RECON_MAX_THREADS; i++) {
        if (ctx->curl_handles[i]) {
            curl_easy_cleanup(ctx->curl_handles[i]);
        }
    }

    pthread_mutex_destroy(&ctx->results_mutex);
    pthread_mutex_destroy(&ctx->curl_mutex);
    recon_cleanup_context(&ctx->base_ctx);

    curl_global_cleanup();
}

// Grab banners from multiple URLs
int http_banner_grab_multiple(http_banner_context_t *ctx, const char **urls, uint32_t url_count) {
    if (!ctx || !urls) return -1;

    recon_log_info("http_banner", "Starting HTTP banner grabbing");

    int successful_grabs = 0;

    for (uint32_t i = 0; i < url_count; i++) {
        http_banner_result_t result;
        http_banner_init_result(&result);

        if (http_banner_grab_single(ctx, urls[i], &result) == 0) {
            http_banner_add_result(ctx, &result);
            successful_grabs++;
        }

        // OPSEC delay between requests
        if (i < url_count - 1) {
            usleep(ctx->config.delay_between_requests_ms * 1000);
        }
    }

    recon_log_info("http_banner", "HTTP banner grabbing completed");
    return successful_grabs;
}

// Grab banner from single URL
int http_banner_grab_single(http_banner_context_t *ctx, const char *url, http_banner_result_t *result) {
    if (!ctx || !url || !result) return -1;

    CURL *curl = NULL;
    CURLcode res;
    curl_response_data_t response_data = {0};
    struct curl_slist *headers = NULL;
    clock_t start_time, end_time;

    http_banner_init_result(result);
    strncpy(result->url, url, sizeof(result->url) - 1);
    result->method = ctx->config.default_method;
    result->timestamp = time(NULL);

    start_time = clock();

    // Create and configure cURL handle
    curl = http_banner_create_curl_handle(&ctx->config);
    if (!curl) {
        strcpy(result->error_message, "Failed to create cURL handle");
        return -1;
    }

    // Configure request
    if (http_banner_configure_request(curl, url, &ctx->config) != 0) {
        strcpy(result->error_message, "Failed to configure request");
        curl_easy_cleanup(curl);
        return -1;
    }

    // Set up response data structure
    response_data.max_size = HTTP_MAX_RESPONSE_SIZE;
    response_data.data = malloc(response_data.max_size);
    if (!response_data.data) {
        strcpy(result->error_message, "Memory allocation failed");
        curl_easy_cleanup(curl);
        return -1;
    }

    // Set callbacks
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_banner_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, http_banner_header_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &result->response);

    // Execute request
    res = curl_easy_perform(curl);
    end_time = clock();

    result->response.response_time_ms = (uint32_t)((end_time - start_time) * 1000 / CLOCKS_PER_SEC);

    if (res != CURLE_OK) {
        snprintf(result->error_message, sizeof(result->error_message),
                "cURL error: %s", curl_easy_strerror(res));
        free(response_data.data);
        curl_easy_cleanup(curl);
        return -1;
    }

    // Get response information
    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    result->response.status_code = (uint32_t)response_code;

    char *content_type;
    if (curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &content_type) == CURLE_OK && content_type) {
        strncpy(result->response.content_type, content_type, sizeof(result->response.content_type) - 1);
    }

    // Store body preview (first 1KB)
    if (response_data.size > 0) {
        size_t preview_size = (response_data.size > 1024) ? 1024 : response_data.size;
        result->response.body_preview = malloc(preview_size + 1);
        if (result->response.body_preview) {
            memcpy(result->response.body_preview, response_data.data, preview_size);
            result->response.body_preview[preview_size] = '\0';
            result->response.body_preview_size = preview_size;
        }
        result->response.content_length = response_data.size;
    }

    // Check if HTTPS and analyze SSL
    if (strncmp(url, "https://", 8) == 0) {
        result->response.has_ssl = true;

        // Extract hostname and port for SSL analysis
        char hostname[256] = {0};
        uint16_t port = 443;
        bool is_https;

        if (http_banner_parse_url(url, hostname, &port, NULL, &is_https) == 0) {
            http_banner_analyze_ssl(hostname, port, &result->response.ssl_info);
        }
    }

    // Detect technologies
    if (ctx->config.detect_technologies) {
        http_banner_detect_technologies(&result->response, result->technologies, &result->technology_count);
    }

    // Analyze security headers
    if (ctx->config.check_security_headers) {
        http_banner_analyze_security_headers(&result->response, result->security_headers, &result->security_header_count);
    }

    // Set status message based on code
    switch (result->response.status_code) {
        case 200: strcpy(result->response.status_message, "OK"); break;
        case 301: strcpy(result->response.status_message, "Moved Permanently"); break;
        case 302: strcpy(result->response.status_message, "Found"); break;
        case 400: strcpy(result->response.status_message, "Bad Request"); break;
        case 401: strcpy(result->response.status_message, "Unauthorized"); break;
        case 403: strcpy(result->response.status_message, "Forbidden"); break;
        case 404: strcpy(result->response.status_message, "Not Found"); break;
        case 500: strcpy(result->response.status_message, "Internal Server Error"); break;
        case 502: strcpy(result->response.status_message, "Bad Gateway"); break;
        case 503: strcpy(result->response.status_message, "Service Unavailable"); break;
        default: strcpy(result->response.status_message, "Unknown"); break;
    }

    result->success = (result->response.status_code >= 200 && result->response.status_code < 400);

    // Cleanup
    free(response_data.data);
    curl_easy_cleanup(curl);

    recon_log_info("http_banner", "Banner grab completed");
    return 0;
}

// Add result to context
int http_banner_add_result(http_banner_context_t *ctx, const http_banner_result_t *result) {
    if (!ctx || !result) return -1;

    pthread_mutex_lock(&ctx->results_mutex);

    if (ctx->result_count >= ctx->max_results) {
        pthread_mutex_unlock(&ctx->results_mutex);
        return -1;
    }

    ctx->results[ctx->result_count] = *result;
    ctx->result_count++;

    pthread_mutex_unlock(&ctx->results_mutex);
    return 0;
}

// Print HTTP banner summary
void http_banner_print_summary(const http_banner_context_t *ctx) {
    if (!ctx) return;

    printf("\n=== HTTP Banner Grabbing Results ===\n");
    printf("Total requests: %u\n", ctx->result_count);

    for (uint32_t i = 0; i < ctx->result_count; i++) {
        const http_banner_result_t *result = &ctx->results[i];
        printf("\nURL: %s\n", result->url);
        if (result->success) {
            printf("  Status: %u %s\n", result->response.status_code, result->response.status_message);
            printf("  Server: %s\n", result->response.server_header);
            printf("  Content-Type: %s\n", result->response.content_type);
            printf("  Response Time: %ums\n", result->response.response_time_ms);
            if (result->response.has_ssl) {
                printf("  SSL/TLS: %s\n", ssl_version_to_string(result->response.ssl_info.version));
                printf("  Cipher: %s\n", result->response.ssl_info.cipher_suite);
            }
        } else {
            printf("  Error: %s\n", result->error_message);
        }
    }
    printf("====================================\n\n");
}

// Initialize HTTP banner result
void http_banner_init_result(http_banner_result_t *result) {
    if (!result) return;
    memset(result, 0, sizeof(http_banner_result_t));
    http_banner_init_response(&result->response);
}

// Cleanup HTTP banner result
void http_banner_cleanup_result(http_banner_result_t *result) {
    if (!result) return;
    http_banner_cleanup_response(&result->response);
}

// Initialize HTTP response
void http_banner_init_response(http_response_t *response) {
    if (!response) return;
    memset(response, 0, sizeof(http_response_t));
}

// Cleanup HTTP response
void http_banner_cleanup_response(http_response_t *response) {
    if (!response) return;
    if (response->body_preview) {
        free(response->body_preview);
        response->body_preview = NULL;
    }
}

// Convert HTTP method to string
const char *http_method_to_string(http_method_t method) {
    switch (method) {
        case HTTP_METHOD_GET: return "GET";
        case HTTP_METHOD_HEAD: return "HEAD";
        case HTTP_METHOD_OPTIONS: return "OPTIONS";
        case HTTP_METHOD_POST: return "POST";
        case HTTP_METHOD_PUT: return "PUT";
        case HTTP_METHOD_DELETE: return "DELETE";
        case HTTP_METHOD_TRACE: return "TRACE";
        case HTTP_METHOD_CONNECT: return "CONNECT";
        default: return "UNKNOWN";
    }
}

// Convert SSL version to string
const char *ssl_version_to_string(ssl_version_t version) {
    switch (version) {
        case SSL_VERSION_SSLV2: return "SSLv2";
        case SSL_VERSION_SSLV3: return "SSLv3";
        case SSL_VERSION_TLSV1_0: return "TLSv1.0";
        case SSL_VERSION_TLSV1_1: return "TLSv1.1";
        case SSL_VERSION_TLSV1_2: return "TLSv1.2";
        case SSL_VERSION_TLSV1_3: return "TLSv1.3";
        default: return "Unknown";
    }
}

// C-INTERNAL Implementation: Advanced HTTP Banner Grabbing Module
// Performance target: 1500+ banner grabs/second with comprehensive analysis

// Create and configure cURL handle
CURL *http_banner_create_curl_handle(const http_banner_config_t *config) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;

    // Basic options
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, config->timeout_seconds);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, config->follow_redirects ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, config->max_redirects);

    // SSL options for reconnaissance
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, config->verify_ssl_certs ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, config->verify_ssl_certs ? 2L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_DEFAULT);

    // HTTP options with OPSEC evasion
    curl_easy_setopt(curl, CURLOPT_USERAGENT, http_banner_get_random_user_agent(config));
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "gzip, deflate");
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);

    // Security and evasion features
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, ""); // Enable cookie engine
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPIDLE, 60L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPINTVL, 30L);

    // Connection pooling for performance
    curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 0L);
    curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 0L);

    return curl;
}

// Configure HTTP request with method and headers
int http_banner_configure_request(CURL *curl, const char *url, const http_banner_config_t *config) {
    if (!curl || !url || !config) return -1;

    curl_easy_setopt(curl, CURLOPT_URL, url);

    // Set HTTP method based on configuration
    switch (config->default_method) {
        case HTTP_METHOD_GET:
            curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
            break;
        case HTTP_METHOD_HEAD:
            curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
            break;
        case HTTP_METHOD_OPTIONS:
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "OPTIONS");
            break;
        case HTTP_METHOD_POST:
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
            break;
        case HTTP_METHOD_PUT:
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
            break;
        case HTTP_METHOD_DELETE:
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
            break;
        case HTTP_METHOD_TRACE:
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "TRACE");
            break;
        case HTTP_METHOD_CONNECT:
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "CONNECT");
            break;
        default:
            curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
            break;
    }

    // Add custom headers for better fingerprinting and evasion
    http_banner_add_custom_headers(curl, config);

    return 0;
}

// cURL write callback for response body
size_t http_banner_write_callback(void *contents, size_t size, size_t nmemb, curl_response_data_t *data) {
    size_t realsize = size * nmemb;
    size_t new_size = data->size + realsize;

    if (new_size >= data->max_size) {
        // Truncate if exceeds max size to prevent memory issues
        realsize = data->max_size - data->size - 1;
        new_size = data->max_size - 1;
    }

    if (realsize > 0) {
        memcpy(data->data + data->size, contents, realsize);
        data->size = new_size;
        data->data[data->size] = '\0';
    }

    return realsize;
}

// cURL header callback for response headers
size_t http_banner_header_callback(char *buffer, size_t size, size_t nitems, http_response_t *response) {
    size_t realsize = size * nitems;
    char header_line[HTTP_MAX_HEADER_SIZE];

    if (realsize >= sizeof(header_line)) return realsize;

    strncpy(header_line, buffer, realsize);
    header_line[realsize] = '\0';

    // Remove trailing CRLF
    char *end = header_line + strlen(header_line) - 1;
    while (end > header_line && (*end == '\r' || *end == '\n')) {
        *end = '\0';
        end--;
    }

    if (strlen(header_line) == 0) return realsize;

    // Parse header name:value
    char *colon = strchr(header_line, ':');
    if (colon && response->header_count < HTTP_MAX_HEADERS) {
        *colon = '\0';
        char *name = header_line;
        char *value = colon + 1;

        // Trim whitespace from value
        while (*value == ' ' || *value == '\t') value++;

        strncpy(response->headers[response->header_count].name, name, 255);
        strncpy(response->headers[response->header_count].value, value, HTTP_MAX_HEADER_SIZE - 1);

        // Extract specific headers for quick access
        if (strcasecmp(name, "server") == 0) {
            strncpy(response->server_header, value, sizeof(response->server_header) - 1);
        }

        response->header_count++;
    }

    return realsize;
}

// Get random User-Agent for OPSEC evasion
const char *http_banner_get_random_user_agent(const http_banner_config_t *config) {
    static const char *default_user_agents[] = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
    };

    if (config->user_agent_count > 0) {
        int index = rand() % config->user_agent_count;
        return config->user_agents[index];
    }

    int index = rand() % (sizeof(default_user_agents) / sizeof(default_user_agents[0]));
    return default_user_agents[index];
}

// Add custom headers with evasion techniques
int http_banner_add_custom_headers(CURL *curl, const http_banner_config_t *config) {
    struct curl_slist *headers = NULL;

    // Add user-defined custom headers
    for (uint32_t i = 0; i < config->custom_header_count; i++) {
        headers = curl_slist_append(headers, config->custom_headers[i]);
    }

    // Add common headers for better evasion and fingerprinting
    headers = curl_slist_append(headers, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
    headers = curl_slist_append(headers, "Accept-Language: en-US,en;q=0.5");
    headers = curl_slist_append(headers, "Accept-Encoding: gzip, deflate");
    headers = curl_slist_append(headers, "DNT: 1");
    headers = curl_slist_append(headers, "Connection: keep-alive");
    headers = curl_slist_append(headers, "Upgrade-Insecure-Requests: 1");

    if (headers) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    return 0;
}

// Parse URL into components for analysis
int http_banner_parse_url(const char *url, char *hostname, uint16_t *port, char *path, bool *is_https) {
    if (!url || !hostname) return -1;

    const char *scheme_end = strstr(url, "://");
    if (!scheme_end) return -1;

    *is_https = (strncmp(url, "https", 5) == 0);
    *port = *is_https ? 443 : 80;

    const char *host_start = scheme_end + 3;
    const char *path_start = strchr(host_start, '/');
    const char *port_start = strchr(host_start, ':');

    // Extract hostname
    const char *host_end = path_start ? path_start : (port_start ? port_start : host_start + strlen(host_start));
    size_t host_len = host_end - host_start;
    strncpy(hostname, host_start, host_len);
    hostname[host_len] = '\0';

    // Extract port if specified
    if (port_start && (!path_start || port_start < path_start)) {
        *port = (uint16_t)atoi(port_start + 1);
    }

    // Extract path if needed
    if (path && path_start) {
        strcpy(path, path_start);
    } else if (path) {
        strcpy(path, "/");
    }

    return 0;
}

// Comprehensive SSL/TLS analysis
int http_banner_analyze_ssl(const char *hostname, uint16_t port, ssl_info_t *ssl_info) {
    if (!hostname || !ssl_info) return -1;

    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int sockfd = -1;
    struct sockaddr_in addr;
    struct hostent *host_entry;

    // Initialize SSL library
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Create SSL context with latest methods
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return -1;

    // Disable certificate verification for reconnaissance
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        SSL_CTX_free(ctx);
        return -1;
    }

    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Resolve hostname
    host_entry = gethostbyname(hostname);
    if (!host_entry) {
        close(sockfd);
        SSL_CTX_free(ctx);
        return -1;
    }

    // Set up address structure
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr.s_addr, host_entry->h_addr, host_entry->h_length);

    // Connect to server
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sockfd);
        SSL_CTX_free(ctx);
        return -1;
    }

    // Create SSL connection
    ssl = SSL_new(ctx);
    if (!ssl) {
        close(sockfd);
        SSL_CTX_free(ctx);
        return -1;
    }

    SSL_set_fd(ssl, sockfd);
    SSL_set_tlsext_host_name(ssl, hostname); // SNI support

    // Perform SSL handshake
    if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        return -1;
    }

    // Extract comprehensive SSL information
    ssl_info->version = http_banner_detect_ssl_version(ssl);

    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    if (cipher) {
        strncpy(ssl_info->cipher_suite, SSL_CIPHER_get_name(cipher), sizeof(ssl_info->cipher_suite) - 1);
        ssl_info->key_exchange_bits = SSL_CIPHER_get_bits(cipher, NULL);
    }

    const char *protocol = SSL_get_version(ssl);
    if (protocol) {
        strncpy(ssl_info->protocol, protocol, sizeof(ssl_info->protocol) - 1);
    }

    // Extract certificate information
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        http_banner_extract_cert_info(cert, &ssl_info->certificate);
        X509_free(cert);
    }

    // Check for SSL/TLS extensions
    ssl_info->supports_sni = true; // Assume support if we got here with SNI
    ssl_info->supports_ocsp = (SSL_get_tlsext_status_type(ssl) != -1);

    // Cleanup
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);

    return 0;
}

// Detect SSL/TLS version from connection
ssl_version_t http_banner_detect_ssl_version(SSL *ssl) {
    if (!ssl) return SSL_VERSION_UNKNOWN;

    int version = SSL_version(ssl);
    switch (version) {
        case SSL2_VERSION: return SSL_VERSION_SSLV2;
        case SSL3_VERSION: return SSL_VERSION_SSLV3;
        case TLS1_VERSION: return SSL_VERSION_TLSV1_0;
        case TLS1_1_VERSION: return SSL_VERSION_TLSV1_1;
        case TLS1_2_VERSION: return SSL_VERSION_TLSV1_2;
        case TLS1_3_VERSION: return SSL_VERSION_TLSV1_3;
        default: return SSL_VERSION_UNKNOWN;
    }
}
// Stub implementations for missing functions

int http_banner_extract_cert_info(X509 *cert, ssl_cert_info_t *cert_info) {
    if (!cert || !cert_info) return -1;
    
    // Extract basic cert info
    X509_NAME *subj = X509_get_subject_name(cert);
    if (subj) {
        X509_NAME_oneline(subj, cert_info->subject, sizeof(cert_info->subject) - 1);
    }
    
    X509_NAME *issuer = X509_get_issuer_name(cert);
    if (issuer) {
        X509_NAME_oneline(issuer, cert_info->issuer, sizeof(cert_info->issuer) - 1);
    }
    
    return 0;
}

int http_banner_analyze_security_headers(const http_response_t *response, char security_headers[][256], uint32_t *header_count) {
    if (!response || !security_headers || !header_count) return -1;
    
    *header_count = 0;
    
    // Analyze common security headers
    if (strstr(response->headers, "Strict-Transport-Security")) {
        snprintf(security_headers[(*header_count)++], 256, "HSTS: Enabled");
    }
    if (strstr(response->headers, "Content-Security-Policy")) {
        snprintf(security_headers[(*header_count)++], 256, "CSP: Enabled");
    }
    if (strstr(response->headers, "X-Frame-Options")) {
        snprintf(security_headers[(*header_count)++], 256, "X-Frame-Options: Enabled");
    }
    
    return 0;
}

int http_banner_detect_technologies(const http_response_t *response, technology_detection_t *technologies, uint32_t *tech_count) {
    if (!response || !technologies || !tech_count) return -1;
    
    *tech_count = 0;
    
    // Simple technology detection based on headers
    if (strstr(response->headers, "X-Powered-By")) {
        *tech_count = 1;
        strncpy(technologies[0].technology, "Unknown", sizeof(technologies[0].technology) - 1);
        strncpy(technologies[0].version, "Unknown", sizeof(technologies[0].version) - 1);
    }
    
    return 0;
}
