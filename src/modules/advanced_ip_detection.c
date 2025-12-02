/*
 * Advanced IP Detection Module - Implementation
 * Comprehensive techniques to discover origin IPs behind Cloudflare/CDNs
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "platform_compat.h"
#ifdef _WIN32
    /* arpa/nameser.h compatibility provided by platform_compat.h */
#else
    #include <arpa/nameser.h>
    #include <resolv.h>
#endif
#include <curl/curl.h>

// NI_NAMEFQDN is BSD-specific, not available on all Linux systems
#ifndef NI_NAMEFQDN
#define NI_NAMEFQDN 0
#endif
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <pthread.h>
#include "advanced_ip_detection.h"

// HTTP response callback
struct http_response_buffer {
    char *data;
    size_t size;
};

static size_t http_write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t real_size = size * nmemb;
    struct http_response_buffer *mem = (struct http_response_buffer *)userp;

    char *ptr = realloc(mem->data, mem->size + real_size + 1);
    if(!ptr) return 0;

    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, real_size);
    mem->size += real_size;
    mem->data[mem->size] = 0;

    return real_size;
}

// Initialize detection result structure
static int init_detection_result(struct advanced_ip_detection_result *result, const char *domain) {
    memset(result, 0, sizeof(struct advanced_ip_detection_result));
    strncpy(result->target_domain, domain, sizeof(result->target_domain) - 1);

    pthread_mutex_init(&result->candidates_mutex, NULL);
    atomic_store(&result->candidate_capacity, 32);
    result->candidates = calloc(32, sizeof(struct origin_ip_candidate));

    result->scan_timestamp = time(NULL);

    return (result->candidates != NULL) ? 0 : -1;
}

// SSL Certificate extraction from connection
int extract_ssl_certificate_info(SSL *ssl, struct ssl_certificate_info *cert_info) {
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) return -1;

    memset(cert_info, 0, sizeof(struct ssl_certificate_info));

    // Get subject
    X509_NAME *subject = X509_get_subject_name(cert);
    X509_NAME_oneline(subject, cert_info->subject, sizeof(cert_info->subject));

    // Get issuer
    X509_NAME *issuer = X509_get_issuer_name(cert);
    X509_NAME_oneline(issuer, cert_info->issuer, sizeof(cert_info->issuer));

    // Get Common Name
    X509_NAME_get_text_by_NID(subject, NID_commonName,
                             cert_info->common_name,
                             sizeof(cert_info->common_name));

    // Check for wildcard
    cert_info->is_wildcard = (cert_info->common_name[0] == '*');

    // Get validity dates
    ASN1_TIME *not_before = X509_get_notBefore(cert);
    ASN1_TIME *not_after = X509_get_notAfter(cert);
    (void)not_before; // Reserved for future certificate validation
    (void)not_after;  // Reserved for future certificate validation

    // Get Serial Number
    ASN1_INTEGER *serial = X509_get_serialNumber(cert);
    BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
    if (bn) {
        char *serial_str = BN_bn2hex(bn);
        if (serial_str) {
            strncpy(cert_info->serial_number, serial_str, sizeof(cert_info->serial_number) - 1);
            OPENSSL_free(serial_str);
        }
        BN_free(bn);
    }

    // Get Subject Alternative Names (SANs)
    STACK_OF(GENERAL_NAME) *san_names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (san_names) {
        int san_count = sk_GENERAL_NAME_num(san_names);
        cert_info->san_entries = calloc(san_count, sizeof(char*));
        cert_info->san_count = 0;

        for (int i = 0; i < san_count; i++) {
            GENERAL_NAME *gen = sk_GENERAL_NAME_value(san_names, i);
            if (gen->type == GEN_DNS) {
                ASN1_STRING *asn1_str = gen->d.dNSName;
                const char *san_str = (const char *)ASN1_STRING_get0_data(asn1_str);
                cert_info->san_entries[cert_info->san_count++] = strdup(san_str);
            }
        }
        sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
    }

    // Check if self-signed
    cert_info->self_signed = (X509_check_issued(cert, cert) == X509_V_OK);

    X509_free(cert);
    return 0;
}

// Test direct IP connection with SSL certificate matching
int test_direct_ip_connection(const char *ip_address, const char *domain,
                             struct ssl_certificate_info *cert_info) {
    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd;
    struct sockaddr_in addr;

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return -1;

    // Disable certificate verification for testing
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        SSL_CTX_free(ctx);
        return -1;
    }

    // Set connection timeout
    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    // Connect to IP on port 443
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    if (inet_pton(AF_INET, ip_address, &addr.sin_addr) <= 0) {
        close(sockfd);
        SSL_CTX_free(ctx);
        return -1;
    }

    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sockfd);
        SSL_CTX_free(ctx);
        return -1;
    }

    // Create SSL connection
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    SSL_set_tlsext_host_name(ssl, domain);  // SNI

    if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        return -1;
    }

    // Extract certificate information
    int result = extract_ssl_certificate_info(ssl, cert_info);

    // Cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);

    return result;
}

// Compare two SSL certificates for similarity
int compare_ssl_certificates(struct ssl_certificate_info *cert1,
                            struct ssl_certificate_info *cert2,
                            float *similarity_score) {
    *similarity_score = 0.0f;
    int matches = 0;
    int total_checks = 0;

    // Compare Common Name
    total_checks++;
    if (strcmp(cert1->common_name, cert2->common_name) == 0) {
        matches++;
    } else if (cert1->is_wildcard || cert2->is_wildcard) {
        // Wildcard matching
        const char *wildcard = cert1->is_wildcard ? cert1->common_name : cert2->common_name;
        const char *specific = cert1->is_wildcard ? cert2->common_name : cert1->common_name;
        if (strstr(specific, wildcard + 2) != NULL) {  // Skip "*."
            matches++;
        }
    }

    // Compare Issuer
    total_checks++;
    if (strcmp(cert1->issuer, cert2->issuer) == 0) {
        matches++;
    }

    // Compare Serial Number
    total_checks++;
    if (strcmp(cert1->serial_number, cert2->serial_number) == 0) {
        matches += 2;  // Serial match is strong evidence
        total_checks++;
    }

    // Compare SANs
    for (int i = 0; i < cert1->san_count; i++) {
        for (int j = 0; j < cert2->san_count; j++) {
            total_checks++;
            if (strcmp(cert1->san_entries[i], cert2->san_entries[j]) == 0) {
                matches++;
            }
        }
    }

    if (total_checks > 0) {
        *similarity_score = (float)matches / (float)total_checks;
    }

    return 0;
}

// Add origin candidate (thread-safe)
int add_origin_candidate(struct advanced_ip_detection_result *result,
                        const char *ip_address,
                        const char *discovery_method,
                        float confidence) {
    pthread_mutex_lock(&result->candidates_mutex);

    // Check if candidate already exists
    for (int i = 0; i < result->candidate_count; i++) {
        if (strcmp(result->candidates[i].ip_address, ip_address) == 0) {
            // Update existing candidate
            if (confidence > result->candidates[i].confidence_score) {
                result->candidates[i].confidence_score = confidence;
            }
            // Add discovery method as evidence
            result->candidates[i].evidence_count++;
            result->candidates[i].supporting_evidence = realloc(
                result->candidates[i].supporting_evidence,
                result->candidates[i].evidence_count * sizeof(char*)
            );
            result->candidates[i].supporting_evidence[result->candidates[i].evidence_count - 1] =
                strdup(discovery_method);
            pthread_mutex_unlock(&result->candidates_mutex);
            return 0;
        }
    }

    // Check capacity
    if (result->candidate_count >= atomic_load(&result->candidate_capacity)) {
        int new_capacity = atomic_load(&result->candidate_capacity) * 2;
        struct origin_ip_candidate *new_candidates = realloc(
            result->candidates,
            new_capacity * sizeof(struct origin_ip_candidate)
        );
        if (!new_candidates) {
            pthread_mutex_unlock(&result->candidates_mutex);
            return -1;
        }
        result->candidates = new_candidates;
        atomic_store(&result->candidate_capacity, new_capacity);
    }

    // Add new candidate
    struct origin_ip_candidate *candidate = &result->candidates[result->candidate_count];
    memset(candidate, 0, sizeof(struct origin_ip_candidate));

    strncpy(candidate->ip_address, ip_address, sizeof(candidate->ip_address) - 1);
    strncpy(candidate->discovery_method, discovery_method, sizeof(candidate->discovery_method) - 1);
    candidate->confidence_score = confidence;
    candidate->discovered_at = time(NULL);
    candidate->evidence_count = 1;
    candidate->supporting_evidence = calloc(1, sizeof(char*));
    candidate->supporting_evidence[0] = strdup(discovery_method);

    result->candidate_count++;

    pthread_mutex_unlock(&result->candidates_mutex);
    return 0;
}

// Enumerate MX records for mail server analysis
int enumerate_mx_records(const char *domain, struct mx_record_info **mx_records, int *count) {
    unsigned char response[4096];
    ns_msg handle;
    ns_rr rr;
    int response_len;

    response_len = res_query(domain, ns_c_in, ns_t_mx, response, sizeof(response));
    if (response_len < 0) {
        return -1;
    }

    if (ns_initparse(response, response_len, &handle) < 0) {
        return -1;
    }

    int mx_count = ns_msg_count(handle, ns_s_an);
    if (mx_count <= 0) {
        return 0;
    }

    *mx_records = calloc(mx_count, sizeof(struct mx_record_info));
    *count = 0;

    for (int i = 0; i < mx_count; i++) {
        if (ns_parserr(&handle, ns_s_an, i, &rr) < 0) {
            continue;
        }

        if (ns_rr_type(rr) == ns_t_mx) {
            struct mx_record_info *mx = &(*mx_records)[*count];

            // Get MX priority (first 2 bytes of RDATA)
            const unsigned char *rdata = ns_rr_rdata(rr);
            mx->priority = ns_get16(rdata);

            // Get MX hostname
            char hostname[256];
            if (dn_expand(response, response + response_len, rdata + 2,
                         hostname, sizeof(hostname)) >= 0) {
                strncpy(mx->hostname, hostname, sizeof(mx->hostname) - 1);
                mx->hostname[sizeof(mx->hostname) - 1] = '\0';

                // Resolve MX hostname to IPs
                struct addrinfo hints, *res, *p;
                memset(&hints, 0, sizeof(hints));
                hints.ai_family = AF_INET;
                hints.ai_socktype = SOCK_STREAM;

                if (getaddrinfo(hostname, NULL, &hints, &res) == 0) {
                    mx->ip_count = 0;
                    for (p = res; p != NULL && mx->ip_count < 8; p = p->ai_next) {
                        struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
                        inet_ntop(AF_INET, &(ipv4->sin_addr),
                                 mx->ip_addresses[mx->ip_count],
                                 INET_ADDRSTRLEN);
                        mx->ip_count++;
                    }
                    freeaddrinfo(res);
                }

                (*count)++;
            }
        }
    }

    return *count;
}

// Analyze mail server infrastructure
int analyze_mail_server_infrastructure(const char *domain,
                                      struct advanced_ip_detection_result *result) {
    printf("\n[MX ANALYSIS] Enumerating mail servers for %s\n", domain);

    struct mx_record_info *mx_records = NULL;
    int mx_count = 0;

    if (enumerate_mx_records(domain, &mx_records, &mx_count) < 0) {
        printf("   [-] No MX records found\n");
        return -1;
    }

    printf("   [+] Found %d MX record(s)\n", mx_count);

    for (int i = 0; i < mx_count; i++) {
        struct mx_record_info *mx = &mx_records[i];
        printf("   [+] MX: %s (priority %d)\n", mx->hostname, mx->priority);

        for (int j = 0; j < mx->ip_count; j++) {
            printf("      -> IP: %s\n", mx->ip_addresses[j]);

            // Perform reverse DNS lookup
            struct sockaddr_in sa;
            sa.sin_family = AF_INET;
            inet_pton(AF_INET, mx->ip_addresses[j], &sa.sin_addr);

            char hostname[NI_MAXHOST];
            if (getnameinfo((struct sockaddr *)&sa, sizeof(sa),
                          hostname, sizeof(hostname), NULL, 0, NI_NAMEFQDN) == 0) {
                printf("      -> PTR: %s\n", hostname);

                if (mx->reverse_dns_count < 8) {
                    snprintf(mx->reverse_dns[mx->reverse_dns_count], 256, "%s", hostname);
                    mx->reverse_dns_count++;
                }

                // Check if PTR contains original domain
                if (strstr(hostname, domain) != NULL) {
                    printf("      -> [!] PTR matches target domain - likely same infrastructure\n");
                    mx->likely_origin_network = true;

                    // Add as origin candidate with high confidence
                    add_origin_candidate(result, mx->ip_addresses[j],
                                       "MX Record PTR Match", 0.85f);
                }
            }

            // Add as candidate with medium confidence
            add_origin_candidate(result, mx->ip_addresses[j],
                               "MX Record Analysis", 0.65f);
        }
    }

    result->mx_records = mx_records;
    result->mx_record_count = mx_count;

    return mx_count;
}

// Get list of common SRV services to check
const char** get_common_srv_services(int *count) {
    static const char *services[] = {
        "_sip._tcp",
        "_sip._udp",
        "_sips._tcp",
        "_xmpp-client._tcp",
        "_xmpp-server._tcp",
        "_jabber._tcp",
        "_ldap._tcp",
        "_ldaps._tcp",
        "_kerberos._tcp",
        "_kerberos._udp",
        "_kpasswd._tcp",
        "_caldav._tcp",
        "_carddav._tcp",
        "_imap._tcp",
        "_imaps._tcp",
        "_submission._tcp",
        "_autodiscover._tcp",
        "_mssql._tcp",
        "_mongodb._tcp",
        "_mysql._tcp"
    };

    *count = sizeof(services) / sizeof(services[0]);
    return services;
}

// Discover SRV records
int discover_srv_records(const char *domain, struct srv_record_info **srv_records, int *count) {
    int service_count;
    const char **services = get_common_srv_services(&service_count);

    *srv_records = calloc(service_count, sizeof(struct srv_record_info));
    *count = 0;

    for (int i = 0; i < service_count; i++) {
        char query[512];
        snprintf(query, sizeof(query), "%s.%s", services[i], domain);

        unsigned char response[4096];
        int response_len = res_query(query, ns_c_in, ns_t_srv, response, sizeof(response));

        if (response_len > 0) {
            ns_msg handle;
            if (ns_initparse(response, response_len, &handle) >= 0) {
                int answer_count = ns_msg_count(handle, ns_s_an);

                if (answer_count > 0) {
                    ns_rr rr;
                    if (ns_parserr(&handle, ns_s_an, 0, &rr) >= 0) {
                        if (ns_rr_type(rr) == ns_t_srv) {
                            struct srv_record_info *srv = &(*srv_records)[*count];
                            strncpy(srv->service_name, services[i], sizeof(srv->service_name) - 1);

                            const unsigned char *rdata = ns_rr_rdata(rr);
                            srv->priority = ns_get16(rdata);
                            srv->weight = ns_get16(rdata + 2);
                            srv->port = ns_get16(rdata + 4);

                            char target[256];
                            if (dn_expand(response, response + response_len, rdata + 6,
                                        target, sizeof(target)) >= 0) {
                                strncpy(srv->target_host, target, sizeof(srv->target_host) - 1);
                                srv->target_host[sizeof(srv->target_host) - 1] = '\0';
                                (*count)++;
                            }
                        }
                    }
                }
            }
        }
    }

    return *count;
}

// Analyze HTTP headers for CDN/origin detection
int analyze_http_headers(const char *domain, struct http_header_analysis *analysis) {
    CURL *curl;
    CURLcode res;
    struct http_response_buffer response = {0};
    char url[512];

    memset(analysis, 0, sizeof(struct http_header_analysis));

    curl = curl_easy_init();
    if (!curl) return -1;

    snprintf(url, sizeof(url), "https://%s", domain);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_HEADER, 1L);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);  // HEAD request
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

    res = curl_easy_perform(curl);

    if (res == CURLE_OK && response.data) {
        // Parse headers
        char *line = strtok(response.data, "\r\n");
        while (line != NULL) {
            if (strncasecmp(line, "Server:", 7) == 0) {
                sscanf(line, "Server: %255[^\r\n]", analysis->server_header);
            } else if (strncasecmp(line, "X-Powered-By:", 13) == 0) {
                sscanf(line, "X-Powered-By: %255[^\r\n]", analysis->x_powered_by);
            } else if (strncasecmp(line, "Via:", 4) == 0) {
                sscanf(line, "Via: %255[^\r\n]", analysis->via_header);
            } else if (strncasecmp(line, "CF-RAY:", 7) == 0) {
                sscanf(line, "CF-RAY: %63[^\r\n]", analysis->cf_ray);
                analysis->behind_cloudflare = true;
                strcpy(analysis->cdn_provider, "Cloudflare");
            }

            line = strtok(NULL, "\r\n");
        }

        free(response.data);
    }

    curl_easy_cleanup(curl);
    return 0;
}

// Detect Cloudflare-specific bypass opportunities
int detect_cloudflare_bypass_subdomains(const char *domain,
                                       struct cloudflare_bypass_info *bypass_info) {
    printf("\n[CF BYPASS] Detecting Cloudflare bypass opportunities for %s\n", domain);

    // Common subdomains that might bypass Cloudflare
    const char *bypass_candidates[] = {
        "direct", "origin", "backend", "internal", "admin", "api", "dev",
        "staging", "test", "vpn", "intranet", "cpanel", "webmail",
        "mail", "ftp", "ns1", "ns2", "mysql", "db"
    };

    int candidate_count = sizeof(bypass_candidates) / sizeof(bypass_candidates[0]);
    bypass_info->bypass_subdomain_count = 0;

    for (int i = 0; i < candidate_count && bypass_info->bypass_subdomain_count < 16; i++) {
        char subdomain[256];
        snprintf(subdomain, sizeof(subdomain), "%s.%s", bypass_candidates[i], domain);

        // Try to resolve subdomain
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(subdomain, NULL, &hints, &res) == 0) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, INET_ADDRSTRLEN);

            // Check if IP is in Cloudflare range
            if (!is_ip_in_cloudflare_range(ip_str)) {
                printf("   [+] Potential bypass subdomain: %s -> %s\n", subdomain, ip_str);
                snprintf(bypass_info->bypass_subdomains[bypass_info->bypass_subdomain_count],
                       256, "%s", subdomain);
                bypass_info->bypass_subdomain_count++;

                // Add to origin IPs
                bool ip_exists = false;
                for (int j = 0; j < bypass_info->origin_ip_count; j++) {
                    if (strcmp(bypass_info->origin_ips[j], ip_str) == 0) {
                        ip_exists = true;
                        break;
                    }
                }
                if (!ip_exists && bypass_info->origin_ip_count < 8) {
                    snprintf(bypass_info->origin_ips[bypass_info->origin_ip_count],
                           INET_ADDRSTRLEN, "%s", ip_str);
                    bypass_info->origin_ip_count++;
                }
            }

            freeaddrinfo(res);
        }
    }

    if (bypass_info->bypass_subdomain_count > 0) {
        bypass_info->direct_connect_possible = true;
        snprintf(bypass_info->suggested_techniques, sizeof(bypass_info->suggested_techniques),
                "Found %d potential bypass subdomain(s). Try connecting directly to these IPs with Host header set to target domain.",
                bypass_info->bypass_subdomain_count);
    }

    return bypass_info->bypass_subdomain_count;
}

// Check if IP is in Cloudflare range
bool is_ip_in_cloudflare_range(const char *ip_address) {
    // Cloudflare IPv4 ranges (sample - not exhaustive)
    const char *cf_ranges[] = {
        "103.21.244.", "103.22.200.", "103.31.4.", "104.16.",
        "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
        "104.22.", "104.23.", "104.24.", "104.25.", "104.26.",
        "104.27.", "104.28.", "108.162.", "131.0.72.", "141.101.",
        "162.158.", "162.159.", "172.64.", "172.65.", "172.66.",
        "172.67.", "173.245.", "188.114.", "190.93.", "197.234.",
        "198.41."
    };

    int range_count = sizeof(cf_ranges) / sizeof(cf_ranges[0]);

    for (int i = 0; i < range_count; i++) {
        if (strncmp(ip_address, cf_ranges[i], strlen(cf_ranges[i])) == 0) {
            return true;
        }
    }

    return false;
}

// Main advanced IP detection function
int perform_advanced_ip_detection(const char *domain,
                                 struct advanced_ip_detection_result *result) {
    printf("\n=== Advanced IP Detection Started ===\n");
    printf("Target: %s\n", domain);

    init_detection_result(result, domain);

    // Technique 1: HTTP Header Analysis
    printf("\n[1/8] HTTP Header Analysis\n");
    analyze_http_headers(domain, &result->header_analysis);
    if (result->header_analysis.behind_cloudflare) {
        printf("   [!] Target is behind Cloudflare\n");
    }
    result->total_techniques_attempted++;

    // Technique 2: MX Record Analysis
    printf("\n[2/8] Mail Server Infrastructure Analysis\n");
    if (analyze_mail_server_infrastructure(domain, result) > 0) {
        printf("   [+] Mail server analysis completed successfully\n");
        result->successful_techniques++;
    }
    result->total_techniques_attempted++;

    // Technique 3: SRV Record Discovery
    printf("\n[3/8] SRV Record Discovery\n");
    struct srv_record_info *srv_records = NULL;
    int srv_count = 0;
    if (discover_srv_records(domain, &srv_records, &srv_count) > 0) {
        printf("   [+] Found %d SRV record(s)\n", srv_count);
        result->srv_records = srv_records;
        result->srv_record_count = srv_count;

        for (int i = 0; i < srv_count; i++) {
            printf("   [+] Service: %s -> %s:%d\n",
                   srv_records[i].service_name,
                   srv_records[i].target_host,
                   srv_records[i].port);

            // Resolve SRV target to IPs
            struct addrinfo hints, *res, *p;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;

            if (getaddrinfo(srv_records[i].target_host, NULL, &hints, &res) == 0) {
                srv_records[i].ip_count = 0;
                for (p = res; p != NULL && srv_records[i].ip_count < 4; p = p->ai_next) {
                    struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
                    inet_ntop(AF_INET, &(ipv4->sin_addr),
                             srv_records[i].ip_addresses[srv_records[i].ip_count],
                             INET_ADDRSTRLEN);
                    printf("      -> IP: %s\n", srv_records[i].ip_addresses[srv_records[i].ip_count]);

                    add_origin_candidate(result, srv_records[i].ip_addresses[srv_records[i].ip_count],
                                       "SRV Record Discovery", 0.70f);

                    srv_records[i].ip_count++;
                }
                freeaddrinfo(res);
            }
        }
        result->successful_techniques++;
    }
    result->total_techniques_attempted++;

    // Technique 4: Cloudflare Bypass Detection
    printf("\n[4/8] Cloudflare Bypass Subdomain Detection\n");
    if (detect_cloudflare_bypass_subdomains(domain, &result->cloudflare_bypass) > 0) {
        printf("   [+] Found potential bypass subdomains\n");
        for (int i = 0; i < result->cloudflare_bypass.origin_ip_count; i++) {
            add_origin_candidate(result, result->cloudflare_bypass.origin_ips[i],
                               "Cloudflare Bypass Subdomain", 0.80f);
        }
        result->successful_techniques++;
    }
    result->total_techniques_attempted++;

    // Technique 5: SSL Certificate Comparison (on discovered IPs)
    printf("\n[5/8] SSL Certificate Comparison (on discovered IPs)\n");
    printf("   [*] Testing %d candidate IPs for SSL certificate match\n", result->candidate_count);

    struct ssl_certificate_info domain_cert;
    if (test_direct_ip_connection(domain, domain, &domain_cert) == 0) {
        printf("   [+] Retrieved SSL certificate from domain\n");

        for (int i = 0; i < result->candidate_count; i++) {
            struct ssl_certificate_info candidate_cert;
            printf("   [*] Testing IP: %s\n", result->candidates[i].ip_address);

            if (test_direct_ip_connection(result->candidates[i].ip_address, domain, &candidate_cert) == 0) {
                float similarity = 0.0f;
                compare_ssl_certificates(&domain_cert, &candidate_cert, &similarity);

                printf("      -> SSL Certificate Match: %.2f%%\n", similarity * 100);

                if (similarity > 0.7f) {
                    result->candidates[i].confidence_score += 0.3f;  // Boost confidence
                    printf("      -> [!] High SSL match - likely origin server!\n");
                }

                cleanup_ssl_certificate_info(&candidate_cert);
            }
        }
        cleanup_ssl_certificate_info(&domain_cert);
        result->successful_techniques++;
    }
    result->total_techniques_attempted++;

    // Technique 6: Reverse DNS (PTR) Analysis
    printf("\n[6/8] Reverse DNS Intelligence\n");
    if (analyze_ptr_records(result) == 0) {
        printf("   [+] PTR record analysis completed\n");
        result->successful_techniques++;
    }
    result->total_techniques_attempted++;

    // Technique 7: ASN/Network Clustering
    printf("\n[7/8] ASN Network Infrastructure Clustering\n");
    if (cluster_ips_by_asn(result) > 0) {
        printf("   [+] ASN clustering completed successfully\n");
        result->successful_techniques++;
    }
    result->total_techniques_attempted++;

    // Technique 8: Passive DNS Historical Data
    printf("\n[8/8] Passive DNS Historical Records\n");
    struct passive_dns_record *pdns_records = NULL;
    int pdns_count = 0;
    query_passive_dns_historical(domain, &pdns_records, &pdns_count);
    result->passive_dns_records = pdns_records;
    result->passive_dns_count = pdns_count;
    result->total_techniques_attempted++;
    if (pdns_count > 0) {
        result->successful_techniques++;
    }

    // Rank candidates by confidence
    rank_origin_ip_candidates(result);

    printf("\n=== Advanced IP Detection Completed ===\n");
    printf("Techniques attempted: %d\n", result->total_techniques_attempted);
    printf("Successful techniques: %d\n", result->successful_techniques);
    printf("Origin IP candidates found: %d\n", result->candidate_count);

    return result->candidate_count;
}

// Rank origin IP candidates by confidence
void rank_origin_ip_candidates(struct advanced_ip_detection_result *result) {
    // Simple bubble sort by confidence score
    for (int i = 0; i < result->candidate_count - 1; i++) {
        for (int j = 0; j < result->candidate_count - i - 1; j++) {
            if (result->candidates[j].confidence_score < result->candidates[j + 1].confidence_score) {
                struct origin_ip_candidate temp = result->candidates[j];
                result->candidates[j] = result->candidates[j + 1];
                result->candidates[j + 1] = temp;
            }
        }
    }

    // Set most likely origin IP
    if (result->candidate_count > 0) {
        strncpy(result->most_likely_origin_ip,
               result->candidates[0].ip_address,
               sizeof(result->most_likely_origin_ip) - 1);
        result->most_likely_origin_ip[sizeof(result->most_likely_origin_ip) - 1] = '\0';
        result->origin_ip_confidence = result->candidates[0].confidence_score;
    }
}

// Print detection results
void print_advanced_detection_results(struct advanced_ip_detection_result *result) {
    printf("\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("           ADVANCED IP DETECTION RESULTS                       \n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("Target Domain: %s\n", result->target_domain);
    printf("Scan Timestamp: %s", ctime(&result->scan_timestamp));
    printf("───────────────────────────────────────────────────────────────\n");

    if (result->header_analysis.behind_cloudflare) {
        printf("\n[CDN DETECTION]\n");
        printf("   Provider: %s\n", result->header_analysis.cdn_provider);
        printf("   CF-RAY: %s\n", result->header_analysis.cf_ray);
    }

    printf("\n[ORIGIN IP CANDIDATES] (Ranked by Confidence)\n");
    printf("───────────────────────────────────────────────────────────────\n");

    for (int i = 0; i < result->candidate_count && i < 10; i++) {
        struct origin_ip_candidate *c = &result->candidates[i];
        printf("\n%d. IP Address: %s\n", i + 1, c->ip_address);
        printf("   Confidence: %.2f%%\n", c->confidence_score * 100);
        printf("   Discovery Method: %s\n", c->discovery_method);
        printf("   Evidence Count: %d\n", c->evidence_count);

        if (c->asn > 0) {
            printf("   ASN: AS%u (%s)\n", c->asn, c->asn_name);
        }
        if (strlen(c->hosting_provider) > 0) {
            printf("   Hosting: %s\n", c->hosting_provider);
        }

        printf("   Supporting Evidence:\n");
        for (int j = 0; j < c->evidence_count; j++) {
            printf("      - %s\n", c->supporting_evidence[j]);
        }
    }

    if (result->candidate_count > 0) {
        printf("\n───────────────────────────────────────────────────────────────\n");
        printf("[MOST LIKELY ORIGIN IP]\n");
        printf("   %s (Confidence: %.2f%%)\n",
               result->most_likely_origin_ip,
               result->origin_ip_confidence * 100);
    }

    if (result->cloudflare_bypass.bypass_subdomain_count > 0) {
        printf("\n───────────────────────────────────────────────────────────────\n");
        printf("[CLOUDFLARE BYPASS OPPORTUNITIES]\n");
        for (int i = 0; i < result->cloudflare_bypass.bypass_subdomain_count; i++) {
            printf("   - %s\n", result->cloudflare_bypass.bypass_subdomains[i]);
        }
    }

    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("Success Rate: %d/%d techniques successful\n",
           result->successful_techniques, result->total_techniques_attempted);
    printf("═══════════════════════════════════════════════════════════════\n");
}

// Perform reverse DNS lookup
int perform_reverse_dns_lookup(const char *ip_address, char *hostname, size_t hostname_size) {
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;

    if (inet_pton(AF_INET, ip_address, &sa.sin_addr) <= 0) {
        return -1;
    }

    if (getnameinfo((struct sockaddr *)&sa, sizeof(sa),
                   hostname, hostname_size, NULL, 0, NI_NAMEFQDN) == 0) {
        return 0;
    }

    return -1;
}

// Analyze PTR records for all candidates
int analyze_ptr_records(struct advanced_ip_detection_result *result) {
    printf("\n[PTR ANALYSIS] Analyzing reverse DNS records\n");

    for (int i = 0; i < result->candidate_count; i++) {
        char hostname[256];
        if (perform_reverse_dns_lookup(result->candidates[i].ip_address,
                                      hostname, sizeof(hostname)) == 0) {
            printf("   [+] %s -> %s\n", result->candidates[i].ip_address, hostname);

            // Check if PTR contains target domain
            if (strstr(hostname, result->target_domain) != NULL) {
                printf("      -> [!] PTR matches target domain!\n");
                result->candidates[i].confidence_score += 0.15f;  // Boost confidence
            }

            // Check if PTR indicates origin server
            if (strstr(hostname, "origin") != NULL ||
                strstr(hostname, "direct") != NULL ||
                strstr(hostname, "backend") != NULL) {
                printf("      -> [!] PTR suggests origin server!\n");
                result->candidates[i].confidence_score += 0.10f;
            }
        }
    }

    return 0;
}

// Query ASN information for IP
int query_asn_information(const char *ip_address, struct asn_network_info *asn_info) {
    // Use cymru.com DNS-based ASN lookup
    // Format: reverse IP + .origin.asn.cymru.com
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_address, &addr) <= 0) {
        return -1;
    }

    // Reverse the IP octets
    unsigned char *bytes = (unsigned char *)&addr.s_addr;
    char query[256];
    snprintf(query, sizeof(query), "%u.%u.%u.%u.origin.asn.cymru.com",
            bytes[3], bytes[2], bytes[1], bytes[0]);

    // Query TXT record
    unsigned char response[4096];
    int response_len = res_query(query, ns_c_in, ns_t_txt, response, sizeof(response));

    if (response_len < 0) {
        return -1;
    }

    ns_msg handle;
    if (ns_initparse(response, response_len, &handle) < 0) {
        return -1;
    }

    int answer_count = ns_msg_count(handle, ns_s_an);
    if (answer_count > 0) {
        ns_rr rr;
        if (ns_parserr(&handle, ns_s_an, 0, &rr) >= 0) {
            if (ns_rr_type(rr) == ns_t_txt) {
                const unsigned char *rdata = ns_rr_rdata(rr);
                int txt_len = rdata[0];
                char txt_data[256];
                memcpy(txt_data, rdata + 1, txt_len);
                txt_data[txt_len] = '\0';

                // Parse: "ASN | IP | BGP Prefix | CC | Registry | Allocated Date | AS Name"
                char *token = strtok(txt_data, "|");
                if (token) {
                    asn_info->asn = atoi(token);
                    token = strtok(NULL, "|");  // Skip IP
                    token = strtok(NULL, "|");  // BGP Prefix
                    if (token) {
                        strncpy(asn_info->ip_range, token, sizeof(asn_info->ip_range) - 1);
                    }
                    token = strtok(NULL, "|");  // Country
                    if (token) {
                        strncpy(asn_info->country, token, sizeof(asn_info->country) - 1);
                    }
                }

                // Query AS name separately
                snprintf(query, sizeof(query), "AS%u.asn.cymru.com", asn_info->asn);
                response_len = res_query(query, ns_c_in, ns_t_txt, response, sizeof(response));
                if (response_len > 0 && ns_initparse(response, response_len, &handle) >= 0) {
                    if (ns_parserr(&handle, ns_s_an, 0, &rr) >= 0 && ns_rr_type(rr) == ns_t_txt) {
                        rdata = ns_rr_rdata(rr);
                        txt_len = rdata[0];
                        if ((size_t)txt_len < sizeof(asn_info->asn_name)) {
                            memcpy(asn_info->asn_name, rdata + 1, txt_len);
                            asn_info->asn_name[txt_len] = '\0';
                        }
                    }
                }

                return 0;
            }
        }
    }

    return -1;
}

// Cluster IPs by ASN
int cluster_ips_by_asn(struct advanced_ip_detection_result *result) {
    printf("\n[ASN CLUSTERING] Analyzing network infrastructure\n");

    // Allocate ASN info array
    result->asn_networks = calloc(result->candidate_count, sizeof(struct asn_network_info));
    result->asn_network_count = 0;

    for (int i = 0; i < result->candidate_count; i++) {
        struct asn_network_info asn_info = {0};

        if (query_asn_information(result->candidates[i].ip_address, &asn_info) == 0) {
            printf("   [+] %s -> AS%u (%s) [%s]\n",
                   result->candidates[i].ip_address,
                   asn_info.asn,
                   asn_info.asn_name,
                   asn_info.ip_range);

            // Store in candidate
            result->candidates[i].asn = asn_info.asn;
            snprintf(result->candidates[i].asn_name,
                   sizeof(result->candidates[i].asn_name), "%s", asn_info.asn_name);

            // Check if ASN already exists in network list
            bool asn_exists = false;
            for (int j = 0; j < result->asn_network_count; j++) {
                if (result->asn_networks[j].asn == asn_info.asn) {
                    result->asn_networks[j].discovered_ip_count++;
                    asn_exists = true;
                    break;
                }
            }

            // Add new ASN to network list
            if (!asn_exists) {
                result->asn_networks[result->asn_network_count] = asn_info;
                result->asn_networks[result->asn_network_count].discovered_ip_count = 1;
                result->asn_network_count++;
            }
        }
    }

    // Identify likely origin networks (ASNs with multiple IPs)
    printf("\n   [*] ASN Network Summary:\n");
    for (int i = 0; i < result->asn_network_count; i++) {
        printf("      AS%u (%s): %d IP(s) - %s\n",
               result->asn_networks[i].asn,
               result->asn_networks[i].asn_name,
               result->asn_networks[i].discovered_ip_count,
               result->asn_networks[i].ip_range);

        if (result->asn_networks[i].discovered_ip_count >= 2) {
            printf("         [!] Multiple IPs in this ASN - likely origin network\n");
            result->asn_networks[i].confidence_as_origin = 0.75f;

            // Boost confidence for all IPs in this ASN
            for (int j = 0; j < result->candidate_count; j++) {
                if (result->candidates[j].asn == result->asn_networks[i].asn) {
                    result->candidates[j].confidence_score += 0.10f;
                }
            }
        }
    }

    return result->asn_network_count;
}

// Query passive DNS for historical IPs
int query_passive_dns_historical(const char *domain,
                                struct passive_dns_record **records,
                                int *count) {
    printf("\n[PASSIVE DNS] Querying historical IP records for %s\n", domain);

    // This is a placeholder for passive DNS integration
    // In production, this would query services like:
    // - CIRCL pDNS (circl.lu)
    // - Farsight DNSDB
    // - VirusTotal
    // - SecurityTrails
    // - PassiveTotal

    printf("   [*] Note: Passive DNS requires API keys for external services\n");
    printf("   [*] Supported services: CIRCL, DNSDB, VirusTotal, SecurityTrails\n");

    // For now, we'll use DNS history from DNS queries
    // Real implementation would make HTTP API calls to passive DNS services

    *records = NULL;
    *count = 0;

    return 0;
}

// Perform WHOIS lookup on IP
int perform_whois_lookup(const char *ip_address, struct whois_info *whois) {
    printf("\n[WHOIS] Looking up network information for %s\n", ip_address);

    // This is a basic implementation
    // In production, this would:
    // 1. Connect to appropriate WHOIS server (ARIN, RIPE, APNIC, etc.)
    // 2. Parse structured WHOIS data
    // 3. Extract netblock, organization, contacts

    memset(whois, 0, sizeof(struct whois_info));

    // For now, use RDAP (modern WHOIS alternative) via HTTP
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    struct http_response_buffer response = {0};
    char url[512];

    // Use ARIN RDAP service
    snprintf(url, sizeof(url), "https://rdap.arin.net/registry/ip/%s", ip_address);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    CURLcode res = curl_easy_perform(curl);

    if (res == CURLE_OK && response.data) {
        // Basic parsing of RDAP JSON response
        // Look for network range and organization
        char *cidr = strstr(response.data, "\"cidr0_cidrs\"");
        if (cidr) {
            char *start = strchr(cidr, '[');
            char *end = strchr(cidr, ']');
            if (start && end && (end - start) < 64) {
                int len = end - start - 1;
                char cidr_str[64];
                memcpy(cidr_str, start + 1, len);
                cidr_str[len] = '\0';

                // Extract CIDR notation
                char *quote1 = strchr(cidr_str, '"');
                char *quote2 = quote1 ? strchr(quote1 + 1, '"') : NULL;
                if (quote1 && quote2) {
                    int cidr_len = quote2 - quote1 - 1;
                    memcpy(whois->netblock, quote1 + 1, cidr_len);
                    whois->netblock[cidr_len] = '\0';
                }
            }
        }

        free(response.data);
    }

    curl_easy_cleanup(curl);

    if (strlen(whois->netblock) > 0) {
        printf("   [+] Netblock: %s\n", whois->netblock);
        return 0;
    }

    return -1;
}

// Cleanup functions
void cleanup_ssl_certificate_info(struct ssl_certificate_info *cert_info) {
    if (cert_info->san_entries) {
        for (int i = 0; i < cert_info->san_count; i++) {
            free(cert_info->san_entries[i]);
        }
        free(cert_info->san_entries);
    }
}

void cleanup_advanced_ip_detection_result(struct advanced_ip_detection_result *result) {
    // Cleanup candidates
    if (result->candidates) {
        for (int i = 0; i < result->candidate_count; i++) {
            if (result->candidates[i].cert_info) {
                cleanup_ssl_certificate_info(result->candidates[i].cert_info);
                free(result->candidates[i].cert_info);
            }
            if (result->candidates[i].supporting_evidence) {
                for (int j = 0; j < result->candidates[i].evidence_count; j++) {
                    free(result->candidates[i].supporting_evidence[j]);
                }
                free(result->candidates[i].supporting_evidence);
            }
        }
        free(result->candidates);
    }

    pthread_mutex_destroy(&result->candidates_mutex);

    // Cleanup MX records
    free(result->mx_records);

    // Cleanup SRV records
    free(result->srv_records);

    // Cleanup ASN networks
    if (result->asn_networks) {
        for (int i = 0; i < result->asn_network_count; i++) {
            if (result->asn_networks[i].discovered_ips) {
                for (int j = 0; j < result->asn_networks[i].discovered_ip_count; j++) {
                    free(result->asn_networks[i].discovered_ips[j]);
                }
                free(result->asn_networks[i].discovered_ips);
            }
        }
        free(result->asn_networks);
    }

    // Cleanup passive DNS records
    free(result->passive_dns_records);

    // Cleanup WHOIS data
    if (result->whois_data) {
        for (int i = 0; i < result->whois_data_count; i++) {
            if (result->whois_data[i].related_netblocks) {
                for (int j = 0; j < result->whois_data[i].related_netblock_count; j++) {
                    free(result->whois_data[i].related_netblocks[j]);
                }
                free(result->whois_data[i].related_netblocks);
            }
        }
        free(result->whois_data);
    }

    // Cleanup bypass recommendations
    if (result->bypass_recommendations) {
        for (int i = 0; i < result->bypass_recommendation_count; i++) {
            free(result->bypass_recommendations[i]);
        }
        free(result->bypass_recommendations);
    }
}
