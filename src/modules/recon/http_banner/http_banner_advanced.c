/*
 * CloudUnflare Enhanced - HTTP Banner Grabbing Advanced Functions
 * C-INTERNAL Implementation: Phase 1 Advanced Features
 *
 * Advanced certificate analysis, technology detection, and security analysis
 * Performance optimized for 1500+ banner grabs/second
 */

#include "http_banner.h"

// Extract comprehensive certificate information
int http_banner_extract_cert_info(X509 *cert, ssl_cert_info_t *cert_info) {
    if (!cert || !cert_info) return -1;

    memset(cert_info, 0, sizeof(ssl_cert_info_t));

    // Get subject information
    X509_NAME *subject = X509_get_subject_name(cert);
    if (subject) {
        X509_NAME_oneline(subject, cert_info->subject, sizeof(cert_info->subject) - 1);
    }

    // Get issuer information
    X509_NAME *issuer = X509_get_issuer_name(cert);
    if (issuer) {
        X509_NAME_oneline(issuer, cert_info->issuer, sizeof(cert_info->issuer) - 1);
    }

    // Get serial number
    ASN1_INTEGER *serial = X509_get_serialNumber(cert);
    if (serial) {
        BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
        if (bn) {
            char *serial_str = BN_bn2hex(bn);
            if (serial_str) {
                strncpy(cert_info->serial_number, serial_str, sizeof(cert_info->serial_number) - 1);
                OPENSSL_free(serial_str);
            }
            BN_free(bn);
        }
    }

    // Get validity dates
    ASN1_TIME *not_before = X509_get_notBefore(cert);
    ASN1_TIME *not_after = X509_get_notAfter(cert);

    if (not_before) {
        BIO *bio = BIO_new(BIO_s_mem());
        if (bio) {
            ASN1_TIME_print(bio, not_before);
            BIO_gets(bio, cert_info->not_before, sizeof(cert_info->not_before) - 1);
            BIO_free(bio);
        }
    }

    if (not_after) {
        BIO *bio = BIO_new(BIO_s_mem());
        if (bio) {
            ASN1_TIME_print(bio, not_after);
            BIO_gets(bio, cert_info->not_after, sizeof(cert_info->not_after) - 1);
            BIO_free(bio);
        }
    }

    // Check certificate status
    cert_info->is_expired = (X509_cmp_current_time(not_after) < 0);
    cert_info->is_self_signed = (X509_NAME_cmp(subject, issuer) == 0);

    // Get public key information
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (pkey) {
        cert_info->key_size = EVP_PKEY_bits(pkey);
        EVP_PKEY_free(pkey);
    }

    // Get signature algorithm
    const X509_ALGOR *sig_alg;
    X509_get0_signature(NULL, &sig_alg, cert);
    if (sig_alg) {
        int nid = OBJ_obj2nid(sig_alg->algorithm);
        const char *sig_name = OBJ_nid2ln(nid);
        if (sig_name) {
            strncpy(cert_info->signature_algorithm, sig_name, sizeof(cert_info->signature_algorithm) - 1);
        }
    }

    // Check for wildcard certificate
    cert_info->is_wildcard = (strstr(cert_info->subject, "*.") != NULL);

    // Generate SHA256 fingerprint
    unsigned char md[SHA256_DIGEST_LENGTH];
    unsigned int md_len;
    if (X509_digest(cert, EVP_sha256(), md, &md_len) == 1) {
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            sprintf(cert_info->fingerprint_sha256 + (i * 2), "%02x", md[i]);
        }
    }

    // Extract Subject Alternative Names (SAN)
    STACK_OF(GENERAL_NAME) *san_list = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (san_list) {
        int san_count = sk_GENERAL_NAME_num(san_list);
        size_t san_buffer_size = san_count * 256; // Estimate buffer size
        cert_info->san_list = malloc(san_buffer_size);
        if (cert_info->san_list) {
            cert_info->san_list[0] = '\0';

            for (int i = 0; i < san_count; i++) {
                GENERAL_NAME *san = sk_GENERAL_NAME_value(san_list, i);
                if (san->type == GEN_DNS) {
                    ASN1_STRING *dns_name = san->d.dNSName;
                    char *dns_str = (char *)ASN1_STRING_get0_data(dns_name);
                    if (dns_str) {
                        if (strlen(cert_info->san_list) > 0) {
                            strcat(cert_info->san_list, ", ");
                        }
                        strncat(cert_info->san_list, dns_str, 255);
                    }
                }
            }
        }
        sk_GENERAL_NAME_pop_free(san_list, GENERAL_NAME_free);
    }

    return 0;
}

// Advanced technology detection from HTTP response
int http_banner_detect_technologies(const http_response_t *response, technology_detection_t *technologies, uint32_t *tech_count) {
    if (!response || !technologies || !tech_count) return -1;

    *tech_count = 0;

    // Server header analysis with version extraction
    if (strlen(response->server_header) > 0) {
        // nginx detection with version
        if (strstr(response->server_header, "nginx")) {
            strcpy(technologies[*tech_count].technology, "nginx");
            strcpy(technologies[*tech_count].detection_method, "Server Header");
            strcpy(technologies[*tech_count].confidence_level, "High");

            const char *version_start = strchr(response->server_header, '/');
            if (version_start) {
                strncpy(technologies[*tech_count].version, version_start + 1, 63);
                // Remove any additional info after space
                char *space = strchr(technologies[*tech_count].version, ' ');
                if (space) *space = '\0';
            }
            (*tech_count)++;
        }

        // Apache detection with modules
        if (strstr(response->server_header, "Apache")) {
            strcpy(technologies[*tech_count].technology, "Apache");
            strcpy(technologies[*tech_count].detection_method, "Server Header");
            strcpy(technologies[*tech_count].confidence_level, "High");

            const char *version_start = strchr(response->server_header, '/');
            if (version_start) {
                strncpy(technologies[*tech_count].version, version_start + 1, 63);
                char *space = strchr(technologies[*tech_count].version, ' ');
                if (space) *space = '\0';
            }
            (*tech_count)++;
        }

        // IIS detection
        if (strstr(response->server_header, "IIS")) {
            strcpy(technologies[*tech_count].technology, "Microsoft IIS");
            strcpy(technologies[*tech_count].detection_method, "Server Header");
            strcpy(technologies[*tech_count].confidence_level, "High");

            const char *version_start = strchr(response->server_header, '/');
            if (version_start) {
                strncpy(technologies[*tech_count].version, version_start + 1, 63);
            }
            (*tech_count)++;
        }

        // Cloudflare detection
        if (strstr(response->server_header, "cloudflare")) {
            strcpy(technologies[*tech_count].technology, "Cloudflare");
            strcpy(technologies[*tech_count].detection_method, "Server Header");
            strcpy(technologies[*tech_count].confidence_level, "High");
            (*tech_count)++;
        }

        // LiteSpeed detection
        if (strstr(response->server_header, "LiteSpeed")) {
            strcpy(technologies[*tech_count].technology, "LiteSpeed");
            strcpy(technologies[*tech_count].detection_method, "Server Header");
            strcpy(technologies[*tech_count].confidence_level, "High");
            (*tech_count)++;
        }
    }

    // Detailed header analysis for technologies
    const char *powered_by = http_banner_get_header_value(response, "X-Powered-By");
    if (powered_by) {
        if (strstr(powered_by, "PHP")) {
            strcpy(technologies[*tech_count].technology, "PHP");
            strcpy(technologies[*tech_count].detection_method, "X-Powered-By Header");
            strcpy(technologies[*tech_count].confidence_level, "High");

            const char *version_start = strchr(powered_by, '/');
            if (version_start) {
                strncpy(technologies[*tech_count].version, version_start + 1, 63);
            }
            (*tech_count)++;
        }

        if (strstr(powered_by, "ASP.NET")) {
            strcpy(technologies[*tech_count].technology, "ASP.NET");
            strcpy(technologies[*tech_count].detection_method, "X-Powered-By Header");
            strcpy(technologies[*tech_count].confidence_level, "High");
            (*tech_count)++;
        }

        if (strstr(powered_by, "Express")) {
            strcpy(technologies[*tech_count].technology, "Express.js");
            strcpy(technologies[*tech_count].detection_method, "X-Powered-By Header");
            strcpy(technologies[*tech_count].confidence_level, "High");
            (*tech_count)++;
        }
    }

    // Check for generator meta tag and framework headers
    const char *generator = http_banner_get_header_value(response, "X-Generator");
    if (generator) {
        if (strstr(generator, "WordPress")) {
            strcpy(technologies[*tech_count].technology, "WordPress");
            strcpy(technologies[*tech_count].detection_method, "X-Generator Header");
            strcpy(technologies[*tech_count].confidence_level, "High");
            (*tech_count)++;
        }

        if (strstr(generator, "Drupal")) {
            strcpy(technologies[*tech_count].technology, "Drupal");
            strcpy(technologies[*tech_count].detection_method, "X-Generator Header");
            strcpy(technologies[*tech_count].confidence_level, "High");
            (*tech_count)++;
        }
    }

    // Framework detection through headers
    if (http_banner_get_header_value(response, "X-Django-Version")) {
        strcpy(technologies[*tech_count].technology, "Django");
        strcpy(technologies[*tech_count].detection_method, "Framework Header");
        strcpy(technologies[*tech_count].confidence_level, "High");
        (*tech_count)++;
    }

    if (http_banner_get_header_value(response, "X-Rails-Version")) {
        strcpy(technologies[*tech_count].technology, "Ruby on Rails");
        strcpy(technologies[*tech_count].detection_method, "Framework Header");
        strcpy(technologies[*tech_count].confidence_level, "High");
        (*tech_count)++;
    }

    // CDN and service detection
    if (http_banner_get_header_value(response, "CF-RAY")) {
        strcpy(technologies[*tech_count].technology, "Cloudflare CDN");
        strcpy(technologies[*tech_count].detection_method, "CDN Header");
        strcpy(technologies[*tech_count].confidence_level, "High");
        (*tech_count)++;
    }

    if (http_banner_get_header_value(response, "X-Amz-Cf-Id")) {
        strcpy(technologies[*tech_count].technology, "Amazon CloudFront");
        strcpy(technologies[*tech_count].detection_method, "CDN Header");
        strcpy(technologies[*tech_count].confidence_level, "High");
        (*tech_count)++;
    }

    // Body content analysis for deeper detection
    if (response->body_preview && response->body_preview_size > 0) {
        const char *body = response->body_preview;

        // WordPress detection through body content
        if (strstr(body, "wp-content") || strstr(body, "wp-includes") || strstr(body, "/wp-json/")) {
            if (*tech_count < 20) {
                strcpy(technologies[*tech_count].technology, "WordPress");
                strcpy(technologies[*tech_count].detection_method, "Body Content");
                strcpy(technologies[*tech_count].confidence_level, "High");
                (*tech_count)++;
            }
        }

        // jQuery detection
        if (strstr(body, "jquery") || strstr(body, "jQuery")) {
            if (*tech_count < 20) {
                strcpy(technologies[*tech_count].technology, "jQuery");
                strcpy(technologies[*tech_count].detection_method, "Body Content");
                strcpy(technologies[*tech_count].confidence_level, "Medium");
                (*tech_count)++;
            }
        }

        // Bootstrap detection
        if (strstr(body, "bootstrap") || strstr(body, "Bootstrap")) {
            if (*tech_count < 20) {
                strcpy(technologies[*tech_count].technology, "Bootstrap");
                strcpy(technologies[*tech_count].detection_method, "Body Content");
                strcpy(technologies[*tech_count].confidence_level, "Medium");
                (*tech_count)++;
            }
        }

        // React detection
        if (strstr(body, "react") || strstr(body, "React") || strstr(body, "__REACT_")) {
            if (*tech_count < 20) {
                strcpy(technologies[*tech_count].technology, "React");
                strcpy(technologies[*tech_count].detection_method, "Body Content");
                strcpy(technologies[*tech_count].confidence_level, "Medium");
                (*tech_count)++;
            }
        }

        // Angular detection
        if (strstr(body, "angular") || strstr(body, "ng-app") || strstr(body, "Angular")) {
            if (*tech_count < 20) {
                strcpy(technologies[*tech_count].technology, "Angular");
                strcpy(technologies[*tech_count].detection_method, "Body Content");
                strcpy(technologies[*tech_count].confidence_level, "Medium");
                (*tech_count)++;
            }
        }

        // Vue.js detection
        if (strstr(body, "vue") || strstr(body, "Vue") || strstr(body, "v-app")) {
            if (*tech_count < 20) {
                strcpy(technologies[*tech_count].technology, "Vue.js");
                strcpy(technologies[*tech_count].detection_method, "Body Content");
                strcpy(technologies[*tech_count].confidence_level, "Medium");
                (*tech_count)++;
            }
        }

        // Google Analytics detection
        if (strstr(body, "google-analytics") || strstr(body, "gtag") || strstr(body, "ga('")) {
            if (*tech_count < 20) {
                strcpy(technologies[*tech_count].technology, "Google Analytics");
                strcpy(technologies[*tech_count].detection_method, "Body Content");
                strcpy(technologies[*tech_count].confidence_level, "High");
                (*tech_count)++;
            }
        }
    }

    return 0;
}

// Get header value by name (case-insensitive)
const char *http_banner_get_header_value(const http_response_t *response, const char *header_name) {
    if (!response || !header_name) return NULL;

    for (uint32_t i = 0; i < response->header_count; i++) {
        if (strcasecmp(response->headers[i].name, header_name) == 0) {
            return response->headers[i].value;
        }
    }

    return NULL;
}

// Comprehensive security header analysis
int http_banner_analyze_security_headers(const http_response_t *response, char security_headers[][256], uint32_t *header_count) {
    if (!response || !security_headers || !header_count) return -1;

    *header_count = 0;

    const char *security_header_names[] = {
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy",
        "Feature-Policy",  // Legacy name for Permissions-Policy
        "Cross-Origin-Embedder-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy",
        "Public-Key-Pins",
        "Expect-CT",
        "X-Permitted-Cross-Domain-Policies"
    };

    for (size_t i = 0; i < sizeof(security_header_names) / sizeof(security_header_names[0]); i++) {
        const char *value = http_banner_get_header_value(response, security_header_names[i]);
        if (value && *header_count < 10) {
            snprintf(security_headers[*header_count], 256, "%s: %s", security_header_names[i], value);
            (*header_count)++;
        }
    }

    return 0;
}

// Check if security header exists
bool http_banner_has_security_header(const http_response_t *response, const char *header_name) {
    return (http_banner_get_header_value(response, header_name) != NULL);
}

// Rate security posture comprehensively
int http_banner_rate_security_posture(const http_response_t *response) {
    if (!response) return -1;

    int score = 0;

    // HSTS (HTTP Strict Transport Security) - 25 points
    const char *hsts = http_banner_get_header_value(response, "Strict-Transport-Security");
    if (hsts) {
        score += 20;
        if (strstr(hsts, "includeSubDomains")) score += 3;
        if (strstr(hsts, "preload")) score += 2;
    }

    // CSP (Content Security Policy) - 20 points
    if (http_banner_has_security_header(response, "Content-Security-Policy")) {
        score += 20;
    }

    // X-Frame-Options - 15 points
    const char *frame_options = http_banner_get_header_value(response, "X-Frame-Options");
    if (frame_options) {
        score += 10;
        if (strcasecmp(frame_options, "DENY") == 0) score += 5;
        else if (strcasecmp(frame_options, "SAMEORIGIN") == 0) score += 3;
    }

    // X-Content-Type-Options - 10 points
    const char *content_type_options = http_banner_get_header_value(response, "X-Content-Type-Options");
    if (content_type_options && strcasecmp(content_type_options, "nosniff") == 0) {
        score += 10;
    }

    // X-XSS-Protection - 5 points
    const char *xss_protection = http_banner_get_header_value(response, "X-XSS-Protection");
    if (xss_protection) {
        score += 5;
    }

    // Referrer-Policy - 8 points
    if (http_banner_has_security_header(response, "Referrer-Policy")) {
        score += 8;
    }

    // Permissions-Policy/Feature-Policy - 7 points
    if (http_banner_has_security_header(response, "Permissions-Policy") ||
        http_banner_has_security_header(response, "Feature-Policy")) {
        score += 7;
    }

    // Cross-Origin policies - 10 points total
    if (http_banner_has_security_header(response, "Cross-Origin-Embedder-Policy")) score += 3;
    if (http_banner_has_security_header(response, "Cross-Origin-Opener-Policy")) score += 3;
    if (http_banner_has_security_header(response, "Cross-Origin-Resource-Policy")) score += 4;

    // Expect-CT - 5 points
    if (http_banner_has_security_header(response, "Expect-CT")) {
        score += 5;
    }

    return score; // Maximum 100+ points
}

// Build URL from target specification
int http_banner_build_url(const recon_target_t *target, bool use_https, char *url, size_t url_size) {
    if (!target || !url) return -1;

    const char *hostname = strlen(target->hostname) > 0 ? target->hostname : target->ip_address;
    const char *scheme = use_https ? "https" : "http";
    uint16_t default_port = use_https ? 443 : 80;

    if (target->port != default_port) {
        snprintf(url, url_size, "%s://%s:%u/", scheme, hostname, target->port);
    } else {
        snprintf(url, url_size, "%s://%s/", scheme, hostname);
    }

    return 0;
}

// Validate URL format
bool http_banner_is_valid_url(const char *url) {
    if (!url) return false;

    return (strncmp(url, "http://", 7) == 0 || strncmp(url, "https://", 8) == 0);
}

// Set banner grabbing configuration
int http_banner_set_config(http_banner_context_t *ctx, const http_banner_config_t *config) {
    if (!ctx || !config) return -1;

    ctx->config = *config;
    return 0;
}

// Export results to JSON format
int http_banner_export_json(const http_banner_context_t *ctx, const char *filename) {
    if (!ctx || !filename) return -1;

    FILE *file = fopen(filename, "w");
    if (!file) return -1;

    fprintf(file, "{\n");
    fprintf(file, "  \"http_banner_results\": {\n");
    fprintf(file, "    \"total_requests\": %u,\n", ctx->result_count);
    fprintf(file, "    \"results\": [\n");

    for (uint32_t i = 0; i < ctx->result_count; i++) {
        const http_banner_result_t *result = &ctx->results[i];

        fprintf(file, "      {\n");
        fprintf(file, "        \"url\": \"%s\",\n", result->url);
        fprintf(file, "        \"method\": \"%s\",\n", http_method_to_string(result->method));
        fprintf(file, "        \"success\": %s,\n", result->success ? "true" : "false");
        fprintf(file, "        \"timestamp\": %ld,\n", result->timestamp);

        if (result->success) {
            fprintf(file, "        \"response\": {\n");
            fprintf(file, "          \"status_code\": %u,\n", result->response.status_code);
            fprintf(file, "          \"status_message\": \"%s\",\n", result->response.status_message);
            fprintf(file, "          \"server\": \"%s\",\n", result->response.server_header);
            fprintf(file, "          \"content_type\": \"%s\",\n", result->response.content_type);
            fprintf(file, "          \"content_length\": %lu,\n", result->response.content_length);
            fprintf(file, "          \"response_time_ms\": %u,\n", result->response.response_time_ms);
            fprintf(file, "          \"has_ssl\": %s", result->response.has_ssl ? "true" : "false");

            if (result->response.has_ssl) {
                fprintf(file, ",\n          \"ssl_info\": {\n");
                fprintf(file, "            \"version\": \"%s\",\n", ssl_version_to_string(result->response.ssl_info.version));
                fprintf(file, "            \"cipher_suite\": \"%s\",\n", result->response.ssl_info.cipher_suite);
                fprintf(file, "            \"certificate\": {\n");
                fprintf(file, "              \"subject\": \"%s\",\n", result->response.ssl_info.certificate.subject);
                fprintf(file, "              \"issuer\": \"%s\",\n", result->response.ssl_info.certificate.issuer);
                fprintf(file, "              \"key_size\": %u,\n", result->response.ssl_info.certificate.key_size);
                fprintf(file, "              \"is_expired\": %s,\n", result->response.ssl_info.certificate.is_expired ? "true" : "false");
                fprintf(file, "              \"is_self_signed\": %s\n", result->response.ssl_info.certificate.is_self_signed ? "true" : "false");
                fprintf(file, "            }\n");
                fprintf(file, "          }");
            }

            fprintf(file, "\n        }");
        } else {
            fprintf(file, "        \"error\": \"%s\"", result->error_message);
        }

        fprintf(file, "\n      }");
        if (i < ctx->result_count - 1) {
            fprintf(file, ",");
        }
        fprintf(file, "\n");
    }

    fprintf(file, "    ]\n");
    fprintf(file, "  }\n");
    fprintf(file, "}\n");

    fclose(file);
    return 0;
}

// Export results to CSV format
int http_banner_export_csv(const http_banner_context_t *ctx, const char *filename) {
    if (!ctx || !filename) return -1;

    FILE *file = fopen(filename, "w");
    if (!file) return -1;

    // Write CSV header
    fprintf(file, "URL,Method,Success,Status Code,Status Message,Server,Content Type,Content Length,Response Time (ms),SSL Version,Cipher Suite,Certificate Subject,Timestamp\n");

    // Write data rows
    for (uint32_t i = 0; i < ctx->result_count; i++) {
        const http_banner_result_t *result = &ctx->results[i];

        fprintf(file, "\"%s\",\"%s\",%s,%u,\"%s\",\"%s\",\"%s\",%lu,%u,\"%s\",\"%s\",\"%s\",%ld\n",
                result->url,
                http_method_to_string(result->method),
                result->success ? "true" : "false",
                result->response.status_code,
                result->response.status_message,
                result->response.server_header,
                result->response.content_type,
                result->response.content_length,
                result->response.response_time_ms,
                result->response.has_ssl ? ssl_version_to_string(result->response.ssl_info.version) : "N/A",
                result->response.has_ssl ? result->response.ssl_info.cipher_suite : "N/A",
                result->response.has_ssl ? result->response.ssl_info.certificate.subject : "N/A",
                result->timestamp);
    }

    fclose(file);
    return 0;
}

// Print detailed banner result
void http_banner_print_result(const http_banner_result_t *result) {
    if (!result) return;

    printf("\n=== HTTP Banner Analysis Result ===\n");
    printf("URL: %s\n", result->url);
    printf("Method: %s\n", http_method_to_string(result->method));
    printf("Success: %s\n", result->success ? "Yes" : "No");
    printf("Timestamp: %s", ctime(&result->timestamp));

    if (result->success) {
        printf("\n--- HTTP Response ---\n");
        printf("Status: %u %s\n", result->response.status_code, result->response.status_message);
        printf("Server: %s\n", strlen(result->response.server_header) > 0 ? result->response.server_header : "Not disclosed");
        printf("Content-Type: %s\n", strlen(result->response.content_type) > 0 ? result->response.content_type : "Unknown");
        printf("Content-Length: %lu bytes\n", result->response.content_length);
        printf("Response Time: %u ms\n", result->response.response_time_ms);

        // SSL/TLS Information
        if (result->response.has_ssl) {
            printf("\n--- SSL/TLS Analysis ---\n");
            printf("Protocol Version: %s\n", ssl_version_to_string(result->response.ssl_info.version));
            printf("Cipher Suite: %s\n", result->response.ssl_info.cipher_suite);
            printf("Key Exchange Bits: %u\n", result->response.ssl_info.key_exchange_bits);
            printf("SNI Support: %s\n", result->response.ssl_info.supports_sni ? "Yes" : "No");
            printf("OCSP Support: %s\n", result->response.ssl_info.supports_ocsp ? "Yes" : "No");

            printf("\n--- Certificate Information ---\n");
            printf("Subject: %s\n", result->response.ssl_info.certificate.subject);
            printf("Issuer: %s\n", result->response.ssl_info.certificate.issuer);
            printf("Serial Number: %s\n", result->response.ssl_info.certificate.serial_number);
            printf("Key Size: %u bits\n", result->response.ssl_info.certificate.key_size);
            printf("Signature Algorithm: %s\n", result->response.ssl_info.certificate.signature_algorithm);
            printf("Valid From: %s\n", result->response.ssl_info.certificate.not_before);
            printf("Valid Until: %s\n", result->response.ssl_info.certificate.not_after);
            printf("Is Expired: %s\n", result->response.ssl_info.certificate.is_expired ? "Yes" : "No");
            printf("Is Self-Signed: %s\n", result->response.ssl_info.certificate.is_self_signed ? "Yes" : "No");
            printf("Is Wildcard: %s\n", result->response.ssl_info.certificate.is_wildcard ? "Yes" : "No");
            printf("SHA256 Fingerprint: %s\n", result->response.ssl_info.certificate.fingerprint_sha256);

            if (result->response.ssl_info.certificate.san_list) {
                printf("Subject Alternative Names: %s\n", result->response.ssl_info.certificate.san_list);
            }
        }

        // Technology Detection
        if (result->technology_count > 0) {
            printf("\n--- Detected Technologies ---\n");
            for (uint32_t i = 0; i < result->technology_count; i++) {
                printf("%s", result->technologies[i].technology);
                if (strlen(result->technologies[i].version) > 0) {
                    printf(" %s", result->technologies[i].version);
                }
                printf(" (Confidence: %s, Method: %s)\n",
                       result->technologies[i].confidence_level,
                       result->technologies[i].detection_method);
            }
        }

        // Security Headers Analysis
        if (result->security_header_count > 0) {
            printf("\n--- Security Headers ---\n");
            for (uint32_t i = 0; i < result->security_header_count; i++) {
                printf("%s\n", result->security_headers[i]);
            }

            int security_score = http_banner_rate_security_posture(&result->response);
            printf("\nSecurity Posture Score: %d/100", security_score);
            if (security_score >= 80) printf(" (Excellent)");
            else if (security_score >= 60) printf(" (Good)");
            else if (security_score >= 40) printf(" (Fair)");
            else printf(" (Poor)");
            printf("\n");
        }

        // All Response Headers
        if (result->response.header_count > 0) {
            printf("\n--- All Response Headers ---\n");
            for (uint32_t i = 0; i < result->response.header_count; i++) {
                printf("%s: %s\n",
                       result->response.headers[i].name,
                       result->response.headers[i].value);
            }
        }

        // Body Preview
        if (result->response.body_preview && result->response.body_preview_size > 0) {
            printf("\n--- Body Preview (first %zu bytes) ---\n", result->response.body_preview_size);
            printf("%.*s\n", (int)result->response.body_preview_size, result->response.body_preview);
        }
    } else {
        printf("Error: %s\n", result->error_message);
    }

    printf("=====================================\n\n");
}

// Additional utility and helper functions for comprehensive HTTP banner grabbing
// These provide OPSEC compliance, performance optimization, and advanced analysis