/*
 * CloudUnflare Enhanced - Cloudflare Radar Parser Module
 *
 * Handles JSON parsing and extraction of scan results from Cloudflare Radar API
 */

#include "cloudflare_radar.h"
#include "../common/recon_common.h"
#include <json-c/json.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * Parse comprehensive Cloudflare Radar response
 * Returns: 0 on success, -1 on error
 */
int radar_scan_parse_response(const char *response_data, size_t data_len,
                              radar_scan_result_t *result) {
    if (!response_data || !result) {
        return -1;
    }

    // Parse JSON
    json_object *root = json_tokener_parse(response_data);
    if (!root) {
        fprintf(stderr, "Error: Failed to parse JSON response\n");
        return -1;
    }

    // Extract domain if available
    json_object *domain_obj = json_object_object_get(root, "domain");
    if (domain_obj && json_object_get_type(domain_obj) == json_type_string) {
        strncpy(result->domain, json_object_get_string(domain_obj),
                sizeof(result->domain) - 1);
    }

    // Extract scan timestamp
    json_object *timestamp_obj = json_object_object_get(root, "timestamp");
    if (timestamp_obj && json_object_get_type(timestamp_obj) == json_type_int) {
        result->scan_timestamp = json_object_get_int64(timestamp_obj);
    } else {
        result->scan_timestamp = time(NULL);
    }

    // Extract DNS results
    radar_scan_extract_dns_results(response_data, &result->dns_results,
                                   &result->dns_result_count);

    // Extract HTTP configuration
    radar_scan_extract_http_config(response_data, &result->http_result);

    // Extract SSL/TLS information
    radar_scan_extract_ssl_info(response_data, &result->ssl_result);

    // Extract security analysis
    radar_scan_extract_security_analysis(response_data, &result->security_result);

    // Extract technology stack
    radar_scan_extract_technology_stack(response_data, &result->technology_stack);

    // Extract WHOIS data
    radar_scan_extract_whois_data(response_data, result);

    // Mark as completed
    result->status = RADAR_STATUS_COMPLETED;

    json_object_put(root);
    return 0;
}

/*
 * Extract DNS results from JSON response
 */
int radar_scan_extract_dns_results(const char *json_data, radar_dns_result_t **results,
                                   uint32_t *result_count) {
    if (!json_data || !results || !result_count) {
        return -1;
    }

    json_object *root = json_tokener_parse(json_data);
    if (!root) {
        return -1;
    }

    *result_count = 0;
    *results = NULL;

    // Get DNS array from response
    json_object *dns_array = json_object_object_get(root, "dns");
    if (!dns_array || json_object_get_type(dns_array) != json_type_array) {
        json_object_put(root);
        return 0;
    }

    int array_len = json_object_array_length(dns_array);
    if (array_len == 0) {
        json_object_put(root);
        return 0;
    }

    // Allocate memory for results
    *results = malloc(array_len * sizeof(radar_dns_result_t));
    if (!*results) {
        json_object_put(root);
        return -1;
    }

    memset(*results, 0, array_len * sizeof(radar_dns_result_t));

    // Parse each DNS result
    for (int i = 0; i < array_len; i++) {
        json_object *dns_obj = json_object_array_get_idx(dns_array, i);
        if (!dns_obj) continue;

        radar_dns_result_t *result = &(*results)[*result_count];

        // Extract nameserver
        json_object *ns_obj = json_object_object_get(dns_obj, "nameserver");
        if (ns_obj && json_object_get_type(ns_obj) == json_type_string) {
            strncpy(result->nameserver, json_object_get_string(ns_obj),
                    sizeof(result->nameserver) - 1);
        }

        // Extract IP address
        json_object *ip_obj = json_object_object_get(dns_obj, "ip_address");
        if (ip_obj && json_object_get_type(ip_obj) == json_type_string) {
            strncpy(result->ip_address, json_object_get_string(ip_obj),
                    sizeof(result->ip_address) - 1);
        }

        // Extract response time
        json_object *response_time_obj = json_object_object_get(dns_obj, "response_time_ms");
        if (response_time_obj && json_object_get_type(response_time_obj) == json_type_int) {
            result->response_time_ms = json_object_get_int(response_time_obj);
        }

        // Extract DNSSEC status
        json_object *dnssec_obj = json_object_object_get(dns_obj, "dnssec_enabled");
        if (dnssec_obj && json_object_get_type(dnssec_obj) == json_type_boolean) {
            result->dnssec_enabled = json_object_get_boolean(dnssec_obj);
        }

        // Extract supported record types
        json_object *records_obj = json_object_object_get(dns_obj, "record_types");
        if (records_obj && json_object_get_type(records_obj) == json_type_string) {
            strncpy(result->record_types, json_object_get_string(records_obj),
                    sizeof(result->record_types) - 1);
        }

        result->discovered = time(NULL);
        (*result_count)++;
    }

    json_object_put(root);
    return 0;
}

/*
 * Extract HTTP configuration from JSON response
 */
int radar_scan_extract_http_config(const char *json_data, radar_http_result_t *result) {
    if (!json_data || !result) {
        return -1;
    }

    json_object *root = json_tokener_parse(json_data);
    if (!root) {
        return -1;
    }

    memset(result, 0, sizeof(*result));

    json_object *http_obj = json_object_object_get(root, "http");
    if (!http_obj || json_object_get_type(http_obj) != json_type_object) {
        json_object_put(root);
        return -1;
    }

    // Extract HTTP port
    json_object *http_port_obj = json_object_object_get(http_obj, "http_port");
    if (http_port_obj && json_object_get_type(http_port_obj) == json_type_int) {
        result->http_port = json_object_get_int(http_port_obj);
    }

    // Extract HTTPS port
    json_object *https_port_obj = json_object_object_get(http_obj, "https_port");
    if (https_port_obj && json_object_get_type(https_port_obj) == json_type_int) {
        result->https_port = json_object_get_int(https_port_obj);
    }

    // Extract HTTP status
    json_object *http_enabled_obj = json_object_object_get(http_obj, "http_enabled");
    if (http_enabled_obj && json_object_get_type(http_enabled_obj) == json_type_boolean) {
        result->http_enabled = json_object_get_boolean(http_enabled_obj);
    }

    // Extract HTTPS status
    json_object *https_enabled_obj = json_object_object_get(http_obj, "https_enabled");
    if (https_enabled_obj && json_object_get_type(https_enabled_obj) == json_type_boolean) {
        result->https_enabled = json_object_get_boolean(https_enabled_obj);
    }

    // Extract redirect status
    json_object *redirect_obj = json_object_object_get(http_obj, "redirect_http_to_https");
    if (redirect_obj && json_object_get_type(redirect_obj) == json_type_boolean) {
        result->redirect_http_to_https = json_object_get_boolean(redirect_obj);
    }

    // Extract server header
    json_object *server_obj = json_object_object_get(http_obj, "server_header");
    if (server_obj && json_object_get_type(server_obj) == json_type_string) {
        strncpy(result->server_header, json_object_get_string(server_obj),
                sizeof(result->server_header) - 1);
    }

    // Extract response time
    json_object *response_time_obj = json_object_object_get(http_obj, "response_time_ms");
    if (response_time_obj && json_object_get_type(response_time_obj) == json_type_int) {
        result->response_time_ms = json_object_get_int(response_time_obj);
    }

    json_object_put(root);
    return 0;
}

/*
 * Extract SSL/TLS information from JSON response
 */
int radar_scan_extract_ssl_info(const char *json_data, radar_ssl_result_t *result) {
    if (!json_data || !result) {
        return -1;
    }

    json_object *root = json_tokener_parse(json_data);
    if (!root) {
        return -1;
    }

    memset(result, 0, sizeof(*result));

    json_object *ssl_obj = json_object_object_get(root, "ssl");
    if (!ssl_obj || json_object_get_type(ssl_obj) != json_type_object) {
        json_object_put(root);
        return -1;
    }

    // Extract certificate fields
    json_object *subject_obj = json_object_object_get(ssl_obj, "certificate_subject");
    if (subject_obj && json_object_get_type(subject_obj) == json_type_string) {
        strncpy(result->certificate_subject, json_object_get_string(subject_obj),
                sizeof(result->certificate_subject) - 1);
    }

    json_object *issuer_obj = json_object_object_get(ssl_obj, "certificate_issuer");
    if (issuer_obj && json_object_get_type(issuer_obj) == json_type_string) {
        strncpy(result->certificate_issuer, json_object_get_string(issuer_obj),
                sizeof(result->certificate_issuer) - 1);
    }

    json_object *fingerprint_obj = json_object_object_get(ssl_obj, "certificate_fingerprint");
    if (fingerprint_obj && json_object_get_type(fingerprint_obj) == json_type_string) {
        strncpy(result->certificate_fingerprint, json_object_get_string(fingerprint_obj),
                sizeof(result->certificate_fingerprint) - 1);
    }

    // Extract validity dates
    json_object *valid_from_obj = json_object_object_get(ssl_obj, "valid_from");
    if (valid_from_obj && json_object_get_type(valid_from_obj) == json_type_int) {
        result->valid_from = json_object_get_int64(valid_from_obj);
    }

    json_object *valid_to_obj = json_object_object_get(ssl_obj, "valid_to");
    if (valid_to_obj && json_object_get_type(valid_to_obj) == json_type_int) {
        result->valid_to = json_object_get_int64(valid_to_obj);
    }

    // Extract certificate status
    json_object *self_signed_obj = json_object_object_get(ssl_obj, "self_signed");
    if (self_signed_obj && json_object_get_type(self_signed_obj) == json_type_boolean) {
        result->self_signed = json_object_get_boolean(self_signed_obj);
    }

    json_object *expired_obj = json_object_object_get(ssl_obj, "expired");
    if (expired_obj && json_object_get_type(expired_obj) == json_type_boolean) {
        result->expired = json_object_get_boolean(expired_obj);
    }

    // Extract TLS configuration
    json_object *cipher_obj = json_object_object_get(ssl_obj, "cipher_suite");
    if (cipher_obj && json_object_get_type(cipher_obj) == json_type_string) {
        strncpy(result->cipher_suite, json_object_get_string(cipher_obj),
                sizeof(result->cipher_suite) - 1);
    }

    json_object *tls_obj = json_object_object_get(ssl_obj, "tls_version");
    if (tls_obj && json_object_get_type(tls_obj) == json_type_string) {
        strncpy(result->tls_version, json_object_get_string(tls_obj),
                sizeof(result->tls_version) - 1);
    }

    json_object_put(root);
    return 0;
}

/*
 * Extract security analysis from JSON response
 */
int radar_scan_extract_security_analysis(const char *json_data, radar_security_result_t *result) {
    if (!json_data || !result) {
        return -1;
    }

    json_object *root = json_tokener_parse(json_data);
    if (!root) {
        return -1;
    }

    memset(result, 0, sizeof(*result));

    json_object *security_obj = json_object_object_get(root, "security");
    if (!security_obj || json_object_get_type(security_obj) != json_type_object) {
        json_object_put(root);
        return -1;
    }

    // Extract vulnerability flags
    json_object *dns_spoof_obj = json_object_object_get(security_obj, "vulnerable_to_dns_spoofing");
    if (dns_spoof_obj && json_object_get_type(dns_spoof_obj) == json_type_boolean) {
        result->vulnerable_to_dns_spoofing = json_object_get_boolean(dns_spoof_obj);
    }

    json_object *dnssec_obj = json_object_object_get(security_obj, "vulnerable_to_dnssec_bypass");
    if (dnssec_obj && json_object_get_type(dnssec_obj) == json_type_boolean) {
        result->vulnerable_to_dnssec_bypass = json_object_get_boolean(dnssec_obj);
    }

    json_object *tls_obj = json_object_object_get(security_obj, "vulnerable_to_tls_downgrade");
    if (tls_obj && json_object_get_type(tls_obj) == json_type_boolean) {
        result->vulnerable_to_tls_downgrade = json_object_get_boolean(tls_obj);
    }

    json_object *cipher_obj = json_object_object_get(security_obj, "vulnerable_to_weak_cipher");
    if (cipher_obj && json_object_get_type(cipher_obj) == json_type_boolean) {
        result->vulnerable_to_weak_cipher = json_object_get_boolean(cipher_obj);
    }

    // Extract vulnerability list
    json_object *vuln_obj = json_object_object_get(security_obj, "detected_vulnerabilities");
    if (vuln_obj && json_object_get_type(vuln_obj) == json_type_string) {
        strncpy(result->detected_vulnerabilities, json_object_get_string(vuln_obj),
                sizeof(result->detected_vulnerabilities) - 1);
    }

    // Extract security score
    json_object *score_obj = json_object_object_get(security_obj, "security_score");
    if (score_obj && json_object_get_type(score_obj) == json_type_int) {
        result->security_score = json_object_get_int(score_obj);
    }

    json_object_put(root);
    return 0;
}

/*
 * Extract technology stack from JSON response
 */
int radar_scan_extract_technology_stack(const char *json_data, radar_technology_stack_t *stack) {
    if (!json_data || !stack) {
        return -1;
    }

    json_object *root = json_tokener_parse(json_data);
    if (!root) {
        return -1;
    }

    memset(stack, 0, sizeof(*stack));

    json_object *tech_array = json_object_object_get(root, "technologies");
    if (!tech_array || json_object_get_type(tech_array) != json_type_array) {
        json_object_put(root);
        return 0;
    }

    int array_len = json_object_array_length(tech_array);
    if (array_len == 0) {
        json_object_put(root);
        return 0;
    }

    // Allocate memory for technologies
    stack->technologies = malloc(array_len * sizeof(radar_technology_t));
    if (!stack->technologies) {
        json_object_put(root);
        return -1;
    }

    memset(stack->technologies, 0, array_len * sizeof(radar_technology_t));

    // Parse each technology
    for (int i = 0; i < array_len; i++) {
        json_object *tech_obj = json_object_array_get_idx(tech_array, i);
        if (!tech_obj) continue;

        radar_technology_t *tech = &stack->technologies[stack->tech_count];

        json_object *name_obj = json_object_object_get(tech_obj, "name");
        if (name_obj && json_object_get_type(name_obj) == json_type_string) {
            strncpy(tech->technology_name, json_object_get_string(name_obj),
                    sizeof(tech->technology_name) - 1);
        }

        json_object *version_obj = json_object_object_get(tech_obj, "version");
        if (version_obj && json_object_get_type(version_obj) == json_type_string) {
            strncpy(tech->version, json_object_get_string(version_obj),
                    sizeof(tech->version) - 1);
        }

        json_object *category_obj = json_object_object_get(tech_obj, "category");
        if (category_obj && json_object_get_type(category_obj) == json_type_string) {
            strncpy(tech->category, json_object_get_string(category_obj),
                    sizeof(tech->category) - 1);
        }

        stack->tech_count++;
    }

    stack->max_tech_count = array_len;
    json_object_put(root);
    return 0;
}

/*
 * Extract WHOIS data from JSON response
 */
int radar_scan_extract_whois_data(const char *json_data, radar_scan_result_t *result) {
    if (!json_data || !result) {
        return -1;
    }

    json_object *root = json_tokener_parse(json_data);
    if (!root) {
        return -1;
    }

    json_object *whois_obj = json_object_object_get(root, "whois");
    if (!whois_obj || json_object_get_type(whois_obj) != json_type_object) {
        json_object_put(root);
        return -1;
    }

    // Extract registrar
    json_object *registrar_obj = json_object_object_get(whois_obj, "registrar");
    if (registrar_obj && json_object_get_type(registrar_obj) == json_type_string) {
        strncpy(result->registrar, json_object_get_string(registrar_obj),
                sizeof(result->registrar) - 1);
    }

    // Extract dates
    json_object *created_obj = json_object_object_get(whois_obj, "created_date");
    if (created_obj && json_object_get_type(created_obj) == json_type_int) {
        result->created_date = json_object_get_int64(created_obj);
    }

    json_object *expires_obj = json_object_object_get(whois_obj, "expires_date");
    if (expires_obj && json_object_get_type(expires_obj) == json_type_int) {
        result->expires_date = json_object_get_int64(expires_obj);
    }

    json_object *updated_obj = json_object_object_get(whois_obj, "updated_date");
    if (updated_obj && json_object_get_type(updated_obj) == json_type_int) {
        result->updated_date = json_object_get_int64(updated_obj);
    }

    json_object_put(root);
    return 0;
}
