/*
 * CloudClear - SSL Certificate Enumeration Module
 *
 * Comprehensive SSL/TLS certificate analysis and enumeration
 * Critical for CDN bypass via certificate correlation and origin discovery
 *
 * Techniques:
 * - SSL certificate chain analysis
 * - Subject Alternative Name (SAN) extraction
 * - Certificate Transparency log mining
 * - Certificate fingerprinting and correlation
 * - Issuer and subject matching across IPs
 * - Historical certificate analysis
 * - Certificate pinning detection
 */

#ifndef SSL_CERT_ENUM_H
#define SSL_CERT_ENUM_H

#include "../common/recon_common.h"
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#define SSL_CERT_MAX_SANS 100
#define SSL_CERT_MAX_CHAIN_DEPTH 10
#define SSL_CERT_MAX_FINGERPRINT_LEN 128
#define SSL_CERT_MAX_DN_LEN 512

// SSL/TLS protocol versions
typedef enum {
    SSL_PROTO_UNKNOWN,
    SSL_PROTO_SSL3,
    SSL_PROTO_TLS1_0,
    SSL_PROTO_TLS1_1,
    SSL_PROTO_TLS1_2,
    SSL_PROTO_TLS1_3
} ssl_protocol_version_t;

// Certificate type
typedef enum {
    CERT_TYPE_UNKNOWN,
    CERT_TYPE_DV,           // Domain Validated
    CERT_TYPE_OV,           // Organization Validated
    CERT_TYPE_EV,           // Extended Validation
    CERT_TYPE_WILDCARD,     // Wildcard certificate
    CERT_TYPE_SELF_SIGNED   // Self-signed
} ssl_cert_type_t;

// SSL certificate information
typedef struct {
    char subject[SSL_CERT_MAX_DN_LEN];
    char issuer[SSL_CERT_MAX_DN_LEN];
    char serial_number[128];
    char fingerprint_sha1[SSL_CERT_MAX_FINGERPRINT_LEN];
    char fingerprint_sha256[SSL_CERT_MAX_FINGERPRINT_LEN];
    char common_name[256];
    char organization[256];
    char country[64];

    // Subject Alternative Names
    char **san_list;
    uint32_t san_count;

    // Validity period
    time_t not_before;
    time_t not_after;
    bool is_expired;
    bool is_self_signed;
    uint32_t days_until_expiry;

    // Certificate properties
    ssl_cert_type_t cert_type;
    uint32_t key_size;
    char public_key_algorithm[64];
    char signature_algorithm[128];

    // Extensions
    bool has_san;
    bool has_basic_constraints;
    bool has_key_usage;
    bool has_extended_key_usage;
    bool has_subject_key_id;
    bool has_authority_key_id;
    bool has_ct_precert_scts;  // Certificate Transparency
} ssl_cert_info_t;

// SSL certificate chain
typedef struct {
    ssl_cert_info_t *certificates;
    uint32_t cert_count;
    uint32_t max_depth;
    bool chain_valid;
    char chain_error[256];
} ssl_cert_chain_t;

// SSL connection information
typedef struct {
    char target_host[RECON_MAX_DOMAIN_LEN];
    char target_ip[INET6_ADDRSTRLEN];
    uint16_t target_port;

    ssl_protocol_version_t protocol;
    char cipher_suite[256];
    uint32_t cipher_bits;

    ssl_cert_chain_t cert_chain;

    bool supports_tls_1_3;
    bool supports_tls_1_2;
    bool supports_sni;
    bool supports_alpn;
    char alpn_protocols[512];

    uint32_t handshake_time_ms;
    time_t scan_timestamp;
} ssl_connection_info_t;

// SSL enumeration context
typedef struct {
    recon_context_t base_ctx;

    // Results
    ssl_connection_info_t *results;
    uint32_t result_count;
    uint32_t max_results;

    // Configuration
    bool enumerate_sans;
    bool enumerate_chain;
    bool check_ct_logs;
    bool verify_certificates;
    bool test_protocol_versions;
    bool test_cipher_suites;
    uint32_t connect_timeout_ms;

    // Certificate correlation
    char **unique_fingerprints;
    uint32_t unique_fingerprint_count;

    // Thread safety
    pthread_mutex_t results_mutex;

    // Statistics
    _Atomic uint32_t successful_connections;
    _Atomic uint32_t failed_connections;
    _Atomic uint32_t expired_certs;
    _Atomic uint32_t self_signed_certs;
} ssl_cert_enum_context_t;

// Function prototypes

// Initialization and cleanup
int ssl_cert_enum_init_context(ssl_cert_enum_context_t *ctx);
void ssl_cert_enum_cleanup_context(ssl_cert_enum_context_t *ctx);

// SSL connection and enumeration
int ssl_cert_enum_connect(ssl_cert_enum_context_t *ctx,
                          const char *host,
                          uint16_t port,
                          ssl_connection_info_t *info);
int ssl_cert_enum_scan_ip_range(ssl_cert_enum_context_t *ctx,
                                const char *ip_start,
                                const char *ip_end,
                                uint16_t port);

// Certificate extraction and analysis
int ssl_cert_extract_info(X509 *cert, ssl_cert_info_t *info);
int ssl_cert_extract_san_list(X509 *cert, char ***san_list, uint32_t *san_count);
int ssl_cert_extract_chain(SSL *ssl, ssl_cert_chain_t *chain);
int ssl_cert_calculate_fingerprint(X509 *cert, const EVP_MD *md, char *fingerprint, size_t max_len);

// Certificate correlation and matching
bool ssl_cert_fingerprints_match(const ssl_cert_info_t *cert1, const ssl_cert_info_t *cert2);
int ssl_cert_find_matching_certs(const ssl_cert_enum_context_t *ctx,
                                 const ssl_cert_info_t *reference_cert,
                                 ssl_connection_info_t **matches,
                                 uint32_t *match_count);
int ssl_cert_correlate_by_issuer(const ssl_cert_enum_context_t *ctx,
                                 const char *issuer,
                                 ssl_connection_info_t **matches,
                                 uint32_t *match_count);

// Origin IP discovery via certificate matching
int ssl_cert_find_origin_candidates(const ssl_cert_enum_context_t *ctx,
                                    const char *domain,
                                    const ssl_cert_info_t *cdn_cert,
                                    char **origin_ips,
                                    uint32_t *ip_count);

// Certificate Transparency integration
int ssl_cert_query_ct_logs(const char *domain, char ***cert_hashes, uint32_t *hash_count);
int ssl_cert_compare_with_ct_logs(const ssl_cert_info_t *cert, const char *domain);

// Protocol and cipher testing
int ssl_cert_test_protocols(const char *host, uint16_t port, bool *supported_protocols);
int ssl_cert_test_cipher_suites(const char *host, uint16_t port, char ***supported_ciphers, uint32_t *cipher_count);

// Result handling
void ssl_cert_print_info(const ssl_cert_info_t *info);
void ssl_cert_print_connection_info(const ssl_connection_info_t *info);
void ssl_cert_print_results(const ssl_cert_enum_context_t *ctx);
int ssl_cert_export_results_json(const ssl_cert_enum_context_t *ctx, const char *filename);

// Statistics
void ssl_cert_print_statistics(const ssl_cert_enum_context_t *ctx);

// Utility functions
const char *ssl_protocol_version_to_string(ssl_protocol_version_t version);
const char *ssl_cert_type_to_string(ssl_cert_type_t type);
bool ssl_cert_is_wildcard(const ssl_cert_info_t *cert);
bool ssl_cert_matches_domain(const ssl_cert_info_t *cert, const char *domain);

#endif // SSL_CERT_ENUM_H
