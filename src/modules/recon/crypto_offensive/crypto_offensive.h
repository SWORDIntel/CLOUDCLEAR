/*
 * CloudClear - Offensive Cryptographic Analysis Module
 *
 * DSSSL-based detection and offensive crypto reconnaissance
 * Identifies hardened cryptographic implementations, post-quantum crypto,
 * and advanced security measures for bypass and analysis
 *
 * Detection Capabilities:
 * - DSSSL/hardened OpenSSL fingerprinting
 * - Post-quantum cryptography detection (ML-KEM, ML-DSA, Kyber, Dilithium)
 * - TPM 2.0 hardware security identification
 * - Certificate pinning detection and bypass
 * - Crypto downgrade attack opportunities
 * - Side-channel vulnerability analysis
 * - Cipher suite weakness identification
 * - TLS fingerprinting for origin discovery
 */

#ifndef CRYPTO_OFFENSIVE_H
#define CRYPTO_OFFENSIVE_H

#include "../common/recon_common.h"
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdint.h>

// Post-Quantum Crypto Algorithm Types
typedef enum {
    PQC_NONE,
    PQC_ML_KEM_512,           // NIST ML-KEM (Kyber) 512-bit
    PQC_ML_KEM_768,           // NIST ML-KEM (Kyber) 768-bit
    PQC_ML_KEM_1024,          // NIST ML-KEM (Kyber) 1024-bit
    PQC_ML_DSA_44,            // NIST ML-DSA (Dilithium) Level 2
    PQC_ML_DSA_65,            // NIST ML-DSA (Dilithium) Level 3
    PQC_ML_DSA_87,            // NIST ML-DSA (Dilithium) Level 5
    PQC_FALCON_512,           // Falcon 512
    PQC_FALCON_1024,          // Falcon 1024
    PQC_SPHINCS_PLUS,         // SPHINCS+
    PQC_UNKNOWN
} pqc_algorithm_t;

// Crypto Implementation Type
typedef enum {
    CRYPTO_IMPL_STANDARD_OPENSSL,
    CRYPTO_IMPL_DSSSL,                // DSSSL-hardened
    CRYPTO_IMPL_BORINGSSL,            // Google BoringSSL
    CRYPTO_IMPL_LIBRESSL,             // LibreSSL
    CRYPTO_IMPL_MBEDTLS,              // Mbed TLS
    CRYPTO_IMPL_WOLFSSL,              // wolfSSL
    CRYPTO_IMPL_CUSTOM,
    CRYPTO_IMPL_UNKNOWN
} crypto_impl_type_t;

// Hardware Security Detection
typedef struct {
    bool tpm_detected;
    char tpm_version[32];             // TPM 1.2 or 2.0
    bool secure_enclave_detected;     // iOS/macOS Secure Enclave
    bool sgx_detected;                // Intel SGX
    bool hsm_detected;                // Hardware Security Module
    char hsm_vendor[128];
    bool hardware_rng_detected;       // Hardware RNG
} hardware_security_t;

// TLS Fingerprint
typedef struct {
    char fingerprint[256];            // JA3/JA3S hash
    uint16_t tls_version;
    char cipher_suites[1024];
    char extensions[1024];
    char supported_groups[512];
    char signature_algorithms[512];
    bool supports_sni;
    bool supports_alpn;
    bool supports_session_tickets;
    bool supports_extended_master_secret;
} tls_fingerprint_t;

// Crypto Weakness Detection
typedef struct {
    bool weak_cipher_detected;
    char weak_ciphers[512];
    bool downgrade_attack_possible;
    bool heartbleed_vulnerable;       // CVE-2014-0160
    bool poodle_vulnerable;           // CVE-2014-3566
    bool freak_vulnerable;            // CVE-2015-0204
    bool logjam_vulnerable;           // CVE-2015-4000
    bool drown_vulnerable;            // CVE-2016-0800
    bool sweet32_vulnerable;          // CVE-2016-2183
    bool robot_vulnerable;            // CVE-2017-13099
    char detected_vulnerabilities[1024];
} crypto_weakness_t;

// Certificate Pinning Detection
typedef struct {
    bool pinning_detected;
    char pinning_type[64];            // HPKP, Certificate, Public Key
    char pinned_hashes[1024];
    bool bypass_possible;
    char bypass_method[256];
    uint32_t pin_count;
} cert_pinning_t;

// Post-Quantum Crypto Detection Result
typedef struct {
    bool pqc_detected;
    pqc_algorithm_t detected_algorithms[10];
    uint32_t algorithm_count;
    bool hybrid_mode;                 // Hybrid classical + PQC
    char classical_algorithm[128];
    float quantum_resistance_score;   // 0.0-1.0
} pqc_detection_t;

// Comprehensive Crypto Analysis Result
typedef struct {
    char target_host[RECON_MAX_DOMAIN_LEN];
    char target_ip[INET6_ADDRSTRLEN];
    uint16_t target_port;

    // Implementation detection
    crypto_impl_type_t implementation;
    char implementation_version[128];
    bool dsssl_detected;
    char dsssl_security_profile[64];  // WORLD_COMPAT, DSMIL_SECURE, ATOMAL

    // TLS analysis
    tls_fingerprint_t tls_fingerprint;
    uint16_t negotiated_tls_version;
    char negotiated_cipher[256];
    uint32_t cipher_bits;

    // Post-quantum crypto
    pqc_detection_t pqc_detection;

    // Hardware security
    hardware_security_t hardware_security;

    // Weaknesses
    crypto_weakness_t weaknesses;

    // Certificate pinning
    cert_pinning_t cert_pinning;

    // Side-channel analysis
    bool timing_attack_vulnerable;
    bool cache_timing_vulnerable;
    bool power_analysis_vulnerable;

    // Overall security score
    float security_score;              // 0.0-100.0
    char security_assessment[512];

    time_t scan_timestamp;
} crypto_analysis_result_t;

// Crypto Offensive Context
typedef struct {
    recon_context_t base_ctx;

    // Configuration
    bool detect_pqc;
    bool detect_hardware_security;
    bool test_downgrade_attacks;
    bool test_cipher_weaknesses;
    bool detect_cert_pinning;
    bool analyze_side_channels;
    uint32_t timeout_seconds;

    // Results
    crypto_analysis_result_t *results;
    uint32_t result_count;
    uint32_t max_results;

    // Statistics
#ifdef _WIN32
    volatile uint32_t dsssl_targets_found;
    volatile uint32_t pqc_targets_found;
    volatile uint32_t vulnerable_targets;
    volatile uint32_t pinned_targets;
#else
    _Atomic uint32_t dsssl_targets_found;
    _Atomic uint32_t pqc_targets_found;
    _Atomic uint32_t vulnerable_targets;
    _Atomic uint32_t pinned_targets;
#endif

    pthread_mutex_t results_mutex;
} crypto_offensive_context_t;

// Function Prototypes

// Initialization and cleanup
int crypto_offensive_init(crypto_offensive_context_t *ctx);
void crypto_offensive_cleanup(crypto_offensive_context_t *ctx);

// Main analysis functions
int crypto_offensive_analyze_target(crypto_offensive_context_t *ctx,
                                    const char *host,
                                    uint16_t port,
                                    crypto_analysis_result_t *result);

// Implementation detection
crypto_impl_type_t crypto_detect_implementation(SSL *ssl);
bool crypto_detect_dsssl(SSL *ssl, char *security_profile, size_t profile_len);
bool crypto_detect_boringssl(SSL *ssl);
bool crypto_detect_libressl(SSL *ssl);

// Post-quantum crypto detection
int crypto_detect_pqc(SSL *ssl, pqc_detection_t *result);
bool crypto_is_pqc_algorithm(const char *algorithm_name);
pqc_algorithm_t crypto_identify_pqc_algorithm(const char *name);
float crypto_calculate_quantum_resistance(const pqc_detection_t *pqc);

// TLS fingerprinting
int crypto_generate_tls_fingerprint(SSL *ssl, tls_fingerprint_t *fingerprint);
int crypto_generate_ja3_hash(const tls_fingerprint_t *fp, char *hash, size_t hash_len);
int crypto_compare_tls_fingerprints(const tls_fingerprint_t *fp1,
                                    const tls_fingerprint_t *fp2);

// Hardware security detection
int crypto_detect_hardware_security(const char *host, hardware_security_t *result);
bool crypto_detect_tpm(const char *host);
bool crypto_detect_sgx(const char *host);
bool crypto_detect_secure_enclave(const char *host);

// Weakness detection
int crypto_analyze_weaknesses(SSL *ssl, crypto_weakness_t *weaknesses);
bool crypto_test_heartbleed(const char *host, uint16_t port);
bool crypto_test_poodle(SSL *ssl);
bool crypto_test_freak(SSL *ssl);
bool crypto_test_logjam(SSL *ssl);
bool crypto_test_drown(const char *host, uint16_t port);
bool crypto_test_robot(SSL *ssl);

// Downgrade attack testing
bool crypto_test_downgrade_attack(const char *host, uint16_t port,
                                  uint16_t *downgraded_version);
bool crypto_test_cipher_downgrade(SSL *ssl, char *weak_cipher, size_t cipher_len);

// Certificate pinning
int crypto_detect_cert_pinning(const char *host, uint16_t port, cert_pinning_t *result);
bool crypto_test_pin_bypass(const char *host, uint16_t port, const cert_pinning_t *pinning);

// Side-channel analysis
bool crypto_test_timing_attack(const char *host, uint16_t port);
bool crypto_analyze_constant_time_ops(SSL *ssl);

// Cipher suite analysis
int crypto_enumerate_cipher_suites(SSL *ssl, char ***cipher_list, uint32_t *count);
int crypto_identify_weak_ciphers(const char **cipher_list, uint32_t count,
                                 char **weak_ciphers, uint32_t *weak_count);
bool crypto_is_cipher_weak(const char *cipher_name);

// Security scoring
float crypto_calculate_security_score(const crypto_analysis_result_t *result);
void crypto_generate_security_assessment(const crypto_analysis_result_t *result,
                                         char *assessment, size_t max_len);

// Result handling
void crypto_print_analysis_result(const crypto_analysis_result_t *result);
void crypto_print_summary(const crypto_offensive_context_t *ctx);
int crypto_export_results_json(const crypto_offensive_context_t *ctx, const char *filename);

// Bypass recommendations
int crypto_generate_bypass_recommendations(const crypto_analysis_result_t *result,
                                          char **recommendations,
                                          uint32_t *recommendation_count);

// Utility functions
const char *crypto_impl_type_to_string(crypto_impl_type_t type);
const char *pqc_algorithm_to_string(pqc_algorithm_t alg);
bool crypto_version_vulnerable(const char *version, const char *cve_id);

#endif // CRYPTO_OFFENSIVE_H
