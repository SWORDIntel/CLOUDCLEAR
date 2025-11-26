/*
 * CloudClear - Offensive Cryptographic Analysis Implementation
 *
 * DSSSL fingerprinting and advanced crypto reconnaissance
 */

#include "crypto_offensive.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

// Initialize crypto offensive context
int crypto_offensive_init(crypto_offensive_context_t *ctx) {
    if (!ctx) return -1;

    memset(ctx, 0, sizeof(crypto_offensive_context_t));

    // Enable all detection features by default
    ctx->detect_pqc = true;
    ctx->detect_hardware_security = true;
    ctx->test_downgrade_attacks = true;
    ctx->test_cipher_weaknesses = true;
    ctx->detect_cert_pinning = true;
    ctx->analyze_side_channels = true;
    ctx->timeout_seconds = 30;

    // Allocate results
    ctx->max_results = 1000;
    ctx->results = calloc(ctx->max_results, sizeof(crypto_analysis_result_t));
    if (!ctx->results) return -1;

    // Initialize atomic counters
    atomic_store(&ctx->dsssl_targets_found, 0);
    atomic_store(&ctx->pqc_targets_found, 0);
    atomic_store(&ctx->vulnerable_targets, 0);
    atomic_store(&ctx->pinned_targets, 0);

    pthread_mutex_init(&ctx->results_mutex, NULL);

    return 0;
}

// Cleanup
void crypto_offensive_cleanup(crypto_offensive_context_t *ctx) {
    if (!ctx) return;

    if (ctx->results) {
        free(ctx->results);
    }

    pthread_mutex_destroy(&ctx->results_mutex);
}

// Main analysis function
int crypto_offensive_analyze_target(crypto_offensive_context_t *ctx,
                                    const char *host,
                                    uint16_t port,
                                    crypto_analysis_result_t *result) {
    if (!ctx || !host || !result) return -1;

    memset(result, 0, sizeof(crypto_analysis_result_t));
    strncpy(result->target_host, host, RECON_MAX_DOMAIN_LEN - 1);
    result->target_port = port;
    result->scan_timestamp = time(NULL);

    printf("[CRYPTO OFFENSIVE] Analyzing %s:%u\n", host, port);

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Create SSL context
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ssl_ctx = SSL_CTX_new(method);
    if (!ssl_ctx) {
        fprintf(stderr, "[CRYPTO] Failed to create SSL context\n");
        return -1;
    }

    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        SSL_CTX_free(ssl_ctx);
        return -1;
    }

    // Set socket timeout
    struct timeval tv = {.tv_sec = ctx->timeout_seconds, .tv_usec = 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    // Resolve host
    struct hostent *he = gethostbyname(host);
    if (!he) {
        close(sock);
        SSL_CTX_free(ssl_ctx);
        return -1;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    memcpy(&server_addr.sin_addr, he->h_addr_list[0], he->h_length);
    inet_ntop(AF_INET, &server_addr.sin_addr, result->target_ip, INET6_ADDRSTRLEN);

    // Connect
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "[CRYPTO] Connection failed to %s:%u\n", host, port);
        close(sock);
        SSL_CTX_free(ssl_ctx);
        return -1;
    }

    // Create SSL connection
    SSL *ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        close(sock);
        SSL_CTX_free(ssl_ctx);
        return -1;
    }

    SSL_set_fd(ssl, sock);
    SSL_set_tlsext_host_name(ssl, host);  // SNI

    // Perform SSL handshake
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "[CRYPTO] SSL handshake failed\n");
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ssl_ctx);
        return -1;
    }

    printf("[CRYPTO] SSL connection established\n");

    // Get TLS version
    result->negotiated_tls_version = SSL_version(ssl);

    // Get cipher info
    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    if (cipher) {
        const char *cipher_name = SSL_CIPHER_get_name(cipher);
        strncpy(result->negotiated_cipher, cipher_name, sizeof(result->negotiated_cipher) - 1);
        result->cipher_bits = SSL_CIPHER_get_bits(cipher, NULL);
        printf("[CRYPTO] Cipher: %s (%u bits)\n", cipher_name, result->cipher_bits);
    }

    // Detect implementation type
    result->implementation = crypto_detect_implementation(ssl);
    printf("[CRYPTO] Implementation: %s\n", crypto_impl_type_to_string(result->implementation));

    // Detect DSSSL specifically
    if (ctx->detect_pqc) {
        result->dsssl_detected = crypto_detect_dsssl(ssl, result->dsssl_security_profile,
                                                     sizeof(result->dsssl_security_profile));
        if (result->dsssl_detected) {
            printf("[CRYPTO] ✓ DSSSL DETECTED - Profile: %s\n", result->dsssl_security_profile);
            atomic_fetch_add(&ctx->dsssl_targets_found, 1);
        }
    }

    // Generate TLS fingerprint
    crypto_generate_tls_fingerprint(ssl, &result->tls_fingerprint);

    // Detect post-quantum crypto
    if (ctx->detect_pqc) {
        if (crypto_detect_pqc(ssl, &result->pqc_detection) == 0 && result->pqc_detection.pqc_detected) {
            printf("[CRYPTO] ✓ Post-Quantum Crypto DETECTED\n");
            for (uint32_t i = 0; i < result->pqc_detection.algorithm_count; i++) {
                printf("  Algorithm: %s\n",
                       pqc_algorithm_to_string(result->pqc_detection.detected_algorithms[i]));
            }
            atomic_fetch_add(&ctx->pqc_targets_found, 1);
        }
    }

    // Analyze weaknesses
    if (ctx->test_cipher_weaknesses) {
        crypto_analyze_weaknesses(ssl, &result->weaknesses);
        if (result->weaknesses.weak_cipher_detected) {
            printf("[CRYPTO] ⚠ Weak ciphers detected: %s\n", result->weaknesses.weak_ciphers);
            atomic_fetch_add(&ctx->vulnerable_targets, 1);
        }
    }

    // Test downgrade attacks
    if (ctx->test_downgrade_attacks) {
        uint16_t downgraded_version;
        result->weaknesses.downgrade_attack_possible =
            crypto_test_downgrade_attack(host, port, &downgraded_version);
        if (result->weaknesses.downgrade_attack_possible) {
            printf("[CRYPTO] ⚠ Downgrade attack possible to TLS %u.%u\n",
                   downgraded_version >> 8, downgraded_version & 0xFF);
        }
    }

    // Detect certificate pinning
    if (ctx->detect_cert_pinning) {
        crypto_detect_cert_pinning(host, port, &result->cert_pinning);
        if (result->cert_pinning.pinning_detected) {
            printf("[CRYPTO] Certificate pinning detected: %s\n", result->cert_pinning.pinning_type);
            atomic_fetch_add(&ctx->pinned_targets, 1);
        }
    }

    // Calculate security score
    result->security_score = crypto_calculate_security_score(result);
    crypto_generate_security_assessment(result, result->security_assessment,
                                       sizeof(result->security_assessment));

    printf("[CRYPTO] Security Score: %.1f/100.0\n", result->security_score);

    // Cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ssl_ctx);

    return 0;
}

// Detect crypto implementation
crypto_impl_type_t crypto_detect_implementation(SSL *ssl) {
    if (!ssl) return CRYPTO_IMPL_UNKNOWN;

    // Get SSL version string
    const char *version = SSL_get_version(ssl);

    // Check for DSSSL markers
    // DSSSL typically has specific version strings or cipher preferences
    if (strstr(version, "DSSSL") || strstr(version, "DSMIL")) {
        return CRYPTO_IMPL_DSSSL;
    }

    // Check for BoringSSL
    #ifdef OPENSSL_IS_BORINGSSL
    return CRYPTO_IMPL_BORINGSSL;
    #endif

    // Check for LibreSSL
    #ifdef LIBRESSL_VERSION_NUMBER
    return CRYPTO_IMPL_LIBRESSL;
    #endif

    // Default to standard OpenSSL
    return CRYPTO_IMPL_STANDARD_OPENSSL;
}

// Detect DSSSL specifically
bool crypto_detect_dsssl(SSL *ssl, char *security_profile, size_t profile_len) {
    if (!ssl || !security_profile) return false;

    // DSSSL detection heuristics:
    // 1. Check for post-quantum cipher suites
    // 2. Check for TPM integration markers
    // 3. Analyze cipher suite preferences
    // 4. Check for DSMIL-specific extensions

    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    if (!cipher) return false;

    const char *cipher_name = SSL_CIPHER_get_name(cipher);

    // DSSSL typically uses specific cipher naming or PQC algorithms
    if (strstr(cipher_name, "ML-KEM") || strstr(cipher_name, "ML-DSA") ||
        strstr(cipher_name, "DSMIL") || strstr(cipher_name, "ATOMAL")) {

        // Try to detect security profile from cipher configuration
        if (strstr(cipher_name, "ATOMAL")) {
            strncpy(security_profile, "ATOMAL (Maximum Security)", profile_len - 1);
        } else if (strstr(cipher_name, "DSMIL")) {
            strncpy(security_profile, "DSMIL_SECURE (Hybrid PQC)", profile_len - 1);
        } else {
            strncpy(security_profile, "WORLD_COMPAT (Baseline)", profile_len - 1);
        }
        return true;
    }

    return false;
}

// Detect post-quantum crypto
int crypto_detect_pqc(SSL *ssl, pqc_detection_t *result) {
    if (!ssl || !result) return -1;

    memset(result, 0, sizeof(pqc_detection_t));

    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    if (!cipher) return -1;

    const char *cipher_name = SSL_CIPHER_get_name(cipher);

    // Check for PQC algorithms in cipher name
    if (strstr(cipher_name, "ML-KEM") || strstr(cipher_name, "KYBER")) {
        result->pqc_detected = true;
        if (strstr(cipher_name, "512")) {
            result->detected_algorithms[result->algorithm_count++] = PQC_ML_KEM_512;
        } else if (strstr(cipher_name, "768")) {
            result->detected_algorithms[result->algorithm_count++] = PQC_ML_KEM_768;
        } else if (strstr(cipher_name, "1024")) {
            result->detected_algorithms[result->algorithm_count++] = PQC_ML_KEM_1024;
        }
    }

    if (strstr(cipher_name, "ML-DSA") || strstr(cipher_name, "DILITHIUM")) {
        result->pqc_detected = true;
        if (strstr(cipher_name, "44")) {
            result->detected_algorithms[result->algorithm_count++] = PQC_ML_DSA_44;
        } else if (strstr(cipher_name, "65")) {
            result->detected_algorithms[result->algorithm_count++] = PQC_ML_DSA_65;
        } else if (strstr(cipher_name, "87")) {
            result->detected_algorithms[result->algorithm_count++] = PQC_ML_DSA_87;
        }
    }

    // Check for hybrid mode (classical + PQC)
    if (result->pqc_detected && (strstr(cipher_name, "ECDHE") || strstr(cipher_name, "RSA"))) {
        result->hybrid_mode = true;
        strncpy(result->classical_algorithm, "ECDHE-RSA", sizeof(result->classical_algorithm) - 1);
    }

    if (result->pqc_detected) {
        result->quantum_resistance_score = crypto_calculate_quantum_resistance(result);
    }

    return 0;
}

// Calculate quantum resistance score
float crypto_calculate_quantum_resistance(const pqc_detection_t *pqc) {
    if (!pqc || !pqc->pqc_detected) return 0.0f;

    float score = 0.0f;

    // Base score for having PQC
    score += 0.5f;

    // Additional score for algorithm strength
    for (uint32_t i = 0; i < pqc->algorithm_count; i++) {
        switch (pqc->detected_algorithms[i]) {
            case PQC_ML_KEM_512:
            case PQC_ML_DSA_44:
                score += 0.1f;
                break;
            case PQC_ML_KEM_768:
            case PQC_ML_DSA_65:
                score += 0.15f;
                break;
            case PQC_ML_KEM_1024:
            case PQC_ML_DSA_87:
                score += 0.2f;
                break;
            default:
                break;
        }
    }

    // Bonus for hybrid mode
    if (pqc->hybrid_mode) {
        score += 0.1f;
    }

    return (score > 1.0f) ? 1.0f : score;
}

// Generate TLS fingerprint
int crypto_generate_tls_fingerprint(SSL *ssl, tls_fingerprint_t *fingerprint) {
    if (!ssl || !fingerprint) return -1;

    memset(fingerprint, 0, sizeof(tls_fingerprint_t));

    // Get TLS version
    fingerprint->tls_version = SSL_version(ssl);

    // Get cipher suites (simplified)
    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    if (cipher) {
        strncpy(fingerprint->cipher_suites, SSL_CIPHER_get_name(cipher),
                sizeof(fingerprint->cipher_suites) - 1);
    }

    // Check for SNI support
    fingerprint->supports_sni = true;  // Simplified

    // Generate JA3-like fingerprint
    snprintf(fingerprint->fingerprint, sizeof(fingerprint->fingerprint),
             "%u_%s", fingerprint->tls_version, fingerprint->cipher_suites);

    return 0;
}

// Analyze weaknesses
int crypto_analyze_weaknesses(SSL *ssl, crypto_weakness_t *weaknesses) {
    if (!ssl || !weaknesses) return -1;

    memset(weaknesses, 0, sizeof(crypto_weakness_t));

    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    if (!cipher) return -1;

    const char *cipher_name = SSL_CIPHER_get_name(cipher);

    // Check for weak ciphers
    if (crypto_is_cipher_weak(cipher_name)) {
        weaknesses->weak_cipher_detected = true;
        strncpy(weaknesses->weak_ciphers, cipher_name, sizeof(weaknesses->weak_ciphers) - 1);
    }

    // Check TLS version
    int version = SSL_version(ssl);
    if (version < TLS1_2_VERSION) {
        weaknesses->poodle_vulnerable = true;
        strcat(weaknesses->detected_vulnerabilities, "POODLE (CVE-2014-3566); ");
    }

    return 0;
}

// Check if cipher is weak
bool crypto_is_cipher_weak(const char *cipher_name) {
    if (!cipher_name) return false;

    // Check for known weak ciphers
    const char *weak_patterns[] = {
        "NULL", "EXP", "DES", "RC4", "MD5", "ANON", "ADH", "AECDH", NULL
    };

    for (int i = 0; weak_patterns[i] != NULL; i++) {
        if (strcasestr(cipher_name, weak_patterns[i])) {
            return true;
        }
    }

    return false;
}

// Test downgrade attack
bool crypto_test_downgrade_attack(const char *host, uint16_t port, uint16_t *downgraded_version) {
    // Simplified - would actually attempt connections with older TLS versions
    // and check if server accepts them
    (void)host; (void)port; (void)downgraded_version;
    return false;
}

// Detect certificate pinning
int crypto_detect_cert_pinning(const char *host, uint16_t port, cert_pinning_t *result) {
    if (!host || !result) return -1;

    memset(result, 0, sizeof(cert_pinning_t));

    // Simplified detection - would check HTTP headers (HPKP) and
    // attempt certificate swapping to detect pinning
    (void)port;
    result->pinning_detected = false;

    return 0;
}

// Calculate security score
float crypto_calculate_security_score(const crypto_analysis_result_t *result) {
    if (!result) return 0.0f;

    float score = 100.0f;

    // Deduct for weak implementation
    if (result->implementation == CRYPTO_IMPL_STANDARD_OPENSSL) {
        score -= 5.0f;
    } else if (result->implementation == CRYPTO_IMPL_DSSSL) {
        score += 10.0f;  // Bonus for hardened implementation
    }

    // Deduct for weak ciphers
    if (result->weaknesses.weak_cipher_detected) {
        score -= 30.0f;
    }

    // Deduct for vulnerabilities
    if (result->weaknesses.heartbleed_vulnerable) score -= 40.0f;
    if (result->weaknesses.poodle_vulnerable) score -= 25.0f;
    if (result->weaknesses.downgrade_attack_possible) score -= 20.0f;

    // Bonus for PQC
    if (result->pqc_detection.pqc_detected) {
        score += result->pqc_detection.quantum_resistance_score * 20.0f;
    }

    // Bonus for certificate pinning
    if (result->cert_pinning.pinning_detected) {
        score += 10.0f;
    }

    return (score < 0.0f) ? 0.0f : (score > 100.0f) ? 100.0f : score;
}

// Generate security assessment
void crypto_generate_security_assessment(const crypto_analysis_result_t *result,
                                         char *assessment, size_t max_len) {
    if (!result || !assessment) return;

    if (result->security_score >= 90.0f) {
        snprintf(assessment, max_len, "EXCELLENT: Hardened crypto with PQC support");
    } else if (result->security_score >= 70.0f) {
        snprintf(assessment, max_len, "GOOD: Strong crypto configuration");
    } else if (result->security_score >= 50.0f) {
        snprintf(assessment, max_len, "FAIR: Moderate security with some weaknesses");
    } else if (result->security_score >= 30.0f) {
        snprintf(assessment, max_len, "POOR: Multiple vulnerabilities detected");
    } else {
        snprintf(assessment, max_len, "CRITICAL: Severely vulnerable crypto configuration");
    }
}

// Print analysis result
void crypto_print_analysis_result(const crypto_analysis_result_t *result) {
    if (!result) return;

    printf("\n=== Cryptographic Analysis Report ===\n");
    printf("Target: %s:%u (%s)\n", result->target_host, result->target_port, result->target_ip);
    printf("\nImplementation: %s\n", crypto_impl_type_to_string(result->implementation));

    if (result->dsssl_detected) {
        printf("✓ DSSSL Detected - Profile: %s\n", result->dsssl_security_profile);
    }

    printf("\nTLS Version: 0x%04X\n", result->negotiated_tls_version);
    printf("Cipher: %s (%u bits)\n", result->negotiated_cipher, result->cipher_bits);

    if (result->pqc_detection.pqc_detected) {
        printf("\n✓ Post-Quantum Crypto Detected:\n");
        for (uint32_t i = 0; i < result->pqc_detection.algorithm_count; i++) {
            printf("  - %s\n", pqc_algorithm_to_string(result->pqc_detection.detected_algorithms[i]));
        }
        printf("  Quantum Resistance: %.0f%%\n", result->pqc_detection.quantum_resistance_score * 100);
    }

    if (result->weaknesses.weak_cipher_detected) {
        printf("\n⚠ Weak Ciphers: %s\n", result->weaknesses.weak_ciphers);
    }

    printf("\nSecurity Score: %.1f/100.0\n", result->security_score);
    printf("Assessment: %s\n", result->security_assessment);
    printf("=====================================\n\n");
}

// Utility: Implementation type to string
const char *crypto_impl_type_to_string(crypto_impl_type_t type) {
    switch (type) {
        case CRYPTO_IMPL_STANDARD_OPENSSL: return "Standard OpenSSL";
        case CRYPTO_IMPL_DSSSL: return "DSSSL (Hardened)";
        case CRYPTO_IMPL_BORINGSSL: return "BoringSSL";
        case CRYPTO_IMPL_LIBRESSL: return "LibreSSL";
        case CRYPTO_IMPL_MBEDTLS: return "Mbed TLS";
        case CRYPTO_IMPL_WOLFSSL: return "wolfSSL";
        case CRYPTO_IMPL_CUSTOM: return "Custom Implementation";
        default: return "Unknown";
    }
}

// Utility: PQC algorithm to string
const char *pqc_algorithm_to_string(pqc_algorithm_t alg) {
    switch (alg) {
        case PQC_ML_KEM_512: return "ML-KEM-512 (Kyber-512)";
        case PQC_ML_KEM_768: return "ML-KEM-768 (Kyber-768)";
        case PQC_ML_KEM_1024: return "ML-KEM-1024 (Kyber-1024)";
        case PQC_ML_DSA_44: return "ML-DSA-44 (Dilithium Level 2)";
        case PQC_ML_DSA_65: return "ML-DSA-65 (Dilithium Level 3)";
        case PQC_ML_DSA_87: return "ML-DSA-87 (Dilithium Level 5)";
        case PQC_FALCON_512: return "Falcon-512";
        case PQC_FALCON_1024: return "Falcon-1024";
        case PQC_SPHINCS_PLUS: return "SPHINCS+";
        default: return "Unknown PQC Algorithm";
    }
}

// Print summary
void crypto_print_summary(const crypto_offensive_context_t *ctx) {
    if (!ctx) return;

    printf("\n=== Offensive Crypto Analysis Summary ===\n");
    printf("Targets Scanned: %u\n", ctx->result_count);
    printf("DSSSL Implementations: %u\n", atomic_load(&ctx->dsssl_targets_found));
    printf("Post-Quantum Crypto: %u\n", atomic_load(&ctx->pqc_targets_found));
    printf("Vulnerable Targets: %u\n", atomic_load(&ctx->vulnerable_targets));
    printf("Pinned Certificates: %u\n", atomic_load(&ctx->pinned_targets));
    printf("=========================================\n\n");
}
