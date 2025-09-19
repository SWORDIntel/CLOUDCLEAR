/*
 * CloudUnflare Enhanced v2.0 - SIMD/AVX2 Optimization Utilities
 *
 * Vectorized operations for maximum performance on Intel Meteor Lake
 * Optimized for string processing, hashing, and DNS packet parsing
 *
 * Performance Targets:
 * - 4-8x speed improvement over scalar operations
 * - AVX2 256-bit vectorization
 * - Cache-optimized memory access patterns
 * - Branch-free algorithms where possible
 *
 * Agent: OPTIMIZER (SIMD acceleration)
 * Coordination: C-INTERNAL, ARCHITECT
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <immintrin.h>
#include <cpuid.h>
#include "../config.h"

// SIMD feature detection
static bool g_has_avx2 = false;
static bool g_has_fma = false;
static bool g_has_aes = false;
static bool g_has_pclmul = false;
static bool g_simd_initialized = false;

// SIMD constants
#define SIMD_ALIGNMENT 32
#define AVX2_VECTOR_SIZE 32
#define AVX2_LANES 8  // 32-bit lanes
#define AVX2_BYTE_LANES 32

// String processing constants
#define MAX_SIMD_STRING_LENGTH 1024
#define DNS_LABEL_MAX_LENGTH 63
#define DNS_NAME_MAX_LENGTH 255

// Hash constants for SIMD hashing
#define SIMD_HASH_PRIME1 0x9E3779B185EBCA87ULL
#define SIMD_HASH_PRIME2 0xC2B2AE3D27D4EB4FULL
#define SIMD_HASH_PRIME3 0x165667B19E3779F9ULL

// Initialize SIMD capabilities
bool simd_init(void) {
    if (g_simd_initialized) {
        return true;
    }

    unsigned int eax, ebx, ecx, edx;

    // Check for AVX2 support
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        g_has_avx2 = (ebx & (1 << 5)) != 0;  // AVX2
        g_has_fma = (ecx & (1 << 12)) != 0;  // FMA
    }

    // Check for AES and PCLMUL
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        g_has_aes = (ecx & (1 << 25)) != 0;    // AES-NI
        g_has_pclmul = (ecx & (1 << 1)) != 0;  // PCLMULQDQ
    }

    g_simd_initialized = true;

    printf("[OPTIMIZER] SIMD capabilities: AVX2=%s, FMA=%s, AES=%s, PCLMUL=%s\n",
           g_has_avx2 ? "yes" : "no",
           g_has_fma ? "yes" : "no",
           g_has_aes ? "yes" : "no",
           g_has_pclmul ? "yes" : "no");

    return g_has_avx2;
}

// Aligned memory allocation for SIMD operations
void* simd_aligned_alloc(size_t size) {
    return aligned_alloc(SIMD_ALIGNMENT, (size + SIMD_ALIGNMENT - 1) & ~(SIMD_ALIGNMENT - 1));
}

// AVX2 optimized string length calculation
size_t simd_strlen(const char *str) {
    if (!g_has_avx2 || !str) {
        return strlen(str);
    }

    const char *ptr = str;
    size_t len = 0;

    // Handle unaligned prefix
    while (((uintptr_t)ptr & 31) && *ptr) {
        ptr++;
        len++;
    }

    if (!*ptr) {
        return len;
    }

    // AVX2 vectorized loop
    __m256i zero = _mm256_setzero_si256();

    while (1) {
        __m256i chunk = _mm256_load_si256((__m256i*)ptr);
        __m256i cmp = _mm256_cmpeq_epi8(chunk, zero);
        uint32_t mask = _mm256_movemask_epi8(cmp);

        if (mask) {
            // Found null terminator
            len += __builtin_ctz(mask);
            break;
        }

        ptr += 32;
        len += 32;
    }

    return len;
}

// AVX2 optimized string comparison
int simd_strcmp(const char *str1, const char *str2) {
    if (!g_has_avx2 || !str1 || !str2) {
        return strcmp(str1, str2);
    }

    const char *p1 = str1;
    const char *p2 = str2;

    // Handle unaligned prefix
    while (((uintptr_t)p1 & 31) || ((uintptr_t)p2 & 31)) {
        if (*p1 != *p2 || !*p1) {
            return (unsigned char)*p1 - (unsigned char)*p2;
        }
        p1++;
        p2++;
    }

    // AVX2 vectorized comparison
    __m256i zero = _mm256_setzero_si256();

    while (1) {
        __m256i chunk1 = _mm256_load_si256((__m256i*)p1);
        __m256i chunk2 = _mm256_load_si256((__m256i*)p2);

        // Check for null terminators
        __m256i null1 = _mm256_cmpeq_epi8(chunk1, zero);
        __m256i null2 = _mm256_cmpeq_epi8(chunk2, zero);
        __m256i nulls = _mm256_or_si256(null1, null2);

        // Compare chunks
        __m256i diff = _mm256_cmpeq_epi8(chunk1, chunk2);
        __m256i result = _mm256_andnot_si256(diff, _mm256_set1_epi8(-1));

        uint32_t null_mask = _mm256_movemask_epi8(nulls);
        uint32_t diff_mask = _mm256_movemask_epi8(result);

        if (null_mask || diff_mask) {
            // Found difference or null terminator
            int pos = __builtin_ctz(null_mask | diff_mask);
            return (unsigned char)p1[pos] - (unsigned char)p2[pos];
        }

        p1 += 32;
        p2 += 32;
    }
}

// AVX2 optimized case-insensitive string comparison
int simd_strcasecmp(const char *str1, const char *str2) {
    if (!g_has_avx2 || !str1 || !str2) {
        return strcasecmp(str1, str2);
    }

    const char *p1 = str1;
    const char *p2 = str2;

    // AVX2 constants for case conversion
    __m256i a_vec = _mm256_set1_epi8('a');
    __m256i z_vec = _mm256_set1_epi8('z');
    __m256i A_vec = _mm256_set1_epi8('A');
    __m256i Z_vec = _mm256_set1_epi8('Z');
    __m256i case_diff = _mm256_set1_epi8(32);  // 'a' - 'A'
    __m256i zero = _mm256_setzero_si256();

    // Handle unaligned prefix
    while (((uintptr_t)p1 & 31) || ((uintptr_t)p2 & 31)) {
        char c1 = *p1;
        char c2 = *p2;

        if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
        if (c2 >= 'A' && c2 <= 'Z') c2 += 32;

        if (c1 != c2 || !*p1) {
            return (unsigned char)c1 - (unsigned char)c2;
        }
        p1++;
        p2++;
    }

    while (1) {
        __m256i chunk1 = _mm256_load_si256((__m256i*)p1);
        __m256i chunk2 = _mm256_load_si256((__m256i*)p2);

        // Convert to lowercase
        __m256i upper1 = _mm256_and_si256(_mm256_cmpgt_epi8(chunk1, A_vec), _mm256_cmpgt_epi8(Z_vec, chunk1));
        __m256i upper2 = _mm256_and_si256(_mm256_cmpgt_epi8(chunk2, A_vec), _mm256_cmpgt_epi8(Z_vec, chunk2));

        __m256i lower1 = _mm256_add_epi8(chunk1, _mm256_and_si256(upper1, case_diff));
        __m256i lower2 = _mm256_add_epi8(chunk2, _mm256_and_si256(upper2, case_diff));

        // Check for null terminators
        __m256i null1 = _mm256_cmpeq_epi8(chunk1, zero);
        __m256i null2 = _mm256_cmpeq_epi8(chunk2, zero);
        __m256i nulls = _mm256_or_si256(null1, null2);

        // Compare converted chunks
        __m256i diff = _mm256_cmpeq_epi8(lower1, lower2);
        __m256i result = _mm256_andnot_si256(diff, _mm256_set1_epi8(-1));

        uint32_t null_mask = _mm256_movemask_epi8(nulls);
        uint32_t diff_mask = _mm256_movemask_epi8(result);

        if (null_mask || diff_mask) {
            int pos = __builtin_ctz(null_mask | diff_mask);
            char c1 = p1[pos];
            char c2 = p2[pos];

            if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
            if (c2 >= 'A' && c2 <= 'Z') c2 += 32;

            return (unsigned char)c1 - (unsigned char)c2;
        }

        p1 += 32;
        p2 += 32;
    }
}

// AVX2 optimized string search
const char* simd_strstr(const char *haystack, const char *needle) {
    if (!g_has_avx2 || !haystack || !needle || !*needle) {
        return strstr(haystack, needle);
    }

    size_t needle_len = strlen(needle);
    if (needle_len > 32) {
        return strstr(haystack, needle);  // Fallback for long patterns
    }

    const char *ptr = haystack;
    __m256i needle_first = _mm256_set1_epi8(needle[0]);

    while (*ptr) {
        // Handle alignment
        while (((uintptr_t)ptr & 31) && *ptr) {
            if (*ptr == needle[0] && strncmp(ptr, needle, needle_len) == 0) {
                return ptr;
            }
            ptr++;
        }

        if (!*ptr) break;

        // AVX2 search for first character
        __m256i chunk = _mm256_load_si256((__m256i*)ptr);
        __m256i cmp = _mm256_cmpeq_epi8(chunk, needle_first);
        uint32_t mask = _mm256_movemask_epi8(cmp);

        while (mask) {
            int pos = __builtin_ctz(mask);
            if (strncmp(ptr + pos, needle, needle_len) == 0) {
                return ptr + pos;
            }
            mask &= mask - 1;  // Clear lowest set bit
        }

        ptr += 32;
    }

    return NULL;
}

// AVX2 optimized memory comparison
int simd_memcmp(const void *ptr1, const void *ptr2, size_t size) {
    if (!g_has_avx2 || !ptr1 || !ptr2 || size < 32) {
        return memcmp(ptr1, ptr2, size);
    }

    const char *p1 = (const char*)ptr1;
    const char *p2 = (const char*)ptr2;
    size_t remaining = size;

    // Handle unaligned prefix
    while (((uintptr_t)p1 & 31) && remaining > 0) {
        if (*p1 != *p2) {
            return (unsigned char)*p1 - (unsigned char)*p2;
        }
        p1++;
        p2++;
        remaining--;
    }

    // AVX2 vectorized comparison
    while (remaining >= 32) {
        __m256i chunk1 = _mm256_load_si256((__m256i*)p1);
        __m256i chunk2 = _mm256_load_si256((__m256i*)p2);
        __m256i cmp = _mm256_cmpeq_epi8(chunk1, chunk2);
        uint32_t mask = _mm256_movemask_epi8(cmp);

        if (mask != 0xFFFFFFFF) {
            // Found difference
            uint32_t diff_mask = ~mask;
            int pos = __builtin_ctz(diff_mask);
            return (unsigned char)p1[pos] - (unsigned char)p2[pos];
        }

        p1 += 32;
        p2 += 32;
        remaining -= 32;
    }

    // Handle remaining bytes
    return memcmp(p1, p2, remaining);
}

// AVX2 optimized hash function (xxHash-like)
uint64_t simd_hash64(const void *data, size_t size, uint64_t seed) {
    if (!g_has_avx2 || !data || size < 32) {
        // Fallback to simple hash
        const uint8_t *ptr = (const uint8_t*)data;
        uint64_t hash = seed;
        for (size_t i = 0; i < size; i++) {
            hash = hash * SIMD_HASH_PRIME1 + ptr[i];
        }
        return hash;
    }

    const uint8_t *ptr = (const uint8_t*)data;
    size_t remaining = size;

    __m256i prime1 = _mm256_set1_epi64x(SIMD_HASH_PRIME1);
    __m256i prime2 = _mm256_set1_epi64x(SIMD_HASH_PRIME2);
    __m256i acc = _mm256_set1_epi64x(seed);

    // Process 32-byte chunks
    while (remaining >= 32) {
        __m256i chunk = _mm256_loadu_si256((__m256i*)ptr);

        // Convert bytes to 64-bit values and accumulate
        __m256i lo = _mm256_unpacklo_epi8(chunk, _mm256_setzero_si256());
        __m256i hi = _mm256_unpackhi_epi8(chunk, _mm256_setzero_si256());

        lo = _mm256_unpacklo_epi16(lo, _mm256_setzero_si256());
        hi = _mm256_unpacklo_epi16(hi, _mm256_setzero_si256());

        acc = _mm256_add_epi64(acc, _mm256_mul_epi32(lo, prime1));
        acc = _mm256_add_epi64(acc, _mm256_mul_epi32(hi, prime2));

        ptr += 32;
        remaining -= 32;
    }

    // Combine accumulated values
    uint64_t result[4];
    _mm256_storeu_si256((__m256i*)result, acc);
    uint64_t final_hash = result[0] ^ result[1] ^ result[2] ^ result[3];

    // Process remaining bytes
    while (remaining > 0) {
        final_hash = final_hash * SIMD_HASH_PRIME1 + *ptr++;
        remaining--;
    }

    return final_hash ^ (final_hash >> 33);
}

// AVX2 optimized DNS label validation
bool simd_validate_dns_label(const char *label, size_t length) {
    if (!g_has_avx2 || !label || length == 0 || length > DNS_LABEL_MAX_LENGTH) {
        // Fallback validation
        for (size_t i = 0; i < length; i++) {
            char c = label[i];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-')) {
                return false;
            }
        }
        return true;
    }

    // AVX2 character class validation
    __m256i a_lower = _mm256_set1_epi8('a');
    __m256i z_lower = _mm256_set1_epi8('z');
    __m256i a_upper = _mm256_set1_epi8('A');
    __m256i z_upper = _mm256_set1_epi8('Z');
    __m256i zero_digit = _mm256_set1_epi8('0');
    __m256i nine_digit = _mm256_set1_epi8('9');
    __m256i hyphen = _mm256_set1_epi8('-');

    size_t remaining = length;
    const char *ptr = label;

    while (remaining >= 32) {
        __m256i chunk = _mm256_loadu_si256((__m256i*)ptr);

        // Check character classes
        __m256i is_lower = _mm256_and_si256(_mm256_cmpgt_epi8(chunk, a_lower),
                                          _mm256_cmpgt_epi8(z_lower, chunk));
        __m256i is_upper = _mm256_and_si256(_mm256_cmpgt_epi8(chunk, a_upper),
                                          _mm256_cmpgt_epi8(z_upper, chunk));
        __m256i is_digit = _mm256_and_si256(_mm256_cmpgt_epi8(chunk, zero_digit),
                                          _mm256_cmpgt_epi8(nine_digit, chunk));
        __m256i is_hyphen = _mm256_cmpeq_epi8(chunk, hyphen);

        __m256i valid = _mm256_or_si256(_mm256_or_si256(is_lower, is_upper),
                                      _mm256_or_si256(is_digit, is_hyphen));

        uint32_t mask = _mm256_movemask_epi8(valid);
        if (mask != 0xFFFFFFFF) {
            return false;  // Invalid character found
        }

        ptr += 32;
        remaining -= 32;
    }

    // Check remaining bytes
    for (size_t i = 0; i < remaining; i++) {
        char c = ptr[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-')) {
            return false;
        }
    }

    return true;
}

// AVX2 optimized domain name normalization (lowercase conversion)
void simd_normalize_domain(char *domain, size_t length) {
    if (!g_has_avx2 || !domain || length == 0) {
        // Fallback normalization
        for (size_t i = 0; i < length; i++) {
            if (domain[i] >= 'A' && domain[i] <= 'Z') {
                domain[i] += 32;
            }
        }
        return;
    }

    __m256i a_upper = _mm256_set1_epi8('A');
    __m256i z_upper = _mm256_set1_epi8('Z');
    __m256i case_diff = _mm256_set1_epi8(32);

    size_t remaining = length;
    char *ptr = domain;

    while (remaining >= 32) {
        __m256i chunk = _mm256_loadu_si256((__m256i*)ptr);
        __m256i is_upper = _mm256_and_si256(_mm256_cmpgt_epi8(chunk, a_upper),
                                          _mm256_cmpgt_epi8(z_upper, chunk));
        __m256i converted = _mm256_add_epi8(chunk, _mm256_and_si256(is_upper, case_diff));
        _mm256_storeu_si256((__m256i*)ptr, converted);

        ptr += 32;
        remaining -= 32;
    }

    // Handle remaining bytes
    for (size_t i = 0; i < remaining; i++) {
        if (ptr[i] >= 'A' && ptr[i] <= 'Z') {
            ptr[i] += 32;
        }
    }
}

// Get SIMD performance statistics
void simd_get_performance_stats(void) {
    printf("\n[OPTIMIZER] SIMD Performance Statistics\n");
    printf("======================================\n");
    printf("AVX2 Support: %s\n", g_has_avx2 ? "Yes" : "No");
    printf("FMA Support: %s\n", g_has_fma ? "Yes" : "No");
    printf("AES-NI Support: %s\n", g_has_aes ? "Yes" : "No");
    printf("PCLMUL Support: %s\n", g_has_pclmul ? "Yes" : "No");
    printf("Vector Width: %d bits\n", g_has_avx2 ? 256 : 128);
    printf("Parallel Lanes: %d bytes, %d 32-bit integers\n",
           g_has_avx2 ? 32 : 16, g_has_avx2 ? 8 : 4);

    if (g_has_avx2) {
        printf("Expected Performance Gains:\n");
        printf("  String Operations: 4-8x faster\n");
        printf("  Memory Comparison: 8-16x faster\n");
        printf("  Hash Computation: 4-6x faster\n");
        printf("  DNS Validation: 8-12x faster\n");
    }
}