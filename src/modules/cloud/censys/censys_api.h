/*
 * CloudClear - Censys API Integration
 *
 * Features:
 * - Certificate transparency search
 * - Host discovery and reconnaissance
 * - Service fingerprinting
 */

#ifndef CENSYS_API_H
#define CENSYS_API_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#define CENSYS_API_BASE "https://search.censys.io/api/v2"
#define CENSYS_MAX_CERTS 100

typedef struct {
    char fingerprint[128];
    char common_name[256];
    char issuer[256];
    char san[512];
    time_t not_before;
    time_t not_after;
} censys_cert_info_t;

typedef struct {
    char ip[46];
    char hostname[256];
    uint16_t ports[100];
    uint32_t port_count;
    char services[100][64];
    char protocols[100][16];
} censys_host_info_t;

typedef struct {
    char api_id[256];
    char api_secret[256];
    bool configured;
} censys_config_t;

int censys_init(censys_config_t *config, const char *api_id, const char *api_secret);
int censys_search_certificates(censys_config_t *config, const char *domain,
                                censys_cert_info_t *certs, uint32_t *cert_count);
int censys_host_lookup(censys_config_t *config, const char *ip, censys_host_info_t *info);
int censys_search_hosts(censys_config_t *config, const char *query, char *results, size_t size);

#endif
