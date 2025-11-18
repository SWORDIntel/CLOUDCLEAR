/*
 * CloudClear - VirusTotal API Integration
 *
 * Features:
 * - Passive DNS resolution history
 * - Domain/IP reputation scoring
 * - Subdomain enumeration
 * - Malware correlation
 */

#ifndef VIRUSTOTAL_API_H
#define VIRUSTOTAL_API_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#define VT_API_BASE "https://www.virustotal.com/api/v3"
#define VT_MAX_RESOLUTIONS 100

typedef struct {
    char ip[46];
    time_t last_resolved;
} vt_resolution_t;

typedef struct {
    char domain[256];
    uint32_t reputation;
    uint32_t malicious_count;
    uint32_t suspicious_count;
    vt_resolution_t resolutions[VT_MAX_RESOLUTIONS];
    uint32_t resolution_count;
    char categories[512];
    time_t last_analysis_date;
} vt_domain_info_t;

typedef struct {
    char ip[46];
    uint32_t reputation;
    char asn[32];
    char as_owner[256];
    char country[3];
} vt_ip_info_t;

typedef struct {
    char api_key[256];
    bool configured;
} vt_config_t;

int vt_init(vt_config_t *config, const char *api_key);
int vt_domain_lookup(vt_config_t *config, const char *domain, vt_domain_info_t *info);
int vt_ip_lookup(vt_config_t *config, const char *ip, vt_ip_info_t *info);
int vt_get_passive_dns(vt_config_t *config, const char *domain,
                       vt_resolution_t *resolutions, uint32_t *count);

#endif
