/*
 * CloudClear - Shodan API Integration
 *
 * Features:
 * - IP intelligence and port scanning data
 * - Service discovery and fingerprinting
 * - Vulnerability correlation
 * - Historical scan data retrieval
 */

#ifndef SHODAN_API_H
#define SHODAN_API_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#define SHODAN_API_BASE "https://api.shodan.io"
#define SHODAN_MAX_PORTS 100
#define SHODAN_MAX_VULNS 50

typedef struct {
    uint16_t port;
    char protocol[16];
    char service[64];
    char product[128];
    char version[64];
} shodan_port_info_t;

typedef struct {
    char cve_id[32];
    float cvss;
    char summary[512];
} shodan_vuln_info_t;

typedef struct {
    char ip[46];
    char org[256];
    char isp[256];
    char country_code[3];
    char city[128];
    shodan_port_info_t ports[SHODAN_MAX_PORTS];
    uint32_t port_count;
    shodan_vuln_info_t vulns[SHODAN_MAX_VULNS];
    uint32_t vuln_count;
    char os[128];
    time_t last_update;
} shodan_host_info_t;

typedef struct {
    char api_key[256];
    bool configured;
} shodan_config_t;

int shodan_init(shodan_config_t *config, const char *api_key);
int shodan_host_lookup(shodan_config_t *config, const char *ip, shodan_host_info_t *info);
int shodan_dns_resolve(shodan_config_t *config, const char *hostname, char *ip, size_t ip_size);
int shodan_search(shodan_config_t *config, const char *query, char *results, size_t size);

#endif
