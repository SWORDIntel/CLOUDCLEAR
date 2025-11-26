/*
 * CloudClear - Azure (Microsoft) Integration
 *
 * Features:
 * - Azure Front Door detection
 * - Azure CDN detection
 * - Azure WAF detection
 * - Application Gateway detection
 * - Traffic Manager detection
 */

#ifndef AZURE_H
#define AZURE_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <time.h>

#define AZURE_MAX_HEADERS 30

typedef enum {
    AZURE_SERVICE_UNKNOWN,
    AZURE_SERVICE_FRONT_DOOR,
    AZURE_SERVICE_CDN,
    AZURE_SERVICE_WAF,
    AZURE_SERVICE_APP_GATEWAY,
    AZURE_SERVICE_TRAFFIC_MANAGER
} azure_service_type_t;

typedef struct {
    bool azure_detected;
    uint32_t confidence;
    char detection_method[256];
    azure_service_type_t services[10];
    uint32_t service_count;
    char request_id[128];
    char edge_location[64];
    bool front_door_detected;
    bool waf_detected;
    time_t detected_at;
    char target_domain[256];
} azure_detection_result_t;

int azure_init(void);
int azure_detect_from_headers(const char *headers, azure_detection_result_t *result);
bool azure_check_cname_pattern(const char *cname);
const char *azure_service_type_to_string(azure_service_type_t service);
void azure_print_detection_result(const azure_detection_result_t *result);

#endif // AZURE_H
