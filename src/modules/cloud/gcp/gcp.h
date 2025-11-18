/*
 * CloudClear - GCP (Google Cloud Platform) Integration
 *
 * Features:
 * - Google Cloud CDN detection
 * - Cloud Armor (WAF) detection
 * - Cloud Load Balancer detection
 * - Cloud DNS intelligence
 */

#ifndef GCP_H
#define GCP_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

typedef enum {
    GCP_SERVICE_UNKNOWN,
    GCP_SERVICE_CLOUD_CDN,
    GCP_SERVICE_CLOUD_ARMOR,
    GCP_SERVICE_LOAD_BALANCER,
    GCP_SERVICE_CLOUD_DNS,
    GCP_SERVICE_CLOUD_STORAGE
} gcp_service_type_t;

typedef struct {
    bool gcp_detected;
    uint32_t confidence;
    char detection_method[256];
    gcp_service_type_t services[10];
    uint32_t service_count;
    bool cloud_cdn_detected;
    bool cloud_armor_detected;
    char cache_status[64];
    time_t detected_at;
    char target_domain[256];
} gcp_detection_result_t;

int gcp_init(void);
int gcp_detect_from_headers(const char *headers, gcp_detection_result_t *result);
bool gcp_check_cname_pattern(const char *cname);
const char *gcp_service_type_to_string(gcp_service_type_t service);
void gcp_print_detection_result(const gcp_detection_result_t *result);

#endif // GCP_H
