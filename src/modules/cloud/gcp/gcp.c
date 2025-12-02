/*
 * CloudClear - GCP Integration Implementation
 */

#include "platform_compat.h"
#include "gcp.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const char *gcp_headers[] = {
    "x-goog-",
    "via: 1.1 google",
    "x-cloud-trace-context",
    "x-gfe-",
    NULL
};

static const char *gcp_cname_patterns[] = {
    ".googlevideo.com",
    ".gcdn.co",
    ".googleusercontent.com",
    ".googleapis.com",
    ".goog",
    ".c.googlers.com",
    NULL
};

int gcp_init(void) {
    return 0;
}

bool gcp_check_cname_pattern(const char *cname) {
    if (!cname) return false;

    for (int i = 0; gcp_cname_patterns[i] != NULL; i++) {
        if (strcasestr(cname, gcp_cname_patterns[i]) != NULL) {
            return true;
        }
    }
    return false;
}

int gcp_detect_from_headers(const char *headers, gcp_detection_result_t *result) {
    if (!headers || !result) return -1;

    memset(result, 0, sizeof(gcp_detection_result_t));
    result->detected_at = time(NULL);

    for (int i = 0; gcp_headers[i] != NULL; i++) {
        if (strcasestr(headers, gcp_headers[i]) != NULL) {
            result->gcp_detected = true;
            result->confidence = 85;
            strcpy(result->detection_method, "GCP HTTP headers");

            if (strcasestr(headers, "x-goog-") != NULL) {
                result->cloud_cdn_detected = true;
                result->services[result->service_count++] = GCP_SERVICE_CLOUD_CDN;
            }

            if (strcasestr(headers, "via: 1.1 google")) {
                result->services[result->service_count++] = GCP_SERVICE_LOAD_BALANCER;
            }

            return 0;
        }
    }

    return -1;
}

const char *gcp_service_type_to_string(gcp_service_type_t service) {
    switch (service) {
        case GCP_SERVICE_CLOUD_CDN: return "Google Cloud CDN";
        case GCP_SERVICE_CLOUD_ARMOR: return "Cloud Armor";
        case GCP_SERVICE_LOAD_BALANCER: return "Cloud Load Balancer";
        case GCP_SERVICE_CLOUD_DNS: return "Cloud DNS";
        case GCP_SERVICE_CLOUD_STORAGE: return "Cloud Storage";
        default: return "Unknown";
    }
}

void gcp_print_detection_result(const gcp_detection_result_t *result) {
    if (!result) return;

    printf("\n=== GCP Detection Result ===\n");
    printf("Detected: %s\n", result->gcp_detected ? "Yes" : "No");

    if (result->gcp_detected) {
        printf("Confidence: %u%%\n", result->confidence);
        printf("Method: %s\n", result->detection_method);

        if (result->service_count > 0) {
            printf("Services:\n");
            for (uint32_t i = 0; i < result->service_count; i++) {
                printf("  - %s\n", gcp_service_type_to_string(result->services[i]));
            }
        }
    }

    printf("============================\n\n");
}
