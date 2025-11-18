/*
 * CloudClear - Azure Integration Implementation
 */

#include "azure.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const char *azure_headers[] = {
    "x-azure-ref",
    "x-azure-requestid",
    "x-fd-healthprobe",
    "x-msedge-ref",
    "x-cache: ", // Azure CDN
    NULL
};

static const char *azure_cname_patterns[] = {
    ".azurefd.net",
    ".azureedge.net",
    ".trafficmanager.net",
    ".cloudapp.azure.com",
    ".azure-api.net",
    NULL
};

int azure_init(void) {
    return 0;
}

bool azure_check_cname_pattern(const char *cname) {
    if (!cname) return false;

    for (int i = 0; azure_cname_patterns[i] != NULL; i++) {
        if (strcasestr(cname, azure_cname_patterns[i]) != NULL) {
            return true;
        }
    }
    return false;
}

int azure_detect_from_headers(const char *headers, azure_detection_result_t *result) {
    if (!headers || !result) return -1;

    memset(result, 0, sizeof(azure_detection_result_t));
    result->detected_at = time(NULL);

    for (int i = 0; azure_headers[i] != NULL; i++) {
        if (strcasestr(headers, azure_headers[i]) != NULL) {
            result->azure_detected = true;
            result->confidence = 85;
            strcpy(result->detection_method, "Azure HTTP headers");

            if (strcasestr(headers, "x-azure-ref") || strcasestr(headers, "x-fd-")) {
                result->front_door_detected = true;
                result->services[result->service_count++] = AZURE_SERVICE_FRONT_DOOR;
            }

            if (strcasestr(headers, "azureedge")) {
                result->services[result->service_count++] = AZURE_SERVICE_CDN;
            }

            return 0;
        }
    }

    return -1;
}

const char *azure_service_type_to_string(azure_service_type_t service) {
    switch (service) {
        case AZURE_SERVICE_FRONT_DOOR: return "Azure Front Door";
        case AZURE_SERVICE_CDN: return "Azure CDN";
        case AZURE_SERVICE_WAF: return "Azure WAF";
        case AZURE_SERVICE_APP_GATEWAY: return "Application Gateway";
        case AZURE_SERVICE_TRAFFIC_MANAGER: return "Traffic Manager";
        default: return "Unknown";
    }
}

void azure_print_detection_result(const azure_detection_result_t *result) {
    if (!result) return;

    printf("\n=== Azure Detection Result ===\n");
    printf("Detected: %s\n", result->azure_detected ? "Yes" : "No");

    if (result->azure_detected) {
        printf("Confidence: %u%%\n", result->confidence);
        printf("Method: %s\n", result->detection_method);

        if (result->service_count > 0) {
            printf("Services:\n");
            for (uint32_t i = 0; i < result->service_count; i++) {
                printf("  - %s\n", azure_service_type_to_string(result->services[i]));
            }
        }
    }

    printf("==============================\n\n");
}
