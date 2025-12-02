/*
 * Alibaba Cloud Integration Implementation
 */

#include "platform_compat.h"
#include "alibaba.h"
#include <string.h>

int alibaba_detect_from_headers(const char *headers, alibaba_detection_result_t *result) {
    if (!headers || !result) return -1;
    memset(result, 0, sizeof(alibaba_detection_result_t));

    if (strcasestr(headers, "x-ali-") || strcasestr(headers, "alicdn") ||
        strcasestr(headers, "aliyun")) {
        result->alibaba_detected = true;
        result->confidence = 85;

        if (strcasestr(headers, "cdn")) result->cdn_detected = true;

        return 0;
    }
    return -1;
}
