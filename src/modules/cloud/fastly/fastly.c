/*
 * Fastly CDN Integration Implementation
 */

#include "platform_compat.h"
#include "fastly.h"
#include <string.h>
#include <stdio.h>

static const char *fastly_patterns[] = {".fastly.net", ".fastlylb.net", NULL};

bool fastly_check_cname_pattern(const char *cname) {
    if (!cname) return false;
    for (int i = 0; fastly_patterns[i]; i++) {
        if (strstr(cname, fastly_patterns[i])) return true;
    }
    return false;
}

int fastly_detect_from_headers(const char *headers, fastly_detection_result_t *result) {
    if (!headers || !result) return -1;
    memset(result, 0, sizeof(fastly_detection_result_t));
    result->detected_at = time(NULL);

    if (strcasestr(headers, "x-fastly-request-id") || strcasestr(headers, "fastly-debug")) {
        result->fastly_detected = true;
        result->confidence = 95;

        char *hit_line = strcasestr(headers, "x-cache:");
        if (hit_line && strcasestr(hit_line, "HIT")) {
            result->cache_hit = true;
        }
        return 0;
    }
    return -1;
}
