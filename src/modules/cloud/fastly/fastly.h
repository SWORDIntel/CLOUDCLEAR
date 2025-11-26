/*
 * CloudClear - Fastly CDN Integration
 */

#ifndef FASTLY_H
#define FASTLY_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

typedef struct {
    bool fastly_detected;
    uint32_t confidence;
    char request_id[128];
    char pop_location[64];
    bool cache_hit;
    char service_id[64];
    time_t detected_at;
} fastly_detection_result_t;

int fastly_detect_from_headers(const char *headers, fastly_detection_result_t *result);
bool fastly_check_cname_pattern(const char *cname);

#endif
