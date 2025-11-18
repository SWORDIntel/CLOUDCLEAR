/*
 * CloudClear - Alibaba Cloud Integration
 */

#ifndef ALIBABA_H
#define ALIBABA_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    bool alibaba_detected;
    uint32_t confidence;
    bool cdn_detected;
    bool anti_ddos_detected;
} alibaba_detection_result_t;

int alibaba_detect_from_headers(const char *headers, alibaba_detection_result_t *result);

#endif
