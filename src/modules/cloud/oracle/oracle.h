/*
 * CloudClear - Oracle Cloud Integration
 */

#ifndef ORACLE_H
#define ORACLE_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    bool oracle_detected;
    uint32_t confidence;
    bool cdn_detected;
} oracle_detection_result_t;

int oracle_detect_from_headers(const char *headers, oracle_detection_result_t *result);

#endif
