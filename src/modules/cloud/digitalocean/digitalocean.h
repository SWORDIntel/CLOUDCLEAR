/*
 * CloudClear - DigitalOcean Integration
 */

#ifndef DIGITALOCEAN_H
#define DIGITALOCEAN_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    bool digitalocean_detected;
    uint32_t confidence;
    bool spaces_cdn;
    bool app_platform;
} digitalocean_detection_result_t;

int digitalocean_detect(const char *domain, digitalocean_detection_result_t *result);
bool digitalocean_check_domain_pattern(const char *domain);

#endif
