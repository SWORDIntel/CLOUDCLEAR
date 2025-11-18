/*
 * DigitalOcean Integration Implementation
 */

#include "digitalocean.h"
#include <string.h>

static const char *do_patterns[] = {
    ".digitaloceanspaces.com",
    ".ondigitalocean.app",
    ".do-prod.digitalocean.com",
    NULL
};

bool digitalocean_check_domain_pattern(const char *domain) {
    if (!domain) return false;
    for (int i = 0; do_patterns[i]; i++) {
        if (strstr(domain, do_patterns[i])) return true;
    }
    return false;
}

int digitalocean_detect(const char *domain, digitalocean_detection_result_t *result) {
    if (!domain || !result) return -1;
    memset(result, 0, sizeof(digitalocean_detection_result_t));

    if (digitalocean_check_domain_pattern(domain)) {
        result->digitalocean_detected = true;
        result->confidence = 90;

        if (strstr(domain, "spaces")) result->spaces_cdn = true;
        if (strstr(domain, "ondigitalocean")) result->app_platform = true;

        return 0;
    }
    return -1;
}
