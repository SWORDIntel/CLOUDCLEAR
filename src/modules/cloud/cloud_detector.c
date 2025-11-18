/*
 * CloudClear - Unified Cloud Detection Implementation
 */

#include "cloud_detector.h"
#include "akamai/akamai.h"
#include "aws/aws.h"
#include "azure/azure.h"
#include "gcp/gcp.h"
#include "fastly/fastly.h"
#include "digitalocean/digitalocean.h"
#include "oracle/oracle.h"
#include "alibaba/alibaba.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void cloud_detection_config_default(cloud_detection_config_t *config) {
    if (!config) return;

    memset(config, 0, sizeof(cloud_detection_config_t));

    // Enable major providers by default
    config->enable_akamai = true;
    config->enable_aws = true;
    config->enable_azure = true;
    config->enable_gcp = true;
    config->enable_cloudflare = true;
    config->enable_fastly = true;

    // Detection methods
    config->use_dns_detection = true;
    config->use_http_detection = true;
    config->use_certificate_detection = true;
    config->use_ip_range_detection = true;

    // Performance
    config->max_detection_time_ms = 30000; // 30 seconds
    config->parallel_detection = true;
    config->detailed_analysis = true;
}

void cloud_detection_config_all_enabled(cloud_detection_config_t *config) {
    cloud_detection_config_default(config);

    // Enable all providers
    config->enable_digitalocean = true;
    config->enable_oracle = true;
    config->enable_alibaba = true;

    // Enable intelligence services
    config->enable_shodan = true;
    config->enable_censys = true;
    config->enable_virustotal = true;
}

void cloud_detection_config_fast(cloud_detection_config_t *config) {
    cloud_detection_config_default(config);

    // Fast mode: fewer checks
    config->use_certificate_detection = false;
    config->use_ip_range_detection = false;
    config->max_detection_time_ms = 10000; // 10 seconds
    config->detailed_analysis = false;
}

int cloud_detect_from_headers(const char *headers, cloud_detection_result_t *result) {
    if (!headers || !result) return -1;

    memset(result, 0, sizeof(cloud_detection_result_t));
    result->detected_at = time(NULL);

    // Try each provider's header detection
    akamai_detection_result_t akamai_result;
    if (akamai_detect_from_headers(headers, &akamai_result) == 0) {
        result->providers[result->provider_count++] = CLOUD_PROVIDER_AKAMAI;
        result->services[result->service_count].provider = CLOUD_PROVIDER_AKAMAI;
        strcpy(result->services[result->service_count].provider_name, "Akamai");
        result->services[result->service_count].confidence = akamai_result.confidence;
        result->service_count++;

        if (akamai_result.waf_info.waf_detected) {
            result->waf_detected = true;
            strcpy(result->waf_vendor, "Akamai Kona");
        }
        result->cdn_detected = true;
    }

    aws_detection_result_t aws_result;
    if (aws_detect_from_headers(headers, &aws_result) == 0) {
        result->providers[result->provider_count++] = CLOUD_PROVIDER_AWS;
        result->services[result->service_count].provider = CLOUD_PROVIDER_AWS;
        strcpy(result->services[result->service_count].provider_name, "AWS");
        result->services[result->service_count].confidence = aws_result.confidence;
        result->service_count++;

        if (aws_result.cloudfront.enabled) {
            result->cdn_detected = true;
            if (aws_result.cloudfront_pop[0]) {
                strcpy(result->edge_location, aws_result.cloudfront_pop);
            }
        }

        if (aws_result.waf_info.waf_detected) {
            result->waf_detected = true;
            strcpy(result->waf_vendor, "AWS WAF");
        }
    }

    azure_detection_result_t azure_result;
    if (azure_detect_from_headers(headers, &azure_result) == 0) {
        result->providers[result->provider_count++] = CLOUD_PROVIDER_AZURE;
        result->services[result->service_count].provider = CLOUD_PROVIDER_AZURE;
        strcpy(result->services[result->service_count].provider_name, "Azure");
        result->services[result->service_count].confidence = azure_result.confidence;
        result->service_count++;

        if (azure_result.front_door_detected) {
            result->cdn_detected = true;
        }

        if (azure_result.waf_detected) {
            result->waf_detected = true;
            strcpy(result->waf_vendor, "Azure WAF");
        }
    }

    gcp_detection_result_t gcp_result;
    if (gcp_detect_from_headers(headers, &gcp_result) == 0) {
        result->providers[result->provider_count++] = CLOUD_PROVIDER_GCP;
        result->services[result->service_count].provider = CLOUD_PROVIDER_GCP;
        strcpy(result->services[result->service_count].provider_name, "GCP");
        result->services[result->service_count].confidence = gcp_result.confidence;
        result->service_count++;

        if (gcp_result.cloud_cdn_detected) {
            result->cdn_detected = true;
        }

        if (gcp_result.cloud_armor_detected) {
            result->waf_detected = true;
            strcpy(result->waf_vendor, "Cloud Armor");
        }
    }

    fastly_detection_result_t fastly_result;
    if (fastly_detect_from_headers(headers, &fastly_result) == 0) {
        result->providers[result->provider_count++] = CLOUD_PROVIDER_FASTLY;
        result->services[result->service_count].provider = CLOUD_PROVIDER_FASTLY;
        strcpy(result->services[result->service_count].provider_name, "Fastly");
        result->services[result->service_count].confidence = fastly_result.confidence;
        result->service_count++;

        result->cdn_detected = true;
        result->cache_hit = fastly_result.cache_hit;
    }

    oracle_detection_result_t oracle_result;
    if (oracle_detect_from_headers(headers, &oracle_result) == 0) {
        result->providers[result->provider_count++] = CLOUD_PROVIDER_ORACLE;
        result->services[result->service_count].provider = CLOUD_PROVIDER_ORACLE;
        strcpy(result->services[result->service_count].provider_name, "Oracle Cloud");
        result->services[result->service_count].confidence = oracle_result.confidence;
        result->service_count++;
    }

    alibaba_detection_result_t alibaba_result;
    if (alibaba_detect_from_headers(headers, &alibaba_result) == 0) {
        result->providers[result->provider_count++] = CLOUD_PROVIDER_ALIBABA;
        result->services[result->service_count].provider = CLOUD_PROVIDER_ALIBABA;
        strcpy(result->services[result->service_count].provider_name, "Alibaba Cloud");
        result->services[result->service_count].confidence = alibaba_result.confidence;
        result->service_count++;

        if (alibaba_result.cdn_detected) {
            result->cdn_detected = true;
        }

        if (alibaba_result.anti_ddos_detected) {
            result->ddos_protection_detected = true;
        }
    }

    // Identify primary provider
    cloud_identify_primary_provider(result);

    return (result->provider_count > 0) ? 0 : -1;
}

int cloud_identify_primary_provider(cloud_detection_result_t *result) {
    if (!result || result->service_count == 0) return -1;

    // Find service with highest confidence
    uint32_t max_confidence = 0;
    cloud_provider_t primary = CLOUD_PROVIDER_UNKNOWN;

    for (uint32_t i = 0; i < result->service_count; i++) {
        if (result->services[i].confidence > max_confidence) {
            max_confidence = result->services[i].confidence;
            primary = result->services[i].provider;
        }
    }

    result->primary_provider = primary;
    result->primary_confidence = max_confidence;

    return 0;
}

const char *cloud_provider_to_string(cloud_provider_t provider) {
    switch (provider) {
        case CLOUD_PROVIDER_AKAMAI: return "Akamai";
        case CLOUD_PROVIDER_AWS: return "AWS";
        case CLOUD_PROVIDER_AZURE: return "Azure";
        case CLOUD_PROVIDER_GCP: return "Google Cloud Platform";
        case CLOUD_PROVIDER_CLOUDFLARE: return "Cloudflare";
        case CLOUD_PROVIDER_FASTLY: return "Fastly";
        case CLOUD_PROVIDER_DIGITALOCEAN: return "DigitalOcean";
        case CLOUD_PROVIDER_ORACLE: return "Oracle Cloud";
        case CLOUD_PROVIDER_ALIBABA: return "Alibaba Cloud";
        default: return "Unknown";
    }
}

void cloud_print_detection_result(const cloud_detection_result_t *result) {
    if (!result) return;

    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║          CLOUD SERVICE PROVIDER DETECTION RESULT              ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n\n");

    printf("Target: %s\n", result->target_domain[0] ? result->target_domain : result->target_ip);

    if (result->provider_count == 0) {
        printf("Status: No cloud providers detected\n\n");
        return;
    }

    printf("Detected Providers: %u\n", result->provider_count);
    printf("Detected Services: %u\n\n", result->service_count);

    if (result->primary_provider != CLOUD_PROVIDER_UNKNOWN) {
        printf("═══ Primary Provider ═══\n");
        printf("  Provider: %s\n", cloud_provider_to_string(result->primary_provider));
        printf("  Confidence: %u%%\n\n", result->primary_confidence);
    }

    if (result->service_count > 0) {
        printf("═══ Detected Services ═══\n");
        for (uint32_t i = 0; i < result->service_count; i++) {
            printf("  [%u] %s", i + 1, result->services[i].provider_name);
            if (result->services[i].service_name[0]) {
                printf(" - %s", result->services[i].service_name);
            }
            printf(" (Confidence: %u%%)\n", result->services[i].confidence);

            if (result->services[i].detection_method[0]) {
                printf("      Method: %s\n", result->services[i].detection_method);
            }
        }
        printf("\n");
    }

    if (result->cdn_detected || result->waf_detected || result->ddos_protection_detected) {
        printf("═══ Security Features ═══\n");
        if (result->cdn_detected) {
            printf("  CDN: Detected");
            if (result->edge_location[0]) {
                printf(" (Edge: %s)", result->edge_location);
            }
            printf("\n");
        }
        if (result->waf_detected) {
            printf("  WAF: Detected");
            if (result->waf_vendor[0]) {
                printf(" (Vendor: %s)", result->waf_vendor);
            }
            printf("\n");
        }
        if (result->ddos_protection_detected) {
            printf("  DDoS Protection: Detected\n");
        }
        if (result->load_balancer_detected) {
            printf("  Load Balancer: Detected\n");
        }
        printf("\n");
    }

    printf("Detection completed at: %s", ctime(&result->detected_at));
    printf("\n");
}

void cloud_print_summary(const cloud_detection_result_t *result) {
    if (!result) return;

    printf("Cloud Detection Summary: ");

    if (result->provider_count == 0) {
        printf("None detected\n");
        return;
    }

    printf("%s", cloud_provider_to_string(result->primary_provider));

    if (result->cdn_detected) printf(" +CDN");
    if (result->waf_detected) printf(" +WAF");
    if (result->ddos_protection_detected) printf(" +DDoS");

    printf(" (%u%% confidence)\n", result->primary_confidence);
}
