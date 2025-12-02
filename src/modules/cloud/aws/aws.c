/*
 * CloudClear - AWS Integration Implementation
 */

#include "platform_compat.h"
#include "aws.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// AWS CloudFront header signatures
static const char *cloudfront_headers[] = {
    "x-amz-cf-id",
    "x-amz-cf-pop",
    "x-amzn-requestid",
    "x-amzn-trace-id",
    "x-amz-request-id",
    "x-amz-id-2",
    "via: ", // CloudFront adds Via header
    NULL
};

// CloudFront CNAME patterns
static const char *cloudfront_cname_patterns[] = {
    ".cloudfront.net",
    ".awsglobalaccelerator.com",
    NULL
};

// ELB/ALB domain patterns
static const char *elb_patterns[] = {
    ".elb.amazonaws.com",
    ".elasticbeanstalk.com",
    NULL
};

// API Gateway patterns
static const char *api_gateway_patterns[] = {
    ".execute-api.",
    ".amazonaws.com",
    NULL
};

// S3 patterns
static const char *s3_patterns[] = {
    ".s3.amazonaws.com",
    ".s3-website",
    ".s3.",
    NULL
};

int aws_init_context(aws_context_t *ctx) {
    if (!ctx) return -1;
    memset(ctx, 0, sizeof(aws_context_t));

    if (pthread_mutex_init(&ctx->mutex, NULL) != 0) {
        return -1;
    }

    const char *access_key = getenv("AWS_ACCESS_KEY_ID");
    const char *secret_key = getenv("AWS_SECRET_ACCESS_KEY");
    const char *region = getenv("AWS_REGION");

    if (access_key && secret_key) {
        aws_configure_api(ctx, access_key, secret_key, region ? region : "us-east-1");
    }

    return 0;
}

void aws_cleanup_context(aws_context_t *ctx) {
    if (!ctx) return;
    pthread_mutex_destroy(&ctx->mutex);
    memset(&ctx->api_config, 0, sizeof(aws_api_config_t));
    memset(ctx, 0, sizeof(aws_context_t));
}

int aws_configure_api(aws_context_t *ctx, const char *access_key_id,
                      const char *secret_access_key, const char *region) {
    if (!ctx) return -1;

    pthread_mutex_lock(&ctx->mutex);

    if (access_key_id) {
        strncpy(ctx->api_config.access_key_id, access_key_id,
                sizeof(ctx->api_config.access_key_id) - 1);
    }
    if (secret_access_key) {
        strncpy(ctx->api_config.secret_access_key, secret_access_key,
                sizeof(ctx->api_config.secret_access_key) - 1);
    }

    ctx->api_config.credentials_configured =
        (strlen(ctx->api_config.access_key_id) > 0 &&
         strlen(ctx->api_config.secret_access_key) > 0);

    pthread_mutex_unlock(&ctx->mutex);
    return 0;
}

bool aws_is_cloudfront_header(const char *header_name) {
    if (!header_name) return false;

    for (int i = 0; cloudfront_headers[i] != NULL; i++) {
        if (strcasestr(header_name, cloudfront_headers[i]) != NULL) {
            return true;
        }
    }
    return false;
}

bool aws_check_cloudfront_cname(const char *cname) {
    if (!cname) return false;

    for (int i = 0; cloudfront_cname_patterns[i] != NULL; i++) {
        if (strcasestr(cname, cloudfront_cname_patterns[i]) != NULL) {
            return true;
        }
    }
    return false;
}

int aws_parse_cloudfront_headers(const char *headers, aws_detection_result_t *result) {
    if (!headers || !result) return -1;

    char *headers_copy = strdup(headers);
    if (!headers_copy) return -1;

    char *line = strtok(headers_copy, "\r\n");
    while (line) {
        if (strncasecmp(line, "x-amz-cf-id:", 12) == 0) {
            sscanf(line + 12, " %127s", result->cloudfront_request_id);
            result->cloudfront.enabled = true;
        } else if (strncasecmp(line, "x-amz-cf-pop:", 13) == 0) {
            sscanf(line + 13, " %15s", result->cloudfront_pop);
        } else if (strncasecmp(line, "x-cache:", 8) == 0) {
            if (strcasestr(line, "Hit from cloudfront")) {
                result->cloudfront_cache_hit = true;
            }
        } else if (strncasecmp(line, "via:", 4) == 0) {
            if (strcasestr(line, "CloudFront")) {
                result->aws_detected = true;
                result->confidence = AWS_CONFIDENCE_HIGH;
            }
        }
        line = strtok(NULL, "\r\n");
    }

    free(headers_copy);
    return 0;
}

int aws_detect_from_headers(const char *headers, aws_detection_result_t *result) {
    if (!headers || !result) return -1;

    memset(result, 0, sizeof(aws_detection_result_t));
    result->detected_at = time(NULL);

    // Check for CloudFront headers
    if (aws_is_cloudfront_header(headers)) {
        result->aws_detected = true;
        result->confidence = AWS_CONFIDENCE_HIGH;
        strcpy(result->detection_method, "CloudFront HTTP headers");

        result->services[result->service_count++] = AWS_SERVICE_CLOUDFRONT;

        aws_parse_cloudfront_headers(headers, result);
        return 0;
    }

    // Check for WAF headers
    if (strstr(headers, "x-amzn-waf") || strstr(headers, "x-amz-apigw")) {
        result->aws_detected = true;
        result->waf_info.waf_detected = true;
        result->services[result->service_count++] = AWS_SERVICE_WAF;

        if (result->confidence < AWS_CONFIDENCE_MEDIUM) {
            result->confidence = AWS_CONFIDENCE_MEDIUM;
        }
    }

    return result->aws_detected ? 0 : -1;
}

bool aws_is_elb_domain(const char *domain) {
    if (!domain) return false;

    for (int i = 0; elb_patterns[i] != NULL; i++) {
        if (strstr(domain, elb_patterns[i]) != NULL) {
            return true;
        }
    }
    return false;
}

bool aws_is_api_gateway_domain(const char *domain) {
    if (!domain) return false;

    return (strstr(domain, ".execute-api.") != NULL &&
            strstr(domain, ".amazonaws.com") != NULL);
}

bool aws_is_s3_domain(const char *domain) {
    if (!domain) return false;

    for (int i = 0; s3_patterns[i] != NULL; i++) {
        if (strstr(domain, s3_patterns[i]) != NULL) {
            return true;
        }
    }
    return false;
}

const char *aws_service_type_to_string(aws_service_type_t service) {
    switch (service) {
        case AWS_SERVICE_CLOUDFRONT: return "CloudFront CDN";
        case AWS_SERVICE_WAF: return "AWS WAF";
        case AWS_SERVICE_SHIELD: return "AWS Shield";
        case AWS_SERVICE_ROUTE53: return "Route53 DNS";
        case AWS_SERVICE_ELB: return "Elastic Load Balancer";
        case AWS_SERVICE_ALB: return "Application Load Balancer";
        case AWS_SERVICE_NLB: return "Network Load Balancer";
        case AWS_SERVICE_API_GATEWAY: return "API Gateway";
        case AWS_SERVICE_S3: return "S3 Storage";
        case AWS_SERVICE_GLOBAL_ACCELERATOR: return "Global Accelerator";
        default: return "Unknown";
    }
}

const char *aws_confidence_to_string(aws_confidence_t confidence) {
    if (confidence >= AWS_CONFIDENCE_VERIFIED) return "Verified";
    if (confidence >= AWS_CONFIDENCE_HIGH) return "High";
    if (confidence >= AWS_CONFIDENCE_MEDIUM) return "Medium";
    if (confidence >= AWS_CONFIDENCE_LOW) return "Low";
    return "None";
}

void aws_print_detection_result(const aws_detection_result_t *result) {
    if (!result) return;

    printf("\n=== AWS Detection Result ===\n");
    printf("Target: %s\n", result->target_domain);
    printf("Detected: %s\n", result->aws_detected ? "Yes" : "No");

    if (!result->aws_detected) {
        printf("============================\n\n");
        return;
    }

    printf("Confidence: %s (%d%%)\n",
           aws_confidence_to_string(result->confidence), result->confidence);
    printf("Detection Method: %s\n", result->detection_method);

    if (result->service_count > 0) {
        printf("\nDetected AWS Services:\n");
        for (uint32_t i = 0; i < result->service_count; i++) {
            printf("  - %s\n", aws_service_type_to_string(result->services[i]));
        }
    }

    if (result->cloudfront.enabled) {
        printf("\nCloudFront Info:\n");
        printf("  Request ID: %s\n", result->cloudfront_request_id);
        printf("  Edge POP: %s\n", result->cloudfront_pop);
        printf("  Cache Hit: %s\n", result->cloudfront_cache_hit ? "Yes" : "No");
    }

    if (result->waf_info.waf_detected) {
        printf("\nWAF Detected: Yes\n");
    }

    printf("============================\n\n");
}
