/*
 * Shodan API Integration Implementation
 */

#include "shodan_api.h"
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>

int shodan_init(shodan_config_t *config, const char *api_key) {
    if (!config) return -1;

    memset(config, 0, sizeof(shodan_config_t));

    if (!api_key) {
        api_key = getenv("SHODAN_API_KEY");
    }

    if (api_key) {
        strncpy(config->api_key, api_key, sizeof(config->api_key) - 1);
        config->configured = true;
        return 0;
    }

    return -1;
}

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    char *buffer = (char *)userp;
    strncat(buffer, contents, realsize);
    return realsize;
}

int shodan_host_lookup(shodan_config_t *config, const char *ip, shodan_host_info_t *info) {
    if (!config || !config->configured || !ip || !info) return -1;

    memset(info, 0, sizeof(shodan_host_info_t));
    strncpy(info->ip, ip, sizeof(info->ip) - 1);

    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    char url[512];
    snprintf(url, sizeof(url), "%s/shodan/host/%s?key=%s",
             SHODAN_API_BASE, ip, config->api_key);

    char response[65536] = {0};

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) return -1;

    // Parse JSON response (simplified - would use cJSON in production)
    // Extract: org, isp, country_code, city, ports, vulns, os
    // This is a stub - full JSON parsing would be implemented here

    return 0;
}

int shodan_dns_resolve(shodan_config_t *config, const char *hostname, char *ip, size_t ip_size) {
    if (!config || !config->configured || !hostname || !ip) return -1;

    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    char url[512];
    snprintf(url, sizeof(url), "%s/dns/resolve?hostnames=%s&key=%s",
             SHODAN_API_BASE, hostname, config->api_key);

    char response[4096] = {0};

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) return -1;

    // Parse JSON and extract IP
    // Stub implementation

    return 0;
}

int shodan_search(shodan_config_t *config, const char *query, char *results, size_t size) {
    if (!config || !config->configured || !query || !results) return -1;

    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    char url[1024];
    char *encoded_query = curl_easy_escape(curl, query, 0);
    snprintf(url, sizeof(url), "%s/shodan/host/search?query=%s&key=%s",
             SHODAN_API_BASE, encoded_query, config->api_key);
    curl_free(encoded_query);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, results);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    return (res == CURLE_OK) ? 0 : -1;
}
