/*
 * Censys API Integration Implementation
 */

#include "censys_api.h"
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>

int censys_init(censys_config_t *config, const char *api_id, const char *api_secret) {
    if (!config) return -1;

    memset(config, 0, sizeof(censys_config_t));

    if (!api_id) api_id = getenv("CENSYS_API_ID");
    if (!api_secret) api_secret = getenv("CENSYS_API_SECRET");

    if (api_id && api_secret) {
        strncpy(config->api_id, api_id, sizeof(config->api_id) - 1);
        strncpy(config->api_secret, api_secret, sizeof(config->api_secret) - 1);
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

int censys_search_certificates(censys_config_t *config, const char *domain,
                                censys_cert_info_t *certs, uint32_t *cert_count) {
    if (!config || !config->configured || !domain || !certs || !cert_count) return -1;

    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    char url[512];
    snprintf(url, sizeof(url), "%s/certificates/search?q=names:%s",
             CENSYS_API_BASE, domain);

    char response[65536] = {0};

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_easy_setopt(curl, CURLOPT_USERNAME, config->api_id);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, config->api_secret);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) return -1;

    // Parse JSON response and populate certs array
    // Stub implementation
    *cert_count = 0;

    return 0;
}

int censys_host_lookup(censys_config_t *config, const char *ip, censys_host_info_t *info) {
    if (!config || !config->configured || !ip || !info) return -1;

    memset(info, 0, sizeof(censys_host_info_t));
    strncpy(info->ip, ip, sizeof(info->ip) - 1);

    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    char url[512];
    snprintf(url, sizeof(url), "%s/hosts/%s", CENSYS_API_BASE, ip);

    char response[65536] = {0};

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_easy_setopt(curl, CURLOPT_USERNAME, config->api_id);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, config->api_secret);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    return (res == CURLE_OK) ? 0 : -1;
}

int censys_search_hosts(censys_config_t *config, const char *query, char *results, size_t size) {
    if (!config || !config->configured || !query || !results) return -1;

    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    char url[1024];
    snprintf(url, sizeof(url), "%s/hosts/search?q=%s", CENSYS_API_BASE, query);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_easy_setopt(curl, CURLOPT_USERNAME, config->api_id);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, config->api_secret);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, results);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    return (res == CURLE_OK) ? 0 : -1;
}
