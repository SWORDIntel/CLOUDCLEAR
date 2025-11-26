/*
 * CloudClear TUI - Configuration and API Key Management
 *
 * Secure API key storage and configuration management for cloud providers
 */

#ifndef CLOUDCLEAR_TUI_CONFIG_H
#define CLOUDCLEAR_TUI_CONFIG_H

#include <stdbool.h>
#include <stddef.h>

#define CONFIG_FILE_PATH ".cloudclear/config.enc"
#define MAX_API_KEY_LENGTH 512

// API Key configuration structure
typedef struct {
    // Intelligence Services
    char shodan_api_key[MAX_API_KEY_LENGTH];
    char censys_api_id[MAX_API_KEY_LENGTH];
    char censys_api_secret[MAX_API_KEY_LENGTH];
    char virustotal_api_key[MAX_API_KEY_LENGTH];

    // Akamai EdgeGrid
    char akamai_client_token[MAX_API_KEY_LENGTH];
    char akamai_client_secret[MAX_API_KEY_LENGTH];
    char akamai_access_token[MAX_API_KEY_LENGTH];

    // AWS
    char aws_access_key_id[MAX_API_KEY_LENGTH];
    char aws_secret_access_key[MAX_API_KEY_LENGTH];
    char aws_region[64];

    // Azure
    char azure_subscription_id[MAX_API_KEY_LENGTH];
    char azure_client_id[MAX_API_KEY_LENGTH];
    char azure_client_secret[MAX_API_KEY_LENGTH];
    char azure_tenant_id[MAX_API_KEY_LENGTH];

    // GCP
    char gcp_project_id[MAX_API_KEY_LENGTH];
    char gcp_credentials_path[512];

    // Other providers
    char fastly_api_key[MAX_API_KEY_LENGTH];
    char digitalocean_api_token[MAX_API_KEY_LENGTH];

    // Configuration flags
    bool shodan_enabled;
    bool censys_enabled;
    bool virustotal_enabled;
    bool akamai_enabled;
    bool aws_enabled;
    bool azure_enabled;
    bool gcp_enabled;
    bool fastly_enabled;
    bool digitalocean_enabled;
} tui_api_config_t;

// Configuration management functions
int tui_config_init(tui_api_config_t *config);
int tui_config_load(tui_api_config_t *config);
int tui_config_save(const tui_api_config_t *config);
void tui_config_clear(tui_api_config_t *config);

// API key validation
bool tui_validate_api_key(const char *provider, const char *api_key);
int tui_test_api_key(const char *provider, const tui_api_config_t *config);

// Secure storage
int tui_encrypt_config(const tui_api_config_t *config, char *output, size_t output_size);
int tui_decrypt_config(const char *input, tui_api_config_t *config);

// Environment variable integration
void tui_export_to_env(const tui_api_config_t *config);
void tui_import_from_env(tui_api_config_t *config);

#endif // CLOUDCLEAR_TUI_CONFIG_H
