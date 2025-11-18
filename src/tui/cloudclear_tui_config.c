/*
 * CloudClear TUI - Configuration and API Key Management Implementation
 */

#include "cloudclear_tui_config.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

// Initialize configuration with defaults
int tui_config_init(tui_api_config_t *config) {
    if (!config) return -1;

    memset(config, 0, sizeof(tui_api_config_t));

    // Set default region
    strncpy(config->aws_region, "us-east-1", sizeof(config->aws_region) - 1);

    // All services disabled by default until keys are configured
    config->shodan_enabled = false;
    config->censys_enabled = false;
    config->virustotal_enabled = false;
    config->akamai_enabled = false;
    config->aws_enabled = false;
    config->azure_enabled = false;
    config->gcp_enabled = false;
    config->fastly_enabled = false;
    config->digitalocean_enabled = false;

    return 0;
}

// Load configuration from file
int tui_config_load(tui_api_config_t *config) {
    if (!config) return -1;

    // Try to load from environment variables first
    tui_import_from_env(config);

    // Then try to load from config file
    FILE *fp = fopen(CONFIG_FILE_PATH, "r");
    if (!fp) {
        // File doesn't exist, use environment variables only
        return 0;
    }

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        // Remove newline
        line[strcspn(line, "\n")] = 0;

        // Skip empty lines and comments
        if (line[0] == '\0' || line[0] == '#') continue;

        // Parse key=value pairs
        char *equals = strchr(line, '=');
        if (!equals) continue;

        *equals = '\0';
        char *key = line;
        char *value = equals + 1;

        // Map keys to config fields
        if (strcmp(key, "SHODAN_API_KEY") == 0) {
            strncpy(config->shodan_api_key, value, MAX_API_KEY_LENGTH - 1);
            config->shodan_enabled = (strlen(value) > 0);
        } else if (strcmp(key, "CENSYS_API_ID") == 0) {
            strncpy(config->censys_api_id, value, MAX_API_KEY_LENGTH - 1);
        } else if (strcmp(key, "CENSYS_API_SECRET") == 0) {
            strncpy(config->censys_api_secret, value, MAX_API_KEY_LENGTH - 1);
            config->censys_enabled = (strlen(config->censys_api_id) > 0 && strlen(value) > 0);
        } else if (strcmp(key, "VIRUSTOTAL_API_KEY") == 0) {
            strncpy(config->virustotal_api_key, value, MAX_API_KEY_LENGTH - 1);
            config->virustotal_enabled = (strlen(value) > 0);
        } else if (strcmp(key, "AKAMAI_CLIENT_TOKEN") == 0) {
            strncpy(config->akamai_client_token, value, MAX_API_KEY_LENGTH - 1);
        } else if (strcmp(key, "AKAMAI_CLIENT_SECRET") == 0) {
            strncpy(config->akamai_client_secret, value, MAX_API_KEY_LENGTH - 1);
        } else if (strcmp(key, "AKAMAI_ACCESS_TOKEN") == 0) {
            strncpy(config->akamai_access_token, value, MAX_API_KEY_LENGTH - 1);
            config->akamai_enabled = (strlen(config->akamai_client_token) > 0);
        } else if (strcmp(key, "AWS_ACCESS_KEY_ID") == 0) {
            strncpy(config->aws_access_key_id, value, MAX_API_KEY_LENGTH - 1);
        } else if (strcmp(key, "AWS_SECRET_ACCESS_KEY") == 0) {
            strncpy(config->aws_secret_access_key, value, MAX_API_KEY_LENGTH - 1);
            config->aws_enabled = (strlen(config->aws_access_key_id) > 0 && strlen(value) > 0);
        } else if (strcmp(key, "AWS_REGION") == 0) {
            strncpy(config->aws_region, value, sizeof(config->aws_region) - 1);
        } else if (strcmp(key, "AZURE_SUBSCRIPTION_ID") == 0) {
            strncpy(config->azure_subscription_id, value, MAX_API_KEY_LENGTH - 1);
        } else if (strcmp(key, "AZURE_CLIENT_ID") == 0) {
            strncpy(config->azure_client_id, value, MAX_API_KEY_LENGTH - 1);
        } else if (strcmp(key, "AZURE_CLIENT_SECRET") == 0) {
            strncpy(config->azure_client_secret, value, MAX_API_KEY_LENGTH - 1);
        } else if (strcmp(key, "AZURE_TENANT_ID") == 0) {
            strncpy(config->azure_tenant_id, value, MAX_API_KEY_LENGTH - 1);
            config->azure_enabled = (strlen(config->azure_client_id) > 0);
        } else if (strcmp(key, "GCP_PROJECT_ID") == 0) {
            strncpy(config->gcp_project_id, value, MAX_API_KEY_LENGTH - 1);
            config->gcp_enabled = (strlen(value) > 0);
        } else if (strcmp(key, "GCP_CREDENTIALS_PATH") == 0) {
            strncpy(config->gcp_credentials_path, value, sizeof(config->gcp_credentials_path) - 1);
        } else if (strcmp(key, "FASTLY_API_KEY") == 0) {
            strncpy(config->fastly_api_key, value, MAX_API_KEY_LENGTH - 1);
            config->fastly_enabled = (strlen(value) > 0);
        } else if (strcmp(key, "DIGITALOCEAN_API_TOKEN") == 0) {
            strncpy(config->digitalocean_api_token, value, MAX_API_KEY_LENGTH - 1);
            config->digitalocean_enabled = (strlen(value) > 0);
        }
    }

    fclose(fp);
    return 0;
}

// Save configuration to file
int tui_config_save(const tui_api_config_t *config) {
    if (!config) return -1;

    // Create directory if it doesn't exist
    char dir_path[] = ".cloudclear";
    mkdir(dir_path, 0700); // rwx for owner only

    FILE *fp = fopen(CONFIG_FILE_PATH, "w");
    if (!fp) {
        return -1;
    }

    // Set restrictive permissions
    chmod(CONFIG_FILE_PATH, 0600); // rw for owner only

    fprintf(fp, "# CloudClear API Configuration\n");
    fprintf(fp, "# Generated by CloudClear TUI\n\n");

    if (strlen(config->shodan_api_key) > 0) {
        fprintf(fp, "SHODAN_API_KEY=%s\n", config->shodan_api_key);
    }

    if (strlen(config->censys_api_id) > 0) {
        fprintf(fp, "CENSYS_API_ID=%s\n", config->censys_api_id);
        fprintf(fp, "CENSYS_API_SECRET=%s\n", config->censys_api_secret);
    }

    if (strlen(config->virustotal_api_key) > 0) {
        fprintf(fp, "VIRUSTOTAL_API_KEY=%s\n", config->virustotal_api_key);
    }

    if (strlen(config->akamai_client_token) > 0) {
        fprintf(fp, "\nAKAMAI_CLIENT_TOKEN=%s\n", config->akamai_client_token);
        fprintf(fp, "AKAMAI_CLIENT_SECRET=%s\n", config->akamai_client_secret);
        fprintf(fp, "AKAMAI_ACCESS_TOKEN=%s\n", config->akamai_access_token);
    }

    if (strlen(config->aws_access_key_id) > 0) {
        fprintf(fp, "\nAWS_ACCESS_KEY_ID=%s\n", config->aws_access_key_id);
        fprintf(fp, "AWS_SECRET_ACCESS_KEY=%s\n", config->aws_secret_access_key);
        fprintf(fp, "AWS_REGION=%s\n", config->aws_region);
    }

    if (strlen(config->azure_client_id) > 0) {
        fprintf(fp, "\nAZURE_SUBSCRIPTION_ID=%s\n", config->azure_subscription_id);
        fprintf(fp, "AZURE_CLIENT_ID=%s\n", config->azure_client_id);
        fprintf(fp, "AZURE_CLIENT_SECRET=%s\n", config->azure_client_secret);
        fprintf(fp, "AZURE_TENANT_ID=%s\n", config->azure_tenant_id);
    }

    if (strlen(config->gcp_project_id) > 0) {
        fprintf(fp, "\nGCP_PROJECT_ID=%s\n", config->gcp_project_id);
        fprintf(fp, "GCP_CREDENTIALS_PATH=%s\n", config->gcp_credentials_path);
    }

    if (strlen(config->fastly_api_key) > 0) {
        fprintf(fp, "\nFASTLY_API_KEY=%s\n", config->fastly_api_key);
    }

    if (strlen(config->digitalocean_api_token) > 0) {
        fprintf(fp, "\nDIGITALOCEAN_API_TOKEN=%s\n", config->digitalocean_api_token);
    }

    fclose(fp);
    return 0;
}

// Clear configuration
void tui_config_clear(tui_api_config_t *config) {
    if (config) {
        memset(config, 0, sizeof(tui_api_config_t));
    }
}

// Validate API key format
bool tui_validate_api_key(const char *provider, const char *api_key) {
    if (!provider || !api_key) return false;

    // Basic length validation
    size_t len = strlen(api_key);
    if (len < 10) return false; // Most API keys are at least 10 chars

    // Provider-specific validation
    if (strcmp(provider, "shodan") == 0) {
        return (len == 32); // Shodan keys are 32 chars
    } else if (strcmp(provider, "virustotal") == 0) {
        return (len == 64); // VT keys are 64 chars
    } else if (strcmp(provider, "aws") == 0) {
        return (len >= 16); // AWS access keys are ~20 chars
    }

    // Generic validation for other providers
    return true;
}

// Test API key by making a simple API call
int tui_test_api_key(const char *provider, const tui_api_config_t *config) {
    if (!provider || !config) return -1;

    // This would make actual API calls to test the keys
    // For now, just return success if key is present
    if (strcmp(provider, "shodan") == 0) {
        return (strlen(config->shodan_api_key) > 0) ? 0 : -1;
    } else if (strcmp(provider, "censys") == 0) {
        return (strlen(config->censys_api_id) > 0 &&
                strlen(config->censys_api_secret) > 0) ? 0 : -1;
    } else if (strcmp(provider, "virustotal") == 0) {
        return (strlen(config->virustotal_api_key) > 0) ? 0 : -1;
    }

    return -1;
}

// Import from environment variables
void tui_import_from_env(tui_api_config_t *config) {
    if (!config) return;

    const char *val;

    if ((val = getenv("SHODAN_API_KEY")) != NULL) {
        strncpy(config->shodan_api_key, val, MAX_API_KEY_LENGTH - 1);
        config->shodan_enabled = true;
    }

    if ((val = getenv("CENSYS_API_ID")) != NULL) {
        strncpy(config->censys_api_id, val, MAX_API_KEY_LENGTH - 1);
    }
    if ((val = getenv("CENSYS_API_SECRET")) != NULL) {
        strncpy(config->censys_api_secret, val, MAX_API_KEY_LENGTH - 1);
        config->censys_enabled = (strlen(config->censys_api_id) > 0);
    }

    if ((val = getenv("VIRUSTOTAL_API_KEY")) != NULL) {
        strncpy(config->virustotal_api_key, val, MAX_API_KEY_LENGTH - 1);
        config->virustotal_enabled = true;
    }

    if ((val = getenv("AKAMAI_CLIENT_TOKEN")) != NULL) {
        strncpy(config->akamai_client_token, val, MAX_API_KEY_LENGTH - 1);
    }
    if ((val = getenv("AKAMAI_CLIENT_SECRET")) != NULL) {
        strncpy(config->akamai_client_secret, val, MAX_API_KEY_LENGTH - 1);
    }
    if ((val = getenv("AKAMAI_ACCESS_TOKEN")) != NULL) {
        strncpy(config->akamai_access_token, val, MAX_API_KEY_LENGTH - 1);
        config->akamai_enabled = (strlen(config->akamai_client_token) > 0);
    }

    if ((val = getenv("AWS_ACCESS_KEY_ID")) != NULL) {
        strncpy(config->aws_access_key_id, val, MAX_API_KEY_LENGTH - 1);
    }
    if ((val = getenv("AWS_SECRET_ACCESS_KEY")) != NULL) {
        strncpy(config->aws_secret_access_key, val, MAX_API_KEY_LENGTH - 1);
        config->aws_enabled = (strlen(config->aws_access_key_id) > 0);
    }
    if ((val = getenv("AWS_REGION")) != NULL) {
        strncpy(config->aws_region, val, sizeof(config->aws_region) - 1);
    }

    if ((val = getenv("FASTLY_API_KEY")) != NULL) {
        strncpy(config->fastly_api_key, val, MAX_API_KEY_LENGTH - 1);
        config->fastly_enabled = true;
    }

    if ((val = getenv("DIGITALOCEAN_API_TOKEN")) != NULL) {
        strncpy(config->digitalocean_api_token, val, MAX_API_KEY_LENGTH - 1);
        config->digitalocean_enabled = true;
    }
}

// Export to environment variables
void tui_export_to_env(const tui_api_config_t *config) {
    if (!config) return;

    if (strlen(config->shodan_api_key) > 0) {
        setenv("SHODAN_API_KEY", config->shodan_api_key, 1);
    }

    if (strlen(config->censys_api_id) > 0) {
        setenv("CENSYS_API_ID", config->censys_api_id, 1);
        setenv("CENSYS_API_SECRET", config->censys_api_secret, 1);
    }

    if (strlen(config->virustotal_api_key) > 0) {
        setenv("VIRUSTOTAL_API_KEY", config->virustotal_api_key, 1);
    }

    if (strlen(config->akamai_client_token) > 0) {
        setenv("AKAMAI_CLIENT_TOKEN", config->akamai_client_token, 1);
        setenv("AKAMAI_CLIENT_SECRET", config->akamai_client_secret, 1);
        setenv("AKAMAI_ACCESS_TOKEN", config->akamai_access_token, 1);
    }

    if (strlen(config->aws_access_key_id) > 0) {
        setenv("AWS_ACCESS_KEY_ID", config->aws_access_key_id, 1);
        setenv("AWS_SECRET_ACCESS_KEY", config->aws_secret_access_key, 1);
        setenv("AWS_REGION", config->aws_region, 1);
    }

    if (strlen(config->fastly_api_key) > 0) {
        setenv("FASTLY_API_KEY", config->fastly_api_key, 1);
    }

    if (strlen(config->digitalocean_api_token) > 0) {
        setenv("DIGITALOCEAN_API_TOKEN", config->digitalocean_api_token, 1);
    }
}
