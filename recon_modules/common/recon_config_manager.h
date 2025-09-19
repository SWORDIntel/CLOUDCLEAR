/*
 * CloudUnflare Enhanced - Reconnaissance Configuration Manager
 *
 * Centralized configuration management for all reconnaissance modules
 * with hot-reload, validation, and integration with CloudUnflare's main config
 *
 * Agent: ARCHITECT (configuration design)
 * Coordination: SECURITY, OPTIMIZER, C-INTERNAL
 * Features: Hot-reload, validation, OPSEC-aware defaults
 */

#ifndef RECON_CONFIG_MANAGER_H
#define RECON_CONFIG_MANAGER_H

#include "recon_module_interface.h"
#include "recon_opsec.h"
#include <json-c/json.h>
#include <sys/inotify.h>

// Configuration source types
typedef enum {
    CONFIG_SOURCE_FILE,
    CONFIG_SOURCE_ENVIRONMENT,
    CONFIG_SOURCE_COMMAND_LINE,
    CONFIG_SOURCE_RUNTIME_UPDATE,
    CONFIG_SOURCE_DEFAULT
} config_source_t;

// Configuration validation levels
typedef enum {
    CONFIG_VALIDATION_NONE,
    CONFIG_VALIDATION_BASIC,
    CONFIG_VALIDATION_STRICT,
    CONFIG_VALIDATION_PARANOID
} config_validation_level_t;

// Configuration change types
typedef enum {
    CONFIG_CHANGE_ADDED,
    CONFIG_CHANGE_MODIFIED,
    CONFIG_CHANGE_REMOVED,
    CONFIG_CHANGE_RELOADED
} config_change_type_t;

// Configuration value types
typedef enum {
    CONFIG_TYPE_STRING,
    CONFIG_TYPE_INTEGER,
    CONFIG_TYPE_DOUBLE,
    CONFIG_TYPE_BOOLEAN,
    CONFIG_TYPE_ARRAY,
    CONFIG_TYPE_OBJECT
} config_value_type_t;

// Configuration value with metadata
typedef struct {
    char key[128];
    config_value_type_t type;
    config_source_t source;
    union {
        char *string_value;
        int64_t int_value;
        double double_value;
        bool bool_value;
        json_object *json_value;
    } value;
    bool is_sensitive;
    bool requires_restart;
    time_t last_modified;
    char description[256];
} config_value_t;

// Module-specific configuration section
typedef struct {
    char module_name[RECON_MODULE_MAX_NAME_LEN];
    config_value_t *values;
    uint32_t value_count;
    uint32_t max_values;
    bool enabled;
    time_t last_updated;
    pthread_mutex_t section_mutex;
} config_section_t;

// Configuration file watcher
typedef struct {
    int inotify_fd;
    int watch_descriptor;
    char config_file_path[512];
    time_t last_modification;
    pthread_t watcher_thread;
    bool watcher_running;
    void (*change_callback)(const char *file_path, config_change_type_t change_type);
} config_file_watcher_t;

// Configuration validation rule
typedef struct {
    char key_pattern[128];
    config_value_type_t expected_type;
    bool required;
    union {
        struct {
            int64_t min_value;
            int64_t max_value;
        } int_range;
        struct {
            double min_value;
            double max_value;
        } double_range;
        struct {
            size_t min_length;
            size_t max_length;
            char allowed_pattern[256];
        } string_constraints;
    } constraints;
    char error_message[256];
} config_validation_rule_t;

// Configuration manager context
typedef struct {
    // Configuration sections
    config_section_t *sections;
    uint32_t section_count;
    uint32_t max_sections;
    pthread_rwlock_t config_rwlock;

    // File watching
    config_file_watcher_t file_watcher;
    bool hot_reload_enabled;
    bool auto_save_enabled;

    // Validation
    config_validation_rule_t *validation_rules;
    uint32_t rule_count;
    config_validation_level_t validation_level;

    // Global settings
    char main_config_file[512];
    char recon_config_file[512];
    char backup_config_dir[512];
    bool config_encryption_enabled;
    char config_encryption_key[64];

    // Change tracking
    struct {
        config_change_type_t *changes;
        char (*changed_keys)[128];
        time_t *change_times;
        uint32_t change_count;
        uint32_t max_changes;
        pthread_mutex_t change_mutex;
    } change_log;

    // OPSEC integration
    opsec_paranoia_level_t global_opsec_level;
    bool opsec_config_obfuscation;
    bool opsec_config_splitting;

    // Performance settings
    bool lazy_loading_enabled;
    uint32_t config_cache_size;
    time_t config_cache_ttl;

    // Emergency settings
    bool emergency_mode_active;
    char emergency_config_file[512];
    config_section_t emergency_overrides;
} config_manager_t;

// Pre-defined configuration templates
typedef struct {
    char name[64];
    char description[256];
    opsec_paranoia_level_t opsec_level;
    recon_mode_t scan_mode;
    json_object *template_config;
} config_template_t;

// Function prototypes

// Configuration manager lifecycle
int config_manager_init(config_manager_t *manager, const char *main_config_file);
int config_manager_load_config(config_manager_t *manager);
int config_manager_save_config(config_manager_t *manager);
int config_manager_reload_config(config_manager_t *manager);
void config_manager_cleanup(config_manager_t *manager);

// Section management
int config_manager_add_section(config_manager_t *manager, const char *section_name);
int config_manager_remove_section(config_manager_t *manager, const char *section_name);
config_section_t *config_manager_get_section(config_manager_t *manager, const char *section_name);
bool config_manager_has_section(const config_manager_t *manager, const char *section_name);

// Value management
int config_set_string(config_manager_t *manager, const char *section, const char *key, const char *value);
int config_set_int(config_manager_t *manager, const char *section, const char *key, int64_t value);
int config_set_double(config_manager_t *manager, const char *section, const char *key, double value);
int config_set_bool(config_manager_t *manager, const char *section, const char *key, bool value);
int config_set_json(config_manager_t *manager, const char *section, const char *key, json_object *value);

const char *config_get_string(config_manager_t *manager, const char *section, const char *key, const char *default_value);
int64_t config_get_int(config_manager_t *manager, const char *section, const char *key, int64_t default_value);
double config_get_double(config_manager_t *manager, const char *section, const char *key, double default_value);
bool config_get_bool(config_manager_t *manager, const char *section, const char *key, bool default_value);
json_object *config_get_json(config_manager_t *manager, const char *section, const char *key);

bool config_has_key(config_manager_t *manager, const char *section, const char *key);
int config_remove_key(config_manager_t *manager, const char *section, const char *key);

// Validation system
int config_manager_add_validation_rule(config_manager_t *manager, const config_validation_rule_t *rule);
int config_manager_validate_all(config_manager_t *manager, char **error_messages, uint32_t *error_count);
int config_manager_validate_section(config_manager_t *manager, const char *section_name, char **error_messages, uint32_t *error_count);
int config_manager_validate_key(config_manager_t *manager, const char *section, const char *key, char **error_message);

// File watching and hot-reload
int config_manager_enable_hot_reload(config_manager_t *manager);
int config_manager_disable_hot_reload(config_manager_t *manager);
void *config_file_watcher_thread(void *arg);
int config_manager_handle_file_change(config_manager_t *manager, const char *file_path);

// Module configuration helpers
int config_manager_configure_module(config_manager_t *manager, recon_module_t *module);
int config_manager_apply_module_defaults(config_manager_t *manager, const char *module_name, const recon_module_config_t *defaults);
int config_manager_get_module_config(config_manager_t *manager, const char *module_name, recon_module_config_t *config);
int config_manager_update_module_config(config_manager_t *manager, const char *module_name, const recon_module_config_t *config);

// OPSEC-aware configuration
int config_manager_apply_opsec_defaults(config_manager_t *manager, opsec_paranoia_level_t level);
int config_manager_obfuscate_sensitive_values(config_manager_t *manager);
int config_manager_split_config_for_opsec(config_manager_t *manager);
int config_manager_encrypt_config_file(config_manager_t *manager, const char *key);

// Template management
int config_manager_load_templates(config_manager_t *manager, const char *template_dir);
int config_manager_apply_template(config_manager_t *manager, const char *template_name);
int config_manager_create_template(config_manager_t *manager, const char *template_name, const char *description);
config_template_t *config_manager_get_template(config_manager_t *manager, const char *template_name);

// Change tracking and history
int config_manager_log_change(config_manager_t *manager, const char *key, config_change_type_t change_type);
int config_manager_get_change_history(config_manager_t *manager, const char *key, config_change_type_t **changes, time_t **timestamps, uint32_t *count);
int config_manager_rollback_changes(config_manager_t *manager, time_t rollback_time);

// Emergency mode
int config_manager_enter_emergency_mode(config_manager_t *manager, const char *emergency_config_file);
int config_manager_exit_emergency_mode(config_manager_t *manager);
bool config_manager_is_emergency_mode(const config_manager_t *manager);

// Import/Export
int config_manager_export_config(config_manager_t *manager, const char *export_file, const char *format);
int config_manager_import_config(config_manager_t *manager, const char *import_file, const char *format);
int config_manager_merge_config(config_manager_t *manager, const char *merge_file);

// Backup and restore
int config_manager_create_backup(config_manager_t *manager, const char *backup_name);
int config_manager_restore_backup(config_manager_t *manager, const char *backup_name);
int config_manager_list_backups(config_manager_t *manager, char ***backup_names, uint32_t *count);

// Integration with CloudUnflare main config
int config_manager_sync_with_main_config(config_manager_t *manager, const char *main_config_file);
int config_manager_extract_recon_config(config_manager_t *manager, const char *main_config_file);
int config_manager_merge_into_main_config(config_manager_t *manager, const char *main_config_file);

// Utility functions
int config_manager_print_config(const config_manager_t *manager, const char *section_name);
int config_manager_generate_sample_config(const char *output_file);
int config_manager_verify_config_integrity(config_manager_t *manager);
const char *config_value_type_to_string(config_value_type_t type);
const char *config_source_to_string(config_source_t source);

// Global configuration manager
extern config_manager_t global_config_manager;

// Configuration defaults for each module type
extern const recon_module_config_t dns_zone_transfer_default_config;
extern const recon_module_config_t dns_bruteforce_default_config;
extern const recon_module_config_t http_banner_default_config;
extern const recon_module_config_t port_scanner_default_config;

// OPSEC configuration presets
extern const config_template_t opsec_normal_template;
extern const config_template_t opsec_high_template;
extern const config_template_t opsec_maximum_template;
extern const config_template_t opsec_ghost_template;

// Configuration macros
#define CONFIG_GET_STRING(section, key, default) \
    config_get_string(&global_config_manager, section, key, default)

#define CONFIG_GET_INT(section, key, default) \
    config_get_int(&global_config_manager, section, key, default)

#define CONFIG_GET_BOOL(section, key, default) \
    config_get_bool(&global_config_manager, section, key, default)

#define CONFIG_SET_STRING(section, key, value) \
    config_set_string(&global_config_manager, section, key, value)

#define CONFIG_SET_INT(section, key, value) \
    config_set_int(&global_config_manager, section, key, value)

#define CONFIG_SET_BOOL(section, key, value) \
    config_set_bool(&global_config_manager, section, key, value)

#endif // RECON_CONFIG_MANAGER_H