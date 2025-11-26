/*
 * CloudClear TUI - Enhanced Module Integration
 *
 * Adds interactive TUI support for:
 * - CVE-2025 Detector
 * - Advanced Reconnaissance
 * - Crypto Offensive Analysis
 */

#ifndef CLOUDCLEAR_TUI_ENHANCED_MODULES_H
#define CLOUDCLEAR_TUI_ENHANCED_MODULES_H

#include "cloudclear_tui.h"

#ifdef RECON_MODULES_ENABLED
#include "recon/cve_2025_detector/cve_2025_detector.h"
#include "recon/advanced_recon/advanced_recon.h"
#include "recon/crypto_offensive/crypto_offensive.h"
#endif

// Extended screen types for new modules
typedef enum {
    SCREEN_MODULE_MENU = 100,      // Module selection menu
    SCREEN_CVE_SCAN,               // CVE-2025 scanning
    SCREEN_CVE_RESULTS,            // CVE-2025 results
    SCREEN_ADVANCED_RECON,         // Advanced recon selection
    SCREEN_ADVANCED_RECON_RUNNING, // Advanced recon in progress
    SCREEN_ADVANCED_RECON_RESULTS, // Advanced recon results
    SCREEN_CRYPTO_OFFENSIVE,       // Crypto offensive scan
    SCREEN_CRYPTO_RESULTS,         // Crypto offensive results
    SCREEN_SSL_CERT_ENUM,          // SSL certificate enumeration
    SCREEN_IPV6_SCAN,              // IPv6 scanning
    SCREEN_DNS_CACHE_SNOOP,        // DNS cache snooping
    SCREEN_PASSIVE_DNS,            // Passive DNS monitoring
    SCREEN_WEB_FINGERPRINT,        // Web fingerprinting
    SCREEN_EMAIL_ENUM,             // Email enumeration
} tui_enhanced_screen_t;

// Extended TUI state for new modules
typedef struct {
    struct tui_state base;         // Base TUI state

    // CVE-2025 state
    #ifdef RECON_MODULES_ENABLED
    cve_detection_context_t cve_ctx;
    bool cve_scan_active;
    int cve_vulnerabilities_found;
    int cve_critical_count;
    #endif

    // Advanced Recon state
    #ifdef RECON_MODULES_ENABLED
    advanced_recon_context_t recon_ctx;
    bool advanced_recon_active;
    int recon_findings_count;
    int recon_module_selection;    // Bitmask of selected modules
    #endif

    // Crypto Offensive state
    #ifdef RECON_MODULES_ENABLED
    crypto_offensive_context_t crypto_ctx;
    bool crypto_scan_active;
    int dsssl_targets_found;
    int pqc_targets_found;
    int vulnerable_targets_found;
    #endif

    // UI state
    int module_menu_selection;
    int advanced_recon_menu_selection;
    bool show_module_details;
    int result_scroll_offset;
    int selected_result_index;

} tui_enhanced_state_t;

// Module menu items
typedef enum {
    MODULE_MENU_CVE_DETECTOR,
    MODULE_MENU_ADVANCED_RECON,
    MODULE_MENU_CRYPTO_OFFENSIVE,
    MODULE_MENU_BACK,
    MODULE_MENU_COUNT
} module_menu_item_t;

// Advanced recon module flags
#define RECON_MODULE_SSL_CERT       (1 << 0)
#define RECON_MODULE_IPV6           (1 << 1)
#define RECON_MODULE_DNS_CACHE      (1 << 2)
#define RECON_MODULE_PASSIVE_DNS    (1 << 3)
#define RECON_MODULE_REGIONAL       (1 << 4)
#define RECON_MODULE_WEB_FINGER     (1 << 5)
#define RECON_MODULE_API_DISCOVERY  (1 << 6)
#define RECON_MODULE_DIR_BRUTE      (1 << 7)
#define RECON_MODULE_EMAIL_ENUM     (1 << 8)
#define RECON_MODULE_METADATA       (1 << 9)
#define RECON_MODULE_HISTORICAL_DNS (1 << 10)

// Function prototypes

// Enhanced initialization
int tui_enhanced_init(tui_enhanced_state_t *state);
void tui_enhanced_cleanup(tui_enhanced_state_t *state);

// Module menu
void tui_show_module_menu(tui_enhanced_state_t *state);
int tui_handle_module_menu_key(tui_enhanced_state_t *state, int key);

// CVE-2025 Detector screens
void tui_show_cve_scan_screen(tui_enhanced_state_t *state);
void tui_show_cve_results_screen(tui_enhanced_state_t *state);
void tui_start_cve_scan(tui_enhanced_state_t *state, const char *target);
void tui_update_cve_progress(tui_enhanced_state_t *state);
void tui_draw_cve_vulnerability_list(WINDOW *win, tui_enhanced_state_t *state);

// Advanced Recon screens
void tui_show_advanced_recon_menu(tui_enhanced_state_t *state);
void tui_show_advanced_recon_running(tui_enhanced_state_t *state);
void tui_show_advanced_recon_results(tui_enhanced_state_t *state);
void tui_start_advanced_recon(tui_enhanced_state_t *state, const char *target);
void tui_update_advanced_recon_progress(tui_enhanced_state_t *state);
void tui_draw_recon_module_status(WINDOW *win, tui_enhanced_state_t *state);

// Crypto Offensive screens
void tui_show_crypto_offensive_screen(tui_enhanced_state_t *state);
void tui_show_crypto_results_screen(tui_enhanced_state_t *state);
void tui_start_crypto_scan(tui_enhanced_state_t *state, const char *target, uint16_t port);
void tui_update_crypto_progress(tui_enhanced_state_t *state);
void tui_draw_crypto_analysis(WINDOW *win, crypto_analysis_result_t *result);

// Individual module screens
void tui_show_ssl_cert_enum_screen(tui_enhanced_state_t *state);
void tui_show_ipv6_scan_screen(tui_enhanced_state_t *state);
void tui_show_dns_cache_snoop_screen(tui_enhanced_state_t *state);
void tui_show_passive_dns_screen(tui_enhanced_state_t *state);
void tui_show_web_fingerprint_screen(tui_enhanced_state_t *state);
void tui_show_email_enum_screen(tui_enhanced_state_t *state);

// Drawing helpers
void tui_draw_security_score(WINDOW *win, int y, int x, float score);
void tui_draw_pqc_indicator(WINDOW *win, int y, int x, bool detected);
void tui_draw_dsssl_badge(WINDOW *win, int y, int x, const char *profile);
void tui_draw_vulnerability_severity(WINDOW *win, int y, int x, cve_severity_t severity);
void tui_draw_module_progress_grid(WINDOW *win, tui_enhanced_state_t *state);

// Realtime update callbacks
void tui_callback_cve_found(const char *cve_id, cve_severity_t severity);
void tui_callback_pqc_detected(const char *algorithm);
void tui_callback_dsssl_detected(const char *profile);
void tui_callback_vulnerability_found(const char *type);
void tui_callback_recon_finding(const char *module, const char *finding);

// Statistics and summaries
void tui_draw_enhanced_statistics(WINDOW *win, tui_enhanced_state_t *state);
void tui_draw_module_summary(WINDOW *win, tui_enhanced_state_t *state);

// Input handlers
int tui_handle_cve_screen_key(tui_enhanced_state_t *state, int key);
int tui_handle_advanced_recon_key(tui_enhanced_state_t *state, int key);
int tui_handle_crypto_screen_key(tui_enhanced_state_t *state, int key);

// Thread functions for background scanning
void* tui_cve_scan_thread(void *arg);
void* tui_advanced_recon_thread(void *arg);
void* tui_crypto_scan_thread(void *arg);

// Export functions
void tui_export_cve_results(tui_enhanced_state_t *state, const char *filename);
void tui_export_recon_results(tui_enhanced_state_t *state, const char *filename);
void tui_export_crypto_results(tui_enhanced_state_t *state, const char *filename);

#endif // CLOUDCLEAR_TUI_ENHANCED_MODULES_H
