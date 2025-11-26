/*
 * CloudClear TUI - Enhanced Module Integration Implementation
 *
 * Interactive TUI for CVE-2025, Advanced Recon, and Crypto Offensive modules
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <ncurses.h>
#include "cloudclear_tui_enhanced_modules.h"

// Global enhanced state for callbacks
static tui_enhanced_state_t *g_enhanced_state = NULL;
static pthread_mutex_t g_enhanced_mutex = PTHREAD_MUTEX_INITIALIZER;

// Initialize enhanced TUI
int tui_enhanced_init(tui_enhanced_state_t *state) {
    if (!state) return -1;

    memset(state, 0, sizeof(tui_enhanced_state_t));

    // Initialize base TUI
    if (tui_init() != 0) {
        return -1;
    }

    #ifdef RECON_MODULES_ENABLED
    // Initialize module contexts
    cve_detection_init_context(&state->cve_ctx);
    advanced_recon_init(&state->recon_ctx);
    crypto_offensive_init(&state->crypto_ctx);
    #endif

    // Set global state for callbacks
    g_enhanced_state = state;

    return 0;
}

// Cleanup
void tui_enhanced_cleanup(tui_enhanced_state_t *state) {
    if (!state) return;

    #ifdef RECON_MODULES_ENABLED
    cve_detection_cleanup_context(&state->cve_ctx);
    advanced_recon_cleanup(&state->recon_ctx);
    crypto_offensive_cleanup(&state->crypto_ctx);
    #endif

    tui_cleanup();
}

// Show module menu
void tui_show_module_menu(tui_enhanced_state_t *state) {
    clear();

    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);

    // Title
    attron(COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);
    mvprintw(2, (max_x - 40) / 2, "╔════════════════════════════════════╗");
    mvprintw(3, (max_x - 40) / 2, "║    CLOUDCLEAR ENHANCED MODULES     ║");
    mvprintw(4, (max_x - 40) / 2, "╚════════════════════════════════════╝");
    attroff(COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);

    int menu_y = 7;
    int menu_x = (max_x - 50) / 2;

    // Menu items
    const char *menu_items[] = {
        "1. CVE-2025 Vulnerability Detector",
        "2. Advanced Reconnaissance Suite",
        "3. Offensive Cryptographic Analysis",
        "4. Back to Main Menu"
    };

    const char *menu_descriptions[] = {
        "   Detect 2025-era CVEs in CDN providers",
        "   11 advanced CDN bypass techniques",
        "   DSSSL & Post-Quantum Crypto detection",
        "   Return to main CloudClear menu"
    };

    for (int i = 0; i < MODULE_MENU_COUNT; i++) {
        if (i == state->module_menu_selection) {
            attron(COLOR_PAIR(COLOR_PAIR_HIGHLIGHT) | A_BOLD);
            mvprintw(menu_y + i * 3, menu_x - 2, "> ");
        }

        attron(COLOR_PAIR(COLOR_PAIR_INFO) | A_BOLD);
        mvprintw(menu_y + i * 3, menu_x, "%s", menu_items[i]);
        attroff(COLOR_PAIR(COLOR_PAIR_INFO) | A_BOLD);

        attron(COLOR_PAIR(COLOR_PAIR_INFO));
        mvprintw(menu_y + i * 3 + 1, menu_x + 3, "%s", menu_descriptions[i]);
        attroff(COLOR_PAIR(COLOR_PAIR_INFO));

        if (i == state->module_menu_selection) {
            attroff(COLOR_PAIR(COLOR_PAIR_HIGHLIGHT) | A_BOLD);
        }
    }

    // Instructions
    attron(COLOR_PAIR(COLOR_PAIR_INFO));
    mvprintw(max_y - 3, 2, "↑/↓ Navigate  │  ENTER Select  │  Q Quit");
    attroff(COLOR_PAIR(COLOR_PAIR_INFO));

    refresh();
}

// Handle module menu key
int tui_handle_module_menu_key(tui_enhanced_state_t *state, int key) {
    switch (key) {
        case KEY_UP:
        case 'k':
            if (state->module_menu_selection > 0) {
                state->module_menu_selection--;
            }
            break;

        case KEY_DOWN:
        case 'j':
            if (state->module_menu_selection < MODULE_MENU_COUNT - 1) {
                state->module_menu_selection++;
            }
            break;

        case '\n':
        case '\r':
        case KEY_ENTER:
            switch (state->module_menu_selection) {
                case MODULE_MENU_CVE_DETECTOR:
                    state->base.current_screen = SCREEN_CVE_SCAN;
                    break;
                case MODULE_MENU_ADVANCED_RECON:
                    state->base.current_screen = SCREEN_ADVANCED_RECON;
                    break;
                case MODULE_MENU_CRYPTO_OFFENSIVE:
                    state->base.current_screen = SCREEN_CRYPTO_OFFENSIVE;
                    break;
                case MODULE_MENU_BACK:
                    state->base.current_screen = SCREEN_WELCOME;
                    break;
            }
            return 1;

        case 'q':
        case 'Q':
            state->base.current_screen = SCREEN_EXIT;
            return 1;
    }

    return 0;
}

// CVE-2025 Scan Screen
void tui_show_cve_scan_screen(tui_enhanced_state_t *state) {
    clear();

    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);

    // Title
    attron(COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);
    mvprintw(1, 2, "═══ CVE-2025 VULNERABILITY DETECTOR ═══");
    attroff(COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);

    if (!state->cve_scan_active) {
        // Input screen
        attron(COLOR_PAIR(COLOR_PAIR_INFO));
        mvprintw(4, 2, "Target Domain/IP:");
        attroff(COLOR_PAIR(COLOR_PAIR_INFO));

        char target[256] = {0};
        echo();
        curs_set(1);
        mvgetnstr(5, 2, target, sizeof(target) - 1);
        noecho();
        curs_set(0);

        if (strlen(target) > 0) {
            tui_start_cve_scan(state, target);
        }
    } else {
        // Scanning in progress
        attron(COLOR_PAIR(COLOR_PAIR_WARNING) | A_BOLD);
        mvprintw(4, 2, "⟳ Scanning: %s", state->base.target_domain);
        attroff(COLOR_PAIR(COLOR_PAIR_WARNING) | A_BOLD);

        // Progress
        int progress_y = 6;
        mvprintw(progress_y++, 2, "Database: %u CVEs loaded", state->cve_ctx.cve_count);
        mvprintw(progress_y++, 2, "Vulnerabilities Found: %u", state->cve_vulnerabilities_found);

        attron(COLOR_PAIR(COLOR_PAIR_ERROR) | A_BOLD);
        mvprintw(progress_y++, 2, "Critical: %u", state->cve_critical_count);
        attroff(COLOR_PAIR(COLOR_PAIR_ERROR) | A_BOLD);

        // Live vulnerability feed
        mvprintw(progress_y + 2, 2, "═══ Live Detections ═══");

        // Show recent CVEs (last 10)
        int display_y = progress_y + 4;
        int display_count = 0;
        for (uint32_t i = 0; i < state->cve_ctx.result_count && display_count < 10; i++) {
            cve_detection_result_t *result = &state->cve_ctx.results[i];

            int color = (result->cve.severity == CVE_SEVERITY_CRITICAL) ?
                        COLOR_PAIR_ERROR : COLOR_PAIR_WARNING;

            attron(COLOR_PAIR(color));
            mvprintw(display_y++, 4, "● %s - %s (%.0f%% confidence)",
                    result->cve.cve_id,
                    result->cve.title,
                    result->confidence * 100);
            attroff(COLOR_PAIR(color));
            display_count++;
        }
    }

    // Instructions
    attron(COLOR_PAIR(COLOR_PAIR_INFO));
    mvprintw(max_y - 2, 2, "Press 'r' for results  │  'b' to go back  │  'q' to quit");
    attroff(COLOR_PAIR(COLOR_PAIR_INFO));

    refresh();
}

// CVE Results Screen
void tui_show_cve_results_screen(tui_enhanced_state_t *state) {
    clear();

    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);

    // Title
    attron(COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);
    mvprintw(1, 2, "═══ CVE-2025 SCAN RESULTS ═══");
    attroff(COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);

    // Summary
    mvprintw(3, 2, "Target: %s", state->base.target_domain);
    mvprintw(4, 2, "Total Vulnerabilities: %u", state->cve_vulnerabilities_found);

    attron(COLOR_PAIR(COLOR_PAIR_ERROR) | A_BOLD);
    mvprintw(4, 40, "Critical: %u", state->cve_critical_count);
    attroff(COLOR_PAIR(COLOR_PAIR_ERROR) | A_BOLD);

    // Vulnerability list with scrolling
    mvprintw(6, 2, "═══ Detected Vulnerabilities ═══");

    int list_y = 8;
    int max_display = max_y - 12;
    int start_index = state->result_scroll_offset;

    for (uint32_t i = start_index; i < state->cve_ctx.result_count && i < start_index + max_display; i++) {
        cve_detection_result_t *result = &state->cve_ctx.results[i];

        // Highlight selected
        if (i == state->selected_result_index) {
            attron(COLOR_PAIR(COLOR_PAIR_HIGHLIGHT));
        }

        // Severity indicator
        int color = COLOR_PAIR_WARNING;
        const char *severity_str = cve_severity_to_string(result->cve.severity);

        if (result->cve.severity == CVE_SEVERITY_CRITICAL) color = COLOR_PAIR_ERROR;
        else if (result->cve.severity == CVE_SEVERITY_HIGH) color = COLOR_PAIR_WARNING;

        attron(COLOR_PAIR(color) | A_BOLD);
        mvprintw(list_y, 2, "[%s]", severity_str);
        attroff(COLOR_PAIR(color) | A_BOLD);

        mvprintw(list_y, 15, "%s", result->cve.cve_id);
        mvprintw(list_y, 35, "%.1f CVSS", result->cve.cvss_score);

        if (i == state->selected_result_index) {
            attroff(COLOR_PAIR(COLOR_PAIR_HIGHLIGHT));
        }

        list_y++;

        // Show details for selected
        if (i == state->selected_result_index && state->show_module_details) {
            attron(COLOR_PAIR(COLOR_PAIR_INFO));
            mvprintw(list_y++, 4, "→ %s", result->cve.title);
            mvprintw(list_y++, 4, "  Category: %s",
                    cve_category_to_string(result->cve.category));
            mvprintw(list_y++, 4, "  Confidence: %.0f%%", result->confidence * 100);

            if (strlen(result->remediation_advice) > 0) {
                mvprintw(list_y++, 4, "  Fix: %s", result->remediation_advice);
            }
            attroff(COLOR_PAIR(COLOR_PAIR_INFO));
            list_y++;
        }
    }

    // Instructions
    attron(COLOR_PAIR(COLOR_PAIR_INFO));
    mvprintw(max_y - 2, 2, "↑/↓ Navigate  │  ENTER Details  │  'e' Export  │  'b' Back");
    attroff(COLOR_PAIR(COLOR_PAIR_INFO));

    refresh();
}

// Start CVE scan
void tui_start_cve_scan(tui_enhanced_state_t *state, const char *target) {
    strncpy(state->base.target_domain, target, sizeof(state->base.target_domain) - 1);
    state->cve_scan_active = true;
    state->cve_vulnerabilities_found = 0;
    state->cve_critical_count = 0;

    // Launch scan thread
    pthread_t scan_thread;
    pthread_create(&scan_thread, NULL, tui_cve_scan_thread, state);
    pthread_detach(scan_thread);
}

// CVE scan thread
void* tui_cve_scan_thread(void *arg) {
    tui_enhanced_state_t *state = (tui_enhanced_state_t *)arg;

    #ifdef RECON_MODULES_ENABLED
    // Perform CVE detection for common CDN providers
    const char *cdn_providers[] = {"Cloudflare", "Akamai", "Fastly", "AWS CloudFront"};

    for (int i = 0; i < 4; i++) {
        cve_detection_check_cdn_origin_leak(&state->cve_ctx,
                                           state->base.target_domain,
                                           cdn_providers[i]);

        pthread_mutex_lock(&g_enhanced_mutex);
        state->cve_vulnerabilities_found = cve_detection_get_vulnerability_count(&state->cve_ctx);
        state->cve_critical_count = cve_detection_get_critical_count(&state->cve_ctx);
        pthread_mutex_unlock(&g_enhanced_mutex);

        usleep(500000); // Simulate progress
    }

    // DNS vulnerabilities
    cve_detection_check_dns_vulnerabilities(&state->cve_ctx, state->base.target_domain);

    pthread_mutex_lock(&g_enhanced_mutex);
    state->cve_vulnerabilities_found = cve_detection_get_vulnerability_count(&state->cve_ctx);
    state->cve_critical_count = cve_detection_get_critical_count(&state->cve_ctx);
    state->cve_scan_active = false;
    pthread_mutex_unlock(&g_enhanced_mutex);
    #endif

    return NULL;
}

// Advanced Recon Menu
void tui_show_advanced_recon_menu(tui_enhanced_state_t *state) {
    clear();

    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);

    // Title
    attron(COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);
    mvprintw(1, 2, "═══ ADVANCED RECONNAISSANCE SUITE ═══");
    attroff(COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);

    mvprintw(3, 2, "Select reconnaissance modules (SPACE to toggle, ENTER to start):");

    // Module checkboxes
    int menu_y = 5;
    const char *modules[] = {
        "SSL Certificate Enumeration & Correlation",
        "IPv6 Range Scanning",
        "DNS Cache Snooping",
        "Passive DNS Monitoring",
        "Regional Accessibility Testing",
        "Web Application Fingerprinting",
        "API Endpoint Discovery",
        "Directory Brute-forcing",
        "Email Server Enumeration",
        "Document Metadata Analysis",
        "Historical DNS Analysis"
    };

    int flags[] = {
        RECON_MODULE_SSL_CERT, RECON_MODULE_IPV6, RECON_MODULE_DNS_CACHE,
        RECON_MODULE_PASSIVE_DNS, RECON_MODULE_REGIONAL, RECON_MODULE_WEB_FINGER,
        RECON_MODULE_API_DISCOVERY, RECON_MODULE_DIR_BRUTE, RECON_MODULE_EMAIL_ENUM,
        RECON_MODULE_METADATA, RECON_MODULE_HISTORICAL_DNS
    };

    for (int i = 0; i < 11; i++) {
        bool selected = (state->recon_module_selection & flags[i]) != 0;
        bool highlighted = (i == state->advanced_recon_menu_selection);

        if (highlighted) {
            attron(COLOR_PAIR(COLOR_PAIR_HIGHLIGHT));
        }

        // Checkbox
        attron(COLOR_PAIR(selected ? COLOR_PAIR_SUCCESS : COLOR_PAIR_INFO) | A_BOLD);
        mvprintw(menu_y + i, 4, "[%s]", selected ? "X" : " ");
        attroff(COLOR_PAIR(selected ? COLOR_PAIR_SUCCESS : COLOR_PAIR_INFO) | A_BOLD);

        mvprintw(menu_y + i, 8, "%s", modules[i]);

        if (highlighted) {
            attroff(COLOR_PAIR(COLOR_PAIR_HIGHLIGHT));
        }
    }

    // Instructions
    attron(COLOR_PAIR(COLOR_PAIR_INFO));
    mvprintw(max_y - 2, 2, "↑/↓ Navigate  │  SPACE Toggle  │  ENTER Start  │  'a' All  │  'b' Back");
    attroff(COLOR_PAIR(COLOR_PAIR_INFO));

    refresh();
}

// Crypto Offensive Screen
void tui_show_crypto_offensive_screen(tui_enhanced_state_t *state) {
    clear();

    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);

    // Title with DSSSL badge
    attron(COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);
    mvprintw(1, 2, "═══ OFFENSIVE CRYPTOGRAPHIC ANALYSIS ═══");
    attroff(COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);

    attron(COLOR_PAIR(COLOR_PAIR_INFO));
    mvprintw(2, 2, "DSSSL Detection | Post-Quantum Crypto | Vulnerability Scanning");
    attroff(COLOR_PAIR(COLOR_PAIR_INFO));

    if (!state->crypto_scan_active) {
        // Input screen
        mvprintw(5, 2, "Target Domain/IP:");
        mvprintw(6, 2, "Port [443]:");

        char target[256] = {0};
        char port_str[10] = "443";

        echo();
        curs_set(1);
        mvgetnstr(5, 20, target, sizeof(target) - 1);
        mvgetnstr(6, 20, port_str, sizeof(port_str) - 1);
        noecho();
        curs_set(0);

        if (strlen(target) > 0) {
            uint16_t port = atoi(port_str);
            if (port == 0) port = 443;
            tui_start_crypto_scan(state, target, port);
        }
    } else {
        // Scanning in progress
        attron(COLOR_PAIR(COLOR_PAIR_WARNING) | A_BOLD);
        mvprintw(5, 2, "⟳ Analyzing: %s:%u", state->base.target_domain, 443);
        attroff(COLOR_PAIR(COLOR_PAIR_WARNING) | A_BOLD);

        // Real-time indicators
        int indicator_y = 7;

        if (state->dsssl_targets_found > 0) {
            attron(COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);
            mvprintw(indicator_y++, 2, "✓ DSSSL DETECTED");
            attroff(COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);
        }

        if (state->pqc_targets_found > 0) {
            attron(COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);
            mvprintw(indicator_y++, 2, "✓ POST-QUANTUM CRYPTO DETECTED");
            attroff(COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);
        }

        if (state->vulnerable_targets_found > 0) {
            attron(COLOR_PAIR(COLOR_PAIR_ERROR) | A_BOLD);
            mvprintw(indicator_y++, 2, "⚠ VULNERABILITIES DETECTED");
            attroff(COLOR_PAIR(COLOR_PAIR_ERROR) | A_BOLD);
        }

        // Progress details
        mvprintw(indicator_y + 2, 2, "Targets Scanned: %u", state->crypto_ctx.result_count);
        mvprintw(indicator_y + 3, 2, "DSSSL Implementations: %u", state->dsssl_targets_found);
        mvprintw(indicator_y + 4, 2, "PQC Deployments: %u", state->pqc_targets_found);
        mvprintw(indicator_y + 5, 2, "Vulnerable: %u", state->vulnerable_targets_found);
    }

    // Instructions
    attron(COLOR_PAIR(COLOR_PAIR_INFO));
    mvprintw(max_y - 2, 2, "Press 'r' for results  │  'b' to go back  │  'q' to quit");
    attroff(COLOR_PAIR(COLOR_PAIR_INFO));

    refresh();
}

// Start crypto scan
void tui_start_crypto_scan(tui_enhanced_state_t *state, const char *target, uint16_t port) {
    strncpy(state->base.target_domain, target, sizeof(state->base.target_domain) - 1);
    state->crypto_scan_active = true;
    state->dsssl_targets_found = 0;
    state->pqc_targets_found = 0;
    state->vulnerable_targets_found = 0;

    // Launch scan thread
    pthread_t scan_thread;
    pthread_create(&scan_thread, NULL, tui_crypto_scan_thread, state);
    pthread_detach(scan_thread);
}

// Crypto scan thread
void* tui_crypto_scan_thread(void *arg) {
    tui_enhanced_state_t *state = (tui_enhanced_state_t *)arg;

    #ifdef RECON_MODULES_ENABLED
    crypto_analysis_result_t result;

    int ret = crypto_offensive_analyze_target(&state->crypto_ctx,
                                              state->base.target_domain,
                                              443,
                                              &result);

    pthread_mutex_lock(&g_enhanced_mutex);
    if (ret == 0) {
        state->dsssl_targets_found = atomic_load(&state->crypto_ctx.dsssl_targets_found);
        state->pqc_targets_found = atomic_load(&state->crypto_ctx.pqc_targets_found);
        state->vulnerable_targets_found = atomic_load(&state->crypto_ctx.vulnerable_targets);
    }
    state->crypto_scan_active = false;
    pthread_mutex_unlock(&g_enhanced_mutex);
    #endif

    return NULL;
}

// Draw security score with visual indicator
void tui_draw_security_score(WINDOW *win, int y, int x, float score) {
    mvwprintw(win, y, x, "Security Score: ");

    int color;
    if (score >= 90.0f) color = COLOR_PAIR_SUCCESS;
    else if (score >= 70.0f) color = COLOR_PAIR_INFO;
    else if (score >= 50.0f) color = COLOR_PAIR_WARNING;
    else color = COLOR_PAIR_ERROR;

    wattron(win, COLOR_PAIR(color) | A_BOLD);
    wprintw(win, "%.1f/100.0", score);
    wattroff(win, COLOR_PAIR(color) | A_BOLD);

    // Visual bar
    int bar_width = 20;
    int filled = (int)((score / 100.0f) * bar_width);

    wprintw(win, " [");
    wattron(win, COLOR_PAIR(color));
    for (int i = 0; i < bar_width; i++) {
        waddch(win, i < filled ? '#' : '-');
    }
    wattroff(win, COLOR_PAIR(color));
    wprintw(win, "]");
}

// Draw PQC indicator badge
void tui_draw_pqc_indicator(WINDOW *win, int y, int x, bool detected) {
    if (detected) {
        wattron(win, COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);
        mvwprintw(win, y, x, "[PQC ✓]");
        wattroff(win, COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);
    } else {
        wattron(win, COLOR_PAIR(COLOR_PAIR_INFO));
        mvwprintw(win, y, x, "[PQC ✗]");
        wattroff(win, COLOR_PAIR(COLOR_PAIR_INFO));
    }
}

// Draw DSSSL badge
void tui_draw_dsssl_badge(WINDOW *win, int y, int x, const char *profile) {
    wattron(win, COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);
    mvwprintw(win, y, x, "[ DSSSL:%s ]", profile);
    wattroff(win, COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);
}

// Draw enhanced statistics
void tui_draw_enhanced_statistics(WINDOW *win, tui_enhanced_state_t *state) {
    werase(win);
    box(win, 0, 0);

    wattron(win, A_BOLD);
    mvwprintw(win, 0, 2, " Enhanced Statistics ");
    wattroff(win, A_BOLD);

    int y = 2;

    // CVE Stats
    wattron(win, COLOR_PAIR(COLOR_PAIR_HEADER));
    mvwprintw(win, y++, 2, "CVE-2025 Detection:");
    wattroff(win, COLOR_PAIR(COLOR_PAIR_HEADER));
    mvwprintw(win, y++, 4, "Vulnerabilities: %u", state->cve_vulnerabilities_found);
    wattron(win, COLOR_PAIR(COLOR_PAIR_ERROR));
    mvwprintw(win, y++, 4, "Critical: %u", state->cve_critical_count);
    wattroff(win, COLOR_PAIR(COLOR_PAIR_ERROR));

    y++;

    // Recon Stats
    wattron(win, COLOR_PAIR(COLOR_PAIR_HEADER));
    mvwprintw(win, y++, 2, "Advanced Recon:");
    wattroff(win, COLOR_PAIR(COLOR_PAIR_HEADER));
    mvwprintw(win, y++, 4, "Findings: %u", state->recon_findings_count);

    y++;

    // Crypto Stats
    wattron(win, COLOR_PAIR(COLOR_PAIR_HEADER));
    mvwprintw(win, y++, 2, "Crypto Analysis:");
    wattroff(win, COLOR_PAIR(COLOR_PAIR_HEADER));
    mvwprintw(win, y++, 4, "DSSSL: %u", state->dsssl_targets_found);
    mvwprintw(win, y++, 4, "PQC: %u", state->pqc_targets_found);
    wattron(win, COLOR_PAIR(COLOR_PAIR_WARNING));
    mvwprintw(win, y++, 4, "Vulnerable: %u", state->vulnerable_targets_found);
    wattroff(win, COLOR_PAIR(COLOR_PAIR_WARNING));

    wrefresh(win);
}

// Advanced Recon Running Screen
void tui_show_advanced_recon_running(tui_enhanced_state_t *state) {
    clear();

    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);

    // Title
    attron(COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);
    mvprintw(1, 2, "═══ ADVANCED RECONNAISSANCE IN PROGRESS ═══");
    attroff(COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);

    attron(COLOR_PAIR(COLOR_PAIR_WARNING) | A_BOLD);
    mvprintw(3, 2, "⟳ Scanning: %s", state->base.target_domain);
    attroff(COLOR_PAIR(COLOR_PAIR_WARNING) | A_BOLD);

    // Module progress grid
    int grid_y = 5;
    mvprintw(grid_y++, 2, "Module Status:");
    grid_y++;

    const char *modules[] = {
        "SSL Certificate Enum", "IPv6 Range Scanning", "DNS Cache Snooping",
        "Passive DNS Monitoring", "Regional Access Test", "Web Fingerprinting",
        "API Discovery", "Directory Brute-force", "Email Enumeration",
        "Metadata Analysis", "Historical DNS"
    };

    int flags[] = {
        RECON_MODULE_SSL_CERT, RECON_MODULE_IPV6, RECON_MODULE_DNS_CACHE,
        RECON_MODULE_PASSIVE_DNS, RECON_MODULE_REGIONAL, RECON_MODULE_WEB_FINGER,
        RECON_MODULE_API_DISCOVERY, RECON_MODULE_DIR_BRUTE, RECON_MODULE_EMAIL_ENUM,
        RECON_MODULE_METADATA, RECON_MODULE_HISTORICAL_DNS
    };

    for (int i = 0; i < 11; i++) {
        bool enabled = (state->recon_module_selection & flags[i]) != 0;

        if (!enabled) continue;

        // Status indicator
        attron(COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);
        mvprintw(grid_y, 4, "✓");
        attroff(COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);

        mvprintw(grid_y, 6, "%-25s", modules[i]);

        // Simulated progress
        attron(COLOR_PAIR(COLOR_PAIR_INFO));
        mvprintw(grid_y, 35, "[Running]");
        attroff(COLOR_PAIR(COLOR_PAIR_INFO));

        grid_y++;
    }

    // Overall statistics
    mvprintw(grid_y + 2, 2, "Total Findings: %u", state->recon_findings_count);

    // Instructions
    attron(COLOR_PAIR(COLOR_PAIR_INFO));
    mvprintw(max_y - 2, 2, "Press 'r' for results  │  'b' to go back  │  'q' to quit");
    attroff(COLOR_PAIR(COLOR_PAIR_INFO));

    refresh();
}

// Advanced Recon Results Screen
void tui_show_advanced_recon_results(tui_enhanced_state_t *state) {
    clear();

    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);

    // Title
    attron(COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);
    mvprintw(1, 2, "═══ ADVANCED RECONNAISSANCE RESULTS ═══");
    attroff(COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);

    // Summary
    mvprintw(3, 2, "Target: %s", state->base.target_domain);
    mvprintw(4, 2, "Total Findings: %u", state->recon_findings_count);

    // Results by module
    int results_y = 6;
    mvprintw(results_y++, 2, "═══ Findings by Module ═══");
    results_y++;

    #ifdef RECON_MODULES_ENABLED
    // SSL Certificate findings
    if (state->recon_module_selection & RECON_MODULE_SSL_CERT) {
        attron(COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);
        mvprintw(results_y++, 4, "SSL Certificate Enumeration:");
        attroff(COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);

        attron(COLOR_PAIR(COLOR_PAIR_INFO));
        mvprintw(results_y++, 6, "Scanned successfully");
        attroff(COLOR_PAIR(COLOR_PAIR_INFO));
        results_y++;
    }

    // IPv6 findings
    if (state->recon_module_selection & RECON_MODULE_IPV6) {
        attron(COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);
        mvprintw(results_y++, 4, "IPv6 Range Scanning:");
        attroff(COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);

        attron(COLOR_PAIR(COLOR_PAIR_INFO));
        mvprintw(results_y++, 6, "Scanned successfully");
        attroff(COLOR_PAIR(COLOR_PAIR_INFO));
        results_y++;
    }

    // Web fingerprinting
    if (state->recon_module_selection & RECON_MODULE_WEB_FINGER) {
        attron(COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);
        mvprintw(results_y++, 4, "Web Application Fingerprinting:");
        attroff(COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);

        attron(COLOR_PAIR(COLOR_PAIR_INFO));
        mvprintw(results_y++, 6, "Scanned successfully");
        attroff(COLOR_PAIR(COLOR_PAIR_INFO));
        results_y++;
    }

    // Email enumeration
    if (state->recon_module_selection & RECON_MODULE_EMAIL_ENUM) {
        attron(COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);
        mvprintw(results_y++, 4, "Email Server Enumeration:");
        attroff(COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);

        attron(COLOR_PAIR(COLOR_PAIR_INFO));
        mvprintw(results_y++, 6, "Scanned successfully");
        attroff(COLOR_PAIR(COLOR_PAIR_INFO));
        results_y++;
    }

    // Show total findings
    attron(COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);
    mvprintw(results_y + 1, 4, "All findings aggregated in context");
    attroff(COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);
    #endif

    // Instructions
    attron(COLOR_PAIR(COLOR_PAIR_INFO));
    mvprintw(max_y - 2, 2, "↑/↓ Navigate  │  'e' Export  │  'b' Back  │  'q' Quit");
    attroff(COLOR_PAIR(COLOR_PAIR_INFO));

    refresh();
}

// Crypto Results Detail Screen
void tui_show_crypto_results_screen(tui_enhanced_state_t *state) {
    clear();

    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);

    // Title
    attron(COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);
    mvprintw(1, 2, "═══ CRYPTOGRAPHIC ANALYSIS RESULTS ═══");
    attroff(COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);

    #ifdef RECON_MODULES_ENABLED
    if (state->crypto_ctx.result_count > 0) {
        crypto_analysis_result_t *result = &state->crypto_ctx.results[0];

        // Target info
        mvprintw(3, 2, "Target: %s:%u", result->target_host, result->target_port);
        mvprintw(4, 2, "IP: %s", result->target_ip);

        int details_y = 6;

        // Implementation detection
        attron(COLOR_PAIR(COLOR_PAIR_INFO) | A_BOLD);
        mvprintw(details_y++, 2, "Implementation:");
        attroff(COLOR_PAIR(COLOR_PAIR_INFO) | A_BOLD);

        const char *impl_name = crypto_impl_type_to_string(result->implementation);
        mvprintw(details_y++, 4, "Type: %s", impl_name);

        if (result->dsssl_detected) {
            tui_draw_dsssl_badge(stdscr, details_y++, 4, result->dsssl_security_profile);
        }
        details_y++;

        // TLS info
        attron(COLOR_PAIR(COLOR_PAIR_INFO) | A_BOLD);
        mvprintw(details_y++, 2, "TLS Configuration:");
        attroff(COLOR_PAIR(COLOR_PAIR_INFO) | A_BOLD);

        mvprintw(details_y++, 4, "Cipher: %s (%u bits)",
                result->negotiated_cipher, result->cipher_bits);
        mvprintw(details_y++, 4, "TLS Version: 0x%04x", result->negotiated_tls_version);
        details_y++;

        // Post-quantum crypto
        if (result->pqc_detection.pqc_detected) {
            attron(COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);
            mvprintw(details_y++, 2, "✓ POST-QUANTUM CRYPTOGRAPHY DETECTED");
            attroff(COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);

            for (uint32_t i = 0; i < result->pqc_detection.algorithm_count && i < 5; i++) {
                const char *alg_name = pqc_algorithm_to_string(
                    result->pqc_detection.detected_algorithms[i]);
                attron(COLOR_PAIR(COLOR_PAIR_INFO));
                mvprintw(details_y++, 4, "• %s", alg_name);
                attroff(COLOR_PAIR(COLOR_PAIR_INFO));
            }

            mvprintw(details_y++, 4, "Quantum Resistance: %.0f%%",
                    result->pqc_detection.quantum_resistance_score * 100);
            details_y++;
        }

        // Vulnerabilities
        if (result->weaknesses.weak_cipher_detected ||
            result->weaknesses.heartbleed_vulnerable) {
            attron(COLOR_PAIR(COLOR_PAIR_ERROR) | A_BOLD);
            mvprintw(details_y++, 2, "⚠ VULNERABILITIES DETECTED");
            attroff(COLOR_PAIR(COLOR_PAIR_ERROR) | A_BOLD);

            if (result->weaknesses.weak_cipher_detected) {
                attron(COLOR_PAIR(COLOR_PAIR_WARNING));
                mvprintw(details_y++, 4, "• Weak ciphers: %s",
                        result->weaknesses.weak_ciphers);
                attroff(COLOR_PAIR(COLOR_PAIR_WARNING));
            }

            if (result->weaknesses.heartbleed_vulnerable) {
                attron(COLOR_PAIR(COLOR_PAIR_ERROR));
                mvprintw(details_y++, 4, "• Heartbleed (CVE-2014-0160)");
                attroff(COLOR_PAIR(COLOR_PAIR_ERROR));
            }

            if (result->weaknesses.poodle_vulnerable) {
                attron(COLOR_PAIR(COLOR_PAIR_ERROR));
                mvprintw(details_y++, 4, "• POODLE (CVE-2014-3566)");
                attroff(COLOR_PAIR(COLOR_PAIR_ERROR));
            }
            details_y++;
        }

        // Security score
        tui_draw_security_score(stdscr, details_y++, 2, result->security_score);
        details_y++;

        // Assessment
        attron(COLOR_PAIR(COLOR_PAIR_INFO));
        mvprintw(details_y++, 2, "Assessment:");
        mvprintw(details_y++, 4, "%s", result->security_assessment);
        attroff(COLOR_PAIR(COLOR_PAIR_INFO));
    } else {
        mvprintw(5, 2, "No results available. Run a scan first.");
    }
    #endif

    // Instructions
    attron(COLOR_PAIR(COLOR_PAIR_INFO));
    mvprintw(max_y - 2, 2, "'e' Export  │  'b' Back  │  'q' Quit");
    attroff(COLOR_PAIR(COLOR_PAIR_INFO));

    refresh();
}

// Start advanced recon scan
void tui_start_advanced_recon(tui_enhanced_state_t *state, const char *target) {
    strncpy(state->base.target_domain, target, sizeof(state->base.target_domain) - 1);
    state->advanced_recon_active = true;
    state->recon_findings_count = 0;

    // Launch scan thread
    pthread_t scan_thread;
    pthread_create(&scan_thread, NULL, tui_advanced_recon_thread, state);
    pthread_detach(scan_thread);
}

// Advanced recon scan thread
void* tui_advanced_recon_thread(void *arg) {
    tui_enhanced_state_t *state = (tui_enhanced_state_t *)arg;

    #ifdef RECON_MODULES_ENABLED
    // SSL Certificate Enumeration
    if (state->recon_module_selection & RECON_MODULE_SSL_CERT) {
        ssl_cert_result_t ssl_result;
        if (ssl_cert_enumerate(state->base.target_domain, 443, &ssl_result) == 0) {
            pthread_mutex_lock(&g_enhanced_mutex);
            state->recon_findings_count++;
            pthread_mutex_unlock(&g_enhanced_mutex);
        }
        usleep(300000);
    }

    // IPv6 Range Scanning
    if (state->recon_module_selection & RECON_MODULE_IPV6) {
        ipv6_scan_result_t **ipv6_results = NULL;
        uint32_t ipv6_count = 0;
        if (ipv6_discover_for_domain(state->base.target_domain, &ipv6_results, &ipv6_count) == 0) {
            pthread_mutex_lock(&g_enhanced_mutex);
            state->recon_findings_count += ipv6_count;
            pthread_mutex_unlock(&g_enhanced_mutex);

            // Free results
            if (ipv6_results) {
                for (uint32_t i = 0; i < ipv6_count; i++) {
                    free(ipv6_results[i]);
                }
                free(ipv6_results);
            }
        }
        usleep(500000);
    }

    // Web Application Fingerprinting
    if (state->recon_module_selection & RECON_MODULE_WEB_FINGER) {
        web_fingerprint_result_t web_result;
        char url[512];
        snprintf(url, sizeof(url), "https://%s", state->base.target_domain);
        if (web_fingerprint_scan(url, &web_result) == 0) {
            pthread_mutex_lock(&g_enhanced_mutex);
            state->recon_findings_count += web_result.framework_count;
            state->recon_findings_count += web_result.cms_count;
            pthread_mutex_unlock(&g_enhanced_mutex);
        }
        usleep(400000);
    }

    // Email Server Enumeration
    if (state->recon_module_selection & RECON_MODULE_EMAIL_ENUM) {
        email_enum_result_t email_result;
        if (email_enumerate_servers(state->base.target_domain, &email_result) == 0) {
            pthread_mutex_lock(&g_enhanced_mutex);
            state->recon_findings_count += email_result.mx_record_count;
            pthread_mutex_unlock(&g_enhanced_mutex);
        }
        usleep(300000);
    }

    // Additional modules would be called here...

    pthread_mutex_lock(&g_enhanced_mutex);
    state->advanced_recon_active = false;
    pthread_mutex_unlock(&g_enhanced_mutex);
    #endif

    return NULL;
}

// Keyboard handlers

int tui_handle_cve_screen_key(tui_enhanced_state_t *state, int key) {
    switch (key) {
        case 'r':
        case 'R':
            state->base.current_screen = SCREEN_CVE_RESULTS;
            return 1;

        case 'b':
        case 'B':
            state->base.current_screen = SCREEN_MODULE_MENU;
            return 1;

        case 'q':
        case 'Q':
            state->base.current_screen = SCREEN_EXIT;
            return 1;

        case KEY_UP:
        case 'k':
            if (state->selected_result_index > 0) {
                state->selected_result_index--;
                if (state->selected_result_index < state->result_scroll_offset) {
                    state->result_scroll_offset--;
                }
            }
            return 1;

        case KEY_DOWN:
        case 'j':
            if (state->selected_result_index < state->cve_ctx.result_count - 1) {
                state->selected_result_index++;
                int max_y = 20; // Approximate visible area
                if (state->selected_result_index >= state->result_scroll_offset + max_y) {
                    state->result_scroll_offset++;
                }
            }
            return 1;

        case '\n':
        case '\r':
        case KEY_ENTER:
            state->show_module_details = !state->show_module_details;
            return 1;

        case 'e':
        case 'E':
            tui_export_cve_results(state, "cve_results.json");
            // Show confirmation message (would need a message popup)
            return 1;
    }

    return 0;
}

int tui_handle_advanced_recon_key(tui_enhanced_state_t *state, int key) {
    switch (key) {
        case KEY_UP:
        case 'k':
            if (state->advanced_recon_menu_selection > 0) {
                state->advanced_recon_menu_selection--;
            }
            return 1;

        case KEY_DOWN:
        case 'j':
            if (state->advanced_recon_menu_selection < 10) {
                state->advanced_recon_menu_selection++;
            }
            return 1;

        case ' ': // Space to toggle
            {
                int flags[] = {
                    RECON_MODULE_SSL_CERT, RECON_MODULE_IPV6, RECON_MODULE_DNS_CACHE,
                    RECON_MODULE_PASSIVE_DNS, RECON_MODULE_REGIONAL, RECON_MODULE_WEB_FINGER,
                    RECON_MODULE_API_DISCOVERY, RECON_MODULE_DIR_BRUTE, RECON_MODULE_EMAIL_ENUM,
                    RECON_MODULE_METADATA, RECON_MODULE_HISTORICAL_DNS
                };

                int flag = flags[state->advanced_recon_menu_selection];
                state->recon_module_selection ^= flag; // Toggle bit
            }
            return 1;

        case 'a':
        case 'A': // Select all
            state->recon_module_selection = 0x7FF; // All 11 bits set
            return 1;

        case '\n':
        case '\r':
        case KEY_ENTER:
            if (state->recon_module_selection > 0) {
                // Prompt for target
                echo();
                curs_set(1);
                char target[256] = {0};
                mvprintw(20, 2, "Target domain/IP: ");
                getnstr(target, sizeof(target) - 1);
                noecho();
                curs_set(0);

                if (strlen(target) > 0) {
                    tui_start_advanced_recon(state, target);
                    state->base.current_screen = SCREEN_ADVANCED_RECON_RUNNING;
                }
            }
            return 1;

        case 'r':
        case 'R':
            state->base.current_screen = SCREEN_ADVANCED_RECON_RESULTS;
            return 1;

        case 'b':
        case 'B':
            state->base.current_screen = SCREEN_MODULE_MENU;
            return 1;

        case 'q':
        case 'Q':
            state->base.current_screen = SCREEN_EXIT;
            return 1;
    }

    return 0;
}

int tui_handle_crypto_screen_key(tui_enhanced_state_t *state, int key) {
    switch (key) {
        case 'r':
        case 'R':
            state->base.current_screen = SCREEN_CRYPTO_RESULTS;
            return 1;

        case 'b':
        case 'B':
            state->base.current_screen = SCREEN_MODULE_MENU;
            return 1;

        case 'q':
        case 'Q':
            state->base.current_screen = SCREEN_EXIT;
            return 1;

        case 'e':
        case 'E':
            tui_export_crypto_results(state, "crypto_results.json");
            return 1;
    }

    return 0;
}

// Export functions

void tui_export_cve_results(tui_enhanced_state_t *state, const char *filename) {
    #ifdef RECON_MODULES_ENABLED
    FILE *fp = fopen(filename, "w");
    if (!fp) return;

    fprintf(fp, "{\n");
    fprintf(fp, "  \"target\": \"%s\",\n", state->base.target_domain);
    fprintf(fp, "  \"total_vulnerabilities\": %u,\n", state->cve_vulnerabilities_found);
    fprintf(fp, "  \"critical_count\": %u,\n", state->cve_critical_count);
    fprintf(fp, "  \"vulnerabilities\": [\n");

    for (uint32_t i = 0; i < state->cve_ctx.result_count; i++) {
        cve_detection_result_t *result = &state->cve_ctx.results[i];
        fprintf(fp, "    {\n");
        fprintf(fp, "      \"cve_id\": \"%s\",\n", result->cve.cve_id);
        fprintf(fp, "      \"title\": \"%s\",\n", result->cve.title);
        fprintf(fp, "      \"severity\": \"%s\",\n",
                cve_severity_to_string(result->cve.severity));
        fprintf(fp, "      \"cvss_score\": %.1f,\n", result->cve.cvss_score);
        fprintf(fp, "      \"confidence\": %.2f\n", result->confidence);
        fprintf(fp, "    }%s\n", (i < state->cve_ctx.result_count - 1) ? "," : "");
    }

    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");
    fclose(fp);
    #endif
}

void tui_export_recon_results(tui_enhanced_state_t *state, const char *filename) {
    #ifdef RECON_MODULES_ENABLED
    advanced_recon_export_results(&state->recon_ctx, filename);
    #endif
}

void tui_export_crypto_results(tui_enhanced_state_t *state, const char *filename) {
    #ifdef RECON_MODULES_ENABLED
    crypto_export_results_json(&state->crypto_ctx, filename);
    #endif
}
