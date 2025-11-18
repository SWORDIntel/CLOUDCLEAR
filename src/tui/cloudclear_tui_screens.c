/*
 * CloudClear TUI - Enhanced Screens Implementation
 * Settings, API Configuration, and Cloud Status Screens
 */

#include "cloudclear_tui.h"
#include "cloudclear_tui_config.h"
#include <ncurses.h>
#include <string.h>
#include <stdlib.h>

// Show settings menu screen
void tui_show_settings_screen(struct tui_state *state) {
    if (!state) return;

    clear();
    tui_draw_header(state->win_header, "CLOUDCLEAR SETTINGS", "Configure API Keys and Preferences");
    refresh();

    int row = 3;
    int col = 5;

    attron(COLOR_PAIR(COLOR_PAIR_INFO));
    mvprintw(row++, col, "╔══════════════════════════════════════════════════════════════╗");
    mvprintw(row++, col, "║                      SETTINGS MENU                           ║");
    mvprintw(row++, col, "╚══════════════════════════════════════════════════════════════╝");
    attroff(COLOR_PAIR(COLOR_PAIR_INFO));

    row += 2;

    const char *menu_items[] = {
        "1. API Key Configuration",
        "2. Cloud Provider Status",
        "3. General Preferences",
        "4. View Configuration",
        "5. Reset to Defaults",
        "6. Back to Main Menu"
    };

    for (int i = 0; i < 6; i++) {
        if (i == state->settings_menu_item) {
            attron(COLOR_PAIR(COLOR_PAIR_HIGHLIGHT) | A_BOLD);
            mvprintw(row + i * 2, col + 2, "► %s", menu_items[i]);
            attroff(COLOR_PAIR(COLOR_PAIR_HIGHLIGHT) | A_BOLD);
        } else {
            mvprintw(row + i * 2, col + 4, "%s", menu_items[i]);
        }
    }

    row += 14;
    attron(COLOR_PAIR(COLOR_PAIR_INFO) | A_DIM);
    mvprintw(row, col, "Use ↑/↓ to navigate, Enter to select, Q to quit");
    attroff(COLOR_PAIR(COLOR_PAIR_INFO) | A_DIM);

    refresh();
}

// Show API configuration screen
void tui_show_api_config_screen(struct tui_state *state) {
    if (!state || !state->api_config) return;

    tui_api_config_t *config = (tui_api_config_t *)state->api_config;

    clear();
    tui_draw_header(state->win_header, "API KEY CONFIGURATION", "Configure Cloud Provider and Intelligence Service API Keys");
    refresh();

    int row = 3;
    int col = 3;

    attron(COLOR_PAIR(COLOR_PAIR_INFO));
    mvprintw(row++, col, "╔════════════════════════════════════════════════════════════════════════╗");
    mvprintw(row++, col, "║              CLOUD PROVIDER & INTELLIGENCE API KEYS                   ║");
    mvprintw(row++, col, "╚════════════════════════════════════════════════════════════════════════╝");
    attroff(COLOR_PAIR(COLOR_PAIR_INFO));

    row += 2;

    // Intelligence Services section
    attron(COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);
    mvprintw(row++, col, "═══ Intelligence Services ═══");
    attroff(COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);
    row++;

    const char *services[] = {
        "Shodan API Key",
        "Censys API ID",
        "Censys API Secret",
        "VirusTotal API Key"
    };

    bool *enabled[] = {
        &config->shodan_enabled,
        &config->censys_enabled,
        &config->censys_enabled, // Same flag for ID and secret
        &config->virustotal_enabled
    };

    for (int i = 0; i < 4; i++) {
        if (i == state->api_config_item && state->api_config_item < 4) {
            attron(COLOR_PAIR(COLOR_PAIR_HIGHLIGHT) | A_BOLD);
            mvprintw(row, col + 2, "►");
        }

        const char *status = *enabled[i] ? "[✓]" : "[ ]";
        int status_color = *enabled[i] ? COLOR_PAIR_SUCCESS : COLOR_PAIR_ERROR;

        attron(status_color);
        mvprintw(row, col + 4, "%s", status);
        attroff(status_color);

        mvprintw(row, col + 8, "%s", services[i]);

        if (i == state->api_config_item && state->api_config_item < 4) {
            attroff(COLOR_PAIR(COLOR_PAIR_HIGHLIGHT) | A_BOLD);
        }

        row++;
    }

    row += 2;

    // Cloud Providers section
    attron(COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);
    mvprintw(row++, col, "═══ Cloud Providers ═══");
    attroff(COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);
    row++;

    const char *providers[] = {
        "Akamai EdgeGrid (3 credentials)",
        "AWS (Access Key + Secret)",
        "Azure (4 credentials)",
        "GCP (Project ID + Credentials)",
        "Fastly API Key",
        "DigitalOcean API Token"
    };

    bool *provider_enabled[] = {
        &config->akamai_enabled,
        &config->aws_enabled,
        &config->azure_enabled,
        &config->gcp_enabled,
        &config->fastly_enabled,
        &config->digitalocean_enabled
    };

    for (int i = 0; i < 6; i++) {
        int item_index = i + 4;
        if (item_index == state->api_config_item) {
            attron(COLOR_PAIR(COLOR_PAIR_HIGHLIGHT) | A_BOLD);
            mvprintw(row, col + 2, "►");
        }

        const char *status = *provider_enabled[i] ? "[✓]" : "[ ]";
        int status_color = *provider_enabled[i] ? COLOR_PAIR_SUCCESS : COLOR_PAIR_ERROR;

        attron(status_color);
        mvprintw(row, col + 4, "%s", status);
        attroff(status_color);

        mvprintw(row, col + 8, "%s", providers[i]);

        if (item_index == state->api_config_item) {
            attroff(COLOR_PAIR(COLOR_PAIR_HIGHLIGHT) | A_BOLD);
        }

        row++;
    }

    row += 2;

    attron(COLOR_PAIR(COLOR_PAIR_INFO) | A_DIM);
    mvprintw(row++, col, "╔═══════════════════════════════════════════════════════════════╗");
    mvprintw(row++, col, "║  ↑/↓: Navigate  │  Enter: Edit  │  S: Save  │  Q: Back       ║");
    mvprintw(row++, col, "║  T: Test API    │  L: Load      │  C: Clear │  E: Export     ║");
    mvprintw(row++, col, "╚═══════════════════════════════════════════════════════════════╝");
    attroff(COLOR_PAIR(COLOR_PAIR_INFO) | A_DIM);

    refresh();
}

// Show cloud provider status screen
void tui_show_cloud_status_screen(struct tui_state *state) {
    if (!state || !state->api_config) return;

    tui_api_config_t *config = (tui_api_config_t *)state->api_config;

    clear();
    tui_draw_header(state->win_header, "CLOUD PROVIDER STATUS", "Real-time Status of Cloud Integrations");
    refresh();

    int row = 3;
    int col = 3;

    attron(COLOR_PAIR(COLOR_PAIR_INFO));
    mvprintw(row++, col, "╔═══════════════════════════════════════════════════════════════════════╗");
    mvprintw(row++, col, "║                    CLOUD PROVIDER STATUS DASHBOARD                    ║");
    mvprintw(row++, col, "╚═══════════════════════════════════════════════════════════════════════╝");
    attroff(COLOR_PAIR(COLOR_PAIR_INFO));

    row += 2;

    // Table header
    attron(COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);
    mvprintw(row++, col, "%-30s %-15s %-20s", "Provider", "Status", "Details");
    mvprintw(row++, col, "─────────────────────────────────────────────────────────────────────────");
    attroff(COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);

    struct {
        const char *name;
        bool enabled;
        const char *type;
    } providers[] = {
        {"Akamai Edge", config->akamai_enabled, "CDN/WAF"},
        {"AWS CloudFront", config->aws_enabled, "CDN/WAF/Shield"},
        {"Azure Front Door", config->azure_enabled, "CDN/WAF"},
        {"GCP Cloud CDN", config->gcp_enabled, "CDN/Armor"},
        {"Fastly", config->fastly_enabled, "CDN"},
        {"DigitalOcean Spaces", config->digitalocean_enabled, "CDN"},
        {"Shodan", config->shodan_enabled, "Intelligence"},
        {"Censys", config->censys_enabled, "Certificate Intel"},
        {"VirusTotal", config->virustotal_enabled, "Threat Intel"}
    };

    for (int i = 0; i < 9; i++) {
        const char *status_str;
        int status_color;

        if (providers[i].enabled) {
            status_str = "● ACTIVE";
            status_color = COLOR_PAIR_SUCCESS;
        } else {
            status_str = "○ INACTIVE";
            status_color = COLOR_PAIR_ERROR;
        }

        mvprintw(row, col, "%-30s", providers[i].name);

        attron(status_color | A_BOLD);
        mvprintw(row, col + 30, "%-15s", status_str);
        attroff(status_color | A_BOLD);

        attron(COLOR_PAIR_INFO | A_DIM);
        mvprintw(row, col + 45, "%-20s", providers[i].type);
        attroff(COLOR_PAIR_INFO | A_DIM);

        row++;
    }

    row += 2;

    // Summary statistics
    int active_count = 0;
    if (config->akamai_enabled) active_count++;
    if (config->aws_enabled) active_count++;
    if (config->azure_enabled) active_count++;
    if (config->gcp_enabled) active_count++;
    if (config->fastly_enabled) active_count++;
    if (config->digitalocean_enabled) active_count++;
    if (config->shodan_enabled) active_count++;
    if (config->censys_enabled) active_count++;
    if (config->virustotal_enabled) active_count++;

    attron(COLOR_PAIR(COLOR_PAIR_HEADER));
    mvprintw(row++, col, "═══ Summary ═══");
    attroff(COLOR_PAIR(COLOR_PAIR_HEADER));

    attron(COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);
    mvprintw(row++, col + 2, "Active Integrations: %d / 9", active_count);
    attroff(COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);

    if (active_count == 0) {
        attron(COLOR_PAIR(COLOR_PAIR_WARNING));
        mvprintw(row++, col + 2, "⚠ No cloud providers configured. Go to Settings → API Configuration");
        attroff(COLOR_PAIR(COLOR_PAIR_WARNING));
    } else if (active_count < 5) {
        attron(COLOR_PAIR(COLOR_PAIR_INFO));
        mvprintw(row++, col + 2, "ℹ Configure more providers for comprehensive cloud detection");
        attroff(COLOR_PAIR(COLOR_PAIR_INFO));
    } else {
        attron(COLOR_PAIR(COLOR_PAIR_SUCCESS));
        mvprintw(row++, col + 2, "✓ Excellent coverage! Ready for advanced cloud detection");
        attroff(COLOR_PAIR(COLOR_PAIR_SUCCESS));
    }

    row += 2;

    attron(COLOR_PAIR(COLOR_PAIR_INFO) | A_DIM);
    mvprintw(row, col, "Press Q to return to settings menu");
    attroff(COLOR_PAIR(COLOR_PAIR_INFO) | A_DIM);

    refresh();
}

// Show about screen
void tui_show_about_screen(struct tui_state *state) {
    if (!state) return;

    clear();
    tui_draw_header(state->win_header, "ABOUT CLOUDCLEAR", "Advanced Cloud Provider Detection & Intelligence");
    refresh();

    int row = 3;
    int col = 10;

    attron(COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);
    mvprintw(row++, col, "╔═══════════════════════════════════════════════════════╗");
    mvprintw(row++, col, "║                                                       ║");
    mvprintw(row++, col, "║             CLOUDCLEAR v2.0-Enhanced-Cloud            ║");
    mvprintw(row++, col, "║                                                       ║");
    mvprintw(row++, col, "╚═══════════════════════════════════════════════════════╝");
    attroff(COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);

    row += 2;

    attron(COLOR_PAIR(COLOR_PAIR_INFO));
    mvprintw(row++, col, "Complete Cloud Provider Detection & Intelligence Platform");
    row++;

    mvprintw(row++, col, "Integrated Providers:");
    row++;

    attroff(COLOR_PAIR(COLOR_PAIR_INFO));

    const char *providers[] = {
        "  ✓ Akamai Edge (CDN, WAF, Ion, SureRoute)",
        "  ✓ AWS (CloudFront, WAF, Shield, Route53, ELB)",
        "  ✓ Azure (Front Door, CDN, WAF, App Gateway)",
        "  ✓ GCP (Cloud CDN, Cloud Armor, Load Balancer)",
        "  ✓ Fastly CDN",
        "  ✓ DigitalOcean Spaces & App Platform",
        "  ✓ Oracle Cloud CDN & WAF",
        "  ✓ Alibaba Cloud CDN & Anti-DDoS"
    };

    for (int i = 0; i < 8; i++) {
        attron(COLOR_PAIR_SUCCESS);
        mvprintw(row++, col, "%s", providers[i]);
        attroff(COLOR_PAIR_SUCCESS);
    }

    row++;
    attron(COLOR_PAIR(COLOR_PAIR_INFO));
    mvprintw(row++, col, "Intelligence Services:");
    attroff(COLOR_PAIR(COLOR_PAIR_INFO));

    const char *intel[] = {
        "  ✓ Shodan (IP intelligence & port scanning)",
        "  ✓ Censys (Certificate transparency & host discovery)",
        "  ✓ VirusTotal (Passive DNS & threat intel)"
    };

    for (int i = 0; i < 3; i++) {
        attron(COLOR_PAIR_SUCCESS);
        mvprintw(row++, col, "%s", intel[i]);
        attroff(COLOR_PAIR_SUCCESS);
    }

    row += 2;

    attron(COLOR_PAIR(COLOR_PAIR_INFO) | A_DIM);
    mvprintw(row++, col, "Total Integrations: 20+");
    mvprintw(row++, col, "Detection Methods: Headers, DNS, Certificates, IP Ranges");
    mvprintw(row++, col, "Thread-Safe: Yes");
    mvprintw(row++, col, "License: MIT");
    attroff(COLOR_PAIR(COLOR_PAIR_INFO) | A_DIM);

    row += 2;

    attron(COLOR_PAIR(COLOR_PAIR_INFO) | A_BOLD);
    mvprintw(row, col, "Press Q to return");
    attroff(COLOR_PAIR(COLOR_PAIR_INFO) | A_BOLD);

    refresh();
}
