/*
 * CloudClear TUI - Implementation
 * Interactive terminal interface for advanced IP detection
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ncurses.h>
#include <unistd.h>
#include "cloudclear_tui.h"

// Global TUI state
static struct tui_state *g_tui_state = NULL;

// Initialize TUI
int tui_init(void) {
    initscr();              // Initialize ncurses
    cbreak();               // Disable line buffering
    noecho();               // Don't echo input
    keypad(stdscr, TRUE);   // Enable function keys
    curs_set(0);            // Hide cursor
    timeout(100);           // Non-blocking input with 100ms timeout

    // Initialize colors
    if (has_colors()) {
        start_color();
        init_pair(COLOR_PAIR_HEADER, COLOR_CYAN, COLOR_BLACK);
        init_pair(COLOR_PAIR_SUCCESS, COLOR_GREEN, COLOR_BLACK);
        init_pair(COLOR_PAIR_WARNING, COLOR_YELLOW, COLOR_BLACK);
        init_pair(COLOR_PAIR_ERROR, COLOR_RED, COLOR_BLACK);
        init_pair(COLOR_PAIR_INFO, COLOR_BLUE, COLOR_BLACK);
        init_pair(COLOR_PAIR_HIGHLIGHT, COLOR_BLACK, COLOR_CYAN);
        init_pair(COLOR_PAIR_PROGRESS, COLOR_GREEN, COLOR_BLACK);
        init_pair(COLOR_PAIR_BORDER, COLOR_WHITE, COLOR_BLACK);
    }

    return 0;
}

// Cleanup TUI
void tui_cleanup(void) {
    endwin();
}

// Draw ASCII art logo
static void draw_logo(WINDOW *win, int start_y) {
    wattron(win, COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);
    mvwprintw(win, start_y++, 2, "   _____ _                 _  _____ _                 ");
    mvwprintw(win, start_y++, 2, "  / ____| |               | |/ ____| |                ");
    mvwprintw(win, start_y++, 2, " | |    | | ___  _   _  __| | |    | | ___  __ _ _ __");
    mvwprintw(win, start_y++, 2, " | |    | |/ _ \\| | | |/ _` | |    | |/ _ \\/ _` | '__|");
    mvwprintw(win, start_y++, 2, " | |____| | (_) | |_| | (_| | |____| |  __/ (_| | |   ");
    mvwprintw(win, start_y++, 2, "  \\_____|_|\\___/ \\__,_|\\__,_|\\_____|_|\\___|\\__,_|_|   ");
    wattroff(win, COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);

    wattron(win, COLOR_PAIR(COLOR_PAIR_INFO));
    mvwprintw(win, start_y++, 2, "        Advanced CDN Origin IP Detection v2.0");
    wattroff(win, COLOR_PAIR(COLOR_PAIR_INFO));
}

// Draw header
void tui_draw_header(WINDOW *win, const char *title, const char *subtitle) {
    werase(win);
    box(win, 0, 0);

    wattron(win, COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);
    mvwprintw(win, 1, 2, "%s", title);
    wattroff(win, COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);

    if (subtitle) {
        wattron(win, COLOR_PAIR(COLOR_PAIR_INFO));
        mvwprintw(win, 1, 2 + strlen(title) + 3, "| %s", subtitle);
        wattroff(win, COLOR_PAIR(COLOR_PAIR_INFO));
    }

    wrefresh(win);
}

// Draw border with title
void tui_draw_border(WINDOW *win, const char *title) {
    box(win, 0, 0);
    if (title) {
        wattron(win, A_BOLD);
        mvwprintw(win, 0, 2, " %s ", title);
        wattroff(win, A_BOLD);
    }
}

// Draw progress bar
void tui_draw_progress_bar(WINDOW *win, int y, int x, int width, int progress, const char *label) {
    if (progress < 0) progress = 0;
    if (progress > 100) progress = 100;

    int filled = (width * progress) / 100;

    mvwprintw(win, y, x, "%s [", label);
    wattron(win, COLOR_PAIR(COLOR_PAIR_PROGRESS) | A_BOLD);

    for (int i = 0; i < width; i++) {
        if (i < filled) {
            waddch(win, '=');
        } else if (i == filled && progress < 100) {
            waddch(win, '>');
        } else {
            waddch(win, ' ');
        }
    }

    wattroff(win, COLOR_PAIR(COLOR_PAIR_PROGRESS) | A_BOLD);
    wprintw(win, "] %3d%%", progress);
}

// Get phase status string
const char* tui_get_phase_status_string(phase_status_t status) {
    switch (status) {
        case PHASE_PENDING:   return "PENDING";
        case PHASE_RUNNING:   return "RUNNING";
        case PHASE_COMPLETED: return "DONE";
        case PHASE_FAILED:    return "FAILED";
        default:              return "UNKNOWN";
    }
}

// Get phase status color
int tui_get_phase_status_color(phase_status_t status) {
    switch (status) {
        case PHASE_PENDING:   return COLOR_PAIR_INFO;
        case PHASE_RUNNING:   return COLOR_PAIR_WARNING;
        case PHASE_COMPLETED: return COLOR_PAIR_SUCCESS;
        case PHASE_FAILED:    return COLOR_PAIR_ERROR;
        default:              return COLOR_PAIR_INFO;
    }
}

// Draw phase list
void tui_draw_phase_list(WINDOW *win, struct tui_phase *phases, int phase_count, int current_phase) {
    int y = 2;

    for (int i = 0; i < phase_count; i++) {
        struct tui_phase *phase = &phases[i];

        // Phase number and name
        if (i == current_phase) {
            wattron(win, A_BOLD);
        }

        mvwprintw(win, y, 2, "[%d/%d] %s", i + 1, phase_count, phase->name);

        if (i == current_phase) {
            wattroff(win, A_BOLD);
        }

        // Status
        int status_color = tui_get_phase_status_color(phase->status);
        wattron(win, COLOR_PAIR(status_color) | A_BOLD);
        mvwprintw(win, y, 50, "[%s]", tui_get_phase_status_string(phase->status));
        wattroff(win, COLOR_PAIR(status_color) | A_BOLD);

        y++;

        // Progress bar for running phase
        if (phase->status == PHASE_RUNNING) {
            tui_draw_progress_bar(win, y, 4, 40, phase->progress, "Progress");
            y++;
        }

        // Current action
        if (phase->status == PHASE_RUNNING && strlen(phase->current_action) > 0) {
            wattron(win, COLOR_PAIR(COLOR_PAIR_INFO));
            mvwprintw(win, y, 4, "-> %s", phase->current_action);
            wattroff(win, COLOR_PAIR(COLOR_PAIR_INFO));
            y++;
        }

        // Items found
        if (phase->status == PHASE_COMPLETED && phase->items_found > 0) {
            wattron(win, COLOR_PAIR(COLOR_PAIR_SUCCESS));
            mvwprintw(win, y, 4, "Found: %d items", phase->items_found);
            wattroff(win, COLOR_PAIR(COLOR_PAIR_SUCCESS));
            y++;
        }

        y++; // Spacing between phases
    }
}

// Format duration
void tui_format_duration(time_t seconds, char *buffer, size_t buffer_size) {
    if (seconds < 60) {
        snprintf(buffer, buffer_size, "%lds", seconds);
    } else if (seconds < 3600) {
        snprintf(buffer, buffer_size, "%ldm %lds", seconds / 60, seconds % 60);
    } else {
        snprintf(buffer, buffer_size, "%ldh %ldm", seconds / 3600, (seconds % 3600) / 60);
    }
}

// Format confidence
void tui_format_confidence(float confidence, char *buffer, size_t buffer_size) {
    int percent = (int)(confidence * 100);

    if (percent >= 90) {
        snprintf(buffer, buffer_size, "%d%% (VERIFIED)", percent);
    } else if (percent >= 80) {
        snprintf(buffer, buffer_size, "%d%% (VERY LIKELY)", percent);
    } else if (percent >= 70) {
        snprintf(buffer, buffer_size, "%d%% (LIKELY)", percent);
    } else if (percent >= 60) {
        snprintf(buffer, buffer_size, "%d%% (POSSIBLE)", percent);
    } else {
        snprintf(buffer, buffer_size, "%d%% (WEAK)", percent);
    }
}

// Draw candidate list
void tui_draw_candidate_list(WINDOW *win, struct origin_ip_candidate *candidates, int count, int selected) {
    int max_y, max_x;
    getmaxyx(win, max_y, max_x);

    int y = 2;
    int display_count = max_y - 4;  // Leave room for border and instructions

    if (count == 0) {
        wattron(win, COLOR_PAIR(COLOR_PAIR_WARNING));
        mvwprintw(win, y, 2, "No origin IP candidates found");
        wattroff(win, COLOR_PAIR(COLOR_PAIR_WARNING));
        return;
    }

    for (int i = 0; i < count && i < display_count; i++) {
        struct origin_ip_candidate *c = &candidates[i];

        // Highlight selected
        if (i == selected) {
            wattron(win, COLOR_PAIR(COLOR_PAIR_HIGHLIGHT) | A_BOLD);
            mvwprintw(win, y, 1, ">");
        } else {
            mvwprintw(win, y, 1, " ");
        }

        // Rank
        mvwprintw(win, y, 2, "%2d.", i + 1);

        // IP Address
        mvwprintw(win, y, 6, "%-16s", c->ip_address);

        // Confidence with color
        char conf_str[64];
        tui_format_confidence(c->confidence_score, conf_str, sizeof(conf_str));

        int conf_color = COLOR_PAIR_INFO;
        if (c->confidence_score >= 0.90) conf_color = COLOR_PAIR_SUCCESS;
        else if (c->confidence_score >= 0.70) conf_color = COLOR_PAIR_WARNING;

        wattron(win, COLOR_PAIR(conf_color));
        mvwprintw(win, y, 24, "%s", conf_str);
        wattroff(win, COLOR_PAIR(conf_color));

        // Discovery method
        wattron(win, COLOR_PAIR(COLOR_PAIR_INFO));
        mvwprintw(win, y, 50, "%.25s", c->discovery_method);
        wattroff(win, COLOR_PAIR(COLOR_PAIR_INFO));

        if (i == selected) {
            wattroff(win, COLOR_PAIR(COLOR_PAIR_HIGHLIGHT) | A_BOLD);
        }

        y++;
    }

    // Instructions at bottom
    wattron(win, COLOR_PAIR(COLOR_PAIR_INFO));
    mvwprintw(win, max_y - 2, 2, "↑/↓: Navigate  ENTER: Details  Q: Quit");
    wattroff(win, COLOR_PAIR(COLOR_PAIR_INFO));
}

// Draw statistics
void tui_draw_statistics(WINDOW *win, struct tui_state *state) {
    int y = 2;

    wattron(win, A_BOLD);
    mvwprintw(win, y++, 2, "Scan Statistics");
    wattroff(win, A_BOLD);
    y++;

    // Target
    mvwprintw(win, y++, 2, "Target Domain: %s", state->target_domain);
    y++;

    // Timing
    if (state->scan_end_time > 0) {
        time_t duration = state->scan_end_time - state->scan_start_time;
        char duration_str[64];
        tui_format_duration(duration, duration_str, sizeof(duration_str));

        mvwprintw(win, y++, 2, "Scan Duration: %s", duration_str);
    }
    y++;

    // Discoveries
    wattron(win, COLOR_PAIR(COLOR_PAIR_SUCCESS));
    mvwprintw(win, y++, 2, "Origin IP Candidates: %d",
              state->detection_result ? state->detection_result->candidate_count : 0);
    wattroff(win, COLOR_PAIR(COLOR_PAIR_SUCCESS));

    mvwprintw(win, y++, 2, "Total IPs Found: %d", state->total_ips_found);
    mvwprintw(win, y++, 2, "Subdomains Found: %d", state->total_subdomains_found);
    y++;

    // Techniques
    mvwprintw(win, y++, 2, "Techniques Attempted: %d", state->total_techniques_attempted);
    wattron(win, COLOR_PAIR(COLOR_PAIR_SUCCESS));
    mvwprintw(win, y++, 2, "Successful Techniques: %d", state->successful_techniques);
    wattroff(win, COLOR_PAIR(COLOR_PAIR_SUCCESS));

    if (state->total_techniques_attempted > 0) {
        int success_rate = (state->successful_techniques * 100) / state->total_techniques_attempted;
        mvwprintw(win, y++, 2, "Success Rate: %d%%", success_rate);
    }
}

// Center text
void tui_center_text(WINDOW *win, int y, const char *text, int color_pair) {
    int max_x = getmaxx(win);
    int x = (max_x - strlen(text)) / 2;

    if (color_pair > 0) {
        wattron(win, COLOR_PAIR(color_pair));
    }

    mvwprintw(win, y, x, "%s", text);

    if (color_pair > 0) {
        wattroff(win, COLOR_PAIR(color_pair));
    }
}

// Show welcome screen
void tui_show_welcome_screen(struct tui_state *state) {
    clear();

    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);

    // Draw logo
    draw_logo(stdscr, 2);

    // Description
    int y = 10;
    wattron(stdscr, COLOR_PAIR(COLOR_PAIR_INFO));
    tui_center_text(stdscr, y++, "Advanced Origin IP Detection Behind Cloudflare & CDNs", 0);
    wattroff(stdscr, COLOR_PAIR(COLOR_PAIR_INFO));
    y += 2;

    // Features
    wattron(stdscr, A_BOLD);
    tui_center_text(stdscr, y++, "═══ Features ═══", 0);
    wattroff(stdscr, A_BOLD);
    y++;

    wattron(stdscr, COLOR_PAIR(COLOR_PAIR_SUCCESS));
    tui_center_text(stdscr, y++, "✓ SSL Certificate Comparison", 0);
    tui_center_text(stdscr, y++, "✓ Advanced MX Record Enumeration", 0);
    tui_center_text(stdscr, y++, "✓ SRV Record Discovery (20+ services)", 0);
    tui_center_text(stdscr, y++, "✓ Cloudflare Bypass Detection", 0);
    tui_center_text(stdscr, y++, "✓ ASN Network Clustering", 0);
    tui_center_text(stdscr, y++, "✓ Reverse DNS Intelligence", 0);
    tui_center_text(stdscr, y++, "✓ Passive DNS Integration", 0);
    tui_center_text(stdscr, y++, "✓ WHOIS Netblock Discovery", 0);
    wattroff(stdscr, COLOR_PAIR(COLOR_PAIR_SUCCESS));
    y += 2;

    // Instructions
    wattron(stdscr, COLOR_PAIR(COLOR_PAIR_WARNING) | A_BOLD);
    tui_center_text(stdscr, y++, "Press any key to continue...", 0);
    wattroff(stdscr, COLOR_PAIR(COLOR_PAIR_WARNING) | A_BOLD);

    // Footer
    wattron(stdscr, COLOR_PAIR(COLOR_PAIR_INFO));
    mvwprintw(stdscr, max_y - 2, 2, "For authorized security testing only | v2.0-Enhanced");
    wattroff(stdscr, COLOR_PAIR(COLOR_PAIR_INFO));

    refresh();

    // Wait for key
    timeout(-1);  // Blocking
    getch();
    timeout(100); // Back to non-blocking
}

// Get string input
int tui_get_string_input(WINDOW *win, int y, int x, char *buffer, int max_len) {
    echo();
    curs_set(1);

    mvwprintw(win, y, x, "");
    wrefresh(win);

    int ch;
    int pos = 0;
    buffer[0] = '\0';

    while (1) {
        ch = wgetch(win);

        if (ch == '\n' || ch == KEY_ENTER) {
            break;
        } else if (ch == 27) {  // ESC
            buffer[0] = '\0';
            noecho();
            curs_set(0);
            return -1;
        } else if (ch == KEY_BACKSPACE || ch == 127 || ch == '\b') {
            if (pos > 0) {
                pos--;
                buffer[pos] = '\0';
                mvwprintw(win, y, x + pos, " ");
                wmove(win, y, x + pos);
            }
        } else if (ch >= 32 && ch < 127 && pos < max_len - 1) {
            buffer[pos++] = ch;
            buffer[pos] = '\0';
            waddch(win, ch);
        }

        wrefresh(win);
    }

    noecho();
    curs_set(0);
    return pos;
}

// Show input screen
void tui_show_input_screen(struct tui_state *state) {
    clear();

    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);

    WINDOW *win_input = newwin(10, max_x - 4, (max_y - 10) / 2, 2);
    box(win_input, 0, 0);

    wattron(win_input, COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);
    mvwprintw(win_input, 0, 2, " Target Input ");
    wattroff(win_input, COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);

    mvwprintw(win_input, 2, 2, "Enter target domain name:");
    mvwprintw(win_input, 3, 2, "Example: example.com");
    mvwprintw(win_input, 5, 2, "Domain: ");

    wattron(win_input, COLOR_PAIR(COLOR_PAIR_INFO));
    mvwprintw(win_input, 7, 2, "Press ESC to quit");
    wattroff(win_input, COLOR_PAIR(COLOR_PAIR_INFO));

    wrefresh(win_input);

    // Get input
    int result = tui_get_string_input(win_input, 5, 10, state->target_domain, sizeof(state->target_domain));

    delwin(win_input);

    if (result > 0) {
        state->current_screen = SCREEN_SCANNING;
        state->scanning_active = true;
    } else {
        state->current_screen = SCREEN_EXIT;
    }
}

// Initialize phases
void tui_init_phases(struct tui_state *state) {
    state->total_phases = 8;

    strcpy(state->phases[0].name, "DNS Reconnaissance");
    strcpy(state->phases[0].description, "Basic A/AAAA record lookups");

    strcpy(state->phases[1].name, "Certificate Transparency");
    strcpy(state->phases[1].description, "Mining CT logs for subdomains");

    strcpy(state->phases[2].name, "Subdomain Enumeration");
    strcpy(state->phases[2].description, "Multi-threaded subdomain scanning");

    strcpy(state->phases[3].name, "OSINT Gathering");
    strcpy(state->phases[3].description, "Historical IP data collection");

    strcpy(state->phases[4].name, "MX Record Analysis");
    strcpy(state->phases[4].description, "Mail server infrastructure");

    strcpy(state->phases[5].name, "SRV Record Discovery");
    strcpy(state->phases[5].description, "Service-specific DNS records");

    strcpy(state->phases[6].name, "SSL Certificate Testing");
    strcpy(state->phases[6].description, "Direct IP certificate comparison");

    strcpy(state->phases[7].name, "ASN Clustering");
    strcpy(state->phases[7].description, "Network infrastructure analysis");

    for (int i = 0; i < state->total_phases; i++) {
        state->phases[i].phase_number = i;
        state->phases[i].status = PHASE_PENDING;
        state->phases[i].progress = 0;
        state->phases[i].items_found = 0;
    }
}

// Show scanning screen
void tui_show_scanning_screen(struct tui_state *state) {
    clear();

    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);

    // Header
    WINDOW *win_header = newwin(3, max_x, 0, 0);
    tui_draw_header(win_header, "CloudClear - Advanced IP Detection", state->target_domain);

    // Phase list
    WINDOW *win_phases = newwin(max_y - 10, max_x / 2, 3, 0);
    tui_draw_border(win_phases, "Scan Progress");
    tui_draw_phase_list(win_phases, state->phases, state->total_phases, state->current_phase);
    wrefresh(win_phases);

    // Statistics
    WINDOW *win_stats = newwin(max_y - 10, max_x / 2, 3, max_x / 2);
    tui_draw_border(win_stats, "Statistics");
    tui_draw_statistics(win_stats, state);
    wrefresh(win_stats);

    // Status bar
    WINDOW *win_status = newwin(3, max_x, max_y - 3, 0);
    box(win_status, 0, 0);

    if (state->scanning_complete) {
        wattron(win_status, COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);
        mvwprintw(win_status, 1, 2, "Scan Complete! Press any key to view results...");
        wattroff(win_status, COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);
    } else {
        wattron(win_status, COLOR_PAIR(COLOR_PAIR_WARNING));
        mvwprintw(win_status, 1, 2, "Scanning in progress... Please wait");
        wattroff(win_status, COLOR_PAIR(COLOR_PAIR_WARNING));
    }

    wrefresh(win_status);

    // Cleanup windows
    delwin(win_header);
    delwin(win_phases);
    delwin(win_stats);
    delwin(win_status);

    refresh();
}

// Show results screen
void tui_show_results_screen(struct tui_state *state) {
    clear();

    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);

    // Header
    WINDOW *win_header = newwin(3, max_x, 0, 0);
    char subtitle[128];
    snprintf(subtitle, sizeof(subtitle), "%s | %d candidates found",
             state->target_domain,
             state->detection_result ? state->detection_result->candidate_count : 0);
    tui_draw_header(win_header, "CloudClear - Scan Results", subtitle);

    // Candidate list
    WINDOW *win_candidates = newwin(max_y - 6, max_x, 3, 0);
    tui_draw_border(win_candidates, "Origin IP Candidates (Ranked by Confidence)");

    if (state->detection_result && state->detection_result->candidate_count > 0) {
        tui_draw_candidate_list(win_candidates,
                               state->detection_result->candidates,
                               state->detection_result->candidate_count,
                               state->selected_candidate);
    } else {
        wattron(win_candidates, COLOR_PAIR(COLOR_PAIR_WARNING));
        mvwprintw(win_candidates, 2, 2, "No origin IP candidates found");
        wattroff(win_candidates, COLOR_PAIR(COLOR_PAIR_WARNING));
    }

    wrefresh(win_candidates);

    // Status bar
    WINDOW *win_status = newwin(3, max_x, max_y - 3, 0);
    box(win_status, 0, 0);
    wattron(win_status, COLOR_PAIR(COLOR_PAIR_INFO));
    mvwprintw(win_status, 1, 2, "↑/↓: Navigate | ENTER: View Details | Q: Quit | H: Help");
    wattroff(win_status, COLOR_PAIR(COLOR_PAIR_INFO));
    wrefresh(win_status);

    delwin(win_header);
    delwin(win_candidates);
    delwin(win_status);

    refresh();
}

// Show candidate detail
void tui_show_candidate_detail(struct tui_state *state, int candidate_index) {
    if (!state->detection_result || candidate_index >= state->detection_result->candidate_count) {
        return;
    }

    clear();

    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);

    struct origin_ip_candidate *c = &state->detection_result->candidates[candidate_index];

    // Header
    WINDOW *win_header = newwin(3, max_x, 0, 0);
    char subtitle[128];
    snprintf(subtitle, sizeof(subtitle), "Candidate #%d - %s", candidate_index + 1, c->ip_address);
    tui_draw_header(win_header, "Origin IP Candidate Details", subtitle);

    // Details window
    WINDOW *win_details = newwin(max_y - 6, max_x, 3, 0);
    tui_draw_border(win_details, "Detailed Information");

    int y = 2;

    // IP Address
    wattron(win_details, A_BOLD);
    mvwprintw(win_details, y++, 2, "IP Address:");
    wattroff(win_details, A_BOLD);
    wattron(win_details, COLOR_PAIR(COLOR_PAIR_SUCCESS));
    mvwprintw(win_details, y++, 4, "%s", c->ip_address);
    wattroff(win_details, COLOR_PAIR(COLOR_PAIR_SUCCESS));
    y++;

    // Confidence
    wattron(win_details, A_BOLD);
    mvwprintw(win_details, y++, 2, "Confidence Score:");
    wattroff(win_details, A_BOLD);

    char conf_str[64];
    tui_format_confidence(c->confidence_score, conf_str, sizeof(conf_str));

    int conf_color = c->confidence_score >= 0.90 ? COLOR_PAIR_SUCCESS :
                    c->confidence_score >= 0.70 ? COLOR_PAIR_WARNING : COLOR_PAIR_INFO;
    wattron(win_details, COLOR_PAIR(conf_color));
    mvwprintw(win_details, y++, 4, "%s", conf_str);
    wattroff(win_details, COLOR_PAIR(conf_color));
    y++;

    // Discovery Method
    wattron(win_details, A_BOLD);
    mvwprintw(win_details, y++, 2, "Primary Discovery Method:");
    wattroff(win_details, A_BOLD);
    mvwprintw(win_details, y++, 4, "%s", c->discovery_method);
    y++;

    // ASN Information
    if (c->asn > 0) {
        wattron(win_details, A_BOLD);
        mvwprintw(win_details, y++, 2, "Network Information:");
        wattroff(win_details, A_BOLD);
        mvwprintw(win_details, y++, 4, "ASN: AS%u", c->asn);
        if (strlen(c->asn_name) > 0) {
            mvwprintw(win_details, y++, 4, "AS Name: %s", c->asn_name);
        }
        if (strlen(c->hosting_provider) > 0) {
            mvwprintw(win_details, y++, 4, "Hosting: %s", c->hosting_provider);
        }
        y++;
    }

    // Supporting Evidence
    wattron(win_details, A_BOLD);
    mvwprintw(win_details, y++, 2, "Supporting Evidence (%d):", c->evidence_count);
    wattroff(win_details, A_BOLD);

    for (int i = 0; i < c->evidence_count && y < max_y - 8; i++) {
        wattron(win_details, COLOR_PAIR(COLOR_PAIR_SUCCESS));
        mvwprintw(win_details, y++, 4, "✓ %s", c->supporting_evidence[i]);
        wattroff(win_details, COLOR_PAIR(COLOR_PAIR_SUCCESS));
    }

    wrefresh(win_details);

    // Status bar
    WINDOW *win_status = newwin(3, max_x, max_y - 3, 0);
    box(win_status, 0, 0);
    wattron(win_status, COLOR_PAIR(COLOR_PAIR_INFO));
    mvwprintw(win_status, 1, 2, "Press any key to return to results...");
    wattroff(win_status, COLOR_PAIR(COLOR_PAIR_INFO));
    wrefresh(win_status);

    delwin(win_header);
    delwin(win_details);
    delwin(win_status);

    refresh();

    // Wait for key
    timeout(-1);
    getch();
    timeout(100);
}

// Show help screen
void tui_show_help_screen(struct tui_state *state) {
    clear();

    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);

    WINDOW *win_help = newwin(max_y, max_x, 0, 0);
    tui_draw_border(win_help, "CloudClear - Help");

    int y = 2;

    wattron(win_help, COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);
    mvwprintw(win_help, y++, 2, "CloudClear - Advanced Origin IP Detection");
    wattroff(win_help, COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);
    y += 2;

    wattron(win_help, A_BOLD);
    mvwprintw(win_help, y++, 2, "Keyboard Shortcuts:");
    wattroff(win_help, A_BOLD);
    y++;

    mvwprintw(win_help, y++, 4, "↑/↓ or k/j    - Navigate up/down");
    mvwprintw(win_help, y++, 4, "ENTER         - Select / View details");
    mvwprintw(win_help, y++, 4, "ESC or Q      - Quit / Go back");
    mvwprintw(win_help, y++, 4, "H             - Show this help");
    y += 2;

    wattron(win_help, A_BOLD);
    mvwprintw(win_help, y++, 2, "Detection Techniques:");
    wattroff(win_help, A_BOLD);
    y++;

    mvwprintw(win_help, y++, 4, "1. SSL Certificate Comparison - Direct IP testing");
    mvwprintw(win_help, y++, 4, "2. MX Record Analysis - Mail server infrastructure");
    mvwprintw(win_help, y++, 4, "3. SRV Record Discovery - 20+ service types");
    mvwprintw(win_help, y++, 4, "4. Cloudflare Bypass - Subdomain enumeration");
    mvwprintw(win_help, y++, 4, "5. ASN Clustering - Network infrastructure");
    mvwprintw(win_help, y++, 4, "6. Reverse DNS - PTR record analysis");
    mvwprintw(win_help, y++, 4, "7. Passive DNS - Historical IP data");
    mvwprintw(win_help, y++, 4, "8. WHOIS/RDAP - Netblock discovery");
    y += 2;

    wattron(win_help, COLOR_PAIR(COLOR_PAIR_WARNING));
    mvwprintw(win_help, y++, 2, "For authorized security testing only!");
    wattroff(win_help, COLOR_PAIR(COLOR_PAIR_WARNING));
    y += 2;

    wattron(win_help, COLOR_PAIR(COLOR_PAIR_INFO));
    mvwprintw(win_help, y++, 2, "Press any key to return...");
    wattroff(win_help, COLOR_PAIR(COLOR_PAIR_INFO));

    wrefresh(win_help);

    timeout(-1);
    getch();
    timeout(100);

    delwin(win_help);
}

// Handle keys on results screen
int tui_handle_key_results_screen(struct tui_state *state, int key) {
    int candidate_count = state->detection_result ? state->detection_result->candidate_count : 0;

    switch (key) {
        case KEY_UP:
        case 'k':
            if (state->selected_candidate > 0) {
                state->selected_candidate--;
            }
            break;

        case KEY_DOWN:
        case 'j':
            if (state->selected_candidate < candidate_count - 1) {
                state->selected_candidate++;
            }
            break;

        case '\n':
        case KEY_ENTER:
            if (candidate_count > 0) {
                tui_show_candidate_detail(state, state->selected_candidate);
            }
            break;

        case 'h':
        case 'H':
            tui_show_help_screen(state);
            break;

        case 'q':
        case 'Q':
        case 27:  // ESC
            return -1;  // Exit
    }

    return 0;
}

// Main TUI loop
int tui_run(void) {
    tui_init();

    struct tui_state state = {0};
    state.current_screen = SCREEN_WELCOME;
    g_tui_state = &state;

    tui_init_phases(&state);

    while (state.current_screen != SCREEN_EXIT) {
        switch (state.current_screen) {
            case SCREEN_WELCOME:
                tui_show_welcome_screen(&state);
                state.current_screen = SCREEN_INPUT;
                break;

            case SCREEN_INPUT:
                tui_show_input_screen(&state);
                break;

            case SCREEN_SCANNING:
                tui_show_scanning_screen(&state);

                // Check for scan completion
                if (state.scanning_complete) {
                    int ch = getch();
                    if (ch != ERR) {
                        state.current_screen = SCREEN_RESULTS;
                    }
                }
                break;

            case SCREEN_RESULTS:
                tui_show_results_screen(&state);

                timeout(-1);  // Blocking input
                int ch = getch();
                timeout(100);  // Back to non-blocking

                if (tui_handle_key_results_screen(&state, ch) < 0) {
                    state.current_screen = SCREEN_EXIT;
                }
                break;

            default:
                state.current_screen = SCREEN_EXIT;
                break;
        }
    }

    tui_cleanup();
    return 0;
}

// Phase management functions
void tui_update_phase(struct tui_state *state, int phase_num, phase_status_t status, const char *action) {
    if (phase_num < 0 || phase_num >= state->total_phases) return;

    state->phases[phase_num].status = status;
    if (action) {
        strncpy(state->phases[phase_num].current_action, action, sizeof(state->phases[phase_num].current_action) - 1);
    }

    if (status == PHASE_RUNNING) {
        state->current_phase = phase_num;
        state->phases[phase_num].start_time = time(NULL);
    } else if (status == PHASE_COMPLETED) {
        state->phases[phase_num].end_time = time(NULL);
        state->phases[phase_num].progress = 100;
    }
}

void tui_set_phase_progress(struct tui_state *state, int phase_num, int progress) {
    if (phase_num < 0 || phase_num >= state->total_phases) return;
    state->phases[phase_num].progress = progress;
}

void tui_increment_phase_items(struct tui_state *state, int phase_num) {
    if (phase_num < 0 || phase_num >= state->total_phases) return;
    state->phases[phase_num].items_found++;
}

void tui_complete_phase(struct tui_state *state, int phase_num, int items_found) {
    if (phase_num < 0 || phase_num >= state->total_phases) return;
    state->phases[phase_num].status = PHASE_COMPLETED;
    state->phases[phase_num].items_found = items_found;
    state->phases[phase_num].end_time = time(NULL);
    state->phases[phase_num].progress = 100;
}

// Scan management
void tui_start_scan(struct tui_state *state, const char *domain) {
    strncpy(state->target_domain, domain, sizeof(state->target_domain) - 1);
    state->scanning_active = true;
    state->scanning_complete = false;
    state->scan_start_time = time(NULL);
}

void tui_finish_scan(struct tui_state *state, struct advanced_ip_detection_result *result) {
    state->scanning_complete = true;
    state->scan_end_time = time(NULL);
    state->detection_result = result;

    if (result) {
        state->total_techniques_attempted = result->total_techniques_attempted;
        state->successful_techniques = result->successful_techniques;
    }
}
