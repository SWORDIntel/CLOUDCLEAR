/*
 * CloudClear TUI - Enhanced Visual Implementation
 * Polished UI with modern design elements
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ncurses.h>
#include <unistd.h>
#include <wchar.h>
#include <locale.h>
#include "cloudclear_tui.h"

// Enhanced color pairs with more vibrant scheme
#define COLOR_PAIR_TITLE 9
#define COLOR_PAIR_SUBTITLE 10
#define COLOR_PAIR_ACCENT 11
#define COLOR_PAIR_DIM 12
#define COLOR_PAIR_BRIGHT 13

// Unicode box drawing characters
#define BOX_H  "─"  // Horizontal line
#define BOX_V  "│"  // Vertical line
#define BOX_TL "┌"  // Top left corner
#define BOX_TR "┐"  // Top right corner
#define BOX_BL "└"  // Bottom left corner
#define BOX_BR "┘"  // Bottom right corner
#define BOX_VR "├"  // Vertical right
#define BOX_VL "┤"  // Vertical left
#define BOX_HU "┴"  // Horizontal up
#define BOX_HD "┬"  // Horizontal down
#define BOX_C  "┼"  // Cross

// Unicode symbols
#define SYM_CHECK "✓"
#define SYM_CROSS "✗"
#define SYM_ARROW_R "→"
#define SYM_ARROW_L "←"
#define SYM_ARROW_U "↑"
#define SYM_ARROW_D "↓"
#define SYM_DOT "•"
#define SYM_STAR "★"
#define SYM_HOURGLASS "⧗"
#define SYM_GEAR "⚙"
#define SYM_SHIELD "🛡"
#define SYM_TARGET "🎯"
#define SYM_MAGNIFY "🔍"
#define SYM_ROCKET "🚀"
#define SYM_WARNING "⚠"
#define SYM_INFO "ℹ"
#define SYM_LIGHTNING "⚡"

// Initialize enhanced TUI with extended colors
int tui_init_enhanced(void) {
    setlocale(LC_ALL, "");  // Enable UTF-8 support

    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    timeout(100);

    // Initialize colors with enhanced palette
    if (has_colors()) {
        start_color();
        use_default_colors();  // Use terminal background

        // Standard colors
        init_pair(COLOR_PAIR_HEADER, COLOR_CYAN, -1);
        init_pair(COLOR_PAIR_SUCCESS, COLOR_GREEN, -1);
        init_pair(COLOR_PAIR_WARNING, COLOR_YELLOW, -1);
        init_pair(COLOR_PAIR_ERROR, COLOR_RED, -1);
        init_pair(COLOR_PAIR_INFO, COLOR_BLUE, -1);
        init_pair(COLOR_PAIR_HIGHLIGHT, COLOR_BLACK, COLOR_CYAN);
        init_pair(COLOR_PAIR_PROGRESS, COLOR_GREEN, -1);
        init_pair(COLOR_PAIR_BORDER, COLOR_WHITE, -1);

        // Enhanced colors
        init_pair(COLOR_PAIR_TITLE, COLOR_MAGENTA, -1);
        init_pair(COLOR_PAIR_SUBTITLE, COLOR_CYAN, -1);
        init_pair(COLOR_PAIR_ACCENT, COLOR_YELLOW, -1);
        init_pair(COLOR_PAIR_DIM, COLOR_WHITE, -1);
        init_pair(COLOR_PAIR_BRIGHT, COLOR_WHITE, -1);
    }

    return 0;
}

// Draw enhanced ASCII art logo with color gradient
static void draw_logo_enhanced(WINDOW *win, int start_y) {
    int y = start_y;

    // CloudClear ASCII art with color
    wattron(win, COLOR_PAIR(COLOR_PAIR_TITLE) | A_BOLD);
    mvwprintw(win, y++, 8, "   ██████╗██╗      ██████╗ ██╗   ██╗██████╗ ");
    mvwprintw(win, y++, 8, "  ██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗");
    mvwprintw(win, y++, 8, "  ██║     ██║     ██║   ██║██║   ██║██║  ██║");
    mvwprintw(win, y++, 8, "  ██║     ██║     ██║   ██║██║   ██║██║  ██║");
    mvwprintw(win, y++, 8, "  ╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝");
    mvwprintw(win, y++, 8, "   ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝ ");
    wattroff(win, COLOR_PAIR(COLOR_PAIR_TITLE) | A_BOLD);

    wattron(win, COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);
    mvwprintw(win, y++, 8, "   ██████╗██╗     ███████╗ █████╗ ██████╗  ");
    mvwprintw(win, y++, 8, "  ██╔════╝██║     ██╔════╝██╔══██╗██╔══██╗ ");
    mvwprintw(win, y++, 8, "  ██║     ██║     █████╗  ███████║██████╔╝ ");
    mvwprintw(win, y++, 8, "  ██║     ██║     ██╔══╝  ██╔══██║██╔══██╗ ");
    mvwprintw(win, y++, 8, "  ╚██████╗███████╗███████╗██║  ██║██║  ██║ ");
    mvwprintw(win, y++, 8, "   ╚═════╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ");
    wattroff(win, COLOR_PAIR(COLOR_PAIR_HEADER) | A_BOLD);

    y++;
    wattron(win, COLOR_PAIR(COLOR_PAIR_SUBTITLE) | A_BOLD);
    tui_center_text(win, y++, "═══════════════════════════════════════════════════════", 0);
    wattroff(win, COLOR_PAIR(COLOR_PAIR_SUBTITLE) | A_BOLD);

    wattron(win, COLOR_PAIR(COLOR_PAIR_INFO));
    tui_center_text(win, y++, "Advanced CDN Origin IP Detection Platform v2.0", 0);
    wattroff(win, COLOR_PAIR(COLOR_PAIR_INFO));

    wattron(win, COLOR_PAIR(COLOR_PAIR_DIM));
    tui_center_text(win, y++, "Penetrate CDN obfuscation • Discover true origin IPs", 0);
    wattroff(win, COLOR_PAIR(COLOR_PAIR_DIM));
}

// Draw fancy double-line border
void tui_draw_fancy_border(WINDOW *win, const char *title, const char *icon) {
    int max_y, max_x;
    getmaxyx(win, max_y, max_x);

    wattron(win, COLOR_PAIR(COLOR_PAIR_BORDER) | A_BOLD);

    // Top border
    mvwprintw(win, 0, 0, "╔");
    for (int i = 1; i < max_x - 1; i++) {
        wprintw(win, "═");
    }
    wprintw(win, "╗");

    // Sides
    for (int i = 1; i < max_y - 1; i++) {
        mvwprintw(win, i, 0, "║");
        mvwprintw(win, i, max_x - 1, "║");
    }

    // Bottom border
    mvwprintw(win, max_y - 1, 0, "╚");
    for (int i = 1; i < max_x - 1; i++) {
        wprintw(win, "═");
    }
    wprintw(win, "╝");

    wattroff(win, COLOR_PAIR(COLOR_PAIR_BORDER) | A_BOLD);

    // Title with icon
    if (title) {
        wattron(win, COLOR_PAIR(COLOR_PAIR_ACCENT) | A_BOLD);
        if (icon) {
            mvwprintw(win, 0, 3, " %s %s ", icon, title);
        } else {
            mvwprintw(win, 0, 3, " %s ", title);
        }
        wattroff(win, COLOR_PAIR(COLOR_PAIR_ACCENT) | A_BOLD);
    }
}

// Enhanced progress bar with gradient effect
void tui_draw_progress_bar_enhanced(WINDOW *win, int y, int x, int width, int progress, const char *label) {
    if (progress < 0) progress = 0;
    if (progress > 100) progress = 100;

    int filled = (width * progress) / 100;

    // Label
    wattron(win, COLOR_PAIR(COLOR_PAIR_INFO));
    mvwprintw(win, y, x, "%s ", label);
    wattroff(win, COLOR_PAIR(COLOR_PAIR_INFO));

    int bar_x = x + strlen(label) + 1;

    // Left bracket
    wattron(win, COLOR_PAIR(COLOR_PAIR_BORDER));
    mvwprintw(win, y, bar_x, "▕");
    wattroff(win, COLOR_PAIR(COLOR_PAIR_BORDER));

    // Progress fill with color gradient
    for (int i = 0; i < width; i++) {
        int color;
        if (progress < 30) {
            color = COLOR_PAIR_ERROR;
        } else if (progress < 70) {
            color = COLOR_PAIR_WARNING;
        } else {
            color = COLOR_PAIR_SUCCESS;
        }

        if (i < filled) {
            wattron(win, COLOR_PAIR(color) | A_BOLD);
            wprintw(win, "█");
            wattroff(win, COLOR_PAIR(color) | A_BOLD);
        } else {
            wattron(win, COLOR_PAIR(COLOR_PAIR_DIM));
            wprintw(win, "░");
            wattroff(win, COLOR_PAIR(COLOR_PAIR_DIM));
        }
    }

    // Right bracket
    wattron(win, COLOR_PAIR(COLOR_PAIR_BORDER));
    wprintw(win, "▏");
    wattroff(win, COLOR_PAIR(COLOR_PAIR_BORDER));

    // Percentage
    if (progress == 100) {
        wattron(win, COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);
        wprintw(win, " %3d%% %s", progress, SYM_CHECK);
        wattroff(win, COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);
    } else {
        wattron(win, COLOR_PAIR(COLOR_PAIR_INFO));
        wprintw(win, " %3d%%", progress);
        wattroff(win, COLOR_PAIR(COLOR_PAIR_INFO));
    }
}

// Enhanced phase display with icons
void tui_draw_phase_list_enhanced(WINDOW *win, struct tui_phase *phases, int phase_count, int current_phase) {
    int y = 2;
    int max_y, max_x;
    getmaxyx(win, max_y, max_x);

    for (int i = 0; i < phase_count && y < max_y - 2; i++) {
        struct tui_phase *phase = &phases[i];

        // Status icon
        const char *status_icon;
        int status_color;

        switch (phase->status) {
            case PHASE_PENDING:
                status_icon = "○";
                status_color = COLOR_PAIR_DIM;
                break;
            case PHASE_RUNNING:
                status_icon = SYM_GEAR;
                status_color = COLOR_PAIR_WARNING;
                break;
            case PHASE_COMPLETED:
                status_icon = SYM_CHECK;
                status_color = COLOR_PAIR_SUCCESS;
                break;
            case PHASE_FAILED:
                status_icon = SYM_CROSS;
                status_color = COLOR_PAIR_ERROR;
                break;
            default:
                status_icon = "?";
                status_color = COLOR_PAIR_INFO;
        }

        // Draw status icon
        wattron(win, COLOR_PAIR(status_color) | A_BOLD);
        mvwprintw(win, y, 2, "%s", status_icon);
        wattroff(win, COLOR_PAIR(status_color) | A_BOLD);

        // Phase number and name
        if (i == current_phase && phase->status == PHASE_RUNNING) {
            wattron(win, COLOR_PAIR(COLOR_PAIR_ACCENT) | A_BOLD);
            mvwprintw(win, y, 4, "[%d/%d] %s", i + 1, phase_count, phase->name);
            wattroff(win, COLOR_PAIR(COLOR_PAIR_ACCENT) | A_BOLD);
        } else {
            wattron(win, A_BOLD);
            mvwprintw(win, y, 4, "[%d/%d] ", i + 1, phase_count);
            wattroff(win, A_BOLD);
            wprintw(win, "%s", phase->name);
        }

        // Status text
        wattron(win, COLOR_PAIR(status_color));
        mvwprintw(win, y, max_x - 15, "[%s]", tui_get_phase_status_string(phase->status));
        wattroff(win, COLOR_PAIR(status_color));

        y++;

        // Progress bar for running phase
        if (phase->status == PHASE_RUNNING) {
            tui_draw_progress_bar_enhanced(win, y, 4, 35, phase->progress, "Progress");
            y++;
        }

        // Current action with animation
        if (phase->status == PHASE_RUNNING && strlen(phase->current_action) > 0) {
            wattron(win, COLOR_PAIR(COLOR_PAIR_INFO));
            mvwprintw(win, y, 6, "%s %s", SYM_ARROW_R, phase->current_action);
            wattroff(win, COLOR_PAIR(COLOR_PAIR_INFO));
            y++;
        }

        // Items found with visual indicator
        if (phase->status == PHASE_COMPLETED && phase->items_found > 0) {
            wattron(win, COLOR_PAIR(COLOR_PAIR_SUCCESS));
            mvwprintw(win, y, 6, "%s Found: %d items", SYM_STAR, phase->items_found);
            wattroff(win, COLOR_PAIR(COLOR_PAIR_SUCCESS));
            y++;
        }

        y++; // Spacing between phases
    }
}

// Enhanced candidate list with visual ranking
void tui_draw_candidate_list_enhanced(WINDOW *win, struct origin_ip_candidate *candidates, int count, int selected) {
    int max_y, max_x;
    getmaxyx(win, max_y, max_x);

    int y = 2;
    int display_count = max_y - 5;

    if (count == 0) {
        wattron(win, COLOR_PAIR(COLOR_PAIR_WARNING) | A_BOLD);
        mvwprintw(win, y, 2, "%s No origin IP candidates found", SYM_WARNING);
        wattroff(win, COLOR_PAIR(COLOR_PAIR_WARNING) | A_BOLD);

        wattron(win, COLOR_PAIR(COLOR_PAIR_INFO));
        mvwprintw(win, y + 2, 2, "This could mean:");
        mvwprintw(win, y + 3, 4, "%s Target is well protected", SYM_DOT);
        mvwprintw(win, y + 4, 4, "%s CDN/WAF configuration is strong", SYM_DOT);
        mvwprintw(win, y + 5, 4, "%s Origin IP may be hidden in non-standard ways", SYM_DOT);
        wattroff(win, COLOR_PAIR(COLOR_PAIR_INFO));

        return;
    }

    // Column headers
    wattron(win, COLOR_PAIR(COLOR_PAIR_ACCENT) | A_BOLD);
    mvwprintw(win, y, 2, "Rank  IP Address       Confidence Score        Discovery Method");
    wattroff(win, COLOR_PAIR(COLOR_PAIR_ACCENT) | A_BOLD);
    y++;

    wattron(win, COLOR_PAIR(COLOR_PAIR_DIM));
    mvwprintw(win, y, 2, "────  ─────────────────────────────────────────────────────────────");
    wattroff(win, COLOR_PAIR(COLOR_PAIR_DIM));
    y++;

    for (int i = 0; i < count && i < display_count; i++) {
        struct origin_ip_candidate *c = &candidates[i];

        // Selection highlight
        if (i == selected) {
            wattron(win, COLOR_PAIR(COLOR_PAIR_HIGHLIGHT) | A_BOLD);
            mvwprintw(win, y, 0, ">");
            for (int j = 1; j < max_x - 1; j++) {
                wprintw(win, " ");
            }
            wattroff(win, COLOR_PAIR(COLOR_PAIR_HIGHLIGHT) | A_BOLD);
        } else {
            mvwprintw(win, y, 0, " ");
        }

        // Rank with medal icons
        const char *rank_icon;
        int rank_color;
        if (i == 0) {
            rank_icon = "🥇";
            rank_color = COLOR_PAIR_ACCENT;
        } else if (i == 1) {
            rank_icon = "🥈";
            rank_color = COLOR_PAIR_BRIGHT;
        } else if (i == 2) {
            rank_icon = "🥉";
            rank_color = COLOR_PAIR_WARNING;
        } else {
            rank_icon = SYM_DOT;
            rank_color = COLOR_PAIR_INFO;
        }

        wattron(win, COLOR_PAIR(rank_color) | (i == selected ? A_BOLD : 0));
        mvwprintw(win, y, 2, "%s %2d", rank_icon, i + 1);
        wattroff(win, COLOR_PAIR(rank_color) | (i == selected ? A_BOLD : 0));

        // IP Address
        wattron(win, COLOR_PAIR(i == selected ? COLOR_PAIR_BRIGHT : COLOR_PAIR_INFO) | (i == selected ? A_BOLD : 0));
        mvwprintw(win, y, 8, "%-16s", c->ip_address);
        wattroff(win, COLOR_PAIR(i == selected ? COLOR_PAIR_BRIGHT : COLOR_PAIR_INFO) | (i == selected ? A_BOLD : 0));

        // Confidence with color-coded bars
        char conf_str[64];
        tui_format_confidence(c->confidence_score, conf_str, sizeof(conf_str));

        int conf_color;
        const char *conf_icon;
        if (c->confidence_score >= 0.90) {
            conf_color = COLOR_PAIR_SUCCESS;
            conf_icon = "█████";
        } else if (c->confidence_score >= 0.80) {
            conf_color = COLOR_PAIR_SUCCESS;
            conf_icon = "████░";
        } else if (c->confidence_score >= 0.70) {
            conf_color = COLOR_PAIR_WARNING;
            conf_icon = "███░░";
        } else if (c->confidence_score >= 0.60) {
            conf_color = COLOR_PAIR_WARNING;
            conf_icon = "██░░░";
        } else {
            conf_color = COLOR_PAIR_ERROR;
            conf_icon = "█░░░░";
        }

        wattron(win, COLOR_PAIR(conf_color) | (i == selected ? A_BOLD : 0));
        mvwprintw(win, y, 25, "%s %s", conf_icon, conf_str);
        wattroff(win, COLOR_PAIR(conf_color) | (i == selected ? A_BOLD : 0));

        // Discovery method
        wattron(win, COLOR_PAIR(i == selected ? COLOR_PAIR_SUBTITLE : COLOR_PAIR_DIM));
        mvwprintw(win, y, 56, "%.20s", c->discovery_method);
        wattroff(win, COLOR_PAIR(i == selected ? COLOR_PAIR_SUBTITLE : COLOR_PAIR_DIM));

        y++;
    }

    // Navigation help with icons
    y = max_y - 2;
    wattron(win, COLOR_PAIR(COLOR_PAIR_ACCENT));
    mvwprintw(win, y, 2, "%s%s Navigate", SYM_ARROW_U, SYM_ARROW_D);
    wattroff(win, COLOR_PAIR(COLOR_PAIR_ACCENT));

    wattron(win, COLOR_PAIR(COLOR_PAIR_SUCCESS));
    mvwprintw(win, y, 18, "↵ View Details");
    wattroff(win, COLOR_PAIR(COLOR_PAIR_SUCCESS));

    wattron(win, COLOR_PAIR(COLOR_PAIR_ERROR));
    mvwprintw(win, y, 36, "Q Quit");
    wattroff(win, COLOR_PAIR(COLOR_PAIR_ERROR));

    wattron(win, COLOR_PAIR(COLOR_PAIR_INFO));
    mvwprintw(win, y, 46, "H Help");
    wattroff(win, COLOR_PAIR(COLOR_PAIR_INFO));
}

// Enhanced statistics display
void tui_draw_statistics_enhanced(WINDOW *win, struct tui_state *state) {
    int y = 2;
    int max_x = getmaxx(win);

    // Title
    wattron(win, COLOR_PAIR(COLOR_PAIR_ACCENT) | A_BOLD);
    mvwprintw(win, y++, 2, "%s Scan Statistics", SYM_MAGNIFY);
    wattroff(win, COLOR_PAIR(COLOR_PAIR_ACCENT) | A_BOLD);

    wattron(win, COLOR_PAIR(COLOR_PAIR_DIM));
    mvwprintw(win, y++, 2, "────────────────────────────");
    wattroff(win, COLOR_PAIR(COLOR_PAIR_DIM));
    y++;

    // Target
    wattron(win, COLOR_PAIR(COLOR_PAIR_INFO));
    mvwprintw(win, y++, 2, "%s Target:", SYM_TARGET);
    wattroff(win, COLOR_PAIR(COLOR_PAIR_INFO));
    wattron(win, A_BOLD);
    mvwprintw(win, y++, 4, "%s", state->target_domain);
    wattroff(win, A_BOLD);
    y++;

    // Timing
    if (state->scan_end_time > 0) {
        time_t duration = state->scan_end_time - state->scan_start_time;
        char duration_str[64];
        tui_format_duration(duration, duration_str, sizeof(duration_str));

        wattron(win, COLOR_PAIR(COLOR_PAIR_INFO));
        mvwprintw(win, y++, 2, "%s Duration:", SYM_HOURGLASS);
        wattroff(win, COLOR_PAIR(COLOR_PAIR_INFO));
        wattron(win, COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);
        mvwprintw(win, y++, 4, "%s", duration_str);
        wattroff(win, COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);
    }
    y++;

    // Discoveries with visual indicators
    wattron(win, COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);
    int candidate_count = state->detection_result ? state->detection_result->candidate_count : 0;
    mvwprintw(win, y++, 2, "%s Origin Candidates: %d", SYM_STAR, candidate_count);
    wattroff(win, COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);

    wattron(win, COLOR_PAIR(COLOR_PAIR_INFO));
    mvwprintw(win, y++, 2, "%s Total IPs: %d", SYM_DOT, state->total_ips_found);
    mvwprintw(win, y++, 2, "%s Subdomains: %d", SYM_DOT, state->total_subdomains_found);
    wattroff(win, COLOR_PAIR(COLOR_PAIR_INFO));
    y++;

    // Techniques
    wattron(win, COLOR_PAIR(COLOR_PAIR_INFO));
    mvwprintw(win, y++, 2, "%s Techniques:", SYM_LIGHTNING);
    wattroff(win, COLOR_PAIR(COLOR_PAIR_INFO));

    mvwprintw(win, y++, 4, "Attempted: %d", state->total_techniques_attempted);

    wattron(win, COLOR_PAIR(COLOR_PAIR_SUCCESS));
    mvwprintw(win, y++, 4, "Successful: %d", state->successful_techniques);
    wattroff(win, COLOR_PAIR(COLOR_PAIR_SUCCESS));

    if (state->total_techniques_attempted > 0) {
        int success_rate = (state->successful_techniques * 100) / state->total_techniques_attempted;

        int rate_color = success_rate >= 70 ? COLOR_PAIR_SUCCESS :
                        success_rate >= 40 ? COLOR_PAIR_WARNING : COLOR_PAIR_ERROR;

        wattron(win, COLOR_PAIR(rate_color) | A_BOLD);
        mvwprintw(win, y++, 4, "Success Rate: %d%%", success_rate);
        wattroff(win, COLOR_PAIR(rate_color) | A_BOLD);
    }
}

// Enhanced welcome screen
void tui_show_welcome_screen_enhanced(struct tui_state *state) {
    clear();

    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);

    // Draw enhanced logo
    draw_logo_enhanced(stdscr, 1);

    // Features section
    int y = 16;
    wattron(stdscr, COLOR_PAIR(COLOR_PAIR_ACCENT) | A_BOLD);
    tui_center_text(stdscr, y++, "╔═══════════════════ FEATURES ═══════════════════╗", 0);
    wattroff(stdscr, COLOR_PAIR(COLOR_PAIR_ACCENT) | A_BOLD);
    y++;

    wattron(stdscr, COLOR_PAIR(COLOR_PAIR_SUCCESS));
    tui_center_text(stdscr, y++, "✓ SSL Certificate Transparency Analysis", 0);
    tui_center_text(stdscr, y++, "✓ Advanced MX & SRV Record Enumeration", 0);
    tui_center_text(stdscr, y++, "✓ Multi-Vector CDN Bypass Techniques", 0);
    tui_center_text(stdscr, y++, "✓ ASN Network Clustering & BGP Analysis", 0);
    tui_center_text(stdscr, y++, "✓ Reverse DNS & PTR Intelligence", 0);
    tui_center_text(stdscr, y++, "✓ WAF Evasion & Origin Verification (NEW!)", 0);
    wattroff(stdscr, COLOR_PAIR(COLOR_PAIR_SUCCESS));
    y += 2;

    wattron(stdscr, COLOR_PAIR(COLOR_PAIR_ACCENT) | A_BOLD);
    tui_center_text(stdscr, y++, "╚═════════════════════════════════════════════════╝", 0);
    wattroff(stdscr, COLOR_PAIR(COLOR_PAIR_ACCENT) | A_BOLD);
    y += 2;

    // Instructions with animation effect
    wattron(stdscr, COLOR_PAIR(COLOR_PAIR_WARNING) | A_BOLD | A_BLINK);
    tui_center_text(stdscr, y++, "▶ Press any key to continue...", 0);
    wattroff(stdscr, COLOR_PAIR(COLOR_PAIR_WARNING) | A_BOLD | A_BLINK);

    // Footer
    wattron(stdscr, COLOR_PAIR(COLOR_PAIR_DIM));
    mvwprintw(stdscr, max_y - 2, 2, "For authorized security testing only");
    wattroff(stdscr, COLOR_PAIR(COLOR_PAIR_DIM));

    wattron(stdscr, COLOR_PAIR(COLOR_PAIR_INFO));
    mvwprintw(stdscr, max_y - 2, max_x - 30, "v2.0-Enhanced | %s SWORD", SYM_SHIELD);
    wattroff(stdscr, COLOR_PAIR(COLOR_PAIR_INFO));

    refresh();

    timeout(-1);
    getch();
    timeout(100);
}

// Enhanced help screen
void tui_show_help_screen_enhanced(struct tui_state *state) {
    clear();

    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);

    WINDOW *win_help = newwin(max_y - 4, max_x - 4, 2, 2);
    tui_draw_fancy_border(win_help, "HELP & KEYBOARD SHORTCUTS", SYM_INFO);

    int y = 2;

    // Navigation section
    wattron(win_help, COLOR_PAIR(COLOR_PAIR_ACCENT) | A_BOLD);
    mvwprintw(win_help, y++, 4, "%s NAVIGATION", SYM_ROCKET);
    wattroff(win_help, COLOR_PAIR(COLOR_PAIR_ACCENT) | A_BOLD);
    y++;

    wattron(win_help, COLOR_PAIR(COLOR_PAIR_SUCCESS));
    mvwprintw(win_help, y++, 6, "%s / %s     Navigate up/down in lists", SYM_ARROW_U, SYM_ARROW_D);
    mvwprintw(win_help, y++, 6, "↵ ENTER     View detailed information");
    mvwprintw(win_help, y++, 6, "← ESC       Go back / Cancel");
    wattroff(win_help, COLOR_PAIR(COLOR_PAIR_SUCCESS));
    y += 2;

    // Actions section
    wattron(win_help, COLOR_PAIR(COLOR_PAIR_ACCENT) | A_BOLD);
    mvwprintw(win_help, y++, 4, "%s ACTIONS", SYM_GEAR);
    wattroff(win_help, COLOR_PAIR(COLOR_PAIR_ACCENT) | A_BOLD);
    y++;

    wattron(win_help, COLOR_PAIR(COLOR_PAIR_INFO));
    mvwprintw(win_help, y++, 6, "Q           Quit application");
    mvwprintw(win_help, y++, 6, "H / ?       Show this help");
    mvwprintw(win_help, y++, 6, "R           Refresh current view");
    mvwprintw(win_help, y++, 6, "S           Start new scan");
    wattroff(win_help, COLOR_PAIR(COLOR_PAIR_INFO));
    y += 2;

    // Tips section
    wattron(win_help, COLOR_PAIR(COLOR_PAIR_ACCENT) | A_BOLD);
    mvwprintw(win_help, y++, 4, "%s TIPS", SYM_LIGHTNING);
    wattroff(win_help, COLOR_PAIR(COLOR_PAIR_ACCENT) | A_BOLD);
    y++;

    wattron(win_help, COLOR_PAIR(COLOR_PAIR_WARNING));
    mvwprintw(win_help, y++, 6, "%s Candidates are ranked by confidence score", SYM_DOT);
    mvwprintw(win_help, y++, 6, "%s Higher scores indicate more likely origin servers", SYM_DOT);
    mvwprintw(win_help, y++, 6, "%s Multiple discovery methods increase confidence", SYM_DOT);
    mvwprintw(win_help, y++, 6, "%s Verify findings with additional tools", SYM_DOT);
    wattroff(win_help, COLOR_PAIR(COLOR_PAIR_WARNING));
    y += 2;

    // Legal notice
    wattron(win_help, COLOR_PAIR(COLOR_PAIR_ERROR) | A_BOLD);
    mvwprintw(win_help, y++, 4, "%s IMPORTANT", SYM_WARNING);
    wattroff(win_help, COLOR_PAIR(COLOR_PAIR_ERROR) | A_BOLD);
    y++;

    wattron(win_help, COLOR_PAIR(COLOR_PAIR_DIM));
    mvwprintw(win_help, y++, 6, "This tool is for authorized security testing only.");
    mvwprintw(win_help, y++, 6, "Always obtain proper authorization before testing.");
    wattroff(win_help, COLOR_PAIR(COLOR_PAIR_DIM));

    // Close instruction
    y = max_y - 6;
    wattron(win_help, COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);
    tui_center_text(win_help, y, "Press any key to close help...", 0);
    wattroff(win_help, COLOR_PAIR(COLOR_PAIR_SUCCESS) | A_BOLD);

    wrefresh(win_help);

    timeout(-1);
    getch();
    timeout(100);

    delwin(win_help);
}

// Export enhanced functions
int tui_use_enhanced_ui(void) {
    return tui_init_enhanced();
}
