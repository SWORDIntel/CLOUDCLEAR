/*
 * CloudClear TUI - Text User Interface
 * Interactive terminal interface for advanced IP detection
 */

#ifndef CLOUDCLEAR_TUI_H
#define CLOUDCLEAR_TUI_H

#include <ncurses.h>
#include <stdbool.h>
#include <time.h>
#include "advanced_ip_detection.h"

// Color pairs
#define COLOR_PAIR_HEADER 1
#define COLOR_PAIR_SUCCESS 2
#define COLOR_PAIR_WARNING 3
#define COLOR_PAIR_ERROR 4
#define COLOR_PAIR_INFO 5
#define COLOR_PAIR_HIGHLIGHT 6
#define COLOR_PAIR_PROGRESS 7
#define COLOR_PAIR_BORDER 8

// Screen IDs
typedef enum {
    SCREEN_WELCOME,
    SCREEN_INPUT,
    SCREEN_SETTINGS,
    SCREEN_API_CONFIG,
    SCREEN_CLOUD_STATUS,
    SCREEN_SCANNING,
    SCREEN_RESULTS,
    SCREEN_CANDIDATE_DETAIL,
    SCREEN_HELP,
    SCREEN_ABOUT,
    SCREEN_EXIT
} tui_screen_t;

// Phase status
typedef enum {
    PHASE_PENDING,
    PHASE_RUNNING,
    PHASE_COMPLETED,
    PHASE_FAILED
} phase_status_t;

// TUI Phase tracking
struct tui_phase {
    int phase_number;
    char name[128];
    char description[256];
    phase_status_t status;
    int progress;  // 0-100
    int items_found;
    time_t start_time;
    time_t end_time;
    char current_action[128];
};

// TUI State
struct tui_state {
    tui_screen_t current_screen;
    char target_domain[256];
    bool scanning_active;
    bool scanning_complete;

    // Phase tracking
    struct tui_phase phases[8];
    int current_phase;
    int total_phases;

    // Results
    struct advanced_ip_detection_result *detection_result;
    int selected_candidate;
    int scroll_offset;

    // Windows
    WINDOW *win_header;
    WINDOW *win_main;
    WINDOW *win_status;
    WINDOW *win_progress;

    // Statistics
    int total_ips_found;
    int total_subdomains_found;
    int total_techniques_attempted;
    int successful_techniques;
    time_t scan_start_time;
    time_t scan_end_time;

    // UI State
    bool show_help;
    bool show_details;
    int selected_menu_item;
    int settings_menu_item;
    int api_config_item;

    // Configuration
    void *api_config; // tui_api_config_t pointer
};

// TUI Functions

// Initialization and cleanup
int tui_init(void);
void tui_cleanup(void);

// Screen management
void tui_show_welcome_screen(struct tui_state *state);
void tui_show_input_screen(struct tui_state *state);
void tui_show_settings_screen(struct tui_state *state);
void tui_show_api_config_screen(struct tui_state *state);
void tui_show_cloud_status_screen(struct tui_state *state);
void tui_show_scanning_screen(struct tui_state *state);
void tui_show_results_screen(struct tui_state *state);
void tui_show_candidate_detail(struct tui_state *state, int candidate_index);
void tui_show_help_screen(struct tui_state *state);
void tui_show_about_screen(struct tui_state *state);

// Drawing functions
void tui_draw_header(WINDOW *win, const char *title, const char *subtitle);
void tui_draw_border(WINDOW *win, const char *title);
void tui_draw_progress_bar(WINDOW *win, int y, int x, int width, int progress, const char *label);
void tui_draw_phase_list(WINDOW *win, struct tui_phase *phases, int phase_count, int current_phase);
void tui_draw_candidate_list(WINDOW *win, struct origin_ip_candidate *candidates, int count, int selected);
void tui_draw_statistics(WINDOW *win, struct tui_state *state);
void tui_draw_status_bar(WINDOW *win, const char *message);

// Phase management
void tui_init_phases(struct tui_state *state);
void tui_update_phase(struct tui_state *state, int phase_num, phase_status_t status, const char *action);
void tui_set_phase_progress(struct tui_state *state, int phase_num, int progress);
void tui_increment_phase_items(struct tui_state *state, int phase_num);
void tui_complete_phase(struct tui_state *state, int phase_num, int items_found);

// Message functions
void tui_log_message(struct tui_state *state, const char *message, int color_pair);
void tui_log_success(struct tui_state *state, const char *message);
void tui_log_warning(struct tui_state *state, const char *message);
void tui_log_error(struct tui_state *state, const char *message);
void tui_log_info(struct tui_state *state, const char *message);

// Input handling
int tui_get_string_input(WINDOW *win, int y, int x, char *buffer, int max_len);
int tui_handle_key_results_screen(struct tui_state *state, int key);
int tui_handle_key_candidate_detail(struct tui_state *state, int key);

// Utility functions
void tui_center_text(WINDOW *win, int y, const char *text, int color_pair);
void tui_print_wrapped(WINDOW *win, int start_y, int start_x, int max_width, const char *text);
const char* tui_get_phase_status_string(phase_status_t status);
int tui_get_phase_status_color(phase_status_t status);
void tui_format_duration(time_t seconds, char *buffer, size_t buffer_size);
void tui_format_confidence(float confidence, char *buffer, size_t buffer_size);

// Main TUI loop
int tui_run(void);

// Integration with scanning
void tui_start_scan(struct tui_state *state, const char *domain);
void tui_update_scan_progress(struct tui_state *state);
void tui_finish_scan(struct tui_state *state, struct advanced_ip_detection_result *result);

// Live update callbacks
void tui_callback_phase_start(int phase_num, const char *phase_name);
void tui_callback_phase_progress(int phase_num, int progress, const char *action);
void tui_callback_phase_complete(int phase_num, int items_found);
void tui_callback_ip_found(const char *ip_address, const char *method);
void tui_callback_subdomain_found(const char *subdomain);

#endif // CLOUDCLEAR_TUI_H
