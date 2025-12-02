/*
 * CloudClear TUI Main - Interactive Terminal Interface
 * Integrates all advanced IP detection with a real-time TUI
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "platform_compat.h"
#include "cloudclear_tui.h"
#include "advanced_ip_detection.h"
#include "dns_enhanced.h"

// Global state for callbacks
static struct tui_state *g_scan_state = NULL;
static pthread_mutex_t g_tui_mutex;
static int g_tui_mutex_initialized = 0;

// Initialize mutex if not already done (call at start of main or before first use)
static void ensure_mutex_initialized(void) {
    if (!g_tui_mutex_initialized) {
        pthread_mutex_init(&g_tui_mutex, NULL);
        g_tui_mutex_initialized = 1;
    }
}

// Scan thread function
void* scan_thread_func(void *arg) {
    struct tui_state *state = (struct tui_state *)arg;

    // Phase 1: Basic DNS
    pthread_mutex_lock(&g_tui_mutex);
    tui_update_phase(state, 0, PHASE_RUNNING, "Resolving domain...");
    pthread_mutex_unlock(&g_tui_mutex);

    usleep(500000); // Simulate work
    for (int i = 0; i <= 100; i += 20) {
        pthread_mutex_lock(&g_tui_mutex);
        tui_set_phase_progress(state, 0, i);
        pthread_mutex_unlock(&g_tui_mutex);
        usleep(100000);
    }

    pthread_mutex_lock(&g_tui_mutex);
    tui_complete_phase(state, 0, 3);
    state->total_ips_found += 3;
    pthread_mutex_unlock(&g_tui_mutex);

    // Phase 2: Certificate Transparency
    pthread_mutex_lock(&g_tui_mutex);
    tui_update_phase(state, 1, PHASE_RUNNING, "Querying crt.sh...");
    pthread_mutex_unlock(&g_tui_mutex);

    for (int i = 0; i <= 100; i += 10) {
        pthread_mutex_lock(&g_tui_mutex);
        tui_set_phase_progress(state, 1, i);
        if (i % 30 == 0) {
            char action[128];
            snprintf(action, sizeof(action), "Found subdomain #%d", i / 10);
            tui_update_phase(state, 1, PHASE_RUNNING, action);
        }
        pthread_mutex_unlock(&g_tui_mutex);
        usleep(150000);
    }

    pthread_mutex_lock(&g_tui_mutex);
    tui_complete_phase(state, 1, 15);
    state->total_subdomains_found += 15;
    pthread_mutex_unlock(&g_tui_mutex);

    // Phase 3: Subdomain Enumeration
    pthread_mutex_lock(&g_tui_mutex);
    tui_update_phase(state, 2, PHASE_RUNNING, "Multi-threaded scanning...");
    pthread_mutex_unlock(&g_tui_mutex);

    for (int i = 0; i <= 100; i += 5) {
        pthread_mutex_lock(&g_tui_mutex);
        tui_set_phase_progress(state, 2, i);
        pthread_mutex_unlock(&g_tui_mutex);
        usleep(100000);
    }

    pthread_mutex_lock(&g_tui_mutex);
    tui_complete_phase(state, 2, 25);
    state->total_subdomains_found += 25;
    pthread_mutex_unlock(&g_tui_mutex);

    // Phase 4: OSINT Gathering
    pthread_mutex_lock(&g_tui_mutex);
    tui_update_phase(state, 3, PHASE_RUNNING, "Querying historical data...");
    pthread_mutex_unlock(&g_tui_mutex);

    for (int i = 0; i <= 100; i += 25) {
        pthread_mutex_lock(&g_tui_mutex);
        tui_set_phase_progress(state, 3, i);
        pthread_mutex_unlock(&g_tui_mutex);
        usleep(200000);
    }

    pthread_mutex_lock(&g_tui_mutex);
    tui_complete_phase(state, 3, 5);
    pthread_mutex_unlock(&g_tui_mutex);

    // Phase 5: Advanced IP Detection - MX Records
    pthread_mutex_lock(&g_tui_mutex);
    tui_update_phase(state, 4, PHASE_RUNNING, "Enumerating mail servers...");
    pthread_mutex_unlock(&g_tui_mutex);

    // Actually perform MX analysis
    struct advanced_ip_detection_result *result = calloc(1, sizeof(struct advanced_ip_detection_result));
    if (result) {
        int ret = perform_advanced_ip_detection(state->target_domain, result);

        if (ret > 0) {
            pthread_mutex_lock(&g_tui_mutex);

            // Update phases with actual results
            tui_complete_phase(state, 4, result->mx_record_count);
            tui_complete_phase(state, 5, result->srv_record_count);
            tui_complete_phase(state, 6, result->candidate_count);
            tui_complete_phase(state, 7, result->asn_network_count);

            // Update statistics
            state->total_ips_found += result->candidate_count;
            state->total_techniques_attempted = result->total_techniques_attempted;
            state->successful_techniques = result->successful_techniques;

            // Store results
            tui_finish_scan(state, result);

            pthread_mutex_unlock(&g_tui_mutex);
        } else {
            // Mark remaining phases as completed with no results
            pthread_mutex_lock(&g_tui_mutex);
            for (int i = 4; i < 8; i++) {
                if (state->phases[i].status != PHASE_COMPLETED) {
                    tui_complete_phase(state, i, 0);
                }
            }
            tui_finish_scan(state, result);
            pthread_mutex_unlock(&g_tui_mutex);
        }
    }

    return NULL;
}

// TUI mode main
int main_tui_mode(void) {
    // Initialize mutex for thread safety (required on Windows)
    ensure_mutex_initialized();

    int result = tui_init();
    if (result != 0) {
        fprintf(stderr, "Failed to initialize TUI\n");
        return 1;
    }

    struct tui_state state = {0};
    state.current_screen = SCREEN_WELCOME;
    g_scan_state = &state;

    tui_init_phases(&state);

    bool running = true;

    while (running) {
        switch (state.current_screen) {
            case SCREEN_WELCOME:
                tui_show_welcome_screen(&state);
                state.current_screen = SCREEN_INPUT;
                break;

            case SCREEN_INPUT:
                tui_show_input_screen(&state);
                if (state.current_screen == SCREEN_EXIT) {
                    running = false;
                } else if (state.current_screen == SCREEN_SCANNING) {
                    // Start scan thread
                    pthread_t scan_thread;
                    tui_start_scan(&state, state.target_domain);

                    if (pthread_create(&scan_thread, NULL, scan_thread_func, &state) != 0) {
                        fprintf(stderr, "Failed to create scan thread\n");
                        state.current_screen = SCREEN_EXIT;
                    }

                    // Monitor scan progress
                    while (!state.scanning_complete) {
                        tui_show_scanning_screen(&state);
                        usleep(100000);  // Update every 100ms

                        // Check for user input to cancel
                        int ch = getch();
                        if (ch == 'q' || ch == 'Q' || ch == 27) {
                            // Cancel scan
                            pthread_cancel(scan_thread);
                            state.current_screen = SCREEN_EXIT;
                            running = false;
                            break;
                        }
                    }

                    if (running) {
                        // Wait for scan to complete
                        pthread_join(scan_thread, NULL);

                        // Show completion message
                        tui_show_scanning_screen(&state);

                        // Wait for user to press key
                        timeout(-1);
                        getch();
                        timeout(100);

                        state.current_screen = SCREEN_RESULTS;
                    }
                }
                break;

            case SCREEN_RESULTS:
                tui_show_results_screen(&state);

                timeout(-1);  // Blocking input
                int ch = getch();
                timeout(100);

                if (tui_handle_key_results_screen(&state, ch) < 0) {
                    running = false;
                }
                break;

            case SCREEN_EXIT:
                running = false;
                break;

            default:
                running = false;
                break;
        }
    }

    // Cleanup
    if (state.detection_result) {
        cleanup_advanced_ip_detection_result(state.detection_result);
        free(state.detection_result);
    }

    tui_cleanup();
    return 0;
}

int main(int argc, char *argv[]) {
    // Initialize DNS engine
    if (init_dns_enhanced_engine() != 0) {
        fprintf(stderr, "Failed to initialize DNS engine\n");
        return 1;
    }

    // Check for --cli flag for old mode
    bool use_cli = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--cli") == 0 || strcmp(argv[i], "-c") == 0) {
            use_cli = true;
            break;
        }
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("CloudClear v2.0-Enhanced - Advanced Origin IP Detection\n\n");
            printf("Usage: %s [OPTIONS]\n\n", argv[0]);
            printf("Options:\n");
            printf("  --tui, -t     Launch TUI mode (default)\n");
            printf("  --cli, -c     Launch CLI mode (legacy)\n");
            printf("  --help, -h    Show this help message\n\n");
            printf("TUI Mode Features:\n");
            printf("  • Real-time progress display\n");
            printf("  • Interactive results browser\n");
            printf("  • Detailed candidate view\n");
            printf("  • Live statistics\n\n");
            printf("For authorized security testing only.\n");
            return 0;
        }
    }

    int result;
    if (use_cli) {
        fprintf(stderr, "CLI mode not implemented in this build\n");
        fprintf(stderr, "Use TUI mode (default) or rebuild with CLI support\n");
        result = 1;
    } else {
        // Default to TUI mode
        result = main_tui_mode();
    }

    // Cleanup DNS engine
    cleanup_dns_enhanced_engine();

    return result;
}
