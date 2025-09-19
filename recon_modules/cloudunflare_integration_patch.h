/*
 * CloudUnflare Enhanced - Integration Patch Header
 *
 * Integration patch to seamlessly add reconnaissance module support
 * to CloudUnflare main application without breaking existing functionality
 *
 * Agent: ARCHITECT (integration implementation)
 * Instructions: Add this include after line 34 in cloudunflare.c
 */

#ifndef CLOUDUNFLARE_INTEGRATION_PATCH_H
#define CLOUDUNFLARE_INTEGRATION_PATCH_H

#ifdef RECON_MODULES_ENABLED
#include "recon_modules/recon_integration.h"

// Integration initialization flag
static bool recon_integration_initialized = false;

// Initialize reconnaissance modules during CloudUnflare startup
static inline int cloudunflare_init_recon_modules(struct dns_resolver_chain *dns_chain,
                                                 pthread_t *thread_pool,
                                                 uint32_t thread_count) {
    if (recon_integration_initialized) {
        return 0; // Already initialized
    }

    printf("[RECON] Initializing reconnaissance modules...\n");

    // Initialize master context
    if (RECON_INIT("recon_config.json") != 0) {
        fprintf(stderr, "[RECON] Warning: Failed to initialize reconnaissance modules\n");
        return -1;
    }

    // Integrate with CloudUnflare resources
    if (recon_integrate_with_cloudunflare(&global_recon_context,
                                         dns_chain,
                                         thread_pool,
                                         thread_count,
                                         NULL) != 0) {
        fprintf(stderr, "[RECON] Warning: Failed to integrate with CloudUnflare resources\n");
        return -1;
    }

    // Start reconnaissance subsystem
    if (RECON_START() != 0) {
        fprintf(stderr, "[RECON] Warning: Failed to start reconnaissance subsystem\n");
        return -1;
    }

    recon_integration_initialized = true;
    printf("[RECON] Reconnaissance modules initialized successfully\n");
    return 0;
}

// Cleanup reconnaissance modules during CloudUnflare shutdown
static inline void cloudunflare_cleanup_recon_modules(void) {
    if (!recon_integration_initialized) {
        return;
    }

    printf("[RECON] Shutting down reconnaissance modules...\n");
    RECON_STOP();
    recon_integration_cleanup(&global_recon_context);
    recon_integration_initialized = false;
    printf("[RECON] Reconnaissance modules shut down successfully\n");
}

// Check if reconnaissance features are available
static inline bool cloudunflare_has_recon_support(void) {
    return recon_integration_initialized && RECON_IS_READY();
}

// Performance monitoring wrapper
static inline void cloudunflare_check_recon_performance(void) {
    if (recon_integration_initialized) {
        RECON_PERFORMANCE_GUARD();
    }
}

// Add reconnaissance operations to CloudUnflare help output
static inline void cloudunflare_print_recon_help(void) {
    if (!RECON_MODULE_AVAILABLE) {
        return;
    }

    printf("\nReconnaissance Modules (Phase 1):\n");
    printf("  --dns-zone-transfer <domain>     Attempt DNS zone transfer (AXFR/IXFR)\n");
    printf("  --dns-bruteforce <domain>        Enhanced DNS brute-force enumeration\n");
    printf("  --http-banner <target:port>      HTTP/HTTPS banner grabbing\n");
    printf("  --port-scan <target> <ports>     Port scanning (TCP/UDP/SYN)\n");
    printf("\nReconnaissance Options:\n");
    printf("  --opsec-level <normal|high|max|ghost>  Set OPSEC paranoia level\n");
    printf("  --scan-mode <passive|active|stealth>   Set reconnaissance mode\n");
    printf("  --recon-threads <count>               Limit reconnaissance threads\n");
    printf("  --recon-timeout <seconds>             Set operation timeout\n");
    printf("  --recon-export <filename>             Export results to file\n");
}

// Enhanced argument parsing for reconnaissance options
static inline int cloudunflare_parse_recon_args(int argc, char *argv[], int *current_arg) {
    if (!RECON_MODULE_AVAILABLE) {
        return 0;
    }

    char *arg = argv[*current_arg];

    if (strcmp(arg, "--dns-zone-transfer") == 0) {
        if (*current_arg + 1 >= argc) {
            fprintf(stderr, "Error: --dns-zone-transfer requires a domain argument\n");
            return -1;
        }
        char *domain = argv[++(*current_arg)];

        char **records;
        uint32_t record_count;
        if (RECON_DNS_ZONE_TRANSFER(domain, &records, &record_count) == 0) {
            printf("[ZONE TRANSFER] Found %u records for %s:\n", record_count, domain);
            for (uint32_t i = 0; i < record_count; i++) {
                printf("  %s\n", records[i]);
                free(records[i]);
            }
            free(records);
        }
        return 1;
    }

    else if (strcmp(arg, "--dns-bruteforce") == 0) {
        if (*current_arg + 1 >= argc) {
            fprintf(stderr, "Error: --dns-bruteforce requires a domain argument\n");
            return -1;
        }
        char *domain = argv[++(*current_arg)];

        char **subdomains;
        uint32_t subdomain_count;
        if (RECON_DNS_BRUTEFORCE(domain, "wordlists/dns_subdomains.txt", &subdomains, &subdomain_count) == 0) {
            printf("[DNS BRUTEFORCE] Found %u subdomains for %s:\n", subdomain_count, domain);
            for (uint32_t i = 0; i < subdomain_count; i++) {
                printf("  %s\n", subdomains[i]);
                free(subdomains[i]);
            }
            free(subdomains);
        }
        return 1;
    }

    else if (strcmp(arg, "--http-banner") == 0) {
        if (*current_arg + 1 >= argc) {
            fprintf(stderr, "Error: --http-banner requires a target:port argument\n");
            return -1;
        }
        char *target_port = argv[++(*current_arg)];

        char *colon = strchr(target_port, ':');
        if (!colon) {
            fprintf(stderr, "Error: --http-banner requires target:port format\n");
            return -1;
        }

        *colon = '\0';
        char *target = target_port;
        uint16_t port = (uint16_t)atoi(colon + 1);

        char banner[1024];
        if (RECON_HTTP_BANNER(target, port, banner, sizeof(banner)) == 0) {
            printf("[HTTP BANNER] %s:%u:\n%s\n", target, port, banner);
        }
        return 1;
    }

    else if (strcmp(arg, "--port-scan") == 0) {
        if (*current_arg + 2 >= argc) {
            fprintf(stderr, "Error: --port-scan requires target and ports arguments\n");
            return -1;
        }
        char *target = argv[++(*current_arg)];
        char *ports_str = argv[++(*current_arg)];

        // Parse ports (simple implementation for common ports)
        uint16_t ports[] = {21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995};
        uint32_t port_count = sizeof(ports) / sizeof(ports[0]);
        bool *open_ports = calloc(port_count, sizeof(bool));

        if (RECON_PORT_SCAN(target, ports, port_count, open_ports) == 0) {
            printf("[PORT SCAN] Open ports on %s:\n", target);
            for (uint32_t i = 0; i < port_count; i++) {
                if (open_ports[i]) {
                    printf("  %u/tcp\n", ports[i]);
                }
            }
        }
        free(open_ports);
        return 1;
    }

    else if (strcmp(arg, "--opsec-level") == 0) {
        if (*current_arg + 1 >= argc) {
            fprintf(stderr, "Error: --opsec-level requires a level argument\n");
            return -1;
        }
        char *level_str = argv[++(*current_arg)];

        opsec_paranoia_level_t level;
        if (strcmp(level_str, "normal") == 0) {
            level = OPSEC_PARANOIA_NORMAL;
        } else if (strcmp(level_str, "high") == 0) {
            level = OPSEC_PARANOIA_HIGH;
        } else if (strcmp(level_str, "max") == 0) {
            level = OPSEC_PARANOIA_MAXIMUM;
        } else if (strcmp(level_str, "ghost") == 0) {
            level = OPSEC_PARANOIA_GHOST;
        } else {
            fprintf(stderr, "Error: Invalid OPSEC level: %s\n", level_str);
            return -1;
        }

        recon_get_simple_api()->set_opsec_level(level);
        printf("[OPSEC] Set paranoia level to %s\n", level_str);
        return 1;
    }

    else if (strcmp(arg, "--scan-mode") == 0) {
        if (*current_arg + 1 >= argc) {
            fprintf(stderr, "Error: --scan-mode requires a mode argument\n");
            return -1;
        }
        char *mode_str = argv[++(*current_arg)];

        recon_mode_t mode;
        if (strcmp(mode_str, "passive") == 0) {
            mode = RECON_MODE_PASSIVE;
        } else if (strcmp(mode_str, "active") == 0) {
            mode = RECON_MODE_ACTIVE;
        } else if (strcmp(mode_str, "stealth") == 0) {
            mode = RECON_MODE_STEALTH;
        } else {
            fprintf(stderr, "Error: Invalid scan mode: %s\n", mode_str);
            return -1;
        }

        recon_get_simple_api()->set_scan_mode(mode);
        printf("[SCAN MODE] Set to %s\n", mode_str);
        return 1;
    }

    else if (strcmp(arg, "--recon-threads") == 0) {
        if (*current_arg + 1 >= argc) {
            fprintf(stderr, "Error: --recon-threads requires a count argument\n");
            return -1;
        }
        uint32_t thread_count = (uint32_t)atoi(argv[++(*current_arg)]);

        recon_get_simple_api()->set_thread_limit(thread_count);
        printf("[THREADS] Limited reconnaissance to %u threads\n", thread_count);
        return 1;
    }

    else if (strcmp(arg, "--recon-export") == 0) {
        if (*current_arg + 1 >= argc) {
            fprintf(stderr, "Error: --recon-export requires a filename argument\n");
            return -1;
        }
        char *filename = argv[++(*current_arg)];

        if (recon_export_results(&global_recon_context, filename, "json") == 0) {
            printf("[EXPORT] Results exported to %s\n", filename);
        }
        return 1;
    }

    return 0; // Not a reconnaissance argument
}

// Integration status for main application
static inline void cloudunflare_print_recon_status(void) {
    if (!RECON_MODULE_AVAILABLE) {
        printf("Reconnaissance modules: Not compiled\n");
        return;
    }

    if (!recon_integration_initialized) {
        printf("Reconnaissance modules: Not initialized\n");
        return;
    }

    recon_integration_status_t status = recon_get_integration_status(&global_recon_context);
    printf("Reconnaissance modules: %s\n", recon_integration_status_to_string(status));

    if (status == RECON_INTEGRATION_ACTIVE) {
        char *metrics_json;
        if (recon_get_simple_api()->get_performance_metrics(&metrics_json) == 0) {
            printf("Performance metrics: %s\n", metrics_json);
            free(metrics_json);
        }
    }
}

#else
// Stub implementations when reconnaissance modules are disabled

static inline int cloudunflare_init_recon_modules(void *dns_chain, void *thread_pool, uint32_t thread_count) {
    return 0;
}

static inline void cloudunflare_cleanup_recon_modules(void) {
    // No-op
}

static inline bool cloudunflare_has_recon_support(void) {
    return false;
}

static inline void cloudunflare_check_recon_performance(void) {
    // No-op
}

static inline void cloudunflare_print_recon_help(void) {
    // No-op
}

static inline int cloudunflare_parse_recon_args(int argc, char *argv[], int *current_arg) {
    return 0;
}

static inline void cloudunflare_print_recon_status(void) {
    printf("Reconnaissance modules: Disabled at compile time\n");
}

#endif // RECON_MODULES_ENABLED

#endif // CLOUDUNFLARE_INTEGRATION_PATCH_H