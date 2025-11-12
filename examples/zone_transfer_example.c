/*
 * CloudUnflare Enhanced - DNS Zone Transfer Example
 *
 * Comprehensive example demonstrating DNS Zone Transfer functionality
 * Shows AXFR/IXFR usage with OPSEC compliance and performance features
 */

#include "recon_modules/dns_zone_transfer/dns_zone_transfer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

void print_banner(void) {
    printf("CloudUnflare Enhanced v2.0 - DNS Zone Transfer Module\n");
    printf("====================================================\n");
    printf("AXFR/IXFR zone transfer with OPSEC compliance\n");
    printf("Designed for reconnaissance and security testing\n\n");
}

void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS] <domain>\n\n", program_name);
    printf("Options:\n");
    printf("  -t, --type <type>        Transfer type: axfr, ixfr, auto (default: auto)\n");
    printf("  -s, --server <server>    Name server to query (default: auto-discover)\n");
    printf("  -p, --port <port>        Server port (default: 53)\n");
    printf("  -T, --timeout <seconds>  Query timeout (default: 60)\n");
    printf("  -r, --retries <count>    Max retry attempts (default: 3)\n");
    printf("  -d, --delay <ms>         Delay between attempts (default: 2000)\n");
    printf("  -a, --all-servers        Try all discovered servers\n");
    printf("  -S, --stealth            Enable stealth mode (slower, harder to detect)\n");
    printf("  -v, --verbose            Verbose output\n");
    printf("  -j, --json <file>        Export results to JSON\n");
    printf("  -c, --csv <file>         Export results to CSV\n");
    printf("  -h, --help               Show this help message\n\n");
    printf("Examples:\n");
    printf("  %s example.com                    # Auto-discover and attempt zone transfer\n", program_name);
    printf("  %s -t axfr -s ns1.example.com example.com  # AXFR from specific server\n", program_name);
    printf("  %s -S -d 5000 example.com         # Stealth mode with 5s delays\n", program_name);
    printf("  %s -j results.json example.com    # Export results to JSON\n", program_name);
}

zone_transfer_type_t parse_transfer_type(const char *type_str) {
    if (!type_str) return ZONE_TRANSFER_AUTO;

    if (strcasecmp(type_str, "axfr") == 0) {
        return ZONE_TRANSFER_AXFR;
    } else if (strcasecmp(type_str, "ixfr") == 0) {
        return ZONE_TRANSFER_IXFR;
    } else if (strcasecmp(type_str, "auto") == 0) {
        return ZONE_TRANSFER_AUTO;
    }

    return ZONE_TRANSFER_AUTO;
}

int main(int argc, char *argv[]) {
    // Configuration variables
    char *domain = NULL;
    char *server = NULL;
    char *json_file = NULL;
    char *csv_file = NULL;
    zone_transfer_type_t transfer_type = ZONE_TRANSFER_AUTO;
    uint16_t port = 53;
    uint32_t timeout = 60;
    uint32_t retries = 3;
    uint32_t delay = 2000;
    bool all_servers = false;
    bool stealth_mode = false;
    bool verbose = false;

    // Parse command line options
    static struct option long_options[] = {
        {"type", required_argument, 0, 't'},
        {"server", required_argument, 0, 's'},
        {"port", required_argument, 0, 'p'},
        {"timeout", required_argument, 0, 'T'},
        {"retries", required_argument, 0, 'r'},
        {"delay", required_argument, 0, 'd'},
        {"all-servers", no_argument, 0, 'a'},
        {"stealth", no_argument, 0, 'S'},
        {"verbose", no_argument, 0, 'v'},
        {"json", required_argument, 0, 'j'},
        {"csv", required_argument, 0, 'c'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int option_index = 0;
    int c;

    while ((c = getopt_long(argc, argv, "t:s:p:T:r:d:aSvj:c:h", long_options, &option_index)) != -1) {
        switch (c) {
            case 't':
                transfer_type = parse_transfer_type(optarg);
                break;
            case 's':
                server = strdup(optarg);
                break;
            case 'p':
                port = (uint16_t)atoi(optarg);
                break;
            case 'T':
                timeout = (uint32_t)atoi(optarg);
                break;
            case 'r':
                retries = (uint32_t)atoi(optarg);
                break;
            case 'd':
                delay = (uint32_t)atoi(optarg);
                break;
            case 'a':
                all_servers = true;
                break;
            case 'S':
                stealth_mode = true;
                break;
            case 'v':
                verbose = true;
                break;
            case 'j':
                json_file = strdup(optarg);
                break;
            case 'c':
                csv_file = strdup(optarg);
                break;
            case 'h':
                print_banner();
                print_usage(argv[0]);
                return 0;
            case '?':
                print_usage(argv[0]);
                return 1;
            default:
                break;
        }
    }

    // Check for domain argument
    if (optind >= argc) {
        fprintf(stderr, "Error: Domain name required\n\n");
        print_usage(argv[0]);
        return 1;
    }

    domain = argv[optind];

    print_banner();

    if (verbose) {
        printf("Configuration:\n");
        printf("  Domain: %s\n", domain);
        printf("  Transfer Type: %s\n", zone_transfer_type_to_string(transfer_type));
        if (server) printf("  Server: %s:%u\n", server, port);
        printf("  Timeout: %u seconds\n", timeout);
        printf("  Retries: %u\n", retries);
        printf("  Delay: %u ms\n", delay);
        printf("  All Servers: %s\n", all_servers ? "Yes" : "No");
        printf("  Stealth Mode: %s\n", stealth_mode ? "Yes" : "No");
        printf("\n");
    }

    // Initialize zone transfer context
    zone_transfer_context_t ctx;
    if (zone_transfer_init_context(&ctx) != 0) {
        fprintf(stderr, "Error: Failed to initialize zone transfer context\n");
        return 1;
    }

    // Configure zone transfer settings
    zone_transfer_config_t config = {
        .preferred_type = transfer_type,
        .timeout_seconds = timeout,
        .max_retries = retries,
        .delay_between_attempts_ms = delay,
        .try_all_servers = all_servers,
        .extract_subdomains = true,
        .validate_records = true,
        .opsec = {
            .min_delay_ms = stealth_mode ? delay * 2 : delay / 2,
            .max_delay_ms = stealth_mode ? delay * 4 : delay * 2,
            .jitter_ms = stealth_mode ? delay : delay / 2,
            .max_requests_per_session = stealth_mode ? 5 : 20
        }
    };

    if (zone_transfer_set_config(&ctx, &config) != 0) {
        fprintf(stderr, "Error: Failed to set zone transfer configuration\n");
        zone_transfer_cleanup_context(&ctx);
        return 1;
    }

    // Add specific server if provided
    if (server) {
        printf("Adding specified name server: %s:%u\n", server, port);
        if (zone_transfer_add_server(&ctx, server, port) != 0) {
            fprintf(stderr, "Warning: Failed to add specified server\n");
        }
    }

    printf("Starting zone transfer for domain: %s\n", domain);
    printf("========================================\n\n");

    // Execute zone transfer
    clock_t start_time = clock();
    int result = zone_transfer_execute(&ctx, domain);
    clock_t end_time = clock();

    double execution_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

    printf("\nZone transfer execution completed in %.2f seconds\n", execution_time);
    printf("Results: %u zone transfer attempts\n", ctx.result_count);

    if (result > 0) {
        printf("✓ Successfully completed %d zone transfer(s)\n", result);
    } else {
        printf("✗ No successful zone transfers completed\n");
        if (ctx.result_count > 0) {
            printf("  Check individual transfer results below for details\n");
        } else {
            printf("  Common causes:\n");
            printf("  - Zone transfers disabled on target servers\n");
            printf("  - Access restrictions (IP-based filtering)\n");
            printf("  - Firewall blocking TCP port 53\n");
            printf("  - Domain does not exist or has no authoritative servers\n");
        }
    }

    // Print detailed results
    if (ctx.result_count > 0) {
        printf("\n");
        zone_transfer_print_results(&ctx);

        // Extract and display subdomains if any records were found
        for (uint32_t i = 0; i < ctx.result_count; i++) {
            const zone_transfer_result_t *transfer_result = &ctx.results[i];
            if (transfer_result->status == ZONE_STATUS_SUCCESS && transfer_result->record_count > 0) {
                char **subdomains = NULL;
                uint32_t subdomain_count = 0;

                if (zone_transfer_extract_subdomains(transfer_result->records,
                                                   transfer_result->record_count,
                                                   &subdomains, &subdomain_count) == 0) {
                    if (subdomain_count > 0) {
                        printf("Extracted Subdomains for %s:\n", transfer_result->zone_name);
                        for (uint32_t j = 0; j < subdomain_count; j++) {
                            printf("  %s\n", subdomains[j]);
                            free(subdomains[j]);
                        }
                        free(subdomains);
                        printf("\n");
                    }
                }
            }
        }
    }

    // Export results if requested
    if (json_file && ctx.result_count > 0) {
        printf("Exporting results to JSON: %s\n", json_file);
        if (zone_transfer_export_json(&ctx, json_file) == 0) {
            printf("✓ JSON export completed successfully\n");
        } else {
            fprintf(stderr, "✗ JSON export failed\n");
        }
    }

    if (csv_file && ctx.result_count > 0) {
        printf("Exporting results to CSV: %s\n", csv_file);
        if (zone_transfer_export_csv(&ctx, csv_file) == 0) {
            printf("✓ CSV export completed successfully\n");
        } else {
            fprintf(stderr, "✗ CSV export failed\n");
        }
    }

    // Performance summary
    if (verbose && ctx.result_count > 0) {
        printf("\nPerformance Summary:\n");
        printf("  Total Execution Time: %.2f seconds\n", execution_time);
        printf("  Average Time per Transfer: %.2f seconds\n", execution_time / ctx.result_count);

        uint32_t total_records = 0;
        uint32_t successful_transfers = 0;
        for (uint32_t i = 0; i < ctx.result_count; i++) {
            if (ctx.results[i].status == ZONE_STATUS_SUCCESS) {
                total_records += ctx.results[i].record_count;
                successful_transfers++;
            }
        }

        if (successful_transfers > 0) {
            printf("  Total Records Transferred: %u\n", total_records);
            printf("  Average Records per Transfer: %.1f\n", (float)total_records / successful_transfers);
            printf("  Estimated Query Rate: %.1f queries/second\n",
                   total_records / execution_time);
        }
    }

    // Cleanup
    zone_transfer_cleanup_context(&ctx);

    if (server) free(server);
    if (json_file) free(json_file);
    if (csv_file) free(csv_file);

    printf("\nZone transfer analysis completed.\n");

    return (result > 0) ? 0 : 1;
}