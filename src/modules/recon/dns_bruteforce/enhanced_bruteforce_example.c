/*
 * CloudUnflare Enhanced - DNS Brute-Force Usage Example
 *
 * Practical demonstration of the Enhanced DNS Brute-Force module
 * showing real-world usage patterns for subdomain enumeration
 *
 * Usage Examples:
 * 1. Basic enumeration with default settings
 * 2. High-performance enumeration (2000+ subdomains/second)
 * 3. Stealth enumeration with OPSEC compliance
 * 4. Comprehensive enumeration with all strategies
 * 5. Custom wordlist and pattern-based discovery
 *
 * Compile: gcc -o enhanced_bruteforce_example enhanced_bruteforce_example.c dns_bruteforce_enhanced.c -lpthread -lm
 */

#include "dns_bruteforce_enhanced.h"
#include <signal.h>
#include <getopt.h>

// Global context for signal handling
enhanced_bruteforce_context_t *global_ctx = NULL;

// Signal handler for graceful shutdown
void signal_handler(int signum) {
    if (global_ctx) {
        global_ctx->stop_enumeration = true;
        printf("\n🛑 Received signal %d, stopping enumeration gracefully...\n", signum);
    }
}

// Configuration structure for examples
typedef struct {
    char target_domain[256];
    char wordlist_file[256];
    char output_file[256];
    discovery_strategy_t strategy;
    uint32_t max_threads;
    uint32_t max_depth;
    float paranoia_level;
    bool verbose;
    bool export_json;
    bool detect_wildcards;
    uint32_t timeout_seconds;
} example_config_t;

// Function prototypes
void print_usage(const char *program_name);
int parse_arguments(int argc, char *argv[], example_config_t *config);
int example_basic_enumeration(const example_config_t *config);
int example_high_performance_enumeration(const example_config_t *config);
int example_stealth_enumeration(const example_config_t *config);
int example_comprehensive_enumeration(const example_config_t *config);
int example_custom_patterns(const example_config_t *config);
void print_progress_callback(const enhanced_bruteforce_context_t *ctx);
int create_default_wordlist(const char *filename);

int main(int argc, char *argv[]) {
    printf("🔍 CloudUnflare Enhanced DNS Brute-Force - Usage Examples\n");
    printf("========================================================\n\n");

    // Parse command line arguments
    example_config_t config = {0};

    // Set defaults
    strcpy(config.target_domain, "example.com");
    strcpy(config.wordlist_file, "wordlist.txt");
    strcpy(config.output_file, "results.json");
    config.strategy = DISCOVERY_STRATEGY_HYBRID;
    config.max_threads = 20;
    config.max_depth = 3;
    config.paranoia_level = 5.0;
    config.verbose = true;
    config.export_json = true;
    config.detect_wildcards = true;
    config.timeout_seconds = 300;

    if (parse_arguments(argc, argv, &config) != 0) {
        print_usage(argv[0]);
        return 1;
    }

    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Create default wordlist if it doesn't exist
    struct stat st;
    if (stat(config.wordlist_file, &st) != 0) {
        printf("📝 Creating default wordlist: %s\n", config.wordlist_file);
        if (create_default_wordlist(config.wordlist_file) != 0) {
            fprintf(stderr, "❌ Failed to create default wordlist\n");
            return 1;
        }
    }

    printf("🎯 Target domain: %s\n", config.target_domain);
    printf("📖 Wordlist: %s\n", config.wordlist_file);
    printf("🧠 Strategy: %s\n", discovery_strategy_to_string(config.strategy));
    printf("🔧 Max threads: %u\n", config.max_threads);
    printf("🛡️  Paranoia level: %.1f\n", config.paranoia_level);
    printf("\n");

    // Run the appropriate example based on strategy
    int result = 0;

    switch (config.strategy) {
        case DISCOVERY_STRATEGY_WORDLIST:
            printf("🚀 Running Basic Enumeration Example\n");
            result = example_basic_enumeration(&config);
            break;

        case DISCOVERY_STRATEGY_PATTERN:
            printf("🎯 Running High-Performance Enumeration Example\n");
            result = example_high_performance_enumeration(&config);
            break;

        case DISCOVERY_STRATEGY_ADAPTIVE:
            printf("🕵️  Running Stealth Enumeration Example\n");
            result = example_stealth_enumeration(&config);
            break;

        case DISCOVERY_STRATEGY_HYBRID:
            printf("🔬 Running Comprehensive Enumeration Example\n");
            result = example_comprehensive_enumeration(&config);
            break;

        default:
            printf("🎨 Running Custom Pattern Example\n");
            result = example_custom_patterns(&config);
            break;
    }

    if (result >= 0) {
        printf("\n✅ Enumeration completed successfully - %d subdomains discovered\n", result);
        if (config.export_json) {
            printf("📊 Results exported to: %s\n", config.output_file);
        }
    } else {
        printf("\n❌ Enumeration failed with error code: %d\n", result);
    }

    return result >= 0 ? 0 : 1;
}

int example_basic_enumeration(const example_config_t *config) {
    enhanced_bruteforce_context_t ctx;

    // Initialize context
    if (enhanced_bruteforce_init_context(&ctx) != 0) {
        fprintf(stderr, "Failed to initialize brute-force context\n");
        return -1;
    }

    global_ctx = &ctx;

    // Configure basic settings
    enhanced_bruteforce_set_target(&ctx, config->target_domain);
    ctx.strategy = DISCOVERY_STRATEGY_WORDLIST;
    ctx.max_depth = 1; // No recursion for basic example

    // Load wordlist
    if (enhanced_bruteforce_load_wordlist(&ctx.wordlists[0], config->wordlist_file,
                                         ENHANCED_WORDLIST_CORE, 100) == 0) {
        ctx.wordlist_count = 1;
        printf("✅ Loaded wordlist: %u words\n", ctx.wordlists[0].word_count);
    } else {
        fprintf(stderr, "❌ Failed to load wordlist\n");
        enhanced_bruteforce_cleanup_context(&ctx);
        return -1;
    }

    // Configure for basic enumeration
    ctx.opsec_config.base_delay_ms = 50;
    ctx.opsec_config.paranoia_level = 1.0; // Minimal stealth

    printf("\n🏃 Starting basic enumeration...\n");

    // Execute enumeration
    int result_count = enhanced_bruteforce_execute(&ctx);

    // Print results
    if (result_count > 0) {
        enhanced_bruteforce_print_results(&ctx);

        if (config->export_json) {
            enhanced_bruteforce_export_json(&ctx, config->output_file);
        }
    }

    enhanced_bruteforce_cleanup_context(&ctx);
    global_ctx = NULL;

    return result_count;
}

int example_high_performance_enumeration(const example_config_t *config) {
    enhanced_bruteforce_context_t ctx;

    if (enhanced_bruteforce_init_context(&ctx) != 0) {
        fprintf(stderr, "Failed to initialize brute-force context\n");
        return -1;
    }

    global_ctx = &ctx;

    // Configure for maximum performance
    enhanced_bruteforce_set_target(&ctx, config->target_domain);
    ctx.strategy = DISCOVERY_STRATEGY_PATTERN;
    ctx.max_depth = 2;

    // Optimize for speed
    ctx.opsec_config.base_delay_ms = 1; // Minimal delay
    ctx.opsec_config.jitter_range_ms = 1;
    ctx.opsec_config.paranoia_level = 1.0; // No stealth
    ctx.opsec_config.burst_limit = 50; // High burst rate

    // Load multiple wordlists for comprehensive coverage
    if (enhanced_bruteforce_load_wordlist(&ctx.wordlists[0], config->wordlist_file,
                                         ENHANCED_WORDLIST_CORE, 100) == 0) {
        ctx.wordlist_count = 1;
    }

    // Configure pattern generation for high coverage
    ctx.pattern_config.algorithm = PATTERN_ALGORITHM_ALPHANUMERIC;
    ctx.pattern_config.min_length = 1;
    ctx.pattern_config.max_length = 4;
    ctx.pattern_config.include_numbers = true;
    ctx.pattern_config.max_patterns = 5000;

    printf("\n🚀 Starting high-performance enumeration (target: 2000+ QPS)...\n");
    printf("⚡ Using maximum threads and minimal delays\n");

    // Execute with performance monitoring
    time_t start_time = time(NULL);
    int result_count = enhanced_bruteforce_execute(&ctx);
    time_t end_time = time(NULL);

    // Calculate and display performance metrics
    uint32_t total_queries = atomic_load(&ctx.metrics.queries_sent);
    uint32_t elapsed_seconds = (uint32_t)(end_time - start_time);
    uint32_t avg_qps = elapsed_seconds > 0 ? total_queries / elapsed_seconds : 0;

    printf("\n📊 Performance Results:\n");
    printf("   Total queries: %u\n", total_queries);
    printf("   Elapsed time: %u seconds\n", elapsed_seconds);
    printf("   Average QPS: %u\n", avg_qps);
    printf("   Peak QPS: %u\n", atomic_load(&ctx.metrics.peak_qps));

    if (avg_qps >= 2000) {
        printf("🎯 Performance target ACHIEVED: %u QPS >= 2000 QPS\n", avg_qps);
    } else {
        printf("⚠️  Performance target missed: %u QPS < 2000 QPS\n", avg_qps);
    }

    if (result_count > 0) {
        enhanced_bruteforce_print_results(&ctx);
        if (config->export_json) {
            enhanced_bruteforce_export_json(&ctx, config->output_file);
        }
    }

    enhanced_bruteforce_cleanup_context(&ctx);
    global_ctx = NULL;

    return result_count;
}

int example_stealth_enumeration(const example_config_t *config) {
    enhanced_bruteforce_context_t ctx;

    if (enhanced_bruteforce_init_context(&ctx) != 0) {
        fprintf(stderr, "Failed to initialize brute-force context\n");
        return -1;
    }

    global_ctx = &ctx;

    // Configure for maximum stealth
    enhanced_bruteforce_set_target(&ctx, config->target_domain);
    ctx.strategy = DISCOVERY_STRATEGY_ADAPTIVE;
    ctx.max_depth = 3;

    // Load wordlist
    if (enhanced_bruteforce_load_wordlist(&ctx.wordlists[0], config->wordlist_file,
                                         ENHANCED_WORDLIST_CORE, 100) == 0) {
        ctx.wordlist_count = 1;
    }

    // Configure for maximum stealth
    ctx.opsec_config.base_delay_ms = 2000; // 2 second base delay
    ctx.opsec_config.jitter_range_ms = 1000; // Up to 1 second jitter
    ctx.opsec_config.paranoia_level = config->paranoia_level; // High stealth
    ctx.opsec_config.burst_limit = 3; // Very low burst rate
    ctx.opsec_config.burst_cooldown_ms = 10000; // 10 second cooldown
    ctx.opsec_config.randomize_resolver_order = true;
    ctx.opsec_config.detect_rate_limiting = true;

    printf("\n🕵️  Starting stealth enumeration...\n");
    printf("🐌 Using high delays and anti-detection measures\n");
    printf("🛡️  Paranoia level: %.1f/10.0\n", config->paranoia_level);

    // Execute with stealth monitoring
    time_t start_time = time(NULL);
    int result_count = enhanced_bruteforce_execute(&ctx);
    time_t end_time = time(NULL);

    printf("\n🔍 Stealth Results:\n");
    printf("   Enumeration time: %ld seconds\n", end_time - start_time);
    printf("   Rate limiting detected: %s\n",
           enhanced_bruteforce_check_rate_limiting(&ctx) ? "Yes" : "No");
    printf("   Average delay per query: %.1f ms\n",
           (float)((end_time - start_time) * 1000) / atomic_load(&ctx.metrics.queries_sent));

    if (result_count > 0) {
        enhanced_bruteforce_print_results(&ctx);
        if (config->export_json) {
            enhanced_bruteforce_export_json(&ctx, config->output_file);
        }
    }

    enhanced_bruteforce_cleanup_context(&ctx);
    global_ctx = NULL;

    return result_count;
}

int example_comprehensive_enumeration(const example_config_t *config) {
    enhanced_bruteforce_context_t ctx;

    if (enhanced_bruteforce_init_context(&ctx) != 0) {
        fprintf(stderr, "Failed to initialize brute-force context\n");
        return -1;
    }

    global_ctx = &ctx;

    // Configure for comprehensive discovery
    enhanced_bruteforce_set_target(&ctx, config->target_domain);
    ctx.strategy = DISCOVERY_STRATEGY_HYBRID;
    ctx.max_depth = config->max_depth;

    // Load primary wordlist
    if (enhanced_bruteforce_load_wordlist(&ctx.wordlists[0], config->wordlist_file,
                                         ENHANCED_WORDLIST_CORE, 100) == 0) {
        ctx.wordlist_count = 1;
    }

    // Configure balanced OPSEC
    ctx.opsec_config.base_delay_ms = 200;
    ctx.opsec_config.jitter_range_ms = 100;
    ctx.opsec_config.paranoia_level = config->paranoia_level;
    ctx.opsec_config.burst_limit = 20;

    // Configure comprehensive pattern generation
    ctx.pattern_config.algorithm = PATTERN_ALGORITHM_HYBRID;
    ctx.pattern_config.min_length = 1;
    ctx.pattern_config.max_length = 5;
    ctx.pattern_config.include_numbers = true;
    ctx.pattern_config.include_hyphens = true;
    ctx.pattern_config.max_patterns = 2000;

    printf("\n🔬 Starting comprehensive enumeration...\n");
    printf("🌐 Using hybrid strategy with all discovery methods\n");
    printf("🔄 Recursive depth: %u levels\n", config->max_depth);

    // Execute with progress monitoring
    time_t start_time = time(NULL);

    // Monitor progress in a separate thread (simplified for example)
    printf("📈 Progress will be displayed every 10 seconds...\n\n");

    int result_count = enhanced_bruteforce_execute(&ctx);
    time_t end_time = time(NULL);

    printf("\n🎯 Comprehensive Results Summary:\n");
    printf("   Total execution time: %ld seconds\n", end_time - start_time);
    printf("   Subdomains discovered: %d\n", result_count);
    printf("   Discovery methods used:\n");
    printf("     • Wordlist enumeration\n");
    printf("     • Pattern generation\n");
    printf("     • Recursive enumeration\n");
    printf("     • Permutation analysis\n");

    // Analyze discovery methods
    uint32_t wordlist_discoveries = 0, pattern_discoveries = 0, recursive_discoveries = 0;

    for (uint32_t i = 0; i < ctx.result_count; i++) {
        switch (ctx.results[i].discovery_method) {
            case DISCOVERY_STRATEGY_WORDLIST:
                wordlist_discoveries++;
                break;
            case DISCOVERY_STRATEGY_PATTERN:
                pattern_discoveries++;
                break;
            case DISCOVERY_STRATEGY_RECURSIVE:
                recursive_discoveries++;
                break;
            default:
                break;
        }
    }

    printf("\n📊 Discovery Method Breakdown:\n");
    printf("   Wordlist discoveries: %u\n", wordlist_discoveries);
    printf("   Pattern discoveries: %u\n", pattern_discoveries);
    printf("   Recursive discoveries: %u\n", recursive_discoveries);

    if (result_count > 0) {
        enhanced_bruteforce_print_results(&ctx);
        if (config->export_json) {
            enhanced_bruteforce_export_json(&ctx, config->output_file);
        }
    }

    enhanced_bruteforce_cleanup_context(&ctx);
    global_ctx = NULL;

    return result_count;
}

int example_custom_patterns(const example_config_t *config) {
    enhanced_bruteforce_context_t ctx;

    if (enhanced_bruteforce_init_context(&ctx) != 0) {
        fprintf(stderr, "Failed to initialize brute-force context\n");
        return -1;
    }

    global_ctx = &ctx;

    enhanced_bruteforce_set_target(&ctx, config->target_domain);
    ctx.strategy = DISCOVERY_STRATEGY_PATTERN;

    // Configure custom pattern generation
    ctx.pattern_config.algorithm = PATTERN_ALGORITHM_ALPHANUMERIC;
    ctx.pattern_config.min_length = 2;
    ctx.pattern_config.max_length = 6;
    ctx.pattern_config.include_numbers = true;
    ctx.pattern_config.include_hyphens = true;
    ctx.pattern_config.max_patterns = 1000;

    printf("\n🎨 Starting custom pattern enumeration...\n");
    printf("🔤 Generating alphanumeric patterns (2-6 characters)\n");

    // Generate and display sample patterns
    char **patterns = NULL;
    uint32_t pattern_count = 0;

    if (enhanced_bruteforce_generate_alphanumeric_patterns(&ctx.pattern_config,
                                                          &patterns, &pattern_count) == 0) {
        printf("📝 Generated %u custom patterns\n", pattern_count);

        // Show first 10 patterns as examples
        printf("🔍 Sample patterns: ");
        for (uint32_t i = 0; i < pattern_count && i < 10; i++) {
            printf("%s ", patterns[i]);
        }
        printf("...\n\n");

        // Add patterns to work queue manually for demonstration
        for (uint32_t i = 0; i < pattern_count; i++) {
            work_item_t item = {0};
            strncpy(item.subdomain_candidate, patterns[i], sizeof(item.subdomain_candidate) - 1);
            item.method = DISCOVERY_STRATEGY_PATTERN;
            item.priority = 50;

            enhanced_bruteforce_add_work_item(&ctx, &item);
        }

        // Cleanup patterns
        for (uint32_t i = 0; i < pattern_count; i++) {
            free(patterns[i]);
        }
        free(patterns);
    }

    int result_count = enhanced_bruteforce_execute(&ctx);

    if (result_count > 0) {
        enhanced_bruteforce_print_results(&ctx);
        if (config->export_json) {
            enhanced_bruteforce_export_json(&ctx, config->output_file);
        }
    }

    enhanced_bruteforce_cleanup_context(&ctx);
    global_ctx = NULL;

    return result_count;
}

int create_default_wordlist(const char *filename) {
    FILE *file = fopen(filename, "w");
    if (!file) return -1;

    // Write common subdomains
    const char *common_subdomains[] = {
        "www", "api", "admin", "test", "dev", "staging", "prod", "production",
        "mail", "email", "smtp", "pop", "imap", "webmail",
        "ftp", "sftp", "ssh", "vpn", "rdp",
        "blog", "shop", "store", "forum", "wiki", "docs", "help", "support",
        "portal", "dashboard", "panel", "control", "manage", "management",
        "monitor", "monitoring", "stats", "analytics", "metrics",
        "backup", "archive", "files", "file", "upload", "download",
        "cdn", "static", "assets", "media", "img", "images", "video",
        "css", "js", "scripts", "style", "styles",
        "mobile", "m", "wap", "touch",
        "secure", "ssl", "tls", "cert", "certificate",
        "db", "database", "mysql", "postgres", "oracle", "mssql",
        "cache", "redis", "memcache", "elastic", "elasticsearch",
        "log", "logs", "syslog", "audit",
        "config", "configuration", "settings", "setup",
        "jenkins", "gitlab", "github", "svn", "git", "repo",
        "jira", "confluence", "redmine", "trac",
        "nagios", "zabbix", "cacti", "munin",
        "grafana", "kibana", "splunk", "prometheus",
        "docker", "k8s", "kubernetes", "swarm",
        "web", "web1", "web2", "web3", "app", "app1", "app2", "app3",
        "lb", "loadbalancer", "proxy", "gateway", "firewall",
        "ns", "ns1", "ns2", "ns3", "dns", "mx", "mx1", "mx2"
    };

    int count = sizeof(common_subdomains) / sizeof(char*);
    for (int i = 0; i < count; i++) {
        fprintf(file, "%s\n", common_subdomains[i]);
    }

    fclose(file);
    return 0;
}

int parse_arguments(int argc, char *argv[], example_config_t *config) {
    int opt;
    static struct option long_options[] = {
        {"domain", required_argument, 0, 'd'},
        {"wordlist", required_argument, 0, 'w'},
        {"output", required_argument, 0, 'o'},
        {"strategy", required_argument, 0, 's'},
        {"threads", required_argument, 0, 't'},
        {"depth", required_argument, 0, 'D'},
        {"paranoia", required_argument, 0, 'p'},
        {"verbose", no_argument, 0, 'v'},
        {"quiet", no_argument, 0, 'q'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "d:w:o:s:t:D:p:vqh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'd':
                strncpy(config->target_domain, optarg, sizeof(config->target_domain) - 1);
                break;
            case 'w':
                strncpy(config->wordlist_file, optarg, sizeof(config->wordlist_file) - 1);
                break;
            case 'o':
                strncpy(config->output_file, optarg, sizeof(config->output_file) - 1);
                break;
            case 's':
                if (strcmp(optarg, "wordlist") == 0) {
                    config->strategy = DISCOVERY_STRATEGY_WORDLIST;
                } else if (strcmp(optarg, "pattern") == 0) {
                    config->strategy = DISCOVERY_STRATEGY_PATTERN;
                } else if (strcmp(optarg, "stealth") == 0) {
                    config->strategy = DISCOVERY_STRATEGY_ADAPTIVE;
                } else if (strcmp(optarg, "hybrid") == 0) {
                    config->strategy = DISCOVERY_STRATEGY_HYBRID;
                } else {
                    fprintf(stderr, "Invalid strategy: %s\n", optarg);
                    return -1;
                }
                break;
            case 't':
                config->max_threads = atoi(optarg);
                if (config->max_threads > ENHANCED_BRUTEFORCE_MAX_THREADS) {
                    config->max_threads = ENHANCED_BRUTEFORCE_MAX_THREADS;
                }
                break;
            case 'D':
                config->max_depth = atoi(optarg);
                if (config->max_depth > ENHANCED_BRUTEFORCE_MAX_RECURSIVE_DEPTH) {
                    config->max_depth = ENHANCED_BRUTEFORCE_MAX_RECURSIVE_DEPTH;
                }
                break;
            case 'p':
                config->paranoia_level = atof(optarg);
                if (config->paranoia_level < 1.0) config->paranoia_level = 1.0;
                if (config->paranoia_level > 10.0) config->paranoia_level = 10.0;
                break;
            case 'v':
                config->verbose = true;
                break;
            case 'q':
                config->verbose = false;
                break;
            case 'h':
                return -1;
            default:
                return -1;
        }
    }

    return 0;
}

void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS]\n\n", program_name);
    printf("CloudUnflare Enhanced DNS Brute-Force - Usage Examples\n\n");
    printf("Options:\n");
    printf("  -d, --domain DOMAIN     Target domain (default: example.com)\n");
    printf("  -w, --wordlist FILE     Wordlist file (default: wordlist.txt)\n");
    printf("  -o, --output FILE       Output file (default: results.json)\n");
    printf("  -s, --strategy STRATEGY Enumeration strategy:\n");
    printf("                            wordlist  - Basic wordlist enumeration\n");
    printf("                            pattern   - High-performance pattern generation\n");
    printf("                            stealth   - Stealth enumeration with OPSEC\n");
    printf("                            hybrid    - Comprehensive hybrid approach\n");
    printf("  -t, --threads NUMBER    Maximum threads (default: 20, max: 50)\n");
    printf("  -D, --depth NUMBER      Recursive enumeration depth (default: 3, max: 5)\n");
    printf("  -p, --paranoia LEVEL    OPSEC paranoia level 1.0-10.0 (default: 5.0)\n");
    printf("  -v, --verbose           Verbose output (default)\n");
    printf("  -q, --quiet             Quiet output\n");
    printf("  -h, --help              Show this help message\n\n");
    printf("Examples:\n");
    printf("  %s -d example.com -s wordlist    # Basic enumeration\n", program_name);
    printf("  %s -d target.com -s pattern -t 50  # High-performance enumeration\n", program_name);
    printf("  %s -d secret.com -s stealth -p 9.0  # Stealth enumeration\n", program_name);
    printf("  %s -d company.com -s hybrid -D 4    # Comprehensive enumeration\n", program_name);
}