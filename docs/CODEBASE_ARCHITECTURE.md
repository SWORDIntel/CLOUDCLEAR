# CloudClear (CloudUnflare) Codebase Architecture Analysis

## Executive Summary
CloudClear is an advanced DNS reconnaissance platform written in C with sophisticated capabilities for origin IP discovery behind CDNs. The project has a modular architecture designed for reconnaissance tasks with proper separation of concerns, OPSEC integration, and multi-threaded operations.

---

## 1. PROJECT STRUCTURE OVERVIEW

```
/home/user/CLOUDCLEAR/
├── src/
│   ├── core/                          # Core DNS and IP detection
│   │   ├── cloudunflare.c            # Main CLI application (entry point)
│   │   └── dns_enhanced.c            # Enhanced DNS resolution engine
│   ├── modules/
│   │   ├── performance/              # Performance optimizations
│   │   │   ├── cpu_affinity.c
│   │   │   ├── lockfree_queue.c
│   │   │   ├── memory_pool.c
│   │   │   ├── performance_monitor.c
│   │   │   ├── simd_utils.c
│   │   │   └── thread_pool_optimized.c
│   │   ├── recon/                    # Reconnaissance modules (Phase 1+)
│   │   │   ├── common/               # Shared module utilities
│   │   │   │   ├── recon_common.c/h
│   │   │   │   ├── recon_module_interface.h    # Module API contract
│   │   │   │   ├── recon_integration_manager.h # Module lifecycle
│   │   │   │   ├── recon_config_manager.h      # Configuration
│   │   │   │   ├── recon_result_aggregator.h   # Result handling
│   │   │   │   ├── recon_opsec.c/h             # OPSEC framework
│   │   │   │   └── recon_proxy.c               # Proxy management
│   │   │   ├── dns_zone_transfer/   # AXFR/IXFR exploitation
│   │   │   │   ├── dns_zone_transfer.c/h
│   │   │   │   └── dns_zone_transfer_enhanced.c
│   │   │   ├── dns_bruteforce/      # Subdomain enumeration
│   │   │   │   ├── dns_bruteforce.c/h
│   │   │   │   └── dns_bruteforce_enhanced.c/h
│   │   │   ├── http_banner/         # HTTP/HTTPS banner grabbing
│   │   │   │   ├── http_banner.c/h
│   │   │   │   ├── http_banner_advanced.c
│   │   │   │   ├── http_waf_evasion.c/h
│   │   │   │   └── http_banner_waf_integration.c
│   │   │   ├── port_scanner/        # TCP/UDP port scanning
│   │   │   │   └── port_scanner.c/h
│   │   │   ├── recon_integration.h  # Master integration header
│   │   │   └── cloudunflare_integration_patch.h
│   │   ├── advanced_ip_detection.c/h # CDN bypass techniques
│   └── tui/                          # Terminal User Interface
│       ├── cloudunflare_tui_main.c  # TUI entry point
│       ├── cloudclear_tui.c          # Standard TUI
│       └── cloudclear_tui_enhanced.c # Enhanced TUI with Unicode
├── include/                          # Header files
│   ├── config.h                      # Configuration constants
│   ├── dns_enhanced.h
│   ├── advanced_ip_detection.h
│   └── cloudclear_tui.h
├── tests/                            # Test suite
├── data/                             # Runtime data
│   ├── config/
│   └── wordlists/
├── docs/                             # Documentation
├── docker/                           # Docker configuration
├── Makefile                          # Build system
└── README.md
```

---

## 2. CURRENT ENDPOINTS/MODULES ARCHITECTURE

The codebase uses a **module-based architecture** rather than traditional HTTP endpoints. Each reconnaissance task is implemented as a self-contained module.

### Current Available Modules (Phase 1):

#### **A. DNS Zone Transfer Module**
- **Location**: `/home/user/CLOUDCLEAR/src/modules/recon/dns_zone_transfer/`
- **Files**: 
  - `dns_zone_transfer.h` (interface definition)
  - `dns_zone_transfer.c` (implementation)
  - `dns_zone_transfer_enhanced.c` (enhancements)
- **Capabilities**:
  - AXFR (Full zone transfer) exploitation
  - IXFR (Incremental zone transfer) exploitation
  - Nameserver discovery and validation
  - Zone record parsing and analysis
  - Multi-server attempts with fallback

#### **B. DNS Brute-Force Module**
- **Location**: `/home/user/CLOUDCLEAR/src/modules/recon/dns_bruteforce/`
- **Files**:
  - `dns_bruteforce.h` (interface)
  - `dns_bruteforce.c` (implementation)
  - `dns_bruteforce_enhanced.h/c` (enhancements)
- **Capabilities**:
  - Multi-threaded subdomain enumeration
  - Custom wordlist support
  - Wildcard detection
  - Permutation generation
  - Rate limiting and backoff

#### **C. HTTP Banner Grabbing Module**
- **Location**: `/home/user/CLOUDCLEAR/src/modules/recon/http_banner/`
- **Files**:
  - `http_banner.h` (interface)
  - `http_banner.c` (implementation)
  - `http_banner_advanced.c` (enhanced features)
  - `http_waf_evasion.h/c` (WAF bypass)
  - `http_banner_waf_integration.c` (WAF detection)
- **Capabilities**:
  - SSL/TLS certificate analysis
  - HTTP header extraction
  - Server fingerprinting (10+ WAF vendors)
  - Technology stack detection
  - Redirect chain following
  - 10+ WAF evasion techniques (IP spoofing, chunked encoding, HPP, etc.)

#### **D. Port Scanner Module**
- **Location**: `/home/user/CLOUDCLEAR/src/modules/recon/port_scanner/`
- **Files**:
  - `port_scanner.h` (interface)
  - `port_scanner.c` (implementation)
- **Capabilities**:
  - TCP SYN scanning
  - UDP service discovery
  - Service version detection
  - Common ports enumeration
  - Custom port ranges

### Core Modules (Not Reconnaissance):

#### **E. Advanced IP Detection**
- **Location**: `/home/user/CLOUDCLEAR/src/modules/advanced_ip_detection.c/h`
- **Purpose**: CDN bypass and origin IP discovery
- **Techniques**:
  - SSL certificate Subject Alternative Name (SAN) matching
  - Historical DNS record analysis
  - Direct IP connection testing with host header manipulation
  - Subdomain correlation and clustering
  - MX record server identification
  - SRV record service discovery
  - Reverse PTR analysis
  - ASN and BGP route analysis
  - IPv4 + IPv6 dual-stack discovery

#### **F. Enhanced DNS Engine**
- **Location**: `/home/user/CLOUDCLEAR/src/core/dns_enhanced.c/h`
- **Purpose**: Multi-protocol DNS resolution
- **Protocols**:
  - Traditional DNS (UDP/TCP)
  - DNS-over-HTTPS (DoH) - 20+ providers
  - DNS-over-TLS (DoT)
  - DNS-over-QUIC (DoQ)

---

## 3. MODULE DEFINITION & ORGANIZATION PATTERNS

### A. Module Interface Standard (Universal Contract)

All reconnaissance modules follow the **Unified Reconnaissance Module Interface** defined in:
**`/home/user/CLOUDCLEAR/src/modules/recon/common/recon_module_interface.h`**

#### Core Structures:

```c
// Module configuration (universal)
typedef struct {
    char name[64];                          // Module name
    char description[256];                  // Description
    char version[16];                       // Version
    uint32_t capabilities;                  // Capability flags
    module_priority_t priority;             // Resource priority
    uint32_t max_threads;                   // Thread limit
    uint32_t max_concurrent_operations;     // Operation limit
    uint32_t timeout_seconds;               // Operation timeout
    uint32_t max_retries;                   // Retry attempts
    uint32_t memory_limit_mb;               // Memory limit
    opsec_paranoia_level_t opsec_level;     // OPSEC level
    bool opsec_enabled;                     // OPSEC flag
    uint32_t min_delay_ms;                  // Min request delay
    uint32_t max_delay_ms;                  // Max request delay
    uint32_t max_requests_per_second;       // Rate limit
} recon_module_config_t;

// Module instance (universal)
typedef struct recon_module {
    recon_module_config_t config;           // Configuration
    module_state_t state;                   // Current state
    pthread_mutex_t state_mutex;            // State sync
    
    // Performance tracking
    module_performance_metrics_t metrics;   // Performance metrics
    module_resource_usage_t resources;      // Resource usage
    
    // Threading
    pthread_t *worker_threads;              // Thread pool
    uint32_t thread_count;                  // Thread count
    
    // Operation queue
    recon_module_operation_t **operation_queue;
    uint32_t queue_size;
    
    // Function pointers (implementation contract)
    int (*init)(struct recon_module *module);
    int (*execute_operation)(struct recon_module *module, 
                           recon_module_operation_t *operation, 
                           recon_result_t *result);
    int (*pause)(struct recon_module *module);
    int (*resume)(struct recon_module *module);
    int (*stop)(struct recon_module *module);
    void (*cleanup)(struct recon_module *module);
    int (*configure)(struct recon_module *module, 
                    const recon_module_config_t *config);
    int (*health_check)(struct recon_module *module);
    
    // Callbacks
    void (*on_result_ready)(struct recon_module *, recon_result_t *);
    void (*on_error)(struct recon_module *, const char *);
    void (*on_state_change)(struct recon_module *, module_state_t, module_state_t);
    
    void *private_data;                     // Module-specific data
} recon_module_t;
```

#### Module Capability Flags:

```c
MODULE_CAP_PASSIVE_SCAN           // Passive reconnaissance only
MODULE_CAP_ACTIVE_SCAN            // Active target interaction
MODULE_CAP_THREADED               // Multi-threading support
MODULE_CAP_OPSEC_COMPLIANT        // OPSEC framework integration
MODULE_CAP_REAL_TIME              // Real-time processing
MODULE_CAP_BULK_PROCESSING        // Batch operations
MODULE_CAP_ADAPTIVE_TIMING        // Adaptive delay support
MODULE_CAP_PROXY_AWARE            // Proxy chain support
MODULE_CAP_RATE_LIMITED           // Built-in rate limiting
MODULE_CAP_DNS_INTEGRATION        // DNS Enhanced integration
MODULE_CAP_RESULT_CORRELATION     // Cross-module result correlation
```

#### Module States:

```c
MODULE_STATE_UNINITIALIZED
MODULE_STATE_INITIALIZING
MODULE_STATE_READY
MODULE_STATE_RUNNING
MODULE_STATE_PAUSED
MODULE_STATE_STOPPING
MODULE_STATE_STOPPED
MODULE_STATE_ERROR
MODULE_STATE_EMERGENCY_HALT
```

### B. Module Implementation Pattern

Each module follows a consistent pattern:

1. **Header File** (`.h`): Define module-specific structures and functions
2. **Implementation File** (`.c`): Implement module-specific operations
3. **Integration**: Register with module registry and master integration

**Example: DNS Zone Transfer Module Structure**

```c
// dns_zone_transfer.h
typedef struct {
    recon_context_t base_ctx;
    zone_transfer_config_t config;
    zone_server_t servers[ZONE_TRANSFER_MAX_SERVERS];
    uint32_t server_count;
    zone_transfer_result_t *results;
    pthread_mutex_t results_mutex;
} zone_transfer_context_t;

// Function implementations
int zone_transfer_init_context(zone_transfer_context_t *ctx);
int zone_transfer_execute(zone_transfer_context_t *ctx, const char *domain);
void zone_transfer_cleanup_context(zone_transfer_context_t *ctx);
```

### C. Integration Framework

All modules integrate through the **Reconnaissance Integration Manager**:
- **File**: `/home/user/CLOUDCLEAR/src/modules/recon/recon_integration.h`
- **Provides**: Unified API, lifecycle management, performance isolation
- **Features**: 
  - Module registry and lifecycle management
  - Result aggregation across modules
  - OPSEC framework integration
  - Performance monitoring and protection

#### Master Integration Context:

```c
typedef struct {
    integration_manager_t integration_manager;
    config_manager_t config_manager;
    result_aggregator_t result_aggregator;
    module_registry_t module_registry;
    opsec_context_t opsec_context;
    
    recon_integration_status_t status;
    bool initialized;
    bool auto_start_enabled;
    bool performance_monitoring_enabled;
    
    struct dns_resolver_chain *shared_dns_chain;
    pthread_t *shared_thread_pool;
    // ... more fields
} recon_master_context_t;
```

#### Integration Macros (Convenience API):

```c
#define RECON_INIT(config_file)                    // Initialize
#define RECON_START()                              // Start modules
#define RECON_STOP()                               // Stop modules
#define RECON_IS_READY()                           // Check readiness
#define RECON_PERFORMANCE_GUARD()                  // Monitor performance
#define RECON_DNS_ZONE_TRANSFER(...)               // Call zone transfer
#define RECON_DNS_BRUTEFORCE(...)                  // Call brute force
#define RECON_HTTP_BANNER(...)                     // Call HTTP banner
#define RECON_PORT_SCAN(...)                       // Call port scan
```

---

## 4. WHERE TO ADD CLOUDFLARE RADAR SCAN SUPPORT

### A. Recommended Module Location

Create a new reconnaissance module following the existing pattern:

```
/home/user/CLOUDCLEAR/src/modules/recon/cloudflare_radar/
├── cloudflare_radar.h              # Module interface definition
├── cloudflare_radar.c              # Core implementation
├── cloudflare_radar_api.c/h         # Cloudflare Radar API client
├── cloudflare_radar_parser.c/h      # Response parsing
└── cloudflare_radar_integration.c   # CloudClear integration
```

### B. Integration Points

1. **Module Registration** (`recon_integration.h`):
   - Add module to registry in initialization
   - Register capability flags
   - Set OPSEC compliance flags

2. **Module Registry** (`recon_module_interface.h`):
   - Create module instance with standard interface
   - Implement all required function pointers
   - Integrate with thread pool and result aggregator

3. **Main Application** (`cloudunflare.c`):
   - Add module invocation in Phase 5 (Advanced Reconnaissance)
   - Call through macro: `RECON_CLOUDFLARE_RADAR(...)`

4. **Build System** (`Makefile`):
   - Add source files to `RECON_SOURCES`
   - Update compilation flags if needed

5. **Configuration** (`config.h`):
   - Define rate limits: `CLOUDFLARE_RADAR_RATE_LIMIT_MS`
   - Set timeouts: `CLOUDFLARE_RADAR_TIMEOUT`
   - Configure API endpoints

### C. Detailed Integration Strategy

#### Step 1: Create Module Header
File: `/home/user/CLOUDCLEAR/src/modules/recon/cloudflare_radar/cloudflare_radar.h`

```c
#ifndef CLOUDFLARE_RADAR_H
#define CLOUDFLARE_RADAR_H

#include "../common/recon_common.h"
#include "../../dns_enhanced.h"

// Module constants
#define CF_RADAR_BASE_URL "https://radar.cloudflare.com/api/v1"
#define CF_RADAR_TIMEOUT 30
#define CF_RADAR_MAX_RETRIES 3
#define CF_RADAR_RATE_LIMIT_MS 1000

// Data structures specific to Cloudflare Radar
typedef struct {
    char ip_address[INET6_ADDRSTRLEN];
    uint32_t asn;
    char organization[256];
    float threat_score;
    uint32_t last_seen_timestamp;
    bool is_datacenter;
    bool is_residential;
} cloudflare_radar_ip_result_t;

typedef struct {
    cloudflare_radar_ip_result_t *results;
    uint32_t result_count;
    char query_domain[MAX_DOMAIN_LEN];
    time_t timestamp;
} cloudflare_radar_response_t;

// Module functions
int cloudflare_radar_init();
int cloudflare_radar_query(const char *domain, cloudflare_radar_response_t *response);
void cloudflare_radar_cleanup();

#endif
```

#### Step 2: Implement Module
File: `/home/user/CLOUDCLEAR/src/modules/recon/cloudflare_radar/cloudflare_radar.c`

Implement:
- API client code (HTTP requests to Cloudflare Radar)
- Response parsing (JSON to result structures)
- OPSEC integration (rate limiting, proxy support)
- Error handling and retries
- Integration with module interface

#### Step 3: Register in Module Interface
Update `recon_integration.h` to:
- Add Cloudflare Radar to simple API:
  ```c
  int (*cloudflare_radar_scan)(const char *domain, cloudflare_radar_response_t *response);
  ```
- Add macro for convenience:
  ```c
  #define RECON_CLOUDFLARE_RADAR(domain, response) \
      recon_get_simple_api()->cloudflare_radar_scan(domain, response)
  ```

#### Step 4: Update Makefile
Add to `RECON_SOURCES`:
```makefile
RECON_RADAR_SOURCES = $(MODULES_DIR)/recon/cloudflare_radar/cloudflare_radar.c \
                      $(MODULES_DIR)/recon/cloudflare_radar/cloudflare_radar_api.c
```

#### Step 5: Update Configuration
Add to `config.h`:
```c
#define CLOUDFLARE_RADAR_API_URL "https://radar.cloudflare.com/api/v1"
#define CLOUDFLARE_RADAR_TIMEOUT 30
#define CLOUDFLARE_RADAR_RATE_LIMIT_MS 1000
#define CLOUDFLARE_RADAR_MAX_RETRIES 3
```

#### Step 6: Integrate with Main Application
Modify `cloudunflare.c` main function to include:
```c
#ifdef RECON_MODULES_ENABLED
    // Phase 5: Cloudflare Radar Scan (new)
    printf("\n=== Phase 5: Cloudflare Radar Intelligence ===\n");
    cloudflare_radar_response_t radar_response = {0};
    if (RECON_CLOUDFLARE_RADAR(domain, &radar_response) > 0) {
        // Process and display results
    }
#endif
```

---

## 5. FILES CONTAINING ENDPOINT/API LOGIC

### A. Core Application Entry Points

1. **Main CLI Application**
   - `/home/user/CLOUDCLEAR/src/core/cloudunflare.c` (lines 892-1013)
   - Entry point: `int main(int argc, char *argv[])`
   - Current flow: 6 phases of reconnaissance
   - Handles initialization, module invocation, and cleanup

2. **TUI Entry Point**
   - `/home/user/CLOUDCLEAR/src/tui/cloudunflare_tui_main.c` (lines 143-242)
   - Entry point: `int main_tui_mode(void)`
   - Manages interactive terminal interface
   - Handles screen transitions and user input

### B. Module-Related Files

1. **Module Interface Definition**
   - `/home/user/CLOUDCLEAR/src/modules/recon/common/recon_module_interface.h`
   - Defines universal module contract
   - All modules must implement these function pointers

2. **Integration Manager**
   - `/home/user/CLOUDCLEAR/src/modules/recon/recon_integration.h`
   - Master context and lifecycle management
   - Macro-based convenience API

3. **Module Registry**
   - `/home/user/CLOUDCLEAR/src/modules/recon/common/recon_module_interface.h` (lines 180-197)
   - Centralized module management
   - Module lifecycle control

### C. Module Implementation Examples

1. **DNS Zone Transfer Module**
   - Header: `/home/user/CLOUDCLEAR/src/modules/recon/dns_zone_transfer/dns_zone_transfer.h`
   - Implementation: `/home/user/CLOUDCLEAR/src/modules/recon/dns_zone_transfer/dns_zone_transfer.c`
   - Pattern reference for new modules

2. **HTTP Banner Module**
   - Header: `/home/user/CLOUDCLEAR/src/modules/recon/http_banner/http_banner.h`
   - Implementation: `/home/user/CLOUDCLEAR/src/modules/recon/http_banner/http_banner.c`
   - More complex example with WAF integration

### D. Configuration Files

1. **Build Configuration**
   - `/home/user/CLOUDCLEAR/Makefile`
   - Source file compilation
   - Build targets and dependencies

2. **Runtime Configuration**
   - `/home/user/CLOUDCLEAR/include/config.h` (lines 1-294)
   - API endpoints (lines 225-283)
   - DoH providers (lines 230-283)
   - Module feature flags (lines 107-124)
   - Rate limits and timeouts

3. **DNS Enhanced Configuration**
   - `/home/user/CLOUDCLEAR/include/dns_enhanced.h`
   - DNS protocol definitions
   - Resolver configuration

### E. Common Utilities

1. **OPSEC Framework**
   - `/home/user/CLOUDCLEAR/src/modules/recon/common/recon_opsec.h`
   - `/home/user/CLOUDCLEAR/src/modules/recon/common/recon_opsec.c`
   - Rate limiting, timing evasion, detection avoidance

2. **Result Aggregator**
   - `/home/user/CLOUDCLEAR/src/modules/recon/common/recon_result_aggregator.h`
   - Cross-module result collection and correlation

3. **Configuration Manager**
   - `/home/user/CLOUDCLEAR/src/modules/recon/common/recon_config_manager.h`
   - Dynamic module configuration

---

## 6. ARCHITECTURAL PATTERNS & DESIGN PRINCIPLES

### A. Modular Design

- **Loose Coupling**: Modules interact through standardized interfaces
- **High Cohesion**: Each module handles a single reconnaissance task
- **Encapsulation**: Private module data and implementation details hidden
- **Extensibility**: New modules can be added without modifying core code

### B. Thread Safety

- **Atomic Operations**: `_Atomic` types for lock-free updates
- **Mutex Protection**: Critical sections protected with pthread mutexes
- **Thread Pools**: Shared thread pool with workload distribution
- **Queue-Based Communication**: Lock-free queues for inter-thread communication

### C. OPSEC Integration

- **Paranoia Levels**: 5 levels of operational security (SILENT to AGGRESSIVE)
- **Rate Limiting**: Configurable requests per second
- **Timing Evasion**: Jitter and randomization
- **Proxy Support**: Proxy chain rotation
- **Detection Avoidance**: Automatic detection response

### D. Performance Optimization

- **Lock-Free Queues**: Minimize contention
- **Memory Pooling**: Pre-allocated memory for efficiency
- **SIMD Optimizations**: Vectorized operations
- **CPU Affinity**: Thread pinning for cache efficiency
- **Adaptive Timing**: Dynamic delay adjustment

### E. Error Handling

- **Return Codes**: Standard C function return patterns
- **Cleanup Handlers**: Signal handlers for graceful shutdown
- **Resource Management**: Automatic cleanup of allocated resources
- **Emergency Halt**: Capability to pause operations on detection

---

## 7. COMPILATION & BUILD FLOW

### Available Build Targets

```makefile
make                  # Standard build (core only)
make tui              # Build with interactive TUI
make tui-enhanced     # Build with enhanced TUI (Unicode + polished UI)
make recon            # Build with reconnaissance modules
make test             # Run test suite
make docker           # Build Docker image
```

### Build Flags

- `RECON_MODULES_ENABLED`: Enables reconnaissance module compilation
- `THREAD_SAFE_BUILD`: Enables thread safety features
- Standard C11 with GNU extensions (`-D_GNU_SOURCE`)

### Compilation Dependencies

```c
Libraries:
- libcurl             (HTTP/HTTPS client)
- openssl             (SSL/TLS support)
- json-c              (JSON parsing)
- pthread             (Thread support)
- ncurses             (TUI, optional)
- resolv              (DNS resolution)
- atomic              (Atomic operations)
```

---

## 8. SUMMARY TABLE: Current Endpoints/Modules

| Module | Location | Status | Type | Key Features |
|--------|----------|--------|------|--------------|
| DNS Zone Transfer | `dns_zone_transfer/` | Complete | Active | AXFR/IXFR, nameserver discovery |
| DNS Brute-Force | `dns_bruteforce/` | Complete | Active | Multi-threaded, custom wordlists |
| HTTP Banner | `http_banner/` | Complete | Active | SSL analysis, WAF detection/evasion |
| Port Scanner | `port_scanner/` | Complete | Active | TCP/UDP scanning, service detection |
| Advanced IP Detection | `modules/advanced_ip_detection.c` | Complete | Core | CDN bypass, origin IP discovery |
| DNS Enhanced | `core/dns_enhanced.c` | Complete | Core | DoH/DoT/DoQ, multi-provider |
| **Cloudflare Radar** | `cloudflare_radar/` | **PLANNED** | **Reconnaissance** | **Threat intelligence integration** |

---

## 9. IMPLEMENTATION RECOMMENDATIONS FOR CLOUDFLARE RADAR

### Phase 1: Module Creation
1. Create module directory structure
2. Implement API client for Cloudflare Radar
3. Define data structures and return types
4. Implement core query logic

### Phase 2: Integration
1. Implement module interface functions
2. Add OPSEC integration
3. Register with module registry
4. Add to build system

### Phase 3: Testing
1. Unit tests for API client
2. Integration tests with main application
3. Performance benchmarking
4. OPSEC compliance validation

### Phase 4: Documentation
1. Module README with examples
2. API documentation
3. Integration guide
4. Configuration options

---

## 10. KEY FILES FOR REFERENCE

**Essential Files for Adding Cloudflare Radar:**

1. `/home/user/CLOUDCLEAR/src/modules/recon/dns_zone_transfer/` - Complete example module
2. `/home/user/CLOUDCLEAR/src/modules/recon/common/recon_module_interface.h` - Module contract
3. `/home/user/CLOUDCLEAR/src/modules/recon/recon_integration.h` - Integration framework
4. `/home/user/CLOUDCLEAR/Makefile` - Build system
5. `/home/user/CLOUDCLEAR/include/config.h` - Configuration constants
6. `/home/user/CLOUDCLEAR/src/core/cloudunflare.c` - Main application flow

