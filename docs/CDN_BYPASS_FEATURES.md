# CloudClear - Comprehensive CDN Bypass & Passive Intelligence Gathering

## Overview

CloudClear has been enhanced with comprehensive CDN bypass techniques and passive intelligence gathering capabilities, integrating cutting-edge reconnaissance modules for origin IP discovery.

## New Modules Implemented

### 1. CVE-2025 Detector (`src/modules/recon/cve_2025_detector/`)

Detects and analyzes 2025-era CVEs relevant to CDN bypass and infrastructure discovery.

**Key Features:**
- CDN origin IP exposure vulnerability detection
- DNS cache poisoning identification (CVE-2025-XXXX series)
- SSL/TLS certificate validation bypass detection
- HTTP/2 and HTTP/3 implementation flaw analysis
- Cloud metadata service exploit detection
- Built-in CVE database with threat intelligence

**Usage:**
```c
cve_detection_context_t ctx;
cve_detection_init_context(&ctx);
cve_detection_check_cdn_origin_leak(&ctx, target, "Cloudflare");
cve_detection_print_results(&ctx);
```

### 2. Advanced Reconnaissance Module (`src/modules/recon/advanced_recon/`)

Comprehensive CDN bypass and passive intelligence gathering mega-module combining all advanced techniques.

#### SSL Certificate Enumeration & Correlation
- SSL certificate chain analysis
- Subject Alternative Name (SAN) extraction
- Certificate fingerprinting and correlation
- Issuer and subject matching across IPs
- Origin IP discovery via certificate matching

#### IPv6 Range Scanning
- IPv6 address discovery for domains
- IPv6 prefix scanning
- Dual-stack analysis for CDN bypass

#### DNS Cache Snooping
- Cache timing attacks
- Non-recursive DNS queries
- Nameserver cache analysis

#### Passive DNS Monitoring
- Historical DNS record analysis
- IP address timeline tracking
- Origin IP candidate identification

#### Regional Accessibility Testing
- Multi-region DNS resolution testing
- Geographic access pattern analysis
- CDN edge server mapping

#### Web Application Fingerprinting
- Framework detection (React, Angular, Vue, Django, Rails, etc.)
- CMS identification (WordPress, Drupal, Joomla, Magento, Shopify, etc.)
- JavaScript library enumeration with vulnerability detection
- Technology stack mapping
- API type detection (REST, GraphQL, SOAP)

#### API Endpoint Discovery
- Common API path enumeration
- GraphQL introspection detection
- Swagger/OpenAPI documentation discovery
- Endpoint brute-forcing with intelligent patterns

#### Directory Brute-forcing
- Web directory enumeration
- Extension-based scanning
- Recursive directory traversal
- Authentication detection

#### Email Server Enumeration
- MX record discovery and analysis
- SMTP server testing and banner grabbing
- SPF, DMARC, DKIM record extraction
- Mail server infrastructure mapping

#### Document Metadata Analysis
- PDF, DOCX, XLSX metadata extraction
- Author, creator, company information discovery
- Internal path and username extraction
- Email address and internal IP leakage detection

#### Historical DNS Records Analysis
- DNS record timeline construction
- Origin IP candidate discovery from historical data
- Infrastructure change tracking

## CDN Bypass Techniques Summary

CloudClear now implements the following CDN bypass methods:

1. **SSL Certificate Comparison** - Direct IP testing with cert fingerprint matching
2. **Advanced MX Record Enumeration** - Mail server infrastructure correlation
3. **Expanded SRV Record Discovery** - 15+ service type enumeration
4. **Cloudflare-Specific Bypass** - Origin IP discovery techniques
5. **IP Block/ASN Clustering** - Network infrastructure correlation
6. **Enhanced Reverse DNS (PTR)** - Intelligence gathering via PTR records
7. **Passive DNS Integration** - Historical IP data analysis
8. **WHOIS Netblock Discovery** - IP ownership chain analysis
9. **HTTP Header Analysis** - Origin server header detection
10. **Subdomain SSL Certificate SNI Testing** - Certificate correlation
11. **IPv6 Range Scanning** - Dual-stack bypass techniques
12. **DNS Cache Snooping** - Timing-based cache analysis
13. **Regional DNS Testing** - Geographic resolution differences
14. **Historical DNS Analysis** - Time-series IP discovery

## Passive Intelligence Gathering

### SSL Certificate Monitoring
- Real-time certificate enumeration
- Certificate Transparency log mining
- Fingerprint correlation across IP ranges

### Passive DNS Records
- Multi-source passive DNS aggregation
- Historical record correlation
- Timeline-based analysis

### Email Server Enumeration
- MX record discovery with priority analysis
- SMTP banner grabbing
- Email infrastructure mapping

### Document Metadata Analysis
- Automated document discovery on websites
- Metadata extraction and aggregation
- Intelligence leakage detection

## Integration with DSLLVM Toolchain

CloudClear now supports compilation with the DSLLVM hardened compiler toolchain:

```bash
# Build with DSLLVM
make USE_DSLLVM=1

# Build with standard GCC
make
```

**DSLLVM Features:**
- Post-quantum cryptography readiness
- Hardware-backed security (TPM 2.0)
- DSMIL-grade security annotations
- Side-channel protection

## Build Instructions

### Dependencies

```bash
sudo apt-get install -y \
    libcurl4-openssl-dev \
    libssl-dev \
    libjson-c-dev \
    libncurses-dev \
    build-essential
```

### Compilation

```bash
# Standard build
make

# With reconnaissance modules
make recon

# With interactive TUI
make tui

# With enhanced TUI
make tui-enhanced
```

### Using Modules

All new modules are enabled when compiling with `RECON_MODULES_ENABLED`:

```bash
make recon
./cloudclear-recon
```

## Module Integration

The new modules integrate seamlessly with the existing CloudClear infrastructure:

```c
#ifdef RECON_MODULES_ENABLED
#include "recon/cve_2025_detector/cve_2025_detector.h"
#include "recon/advanced_recon/advanced_recon.h"

// Initialize advanced reconnaissance
advanced_recon_context_t recon_ctx;
advanced_recon_init(&recon_ctx);
advanced_recon_scan_target(&recon_ctx, "example.com");
advanced_recon_print_summary(&recon_ctx);
advanced_recon_cleanup(&recon_ctx);
#endif
```

## Configuration

New configuration options in `include/config.h`:

```c
// CVE Detection
#define CVE_2025_DB_VERSION "2025.01"
#define CVE_2025_MAX_CVES 500

// Advanced Reconnaissance Features
#define FEATURE_SSL_CERT_ENUM 1
#define FEATURE_IPV6_SCANNING 1
#define FEATURE_DNS_CACHE_SNOOP 1
#define FEATURE_PASSIVE_DNS 1
#define FEATURE_REGIONAL_ACCESS_TEST 1
#define FEATURE_WEB_FINGERPRINT 1
#define FEATURE_API_DISCOVERY 1
#define FEATURE_DIR_BRUTEFORCE 1
#define FEATURE_EMAIL_ENUM 1
#define FEATURE_METADATA_ANALYSIS 1
#define FEATURE_HISTORICAL_DNS 1
```

## Security Considerations

All new modules implement OPSEC-compliant reconnaissance:

- Adaptive timing delays
- Proxy rotation support
- User-agent randomization
- Rate limiting
- Detection avoidance
- Thread-safe operations

## API Integration

The modules can be accessed via the API server:

```bash
# Start API server
cd api && python server.py

# Use advanced reconnaissance
curl -X POST http://localhost:8080/api/v1/advanced-recon \
     -H "Content-Type: application/json" \
     -d '{"domain": "example.com"}'
```

## Performance

- Multi-threaded execution (up to 50 concurrent threads)
- Optimized memory management
- Lock-free data structures where applicable
- SIMD optimizations
- CPU affinity pinning

## Future Enhancements

Planned additions:
- Machine learning-based origin IP prediction
- Blockchain domain resolution
- Decentralized DNS analysis
- Advanced traffic fingerprinting
- Deep packet inspection capabilities

## License

This project is for authorized security testing and research only. Unauthorized use against systems you do not own or have permission to test is illegal.

## Credits

Developed by the SWORD Intelligence team with contributions from various security research agents.
