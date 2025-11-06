# Quick Start Guide

## 🚀 Get CloudUnflare Enhanced Running in 5 Minutes

This guide will get you from zero to running CloudUnflare Enhanced with all advanced features in just 5 minutes.

## ⚡ One-Command Installation

### Ubuntu/Debian
```bash
# Single command installation
curl -fsSL https://raw.githubusercontent.com/SWORDIntel/claude-backups/main/CloudUnflare/install.sh | bash

# Or step-by-step:
sudo apt-get update && sudo apt-get install -y git build-essential libcurl4-openssl-dev libssl-dev libjson-c-dev
git clone https://github.com/SWORDIntel/claude-backups.git
cd claude-backups/CloudUnflare && make && sudo make install
```

### macOS
```bash
# Install Homebrew dependencies
brew install curl openssl json-c

# Clone and build
git clone https://github.com/SWORDIntel/claude-backups.git
cd claude-backups/CloudUnflare && make && sudo make install
```

## ✅ Verify Installation

```bash
# Check version and features
cloudunflare --version

# Run test suite to verify all features
cloudunflare --test
```

Expected output:
```
CloudUnflare Enhanced v2.0
✓ Enhanced DNS resolution engine
✓ DoQ/DoH/DoT protocol support
✓ Dual-stack IPv4/IPv6 resolution
✓ IP enrichment and geolocation
✓ CDN detection capabilities
✓ OPSEC protections active
```

## 🎯 First Reconnaissance

### Basic Domain Scan
```bash
# Interactive mode
cloudunflare

# When prompted, enter target domain:
# >> example.com
```

### Command Line Mode
```bash
# Direct domain specification
echo "example.com" | cloudunflare

# With enhanced verbosity
echo "example.com" | cloudunflare --verbose
```

## 📊 Expected Output

```
       __
    __(  )_       CLOUDFLARE
 __(       )_   RECONNAISSANCE
(____________)__ _  V 2.0-Enhanced
 _   _ _ __  / _| | __ _ _ __ ___
| | | | `_ \| |_| |/ _` | `__/ _ \
| |_| | | | |  _| | (_| | | |  __/
 \__,_|_| |_|_| |_|\__,_|_|  \___|

Enhanced with RESEARCHER + NSA capabilities
Features: Multi-threaded, OPSEC-hardened, AI-enhanced

[INIT] Target domain: example.com
[OPSEC] Initializing enhanced reconnaissance session
[DNS] 10 resolvers available with intelligent fallback

=== Phase 1: Enhanced DNS Reconnaissance ===
   [+] example.com -> 93.184.216.34 (Mountain View, US, AS15133 [HOSTING])
   [+] example.com -> 2606:2800:220:1:248:1893:25c8:1946 [IPv6]

=== Phase 2: Certificate Transparency Mining ===
 [CT] Mining certificate transparency logs for example.com
   [+] Found 15 certificate entries
   [+] CT subdomain: www.example.com
   [+] CT subdomain: mail.example.com

=== Phase 3: Multi-threaded Subdomain Enumeration ===
 [ENUM] Starting subdomain enumeration with 10 threads
 [T1] Found subdomain: www.example.com
 [T3] Found subdomain: mail.example.com
 [ENUM] Subdomain enumeration completed

=== Phase 4: OSINT Intelligence Gathering ===
 [OSINT] Querying ViewDNS.info for IP history
   [+] IP history data found
 [CDN] No CDN detected for example.com

=== Enhanced Reconnaissance Summary ===
 Target: example.com
 IP addresses discovered: 2 (IPv4: 1, IPv6: 1)
 Subdomains discovered: 3
 DNS results with enrichment: 1
 Detection score: 0.10
 OPSEC status: ACTIVE

=== Detailed DNS Analysis ===
Domain: example.com
Resolution Time: 245 ms
Protocol Used: DoQ
Resolver Used: dns.cloudflare.com
Confidence Score: 0.95

IPv4 Addresses (1):
  93.184.216.34 (Mountain View, US, AS15133)

IPv6 Addresses (1):
  2606:2800:220:1:248:1893:25c8:1946

[OPSEC] Enhanced reconnaissance completed, performing secure cleanup
```

## 🔧 Quick Configuration

### Performance Tuning
```bash
# High-performance mode (more aggressive)
export CLOUDUNFLARE_THREADS=25
export CLOUDUNFLARE_TIMEOUT=5
cloudunflare

# Stealth mode (slower, more evasive)
export CLOUDUNFLARE_STEALTH=true
export CLOUDUNFLARE_DELAY=3000
cloudunflare
```

### Protocol Selection
```bash
# Force specific DNS protocol
export CLOUDUNFLARE_PROTOCOL=doq    # DNS over QUIC (fastest)
export CLOUDUNFLARE_PROTOCOL=doh    # DNS over HTTPS
export CLOUDUNFLARE_PROTOCOL=dot    # DNS over TLS
export CLOUDUNFLARE_PROTOCOL=udp    # Traditional UDP
```

## 🎯 Common Use Cases

### 1. CloudFlare Bypass Discovery
```bash
# Target CloudFlare-protected domain
echo "protected-site.com" | cloudunflare

# Look for:
# - Origin IP addresses in certificate transparency logs
# - Subdomains not behind CloudFlare
# - Historical DNS records
# - Direct IP access possibilities
```

### 2. Attack Surface Enumeration
```bash
# Comprehensive subdomain discovery
echo "target-company.com" | cloudunflare --comprehensive

# Review output for:
# - Development/staging subdomains
# - Admin interfaces
# - API endpoints
# - Mail servers
```

### 3. Infrastructure Analysis
```bash
# Analyze hosting infrastructure
echo "target.com" | cloudunflare --infrastructure

# Examine results for:
# - Hosting providers and data centers
# - CDN usage and configuration
# - IPv6 adoption
# - Geographic distribution
```

## 🛡️ OPSEC Considerations

### Stealth Operation
```bash
# Maximum stealth with rate limiting
export CLOUDUNFLARE_STEALTH=true
export CLOUDUNFLARE_RATE_LIMIT=1000  # 1 second between requests
export CLOUDUNFLARE_USER_AGENT_ROTATION=true
cloudunflare
```

### Proxy Usage
```bash
# Route through Tor (requires tor service)
export CLOUDUNFLARE_PROXY="socks5://127.0.0.1:9050"
cloudunflare

# HTTP proxy
export CLOUDUNFLARE_PROXY="http://proxy.example.com:8080"
cloudunflare
```

## 🔍 Interpreting Results

### DNS Resolution Analysis
- **Protocol Used**: Shows which DNS protocol provided the best performance
- **Resolution Time**: Total time for complete resolution with enrichment
- **Confidence Score**: Data reliability (0.0-1.0, higher is better)

### IP Enrichment Data
- **Geolocation**: City, country for infrastructure analysis
- **ASN Information**: Autonomous System Number and provider
- **Hosting Detection**: Whether IP belongs to hosting provider
- **Threat Classification**: Malicious IP reputation data

### CDN Detection Results
- **CDN Provider**: Identified content delivery network
- **Bypass Possible**: Whether origin discovery techniques may work
- **Bypass Techniques**: Recommended methods for origin discovery

## ⚠️ Legal and Ethical Guidelines

### ✅ Authorized Use Cases
- **Personal domains**: Your own infrastructure
- **Authorized testing**: With written permission
- **Academic research**: Educational purposes
- **Defensive analysis**: Blue team activities

### ❌ Prohibited Activities
- **Unauthorized scanning**: Third-party systems without permission
- **Rate limit abuse**: Overwhelming target services
- **Malicious intent**: Using results for attacks
- **Terms of service violations**: Ignoring API limits

## 🆘 Quick Troubleshooting

### Installation Issues
```bash
# Check dependencies
make check

# Install missing dependencies
make deps

# Rebuild completely
make clean && make
```

### Runtime Issues
```bash
# Enable debug mode
make debug
./cloudunflare --debug

# Test network connectivity
curl -I https://crt.sh/
dig google.com

# Check permissions
ls -la cloudunflare
```

### Performance Issues
```bash
# Reduce thread count
export CLOUDUNFLARE_THREADS=5

# Increase timeouts
export CLOUDUNFLARE_TIMEOUT=30

# Monitor resource usage
top -p $(pgrep cloudunflare)
```

## 📈 Next Steps

After successful basic operation:

1. **[Advanced Techniques](../guides/advanced-techniques.md)** - Professional workflows
2. **[Configuration Guide](../guides/configuration.md)** - Customize behavior
3. **[OPSEC Best Practices](../guides/opsec-best-practices.md)** - Operational security
4. **[Performance Tuning](../guides/performance-tuning.md)** - Optimize for scale

## 🔗 Quick Links

- **[Full Documentation](../README.md)** - Complete documentation index
- **[API Reference](../api/)** - Developer documentation
- **[Troubleshooting](../troubleshooting/)** - Problem solving guides
- **[GitHub Issues](https://github.com/SWORDIntel/claude-backups/issues)** - Report bugs

---

*🚀 You're now ready to perform advanced DNS reconnaissance with nation-state level capabilities!*