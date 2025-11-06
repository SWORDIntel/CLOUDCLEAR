# CloudClear

<div align="center">

![CloudClear](docs/cloudunflare.png)

**Advanced DNS Reconnaissance & Origin Discovery Platform**

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)](docker/)
[![Version](https://img.shields.io/badge/version-2.0-orange.svg)](CHANGELOG.md)

*Penetrate CDN obfuscation. Discover true origin IPs. Master DNS intelligence.*

[Quick Start](#-quick-start-docker-recommended) • [Features](#-core-capabilities) • [Documentation](docs/) • [Examples](#-usage-examples)

</div>

---

## 🎯 What is CloudClear?

CloudClear is a **next-generation DNS reconnaissance and origin discovery platform** designed for security professionals, penetration testers, and red team operators. It goes far beyond basic DNS lookups to reveal the infrastructure hidden behind content delivery networks (CDNs) like Cloudflare, Akamai, and CloudFront.

### Why CloudClear?

When targets hide behind CDNs, traditional reconnaissance fails. CloudClear employs **advanced correlation techniques**, **multi-vector intelligence gathering**, and **OPSEC-hardened scanning** to unmask real infrastructure:

- **Origin IP Discovery**: Find true servers behind CDN protection using SSL certificate matching, historical DNS records, direct connect probing, and subdomain correlation
- **Advanced DNS Intelligence**: Leverage DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), DNS-over-QUIC (DoQ), and traditional protocols with intelligent fallback
- **Multi-Vector Analysis**: Combine MX records, SRV discovery, PTR analysis, ASN clustering, and SSL/TLS fingerprinting for comprehensive intelligence
- **Subdomain Enumeration**: Powerful brute-force and permutation engine with OPSEC-compliant rate limiting
- **Zone Transfer Exploitation**: Automated AXFR/IXFR testing against misconfigured nameservers
- **HTTP Banner Grabbing**: Deep SSL/TLS analysis, technology fingerprinting, and vulnerability indicators
- **Port Intelligence**: Fast, stealthy port scanning with service detection

## 🚀 Core Capabilities

### Origin IP Detection & CDN Bypass

CloudClear's flagship feature uses multiple correlation techniques to discover origin IPs:

```
✓ SSL Certificate Subject Alternative Name (SAN) matching
✓ Historical DNS record analysis
✓ Direct IP connection testing with host header manipulation
✓ Subdomain correlation and clustering
✓ MX record server identification
✓ SRV record service discovery
✓ Reverse PTR analysis
✓ ASN and BGP route analysis
✓ IPv4 + IPv6 dual-stack discovery
```

**Success Rate**: 60-80% on properly configured CDNs, 95%+ on misconfigured infrastructure

### Modern DNS Protocol Support

- **DNS-over-HTTPS (DoH)**: Cloudflare, Google, Quad9 providers with custom server support
- **DNS-over-TLS (DoT)**: Encrypted DNS with certificate validation
- **DNS-over-QUIC (DoQ)**: Next-gen protocol for enhanced privacy and performance
- **Traditional DNS**: UDP/TCP with EDNS0 support and intelligent fallback
- **IPv6 Support**: Full dual-stack resolution for modern infrastructure

### Reconnaissance Modules

#### 1. DNS Zone Transfer
- Automated AXFR/IXFR testing
- Nameserver discovery and validation
- Zone data parsing and analysis
- Misconfiguration detection

#### 2. Subdomain Brute-Force
- Multi-threaded enumeration (1000+ queries/sec)
- Smart wordlist management
- Permutation generation
- Rate limiting and backoff
- Result validation and deduplication

#### 3. HTTP Banner Grabbing
- SSL/TLS certificate analysis
- Technology stack fingerprinting
- HTTP header intelligence
- Redirect chain following
- Response time analysis
- Vulnerability indicators

#### 3.1. WAF Evasion & Origin Verification (NEW!)
- **Automatic WAF Detection**: Fingerprint 10+ major WAF vendors (Cloudflare, Akamai, AWS WAF, Imperva, etc.)
- **IP Spoofing Headers**: 10+ header types (X-Forwarded-For, X-Real-IP, CF-Connecting-IP, etc.)
- **Chunked Transfer Encoding**: Fragment requests to evade signature matching
- **HTTP Parameter Pollution**: Duplicate parameters to confuse WAF parsers
- **Header Case Mutation**: 5 mutation strategies to bypass case-sensitive filters
- **Encoding Variations**: URL, double, Unicode, and hex encoding
- **Adaptive Evasion**: Auto-configure based on detected WAF type
- **Three-Tier Presets**: Light (stealth), Moderate (balanced), Aggressive (maximum bypass)
- **Success Tracking**: Real-time bypass rate monitoring and statistics
- **OPSEC Integration**: Seamless integration with existing paranoia levels

**Effectiveness**: 70-95% bypass rate depending on WAF type and configuration

See [WAF Evasion Documentation](docs/WAF_EVASION.md) for complete details.

#### 4. Port Scanning
- TCP SYN/Connect scanning
- UDP service discovery
- Common service ports
- Custom port ranges
- Service version detection

### OPSEC & Stealth Features

Designed for real-world penetration testing where detection matters:

- **Traffic Randomization**: Timing jitter, request spacing, pattern obfuscation
- **User-Agent Rotation**: Realistic browser simulation
- **Rate Limiting**: Configurable QPS limits to avoid detection
- **Proxy Support**: SOCKS5/HTTP proxy rotation
- **Circuit Breaking**: Automatic pause on rate limit detection
- **Secure Memory**: Protected credential storage and automatic cleanup
- **DNS Fingerprint Evasion**: Protocol switching and query distribution

### Performance

- **Multi-threaded Architecture**: 50-100 concurrent workers
- **Lock-free Queues**: Minimal contention for maximum throughput
- **Memory Pooling**: Efficient allocation for sustained operations
- **SIMD Optimizations**: Vectorized string operations
- **10,000+ DNS queries per second** (hardware dependent)
- **Sub-500MB memory footprint**

### Interactive TUI

Beautiful ncurses-based interface for real-time operation monitoring:

**Standard TUI:**
- Live progress tracking
- Interactive results browser
- Detailed evidence viewer
- Statistics dashboard
- Phase tracking
- Candidate scoring

**Enhanced TUI (NEW!):**
- ✨ Modern Unicode box-drawing characters
- 🎨 Vibrant color scheme with gradient effects
- 📊 Enhanced progress bars with visual feedback
- 🏅 Medal ranking for top 3 candidates
- ⚡ Animated status indicators
- 💎 Polished professional design

See [Enhanced TUI Guide](docs/TUI_ENHANCED.md) for details

## 📦 Quick Start (Docker Recommended)

### Option 1: Docker Compose (Recommended)

```bash
# Clone repository
git clone https://github.com/SWORDIntel/CLOUDCLEAR.git
cd CLOUDCLEAR

# Start CloudClear with Docker Compose
cd docker && docker-compose up -d

# Run a scan
docker exec -it cloudclear-main /app/cloudclear -d example.com

# Enable reconnaissance modules
docker-compose --profile recon up -d
docker exec -it cloudclear-recon /app/cloudclear-recon -d example.com

# Use interactive TUI
docker-compose --profile interactive up cloudclear-tui
```

### Option 2: Docker Build

```bash
# Build image
cd docker && docker build -t cloudclear:latest -f Dockerfile ..

# Run CloudClear
docker run -it --rm \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  -v $(pwd)/results:/app/results \
  cloudclear:latest -d example.com
```

### Option 3: Native Build

```bash
# Install dependencies
make deps

# Build CloudClear
make

# Run
./cloudclear -d example.com

# Or build with TUI
make tui
./cloudclear-tui

# Or build with enhanced TUI (Unicode + modern UI)
make tui-enhanced
./cloudclear-tui-enhanced

# Or build with reconnaissance modules
make recon
./cloudclear-recon -d example.com
```

## 💡 Usage Examples

### Basic Origin IP Discovery

```bash
# Discover origin IPs behind CDN
./cloudclear -d example.com

# With verbose output
./cloudclear -d example.com -v

# Enable OPSEC mode with rate limiting
./cloudclear -d example.com --opsec --rate-limit 100
```

### Advanced Reconnaissance

```bash
# Full reconnaissance with all modules
./cloudclear-recon -d example.com --all-modules

# Subdomain enumeration with custom wordlist
./cloudclear-recon -d example.com --subdomain-brute --wordlist /path/to/list.txt

# Zone transfer attempts
./cloudclear-recon -d example.com --zone-transfer

# HTTP banner grabbing on discovered IPs
./cloudclear-recon -d example.com --http-banners

# Port scanning on candidate IPs
./cloudclear-recon -d example.com --port-scan --ports 80,443,8080,8443
```

### Modern DNS Protocols

```bash
# Use DNS-over-HTTPS
./cloudclear -d example.com --doh

# Use DNS-over-TLS
./cloudclear -d example.com --dot

# Use DNS-over-QUIC
./cloudclear -d example.com --doq

# Custom DoH server
./cloudclear -d example.com --doh --doh-server https://dns.custom.com/dns-query
```

### Performance Tuning

```bash
# High-performance mode (100 threads)
./cloudclear -d example.com --threads 100

# Memory-constrained environment
./cloudclear -d example.com --threads 25 --mem-limit 256

# IPv6 discovery
./cloudclear -d example.com --ipv6

# Output to JSON
./cloudclear -d example.com --output json > results.json
```

### Docker Usage

```bash
# Basic scan
docker exec cloudclear-main /app/cloudclear -d example.com

# Interactive TUI
docker-compose --profile interactive up cloudclear-tui

# Full recon with all modules
docker exec cloudclear-recon /app/cloudclear-recon -d example.com --all-modules

# Access results
docker cp cloudclear-main:/app/results/example.com_results.json ./
```

## 🏗️ Architecture

```
CloudClear/
├── src/
│   ├── core/              # Core DNS and IP detection engine
│   ├── tui/               # Interactive terminal interface
│   └── modules/
│       ├── performance/   # Lock-free queues, memory pools, SIMD
│       └── recon/         # Reconnaissance modules (zone transfer, brute-force, etc.)
├── include/               # Header files
├── tests/                 # Test suite
├── scripts/               # Utility scripts
├── docker/                # Docker configuration
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── portainer-stack.yml
├── docs/                  # Documentation
├── data/                  # Runtime data
│   ├── config/           # Configuration files
│   └── wordlists/        # Enumeration wordlists
└── Makefile              # Build system
```

## 📚 Documentation

- **[Quick Start Guide](docs/QUICKSTART.md)** - Get up and running in 5 minutes
- **[Docker Deployment](docs/DOCKER.md)** - Complete Docker and Portainer guide
- **[TUI Guide](docs/TUI_GUIDE.md)** - Interactive interface documentation
- **[Enhanced TUI Guide](docs/TUI_ENHANCED.md)** - NEW! Modern UI with Unicode and polished design
- **[Advanced IP Detection](docs/ADVANCED_IP_DETECTION.md)** - Origin discovery techniques
- **[WAF Evasion Guide](docs/WAF_EVASION.md)** - NEW! Web Application Firewall bypass techniques
- **[WAF Research Summary](docs/IMPROVEMENTS_FROM_WAF_RESEARCH.md)** - Implementation details and effectiveness analysis
- **[API Documentation](docs/api/)** - Programmatic usage

## 🔒 Security & Ethics

### Legal Notice

**CloudClear is designed for authorized security testing only.** Users are responsible for:

- Obtaining proper authorization before testing any systems
- Complying with applicable laws and regulations
- Respecting rate limits and terms of service
- Following responsible disclosure practices

### Intended Use Cases

✅ **Authorized Activities:**
- Penetration testing with written authorization
- Bug bounty programs within scope
- Red team exercises
- Security research with permission
- Defensive security assessments
- CTF competitions

❌ **Prohibited Activities:**
- Unauthorized reconnaissance
- Denial of service attacks
- Detection evasion for malicious purposes
- Mass targeting without authorization
- Supply chain attacks

### OPSEC Best Practices

1. **Always obtain authorization** before testing
2. **Use OPSEC mode** for sensitive engagements
3. **Configure rate limiting** to avoid detection
4. **Use proxy rotation** for anonymity
5. **Clean up artifacts** after testing
6. **Document and report** findings responsibly

## 🛠️ Development

### Building from Source

```bash
# Check dependencies
make check

# Install dependencies (Debian/Ubuntu)
make deps

# Build variants
make              # Standard build
make tui          # Interactive TUI
make recon        # With recon modules
make test         # Run test suite

# Show structure
make structure

# Build Docker image
make docker
```

### System Requirements

- **OS**: Linux (Ubuntu 20.04+, Debian 10+, RHEL 8+)
- **CPU**: 2+ cores (4+ recommended)
- **RAM**: 512MB minimum (2GB+ recommended)
- **Disk**: 100MB + space for results
- **Network**: Internet connectivity for external DNS

### Dependencies

- `libcurl` - HTTP/HTTPS client
- `openssl` - SSL/TLS support
- `json-c` - JSON parsing
- `ncurses` - TUI (optional)
- `gcc` - Compiler (C11 support)

## 📄 License

CloudClear is released under the MIT License. See [LICENSE](LICENSE) for details.

## 🙏 Credits

Developed by the SWORD Intelligence team for the offensive security community.

Special thanks to the researchers and projects that inspired this work:
- CloudFlair, CloudFail, and other CDN bypass tools
- Sublist3r, Amass, and subdomain enumeration tools
- dnsx, massdns, and modern DNS tooling
- WAF bypass research community (Knockin-on-Heaven-s-Door, OWASP, PortSwigger)
- SQLMap tamper script methodologies

## 📞 Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/SWORDIntel/CLOUDCLEAR/issues)

---

<div align="center">

**CloudClear** - *Bring the light of day upon thee*

Made with ⚔️ by SWORD Intelligence

</div>
