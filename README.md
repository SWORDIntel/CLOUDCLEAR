# CloudClear

> **Advanced Cloud Provider Detection & Intelligence Platform**
>
> Detect and analyze 20+ cloud service providers, CDNs, WAFs, and intelligence services

[![Version](https://img.shields.io/badge/version-2.0--Enhanced--Cloud-blue.svg)](https://github.com/SWORDIntel/CLOUDCLEAR)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

---

## 🚀 One-Command Installation

```bash
./install.sh
```

**That's it!** The automated installer handles everything:
- ✅ Detects your OS and installs dependencies
- ✅ Builds all executables (CLI, TUI, Enhanced TUI)
- ✅ Sets up configuration with progress indicators
- ✅ Creates launch scripts
- ✅ Guides you through setup

**See [QUICKSTART.md](QUICKSTART.md) for detailed instructions.**

---

## 🐳 Docker Deployment (NEW!)

Deploy CloudClear with a modern TEMPEST Class C web UI:

```bash
# Configure environment
cp .env.example .env
# Edit .env with your API keys

# Deploy with Docker Compose
docker-compose up -d

# Access at:
# https://scan.yourdomain.com
```

Features:
- 🌐 TEMPEST Class C Security-Focused Web Interface
- 🔒 Automatic HTTPS with Caddy (Let's Encrypt)
- ⚡ Real-time WebSocket scan updates
- 📊 Integration status dashboard
- 🔐 Secure API key management

**See [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md) for complete guide.**

---

## ⚡ Quick Start (Local)

### Launch the Interactive TUI (Recommended)
```bash
./cloudclear-tui-enhanced
```

### Use the Quick Launcher
```bash
./cloudclear-launch.sh
```

### CLI Mode (Fastest)
```bash
./cloudclear example.com
```

---

## 🌐 Supported Integrations (15 Total)

### Cloud Providers (12)
**Cloudflare** • **Akamai Edge** • **AWS CloudFront** • **Azure Front Door** • **GCP Cloud CDN** • **Fastly** • **DigitalOcean** • **Oracle Cloud** • **Alibaba Cloud** • **Imperva** • **Sucuri** • **Stackpath**

### Intelligence Services (3)
**Shodan** • **Censys** • **VirusTotal**

### Detection Methods
HTTP Header Analysis • DNS/CNAME Resolution • SSL/TLS Certificates • IP Range Detection • API Intelligence • WAF Signatures

---

## ✨ Key Features

- 🎯 **Multi-Provider Detection** - Simultaneous detection across 15 services (12 CDN/WAF + 3 intelligence)
- 🐳 **Docker Deployment** - One-command deployment with TEMPEST Class C web UI
- 🔐 **Secure API Management** - Built-in credential storage with encryption
- 📊 **Real-Time Dashboard** - Interactive TUI and web UI with live WebSocket updates
- 🧠 **Intelligence Enrichment** - Shodan, Censys, VirusTotal integration for threat intel
- 🎨 **Multiple Interfaces** - CLI, TUI, Enhanced TUI, and Web UI options
- ⚡ **Progress Indicators** - Visual feedback throughout installation and scanning
- 🔒 **TEMPEST Class C Security** - Military-grade security-focused interface design

---

## 📚 Documentation

- **[Quick Start Guide](QUICKSTART.md)** - Get started in 5 minutes
- **[Docker Deployment Guide](DOCKER_DEPLOYMENT.md)** - Complete Docker setup and deployment
- **[Complete Integration Guide](docs/CLOUD_INTEGRATION_COMPLETE.md)** - Full documentation for all providers
- **[Integration Plan](docs/COMPLETE_CLOUD_INTEGRATION_PLAN.md)** - Technical implementation details

---

## 🚀 Get Started

**Local Installation:**
```bash
./install.sh
```

**Docker Deployment:**
```bash
docker-compose up -d
```

**Ready to detect cloud providers and enhance your intelligence gathering! 🎯**
