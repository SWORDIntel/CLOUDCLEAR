# CloudClear

> **Advanced Cloud Provider Detection & Intelligence Platform**
>
> Detect and analyze 20+ cloud service providers, CDNs, WAFs, and intelligence services
>
> **Cross-Platform:** Fully supported on **Windows** and **Linux**

[![Version](https://img.shields.io/badge/version-2.0--Enhanced--Cloud-blue.svg)](https://github.com/SWORDIntel/CLOUDCLEAR)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)]()

---

## 🚀 Quick Installation

### Linux Installation

```bash
./install.sh
```

**That's it!** The automated installer handles everything:
- ✅ Detects your OS and installs dependencies
- ✅ Builds all executables (CLI, TUI, Enhanced TUI)
- ✅ Sets up configuration with progress indicators
- ✅ Creates launch scripts
- ✅ Guides you through setup

### Windows Installation

CloudClear uses **CMake** for Windows builds with **vcpkg** for dependency management:

```batch
# Install dependencies via vcpkg
vcpkg install curl openssl json-c

# Configure and build
mkdir build
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake
cmake --build . --config Release
```

**See [QUICKSTART.md](docs/QUICKSTART.md) for detailed instructions.**

---

## 🐳 Docker Deployment (NEW!)

Deploy CloudClear with a modern TEMPEST Class C web UI:

```bash
# Start with random ports (recommended - avoids port conflicts)
./docker-start.sh

# Or use Docker Compose directly
docker-compose up -d

# View assigned ports
./docker-ports.sh
```

**Random Port Assignment**: The startup script automatically finds available ports and displays them to you!

See [DOCKER_STARTUP.md](DOCKER_STARTUP.md) for detailed Docker usage.

Features:
- 🌐 TEMPEST Class C Security-Focused Web Interface
- 🔒 Automatic HTTPS with Caddy (Let's Encrypt)
- ⚡ Real-time WebSocket scan updates
- 📊 Integration status dashboard
- 🔐 Secure API key management

**See [DOCKER_DEPLOYMENT.md](docs/DOCKER_DEPLOYMENT.md) for complete guide.**

---

## ⚡ Quick Start (Local)

### Linux

**Launch the Interactive TUI (Recommended)**
```bash
./cloudclear-tui-enhanced
```

**Use the Quick Launcher**
```bash
./cloudclear-launch.sh
```

**CLI Mode (Fastest)**
```bash
./cloudclear example.com
```

### Windows

**Launch the Interactive TUI**
```batch
build\Release\cloudclear-tui.exe
```

**CLI Mode**
```batch
build\Release\cloudclear.exe example.com
```

**Note:** Windows builds require Visual Studio 2019+ or Build Tools with CMake and vcpkg.

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
- 🪟 **Cross-Platform Support** - Native builds for **Windows** (MSVC/CMake) and **Linux** (GCC/Make)
- 🐳 **Docker Deployment** - One-command deployment with TEMPEST Class C web UI (Linux/WSL)
- 🔐 **Secure API Management** - Built-in credential storage with encryption
- 📊 **Real-Time Dashboard** - Interactive TUI and web UI with live WebSocket updates
- 🧠 **Intelligence Enrichment** - Shodan, Censys, VirusTotal integration for threat intel
- 🎨 **Multiple Interfaces** - CLI, TUI, Enhanced TUI, and Web UI options
- ⚡ **Progress Indicators** - Visual feedback throughout installation and scanning
- 🔒 **TEMPEST Class C Security** - Military-grade security-focused interface design
- 🔧 **Platform Compatibility** - Comprehensive Windows/Linux compatibility layer for seamless cross-platform operation

---

## 📚 Documentation

### Getting Started
- **[Quick Start Guide](docs/QUICKSTART.md)** - Get started in 5 minutes
- **[Installation Guide](docs/INSTALLATION_COMPLETE.txt)** - Complete installation documentation

### Deployment
- **[Docker Deployment](docs/DOCKER_DEPLOYMENT.md)** - Complete Docker setup
- **[Simple API](docs/SIMPLE_API.md)** - Lightweight localhost JSON endpoint
- **[Web UI Deployment](docs/WEB_UI_DEPLOYMENT.md)** - Web interface setup

### Platform Support
- **[Windows Build Guide](docs/WINDOWS_BUILD.md)** - Complete Windows build instructions with CMake/vcpkg
- **[Platform Support](docs/PLATFORM_SUPPORT.md)** - Cross-platform compatibility details
- **[Root Structure](docs/ROOT_STRUCTURE.md)** - Project organization
- **Cross-Platform Compatibility** - All code uses `platform_compat.h` for seamless Windows/Linux support

### Features
- **[CDN Bypass Features](docs/CDN_BYPASS_FEATURES.md)** - Advanced detection capabilities
- **[Crypto Offensive](docs/DSSSL_CRYPTO_OFFENSIVE.md)** - Cryptographic analysis
- **[Complete Integration Guide](docs/CLOUD_INTEGRATION_COMPLETE.md)** - All providers

---

## 🚀 Get Started

### Linux Installation
```bash
./install.sh
```

### Windows Installation
```batch
# Using CMake with vcpkg (recommended)
mkdir build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake
cmake --build . --config Release
```

### Docker Deployment (Linux/WSL)
```bash
docker-compose up -d
```

**Ready to detect cloud providers and enhance your intelligence gathering! 🎯**

---

## 📋 Platform Requirements

### Linux
- **Compiler:** GCC 9+ or Clang 10+
- **Dependencies:** libcurl, OpenSSL, json-c, ncurses (for TUI)
- **Build System:** Make
- **Package Managers:** apt (Debian/Ubuntu), yum/dnf (RHEL/CentOS), pacman (Arch)

### Windows
- **Compiler:** MSVC 2019+ (Visual Studio 2019/2022 or Build Tools)
- **Build System:** CMake 3.15+
- **Dependency Manager:** vcpkg (recommended)
- **Dependencies:** curl, openssl, json-c, PDCurses (for TUI)
- **Architecture:** x64 (64-bit)

**Note:** CloudClear includes comprehensive cross-platform compatibility via `platform_compat.h`, ensuring identical functionality on both Windows and Linux.
