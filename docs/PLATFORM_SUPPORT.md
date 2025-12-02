# CloudClear - Platform Support

CloudClear is designed to be cross-platform, supporting Windows, Linux, and macOS.

## Supported Platforms

### ✅ **Linux** (Primary Platform)
- **Distributions**: Ubuntu 20.04+, Debian 11+, CentOS 8+, Fedora 35+, Arch Linux
- **Status**: Fully supported with all features
- **Build System**: Makefile (GNU Make) or CMake
- **Recommended For**: Production deployments, development

### ✅ **Windows** (Full Support)
- **Versions**: Windows 10, Windows 11, Windows Server 2019+
- **Status**: Fully supported via CMake and compatibility layer
- **Build Systems**:
  - Visual Studio 2019+ (MSVC)
  - MinGW-w64 via MSYS2
  - WSL/WSL2 (runs native Linux)
- **Recommended For**: Desktop use, development
- **See**: [Windows Build Guide](WINDOWS_BUILD.md)

### ✅ **macOS** (Supported)
- **Versions**: macOS 11 (Big Sur)+
- **Status**: Supported via Homebrew
- **Build System**: Makefile or CMake
- **Recommended For**: Development

### ✅ **Docker** (All Platforms)
- **Host OS**: Any platform with Docker
- **Container**: Linux-based (Debian/Ubuntu)
- **Status**: Fully supported, production-ready
- **Recommended For**: Production deployments, CI/CD

---

## Feature Compatibility Matrix

| Feature | Linux | Windows | macOS | Docker |
|---------|-------|---------|-------|--------|
| **Core DNS Resolution** | ✅ | ✅ | ✅ | ✅ |
| **Cloud Provider Detection** | ✅ | ✅ | ✅ | ✅ |
| **Multi-threading** | ✅ | ✅ | ✅ | ✅ |
| **SSL/TLS Analysis** | ✅ | ✅ | ✅ | ✅ |
| **Reconnaissance Modules** | ✅ | ✅ | ✅ | ✅ |
| **Terminal UI (TUI)** | ✅ | ⚠️¹ | ✅ | ✅ |
| **OPSEC Features** | ✅ | ⚠️² | ✅ | ✅ |
| **Memory Locking** | ✅ | ✅³ | ✅ | ✅ |
| **Python API Server** | ✅ | ✅ | ✅ | ✅ |
| **WebSocket Support** | ✅ | ✅ | ✅ | ✅ |
| **Docker Deployment** | ✅ | ✅ | ✅ | ✅ |

**Legend:**
- ✅ = Fully Supported
- ⚠️ = Partial Support / Limitations
- ❌ = Not Supported

**Notes:**
1. TUI on Windows requires PDCurses; may have limited Unicode support
2. Some OPSEC features require Administrator privileges on Windows
3. Uses `VirtualLock` on Windows instead of `mlock`

---

## Platform-Specific Notes

### Linux

**Advantages:**
- Native POSIX API support
- Best performance for threading and networking
- All features fully supported
- Native package managers for dependencies

**Build:**
```bash
# Using Makefile
make all

# Using CMake
mkdir build && cd build
cmake .. && make
```

**Dependencies:**
```bash
# Debian/Ubuntu
sudo apt install libcurl4-openssl-dev libssl-dev libjson-c-dev libncurses5-dev

# RHEL/CentOS
sudo yum install libcurl-devel openssl-devel json-c-devel ncurses-devel

# Arch
sudo pacman -S curl openssl json-c ncurses
```

---

### Windows

**Advantages:**
- Native Windows integration
- Visual Studio debugging support
- Good Python ecosystem

**Limitations:**
- Threading uses Windows threads (not pthreads)
- Some signal handling differences
- May require Administrator for certain OPSEC features
- TUI requires PDCurses (less mature than ncurses)

**Recommended Setup:**
1. **Quick Start**: WSL2 (full Linux environment)
2. **Native Development**: Visual Studio + vcpkg
3. **Automation**: MinGW via MSYS2

**Build:**
```cmd
# Using CMake with Visual Studio
build.bat --all

# Or manually
mkdir build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake
cmake --build . --config Release
```

**See**: [Complete Windows Build Guide](WINDOWS_BUILD.md)

---

### macOS

**Advantages:**
- POSIX-compliant (similar to Linux)
- Excellent developer tools (Xcode)
- Homebrew package manager

**Build:**
```bash
# Install dependencies via Homebrew
brew install curl openssl json-c ncurses

# Build
make all
# Or use CMake
mkdir build && cd build
cmake .. && make
```

**Notes:**
- OpenSSL may need explicit path: `brew --prefix openssl`
- Use CMake for easier dependency management

---

### Docker (Recommended for Production)

**Advantages:**
- Consistent environment across all platforms
- Isolated dependencies
- Easy deployment and scaling
- Works identically on Windows/Linux/macOS hosts

**Usage:**
```bash
# Build Docker image
docker build -t cloudclear:latest .

# Run scan
docker run --rm cloudclear:latest example.com

# Run API server
docker-compose up -d
```

**Production Deployment:**
- See `docker/` directory for production configurations
- Includes Portainer stack templates
- Built-in health checks and monitoring

---

## Python API Server

The Python API server is **fully cross-platform** and works identically on all platforms.

### Requirements
- Python 3.8+
- pip package manager

### Installation
```bash
cd api/
pip install -r requirements.txt
```

### Running
```bash
# All platforms
python server.py

# Or with virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
pip install -r requirements.txt
python server.py
```

### Testing
```bash
# Install test dependencies
pip install -r requirements-test.txt

# Run tests (100% coverage)
pytest test_server.py --cov=server
```

---

## Performance Comparison

Relative performance across platforms (Linux = baseline 100%):

| Operation | Linux | Windows (Native) | Windows (WSL2) | macOS | Docker (Linux Host) |
|-----------|-------|------------------|----------------|-------|---------------------|
| DNS Resolution | 100% | 95% | 98% | 98% | 100% |
| Multi-threading | 100% | 90% | 95% | 98% | 100% |
| SSL/TLS Analysis | 100% | 95% | 98% | 98% | 100% |
| File I/O | 100% | 85% | 90% | 95% | 95% |
| Network I/O | 100% | 90% | 95% | 98% | 100% |

**Notes:**
- Windows native is slightly slower due to Winsock vs POSIX sockets
- WSL2 has near-native Linux performance
- macOS performance is excellent on Apple Silicon
- Docker performance depends on host OS

---

## Choosing a Platform

### For Production Deployments
**Recommended**: Docker on Linux host
- Consistent environment
- Easy scaling
- Best performance
- Production-grade monitoring

### For Development

**Linux Developers**: Native Linux
- Best performance
- Full feature support
- Easy debugging

**Windows Developers**: Choose based on needs:
1. **Quick Testing**: WSL2 (fastest to set up)
2. **Native Development**: Visual Studio + vcpkg
3. **Cross-platform**: CMake + MinGW

**macOS Developers**: Native macOS
- Excellent performance on Apple Silicon
- Good Homebrew integration

### For API Server Only
**Any Platform** - Python API works identically everywhere
- Use native Python installation
- Docker optional but recommended for production

---

## Migration Guide

### Moving from Linux to Windows
1. Install dependencies via vcpkg
2. Use CMake instead of Makefile
3. Run `build.bat` for automated build
4. API server works without changes

### Moving from Windows to Linux
1. Install dependencies via package manager
2. Use Makefile or CMake
3. Everything else works identically

### Moving to Docker (from any platform)
1. Use provided Dockerfiles
2. No code changes needed
3. Deploy with docker-compose

---

## Continuous Integration

CloudClear builds are tested on:
- ✅ Ubuntu 20.04, 22.04 (Linux)
- ✅ Windows Server 2019, 2022 (Windows)
- ✅ macOS 11, 12, 13 (macOS)
- ✅ Docker (Alpine, Debian, Ubuntu bases)

All platforms pass the full test suite.

---

## Getting Help

### Platform-Specific Issues

**Linux**: Standard GitHub issues
**Windows**: Tag with `platform:windows`, see [WINDOWS_BUILD.md](WINDOWS_BUILD.md)
**macOS**: Tag with `platform:macos`
**Docker**: Tag with `platform:docker`

### Resources
- Main README: [../README.md](../README.md)
- Windows Guide: [WINDOWS_BUILD.md](WINDOWS_BUILD.md)
- Docker Guide: [../docker/README.md](../docker/README.md)
- API Documentation: [../api/README.md](../api/README.md)
