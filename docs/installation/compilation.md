# Compilation Instructions

## 🏗️ Complete Build Guide for CloudUnflare Enhanced

This guide provides detailed compilation instructions for building CloudUnflare Enhanced from source with all advanced features enabled.

## 📋 Prerequisites

### System Requirements
- **Operating System**: Linux (Ubuntu 20.04+, CentOS 8+), macOS (10.15+), Windows WSL2
- **Architecture**: x86_64 (Intel/AMD), ARM64 (Apple Silicon supported)
- **Memory**: Minimum 2GB RAM, 4GB+ recommended for large scans
- **Disk Space**: 500MB for source + dependencies
- **Network**: Internet connection for dependency installation and testing

### Required Compilers
```bash
# GCC (Recommended)
gcc --version  # 9.0+ required, 11.0+ recommended

# Alternative: Clang (also supported)
clang --version  # 10.0+ required
```

## 📦 Dependencies Installation

### Ubuntu/Debian
```bash
# Update package manager
sudo apt-get update

# Install build essentials
sudo apt-get install -y build-essential pkg-config git

# Install required libraries
sudo apt-get install -y \
    libcurl4-openssl-dev \
    libssl-dev \
    libjson-c-dev \
    libpthread-stubs0-dev

# Verify installations
pkg-config --exists libcurl && echo "✓ libcurl installed"
pkg-config --exists openssl && echo "✓ OpenSSL installed"
pkg-config --exists json-c && echo "✓ json-c installed"
```

### CentOS/RHEL/Rocky Linux
```bash
# Install development tools
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y pkg-config git

# Install libraries
sudo dnf install -y \
    libcurl-devel \
    openssl-devel \
    json-c-devel

# For older CentOS 7
sudo yum groupinstall -y "Development Tools"
sudo yum install -y libcurl-devel openssl-devel json-c-devel
```

### macOS
```bash
# Install Xcode command line tools
xcode-select --install

# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install curl openssl json-c pkg-config

# Set environment variables for OpenSSL
export PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig:$PKG_CONFIG_PATH"
export LDFLAGS="-L/usr/local/opt/openssl/lib"
export CPPFLAGS="-I/usr/local/opt/openssl/include"
```

### Windows WSL2
```bash
# Install Ubuntu 20.04+ from Microsoft Store
# Then follow Ubuntu instructions above

# Additional WSL-specific setup
sudo apt-get install -y wslu

# For GUI applications (optional)
sudo apt-get install -y x11-apps
```

## 🔨 Compilation Process

### Method 1: Automated Build (Recommended)
```bash
# Clone repository
git clone https://github.com/SWORDIntel/claude-backups.git
cd claude-backups/CloudUnflare

# Quick dependency check and installation
make deps

# Build with all enhancements
make

# Verify build
./cloudunflare --help
```

### Method 2: Manual Compilation
```bash
# Standard build with optimizations
gcc -Wall -Wextra -O3 -std=c99 -D_GNU_SOURCE \
    -o cloudunflare \
    cloudunflare.c dns_enhanced.c \
    -lcurl -lssl -lcrypto -ljson-c -lpthread

# Verify successful compilation
ls -la cloudunflare
file cloudunflare
```

### Method 3: Security-Hardened Build
```bash
# Build with security enhancements
make secure

# Equivalent manual command
gcc -Wall -Wextra -O3 -std=c99 -D_GNU_SOURCE \
    -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE \
    -o cloudunflare \
    cloudunflare.c dns_enhanced.c \
    -lcurl -lssl -lcrypto -ljson-c -lpthread -pie
```

### Method 4: Debug Build
```bash
# Build with debug symbols and verbose output
make debug

# Equivalent manual command
gcc -Wall -Wextra -g -DDEBUG -std=c99 -D_GNU_SOURCE \
    -o cloudunflare \
    cloudunflare.c dns_enhanced.c \
    -lcurl -lssl -lcrypto -ljson-c -lpthread
```

## ⚙️ Advanced Compilation Options

### Compiler Flags Explained

#### Basic Flags
```bash
-Wall              # Enable all common warnings
-Wextra            # Enable extra warnings
-O3                # Maximum optimization for speed
-std=c99           # Use C99 standard
-D_GNU_SOURCE      # Enable GNU extensions
```

#### Security Flags
```bash
-fstack-protector-strong    # Stack protection against buffer overflows
-D_FORTIFY_SOURCE=2        # Runtime buffer overflow detection
-fPIE                      # Position Independent Executable
-pie                       # Create position independent executable
```

#### Debug Flags
```bash
-g                 # Include debug symbols
-DDEBUG           # Enable debug preprocessor macro
-fsanitize=address # AddressSanitizer (memory error detection)
-fsanitize=thread  # ThreadSanitizer (data race detection)
```

### Custom Feature Configuration
```bash
# Disable specific features (if needed)
gcc -DDISABLE_DOQ_SUPPORT \
    -DDISABLE_IPV6_SUPPORT \
    -o cloudunflare \
    cloudunflare.c dns_enhanced.c \
    -lcurl -lssl -lcrypto -ljson-c -lpthread

# Enable verbose logging
gcc -DENABLE_VERBOSE_LOGGING \
    -DDEBUG_LEVEL=2 \
    -o cloudunflare \
    cloudunflare.c dns_enhanced.c \
    -lcurl -lssl -lcrypto -ljson-c -lpthread
```

## 🧪 Testing the Build

### Comprehensive Test Suite
```bash
# Build and run complete test suite
make test

# Manual test compilation and execution
gcc -Wall -Wextra -O3 -std=c99 -D_GNU_SOURCE \
    -o test_enhanced \
    test_enhanced.c dns_enhanced.c \
    -lcurl -lssl -lcrypto -ljson-c -lpthread

./test_enhanced
```

### Quick Functionality Test
```bash
# Test basic functionality
echo "google.com" | ./cloudunflare

# Test enhanced DNS features
./cloudunflare --test-dns-enhanced

# Performance benchmark
time ./cloudunflare --benchmark
```

## 🚀 Performance Optimization

### CPU-Specific Optimizations
```bash
# Intel CPUs with AVX2 support
gcc -march=native -mtune=native -mavx2 \
    -Wall -Wextra -O3 -std=c99 -D_GNU_SOURCE \
    -o cloudunflare \
    cloudunflare.c dns_enhanced.c \
    -lcurl -lssl -lcrypto -ljson-c -lpthread

# ARM64 (Apple Silicon) optimization
gcc -mcpu=native -mtune=native \
    -Wall -Wextra -O3 -std=c99 -D_GNU_SOURCE \
    -o cloudunflare \
    cloudunflare.c dns_enhanced.c \
    -lcurl -lssl -lcrypto -ljson-c -lpthread
```

### Link-Time Optimization (LTO)
```bash
# Enable LTO for maximum performance
gcc -flto -Wall -Wextra -O3 -std=c99 -D_GNU_SOURCE \
    -o cloudunflare \
    cloudunflare.c dns_enhanced.c \
    -lcurl -lssl -lcrypto -ljson-c -lpthread
```

## 📦 Static Linking (Optional)

### Create Portable Binary
```bash
# Static linking for maximum portability
gcc -static -Wall -Wextra -O3 -std=c99 -D_GNU_SOURCE \
    -o cloudunflare-static \
    cloudunflare.c dns_enhanced.c \
    -lcurl -lssl -lcrypto -ljson-c -lpthread \
    -lz -ldl

# Note: Requires static versions of libraries
# May not work on all systems due to glibc static linking issues
```

## 🐳 Docker Build

### Multi-stage Docker Build
```dockerfile
# Create Dockerfile for containerized build
FROM ubuntu:22.04 as builder

RUN apt-get update && apt-get install -y \
    build-essential pkg-config \
    libcurl4-openssl-dev libssl-dev libjson-c-dev

COPY . /src
WORKDIR /src

RUN make secure

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y \
    libcurl4 libssl3 libjson-c5
COPY --from=builder /src/cloudunflare /usr/local/bin/

ENTRYPOINT ["cloudunflare"]
```

```bash
# Build Docker image
docker build -t cloudunflare-enhanced .

# Run containerized
docker run -it --rm cloudunflare-enhanced
```

## 🔍 Troubleshooting Compilation

### Common Issues and Solutions

#### Missing Headers
```bash
# Error: curl/curl.h: No such file or directory
sudo apt-get install libcurl4-openssl-dev

# Error: openssl/ssl.h: No such file or directory
sudo apt-get install libssl-dev

# Error: json-c/json.h: No such file or directory
sudo apt-get install libjson-c-dev
```

#### Linking Errors
```bash
# Error: undefined reference to 'curl_easy_init'
# Add -lcurl to linking flags

# Error: undefined reference to 'pthread_create'
# Add -lpthread to linking flags

# Error: undefined reference to 'SSL_library_init'
# Add -lssl -lcrypto to linking flags
```

#### Version Compatibility
```bash
# Check library versions
pkg-config --modversion libcurl    # Should be 7.0+
pkg-config --modversion openssl    # Should be 1.1.1+
pkg-config --modversion json-c     # Should be 0.13+

# Update if necessary
sudo apt-get update && sudo apt-get upgrade
```

### Build Verification
```bash
# Verify all required symbols are resolved
nm cloudunflare | grep -E "(curl|SSL|json)"

# Check dynamic dependencies
ldd cloudunflare

# Test basic functionality
./cloudunflare --version
```

## 📋 Make Targets Reference

```bash
make                # Standard build
make deps          # Install dependencies
make check         # Verify dependencies
make test          # Build and run test suite
make debug         # Debug build with symbols
make secure        # Security-hardened build
make analyze       # Static code analysis
make install       # Install system-wide
make clean         # Remove build artifacts
make help          # Show all available targets
```

## 🚀 Installation

### System-wide Installation
```bash
# Install to /usr/local/bin
sudo make install

# Verify installation
which cloudunflare
cloudunflare --version
```

### User-local Installation
```bash
# Install to ~/.local/bin
mkdir -p ~/.local/bin
cp cloudunflare ~/.local/bin/
export PATH="$HOME/.local/bin:$PATH"

# Add to shell profile for persistence
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
```

## 🏁 Next Steps

After successful compilation:

1. **[Basic Usage Guide](../guides/basic-usage.md)** - Learn the fundamentals
2. **[Configuration Guide](../guides/configuration.md)** - Customize behavior
3. **[OPSEC Best Practices](../guides/opsec-best-practices.md)** - Operational security
4. **[Performance Tuning](../guides/performance-tuning.md)** - Optimize for your environment

---

*For additional help, see [Troubleshooting](../troubleshooting/) or run `make help`*