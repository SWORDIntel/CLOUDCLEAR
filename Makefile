# Makefile for CloudClear (CloudUnflare Enhanced)
# Advanced DNS reconnaissance tool with OPSEC capabilities and thread safety

CC = gcc
CFLAGS = -Wall -Wextra -O3 -std=c11 -D_GNU_SOURCE -pthread -Iinclude
THREAD_SAFE_CFLAGS = $(CFLAGS) -DTHREAD_SAFE_BUILD
RECON_CFLAGS = $(CFLAGS) -DRECON_MODULES_ENABLED
LIBS = -lcurl -lssl -lcrypto -ljson-c -lpthread -latomic -lresolv
TUI_LIBS = $(LIBS) -lncurses
TARGET = cloudclear
TUI_TARGET = cloudclear-tui
TUI_ENHANCED_TARGET = cloudclear-tui-enhanced
RECON_TARGET = cloudclear-recon

# Source directories
SRC_DIR = src
CORE_DIR = $(SRC_DIR)/core
TUI_DIR = $(SRC_DIR)/tui
MODULES_DIR = $(SRC_DIR)/modules
INCLUDE_DIR = include
TEST_DIR = tests
BUILD_DIR = build

# Core sources
CORE_SOURCES = $(CORE_DIR)/cloudunflare.c \
               $(CORE_DIR)/dns_enhanced.c \
               $(MODULES_DIR)/advanced_ip_detection.c

TUI_SOURCES = $(TUI_DIR)/cloudunflare_tui_main.c \
              $(TUI_DIR)/cloudclear_tui.c \
              $(CORE_DIR)/dns_enhanced.c \
              $(MODULES_DIR)/advanced_ip_detection.c

TUI_ENHANCED_SOURCES = $(TUI_DIR)/cloudunflare_tui_main.c \
                       $(TUI_DIR)/cloudclear_tui.c \
                       $(TUI_DIR)/cloudclear_tui_enhanced.c \
                       $(CORE_DIR)/dns_enhanced.c \
                       $(MODULES_DIR)/advanced_ip_detection.c

# Reconnaissance module sources
RECON_COMMON_DIR = $(MODULES_DIR)/recon/common
RECON_COMMON_SOURCES = $(RECON_COMMON_DIR)/recon_common.c \
                       $(RECON_COMMON_DIR)/recon_opsec.c \
                       $(RECON_COMMON_DIR)/recon_proxy.c

RECON_DNS_ZONE_SOURCES = $(MODULES_DIR)/recon/dns_zone_transfer/dns_zone_transfer.c \
                         $(MODULES_DIR)/recon/dns_zone_transfer/dns_zone_transfer_enhanced.c
RECON_DNS_BRUTE_SOURCES = $(MODULES_DIR)/recon/dns_bruteforce/dns_bruteforce.c
RECON_HTTP_BANNER_SOURCES = $(MODULES_DIR)/recon/http_banner/http_banner.c
RECON_PORT_SCANNER_SOURCES = $(MODULES_DIR)/recon/port_scanner/port_scanner.c
RECON_CLOUDFLARE_RADAR_SOURCES = $(MODULES_DIR)/recon/cloudflare_radar/cloudflare_radar.c \
                                  $(MODULES_DIR)/recon/cloudflare_radar/cloudflare_radar_api.c \
                                  $(MODULES_DIR)/recon/cloudflare_radar/cloudflare_radar_parser.c

# All reconnaissance sources
RECON_SOURCES = $(RECON_COMMON_SOURCES) $(RECON_DNS_ZONE_SOURCES) \
                $(RECON_DNS_BRUTE_SOURCES) $(RECON_HTTP_BANNER_SOURCES) \
                $(RECON_PORT_SCANNER_SOURCES) $(RECON_CLOUDFLARE_RADAR_SOURCES)

# Combined sources for full build
SOURCES = $(CORE_SOURCES) $(RECON_SOURCES)

# Headers
CORE_HEADERS = $(INCLUDE_DIR)/dns_enhanced.h \
               $(INCLUDE_DIR)/config.h \
               $(INCLUDE_DIR)/advanced_ip_detection.h
TUI_HEADERS = $(CORE_HEADERS) $(INCLUDE_DIR)/cloudclear_tui.h

# Check for required libraries
CURL_EXISTS := $(shell pkg-config --exists libcurl && echo yes)
SSL_EXISTS := $(shell pkg-config --exists openssl && echo yes)
JSON_EXISTS := $(shell pkg-config --exists json-c && echo yes)
NCURSES_EXISTS := $(shell pkg-config --exists ncurses && echo yes)

.PHONY: all clean install deps check tui tui-enhanced recon test help structure docker

all: check $(TARGET)

# Main build target
$(TARGET): $(SOURCES)
	@echo "========================================="
	@echo "Building CloudClear..."
	@echo "========================================="
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) $(LIBS)
	@echo "✓ Build completed successfully!"
	@echo ""
	@echo "Enhanced features:"
	@echo "  • DoQ/DoH/DoT protocol support"
	@echo "  • Advanced IP detection (SSL cert matching, MX analysis, SRV discovery)"
	@echo "  • Cloudflare bypass detection"
	@echo "  • ASN clustering and PTR analysis"
	@echo "  • IP enrichment, CDN detection, dual-stack IPv6"
	@echo ""
	@echo "Run with: ./$(TARGET)"
	@echo "========================================="

# TUI build target (with interactive interface)
tui: check-tui
	@echo "========================================="
	@echo "Building CloudClear with Interactive TUI..."
	@echo "========================================="
	$(CC) $(CFLAGS) -o $(TUI_TARGET) $(TUI_SOURCES) $(TUI_LIBS)
	@echo "✓ TUI Build completed successfully!"
	@echo ""
	@echo "Features:"
	@echo "  • Real-time progress display"
	@echo "  • Interactive results browser"
	@echo "  • Detailed candidate view with evidence"
	@echo "  • Live statistics and phase tracking"
	@echo "  • Beautiful ASCII art interface"
	@echo ""
	@echo "Run with: ./$(TUI_TARGET)"
	@echo "========================================="

# Enhanced TUI build target (with Unicode and modern UI)
tui-enhanced: check-tui
	@echo "========================================="
	@echo "Building CloudClear with Enhanced TUI..."
	@echo "========================================="
	$(CC) $(CFLAGS) -o $(TUI_ENHANCED_TARGET) $(TUI_ENHANCED_SOURCES) $(TUI_LIBS)
	@echo "✓ Enhanced TUI Build completed successfully!"
	@echo ""
	@echo "Enhanced Features:"
	@echo "  ✨ Modern Unicode box-drawing characters"
	@echo "  🎨 Vibrant color scheme with gradients"
	@echo "  📊 Enhanced progress bars with visual feedback"
	@echo "  🏅 Medal ranking for top candidates"
	@echo "  ⚡ Animated status indicators"
	@echo "  💎 Polished visual design"
	@echo ""
	@echo "Requirements:"
	@echo "  • Terminal with UTF-8 support"
	@echo "  • 256-color terminal (xterm-256color)"
	@echo "  • Font with Unicode support (Nerd Font recommended)"
	@echo ""
	@echo "Run with: ./$(TUI_ENHANCED_TARGET)"
	@echo "========================================="

check-tui: check
	@echo "Checking TUI dependencies..."
ifeq ($(NCURSES_EXISTS),yes)
	@echo "✓ ncurses found"
else
	@echo "✗ ncurses not found - install with: sudo apt-get install libncurses-dev"
	@exit 1
endif
	@echo "✓ All TUI dependencies satisfied"

# Reconnaissance modules build target
recon: check
	@echo "========================================="
	@echo "Building CloudClear with Reconnaissance Modules..."
	@echo "========================================="
	$(CC) $(RECON_CFLAGS) -o $(RECON_TARGET) $(SOURCES) $(LIBS)
	@echo "✓ Reconnaissance build completed successfully!"
	@echo ""
	@echo "Features: DNS Zone Transfer, Brute-Force, HTTP Banner Grabbing, Port Scanning"
	@echo ""
	@echo "Run with: ./$(RECON_TARGET)"
	@echo "========================================="

# Dependency checking
check:
	@echo "Checking dependencies..."
ifeq ($(CURL_EXISTS),yes)
	@echo "✓ libcurl found"
else
	@echo "✗ libcurl not found - install with: sudo apt-get install libcurl4-openssl-dev"
	@exit 1
endif
ifeq ($(SSL_EXISTS),yes)
	@echo "✓ OpenSSL found"
else
	@echo "✗ OpenSSL not found - install with: sudo apt-get install libssl-dev"
	@exit 1
endif
ifeq ($(JSON_EXISTS),yes)
	@echo "✓ json-c found"
else
	@echo "✗ json-c not found - install with: sudo apt-get install libjson-c-dev"
	@exit 1
endif
	@echo "✓ All dependencies satisfied"

# Install dependencies
deps:
	@echo "Installing dependencies..."
	sudo apt-get update
	sudo apt-get install -y libcurl4-openssl-dev libssl-dev libjson-c-dev libncurses-dev build-essential pkg-config

# System installation
install: $(TARGET)
	@echo "Installing CloudClear..."
	sudo cp $(TARGET) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(TARGET)
	@echo "✓ Installation completed. Run with: cloudclear"

# Build tests
test: $(TEST_DIR)/test_enhanced.c $(CORE_DIR)/dns_enhanced.c
	@echo "Building test suite..."
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/test_enhanced $(TEST_DIR)/test_enhanced.c $(CORE_DIR)/dns_enhanced.c $(LIBS)
	@echo "Running tests..."
	./$(BUILD_DIR)/test_enhanced

# Clean build artifacts
clean:
	@echo "Cleaning build files..."
	rm -f $(TARGET) $(TUI_TARGET) $(TUI_ENHANCED_TARGET) $(RECON_TARGET)
	find $(BUILD_DIR) -type f -delete 2>/dev/null || true
	rm -f $(SRC_DIR)/*/*.o $(SRC_DIR)/*/*/*.o $(SRC_DIR)/*/*/*/*.o
	@echo "✓ Clean completed"

# Docker build
docker:
	@echo "Building Docker image..."
	cd docker && docker build -t cloudclear:latest -f Dockerfile ..
	@echo "✓ Docker image built successfully"

# Show project structure
structure:
	@echo "CloudClear Project Structure:"
	@echo ""
	@echo "CLOUDCLEAR/"
	@echo "├── src/                  # Source code"
	@echo "│   ├── core/            # Core application"
	@echo "│   ├── tui/             # Text User Interface"
	@echo "│   └── modules/         # Feature modules"
	@echo "│       ├── performance/ # Performance optimizations"
	@echo "│       └── recon/       # Reconnaissance modules"
	@echo "├── include/             # Header files"
	@echo "├── tests/               # Test suite"
	@echo "├── scripts/             # Utility scripts"
	@echo "├── docker/              # Docker configuration"
	@echo "├── docs/                # Documentation"
	@echo "├── data/                # Runtime data"
	@echo "│   ├── config/         # Configuration files"
	@echo "│   └── wordlists/      # Enumeration wordlists"
	@echo "└── build/               # Build artifacts"

# Help
help:
	@echo "========================================="
	@echo "CloudClear Build System"
	@echo "========================================="
	@echo ""
	@echo "Available targets:"
	@echo "  make              - Build the application (default)"
	@echo "  make tui          - Build with interactive TUI"
	@echo "  make tui-enhanced - Build with enhanced TUI (Unicode + modern UI)"
	@echo "  make recon        - Build with reconnaissance modules"
	@echo "  make test         - Build and run test suite"
	@echo "  make docker       - Build Docker image"
	@echo "  make deps         - Install required dependencies"
	@echo "  make check        - Check for required dependencies"
	@echo "  make install      - Install to /usr/local/bin"
	@echo "  make clean        - Remove build files"
	@echo "  make structure    - Show project structure"
	@echo "  make help         - Show this help message"
	@echo ""
	@echo "Quick start:"
	@echo "  1. make deps      # Install dependencies"
	@echo "  2. make           # Build application"
	@echo "  3. ./cloudclear   # Run CloudClear"
	@echo ""
	@echo "Docker deployment (recommended):"
	@echo "  cd docker && docker-compose up -d"
	@echo ""
	@echo "See docs/QUICKSTART.md for more information"
	@echo "========================================="
