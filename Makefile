# Makefile for CloudUnflare Enhanced
# Advanced DNS reconnaissance tool with OPSEC capabilities and thread safety
# Phase 1: API-free reconnaissance modules (DNS Zone Transfer, Brute-Force, HTTP Banner, Port Scanner)

CC = gcc
CFLAGS = -Wall -Wextra -O3 -std=c11 -D_GNU_SOURCE -pthread
THREAD_SAFE_CFLAGS = $(CFLAGS) -DTHREAD_SAFE_BUILD
RECON_CFLAGS = $(CFLAGS) -DRECON_MODULES_ENABLED
LIBS = -lcurl -lssl -lcrypto -ljson-c -lpthread -latomic -lresolv
TARGET = cloudunflare
THREAD_TEST_TARGET = thread_safety_test
RECON_TARGET = cloudunflare-recon

# Core sources
CORE_SOURCES = cloudunflare.c dns_enhanced.c advanced_ip_detection.c
THREAD_TEST_SOURCES = thread_safety_test.c dns_enhanced.c

# Reconnaissance module sources
RECON_COMMON_SOURCES = recon_modules/common/recon_common.c
RECON_DNS_ZONE_SOURCES = recon_modules/dns_zone_transfer/dns_zone_transfer.c
RECON_DNS_BRUTE_SOURCES = recon_modules/dns_bruteforce/dns_bruteforce.c
RECON_HTTP_BANNER_SOURCES = recon_modules/http_banner/http_banner.c
RECON_PORT_SCANNER_SOURCES = recon_modules/port_scanner/port_scanner.c

# All reconnaissance sources
RECON_SOURCES = $(RECON_COMMON_SOURCES) $(RECON_DNS_ZONE_SOURCES) $(RECON_DNS_BRUTE_SOURCES) $(RECON_HTTP_BANNER_SOURCES) $(RECON_PORT_SCANNER_SOURCES)

# Combined sources for full build
SOURCES = $(CORE_SOURCES) $(RECON_SOURCES)

# Headers
CORE_HEADERS = dns_enhanced.h config.h advanced_ip_detection.h
RECON_HEADERS = recon_modules/common/recon_common.h \
                recon_modules/dns_zone_transfer/dns_zone_transfer.h \
                recon_modules/dns_bruteforce/dns_bruteforce.h \
                recon_modules/http_banner/http_banner.h \
                recon_modules/port_scanner/port_scanner.h

HEADERS = $(CORE_HEADERS) $(RECON_HEADERS)

# Check for required libraries
CURL_EXISTS := $(shell pkg-config --exists libcurl && echo yes)
SSL_EXISTS := $(shell pkg-config --exists openssl && echo yes)
JSON_EXISTS := $(shell pkg-config --exists json-c && echo yes)

.PHONY: all clean install deps check thread-test thread-safe recon recon-core help-recon test-zone-transfer zone-transfer-example

all: check $(TARGET)

# Reconnaissance modules build target
recon: check recon-build

recon-build: $(SOURCES) $(HEADERS)
	@echo "Compiling CloudUnflare Enhanced with reconnaissance modules..."
	$(CC) $(RECON_CFLAGS) -o $(RECON_TARGET) $(SOURCES) $(LIBS)
	@echo "Reconnaissance build completed successfully!"
	@echo "Features: DNS Zone Transfer, Brute-Force, HTTP Banner Grabbing, Port Scanning"
	@echo "Run with: ./$(RECON_TARGET)"

# Core reconnaissance modules only (for development)
recon-core: $(RECON_SOURCES) $(RECON_HEADERS)
	@echo "Building reconnaissance modules library..."
	$(CC) $(RECON_CFLAGS) -c $(RECON_SOURCES)
	@echo "Reconnaissance modules compiled successfully!"

# Thread-safe build target
thread-safe: check thread-safe-build

thread-safe-build: $(SOURCES) $(HEADERS)
	@echo "Compiling CloudUnflare Enhanced with thread safety improvements..."
	$(CC) $(THREAD_SAFE_CFLAGS) -o $(TARGET) $(SOURCES) $(LIBS)
	@echo "Thread-safe build completed successfully!"
	@echo "Features: 50-thread concurrency, atomic operations, mutex protection"

$(TARGET): $(SOURCES) $(HEADERS)
	@echo "Compiling CloudUnflare Enhanced with Advanced IP Detection..."
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) $(LIBS)
	@echo "Build completed successfully!"
	@echo "Enhanced features:"
	@echo "  • DoQ/DoH/DoT protocol support"
	@echo "  • Advanced IP detection (SSL cert matching, MX analysis, SRV discovery)"
	@echo "  • Cloudflare bypass detection"
	@echo "  • ASN clustering and PTR analysis"
	@echo "  • IP enrichment, CDN detection, dual-stack IPv6"
	@echo "Run with: ./$(TARGET)"

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

deps:
	@echo "Installing dependencies..."
	sudo apt-get update
	sudo apt-get install -y libcurl4-openssl-dev libssl-dev libjson-c-dev build-essential pkg-config

install: $(TARGET)
	@echo "Installing CloudUnflare Enhanced..."
	sudo cp $(TARGET) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(TARGET)
	@echo "Installation completed. Run with: cloudunflare"

# DNS Zone Transfer test and example programs
test-zone-transfer: test_zone_transfer.c $(RECON_SOURCES) $(RECON_HEADERS)
	@echo "Building DNS Zone Transfer test suite..."
	$(CC) $(RECON_CFLAGS) -o test_zone_transfer test_zone_transfer.c $(RECON_SOURCES) $(LIBS)
	@echo "✓ Zone transfer test build completed"
	@echo "Run with: ./test_zone_transfer"

zone-transfer-example: zone_transfer_example.c $(RECON_SOURCES) $(RECON_HEADERS)
	@echo "Building DNS Zone Transfer example program..."
	$(CC) $(RECON_CFLAGS) -o zone_transfer_example zone_transfer_example.c $(RECON_SOURCES) $(LIBS)
	@echo "✓ Zone transfer example build completed"
	@echo "Run with: ./zone_transfer_example --help"

clean:
	@echo "Cleaning build files..."
	rm -f $(TARGET) $(RECON_TARGET) test_enhanced $(THREAD_TEST_TARGET)
	rm -f test_zone_transfer zone_transfer_example
	rm -f *.o recon_modules/*/*.o recon_modules/*/*/*.o
	@echo "Clean completed"

# Debug build
debug: CFLAGS += -g -DDEBUG
debug: $(TARGET)

# Static analysis
analyze:
	@echo "Running static analysis..."
	cppcheck --enable=all --std=c99 $(SOURCE)

# Security hardening flags
secure: CFLAGS += -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
secure: LIBS += -pie
secure: $(TARGET)
	@echo "Security-hardened build completed"

# Test suite
test: test_enhanced
	@echo "Running enhanced DNS resolution test suite..."
	./test_enhanced

test_enhanced: test_enhanced.c $(SOURCES) $(HEADERS)
	@echo "Building enhanced DNS test suite..."
	$(CC) $(CFLAGS) -o test_enhanced test_enhanced.c dns_enhanced.c $(LIBS)

# Thread safety test
thread-test: $(THREAD_TEST_TARGET)
	@echo "Running thread safety verification test..."
	@echo "This test validates 50-thread concurrency safety..."
	./$(THREAD_TEST_TARGET)

$(THREAD_TEST_TARGET): $(THREAD_TEST_SOURCES) $(HEADERS)
	@echo "Building thread safety test suite..."
	$(CC) $(THREAD_SAFE_CFLAGS) -o $(THREAD_TEST_TARGET) $(THREAD_TEST_SOURCES) $(LIBS)

help:
	@echo "CloudUnflare Enhanced Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  all         - Build the application (default)"
	@echo "  recon       - Build with reconnaissance modules (Phase 1)"
	@echo "  recon-core  - Build reconnaissance modules only"
	@echo "  thread-safe - Build with thread safety features"
	@echo "  test        - Build and run DNS test suite"
	@echo "  thread-test - Build and run thread safety tests"
	@echo "  test-zone-transfer - Build DNS Zone Transfer test suite"
	@echo "  zone-transfer-example - Build Zone Transfer example program"
	@echo "  deps        - Install required dependencies"
	@echo "  check       - Check for required dependencies"
	@echo "  debug       - Build with debug symbols"
	@echo "  secure      - Build with security hardening"
	@echo "  analyze     - Run static code analysis"
	@echo "  install     - Install to /usr/local/bin"
	@echo "  clean       - Remove build files"
	@echo "  help        - Show this help message"
	@echo "  help-recon  - Show reconnaissance modules help"
	@echo ""
	@echo "Enhanced DNS Features:"
	@echo "  • DoQ/DoH/DoT protocol support with intelligent fallback"
	@echo "  • Dual-stack IPv4/IPv6 resolution"
	@echo "  • IP enrichment with geolocation and ASN data"
	@echo "  • CDN detection and origin discovery"
	@echo "  • Rate limiting and OPSEC protections"
	@echo ""
	@echo "Usage examples:"
	@echo "  make deps    # Install dependencies"
	@echo "  make         # Build application"
	@echo "  make recon   # Build with reconnaissance modules"
	@echo "  make test    # Run test suite"
	@echo "  make secure  # Build with security features"
	@echo "  make install # Install system-wide"

help-recon:
	@echo "CloudUnflare Enhanced - Reconnaissance Modules (Phase 1)"
	@echo ""
	@echo "Available reconnaissance modules:"
	@echo "  • DNS Zone Transfer    - AXFR/IXFR enumeration"
	@echo "  • DNS Brute-Force     - Enhanced subdomain enumeration"
	@echo "  • HTTP Banner Grabbing - SSL analysis and fingerprinting"
	@echo "  • Port Scanner        - TCP SYN/UDP/Connect scanning"
	@echo ""
	@echo "Build targets:"
	@echo "  make recon      - Build CloudUnflare with reconnaissance modules"
	@echo "  make recon-core - Build reconnaissance modules only (development)"
	@echo ""
	@echo "Agent coordination for Phase 1 implementation:"
	@echo "  C-INTERNAL  - Core module implementation"
	@echo "  ARCHITECT   - Integration design and structure"
	@echo "  SECURITY    - OPSEC compliance and stealth features"
	@echo "  OPTIMIZER   - Performance tuning and efficiency"
	@echo ""
	@echo "Features:"
	@echo "  • OPSEC-compliant timing and evasion"
	@echo "  • Multi-threaded operations with rate limiting"
	@echo "  • Comprehensive error handling and logging"
	@echo "  • Modular design for easy extension"
	@echo "  • Integration with existing DNS enhanced capabilities"