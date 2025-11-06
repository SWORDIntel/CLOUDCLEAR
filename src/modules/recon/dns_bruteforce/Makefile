# CloudUnflare Enhanced - DNS Brute-Force Module Makefile
#
# Builds the complete Enhanced DNS Brute-Force system with all dependencies
# Supports multiple build targets: development, testing, production, and optimization
#
# Agent: C-INTERNAL (build system implementation)

# Compiler and flags
CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -O3 -fPIC
DEBUG_CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -g -O0 -DDEBUG -fsanitize=address,undefined
OPTIMIZE_CFLAGS = -std=c11 -Wall -Wextra -O3 -march=native -mtune=native -flto -ffast-math
INCLUDES = -I. -I../common -I../.. -I../../..
LIBS = -lpthread -lm -lresolv
DEBUG_LIBS = -lpthread -lm -lresolv -lasan -lubsan

# Source files
ENHANCED_SOURCES = dns_bruteforce_enhanced.c
COMMON_SOURCES = ../common/recon_common.c
DNS_SOURCES = ../../dns_enhanced.c
TEST_SOURCES = test_enhanced_bruteforce.c
EXAMPLE_SOURCES = enhanced_bruteforce_example.c

# Object files
ENHANCED_OBJECTS = $(ENHANCED_SOURCES:.c=.o)
COMMON_OBJECTS = $(COMMON_SOURCES:.c=.o)
DNS_OBJECTS = $(DNS_SOURCES:.c=.o)
TEST_OBJECTS = $(TEST_SOURCES:.c=.o)
EXAMPLE_OBJECTS = $(EXAMPLE_SOURCES:.c=.o)

# Target binaries
LIBRARY = libenhanced_bruteforce.a
SHARED_LIBRARY = libenhanced_bruteforce.so
TEST_BINARY = test_enhanced_bruteforce
EXAMPLE_BINARY = enhanced_bruteforce_example
DEBUG_TEST_BINARY = test_enhanced_bruteforce_debug
DEBUG_EXAMPLE_BINARY = enhanced_bruteforce_example_debug

# Installation directories
PREFIX = /usr/local
LIBDIR = $(PREFIX)/lib
INCLUDEDIR = $(PREFIX)/include/cloudunflare
BINDIR = $(PREFIX)/bin

# Performance test parameters
PERF_TARGET = example.com
PERF_THREADS = 50
PERF_WORDLIST = wordlists/performance_test.txt

# Default target
all: library shared test example

# Build targets
library: $(LIBRARY)
shared: $(SHARED_LIBRARY)
test: $(TEST_BINARY)
example: $(EXAMPLE_BINARY)
debug: debug-test debug-example
debug-test: $(DEBUG_TEST_BINARY)
debug-example: $(DEBUG_EXAMPLE_BINARY)

# Static library
$(LIBRARY): $(ENHANCED_OBJECTS) $(COMMON_OBJECTS) $(DNS_OBJECTS)
	@echo "🔗 Building static library: $@"
	ar rcs $@ $^
	ranlib $@
	@echo "✅ Static library built successfully"

# Shared library
$(SHARED_LIBRARY): $(ENHANCED_OBJECTS) $(COMMON_OBJECTS) $(DNS_OBJECTS)
	@echo "🔗 Building shared library: $@"
	$(CC) -shared -o $@ $^ $(LIBS)
	@echo "✅ Shared library built successfully"

# Test binary
$(TEST_BINARY): $(TEST_OBJECTS) $(LIBRARY)
	@echo "🔗 Building test binary: $@"
	$(CC) $(CFLAGS) -o $@ $(TEST_OBJECTS) $(LIBRARY) $(LIBS)
	@echo "✅ Test binary built successfully"

# Example binary
$(EXAMPLE_BINARY): $(EXAMPLE_OBJECTS) $(LIBRARY)
	@echo "🔗 Building example binary: $@"
	$(CC) $(CFLAGS) -o $@ $(EXAMPLE_OBJECTS) $(LIBRARY) $(LIBS)
	@echo "✅ Example binary built successfully"

# Debug test binary
$(DEBUG_TEST_BINARY): $(TEST_SOURCES) $(ENHANCED_SOURCES) $(COMMON_SOURCES) $(DNS_SOURCES)
	@echo "🔗 Building debug test binary: $@"
	$(CC) $(DEBUG_CFLAGS) $(INCLUDES) -o $@ $^ $(DEBUG_LIBS)
	@echo "✅ Debug test binary built successfully"

# Debug example binary
$(DEBUG_EXAMPLE_BINARY): $(EXAMPLE_SOURCES) $(ENHANCED_SOURCES) $(COMMON_SOURCES) $(DNS_SOURCES)
	@echo "🔗 Building debug example binary: $@"
	$(CC) $(DEBUG_CFLAGS) $(INCLUDES) -o $@ $^ $(DEBUG_LIBS)
	@echo "✅ Debug example binary built successfully"

# Object file compilation
%.o: %.c
	@echo "🔨 Compiling: $<"
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Optimization build
optimize: CFLAGS = $(OPTIMIZE_CFLAGS)
optimize: clean all
	@echo "🚀 Optimized build completed"

# Performance test wordlist generation
$(PERF_WORDLIST):
	@echo "📝 Generating performance test wordlist"
	@mkdir -p wordlists
	@echo "Creating $(PERF_WORDLIST) with 50,000 entries..."
	@(for i in $$(seq 1 10000); do echo "test$$i"; done; \
	  for prefix in www api admin dev test staging prod app web db mail ftp ssh vpn blog forum shop; do \
	    for i in $$(seq 1 100); do echo "$$prefix$$i"; done; \
	  done; \
	  for word in $(shell cat /usr/share/dict/words 2>/dev/null | head -20000 || echo "word1 word2 word3"); do \
	    echo "$$word"; \
	  done) | head -50000 > $(PERF_WORDLIST)
	@echo "✅ Performance wordlist created: $(PERF_WORDLIST)"

# Test targets
run-tests: $(TEST_BINARY)
	@echo "🧪 Running comprehensive test suite..."
	./$(TEST_BINARY)

run-debug-tests: $(DEBUG_TEST_BINARY)
	@echo "🐛 Running debug test suite..."
	./$(DEBUG_TEST_BINARY)

run-performance-test: $(EXAMPLE_BINARY) $(PERF_WORDLIST)
	@echo "⚡ Running performance test (target: 2000+ QPS)..."
	@echo "🎯 Target: $(PERF_TARGET)"
	@echo "🧵 Threads: $(PERF_THREADS)"
	@echo "📖 Wordlist: $(PERF_WORDLIST)"
	./$(EXAMPLE_BINARY) -d $(PERF_TARGET) -w $(PERF_WORDLIST) -s pattern -t $(PERF_THREADS) -p 1.0

run-stealth-test: $(EXAMPLE_BINARY)
	@echo "🕵️  Running stealth enumeration test..."
	./$(EXAMPLE_BINARY) -d $(PERF_TARGET) -s stealth -p 8.0 -t 5

run-comprehensive-test: $(EXAMPLE_BINARY)
	@echo "🔬 Running comprehensive enumeration test..."
	./$(EXAMPLE_BINARY) -d $(PERF_TARGET) -s hybrid -D 3 -t 20

# Validation targets
validate: run-tests
	@echo "✅ Validation completed successfully"

validate-performance: run-performance-test
	@echo "📊 Performance validation completed"

validate-all: validate validate-performance run-stealth-test run-comprehensive-test
	@echo "🎯 All validation tests completed"

# Memory leak detection
memcheck: $(DEBUG_TEST_BINARY)
	@echo "🔍 Running memory leak detection..."
	valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all --track-origins=yes ./$(DEBUG_TEST_BINARY)

# Thread safety analysis
threadcheck: $(DEBUG_TEST_BINARY)
	@echo "🔒 Running thread safety analysis..."
	valgrind --tool=helgrind ./$(DEBUG_TEST_BINARY)

# Code coverage (requires gcov)
coverage: CFLAGS += --coverage
coverage: clean $(TEST_BINARY)
	@echo "📊 Generating code coverage report..."
	./$(TEST_BINARY)
	gcov $(ENHANCED_SOURCES)
	@echo "✅ Coverage report generated"

# Static analysis
analyze:
	@echo "🔍 Running static analysis..."
	@which cppcheck >/dev/null 2>&1 && cppcheck --enable=all --std=c11 $(ENHANCED_SOURCES) $(TEST_SOURCES) $(EXAMPLE_SOURCES) || echo "⚠️  cppcheck not available"
	@which clang-tidy >/dev/null 2>&1 && clang-tidy $(ENHANCED_SOURCES) -- $(CFLAGS) $(INCLUDES) || echo "⚠️  clang-tidy not available"

# Documentation generation
docs:
	@echo "📚 Generating documentation..."
	@which doxygen >/dev/null 2>&1 && doxygen Doxyfile || echo "⚠️  doxygen not available"

# Installation
install: $(LIBRARY) $(SHARED_LIBRARY) $(EXAMPLE_BINARY)
	@echo "📦 Installing Enhanced DNS Brute-Force module..."
	install -d $(DESTDIR)$(LIBDIR)
	install -d $(DESTDIR)$(INCLUDEDIR)
	install -d $(DESTDIR)$(BINDIR)
	install -m 644 $(LIBRARY) $(DESTDIR)$(LIBDIR)/
	install -m 755 $(SHARED_LIBRARY) $(DESTDIR)$(LIBDIR)/
	install -m 644 dns_bruteforce_enhanced.h $(DESTDIR)$(INCLUDEDIR)/
	install -m 755 $(EXAMPLE_BINARY) $(DESTDIR)$(BINDIR)/
	ldconfig
	@echo "✅ Installation completed"

# Uninstallation
uninstall:
	@echo "🗑️  Uninstalling Enhanced DNS Brute-Force module..."
	rm -f $(DESTDIR)$(LIBDIR)/$(LIBRARY)
	rm -f $(DESTDIR)$(LIBDIR)/$(SHARED_LIBRARY)
	rm -f $(DESTDIR)$(INCLUDEDIR)/dns_bruteforce_enhanced.h
	rm -f $(DESTDIR)$(BINDIR)/$(EXAMPLE_BINARY)
	ldconfig
	@echo "✅ Uninstallation completed"

# Packaging
package: clean all docs
	@echo "📦 Creating distribution package..."
	@VERSION=$$(date +%Y%m%d_%H%M%S); \
	PKG_DIR="enhanced_dns_bruteforce_$$VERSION"; \
	mkdir -p $$PKG_DIR/{src,include,bin,docs,examples,wordlists}; \
	cp $(ENHANCED_SOURCES) $(TEST_SOURCES) $(EXAMPLE_SOURCES) $$PKG_DIR/src/; \
	cp dns_bruteforce_enhanced.h $$PKG_DIR/include/; \
	cp $(LIBRARY) $(SHARED_LIBRARY) $$PKG_DIR/bin/ 2>/dev/null || true; \
	cp $(TEST_BINARY) $(EXAMPLE_BINARY) $$PKG_DIR/bin/ 2>/dev/null || true; \
	cp Makefile README.md $$PKG_DIR/; \
	cp -r docs/html $$PKG_DIR/docs/ 2>/dev/null || true; \
	cp wordlists/* $$PKG_DIR/wordlists/ 2>/dev/null || true; \
	tar -czf $$PKG_DIR.tar.gz $$PKG_DIR; \
	rm -rf $$PKG_DIR; \
	echo "✅ Package created: $$PKG_DIR.tar.gz"

# Benchmarking
benchmark: $(EXAMPLE_BINARY) $(PERF_WORDLIST)
	@echo "⚡ Running comprehensive benchmarks..."
	@echo "=== Basic Wordlist Benchmark ==="
	time ./$(EXAMPLE_BINARY) -d $(PERF_TARGET) -w $(PERF_WORDLIST) -s wordlist -t 10 -q
	@echo ""
	@echo "=== Pattern Generation Benchmark ==="
	time ./$(EXAMPLE_BINARY) -d $(PERF_TARGET) -s pattern -t $(PERF_THREADS) -q
	@echo ""
	@echo "=== Hybrid Strategy Benchmark ==="
	time ./$(EXAMPLE_BINARY) -d $(PERF_TARGET) -w $(PERF_WORDLIST) -s hybrid -t $(PERF_THREADS) -D 2 -q
	@echo "✅ Benchmarking completed"

# Cleanup targets
clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -f *.o ../*.o ../../*.o
	rm -f $(LIBRARY) $(SHARED_LIBRARY)
	rm -f $(TEST_BINARY) $(EXAMPLE_BINARY)
	rm -f $(DEBUG_TEST_BINARY) $(DEBUG_EXAMPLE_BINARY)
	rm -f *.gcov *.gcda *.gcno
	rm -f core core.*
	@echo "✅ Cleanup completed"

clean-all: clean
	@echo "🧹 Deep cleaning..."
	rm -rf wordlists/
	rm -rf docs/html/
	rm -f *.tar.gz
	@echo "✅ Deep cleanup completed"

# Continuous Integration targets
ci-test: clean all run-tests validate-performance
	@echo "🤖 CI testing completed successfully"

ci-full: clean all run-tests validate-performance memcheck analyze
	@echo "🤖 Full CI pipeline completed successfully"

# Help target
help:
	@echo "CloudUnflare Enhanced DNS Brute-Force - Build System"
	@echo "=================================================="
	@echo ""
	@echo "Build Targets:"
	@echo "  all                  - Build library, shared library, test, and example"
	@echo "  library              - Build static library"
	@echo "  shared               - Build shared library"
	@echo "  test                 - Build test binary"
	@echo "  example              - Build example binary"
	@echo "  debug                - Build debug versions"
	@echo "  optimize             - Build optimized versions"
	@echo ""
	@echo "Test Targets:"
	@echo "  run-tests            - Run comprehensive test suite"
	@echo "  run-performance-test - Run performance validation (2000+ QPS target)"
	@echo "  run-stealth-test     - Run stealth enumeration test"
	@echo "  run-comprehensive-test - Run comprehensive enumeration test"
	@echo "  validate             - Run all validation tests"
	@echo "  validate-all         - Run complete validation suite"
	@echo ""
	@echo "Analysis Targets:"
	@echo "  memcheck             - Memory leak detection with Valgrind"
	@echo "  threadcheck          - Thread safety analysis"
	@echo "  coverage             - Code coverage analysis"
	@echo "  analyze              - Static code analysis"
	@echo "  benchmark            - Performance benchmarking"
	@echo ""
	@echo "Utility Targets:"
	@echo "  docs                 - Generate documentation"
	@echo "  install              - Install system-wide"
	@echo "  uninstall            - Remove system installation"
	@echo "  package              - Create distribution package"
	@echo "  clean                - Remove build artifacts"
	@echo "  clean-all            - Deep cleanup"
	@echo ""
	@echo "CI Targets:"
	@echo "  ci-test              - Continuous integration testing"
	@echo "  ci-full              - Full CI pipeline"

# Phony targets
.PHONY: all library shared test example debug debug-test debug-example optimize
.PHONY: run-tests run-debug-tests run-performance-test run-stealth-test run-comprehensive-test
.PHONY: validate validate-performance validate-all
.PHONY: memcheck threadcheck coverage analyze benchmark
.PHONY: docs install uninstall package
.PHONY: clean clean-all ci-test ci-full help

# Default goal
.DEFAULT_GOAL := all