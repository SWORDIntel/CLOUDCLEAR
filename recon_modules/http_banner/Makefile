# CloudUnflare Enhanced - HTTP Banner Grabbing Makefile
# C-INTERNAL Implementation Build System

CC = gcc
CFLAGS = -Wall -Wextra -O3 -march=native -mtune=native -flto
CFLAGS += -D_GNU_SOURCE -DRECON_MODULES_ENABLED
CFLAGS += -ffast-math -funroll-loops -finline-functions

# Include directories
INCLUDES = -I. -I../common -I../../ -I/usr/include/curl -I/usr/include/openssl

# Libraries
LIBS = -lcurl -lssl -lcrypto -lpthread -lm

# Source files
SOURCES = http_banner.c http_banner_advanced.c ../common/recon_common.c
TEST_SOURCES = http_banner_test.c http_banner.c http_banner_advanced.c ../common/recon_common.c

# Object files
OBJECTS = $(SOURCES:.c=.o)
TEST_OBJECTS = $(TEST_SOURCES:.c=.o)

# Target executables
TARGET = http_banner_demo
TEST_TARGET = http_banner_test
LIBRARY = libhttp_banner.a

# Default target
all: demo-program $(TARGET) $(TEST_TARGET) $(LIBRARY)

# Demo program source
demo-program:
	@echo "/* HTTP Banner Demo Program */" > http_banner_demo.c
	@echo '#include "http_banner.h"' >> http_banner_demo.c
	@echo 'int main() {' >> http_banner_demo.c
	@echo '    printf("HTTP Banner Demo - C-INTERNAL Implementation\\n");' >> http_banner_demo.c
	@echo '    return 0;' >> http_banner_demo.c
	@echo '}' >> http_banner_demo.c

# Main demo executable
$(TARGET): $(OBJECTS) http_banner_demo.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ http_banner_demo.c $(OBJECTS) $(LIBS)

# Test executable
$(TEST_TARGET): $(TEST_OBJECTS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(TEST_OBJECTS) $(LIBS)

# Static library
$(LIBRARY): $(OBJECTS)
	ar rcs $@ $(OBJECTS)

# Object file compilation
%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(OBJECTS) $(TEST_OBJECTS)
	rm -f $(TARGET) $(TEST_TARGET) $(LIBRARY)
	rm -f http_banner_demo.c
	rm -f *.json *.csv

# Install dependencies
install-deps:
	@echo "Installing dependencies..."
	sudo apt-get update
	sudo apt-get install -y libcurl4-openssl-dev libssl-dev build-essential

# Run tests
test: $(TEST_TARGET)
	./$(TEST_TARGET)

# Run demo
demo: $(TARGET)
	./$(TARGET)

# Build information
info:
	@echo "=== HTTP Banner Grabbing Build Information ==="
	@echo "Agent: C-INTERNAL"
	@echo "Phase: 1 Implementation (Days 5-6)"
	@echo "Performance Target: 1500+ banner grabs/second"
	@echo "Features: SSL analysis, technology detection, security headers"
	@echo "Integration: OPSEC-compliant with existing framework"

.PHONY: all clean install-deps test demo info demo-program