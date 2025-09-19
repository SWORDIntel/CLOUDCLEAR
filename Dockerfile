# CloudUnflare Enhanced v2.0 - Production Docker Image
# High-performance DNS reconnaissance tool with OPSEC capabilities
# Optimized for Portainer deployment and container orchestration

FROM ubuntu:22.04 AS base

# Set noninteractive frontend to avoid prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies for CloudUnflare Enhanced
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libcurl4-openssl-dev \
    libssl-dev \
    libjson-c-dev \
    libatomic1 \
    ca-certificates \
    dnsutils \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create application user for security
RUN groupadd -r cloudunflare && useradd -r -g cloudunflare -s /bin/bash cloudunflare

# Set working directory
WORKDIR /app

# Copy source files and build system
COPY cloudunflare.c dns_enhanced.c dns_enhanced.h config.h ./
COPY Makefile* ./
COPY recon_modules/ ./recon_modules/
COPY performance_modules/ ./performance_modules/

# Build stage - compile different variants
FROM base AS builder

# Build all variants for flexibility
RUN make clean && make check && make all
RUN make clean && make recon
RUN make clean && make thread-safe
RUN make clean && make secure

# Create final production image
FROM ubuntu:22.04 AS production

# Install only runtime dependencies
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    libcurl4 \
    libssl3 \
    libjson-c5 \
    libatomic1 \
    ca-certificates \
    dnsutils \
    net-tools \
    iputils-ping \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create application user and directories
RUN groupadd -r cloudunflare && useradd -r -g cloudunflare -s /bin/bash cloudunflare
RUN mkdir -p /app /app/config /app/results /app/logs /app/wordlists /app/probes

# Copy compiled binaries from builder
COPY --from=builder /app/cloudunflare /app/cloudunflare-recon /app/cloudunflare-thread-safe /app/cloudunflare-secure /app/
COPY --from=builder /app/test_zone_transfer /app/zone_transfer_example /app/

# Copy configuration and wordlists
COPY subdomains.txt /app/wordlists/
COPY config.h /app/config/

# Create default configuration files
RUN echo "# CloudUnflare Enhanced Configuration" > /app/config/cloudunflare.conf && \
    echo "MAX_THREADS=50" >> /app/config/cloudunflare.conf && \
    echo "DNS_TIMEOUT=30" >> /app/config/cloudunflare.conf && \
    echo "OPSEC_MODE=1" >> /app/config/cloudunflare.conf && \
    echo "LOG_LEVEL=1" >> /app/config/cloudunflare.conf

# Create healthcheck script
RUN echo '#!/bin/bash' > /app/healthcheck.sh && \
    echo 'timeout 10 /app/cloudunflare --version >/dev/null 2>&1' >> /app/healthcheck.sh && \
    chmod +x /app/healthcheck.sh

# Set ownership and permissions
RUN chown -R cloudunflare:cloudunflare /app && \
    chmod +x /app/cloudunflare* && \
    chmod 750 /app/results /app/logs && \
    chmod 755 /app/config /app/wordlists

# Environment variables for configuration
ENV CLOUDUNFLARE_CONFIG_PATH=/app/config
ENV CLOUDUNFLARE_RESULTS_PATH=/app/results
ENV CLOUDUNFLARE_LOGS_PATH=/app/logs
ENV CLOUDUNFLARE_WORDLISTS_PATH=/app/wordlists
ENV CLOUDUNFLARE_MAX_THREADS=50
ENV CLOUDUNFLARE_DNS_TIMEOUT=30
ENV CLOUDUNFLARE_OPSEC_MODE=1
ENV CLOUDUNFLARE_LOG_LEVEL=1

# Expose ports for advanced DNS operations (optional)
# Port 53 for DNS queries (if running custom DNS server)
# Port 853 for DNS-over-TLS
# Port 443 for DNS-over-HTTPS
EXPOSE 53/udp 53/tcp 853/tcp 443/tcp

# Set working directory
WORKDIR /app

# Switch to non-root user
USER cloudunflare

# Health check for container monitoring
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD /app/healthcheck.sh

# Default command - interactive mode
CMD ["/app/cloudunflare"]

# Build arguments for customization
ARG BUILD_VERSION="2.0-Enhanced"
ARG BUILD_DATE
ARG BUILD_VARIANT="standard"

# Labels for container management
LABEL org.opencontainers.image.title="CloudUnflare Enhanced"
LABEL org.opencontainers.image.description="High-performance DNS reconnaissance tool with OPSEC capabilities"
LABEL org.opencontainers.image.version="${BUILD_VERSION}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.vendor="CloudUnflare Enhanced Project"
LABEL org.opencontainers.image.source="https://github.com/user/cloudunflare-enhanced"
LABEL maintainer="cloudunflare@example.com"
LABEL cloudunflare.variant="${BUILD_VARIANT}"
LABEL cloudunflare.features="DoQ,DoH,DoT,IPv6,OPSEC,Threading,Reconnaissance"
LABEL cloudunflare.performance="10000QPS,50-threads,sub-500MB"