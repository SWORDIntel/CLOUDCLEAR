# CloudClear (CloudUnflare Enhanced) v2.0 - Production Docker Image
# High-performance DNS reconnaissance tool with OPSEC capabilities
# Optimized for Portainer deployment and container orchestration

FROM ubuntu:22.04 AS base

# Set noninteractive frontend to avoid prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libcurl4-openssl-dev \
    libssl-dev \
    libjson-c-dev \
    libncurses-dev \
    libatomic1 \
    ca-certificates \
    dnsutils \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create application user for security
RUN groupadd -r cloudclear && useradd -r -g cloudclear -s /bin/bash cloudclear

# Set working directory
WORKDIR /build

# Copy source files and build system
COPY src/ ./src/
COPY include/ ./include/
COPY Makefile ./
COPY .env.example ./

# Build stage - compile variants
FROM base AS builder

# Build all variants for flexibility
RUN make clean && make all
RUN make tui || echo "TUI build skipped"
RUN make recon

# Create final production image
FROM ubuntu:22.04 AS production

# Install only runtime dependencies
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    libcurl4 \
    libssl3 \
    libjson-c5 \
    libncurses6 \
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
RUN groupadd -r cloudclear && useradd -r -g cloudclear -s /bin/bash cloudclear
RUN mkdir -p /app /app/config /app/results /app/logs /app/wordlists /app/probes /app/data

# Copy compiled binaries from builder
COPY --from=builder /build/cloudclear /build/cloudclear-tui /build/cloudclear-recon /app/
COPY --from=builder /build/include/config.h /app/config/

# Copy data and configuration
COPY data/ /app/data/
COPY docker/.dockerignore /app/

# Create default configuration files
RUN echo "# CloudClear Configuration" > /app/config/cloudclear.conf && \
    echo "MAX_THREADS=50" >> /app/config/cloudclear.conf && \
    echo "DNS_TIMEOUT=30" >> /app/config/cloudclear.conf && \
    echo "OPSEC_MODE=1" >> /app/config/cloudclear.conf && \
    echo "LOG_LEVEL=1" >> /app/config/cloudclear.conf

# Create healthcheck script
RUN echo '#!/bin/bash' > /app/healthcheck.sh && \
    echo 'if [ -f /app/cloudclear ]; then' >> /app/healthcheck.sh && \
    echo '  exit 0' >> /app/healthcheck.sh && \
    echo 'else' >> /app/healthcheck.sh && \
    echo '  exit 1' >> /app/healthcheck.sh && \
    echo 'fi' >> /app/healthcheck.sh && \
    chmod +x /app/healthcheck.sh

# Set ownership and permissions
RUN chown -R cloudclear:cloudclear /app && \
    chmod +x /app/cloudclear* 2>/dev/null || true && \
    chmod 750 /app/results /app/logs 2>/dev/null || true && \
    chmod 755 /app/config /app/wordlists 2>/dev/null || true

# Environment variables for configuration
ENV CLOUDCLEAR_CONFIG_PATH=/app/config
ENV CLOUDCLEAR_RESULTS_PATH=/app/results
ENV CLOUDCLEAR_LOGS_PATH=/app/logs
ENV CLOUDCLEAR_WORDLISTS_PATH=/app/wordlists
ENV CLOUDCLEAR_MAX_THREADS=50
ENV CLOUDCLEAR_DNS_TIMEOUT=30
ENV CLOUDCLEAR_OPSEC_MODE=1
ENV CLOUDCLEAR_LOG_LEVEL=1

# Expose ports for advanced DNS operations (optional)
EXPOSE 53/udp 53/tcp 853/tcp 443/tcp

# Set working directory
WORKDIR /app

# Switch to non-root user
USER cloudclear

# Health check for container monitoring
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD /app/healthcheck.sh

# Default command - interactive mode
CMD ["/app/cloudclear"]

# Build arguments for customization
ARG BUILD_VERSION="2.0-Enhanced"
ARG BUILD_DATE
ARG BUILD_VARIANT="standard"

# Labels for container management
LABEL org.opencontainers.image.title="CloudClear (CloudUnflare Enhanced)"
LABEL org.opencontainers.image.description="High-performance DNS reconnaissance tool with OPSEC capabilities"
LABEL org.opencontainers.image.version="${BUILD_VERSION}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.vendor="CloudClear Project"
LABEL org.opencontainers.image.source="https://github.com/SWORDIntel/CLOUDCLEAR"
LABEL maintainer="cloudclear@swordint.com"
LABEL cloudclear.variant="${BUILD_VARIANT}"
LABEL cloudclear.features="DoQ,DoH,DoT,IPv6,OPSEC,Threading,Reconnaissance,TUI"
LABEL cloudclear.performance="10000QPS,50-threads,sub-500MB"
