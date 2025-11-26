# CloudClear - Multi-stage Docker Build
FROM debian:bookworm-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    make \
    libcurl4-openssl-dev \
    libssl-dev \
    libjson-c-dev \
    libncurses5-dev \
    pkg-config \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy source code
WORKDIR /build
COPY . .

# Build CloudClear
RUN make clean && make all && make tui

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libcurl4 \
    libssl3 \
    libjson-c5 \
    libncurses6 \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy built binaries from builder
COPY --from=builder /build/cloudclear /app/
COPY --from=builder /build/cloudclear-tui /app/
COPY --from=builder /build/.env.example /app/.env.example

# Copy web UI and API server
COPY web/ /app/web/
COPY api/ /app/api/

# Create virtual environment and install Python dependencies
RUN python3 -m venv /app/venv
COPY api/requirements.txt /app/api/
RUN /app/venv/bin/pip install --no-cache-dir -r /app/api/requirements.txt

# Create CloudClear config directory
RUN mkdir -p /root/.cloudclear && chmod 700 /root/.cloudclear

# Set environment variables
ENV PATH="/app:/app/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

# Expose API port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Start API server
CMD ["/app/venv/bin/python", "/app/api/server.py"]
