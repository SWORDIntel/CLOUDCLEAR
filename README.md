# CloudUnflare Enhanced v2.0

CloudUnflare Enhanced is an advanced DNS reconnaissance tool designed for security professionals and researchers. It provides a powerful and flexible platform for DNS analysis, threat detection, and network auditing.

## Architecture

The project is built with a modular C architecture, designed for performance and security. Key components include:

- **`cloudunflare.c`**: The main application logic and entry point.
- **`dns_enhanced.c` / `dns_enhanced.h`**: The core DNS engine, handling DoQ, DoH, and DoT, as well as performance and security features.
- **`config.h`**: A central configuration file for tuning performance, security, and operational parameters.
- **Reconnaissance Modules**: A suite of modules for advanced reconnaissance tasks, such as zone transfers, port scanning, and banner grabbing.
- **Performance Modules**: A collection of modules designed to optimize performance, including multi-threading and connection pooling.

## Key Features & Capabilities

- **Advanced DNS Reconnaissance**:
  - DNS over QUIC (DoQ), DNS over HTTPS (DoH), and DNS over TLS (DoT).
  - Dual-stack IPv4/IPv6 resolution.
  - 33+ pre-configured and verified DoH providers with automatic rotation.

- **High-Performance Engine**:
  - Multi-threaded architecture, supporting up to 50 concurrent threads.
  - Capable of 10,000+ DNS queries per second.
  - Sub-millisecond response correlation for accurate timing analysis.

- **IP Enrichment and Analysis**:
  - Geolocation, ASN, and hosting provider detection.
  - CDN (Content Delivery Network) detection and origin server discovery.
  - Certificate Transparency log mining for subdomain discovery.

- **Operational Security (OPSEC)**:
  - Advanced evasion techniques with randomized timing and traffic patterns.
  - Proxy circuit rotation and user agent randomization.
  - Secure memory wiping and emergency cleanup handlers.
  - Real-time threat monitoring and adaptive evasion.

- **Reconnaissance Modules**:
  - DNS zone transfer enumeration.
  - Enhanced DNS brute-forcing.
  - HTTP banner grabbing.
  - Port scanning and service detection.
  - SSL/TLS analysis and vulnerability checks.

## Getting Started

### Prerequisites

- `libcurl`
- `openssl`
- `json-c`

### Installation

1. **Install Dependencies**:
   ```bash
   sudo apt-get update
   sudo apt-get install -y libcurl4-openssl-dev libssl-dev libjson-c-dev
   ```

2. **Compile from Source**:
   ```bash
   make
   ```

3. **Run the Application**:
   ```bash
   ./cloudunflare
   ```

## Configuration

The application can be configured by editing the `config.h` file. Key options include:

- **Performance Tuning**:
  - `MAX_CONCURRENT_THREADS`: The maximum number of concurrent threads.
  - `MAX_DNS_TIMEOUT`, `MAX_HTTP_TIMEOUT`: Timeouts for DNS and HTTP requests.
  - `CONNECTION_POOL_SIZE`: The size of the connection pool.

- **OPSEC and Evasion**:
  - `MIN_REQUEST_DELAY_MS`, `MAX_REQUEST_DELAY_MS`: The minimum and maximum delay between requests.
  - `JITTER_BASE_MS`, `JITTER_RANGE_MS`: The base and range for request jitter.
  - `MAX_PROXY_CHAIN_LENGTH`: The maximum number of proxies in a chain.
  - `PROXY_ROTATION_INTERVAL`: The number of requests before rotating proxies.

- **Security Features**:
  - `ENABLE_SECURE_MEMORY`: Enable secure memory management.
  - `ENABLE_CANARY_PROTECTION`: Enable stack canary protection.
  - `ENABLE_EMERGENCY_CLEANUP`: Enable emergency memory cleanup.

- **Feature Flags**:
  - `FEATURE_CERTIFICATE_TRANSPARENCY`: Enable Certificate Transparency log mining.
  - `FEATURE_SUBDOMAIN_ENUMERATION`: Enable subdomain enumeration.
  - `RECON_MODULES_ENABLED`: Enable the advanced reconnaissance modules.

## Docker Deployment

For a detailed guide on deploying with Docker, please see the [Docker Deployment Guide](./README-Docker.md).

## Documentation

For more information, please refer to the documentation in the `docs/` directory.

## Legal Notice

This tool is intended for authorized security testing and research purposes only. The user is responsible for ensuring that all activities are in compliance with applicable laws and regulations.
