# CloudUnflare Enhanced v2.0

CloudUnflare Enhanced is an advanced DNS reconnaissance tool designed for security professionals and researchers. It provides a powerful and flexible platform for DNS analysis, threat detection, and network auditing.

## Key Features

- **Advanced DNS Reconnaissance**: Perform in-depth DNS analysis, including DNS over QUIC (DoQ), DNS over HTTPS (DoH), and DNS over TLS (DoT).
- **High-Performance Engine**: A multi-threaded, high-performance engine capable of handling tens of thousands of DNS queries per second.
- **Comprehensive IP Enrichment**: Enhance IP address data with geolocation, ASN, and hosting provider information.
- **CDN Detection and Analysis**: Identify Content Delivery Networks (CDNs) and discover origin servers.
- **Robust Security**: Built-in operational security (OPSEC) features, including traffic randomization, proxy rotation, and secure memory management.
- **Flexible Deployment**: Deploy with Docker for a containerized and scalable solution.

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

## Docker Deployment

For a detailed guide on deploying with Docker, please see the [Docker Deployment Guide](./README-Docker.md).

## Documentation

For more information, please refer to the documentation in the `docs/` directory.

## Legal Notice

This tool is intended for authorized security testing and research purposes only. The user is responsible for ensuring that all activities are in compliance with applicable laws and regulations.
