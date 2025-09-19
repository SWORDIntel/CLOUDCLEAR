# CloudUnflare Enhanced v2.0 - Docker Deployment Guide

This guide provides comprehensive instructions for deploying CloudUnflare Enhanced v2.0 using Docker and Portainer for container orchestration.

## 🚀 Quick Start

### 1. Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- Portainer CE/EE (optional but recommended)
- 4GB+ available RAM
- 10GB+ available disk space

### 2. Initial Setup

```bash
# Clone and prepare the repository
git clone <repository-url>
cd CloudUnflare

# Set up environment configuration
cp .env.example .env
# Edit .env with your specific configuration

# Create data directories
mkdir -p data/{config,results,recon-results,logs,wordlists,probes}

# Set up Docker networks
./docker-network.sh setup

# Configure security (generates certificates and secrets)
./docker-security.sh setup
```

### 3. Build and Deploy

```bash
# Build the Docker image
docker-compose build

# Deploy the stack
docker-compose up -d

# Verify deployment
docker-compose ps
docker-compose logs cloudunflare-main
```

## 📁 Project Structure

```
CloudUnflare/
├── Dockerfile                    # Production-optimized container image
├── docker-compose.yml           # Full deployment configuration
├── portainer-stack.yml          # Portainer-specific stack template
├── .dockerignore                # Build exclusions for clean images
├── .env.example                 # Environment configuration template
├── docker-network.sh            # Network setup and management
├── docker-security.sh           # Security configuration script
├── fluent-bit.conf              # Log aggregation configuration
├── parsers.conf                 # Log parsing rules
└── data/                        # Persistent data directory
    ├── config/                  # Application configuration
    │   ├── docker-runtime.conf  # Container-specific settings
    │   └── security/            # Security configurations
    ├── results/                 # Scan results output
    ├── recon-results/           # Reconnaissance results
    ├── logs/                    # Application logs
    ├── wordlists/               # Enumeration wordlists
    ├── probes/                  # Service detection probes
    ├── certificates/            # TLS certificates
    ├── keys/                    # Private keys
    └── secrets/                 # Application secrets
```

## 🏗️ Architecture Overview

### Container Services

#### 1. CloudUnflare Main (`cloudunflare-main`)
- **Purpose**: Primary DNS reconnaissance engine
- **Image**: `cloudunflare-enhanced:2.0`
- **Resources**: 512MB RAM, 2 CPU cores
- **Features**: DoQ/DoH/DoT, IPv6, OPSEC protections
- **Network**: `cloudunflare-network`

#### 2. CloudUnflare Reconnaissance (`cloudunflare-recon`)
- **Purpose**: Advanced reconnaissance modules
- **Image**: `cloudunflare-enhanced:2.0-recon`
- **Resources**: 1GB RAM, 4 CPU cores
- **Features**: Zone transfer, brute-force, port scanning
- **Network**: `cloudunflare-network`
- **Profile**: `recon` (optional deployment)

#### 3. Monitoring (`cloudunflare-monitor`)
- **Purpose**: System metrics collection
- **Image**: `prom/node-exporter:latest`
- **Port**: 9100 (metrics endpoint)
- **Network**: `monitoring-network`
- **Profile**: `monitoring` (optional)

#### 4. Log Aggregation (`cloudunflare-logs`)
- **Purpose**: Centralized log processing
- **Image**: `fluent/fluent-bit:latest`
- **Features**: Log parsing, filtering, forwarding
- **Network**: `monitoring-network`
- **Profile**: `logging` (optional)

### Network Architecture

#### CloudUnflare Network (`172.20.0.0/16`)
- **Purpose**: Isolated network for DNS operations
- **Features**: Custom bridge with optimized MTU
- **Security**: Network isolation and traffic control

#### Monitoring Network (`172.21.0.0/16`)
- **Purpose**: Observability and log aggregation
- **Features**: Separate network for monitoring traffic
- **Security**: Isolated from main application network

## 🛠️ Configuration

### Environment Variables

Copy `.env.example` to `.env` and customize:

```bash
# Performance Configuration
CLOUDUNFLARE_MAX_THREADS=50
CLOUDUNFLARE_DNS_TIMEOUT=30
CLOUDUNFLARE_PERFORMANCE_MODE=1

# Security Configuration
CLOUDUNFLARE_OPSEC_MODE=1
CLOUDUNFLARE_STEALTH_MODE=1
CLOUDUNFLARE_RATE_LIMITING=1

# DNS Configuration
CLOUDUNFLARE_DOH_ENABLED=1
CLOUDUNFLARE_DOQ_ENABLED=1
CLOUDUNFLARE_IPV6_ENABLED=1

# Volume Paths
CLOUDUNFLARE_CONFIG_PATH=./data/config
CLOUDUNFLARE_RESULTS_PATH=./data/results
CLOUDUNFLARE_LOGS_PATH=./data/logs
```

### Application Configuration

Edit `data/config/docker-runtime.conf`:

```ini
[general]
max_threads = 50
memory_limit_mb = 512

[dns]
doh_enabled = true
ipv6_enabled = true
default_timeout = 30

[opsec]
stealth_mode = true
rate_limiting = true
evasion_techniques = true

[security]
secure_memory = true
stack_protection = true
emergency_cleanup = true
```

## 🔒 Security Features

### Container Security
- **Non-root execution**: Runs as `cloudunflare:cloudunflare` user
- **Read-only filesystem**: Immutable root with minimal writable mounts
- **Capability restrictions**: Only NET_ADMIN, NET_RAW, SYS_PTRACE
- **Resource limits**: Memory, CPU, and PID constraints
- **Security profiles**: AppArmor/SELinux integration

### Network Security
- **Network isolation**: Custom bridges with traffic control
- **TLS encryption**: Internal communication encryption
- **DNS security**: Secure DNS-over-HTTPS/TLS/QUIC
- **Firewall integration**: iptables rules for traffic filtering

### OPSEC Compliance
- **Traffic randomization**: Timing and pattern obfuscation
- **User agent rotation**: Realistic browser simulation
- **Rate limiting**: Anti-detection request spacing
- **Circuit breaking**: Automatic detection avoidance

### Secrets Management
- **Encrypted storage**: Secure secret generation and storage
- **Certificate management**: TLS certificate automation
- **Access control**: Restrictive file permissions
- **Key rotation**: Automated credential lifecycle

## 🎯 Portainer Integration

### Portainer Stack Deployment

1. **Access Portainer**: Navigate to your Portainer instance
2. **Create Stack**: Go to Stacks → Add Stack
3. **Upload Configuration**: Use `portainer-stack.yml`
4. **Configure Environment**: Set environment variables via UI
5. **Deploy Stack**: Review and deploy the configuration

### Portainer Template Features

- **Interactive Configuration**: GUI-based environment variable setup
- **Profile Selection**: Enable/disable optional services
- **Resource Management**: Visual resource allocation
- **Health Monitoring**: Built-in health check integration
- **Log Aggregation**: Centralized logging with Portainer

### Environment Variable UI

The Portainer template provides intuitive configuration options:

- **Performance Settings**: Thread count, timeouts, resource limits
- **DNS Configuration**: Protocol support, server selection
- **Security Options**: OPSEC mode, logging levels
- **Volume Mapping**: Flexible path configuration
- **Network Settings**: DNS servers, subnet configuration

## 🚀 Deployment Scenarios

### Scenario 1: Basic DNS Reconnaissance

```bash
# Deploy main application only
docker-compose up -d cloudunflare-main

# Configure for basic DNS operations
docker exec cloudunflare-main /app/cloudunflare --help
```

### Scenario 2: Advanced Reconnaissance

```bash
# Deploy with reconnaissance modules
docker-compose --profile recon up -d

# Enable specific reconnaissance features
docker exec cloudunflare-recon /app/cloudunflare-recon --modules=dns,http
```

### Scenario 3: Production with Monitoring

```bash
# Deploy full stack with monitoring
docker-compose --profile monitoring --profile logging up -d

# Access metrics
curl http://localhost:9100/metrics
```

### Scenario 4: OPSEC-Hardened Deployment

```bash
# Configure maximum security
./docker-security.sh setup
docker-compose -f docker-compose.yml -f docker-compose.security.yml up -d
```

## 🔧 Management Commands

### Network Management

```bash
# Set up networks
./docker-network.sh setup

# Validate network configuration
./docker-network.sh validate

# Show network status
./docker-network.sh status

# Optimize network performance
./docker-network.sh optimize

# Clean up networks
./docker-network.sh cleanup
```

### Security Management

```bash
# Complete security setup
./docker-security.sh setup

# Generate TLS certificates
./docker-security.sh certs

# Create application secrets
./docker-security.sh secrets

# Validate security configuration
./docker-security.sh validate

# Show security status
./docker-security.sh status
```

### Container Management

```bash
# View stack status
docker-compose ps

# Check logs
docker-compose logs -f cloudunflare-main

# Scale services
docker-compose up -d --scale cloudunflare-main=2

# Update configuration
docker-compose down && docker-compose up -d

# Backup data
tar -czf cloudunflare-backup.tar.gz data/
```

## 📊 Monitoring and Logging

### Health Checks

All containers include comprehensive health checks:

```bash
# Check container health
docker-compose ps
docker inspect cloudunflare-main --format='{{.State.Health.Status}}'

# Manual health check
docker exec cloudunflare-main /app/healthcheck.sh
```

### Metrics Collection

With monitoring profile enabled:

```bash
# Access Prometheus metrics
curl http://localhost:9100/metrics

# View container metrics
docker stats cloudunflare-main
```

### Log Aggregation

Fluent Bit configuration provides:

- **Structured logging**: JSON format with metadata
- **Log parsing**: Custom parsers for CloudUnflare logs
- **Filtering**: Security event and performance metric separation
- **Forwarding**: Optional external log aggregation

### Performance Monitoring

Key metrics to monitor:

- **Memory usage**: Should stay under 400MB for main, 800MB for recon
- **CPU utilization**: Typically 20-40% under normal load
- **Network throughput**: Up to 10,000 DNS queries per second
- **Response times**: DNS queries under 100ms, HTTP under 2s
- **Error rates**: Should remain under 1% for DNS operations

## 🚨 Troubleshooting

### Common Issues

#### Container Won't Start
```bash
# Check logs
docker-compose logs cloudunflare-main

# Verify configuration
docker-compose config

# Check network connectivity
docker-compose exec cloudunflare-main ping 8.8.8.8
```

#### Permission Errors
```bash
# Fix data directory permissions
sudo chown -R 1000:1000 data/
chmod -R 755 data/config data/wordlists
chmod -R 750 data/results data/logs
```

#### Network Issues
```bash
# Recreate networks
./docker-network.sh cleanup
./docker-network.sh setup

# Check DNS resolution
docker-compose exec cloudunflare-main nslookup google.com
```

#### High Resource Usage
```bash
# Check resource limits
docker-compose exec cloudunflare-main cat /sys/fs/cgroup/memory/memory.limit_in_bytes

# Monitor real-time usage
docker stats cloudunflare-main

# Adjust limits in docker-compose.yml
```

### Performance Optimization

#### Memory Optimization
```bash
# Reduce thread count for memory-constrained environments
export CLOUDUNFLARE_MAX_THREADS=25

# Enable memory optimization
export CLOUDUNFLARE_MEMORY_OPTIMIZATION=1
```

#### Network Optimization
```bash
# Optimize DNS timeouts
export CLOUDUNFLARE_DNS_TIMEOUT=15

# Enable connection pooling
export CLOUDUNFLARE_CONNECTION_POOL_SIZE=50
```

#### Security vs Performance
```bash
# Balanced OPSEC mode (faster but less stealthy)
export CLOUDUNFLARE_OPSEC_MODE=0

# Maximum stealth (slower but more secure)
export CLOUDUNFLARE_STEALTH_MODE=1
export RECON_STEALTH_DELAY_MS=5000
```

## 🔐 Security Considerations

### Production Deployment Checklist

- [ ] **Environment Configuration**: Review all environment variables
- [ ] **Secret Management**: Secure API keys and certificates
- [ ] **Network Isolation**: Verify network separation
- [ ] **Resource Limits**: Set appropriate memory/CPU limits
- [ ] **Logging Security**: Configure log retention and access
- [ ] **Update Strategy**: Plan for security updates
- [ ] **Backup Procedures**: Implement data backup strategy
- [ ] **Monitoring Setup**: Deploy health and security monitoring
- [ ] **Access Control**: Restrict container and host access
- [ ] **Compliance Review**: Verify regulatory compliance

### Security Hardening

1. **Host Security**: Keep Docker host updated and secured
2. **Image Security**: Regularly update base images
3. **Network Security**: Use firewalls and network policies
4. **Secret Rotation**: Implement key rotation procedures
5. **Audit Logging**: Enable comprehensive audit trails
6. **Vulnerability Scanning**: Regular security assessments
7. **Access Control**: Implement proper RBAC
8. **Backup Security**: Encrypt backup data

## 📚 Additional Resources

- **CloudUnflare Documentation**: `docs/` directory
- **Docker Best Practices**: https://docs.docker.com/develop/dev-best-practices/
- **Portainer Documentation**: https://documentation.portainer.io/
- **Container Security**: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

## 🆘 Support

For issues and questions:

1. **Check Logs**: Review container and application logs
2. **Validate Configuration**: Verify environment and config files
3. **Network Connectivity**: Test DNS and network access
4. **Resource Monitoring**: Check memory and CPU usage
5. **Security Settings**: Verify security configuration
6. **Documentation**: Review relevant documentation sections

---

**CloudUnflare Enhanced v2.0** - High-performance DNS reconnaissance with production-ready Docker deployment and comprehensive Portainer integration.