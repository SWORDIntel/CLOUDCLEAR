# CloudClear Quick Start Guide

Get up and running with CloudClear in 5 minutes using Docker.

## Prerequisites

- Docker 20.10+ installed
- Docker Compose 2.0+ installed
- 2GB+ available RAM
- Internet connectivity

## 🚀 Fastest Start (Docker Compose)

### 1. Clone and Start

```bash
# Clone the repository
git clone https://github.com/SWORDIntel/CLOUDCLEAR.git
cd CLOUDCLEAR

# Start CloudClear
cd docker && docker-compose up -d

# Check status
docker-compose ps
```

### 2. Run Your First Scan

```bash
# Basic origin IP discovery
docker exec -it cloudclear-main /app/cloudclear -d example.com

# With verbose output
docker exec -it cloudclear-main /app/cloudclear -d example.com -v
```

### 3. Enable Advanced Features

```bash
# Start reconnaissance modules
docker-compose --profile recon up -d

# Run full reconnaissance
docker exec -it cloudclear-recon /app/cloudclear-recon -d example.com --all-modules

# Use interactive TUI
docker-compose --profile interactive up cloudclear-tui
```

## 📋 Common Operations

### View Results

```bash
# Copy results from container
docker cp cloudclear-main:/app/results/example.com_results.json ./

# View logs
docker-compose logs -f cloudclear-main

# Check container status
docker-compose ps
```

### Configuration

```bash
# Edit environment variables
nano .env

# Restart with new config
docker-compose down && docker-compose up -d
```

### Stop and Clean Up

```bash
# Stop all services
docker-compose down

# Remove volumes (careful!)
docker-compose down -v

# Remove images
docker rmi cloudclear:2.0
```

## 🎯 Use Case Examples

### Penetration Testing

```bash
# Discover origin IPs with OPSEC mode
docker exec -it cloudclear-main /app/cloudclear -d target.com --opsec --rate-limit 50

# Enumerate subdomains
docker exec -it cloudclear-recon /app/cloudclear-recon -d target.com --subdomain-brute

# Test for zone transfers
docker exec -it cloudclear-recon /app/cloudclear-recon -d target.com --zone-transfer
```

### Bug Bounty

```bash
# Quick recon with all modules
docker exec -it cloudclear-recon /app/cloudclear-recon -d target.com --all-modules

# Export results to JSON
docker exec -it cloudclear-main /app/cloudclear -d target.com --output json > results.json

# Subdomain enumeration with custom wordlist
docker cp my-wordlist.txt cloudclear-recon:/app/wordlists/
docker exec -it cloudclear-recon /app/cloudclear-recon -d target.com --subdomain-brute --wordlist /app/wordlists/my-wordlist.txt
```

### Red Team Operations

```bash
# Maximum stealth with OPSEC
docker exec -it cloudclear-main /app/cloudclear -d target.com \
  --opsec \
  --rate-limit 10 \
  --threads 5 \
  --dot

# Distribute queries across DNS protocols
docker exec -it cloudclear-main /app/cloudclear -d target.com \
  --doh \
  --rotate-protocols
```

## 🔧 Advanced Configuration

### Custom DNS Servers

```bash
# Use custom DoH server
docker exec -it cloudclear-main /app/cloudclear -d target.com \
  --doh \
  --doh-server https://dns.custom.com/dns-query

# Use specific DNS resolver
docker exec -it cloudclear-main /app/cloudclear -d target.com \
  --resolver 1.1.1.1
```

### Performance Tuning

```bash
# High-performance mode (more threads)
docker exec -it cloudclear-main /app/cloudclear -d target.com --threads 100

# Low-resource mode
docker exec -it cloudclear-main /app/cloudclear -d target.com --threads 10 --mem-limit 256
```

### Output Formats

```bash
# JSON output
docker exec -it cloudclear-main /app/cloudclear -d target.com --output json

# CSV output
docker exec -it cloudclear-main /app/cloudclear -d target.com --output csv

# Detailed report
docker exec -it cloudclear-main /app/cloudclear -d target.com --output report
```

## 🐛 Troubleshooting

### Container Won't Start

```bash
# Check logs
docker-compose logs cloudclear-main

# Verify Docker resources
docker system df

# Rebuild image
docker-compose build --no-cache
docker-compose up -d
```

### Permission Errors

```bash
# Fix volume permissions
docker-compose down
sudo chown -R $(id -u):$(id -g) data/
docker-compose up -d
```

### Network Issues

```bash
# Check network connectivity
docker exec cloudclear-main ping 8.8.8.8
docker exec cloudclear-main nslookup google.com

# Recreate networks
docker-compose down
docker network prune
docker-compose up -d
```

### Performance Issues

```bash
# Check resource usage
docker stats cloudclear-main

# Adjust resource limits in docker-compose.yml
nano docker/docker-compose.yml

# Reduce thread count
docker exec cloudclear-main /app/cloudclear -d target.com --threads 25
```

## 📚 Next Steps

- Read the [full documentation](docs/)
- Learn about [Docker deployment](docs/DOCKER.md)
- Explore [TUI features](docs/TUI_GUIDE.md)
- Understand [advanced IP detection](docs/ADVANCED_IP_DETECTION.md)
- Review [API documentation](docs/api/)

## 🔒 Security Reminder

Always obtain proper authorization before testing any systems. CloudClear is designed for authorized security testing only.

## 💡 Tips

1. **Start with Docker** - It's the easiest and most reliable deployment method
2. **Use OPSEC mode** for real engagements to avoid detection
3. **Adjust rate limits** based on target sensitivity
4. **Save results** regularly using `docker cp`
5. **Monitor resources** with `docker stats`
6. **Read the logs** when troubleshooting: `docker-compose logs -f`

## ⚡ One-Liner Examples

```bash
# Quick scan and copy results
docker exec cloudclear-main /app/cloudclear -d target.com && \
docker cp cloudclear-main:/app/results/target.com_results.json ./

# Full recon pipeline
docker exec cloudclear-recon /app/cloudclear-recon -d target.com --all-modules \
  --output json > target_recon.json

# Interactive TUI session
docker-compose --profile interactive up cloudclear-tui

# Stealth scan with minimal footprint
docker exec cloudclear-main /app/cloudclear -d target.com --opsec --rate-limit 5 --threads 3
```

---

**Need Help?**

- Check [documentation](docs/)
- Open an [issue](https://github.com/SWORDIntel/CLOUDCLEAR/issues)
- Review [examples](#-use-case-examples) above
