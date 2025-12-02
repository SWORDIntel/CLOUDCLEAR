# CloudClear - Docker Deployment Guide

## 🚀 Quick Start

### **One-Command Deployment:**

```bash
docker-compose up -d
```

Access CloudClear at: **https://scan.cloudclear.local**

---

## 📋 Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- Domain name (for production with HTTPS)
- Ports 80, 443 available

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       Internet                               │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       │ HTTPS (443) / HTTP (80)
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                  Caddy Reverse Proxy                         │
│  - Automatic HTTPS (Let's Encrypt)                          │
│  - HTTP/3 Support                                           │
│  - Security Headers (TEMPEST Class C)                       │
│  - Static File Serving                                      │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       │ HTTP (8080)
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              CloudClear API Server                           │
│  - Flask REST API                                           │
│  - WebSocket Support                                        │
│  - CloudClear Binary Wrapper                                │
│  - Real-time Scan Updates                                   │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       │ Execute
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                CloudClear Binary (C)                         │
│  - 20+ Cloud Provider Detection                             │
│  - DNS, HTTP, Certificate Analysis                          │
│  - Intelligence API Integration                             │
└─────────────────────────────────────────────────────────────┘
```

---

## ⚙️ Configuration

### 1. **Environment Variables**

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

### 2. **Domain Configuration**

Edit `docker-compose.yml` or set environment variables:

```yaml
environment:
  - CLOUDCLEAR_DOMAIN=yourdomain.com
  - CLOUDCLEAR_SUBDOMAIN=scan  # Creates scan.yourdomain.com
```

### 3. **API Keys** (Optional but recommended)

Add to `.env`:

```bash
# Intelligence Services
SHODAN_API_KEY=your_key_here
CENSYS_API_ID=your_id_here
CENSYS_API_SECRET=your_secret_here
VIRUSTOTAL_API_KEY=your_key_here

# Cloud Providers
AKAMAI_CLIENT_TOKEN=your_token_here
AWS_ACCESS_KEY_ID=your_key_here
AZURE_CLIENT_ID=your_id_here
# ... etc
```

---

## 🚢 Deployment Options

### **Option 1: Local Development**

```bash
# Start services
docker-compose up

# Access at: http://scan.cloudclear.local (add to /etc/hosts)
```

### **Option 2: Production with Custom Domain**

1. **Update `.env`:**
   ```bash
   CLOUDCLEAR_DOMAIN=yourdomain.com
   CLOUDCLEAR_SUBDOMAIN=scan
   ```

2. **DNS Configuration:**
   - Point `scan.yourdomain.com` to your server IP
   - Caddy will automatically get Let's Encrypt certificate

3. **Deploy:**
   ```bash
   docker-compose up -d
   ```

4. **Access:**
   - https://scan.yourdomain.com

### **Option 3: Behind Existing Reverse Proxy**

If you already have Nginx/Traefik:

1. **Remove Caddy from `docker-compose.yml`**

2. **Expose API port:**
   ```yaml
   cloudclear-api:
     ports:
       - "8080:8080"
   ```

3. **Configure your proxy** to forward to port 8080

---

## 📁 File Structure

```
CloudClear/
├── docker-compose.yml       # Docker Compose configuration
├── Dockerfile              # Multi-stage build
├── Caddyfile              # Caddy reverse proxy config
├── .env                   # Environment variables
├── api/
│   ├── server.py          # Flask API server
│   └── requirements.txt   # Python dependencies
└── web/
    ├── index.html         # TEMPEST Class C UI
    ├── css/
    │   └── tempest-class-c.css
    ├── js/
    │   └── app.js
    └── 404.html
```

---

## 🔒 Security Features

### **TEMPEST Class C Security Headers**

Caddy automatically applies:
- Strict-Transport-Security (HSTS)
- X-Content-Type-Options
- X-Frame-Options
- X-XSS-Protection
- Content-Security-Policy
- Referrer-Policy

### **Network Isolation**

- Services run in isolated bridge network
- API not directly exposed to internet
- All traffic goes through Caddy

### **API Key Security**

- Stored as environment variables
- Never committed to git
- Passed securely to containers

---

## 📊 Monitoring

### **Health Check**

```bash
curl https://scan.yourdomain.com/api/health
```

Response:
```json
{
  "status": "healthy",
  "version": "2.0-Enhanced-Cloud",
  "active_scans": 0,
  "system": {
    "cpu_percent": 5.2,
    "memory_percent": 45.3,
    "disk_percent": 30.1
  }
}
```

### **Logs**

```bash
# View all logs
docker-compose logs -f

# API logs only
docker-compose logs -f cloudclear-api

# Caddy logs
docker-compose logs -f caddy
```

### **Container Status**

```bash
docker-compose ps
```

---

## 🔧 Management

### **Start Services**
```bash
docker-compose up -d
```

### **Stop Services**
```bash
docker-compose down
```

### **Restart Services**
```bash
docker-compose restart
```

### **Update Configuration**
```bash
# Edit .env or docker-compose.yml
docker-compose down
docker-compose up -d
```

### **View Logs**
```bash
docker-compose logs -f cloudclear-api
```

### **Rebuild Images**
```bash
docker-compose build --no-cache
docker-compose up -d
```

---

## 🌐 Web UI Features

### **TEMPEST Class C Interface**

- **Dark military-grade theme**
- **High contrast design**
- **Real-time scan updates via WebSocket**
- **Security classification banner**
- **Responsive layout**
- **Toast notifications**

### **Endpoints**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main web interface |
| `/api/v1/info` | GET | System information |
| `/api/v1/scan` | POST | Start scan |
| `/api/v1/scan/{id}` | GET | Get scan status |
| `/api/v1/scans` | GET | List all scans |
| `/api/v1/config` | GET | Configuration status |
| `/api/health` | GET | Health check |
| `/ws` | WebSocket | Real-time updates |

---

## 🐛 Troubleshooting

### **Containers Won't Start**

```bash
# Check logs
docker-compose logs

# Check port conflicts
sudo netstat -tulpn | grep -E '(80|443|8080)'
```

### **Can't Access Web UI**

1. Check DNS: `nslookup scan.yourdomain.com`
2. Check firewall: Ports 80, 443 open
3. Check Caddy logs: `docker-compose logs caddy`

### **Scans Failing**

1. Check API logs: `docker-compose logs cloudclear-api`
2. Verify binary works: `docker-compose exec cloudclear-api ./cloudclear example.com`
3. Check API keys configured: `docker-compose exec cloudclear-api env | grep API_KEY`

### **WebSocket Not Connecting**

1. Verify WebSocket upgrade headers in Caddy
2. Check browser console for errors
3. Try disabling ad blockers

---

## 🔄 Updates

### **Update CloudClear**

```bash
git pull
docker-compose build --no-cache
docker-compose up -d
```

### **Update Individual Service**

```bash
docker-compose up -d --build cloudclear-api
```

---

## 📈 Performance

### **Scaling API Workers**

Edit `docker-compose.yml`:

```yaml
environment:
  - API_WORKERS=8  # Increase for more concurrent scans
```

### **Resource Limits**

Add to `docker-compose.yml`:

```yaml
cloudclear-api:
  deploy:
    resources:
      limits:
        cpus: '2.0'
        memory: 2G
      reservations:
        cpus: '1.0'
        memory: 1G
```

---

## 🎯 Production Checklist

- [ ] Configure custom domain
- [ ] Set up DNS records
- [ ] Configure API keys in `.env`
- [ ] Enable firewall (ports 80, 443)
- [ ] Set up SSL certificate (automatic with Caddy)
- [ ] Configure log rotation
- [ ] Set up monitoring
- [ ] Test health check endpoint
- [ ] Review security headers
- [ ] Set resource limits
- [ ] Configure backups for volumes

---

## 📚 Additional Resources

- **CloudClear Documentation**: `docs/CLOUD_INTEGRATION_COMPLETE.md`
- **Quick Start**: `QUICKSTART.md`
- **Caddy Documentation**: https://caddyserver.com/docs/
- **Docker Compose**: https://docs.docker.com/compose/

---

**Ready to deploy CloudClear with Docker! 🚀**

Access your deployment at: **https://scan.yourdomain.com**
