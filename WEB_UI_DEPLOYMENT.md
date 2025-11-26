# CloudClear Web UI Deployment

## Important: Web UI is Docker-Only

The CloudClear TEMPEST Class C Web UI is **designed exclusively for Docker deployment**. It is not meant to run standalone on the local machine.

## Why Docker-Only?

The Web UI architecture requires:
- **Caddy** reverse proxy for HTTPS, security headers, and static file serving
- **Flask API Server** running continuously in the background
- **Isolated network** for security
- **Persistent volumes** for scan data and SSL certificates
- **WebSocket connections** for real-time updates

All of these components are orchestrated by Docker Compose and would be complex to set up manually.

## For Local Use

If you want to use CloudClear locally (without Docker), use one of these interfaces:

### 1. **Command Line Interface (CLI)** - Fastest
```bash
./cloudclear example.com
```

### 2. **Text User Interface (TUI)** - Interactive
```bash
./cloudclear-tui-enhanced
```

### 3. **Quick Launcher** - Menu-based
```bash
./cloudclear-launch.sh
```

## For Web UI (Production)

Deploy with Docker Compose:

```bash
# 1. Configure environment
cp .env.example .env
nano .env  # Add your API keys

# 2. Deploy
docker-compose up -d

# 3. Access
# Local: http://scan.cloudclear.local (add to /etc/hosts)
# Production: https://scan.yourdomain.com (automatic HTTPS)
```

## Architecture

```
Internet → Caddy (HTTPS/Security) → Flask API (WebSocket) → CloudClear Binary
              ↓
         Static Web UI Files
         (/web directory)
```

## Entrypoints Exposed

### Caddy (Port 80, 443)
- **Static Files**: `/srv/web` → Serves HTML/CSS/JS
- **API Proxy**: `/api/*` → Proxies to `cloudclear-api:8080`
- **WebSocket**: `/socket.io/*` → Proxies Socket.IO connections
- **Health Check**: `/health` → Proxies to API health endpoint

### API Server (Internal Port 8080)
- **Not exposed externally** - Only accessible via Caddy proxy
- **WebSocket Server**: Socket.IO on same port for real-time updates
- **REST API**: `/api/v1/*` endpoints for scan management
- **Health Check**: `/health` for container health monitoring

## Security Features

### TEMPEST Class C Headers (Applied by Caddy)
- ✅ HSTS (Strict-Transport-Security)
- ✅ X-Content-Type-Options: nosniff
- ✅ X-Frame-Options: SAMEORIGIN
- ✅ Content-Security-Policy with WebSocket allowlist
- ✅ Referrer-Policy: strict-origin-when-cross-origin
- ✅ Permissions-Policy (restricts geolocation, camera, mic)

### Network Isolation
- API server runs in isolated Docker network
- No direct port exposure (8080 is internal only)
- All traffic flows through Caddy reverse proxy

### Automatic HTTPS
- Let's Encrypt certificates automatically provisioned
- HTTP → HTTPS redirection
- HTTP/3 support (QUIC)

## Running API Server Locally (Not Recommended)

If you absolutely need to run the API server standalone for development:

```bash
# Install Python dependencies
cd api
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run (will show warning)
python server.py
```

**Warning**: This will display a warning that the API server is designed for Docker. The Web UI files won't be served (no Caddy), and WebSocket connections may not work correctly without proper reverse proxy configuration.

## Troubleshooting

### Web UI Not Loading
1. Check Caddy logs: `docker-compose logs caddy`
2. Verify web files are mounted: `docker-compose exec caddy ls /srv/web`
3. Check DNS resolution for your domain

### WebSocket Not Connecting
1. Verify Socket.IO proxy in Caddyfile: `/socket.io/*` handler
2. Check browser console for connection errors
3. Ensure CSP allows WebSocket connections

### API Not Responding
1. Check API logs: `docker-compose logs cloudclear-api`
2. Verify health check: `curl http://localhost/health` (via Caddy)
3. Check container status: `docker-compose ps`

## Summary

✅ **Use Docker for Web UI**: `docker-compose up -d`
✅ **Use CLI/TUI locally**: `./cloudclear` or `./cloudclear-tui-enhanced`
❌ **Don't run API server standalone**: It's designed for Docker deployment

For full deployment instructions, see: **[DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md)**
