# CloudClear Docker Startup Guide

## Random Port Assignment

CloudClear automatically assigns random available ports on startup to avoid port conflicts.

**Default:** Direct API access (lightweight)
**Optional:** Caddy reverse proxy for web UI (`USE_CADDY=1`)

## Quick Start

### Start CloudClear (Default - Direct API)

```bash
./docker-start.sh
```

This will:

1. Find a random available port for API
2. Start the API container
3. Display the assigned port
4. Save port to `.docker-ports` file

### Start CloudClear with Caddy (Optional Web UI)

```bash
USE_CADDY=1 ./docker-start.sh
```

This will:

1. Find random available ports (API + Caddy HTTP/HTTPS)
2. Start API and Caddy containers
3. Display all assigned ports
4. Provide web UI access through Caddy

### View Current Ports

If you forget the assigned ports, run:

```bash
./docker-ports.sh
```

This displays:

- Current HTTP port
- Current HTTPS port
- Quick access links
- Saved ports from startup

## Example Output

### Default (Direct API)

When you run `./docker-start.sh`, you'll see:

```
Mode: Direct API Access

╔════════════════════════════════════════════════════════════╗
║                    ACCESS INFORMATION                      ║
╚════════════════════════════════════════════════════════════╝

API Access:
  http://localhost:8118

API Health Check:
  http://localhost:8118/health

API Endpoint:
  http://localhost:8118/api/

Tip: Enable web UI with: USE_CADDY=1 ./docker-start.sh
```

### With Caddy (Optional)

When you run `USE_CADDY=1 ./docker-start.sh`, you'll see:

```
Mode: API + Caddy Reverse Proxy

╔════════════════════════════════════════════════════════════╗
║                    ACCESS INFORMATION                      ║
╚════════════════════════════════════════════════════════════╝

API Access:
  http://localhost:8118

API Health Check:
  http://localhost:8118/health

API Endpoint:
  http://localhost:8118/api/

Web Interface (via Caddy):
  HTTP:  http://localhost:8143
  HTTPS: https://localhost:9778
```

## Manual Port Assignment

### Specific API Port

```bash
export API_DIRECT_PORT=5000
./docker-start.sh
```

### With Caddy and Specific Ports

```bash
export API_DIRECT_PORT=5000
export CADDY_HTTP_PORT=8080
export CADDY_HTTPS_PORT=8443
USE_CADDY=1 ./docker-start.sh
```

### Using docker-compose directly

```bash
export API_DIRECT_PORT=5000
docker-compose up -d cloudclear-api

# Or with Caddy
docker-compose --profile caddy up -d
```

## Useful Commands

```bash
# View logs
docker-compose logs -f

# Stop containers
docker-compose down

# Restart containers
docker-compose restart

# View container status
docker-compose ps

# View ports
./docker-ports.sh
```

## Port Ranges

- **API ports**: Randomly selected from range 8000-9000
- **Caddy HTTP ports**: Randomly selected from range 8000-9000
- **Caddy HTTPS ports**: Randomly selected from range 9000-10000

Ports are automatically checked for availability before assignment.

## When to Use Caddy

**Default (Direct API)** is recommended for:

- ✅ API-only access
- ✅ Minimal resource usage
- ✅ Running behind another reverse proxy
- ✅ Development and testing

**With Caddy** (`USE_CADDY=1`) is useful for:

- ✅ Web UI access
- ✅ HTTPS/SSL termination
- ✅ Static file serving
- ✅ Production with web interface

**Note**: API is always directly accessible, even when Caddy is enabled.
