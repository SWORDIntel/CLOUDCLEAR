# CloudClear Simple API - Localhost JSON Endpoint

A lightweight, localhost-bound API endpoint that provides CloudClear scanning capabilities via simple JSON requests.

## Features

- ✅ **Localhost-only binding** (127.0.0.1) for security
- ✅ **Simple JSON input/output** - no complex state management
- ✅ **Synchronous scans** - get results immediately
- ✅ **Docker-ready** - easy deployment
- ✅ **Multiple access methods** - POST or GET requests
- ✅ **Minimal dependencies** - just Flask and Flask-CORS
- ✅ **Health checks** - built-in monitoring

---

## Quick Start

### Option 1: Docker (Recommended)

```bash
# Build and start the API
docker-compose -f docker-compose.simple.yml up -d

# Test it
curl http://localhost:5000/health
curl http://localhost:5000/api/scan?domain=example.com
```

### Option 2: Direct Python

```bash
# Install dependencies
cd api/
pip install -r requirements-simple.txt

# Set the CloudClear binary path
export CLOUDCLEAR_BIN=/path/to/cloudclear

# Start the API
python3 simple_api.py
```

---

## API Endpoints

### 1. Health Check

**GET /health**

Check if the API is running.

```bash
curl http://localhost:5000/health
```

**Response:**
```json
{
  "status": "healthy",
  "service": "CloudClear Simple API",
  "version": "2.0",
  "timestamp": "2025-12-02T15:30:00.000000"
}
```

---

### 2. Root Documentation

**GET /**

Get API documentation and usage examples.

```bash
curl http://localhost:5000/
```

**Response:**
```json
{
  "service": "CloudClear Simple API",
  "version": "2.0",
  "description": "Localhost-bound JSON endpoint for cloud provider detection",
  "endpoints": {
    "GET /health": "Health check",
    "POST /api/scan": "Scan domain (JSON body)",
    "GET /api/scan?domain=example.com": "Scan domain (GET query)",
    "GET /api/scan/quick?domain=example.com": "Quick scan"
  },
  "examples": {
    "curl_post": "curl -X POST http://localhost:5000/api/scan -H \"Content-Type: application/json\" -d '{\"domain\":\"example.com\"}'",
    "curl_get": "curl http://localhost:5000/api/scan?domain=example.com"
  }
}
```

---

### 3. Scan Domain (POST)

**POST /api/scan**

Scan a domain and get JSON results.

**Request:**
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

**Response:**
```json
{
  "success": true,
  "domain": "example.com",
  "timestamp": "2025-12-02T15:30:00.000000",
  "exit_code": 0,
  "results": {
    "raw_output": "CloudClear scan output...",
    "detected_services": [],
    "ip_addresses": ["93.184.216.34"],
    "dns_records": [],
    "ssl_info": {},
    "cloud_providers": ["Cloudflare", "AWS CloudFront"]
  },
  "errors": null
}
```

---

### 4. Scan Domain (GET)

**GET /api/scan?domain=example.com**

Scan a domain via GET request (easier for browser testing).

**Request:**
```bash
curl "http://localhost:5000/api/scan?domain=example.com"
```

**Response:** Same as POST /api/scan

---

### 5. Quick Scan (GET)

**GET /api/scan/quick?domain=example.com**

Alias for GET /api/scan - shorter URL.

**Request:**
```bash
curl "http://localhost:5000/api/scan/quick?domain=example.com"
```

**Response:** Same as POST /api/scan

---

## Docker Deployment

### Build the Image

```bash
# Build from Dockerfile.simple
docker build -f Dockerfile.simple -t cloudclear-simple-api:latest .
```

### Run with Docker Compose (Recommended)

```bash
# Start the service (binds to 127.0.0.1:5000)
docker-compose -f docker-compose.simple.yml up -d

# View logs
docker-compose -f docker-compose.simple.yml logs -f

# Stop the service
docker-compose -f docker-compose.simple.yml down
```

### Run with Docker CLI

```bash
# Run container (bind to localhost only)
docker run -d \
  --name cloudclear-api \
  -p 127.0.0.1:5000:5000 \
  --restart unless-stopped \
  cloudclear-simple-api:latest

# View logs
docker logs -f cloudclear-api

# Stop container
docker stop cloudclear-api
docker rm cloudclear-api
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `API_PORT` | `5000` | Port to bind the API |
| `API_HOST` | `0.0.0.0` | Host to bind (0.0.0.0 in container) |
| `CLOUDCLEAR_BIN` | `/app/cloudclear` | Path to CloudClear binary |
| `SCAN_TIMEOUT` | `300` | Scan timeout in seconds |

### Cloud Provider API Keys (Optional)

Add these to `.env` file or pass as environment variables:

```bash
CLOUDFLARE_API_KEY=your_key_here
AKAMAI_CLIENT_TOKEN=your_token_here
AWS_ACCESS_KEY_ID=your_key_here
AZURE_CLIENT_ID=your_client_id
GCP_PROJECT_ID=your_project_id
FASTLY_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
CENSYS_API_ID=your_api_id
VIRUSTOTAL_API_KEY=your_key_here
```

---

## Usage Examples

### Basic Scan

```bash
# Using POST
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "google.com"}'

# Using GET (easier)
curl "http://localhost:5000/api/scan?domain=google.com"
```

### Scan Multiple Domains (Script)

```bash
#!/bin/bash
# scan_domains.sh

DOMAINS=("example.com" "google.com" "github.com")

for domain in "${DOMAINS[@]}"; do
  echo "Scanning $domain..."
  curl -s "http://localhost:5000/api/scan?domain=$domain" | jq .
  echo "---"
done
```

### Python Client

```python
import requests

# Scan a domain
response = requests.post('http://localhost:5000/api/scan',
                         json={'domain': 'example.com'})
result = response.json()

if result['success']:
    print(f"Domain: {result['domain']}")
    print(f"Cloud Providers: {result['results']['cloud_providers']}")
    print(f"IP Addresses: {result['results']['ip_addresses']}")
else:
    print(f"Scan failed: {result.get('error')}")
```

### JavaScript/Node.js Client

```javascript
const axios = require('axios');

async function scanDomain(domain) {
  try {
    const response = await axios.post('http://localhost:5000/api/scan', {
      domain: domain
    });

    console.log('Success:', response.data.success);
    console.log('Cloud Providers:', response.data.results.cloud_providers);
    console.log('IPs:', response.data.results.ip_addresses);
  } catch (error) {
    console.error('Error:', error.response?.data || error.message);
  }
}

scanDomain('example.com');
```

### Browser (Fetch API)

```javascript
// Scan from browser
fetch('http://localhost:5000/api/scan', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ domain: 'example.com' })
})
.then(response => response.json())
.then(data => {
  console.log('Results:', data);
})
.catch(error => {
  console.error('Error:', error);
});

// Or use GET (simpler)
fetch('http://localhost:5000/api/scan?domain=example.com')
  .then(response => response.json())
  .then(data => console.log(data));
```

---

## Response Format

### Success Response

```json
{
  "success": true,
  "domain": "example.com",
  "timestamp": "2025-12-02T15:30:00.000000",
  "scan_duration_seconds": null,
  "exit_code": 0,
  "results": {
    "raw_output": "Full CloudClear output...",
    "detected_services": [],
    "ip_addresses": ["93.184.216.34"],
    "dns_records": [],
    "ssl_info": {},
    "cloud_providers": ["Cloudflare"]
  },
  "errors": null
}
```

### Error Response

```json
{
  "error": "Invalid domain",
  "message": "Domain must be a valid hostname (e.g., example.com)",
  "domain": "invalid..domain"
}
```

### Timeout Response

```json
{
  "error": "Scan timeout",
  "message": "Scan took longer than 300 seconds",
  "domain": "example.com"
}
```

---

## Security Considerations

### Localhost Binding

The API is designed to bind to **127.0.0.1 only** on the host machine:

```yaml
# docker-compose.simple.yml
ports:
  - "127.0.0.1:5000:5000"  # Only accessible from localhost
```

This means:
- ✅ **Accessible**: From the same machine (curl, browser on http://localhost:5000)
- ❌ **Not accessible**: From network (other machines can't connect)
- ✅ **Secure**: No external exposure by default

### To Allow Network Access (Use with Caution)

If you need to access from other machines on your network:

```yaml
# Change binding to allow all interfaces
ports:
  - "5000:5000"  # Accessible from network

# Or bind to specific IP
ports:
  - "192.168.1.100:5000:5000"
```

⚠️ **Warning**: Only expose to network if you trust all machines on that network.

### Authentication (Not Implemented)

The simple API does **not include authentication**. For production use:
- Use a reverse proxy (nginx, Caddy) with auth
- Add API keys to the application
- Use the full-featured API server (server.py) which has more security features

---

## Troubleshooting

### API Not Starting

**Check logs:**
```bash
docker-compose -f docker-compose.simple.yml logs
```

**Common issues:**
- Port 5000 already in use: Change `API_PORT` in environment
- CloudClear binary missing: Check `CLOUDCLEAR_BIN` path

### Connection Refused

**Error:** `curl: (7) Failed to connect to localhost port 5000: Connection refused`

**Solutions:**
1. Check if container is running: `docker ps`
2. Check port binding: `docker port cloudclear-simple-api`
3. Verify health: `docker-compose -f docker-compose.simple.yml ps`

### Scan Timeout

**Error:** `{"error": "Scan timeout", ...}`

**Solutions:**
1. Increase timeout: Set `SCAN_TIMEOUT=600` (10 minutes)
2. Check network connectivity from container
3. Verify domain is valid and accessible

### Invalid Domain

**Error:** `{"error": "Invalid domain", ...}`

**Solution:** Ensure domain is properly formatted:
- ✅ Valid: `example.com`, `sub.example.com`, `example.co.uk`
- ❌ Invalid: `example`, `http://example.com`, `example..com`

---

## Performance

### Resource Usage

- **Memory**: ~100-256 MB per container
- **CPU**: Minimal when idle, spikes during scans
- **Disk**: ~200 MB image size

### Scan Duration

Typical scan times:
- Simple domain: 5-30 seconds
- Complex domain with many services: 1-3 minutes
- Maximum timeout: 5 minutes (configurable)

### Concurrent Scans

The simple API handles one scan at a time per container. For concurrent scans:

1. **Multiple containers:**
   ```bash
   # Start multiple instances on different ports
   docker run -d -p 127.0.0.1:5001:5000 cloudclear-simple-api
   docker run -d -p 127.0.0.1:5002:5000 cloudclear-simple-api
   docker run -d -p 127.0.0.1:5003:5000 cloudclear-simple-api
   ```

2. **Use full API server:** See `server.py` which supports concurrent scans

---

## Comparison: Simple API vs Full API Server

| Feature | Simple API | Full API Server |
|---------|------------|-----------------|
| **Endpoints** | 5 endpoints | 10+ endpoints |
| **Scan Mode** | Synchronous | Async + WebSocket |
| **Concurrent Scans** | 1 at a time | Configurable (10+) |
| **State Management** | Stateless | Scan history tracking |
| **WebSocket Support** | No | Yes (real-time updates) |
| **Dependencies** | 2 (Flask, CORS) | 10+ (SocketIO, Redis, etc) |
| **Use Case** | Simple scans, scripting | Production, web UI |
| **Setup Complexity** | Simple | Moderate |
| **Resource Usage** | Low | Medium |

**When to use Simple API:**
- Quick scripts and automation
- Single-server deployment
- Don't need real-time updates
- Want minimal dependencies

**When to use Full API:**
- Web UI needed
- Multiple concurrent users
- Real-time scan progress required
- Production deployment with scaling

---

## Development

### Running Locally

```bash
cd api/
pip install -r requirements-simple.txt

# Point to your local CloudClear build
export CLOUDCLEAR_BIN=../cloudclear

# Start API
python3 simple_api.py
```

### Testing

```bash
# Health check
curl http://localhost:5000/health

# Test scan
curl http://localhost:5000/api/scan?domain=example.com

# Check response format
curl -s http://localhost:5000/api/scan?domain=example.com | jq .
```

### Adding Custom Parsing

Edit `parse_cloudclear_output()` in `simple_api.py` to extract additional data from CloudClear output.

---

## Support

- **Documentation**: This file
- **Issues**: https://github.com/SWORDIntel/CLOUDCLEAR/issues
- **Full API**: See `api/README.md` for the full-featured server

---

## License

Same as CloudClear main project.
