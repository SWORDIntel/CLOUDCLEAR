# CloudClear API

CloudClear provides two API servers depending on your needs:

## 1. Simple API (simple_api.py) - **Recommended for Docker/Localhost**

**Best for:** Quick scans, scripting, localhost-only access

### Features
- ✅ **Localhost-bound** (127.0.0.1:5000)
- ✅ **Simple JSON** input/output
- ✅ **Synchronous** scans (get results immediately)
- ✅ **Minimal** dependencies (just Flask)
- ✅ **Docker-ready** with docker-compose

### Quick Start

```bash
# Docker (recommended)
docker-compose -f docker-compose.simple.yml up -d

# Test it
curl http://localhost:5000/api/scan?domain=example.com
```

### Endpoints

- `GET /health` - Health check
- `GET /` - API documentation
- `POST /api/scan` - Scan domain (JSON body: `{"domain": "example.com"}`)
- `GET /api/scan?domain=example.com` - Scan domain (GET query)
- `GET /api/scan/quick?domain=example.com` - Quick scan

### Example Response

```json
{
  "success": true,
  "domain": "example.com",
  "timestamp": "2025-12-02T15:30:00.000000",
  "results": {
    "cloud_providers": ["Cloudflare"],
    "ip_addresses": ["93.184.216.34"],
    "raw_output": "..."
  }
}
```

**Documentation:** [docs/SIMPLE_API.md](../docs/SIMPLE_API.md)

---

## 2. Full API Server (server.py) - **For Production**

**Best for:** Web UIs, multiple concurrent users, real-time updates

### Features
- ✅ **Async scans** with background processing
- ✅ **WebSocket** support for real-time progress
- ✅ **Concurrent** scan management (configurable)
- ✅ **Scan history** and state tracking
- ✅ **Rate limiting** and timeouts
- ✅ **100% test coverage** (61 tests)

### Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Start server
python server.py
```

### Main Endpoints

- `GET /health` - System health with metrics
- `GET /api/v1/info` - CloudClear capabilities
- `POST /api/v1/scan` - Start async scan (returns scan_id)
- `GET /api/v1/scan/<scan_id>` - Get scan status
- `GET /api/v1/scans` - List all scans
- `GET /api/v1/config` - Configuration

### WebSocket Events

- `connect` / `disconnect`
- `subscribe_scan` - Get real-time updates
- `scan_progress` - Progress notifications
- `scan_complete` - Completion notification

---

## Comparison

| Feature | Simple API | Full Server |
|---------|------------|-------------|
| **Scan Mode** | Synchronous | Async + WebSocket |
| **Concurrent Scans** | 1 | 10+ (configurable) |
| **Dependencies** | 2 packages | 10+ packages |
| **State Management** | Stateless | Scan history |
| **Real-time Updates** | No | Yes |
| **Docker Ready** | ✅ | ✅ |
| **Test Coverage** | - | 100% (61 tests) |

---

## Installation

### Simple API

```bash
pip install -r requirements-simple.txt
```

**Dependencies:** Flask, Flask-CORS

### Full API Server

```bash
pip install -r requirements.txt
```

**Dependencies:** Flask, Flask-CORS, Flask-SocketIO, eventlet, psutil, redis, etc.

### Testing (Full Server)

```bash
pip install -r requirements-test.txt
pytest test_server.py --cov=server
```

---

## Docker Deployment

### Simple API (Localhost-bound)

```bash
# Build and run
docker-compose -f docker-compose.simple.yml up -d

# Access
curl http://localhost:5000/api/scan?domain=example.com
```

**Binds to:** `127.0.0.1:5000` (localhost only)

### Full API Server

```bash
# Build and run
docker-compose up -d

# Access API
curl http://localhost:8080/api/v1/info

# Web UI
open http://localhost:8080/web/
```

---

## Configuration

### Environment Variables

```bash
# API Settings
API_HOST=0.0.0.0           # Bind address (0.0.0.0 in container)
API_PORT=5000              # API port

# CloudClear
CLOUDCLEAR_BIN=/app/cloudclear
SCAN_TIMEOUT=300           # Scan timeout (seconds)

# Full Server Only
MAX_CONCURRENT_SCANS=10    # Max concurrent scans
SECRET_KEY=your-secret     # Flask secret key
```

### Cloud Provider API Keys (Optional)

```bash
CLOUDFLARE_API_KEY=...
AWS_ACCESS_KEY_ID=...
AZURE_CLIENT_ID=...
SHODAN_API_KEY=...
# ... etc
```

---

## Usage Examples

### Simple API

```bash
# Quick scan via GET
curl "http://localhost:5000/api/scan?domain=example.com"

# Scan via POST
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

### Full API Server

```bash
# Start async scan
curl -X POST http://localhost:8080/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
# Returns: {"scan_id": "1234567890_example_com", ...}

# Get scan status
curl http://localhost:8080/api/v1/scan/1234567890_example_com

# List all scans
curl http://localhost:8080/api/v1/scans
```

---

## When to Use Which?

### Use Simple API When:
- ✅ Running locally / in Docker
- ✅ Need simple JSON results
- ✅ Scripting/automation
- ✅ Want minimal dependencies
- ✅ Don't need concurrent scans
- ✅ Localhost-only access is fine

### Use Full Server When:
- ✅ Need web UI
- ✅ Multiple concurrent users
- ✅ Want real-time updates
- ✅ Production deployment
- ✅ Need scan history
- ✅ Require state management

---

## Documentation

- **Simple API**: [docs/SIMPLE_API.md](../docs/SIMPLE_API.md)
- **Full Server**: See inline documentation in `server.py`
- **Tests**: See `test_server.py` for full API test examples

---

## Security

### Simple API
- Binds to `127.0.0.1` by default (localhost-only)
- No authentication (use reverse proxy if needed)
- Minimal attack surface

### Full Server
- Input validation and sanitization
- Rate limiting (configurable)
- Domain validation (RFC-1035)
- CORS protection
- Request size limits

**Production:** Always use a reverse proxy (nginx, Caddy) with TLS and authentication.

---

## Performance

### Simple API
- **Memory**: ~100-256 MB
- **Scan Time**: 5-180 seconds
- **Concurrent**: 1 scan at a time

### Full Server
- **Memory**: ~256-512 MB
- **Scan Time**: 5-300 seconds (async)
- **Concurrent**: Configurable (default: 10)

---

## Support

- **GitHub Issues**: https://github.com/SWORDIntel/CLOUDCLEAR/issues
- **Docker Issues**: Tag with `platform:docker`
- **API Issues**: Tag with `component:api`

---

## License

Same as CloudClear main project.
