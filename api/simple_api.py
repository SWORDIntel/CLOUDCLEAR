#!/usr/bin/env python3
"""
CloudClear Simple API - Localhost-bound JSON endpoint
Direct scan interface for Docker deployments
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import subprocess
import json
import os
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Configuration
CLOUDCLEAR_BIN = os.environ.get('CLOUDCLEAR_BIN', '/app/cloudclear')
SCAN_TIMEOUT = int(os.environ.get('SCAN_TIMEOUT', '300'))  # 5 minutes
API_PORT = int(os.environ.get('API_PORT', '5000'))

def validate_domain(domain):
    """Validate domain format"""
    import re
    # RFC-1035 compliant domain validation
    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    if not domain or not isinstance(domain, str):
        return False
    if len(domain) > 255:
        return False
    return bool(domain_regex.match(domain))

def parse_cloudclear_output(output):
    """Parse CloudClear output into structured JSON"""
    result = {
        'raw_output': output,
        'detected_services': [],
        'ip_addresses': [],
        'dns_records': [],
        'ssl_info': {},
        'cloud_providers': []
    }

    lines = output.split('\n')

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Detect cloud providers
        if 'cloudflare' in line.lower():
            result['cloud_providers'].append('Cloudflare')
        elif 'aws' in line.lower() or 'amazon' in line.lower():
            result['cloud_providers'].append('AWS CloudFront')
        elif 'azure' in line.lower():
            result['cloud_providers'].append('Azure')
        elif 'google' in line.lower() or 'gcp' in line.lower():
            result['cloud_providers'].append('Google Cloud')
        elif 'akamai' in line.lower():
            result['cloud_providers'].append('Akamai')
        elif 'fastly' in line.lower():
            result['cloud_providers'].append('Fastly')

        # Extract IP addresses
        import re
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, line)
        for ip in ips:
            if ip not in result['ip_addresses']:
                result['ip_addresses'].append(ip)

    # Remove duplicates
    result['cloud_providers'] = list(set(result['cloud_providers']))

    return result

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'CloudClear Simple API',
        'version': '2.0',
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/api/scan', methods=['POST', 'GET'])
def scan():
    """
    Simple scan endpoint - returns CloudClear results as JSON

    POST /api/scan
    Body: {"domain": "example.com"}

    GET /api/scan?domain=example.com
    """
    # Get domain from POST body or GET parameter
    if request.method == 'POST':
        data = request.get_json()
        if not data:
            return jsonify({
                'error': 'Invalid request',
                'message': 'Request body must be valid JSON'
            }), 400
        domain = data.get('domain', '').strip()
    else:  # GET
        domain = request.args.get('domain', '').strip()

    # Validate domain
    if not domain:
        return jsonify({
            'error': 'Missing parameter',
            'message': 'Domain parameter is required'
        }), 400

    if not validate_domain(domain):
        return jsonify({
            'error': 'Invalid domain',
            'message': 'Domain must be a valid hostname (e.g., example.com)'
        }), 400

    # Check if CloudClear binary exists
    if not os.path.exists(CLOUDCLEAR_BIN):
        return jsonify({
            'error': 'Configuration error',
            'message': 'CloudClear binary not found',
            'path': CLOUDCLEAR_BIN
        }), 500

    try:
        logger.info(f"Starting scan for domain: {domain}")

        # Run CloudClear scan
        result = subprocess.run(
            [CLOUDCLEAR_BIN, domain],
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT,
            env=os.environ.copy()
        )

        # Parse output
        parsed_result = parse_cloudclear_output(result.stdout)

        # Build response
        response = {
            'success': result.returncode == 0,
            'domain': domain,
            'timestamp': datetime.utcnow().isoformat(),
            'scan_duration_seconds': None,  # Could add timing
            'exit_code': result.returncode,
            'results': parsed_result,
            'errors': result.stderr if result.stderr else None
        }

        logger.info(f"Scan completed for {domain}: exit_code={result.returncode}")

        return jsonify(response), 200

    except subprocess.TimeoutExpired:
        logger.warning(f"Scan timeout for domain: {domain}")
        return jsonify({
            'error': 'Scan timeout',
            'message': f'Scan took longer than {SCAN_TIMEOUT} seconds',
            'domain': domain
        }), 504

    except Exception as e:
        logger.error(f"Scan failed for {domain}: {str(e)}")
        return jsonify({
            'error': 'Scan failed',
            'message': str(e),
            'domain': domain
        }), 500

@app.route('/api/scan/quick', methods=['GET'])
def quick_scan():
    """
    Quick scan via GET - simple URL query
    Example: GET /api/scan/quick?domain=example.com
    """
    domain = request.args.get('domain', '').strip()

    if not domain:
        return jsonify({
            'error': 'Missing domain parameter',
            'usage': '/api/scan/quick?domain=example.com'
        }), 400

    # Reuse the main scan logic
    return scan()

@app.route('/', methods=['GET'])
def index():
    """API documentation"""
    return jsonify({
        'service': 'CloudClear Simple API',
        'version': '2.0',
        'description': 'Localhost-bound JSON endpoint for cloud provider detection',
        'endpoints': {
            'GET /health': 'Health check',
            'POST /api/scan': 'Scan domain (JSON body: {"domain": "example.com"})',
            'GET /api/scan?domain=example.com': 'Scan domain (GET query)',
            'GET /api/scan/quick?domain=example.com': 'Quick scan (GET query)'
        },
        'examples': {
            'curl_post': 'curl -X POST http://localhost:5000/api/scan -H "Content-Type: application/json" -d \'{"domain":"example.com"}\'',
            'curl_get': 'curl http://localhost:5000/api/scan?domain=example.com',
            'curl_quick': 'curl http://localhost:5000/api/scan/quick?domain=example.com'
        }
    })

@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return jsonify({
        'error': 'Not found',
        'message': 'Endpoint does not exist',
        'available_endpoints': ['/', '/health', '/api/scan', '/api/scan/quick']
    }), 404

@app.errorhandler(500)
def internal_error(e):
    """Handle internal server errors"""
    logger.error(f"Internal error: {str(e)}")
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred'
    }), 500

if __name__ == '__main__':
    # Bind to 127.0.0.1 for localhost-only access
    # In Docker, this will be remapped by port binding
    host = os.environ.get('API_HOST', '0.0.0.0')  # 0.0.0.0 in container

    logger.info("=" * 70)
    logger.info("CloudClear Simple API - Localhost-bound JSON endpoint")
    logger.info(f"Starting on {host}:{API_PORT}")
    logger.info(f"CloudClear binary: {CLOUDCLEAR_BIN}")
    logger.info(f"Scan timeout: {SCAN_TIMEOUT}s")
    logger.info("=" * 70)

    app.run(host=host, port=API_PORT, debug=False)
