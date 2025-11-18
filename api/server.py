#!/usr/bin/env python3
"""
CloudClear API Server
RESTful API wrapper for CloudClear CLI with real-time WebSocket updates
"""

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import subprocess
import json
import os
import threading
import time
import re
from datetime import datetime
import psutil
import logging
from functools import wraps

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cloudclear-secret-key-change-me')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024  # 16KB max request size
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet', ping_timeout=60)

# Configuration
CLOUDCLEAR_BIN = '/app/cloudclear'
MAX_CONCURRENT_SCANS = int(os.environ.get('MAX_CONCURRENT_SCANS', '10'))
SCAN_TIMEOUT = int(os.environ.get('SCAN_TIMEOUT', '300'))  # 5 minutes default

# Domain validation regex (RFC-1035 compliant)
DOMAIN_REGEX = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)

# Active scans tracking
active_scans = {}
scan_lock = threading.Lock()

def validate_domain(domain):
    """Validate domain name format"""
    if not domain or not isinstance(domain, str):
        return False
    if len(domain) > 255:
        return False
    if not DOMAIN_REGEX.match(domain):
        return False
    return True

def sanitize_input(text):
    """Sanitize user input to prevent injection"""
    if not isinstance(text, str):
        return str(text)
    # Remove any shell-unsafe characters
    return re.sub(r'[;&|`$(){}[\]<>]', '', text)

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'version': '2.0-Enhanced-Cloud',
        'timestamp': datetime.utcnow().isoformat(),
        'active_scans': len(active_scans),
        'system': {
            'cpu_percent': psutil.cpu_percent(),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_percent': psutil.disk_usage('/').percent
        }
    })

@app.route('/api/v1/info', methods=['GET'])
def info():
    """Get CloudClear information and capabilities"""
    cloud_providers = [
        {'name': 'Cloudflare', 'enabled': bool(os.getenv('CLOUDFLARE_API_KEY'))},
        {'name': 'Akamai Edge', 'enabled': bool(os.getenv('AKAMAI_CLIENT_TOKEN'))},
        {'name': 'AWS CloudFront', 'enabled': bool(os.getenv('AWS_ACCESS_KEY_ID'))},
        {'name': 'Azure Front Door', 'enabled': bool(os.getenv('AZURE_CLIENT_ID'))},
        {'name': 'GCP Cloud CDN', 'enabled': bool(os.getenv('GCP_PROJECT_ID'))},
        {'name': 'Fastly', 'enabled': bool(os.getenv('FASTLY_API_KEY'))},
        {'name': 'DigitalOcean', 'enabled': bool(os.getenv('DIGITALOCEAN_API_TOKEN'))},
        {'name': 'Oracle Cloud', 'enabled': bool(os.getenv('ORACLE_CLOUD_TENANCY_OCID'))},
        {'name': 'Alibaba Cloud', 'enabled': bool(os.getenv('ALIBABA_ACCESS_KEY_ID'))},
        {'name': 'Imperva', 'enabled': bool(os.getenv('IMPERVA_API_ID'))},
        {'name': 'Sucuri', 'enabled': bool(os.getenv('SUCURI_API_KEY'))},
        {'name': 'Stackpath', 'enabled': bool(os.getenv('STACKPATH_CLIENT_ID'))}
    ]

    intelligence_services = [
        {'name': 'Shodan', 'enabled': bool(os.getenv('SHODAN_API_KEY'))},
        {'name': 'Censys', 'enabled': bool(os.getenv('CENSYS_API_ID'))},
        {'name': 'VirusTotal', 'enabled': bool(os.getenv('VIRUSTOTAL_API_KEY'))}
    ]

    return jsonify({
        'name': 'CloudClear',
        'version': '2.0-Enhanced-Cloud',
        'description': 'Advanced Cloud Provider Detection & Intelligence Platform',
        'capabilities': {
            'total_providers': len(cloud_providers),
            'enabled_providers': sum(1 for p in cloud_providers if p['enabled']),
            'total_intelligence': len(intelligence_services),
            'enabled_intelligence': sum(1 for s in intelligence_services if s['enabled'])
        },
        'integrations': {
            'cloud_providers': cloud_providers,
            'intelligence': intelligence_services
        },
        'detection_methods': [
            'HTTP Header Analysis',
            'DNS Resolution & CNAME Inspection',
            'SSL/TLS Certificate Analysis',
            'IP Range & ASN Detection',
            'API-Based Intelligence',
            'WAF Signature Detection'
        ]
    })

@app.route('/api/v1/scan', methods=['POST'])
def scan():
    """Start a cloud provider detection scan"""
    try:
        # Parse and validate request
        data = request.get_json()
        if not data:
            return jsonify({
                'error': 'Invalid request',
                'message': 'Request body must be valid JSON'
            }), 400

        if 'domain' not in data:
            return jsonify({
                'error': 'Missing parameter',
                'message': 'Domain parameter is required'
            }), 400

        domain = data['domain'].strip() if isinstance(data['domain'], str) else ''

        # Validate domain format
        if not validate_domain(domain):
            return jsonify({
                'error': 'Invalid domain',
                'message': 'Domain must be a valid hostname (e.g., example.com)'
            }), 400

        # Sanitize domain
        domain = sanitize_input(domain)

        # Check concurrent scan limit
        with scan_lock:
            if len(active_scans) >= MAX_CONCURRENT_SCANS:
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'message': f'Maximum {MAX_CONCURRENT_SCANS} concurrent scans allowed'
                }), 429

        # Generate scan ID
        scan_id = f"{int(time.time())}_{domain.replace('.', '_')}"

        # Log scan initiation
        logger.info(f"Starting scan {scan_id} for domain: {domain}")

        # Start scan in background
        thread = threading.Thread(target=run_scan, args=(scan_id, domain))
        thread.daemon = True
        thread.start()

        return jsonify({
            'scan_id': scan_id,
            'domain': domain,
            'status': 'started',
            'message': 'Scan initiated successfully',
            'timestamp': datetime.utcnow().isoformat()
        }), 202

    except Exception as e:
        logger.error(f"Scan endpoint error: {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'message': 'Failed to initiate scan'
        }), 500

def run_scan(scan_id, domain):
    """Execute CloudClear scan in background with progress tracking"""
    with scan_lock:
        active_scans[scan_id] = {
            'domain': domain,
            'status': 'running',
            'started_at': datetime.utcnow().isoformat(),
            'progress': 0
        }

    try:
        logger.info(f"Executing scan {scan_id} for {domain}")

        # Emit start event
        socketio.emit('scan_progress', {
            'scan_id': scan_id,
            'status': 'running',
            'progress': 10,
            'message': f'Initializing scan for {domain}'
        })

        # Progress update
        socketio.emit('scan_progress', {
            'scan_id': scan_id,
            'status': 'running',
            'progress': 30,
            'message': 'Analyzing DNS and HTTP headers'
        })

        # Run CloudClear with timeout
        result = subprocess.run(
            [CLOUDCLEAR_BIN, domain],
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT,
            env=os.environ.copy()
        )

        # Progress update
        socketio.emit('scan_progress', {
            'scan_id': scan_id,
            'status': 'running',
            'progress': 80,
            'message': 'Processing detection results'
        })

        # Parse results
        results = {
            'domain': domain,
            'exit_code': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr if result.stderr else '',
            'timestamp': datetime.utcnow().isoformat(),
            'success': result.returncode == 0
        }

        # Update scan status
        with scan_lock:
            active_scans[scan_id].update({
                'status': 'completed',
                'results': results,
                'completed_at': datetime.utcnow().isoformat(),
                'progress': 100
            })

        logger.info(f"Scan {scan_id} completed with exit code {result.returncode}")

        # Emit completion
        socketio.emit('scan_complete', {
            'scan_id': scan_id,
            'status': 'completed',
            'results': results
        })

    except subprocess.TimeoutExpired:
        error_msg = f'Scan timeout after {SCAN_TIMEOUT} seconds'
        logger.warning(f"Scan {scan_id} timed out")

        with scan_lock:
            active_scans[scan_id].update({
                'status': 'timeout',
                'error': error_msg,
                'completed_at': datetime.utcnow().isoformat()
            })

        socketio.emit('scan_error', {
            'scan_id': scan_id,
            'error': error_msg,
            'message': 'Scan took too long to complete'
        })

    except FileNotFoundError:
        error_msg = 'CloudClear binary not found'
        logger.error(f"Scan {scan_id} failed: {error_msg}")

        with scan_lock:
            active_scans[scan_id].update({
                'status': 'error',
                'error': error_msg,
                'completed_at': datetime.utcnow().isoformat()
            })

        socketio.emit('scan_error', {
            'scan_id': scan_id,
            'error': error_msg,
            'message': 'Scanner binary is missing'
        })

    except Exception as e:
        error_msg = str(e)
        logger.error(f"Scan {scan_id} failed with exception: {error_msg}")

        with scan_lock:
            active_scans[scan_id].update({
                'status': 'error',
                'error': error_msg,
                'completed_at': datetime.utcnow().isoformat()
            })

        socketio.emit('scan_error', {
            'scan_id': scan_id,
            'error': error_msg,
            'message': 'Unexpected error during scan'
        })

    finally:
        # Clean up old scans (keep last 100)
        with scan_lock:
            if len(active_scans) > 100:
                oldest_scans = sorted(
                    active_scans.items(),
                    key=lambda x: x[1].get('started_at', '')
                )[:len(active_scans) - 100]
                for scan_id_to_remove, _ in oldest_scans:
                    del active_scans[scan_id_to_remove]

@app.route('/api/v1/scan/<scan_id>', methods=['GET'])
def get_scan(scan_id):
    """Get scan status and results"""
    with scan_lock:
        scan = active_scans.get(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        return jsonify(scan)

@app.route('/api/v1/scans', methods=['GET'])
def list_scans():
    """List all active scans"""
    with scan_lock:
        return jsonify({
            'scans': list(active_scans.values()),
            'count': len(active_scans)
        })

@app.route('/api/v1/config', methods=['GET'])
def get_config():
    """Get current configuration status"""
    provider_checks = [
        bool(os.getenv('CLOUDFLARE_API_KEY')),
        bool(os.getenv('AKAMAI_CLIENT_TOKEN')),
        bool(os.getenv('AWS_ACCESS_KEY_ID')),
        bool(os.getenv('AZURE_CLIENT_ID')),
        bool(os.getenv('GCP_PROJECT_ID')),
        bool(os.getenv('FASTLY_API_KEY')),
        bool(os.getenv('DIGITALOCEAN_API_TOKEN')),
        bool(os.getenv('ORACLE_CLOUD_TENANCY_OCID')),
        bool(os.getenv('ALIBABA_ACCESS_KEY_ID')),
        bool(os.getenv('IMPERVA_API_ID')),
        bool(os.getenv('SUCURI_API_KEY')),
        bool(os.getenv('STACKPATH_CLIENT_ID'))
    ]

    intelligence_checks = [
        bool(os.getenv('SHODAN_API_KEY')),
        bool(os.getenv('CENSYS_API_ID')),
        bool(os.getenv('VIRUSTOTAL_API_KEY'))
    ]

    return jsonify({
        'providers_configured': sum(provider_checks),
        'total_providers': len(provider_checks),
        'intelligence_configured': sum(intelligence_checks),
        'total_intelligence': len(intelligence_checks),
        'total_integrations': len(provider_checks) + len(intelligence_checks),
        'enabled_integrations': sum(provider_checks) + sum(intelligence_checks),
        'scan_timeout': SCAN_TIMEOUT,
        'max_concurrent_scans': MAX_CONCURRENT_SCANS
    })

# Error handlers
@app.errorhandler(400)
def bad_request(e):
    """Handle bad request errors"""
    return jsonify({
        'error': 'Bad request',
        'message': str(e)
    }), 400

@app.errorhandler(404)
def not_found(e):
    """Handle not found errors"""
    return jsonify({
        'error': 'Not found',
        'message': 'The requested resource does not exist'
    }), 404

@app.errorhandler(429)
def rate_limit_exceeded(e):
    """Handle rate limit errors"""
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Please try again later.'
    }), 429

@app.errorhandler(500)
def internal_error(e):
    """Handle internal server errors"""
    logger.error(f"Internal error: {str(e)}")
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred'
    }), 500

# WebSocket handlers
@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    logger.info(f"WebSocket client connected: {request.sid}")
    emit('connected', {
        'message': 'Connected to CloudClear',
        'timestamp': datetime.utcnow().isoformat()
    })

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    logger.info(f"WebSocket client disconnected: {request.sid}")

@socketio.on('subscribe_scan')
def handle_subscribe(data):
    """Subscribe to scan updates"""
    scan_id = data.get('scan_id')
    if scan_id:
        logger.info(f"Client {request.sid} subscribed to scan {scan_id}")
        emit('subscribed', {
            'scan_id': scan_id,
            'timestamp': datetime.utcnow().isoformat()
        })

@socketio.on('ping')
def handle_ping():
    """Handle ping requests"""
    emit('pong', {'timestamp': datetime.utcnow().isoformat()})

if __name__ == '__main__':
    # Check if running in Docker (recommended deployment method)
    in_docker = os.path.exists('/.dockerenv') or os.environ.get('DOCKER_CONTAINER', False)

    if not in_docker:
        logger.warning("=" * 70)
        logger.warning("WARNING: API Server is designed to run in Docker!")
        logger.warning("For production deployment, use: docker-compose up -d")
        logger.warning("For local testing, use the CLI/TUI instead: ./cloudclear example.com")
        logger.warning("=" * 70)

    port = int(os.environ.get('API_PORT', 8080))
    host = os.environ.get('API_HOST', '0.0.0.0')

    logger.info("=" * 70)
    logger.info(f"CloudClear API Server v2.0-Enhanced-Cloud")
    logger.info(f"Starting on {host}:{port}")
    logger.info(f"Environment: {'Docker' if in_docker else 'Standalone (not recommended)'}")
    logger.info(f"Max concurrent scans: {MAX_CONCURRENT_SCANS}")
    logger.info(f"Scan timeout: {SCAN_TIMEOUT}s")
    logger.info(f"CloudClear binary: {CLOUDCLEAR_BIN}")
    logger.info("=" * 70)

    try:
        socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        logger.info("Shutting down CloudClear API Server...")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        raise
