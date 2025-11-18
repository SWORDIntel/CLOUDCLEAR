#!/usr/bin/env python3
"""
CloudClear API Server
RESTful API wrapper for CloudClear CLI
"""

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import subprocess
import json
import os
import threading
import time
from datetime import datetime
import psutil

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cloudclear-secret-key-change-me')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Configuration
CLOUDCLEAR_BIN = '/app/cloudclear'
MAX_CONCURRENT_SCANS = int(os.environ.get('MAX_CONCURRENT_SCANS', '10'))

# Active scans tracking
active_scans = {}
scan_lock = threading.Lock()

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
    return jsonify({
        'name': 'CloudClear',
        'version': '2.0-Enhanced-Cloud',
        'description': 'Advanced Cloud Provider Detection & Intelligence',
        'integrations': {
            'cloud_providers': [
                {'name': 'Akamai Edge', 'enabled': bool(os.getenv('AKAMAI_CLIENT_TOKEN'))},
                {'name': 'AWS', 'enabled': bool(os.getenv('AWS_ACCESS_KEY_ID'))},
                {'name': 'Azure', 'enabled': bool(os.getenv('AZURE_CLIENT_ID'))},
                {'name': 'GCP', 'enabled': bool(os.getenv('GCP_PROJECT_ID'))},
                {'name': 'Fastly', 'enabled': bool(os.getenv('FASTLY_API_KEY'))},
                {'name': 'DigitalOcean', 'enabled': bool(os.getenv('DIGITALOCEAN_API_TOKEN'))}
            ],
            'intelligence': [
                {'name': 'Shodan', 'enabled': bool(os.getenv('SHODAN_API_KEY'))},
                {'name': 'Censys', 'enabled': bool(os.getenv('CENSYS_API_ID'))},
                {'name': 'VirusTotal', 'enabled': bool(os.getenv('VIRUSTOTAL_API_KEY'))}
            ]
        },
        'detection_methods': [
            'HTTP Headers',
            'DNS Resolution',
            'Certificate Analysis',
            'IP Range Detection',
            'API Intelligence'
        ]
    })

@app.route('/api/v1/scan', methods=['POST'])
def scan():
    """Start a cloud provider detection scan"""
    data = request.get_json()

    if not data or 'domain' not in data:
        return jsonify({'error': 'Domain is required'}), 400

    domain = data['domain'].strip()

    # Validate domain
    if not domain or len(domain) > 255:
        return jsonify({'error': 'Invalid domain'}), 400

    # Check concurrent scan limit
    with scan_lock:
        if len(active_scans) >= MAX_CONCURRENT_SCANS:
            return jsonify({'error': 'Maximum concurrent scans reached'}), 429

    # Generate scan ID
    scan_id = f"{int(time.time())}_{domain.replace('.', '_')}"

    # Start scan in background
    thread = threading.Thread(target=run_scan, args=(scan_id, domain))
    thread.daemon = True
    thread.start()

    return jsonify({
        'scan_id': scan_id,
        'domain': domain,
        'status': 'started',
        'message': 'Scan initiated'
    }), 202

def run_scan(scan_id, domain):
    """Execute CloudClear scan in background"""
    with scan_lock:
        active_scans[scan_id] = {
            'domain': domain,
            'status': 'running',
            'started_at': datetime.utcnow().isoformat(),
            'progress': 0
        }

    try:
        # Emit start event
        socketio.emit('scan_progress', {
            'scan_id': scan_id,
            'status': 'running',
            'progress': 10,
            'message': f'Starting scan for {domain}'
        })

        # Run CloudClear
        result = subprocess.run(
            [CLOUDCLEAR_BIN, domain],
            capture_output=True,
            text=True,
            timeout=300
        )

        # Parse results
        results = {
            'domain': domain,
            'exit_code': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'timestamp': datetime.utcnow().isoformat()
        }

        # Update scan status
        with scan_lock:
            active_scans[scan_id].update({
                'status': 'completed',
                'results': results,
                'completed_at': datetime.utcnow().isoformat(),
                'progress': 100
            })

        # Emit completion
        socketio.emit('scan_complete', {
            'scan_id': scan_id,
            'status': 'completed',
            'results': results
        })

    except subprocess.TimeoutExpired:
        with scan_lock:
            active_scans[scan_id].update({
                'status': 'timeout',
                'error': 'Scan timeout after 5 minutes'
            })
        socketio.emit('scan_error', {
            'scan_id': scan_id,
            'error': 'Timeout'
        })

    except Exception as e:
        with scan_lock:
            active_scans[scan_id].update({
                'status': 'error',
                'error': str(e)
            })
        socketio.emit('scan_error', {
            'scan_id': scan_id,
            'error': str(e)
        })

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
    return jsonify({
        'providers_configured': sum([
            bool(os.getenv('AKAMAI_CLIENT_TOKEN')),
            bool(os.getenv('AWS_ACCESS_KEY_ID')),
            bool(os.getenv('AZURE_CLIENT_ID')),
            bool(os.getenv('GCP_PROJECT_ID')),
            bool(os.getenv('FASTLY_API_KEY')),
            bool(os.getenv('DIGITALOCEAN_API_TOKEN')),
            bool(os.getenv('SHODAN_API_KEY')),
            bool(os.getenv('CENSYS_API_ID')),
            bool(os.getenv('VIRUSTOTAL_API_KEY'))
        ]),
        'total_providers': 9
    })

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    emit('connected', {'message': 'Connected to CloudClear'})

@socketio.on('subscribe_scan')
def handle_subscribe(data):
    """Subscribe to scan updates"""
    scan_id = data.get('scan_id')
    if scan_id:
        emit('subscribed', {'scan_id': scan_id})

if __name__ == '__main__':
    port = int(os.environ.get('API_PORT', 8080))
    socketio.run(app, host='0.0.0.0', port=port, debug=False)
