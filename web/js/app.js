/**
 * CloudClear Web UI - TEMPEST Class C
 * Real-time cloud provider detection interface with enhanced error handling
 */

class CloudClearApp {
    constructor() {
        this.apiBase = window.location.origin + '/api/v1';
        this.socket = null;
        this.currentScanId = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 2000;
        this.statusUpdateInterval = null;
        this.init();
    }

    async init() {
        console.log('[CloudClear] Initializing TEMPEST Class C Interface...');

        try {
            // Connect WebSocket with retry logic
            this.connectWebSocket();

            // Load initial data
            await this.loadSystemInfo();
            await this.loadIntegrations();

            // Set up event listeners
            this.setupEventListeners();

            // Update system status
            await this.updateSystemStatus();
            this.statusUpdateInterval = setInterval(() => this.updateSystemStatus(), 30000);

            console.log('[CloudClear] Initialization complete');
            this.showToast('CloudClear interface ready', 'success');
        } catch (error) {
            console.error('[CloudClear] Initialization failed:', error);
            this.showToast('Failed to initialize interface', 'error');
        }
    }

    connectWebSocket() {
        try {
            console.log('[WebSocket] Establishing connection...');

            this.socket = io({
                transports: ['websocket', 'polling'],
                upgrade: true,
                reconnection: true,
                reconnectionAttempts: this.maxReconnectAttempts,
                reconnectionDelay: this.reconnectDelay,
                timeout: 10000
            });

            this.socket.on('connect', () => {
                console.log('[WebSocket] Connected successfully');
                this.reconnectAttempts = 0;
                this.updateConnectionStatus(true);
            });

            this.socket.on('disconnect', (reason) => {
                console.log(`[WebSocket] Disconnected: ${reason}`);
                this.updateConnectionStatus(false);

                if (reason === 'io server disconnect') {
                    // Server initiated disconnect, try to reconnect
                    this.socket.connect();
                }
            });

            this.socket.on('connect_error', (error) => {
                console.error('[WebSocket] Connection error:', error);
                this.reconnectAttempts++;

                if (this.reconnectAttempts >= this.maxReconnectAttempts) {
                    this.showToast('Unable to connect to server', 'error');
                } else {
                    this.showToast(`Reconnecting... (${this.reconnectAttempts}/${this.maxReconnectAttempts})`, 'warning');
                }
            });

            this.socket.on('reconnect', (attemptNumber) => {
                console.log(`[WebSocket] Reconnected after ${attemptNumber} attempts`);
                this.showToast('Reconnected to server', 'success');
                this.reconnectAttempts = 0;
            });

            this.socket.on('scan_progress', (data) => {
                this.handleScanProgress(data);
            });

            this.socket.on('scan_complete', (data) => {
                this.handleScanComplete(data);
            });

            this.socket.on('scan_error', (data) => {
                this.handleScanError(data);
            });

            this.socket.on('connected', (data) => {
                console.log('[WebSocket] Server acknowledged connection:', data);
            });

        } catch (error) {
            console.error('[WebSocket] Fatal connection error:', error);
            this.showToast('WebSocket initialization failed', 'error');
        }
    }

    updateConnectionStatus(connected) {
        const statusIndicator = document.getElementById('systemStatus');
        if (connected) {
            statusIndicator.innerHTML = '<span class="pulse"></span> OPERATIONAL';
            statusIndicator.style.color = 'var(--tempest-success)';
        } else {
            statusIndicator.innerHTML = '<span class="pulse"></span> RECONNECTING';
            statusIndicator.style.color = 'var(--tempest-warning)';
        }
    }

    setupEventListeners() {
        const form = document.getElementById('scanForm');
        form.addEventListener('submit', (e) => {
            e.preventDefault();
            this.startScan();
        });
    }

    async loadSystemInfo() {
        try {
            const response = await fetch(`${this.apiBase}/info`);
            const data = await response.json();
            console.log('[System] Info loaded:', data);
        } catch (error) {
            console.error('[System] Failed to load info:', error);
        }
    }

    async loadIntegrations() {
        try {
            const response = await fetch(`${this.apiBase}/info`);
            const data = await response.json();

            const container = document.getElementById('integrationsGrid');
            container.innerHTML = '';

            // Cloud providers
            data.integrations.cloud_providers.forEach(provider => {
                container.appendChild(this.createIntegrationCard(provider));
            });

            // Intelligence services
            data.integrations.intelligence.forEach(service => {
                container.appendChild(this.createIntegrationCard(service));
            });

            // Update provider count
            const enabledCount = [
                ...data.integrations.cloud_providers,
                ...data.integrations.intelligence
            ].filter(i => i.enabled).length;

            document.getElementById('providersConfigured').textContent = enabledCount;
        } catch (error) {
            console.error('[Integrations] Failed to load:', error);
        }
    }

    createIntegrationCard(integration) {
        const card = document.createElement('div');
        card.className = 'integration-card';

        const name = document.createElement('div');
        name.className = 'integration-name';
        name.textContent = integration.name;

        const badge = document.createElement('span');
        badge.className = `integration-badge ${integration.enabled ? 'active' : 'inactive'}`;
        badge.textContent = integration.enabled ? 'ACTIVE' : 'INACTIVE';

        card.appendChild(name);
        card.appendChild(badge);

        return card;
    }

    async startScan() {
        const domainInput = document.getElementById('domainInput');
        const domain = domainInput.value.trim();

        // Client-side validation
        if (!domain) {
            this.showToast('Please enter a domain name', 'error');
            domainInput.focus();
            return;
        }

        // Validate domain format (basic check)
        const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
        if (!domainRegex.test(domain)) {
            this.showToast('Invalid domain format (e.g., example.com)', 'error');
            domainInput.focus();
            return;
        }

        // Disable button and show loading state
        const button = document.getElementById('scanButton');
        button.disabled = true;
        button.innerHTML = `
            <span class="button-text">SCANNING...</span>
            <span style="margin-left: 8px;">⏳</span>
        `;

        try {
            console.log(`[Scan] Initiating scan for: ${domain}`);

            const response = await fetch(`${this.apiBase}/scan`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({ domain })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || data.error || `HTTP ${response.status}`);
            }

            this.currentScanId = data.scan_id;
            console.log(`[Scan] Started with ID: ${this.currentScanId}`);

            // Show progress section
            document.getElementById('scanTarget').textContent = domain;
            document.getElementById('progressSection').style.display = 'block';
            document.getElementById('resultsSection').style.display = 'none';

            // Reset progress bar
            document.getElementById('progressBar').style.width = '0%';
            document.getElementById('scanStatus').textContent = 'INITIALIZING';
            document.getElementById('progressDetails').textContent = 'Starting cloud provider detection...';

            // Subscribe to WebSocket updates
            if (this.socket && this.socket.connected) {
                this.socket.emit('subscribe_scan', { scan_id: data.scan_id });
            } else {
                console.warn('[Scan] WebSocket not connected, results may be delayed');
            }

            this.showToast(`Scanning ${domain}...`, 'info');

        } catch (error) {
            console.error('[Scan] Failed to start:', error);
            this.showToast(error.message || 'Failed to start scan', 'error');
            this.resetScanButton(button);
            document.getElementById('progressSection').style.display = 'none';
        }
    }

    resetScanButton(button) {
        if (!button) {
            button = document.getElementById('scanButton');
        }
        button.disabled = false;
        button.innerHTML = `
            <span class="button-text">INITIATE SCAN</span>
            <svg class="button-icon" viewBox="0 0 24 24" width="20" height="20">
                <path d="M5 12h14M12 5l7 7-7 7" fill="none" stroke="currentColor" stroke-width="2"/>
            </svg>
        `;
    }

    handleScanProgress(data) {
        if (data.scan_id !== this.currentScanId) return;

        const progressBar = document.getElementById('progressBar');
        const statusText = document.getElementById('scanStatus');
        const detailsText = document.getElementById('progressDetails');

        progressBar.style.width = `${data.progress}%`;
        statusText.textContent = data.status.toUpperCase();
        detailsText.textContent = data.message || 'Scanning...';
    }

    handleScanComplete(data) {
        if (data.scan_id !== this.currentScanId) return;

        console.log('[Scan] Complete:', data);

        // Update progress to 100%
        document.getElementById('progressBar').style.width = '100%';
        document.getElementById('scanStatus').textContent = 'COMPLETED';
        document.getElementById('progressDetails').textContent = 'Detection complete. Processing results...';

        // Short delay before showing results for smooth transition
        setTimeout(() => {
            // Hide progress, show results
            document.getElementById('progressSection').style.display = 'none';
            document.getElementById('resultsSection').style.display = 'block';

            // Parse and display results
            this.displayResults(data.results);

            // Re-enable button
            this.resetScanButton();

            // Clear domain input
            document.getElementById('domainInput').value = '';

            this.showToast('Detection completed', 'success');
            this.currentScanId = null;
        }, 500);
    }

    handleScanError(data) {
        if (data.scan_id !== this.currentScanId) return;

        console.error('[Scan] Error:', data);

        // Update progress bar to show error state
        const progressBar = document.getElementById('progressBar');
        progressBar.style.width = '100%';
        progressBar.style.background = 'var(--tempest-error)';

        document.getElementById('scanStatus').textContent = 'ERROR';
        document.getElementById('progressDetails').textContent = data.message || data.error || 'Scan failed';

        // Wait a moment then hide progress section
        setTimeout(() => {
            document.getElementById('progressSection').style.display = 'none';
            progressBar.style.background = 'linear-gradient(90deg, var(--tempest-accent-primary), var(--tempest-accent-secondary))';

            this.resetScanButton();
            this.currentScanId = null;
        }, 2000);

        this.showToast(`Scan failed: ${data.error || 'Unknown error'}`, 'error');
    }

    displayResults(results) {
        const container = document.getElementById('resultsContainer');
        container.innerHTML = '';

        // Create result card
        const card = document.createElement('div');
        card.className = 'result-card';

        // Parse output for detected providers
        const detectedProviders = this.parseDetectedProviders(results.stdout || '');

        // Format timestamp
        const timestamp = new Date(results.timestamp);
        const timestampStr = timestamp.toLocaleString('en-US', {
            month: 'short',
            day: 'numeric',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });

        // Build result HTML
        let resultHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
                <h3 style="color: var(--tempest-accent-primary); margin: 0;">
                    ${results.success ? '✓' : '✗'} Detection Complete
                </h3>
                <span style="font-family: var(--font-mono); color: var(--tempest-text-dim); font-size: 0.85rem;">
                    ${timestampStr}
                </span>
            </div>

            <div style="background: var(--tempest-bg-secondary); padding: 1rem; border-radius: 6px; margin-bottom: 1rem;">
                <p style="margin-bottom: 0.5rem;">
                    <strong style="color: var(--tempest-text-primary);">Target:</strong>
                    <span style="color: var(--tempest-accent-primary); font-family: var(--font-mono);">${this.escapeHtml(results.domain)}</span>
                </p>
                <p style="margin-bottom: 0.5rem;">
                    <strong style="color: var(--tempest-text-primary);">Status:</strong>
                    <span style="color: ${results.success ? 'var(--tempest-success)' : 'var(--tempest-error)'}; font-weight: 700;">
                        ${results.success ? 'SUCCESS' : 'FAILED'}
                    </span>
                </p>
                ${detectedProviders.length > 0 ? `
                <p style="margin-bottom: 0;">
                    <strong style="color: var(--tempest-text-primary);">Detected:</strong>
                    <span style="color: var(--tempest-success);">${detectedProviders.join(', ')}</span>
                </p>
                ` : ''}
            </div>

            <div style="background: var(--tempest-bg-secondary); padding: 1rem; border-radius: 6px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                    <strong style="color: var(--tempest-accent-primary);">Full Detection Output</strong>
                </div>
                <pre style="margin: 0; white-space: pre-wrap; font-family: var(--font-mono); font-size: 0.85rem; color: var(--tempest-text-secondary); max-height: 400px; overflow-y: auto;">${this.escapeHtml(results.stdout || 'No output available')}</pre>
            </div>

            ${results.stderr ? `
            <div style="background: var(--tempest-bg-secondary); padding: 1rem; border-radius: 6px; border-left: 3px solid var(--tempest-error); margin-top: 1rem;">
                <strong style="color: var(--tempest-error);">Errors/Warnings:</strong>
                <pre style="margin-top: 0.5rem; margin-bottom: 0; white-space: pre-wrap; font-family: var(--font-mono); font-size: 0.85rem; color: var(--tempest-text-dim);">${this.escapeHtml(results.stderr)}</pre>
            </div>
            ` : ''}
        `;

        card.innerHTML = resultHTML;
        container.appendChild(card);

        // Scroll results into view
        container.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    parseDetectedProviders(output) {
        const providers = [];
        const lines = output.split('\n');

        // Look for common detection patterns
        const patterns = [
            /cloudflare/i,
            /akamai/i,
            /amazon|aws|cloudfront/i,
            /azure|microsoft/i,
            /google|gcp/i,
            /fastly/i,
            /digitalocean/i,
            /oracle cloud/i,
            /alibaba/i,
            /imperva|incapsula/i,
            /sucuri/i,
            /stackpath/i
        ];

        const names = [
            'Cloudflare', 'Akamai', 'AWS', 'Azure', 'GCP',
            'Fastly', 'DigitalOcean', 'Oracle Cloud', 'Alibaba Cloud',
            'Imperva', 'Sucuri', 'Stackpath'
        ];

        patterns.forEach((pattern, index) => {
            if (pattern.test(output) && !providers.includes(names[index])) {
                providers.push(names[index]);
            }
        });

        return providers;
    }

    async updateSystemStatus() {
        try {
            const response = await fetch(`${this.apiBase}/../health`);
            const data = await response.json();

            const statusIndicator = document.getElementById('systemStatus');
            if (data.status === 'healthy') {
                statusIndicator.innerHTML = '<span class="pulse"></span> OPERATIONAL';
                statusIndicator.style.color = 'var(--tempest-success)';
            }

            // Update active scans count
            document.getElementById('activeScans').textContent = data.active_scans || 0;

        } catch (error) {
            console.error('[System] Status update failed:', error);
            const statusIndicator = document.getElementById('systemStatus');
            statusIndicator.innerHTML = '<span class="pulse"></span> DEGRADED';
            statusIndicator.style.color = 'var(--tempest-warning)';
        }
    }

    showToast(message, type = 'info') {
        const container = document.getElementById('toastContainer');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;

        container.appendChild(toast);

        setTimeout(() => {
            toast.style.animation = 'slideIn 0.3s ease reverse';
            setTimeout(() => toast.remove(), 300);
        }, 5000);
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Show documentation
function showDocs() {
    window.open('/docs/CLOUD_INTEGRATION_COMPLETE.md', '_blank');
}

// Show about
function showAbout() {
    alert('CloudClear v2.0-Enhanced-Cloud\nAdvanced Cloud Provider Detection & Intelligence\n\n© 2025 SWORD Intelligence');
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.cloudclear = new CloudClearApp();
});
