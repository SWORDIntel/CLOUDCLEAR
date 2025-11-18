/**
 * CloudClear Web UI - TEMPEST Class C
 * Real-time cloud provider detection interface
 */

class CloudClearApp {
    constructor() {
        this.apiBase = window.location.origin + '/api/v1';
        this.socket = null;
        this.currentScanId = null;
        this.init();
    }

    async init() {
        console.log('[CloudClear] Initializing...');

        // Connect WebSocket
        this.connectWebSocket();

        // Load initial data
        await this.loadSystemInfo();
        await this.loadIntegrations();

        // Set up event listeners
        this.setupEventListeners();

        // Update system status
        this.updateSystemStatus();
        setInterval(() => this.updateSystemStatus(), 30000);

        console.log('[CloudClear] Initialized successfully');
    }

    connectWebSocket() {
        try {
            this.socket = io({
                transports: ['websocket', 'polling'],
                upgrade: true
            });

            this.socket.on('connect', () => {
                console.log('[WebSocket] Connected');
                this.showToast('Connected to CloudClear', 'success');
            });

            this.socket.on('disconnect', () => {
                console.log('[WebSocket] Disconnected');
                this.showToast('Connection lost. Reconnecting...', 'warning');
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
        } catch (error) {
            console.error('[WebSocket] Connection error:', error);
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

        if (!domain) {
            this.showToast('Please enter a domain', 'error');
            return;
        }

        // Disable button
        const button = document.getElementById('scanButton');
        button.disabled = true;
        button.innerHTML = '<span class="button-text">SCANNING...</span>';

        try {
            const response = await fetch(`${this.apiBase}/scan`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ domain })
            });

            if (!response.ok) {
                throw new Error(`Scan failed: ${response.statusText}`);
            }

            const data = await response.json();
            this.currentScanId = data.scan_id;

            // Show progress section
            document.getElementById('scanTarget').textContent = domain;
            document.getElementById('progressSection').style.display = 'block';
            document.getElementById('resultsSection').style.display = 'none';

            // Subscribe to updates
            if (this.socket) {
                this.socket.emit('subscribe_scan', { scan_id: data.scan_id });
            }

            this.showToast('Scan initiated successfully', 'success');

        } catch (error) {
            console.error('[Scan] Error:', error);
            this.showToast(error.message, 'error');
            button.disabled = false;
            button.innerHTML = `
                <span class="button-text">INITIATE SCAN</span>
                <svg class="button-icon" viewBox="0 0 24 24" width="20" height="20">
                    <path d="M5 12h14M12 5l7 7-7 7" fill="none" stroke="currentColor" stroke-width="2"/>
                </svg>
            `;
        }
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

        // Hide progress, show results
        document.getElementById('progressSection').style.display = 'none';
        document.getElementById('resultsSection').style.display = 'block';

        // Parse and display results
        this.displayResults(data.results);

        // Re-enable button
        const button = document.getElementById('scanButton');
        button.disabled = false;
        button.innerHTML = `
            <span class="button-text">INITIATE SCAN</span>
            <svg class="button-icon" viewBox="0 0 24 24" width="20" height="20">
                <path d="M5 12h14M12 5l7 7-7 7" fill="none" stroke="currentColor" stroke-width="2"/>
            </svg>
        `;

        this.showToast('Scan completed successfully', 'success');
        this.currentScanId = null;
    }

    handleScanError(data) {
        if (data.scan_id !== this.currentScanId) return;

        console.error('[Scan] Error:', data);

        document.getElementById('progressSection').style.display = 'none';

        // Re-enable button
        const button = document.getElementById('scanButton');
        button.disabled = false;
        button.innerHTML = `
            <span class="button-text">INITIATE SCAN</span>
            <svg class="button-icon" viewBox="0 0 24 24" width="20" height="20">
                <path d="M5 12h14M12 5l7 7-7 7" fill="none" stroke="currentColor" stroke-width="2"/>
            </svg>
        `;

        this.showToast(`Scan error: ${data.error}`, 'error');
        this.currentScanId = null;
    }

    displayResults(results) {
        const container = document.getElementById('resultsContainer');
        container.innerHTML = '';

        // Create result card
        const card = document.createElement('div');
        card.className = 'result-card';

        // Add result content
        card.innerHTML = `
            <h3 style="margin-bottom: 1rem; color: var(--tempest-accent-primary);">
                Detection Complete: ${results.domain}
            </h3>
            <div style="background: var(--tempest-bg-secondary); padding: 1rem; border-radius: 6px; margin-bottom: 1rem;">
                <p style="margin-bottom: 0.5rem;"><strong>Status:</strong>
                    <span style="color: ${results.exit_code === 0 ? 'var(--tempest-success)' : 'var(--tempest-error)'}">
                        ${results.exit_code === 0 ? 'SUCCESS' : 'FAILED'}
                    </span>
                </p>
                <p style="margin-bottom: 0.5rem;"><strong>Timestamp:</strong> ${new Date(results.timestamp).toLocaleString()}</p>
            </div>
            <div style="background: var(--tempest-bg-secondary); padding: 1rem; border-radius: 6px; font-family: var(--font-mono); font-size: 0.85rem; overflow-x: auto;">
                <strong style="color: var(--tempest-accent-primary);">Detection Output:</strong>
                <pre style="margin-top: 0.5rem; white-space: pre-wrap; color: var(--tempest-text-secondary);">${this.escapeHtml(results.stdout || 'No output')}</pre>
            </div>
        `;

        container.appendChild(card);
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
