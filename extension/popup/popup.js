class PhishingDetectionPopup {
    constructor() {
        this.apiUrl = 'http://localhost:8000';
        this.currentUrl = '';
        this.scanResults = {};
        this.init();
    }

    async init() {
        await this.getCurrentTab();
        this.setupEventListeners();
        this.updateUI();
        this.performScan();
    }

    async getCurrentTab() {
        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            this.currentUrl = tab.url;
            document.getElementById('current-url').textContent = this.currentUrl;
        } catch (error) {
            console.error('Error getting current tab:', error);
            document.getElementById('current-url').textContent = 'Unable to get URL';
        }
    }

    setupEventListeners() {
        document.getElementById('rescan-btn').addEventListener('click', () => {
            this.performScan();
        });

        document.getElementById('report-btn').addEventListener('click', () => {
            this.reportIssue();
        });

        document.getElementById('settings-link').addEventListener('click', (e) => {
            e.preventDefault();
            this.openSettings();
        });
    }

    updateUI() {
        if (!this.currentUrl) return;

        if (this.currentUrl.startsWith('chrome://') || 
            this.currentUrl.startsWith('chrome-extension://') ||
            this.currentUrl.startsWith('edge://') ||
            this.currentUrl.startsWith('about:')) {
            this.showBrowserPage();
            return;
        }

        this.updateStatus('checking', 'Scanning URL...', 'Please wait while we check this site');
    }

    showBrowserPage() {
        this.updateStatus('safe', 'Browser Page', 'This is a browser internal page');
        document.getElementById('sb-status').textContent = 'N/A';
        document.getElementById('vt-status').textContent = 'N/A';
        document.getElementById('pt-status').textContent = 'N/A';
        document.getElementById('sb-status').className = 'api-status';
        document.getElementById('vt-status').className = 'api-status';
        document.getElementById('pt-status').className = 'api-status';
        document.getElementById('rescan-btn').disabled = true;
    }

    async performScan() {
        if (!this.currentUrl || 
            this.currentUrl.startsWith('chrome://') || 
            this.currentUrl.startsWith('chrome-extension://')) {
            return;
        }

        this.updateStatus('checking', 'Scanning...', 'Checking URL against threat databases');
        this.resetApiStatuses();

        try {
            const response = await fetch(`${this.apiUrl}/scan-url`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: this.currentUrl })
            });

            if (!response.ok) {
                throw new Error(`API Error: ${response.status}`);
            }

            const results = await response.json();
            this.processScanResults(results);
        } catch (error) {
            console.error('Scan error:', error);
            this.handleScanError(error);
        }
    }

    resetApiStatuses() {
        const statuses = ['sb-status', 'vt-status', 'pt-status'];
        statuses.forEach(id => {
            const element = document.getElementById(id);
            element.textContent = 'Checking...';
            element.className = 'api-status checking';
        });
    }

    processScanResults(results) {
        this.scanResults = results;

        this.updateApiStatus('sb-status', results.safe_browsing);
        this.updateApiStatus('vt-status', results.virustotal);
        this.updateApiStatus('pt-status', results.phishtank);

        const threatScore = results.threat_score || 0;
        this.updateThreatScore(threatScore);

        if (threatScore >= 70) {
            this.updateStatus('danger', 'Threat Detected!', 
                'This site may be malicious. Proceed with caution.');
        } else if (threatScore >= 30) {
            this.updateStatus('warning', 'Suspicious Site', 
                'This site shows some suspicious indicators.');
        } else {
            this.updateStatus('safe', 'Site Appears Safe', 
                'No significant threats detected.');
        }
    }

    updateApiStatus(elementId, result) {
        const element = document.getElementById(elementId);
        
        if (!result) {
            element.textContent = 'No Data';
            element.className = 'api-status';
            return;
        }
        
        if (result.error) {
            // Special handling for PhishTank Cloudflare blocks
            if (elementId === 'pt-status' && result.error.includes('403')) {
                element.textContent = 'Blocked';
                element.className = 'api-status';
                element.title = 'PhishTank is temporarily blocked by Cloudflare';
            } else {
                element.textContent = 'Error';
                element.className = 'api-status warning';
            }
            return;
        }
        
        // Check for PhishTank Cloudflare message
        if (result.details && result.details.includes('Cloudflare')) {
            element.textContent = 'Skipped';
            element.className = 'api-status';
            element.title = result.details;
            return;
        }

        if (result.is_malicious) {
            element.textContent = 'Threat Found';
            element.className = 'api-status danger';
        } else if (result.is_suspicious) {
            element.textContent = 'Suspicious';
            element.className = 'api-status warning';
        } else {
            element.textContent = 'Clean';
            element.className = 'api-status safe';
        }
    }

    updateThreatScore(score) {
        const scoreElement = document.getElementById('score-text');
        const fillElement = document.getElementById('score-fill');
        
        scoreElement.textContent = `${score}/100`;
        fillElement.style.width = `${score}%`;
    }

    updateStatus(type, title, message) {
        const statusCard = document.getElementById('current-status');
        const statusTitle = document.getElementById('status-title');
        const statusMessage = document.getElementById('status-message');
        const statusIcon = statusCard.querySelector('.status-icon');

        statusCard.className = `status-card ${type}`;
        statusTitle.textContent = title;
        statusMessage.textContent = message;

        const icons = {
            safe: '✅',
            warning: '⚠️',
            danger: '🚨',
            checking: '🔍'
        };
        
        statusIcon.textContent = icons[type] || '❓';
    }

    handleScanError(error) {
        console.error('Scan failed:', error);
        this.updateStatus('warning', 'Scan Failed', 
            'Unable to complete security scan. Check your connection.');
        
        const statuses = ['sb-status', 'vt-status', 'pt-status'];
        statuses.forEach(id => {
            const element = document.getElementById(id);
            element.textContent = 'Offline';
            element.className = 'api-status warning';
        });
    }

    reportIssue() {
        const reportUrl = `mailto:security@example.com?subject=Phishing Report&body=URL: ${encodeURIComponent(this.currentUrl)}%0A%0ADetails: `;
        window.open(reportUrl);
    }

    openSettings() {
        chrome.runtime.openOptionsPage();
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new PhishingDetectionPopup();
});