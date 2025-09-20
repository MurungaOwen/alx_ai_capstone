class PhishingDetectionContent {
    constructor() {
        this.apiUrl = 'http://localhost:8000';
        this.currentUrl = window.location.href;
        this.isChecking = false;
        this.warningDisplayed = false;
        this.init();
    }

    init() {
        if (this.shouldSkipUrl()) {
            return;
        }

        this.setupUrlMonitoring();
        this.checkCurrentUrl();
        this.setupMessageListener();
    }

    shouldSkipUrl() {
        return this.currentUrl.startsWith('chrome://') ||
               this.currentUrl.startsWith('chrome-extension://') ||
               this.currentUrl.startsWith('edge://') ||
               this.currentUrl.startsWith('about:') ||
               this.currentUrl.startsWith('file://');
    }

    setupUrlMonitoring() {
        let lastUrl = window.location.href;
        
        const observer = new MutationObserver(() => {
            if (window.location.href !== lastUrl) {
                lastUrl = window.location.href;
                this.currentUrl = lastUrl;
                this.warningDisplayed = false;
                this.checkCurrentUrl();
            }
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });

        window.addEventListener('popstate', () => {
            this.currentUrl = window.location.href;
            this.warningDisplayed = false;
            this.checkCurrentUrl();
        });
    }

    setupMessageListener() {
        chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
            if (message.action === 'checkUrl') {
                this.checkCurrentUrl();
                sendResponse({success: true});
            } else if (message.action === 'getUrlInfo') {
                sendResponse({
                    url: this.currentUrl,
                    isChecking: this.isChecking,
                    warningDisplayed: this.warningDisplayed
                });
            }
        });
    }

    async checkCurrentUrl() {
        if (this.isChecking || this.shouldSkipUrl()) {
            return;
        }

        this.isChecking = true;
        
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
            console.log('Phishing detection scan failed:', error);
            this.notifyBackground('scan_error', { error: error.message });
        } finally {
            this.isChecking = false;
        }
    }

    processScanResults(results) {
        const threatScore = results.threat_score || 0;
        
        this.notifyBackground('scan_complete', {
            url: this.currentUrl,
            results: results,
            threatScore: threatScore
        });

        if (threatScore >= 70 && !this.warningDisplayed) {
            this.showPhishingWarning(results);
        } else if (threatScore >= 30 && !this.warningDisplayed) {
            this.showSuspiciousWarning(results);
        }
    }

    showPhishingWarning(results) {
        this.warningDisplayed = true;
        
        const warningDiv = document.createElement('div');
        warningDiv.id = 'phishing-warning-overlay';
        warningDiv.innerHTML = `
            <div class="phishing-warning-modal">
                <div class="warning-header">
                    <div class="warning-icon">🚨</div>
                    <h2>WARNING: Potential Phishing Site</h2>
                </div>
                <div class="warning-content">
                    <p><strong>This website may be trying to steal your personal information.</strong></p>
                    <p>Our security scan detected multiple indicators that this site may be malicious:</p>
                    <ul>
                        ${this.generateThreatList(results)}
                    </ul>
                    <p><strong>Recommended actions:</strong></p>
                    <ul>
                        <li>Do not enter passwords, credit card details, or personal information</li>
                        <li>Close this tab immediately</li>
                        <li>If you trust this site, you can proceed with caution</li>
                    </ul>
                </div>
                <div class="warning-actions">
                    <button id="leave-site-btn" class="btn btn-danger">Leave This Site</button>
                    <button id="continue-anyway-btn" class="btn btn-secondary">Continue Anyway</button>
                </div>
            </div>
        `;

        this.addWarningStyles();
        document.body.appendChild(warningDiv);
        this.setupWarningActions();
    }

    showSuspiciousWarning(results) {
        this.warningDisplayed = true;
        
        const warningBanner = document.createElement('div');
        warningBanner.id = 'phishing-warning-banner';
        warningBanner.innerHTML = `
            <div class="suspicious-banner">
                <div class="banner-content">
                    <span class="warning-icon">⚠️</span>
                    <span class="banner-text">
                        <strong>Suspicious Site Detected:</strong> 
                        This website shows some security concerns. Exercise caution.
                    </span>
                    <button id="banner-details-btn" class="btn btn-link">Details</button>
                    <button id="banner-close-btn" class="btn btn-close">×</button>
                </div>
            </div>
        `;

        this.addBannerStyles();
        document.body.insertBefore(warningBanner, document.body.firstChild);
        this.setupBannerActions(results);
    }

    generateThreatList(results) {
        const threats = [];
        
        if (results.safe_browsing && results.safe_browsing.is_malicious) {
            threats.push('<li>Flagged by Google Safe Browsing</li>');
        }
        
        if (results.virustotal && results.virustotal.is_malicious) {
            threats.push('<li>Detected as malicious by VirusTotal scanners</li>');
        }
        
        if (results.phishtank && results.phishtank.is_malicious) {
            threats.push('<li>Listed in PhishTank database</li>');
        }
        
        if (threats.length === 0) {
            threats.push('<li>Suspicious URL patterns detected</li>');
        }
        
        return threats.join('');
    }

    setupWarningActions() {
        document.getElementById('leave-site-btn').addEventListener('click', () => {
            window.history.back();
            if (window.location.href === this.currentUrl) {
                window.close();
            }
        });

        document.getElementById('continue-anyway-btn').addEventListener('click', () => {
            document.getElementById('phishing-warning-overlay').remove();
            this.notifyBackground('user_action', { action: 'continued_anyway' });
        });
    }

    setupBannerActions(results) {
        document.getElementById('banner-close-btn').addEventListener('click', () => {
            document.getElementById('phishing-warning-banner').remove();
        });

        document.getElementById('banner-details-btn').addEventListener('click', () => {
            document.getElementById('phishing-warning-banner').remove();
            this.showPhishingWarning(results);
        });
    }

    notifyBackground(action, data) {
        chrome.runtime.sendMessage({
            action: action,
            data: data,
            url: this.currentUrl,
            timestamp: Date.now()
        });
    }

    addWarningStyles() {
        const style = document.createElement('style');
        style.textContent = `
            #phishing-warning-overlay {
                position: fixed !important;
                top: 0 !important;
                left: 0 !important;
                width: 100% !important;
                height: 100% !important;
                background: rgba(0, 0, 0, 0.8) !important;
                z-index: 999999 !important;
                display: flex !important;
                align-items: center !important;
                justify-content: center !important;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
            }
            
            .phishing-warning-modal {
                background: white !important;
                padding: 30px !important;
                border-radius: 12px !important;
                max-width: 500px !important;
                width: 90% !important;
                box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3) !important;
                color: #333 !important;
            }
            
            .warning-header {
                display: flex !important;
                align-items: center !important;
                gap: 15px !important;
                margin-bottom: 20px !important;
                padding-bottom: 15px !important;
                border-bottom: 2px solid #dc3545 !important;
            }
            
            .warning-icon {
                font-size: 32px !important;
            }
            
            .warning-header h2 {
                color: #dc3545 !important;
                font-size: 20px !important;
                margin: 0 !important;
                font-weight: 600 !important;
            }
            
            .warning-content p, .warning-content li {
                font-size: 14px !important;
                line-height: 1.5 !important;
                margin-bottom: 10px !important;
            }
            
            .warning-content ul {
                margin-left: 20px !important;
                margin-bottom: 15px !important;
            }
            
            .warning-actions {
                display: flex !important;
                gap: 15px !important;
                margin-top: 25px !important;
            }
            
            .btn {
                padding: 12px 24px !important;
                border: none !important;
                border-radius: 6px !important;
                font-size: 14px !important;
                font-weight: 500 !important;
                cursor: pointer !important;
                flex: 1 !important;
                text-align: center !important;
            }
            
            .btn-danger {
                background: #dc3545 !important;
                color: white !important;
            }
            
            .btn-danger:hover {
                background: #c82333 !important;
            }
            
            .btn-secondary {
                background: #6c757d !important;
                color: white !important;
            }
            
            .btn-secondary:hover {
                background: #545b62 !important;
            }
        `;
        document.head.appendChild(style);
    }

    addBannerStyles() {
        const style = document.createElement('style');
        style.textContent = `
            #phishing-warning-banner {
                position: fixed !important;
                top: 0 !important;
                left: 0 !important;
                width: 100% !important;
                z-index: 999998 !important;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
            }
            
            .suspicious-banner {
                background: linear-gradient(135deg, #ffc107 0%, #ff8c00 100%) !important;
                padding: 12px 20px !important;
                color: #333 !important;
                box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15) !important;
            }
            
            .banner-content {
                display: flex !important;
                align-items: center !important;
                justify-content: center !important;
                gap: 10px !important;
                flex-wrap: wrap !important;
                font-size: 14px !important;
            }
            
            .banner-text {
                flex: 1 !important;
                min-width: 200px !important;
            }
            
            .btn-link {
                background: transparent !important;
                color: #0056b3 !important;
                text-decoration: underline !important;
                border: none !important;
                cursor: pointer !important;
                font-size: 13px !important;
            }
            
            .btn-close {
                background: transparent !important;
                border: none !important;
                font-size: 18px !important;
                cursor: pointer !important;
                padding: 0 5px !important;
                color: #333 !important;
            }
        `;
        document.head.appendChild(style);
    }
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        new PhishingDetectionContent();
    });
} else {
    new PhishingDetectionContent();
}