class PhishingDetectionBackground {
    constructor() {
        this.scanCache = new Map();
        this.cacheTimeout = 5 * 60 * 1000; // 5 minutes
        this.apiUrl = 'http://localhost:8000';
        this.init();
    }
    

    init() {
        this.setupMessageHandlers();
        this.setupTabHandlers();
        this.setupAlarms();
        this.setupBadgeDefault();
    }

    setupMessageHandlers() {
        chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
            this.handleMessage(message, sender, sendResponse);
            return true; // Keep message channel open for async responses
        });
    }

    setupTabHandlers() {
        chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
            if (changeInfo.status === 'complete' && tab.url) {
                this.checkTabUrl(tabId, tab.url);
            }
        });

        chrome.tabs.onActivated.addListener((activeInfo) => {
            chrome.tabs.get(activeInfo.tabId, (tab) => {
                if (tab.url) {
                    this.updateBadgeForTab(tab.url);
                }
            });
        });
    }

    setupAlarms() {
        chrome.alarms.create('clearCache', { periodInMinutes: 30 });
        
        chrome.alarms.onAlarm.addListener((alarm) => {
            if (alarm.name === 'clearCache') {
                this.clearExpiredCache();
            }
        });
    }

    setupBadgeDefault() {
        chrome.action.setBadgeBackgroundColor({ color: '#28a745' });
        chrome.action.setBadgeText({ text: '' });
    }

    async handleMessage(message, sender, sendResponse) {
        try {
            switch (message.action) {
                case 'scan_complete':
                    await this.handleScanComplete(message.data, sender.tab);
                    sendResponse({ success: true });
                    break;

                case 'scan_error':
                    await this.handleScanError(message.data, sender.tab);
                    sendResponse({ success: true });
                    break;

                case 'user_action':
                    await this.handleUserAction(message.data, sender.tab);
                    sendResponse({ success: true });
                    break;

                case 'get_cached_result':
                    const cached = this.getCachedResult(message.url);
                    sendResponse({ cached });
                    break;

                case 'manual_scan':
                    const result = await this.performManualScan(message.url);
                    sendResponse(result);
                    break;

                default:
                    sendResponse({ error: 'Unknown action' });
            }
        } catch (error) {
            console.error('Background script error:', error);
            sendResponse({ error: error.message });
        }
    }

    async checkTabUrl(tabId, url) {
        if (this.shouldSkipUrl(url)) {
            return;
        }

        const cached = this.getCachedResult(url);
        if (cached) {
            this.updateTabBadge(tabId, cached.threatScore);
            return;
        }

        try {
            const result = await this.scanUrl(url);
            this.cacheResult(url, result);
            this.updateTabBadge(tabId, result.threat_score || 0);
        } catch (error) {
            console.log('Background scan failed:', error);
        }
    }

    async scanUrl(url) {
        const response = await fetch(`${this.apiUrl}/scan-url`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url })
        });

        if (!response.ok) {
            throw new Error(`API Error: ${response.status}`);
        }

        return await response.json();
    }

    async performManualScan(url) {
        try {
            const result = await this.scanUrl(url);
            this.cacheResult(url, result);
            return { success: true, result };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    shouldSkipUrl(url) {
        return !url || 
               url.startsWith('chrome://') ||
               url.startsWith('chrome-extension://') ||
               url.startsWith('edge://') ||
               url.startsWith('about:') ||
               url.startsWith('file://');
    }

    cacheResult(url, result) {
        this.scanCache.set(url, {
            result,
            threatScore: result.threat_score || 0,
            timestamp: Date.now()
        });
    }

    getCachedResult(url) {
        const cached = this.scanCache.get(url);
        if (!cached) {
            return null;
        }

        if (Date.now() - cached.timestamp > this.cacheTimeout) {
            this.scanCache.delete(url);
            return null;
        }

        return cached;
    }

    clearExpiredCache() {
        const now = Date.now();
        for (const [url, data] of this.scanCache.entries()) {
            if (now - data.timestamp > this.cacheTimeout) {
                this.scanCache.delete(url);
            }
        }
    }

    async handleScanComplete(data, tab) {
        if (!tab) return;

        this.cacheResult(data.url, data.results);
        this.updateTabBadge(tab.id, data.threatScore);
        
        this.logThreatDetection(data);
    }

    async handleScanError(data, tab) {
        console.log('Scan error reported:', data.error);
        
        if (tab) {
            chrome.action.setBadgeText({ text: '!', tabId: tab.id });
            chrome.action.setBadgeBackgroundColor({ color: '#ffc107', tabId: tab.id });
        }
    }

    async handleUserAction(data, tab) {
        console.log('User action:', data.action, 'on', tab?.url);
        
        this.logUserAction(data, tab);
    }

    updateTabBadge(tabId, threatScore) {
        if (threatScore >= 70) {
            chrome.action.setBadgeText({ text: '🚨', tabId });
            chrome.action.setBadgeBackgroundColor({ color: '#dc3545', tabId });
        } else if (threatScore >= 30) {
            chrome.action.setBadgeText({ text: '⚠️', tabId });
            chrome.action.setBadgeBackgroundColor({ color: '#ffc107', tabId });
        } else {
            chrome.action.setBadgeText({ text: '', tabId });
            chrome.action.setBadgeBackgroundColor({ color: '#28a745', tabId });
        }
    }

    updateBadgeForTab(url) {
        const cached = this.getCachedResult(url);
        if (cached) {
            chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                if (tabs[0]) {
                    this.updateTabBadge(tabs[0].id, cached.threatScore);
                }
            });
        }
    }

    logThreatDetection(data) {
        if (data.threatScore >= 30) {
            console.log('Threat detected:', {
                url: data.url,
                score: data.threatScore,
                timestamp: new Date().toISOString(),
                results: data.results
            });
            
            this.incrementThreatCounter();
        }
    }

    logUserAction(data, tab) {
        const logEntry = {
            action: data.action,
            url: tab?.url,
            timestamp: new Date().toISOString()
        };
        
        console.log('User action logged:', logEntry);
    }

    async incrementThreatCounter() {
        const result = await chrome.storage.local.get(['threatsBlocked']);
        const count = (result.threatsBlocked || 0) + 1;
        await chrome.storage.local.set({ threatsBlocked: count });
    }

    // Extension lifecycle handlers
    onInstalled() {
        chrome.storage.local.set({
            threatsBlocked: 0,
            extensionInstalled: Date.now()
        });
        
        console.log('Phishing Detection Extension installed');
    }

    onStartup() {
        console.log('Phishing Detection Extension started');
        this.clearExpiredCache();
    }
}

const phishingDetection = new PhishingDetectionBackground();

chrome.runtime.onInstalled.addListener(() => {
    phishingDetection.onInstalled();
});

chrome.runtime.onStartup.addListener(() => {
    phishingDetection.onStartup();
});