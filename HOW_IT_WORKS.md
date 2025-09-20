# How the Phishing Detection Extension Works

## System Overview

The Phishing Detection Extension is a comprehensive security tool that protects users from phishing attacks by analyzing URLs in real-time using multiple threat intelligence sources. Here's a detailed explanation of how it works:

## Architecture Flow

```
[User browses website] → [Chrome Extension detects URL change]
                                    ↓
                        [Content Script captures URL]
                                    ↓
                        [Background Service Worker]
                                    ↓
                        [FastAPI Backend Server]
                                    ↓
                    [Parallel API Calls to 3 Services]
                    ↙            ↓              ↘
        [Google Safe Browsing] [VirusTotal] [PhishTank]
                    ↘            ↓              ↙
                        [Threat Score Calculation]
                                    ↓
                        [Response to Extension]
                                    ↓
                    [User Warning/Notification]
```

## Component Breakdown

### 1. Chrome Extension Components

#### **Content Script** (`content/content.js`)
- **Purpose**: Monitors every website you visit
- **How it works**:
  - Injects into every webpage automatically
  - Detects URL changes (including single-page applications)
  - Sends URLs to the background service worker for analysis
  - Displays warning overlays when threats are detected
  - Handles user interactions (dismiss warnings, report issues)

#### **Background Service Worker** (`background/background.js`)
- **Purpose**: Central hub for all extension operations
- **How it works**:
  - Receives URL check requests from content scripts
  - Manages communication with the FastAPI backend
  - Caches scan results for 5 minutes to improve performance
  - Updates extension badge with threat indicators
  - Handles extension lifecycle events

#### **Popup UI** (`popup/popup.html` & `popup.js`)
- **Purpose**: User interface for manual checks and results
- **How it works**:
  - Shows current website's threat status
  - Displays detailed results from each API service
  - Provides threat score visualization (0-100)
  - Allows manual rescanning
  - Links to settings and whitelist management

### 2. FastAPI Backend (`api-service/`)

The backend server acts as a secure intermediary between the extension and external APIs:

- **Endpoint**: `POST /scan-url`
- **Process**:
  1. Receives URL from extension
  2. Makes parallel requests to all three APIs
  3. Aggregates and normalizes responses
  4. Calculates unified threat score
  5. Returns comprehensive results

### 3. Threat Detection APIs

#### **Google Safe Browsing API**
- **Weight**: 40% of total score
- **Checks for**:
  - Known phishing sites
  - Malware distribution
  - Social engineering attacks
  - Unwanted software
- **Database**: Google's continuously updated threat list

#### **VirusTotal API**
- **Weight**: 35% of total score
- **Checks with**: 70+ antivirus engines and security tools
- **Process**:
  - Queries existing scan results
  - Submits new URLs for analysis if needed
  - Aggregates detection from multiple engines
- **Advantage**: Multiple independent verifications

#### **PhishTank API**
- **Weight**: 25% of total score
- **Database**: Community-reported phishing URLs
- **Features**:
  - Verified phishing sites
  - Submission timestamps
  - Community validation
- **Advantage**: Catches newly reported phishing sites quickly

## Threat Scoring Algorithm

```python
def calculate_threat_score(results):
    score = 0
    
    # Google Safe Browsing (40% weight)
    if results['safe_browsing']['is_malicious']:
        score += 40
    elif results['safe_browsing']['is_suspicious']:
        score += 20
    
    # VirusTotal (35% weight)
    if results['virustotal']['is_malicious']:
        score += 35
    elif results['virustotal']['is_suspicious']:
        score += 17
    
    # PhishTank (25% weight)
    if results['phishtank']['is_malicious']:
        score += 25
    elif results['phishtank']['is_suspicious']:
        score += 12
    
    return min(score, 100)
```

**Score Interpretation**:
- **0-29**: Safe (green shield)
- **30-69**: Suspicious (yellow warning)
- **70-100**: Dangerous (red alert)

## Real-Time Protection Flow

### When You Visit a Website:

1. **URL Detection** (0-50ms)
   - Content script detects navigation
   - Extracts current URL
   - Checks against local whitelist

2. **Cache Check** (0-10ms)
   - Background worker checks if URL was recently scanned
   - Returns cached result if available (< 5 minutes old)

3. **API Analysis** (500-2000ms)
   - FastAPI backend receives URL
   - Parallel API calls to all three services
   - Results aggregation and scoring

4. **User Notification** (0-100ms)
   - Extension badge updates (🛡️, ⚠️, or 🚨)
   - For threats: overlay warning appears
   - Popup shows detailed results

## Privacy & Security Features

1. **No Personal Data Collection**:
   - Only URLs are analyzed
   - No browsing history stored
   - No user identification

2. **Local Processing First**:
   - Whitelist checking happens locally
   - Cache reduces API calls
   - Browser-internal URLs never sent

3. **Secure Communication**:
   - HTTPS for all API calls
   - API keys stored locally only
   - No data persistence on backend

## Installing the Chrome Extension

### Step-by-Step Installation:

1. **Prepare the Extension**:
   ```bash
   # Clone the repository
   git clone https://github.com/MurungaOwen/alx_ai_capstone.git
   cd alx_ai_capstone
   ```

2. **Start the Backend Server**:
   ```bash
   # Install Python dependencies
   cd api-service
   pip install -r requirements.txt
   
   # Configure API keys
   cp ../config/api-keys.json.example ../config/api-keys.json
   # Edit api-keys.json with your API keys
   
   # Start the server
   uvicorn app:app --reload
   ```

3. **Load Extension in Chrome**:
   - Open Chrome browser
   - Type `chrome://extensions/` in address bar
   - Enable "Developer mode" (toggle switch in top-right)
   - Click "Load unpacked" button
   - Navigate to and select the `extension/` folder
   - The extension icon (shield) appears in toolbar

4. **Verify Installation**:
   - Click the extension icon - popup should open
   - Visit `http://localhost:8000` - should see API info
   - Browse any website - extension should scan it

### First Use:

1. **Icon States**:
   - Empty shield: Normal/safe site
   - Yellow shield (⚠️): Suspicious site detected
   - Red shield (🚨): Dangerous site detected
   - Exclamation (!): Scan error

2. **Using the Popup**:
   - Click extension icon to see current site status
   - View individual API results
   - See overall threat score
   - Click "Rescan" for fresh analysis

3. **Warning Overlays**:
   - Appear automatically on dangerous sites
   - Show specific threats detected
   - Options to leave or continue
   - Can report false positives

## Troubleshooting

### Extension Not Working?

1. **Check Backend Server**:
   ```bash
   curl http://localhost:8000/health
   ```

2. **Check Extension Console**:
   - Right-click extension icon → "Inspect popup"
   - Check for JavaScript errors

3. **Verify API Keys**:
   - Ensure all API keys are valid
   - Check rate limits haven't been exceeded

### Common Issues:

- **"Cannot connect to backend"**: Start the FastAPI server
- **"No results from APIs"**: Check API key configuration
- **"Extension not loading"**: Verify all files are present
- **"Warnings not showing"**: Check content script injection

## Performance Optimization

- **Caching**: 5-minute cache reduces API calls by ~70%
- **Parallel Processing**: All APIs called simultaneously
- **Lazy Loading**: Only active tabs are monitored
- **Efficient Storage**: LRU cache with 1000 URL limit

## Future Enhancements

- Machine learning model for local URL analysis
- Custom warning messages per threat type
- Reporting dashboard for admins
- Integration with password managers
- Mobile browser support

## Contributing

To improve the extension:

1. Fork the repository
2. Add new threat detection services
3. Improve the UI/UX
4. Submit pull requests

The system is designed to be modular and extensible!