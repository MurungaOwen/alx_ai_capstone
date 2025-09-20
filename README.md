# Phishing Detection Chrome Extension

A real-time phishing detection system that protects users by analyzing URLs using multiple threat intelligence APIs through a Chrome extension. The system combines Google Safe Browsing, VirusTotal, and PhishTank to provide comprehensive protection against phishing attacks.

📖 **[See HOW_IT_WORKS.md for detailed explanation of the system architecture and installation steps](HOW_IT_WORKS.md)**

## Architecture

**Multi-Layer Defense System:**
- **Layer 1:** Local URL pattern analysis for instant detection
- **Layer 2:** Google Safe Browsing API v5 for real-time protection  
- **Layer 3:** VirusTotal API v3 for comprehensive scanning (70+ engines)
- **Layer 4:** PhishTank API for community-driven threat intelligence

## Features

### Core Protection
- **Real-time URL analysis** - Instant threat detection while browsing
- **Multi-API integration** - Combined intelligence from 3 major security services
- **Smart threat scoring** - Weighted algorithm combining all detection sources
- **Non-intrusive warnings** - Clean popup notifications with risk assessment

### Privacy & Security
- **API-first architecture** - No local ML training required
- **Minimal data collection** - Only URLs analyzed, no personal data stored
- **Secure communication** - HTTPS-only API calls with rate limiting
- **User control** - Custom whitelist/blacklist management

## Project Structure

```
alx_ai_capstone/
├── extension/
│   ├── manifest.json          # Chrome Extension Manifest V3
│   ├── popup/                 # Extension UI components
│   ├── content/               # Page analysis scripts  
│   └── background/            # Service worker
├── api-service/
│   ├── app.py                 # FastAPI backend server
│   ├── services/              # API integration modules
│   └── models/                # Response models and schemas
├── config/
│   ├── settings.json          # Extension configuration
│   └── api-keys.json.example  # API key template
└── tests/                     # Unit and integration tests
```

## Quick Start

### 1. Clone and Setup
```bash
git clone https://github.com/MurungaOwen/alx_ai_capstone.git
cd alx_ai_capstone
```

### 2. Configure API Keys
Get your free API keys from:
- **[Google Safe Browsing](https://developers.google.com/safe-browsing/v4/get-started)** - Free with Google Cloud account
- **[VirusTotal](https://www.virustotal.com/gui/join-us)** - 1000 requests/day free tier
- **[PhishTank](https://www.phishtank.com/api_info.php)** - Unlimited free access (optional)

```bash
cp config/api-keys.json.example config/api-keys.json
# Edit api-keys.json with your API keys
```

### 3. Start the Backend Server
```bash
cd api-service
pip install -r requirements.txt
uvicorn app:app --reload
```

### 4. Install Chrome Extension
1. Open Chrome browser
2. Navigate to `chrome://extensions/`
3. Enable "Developer mode" (toggle in top-right)
4. Click "Load unpacked"
5. Select the `extension/` folder from this project
6. The shield icon will appear in your toolbar

✅ **That's it!** The extension is now protecting you from phishing sites.

## API Integration Details

### Google Safe Browsing API v5
- **Primary protection layer**
- Real-time URL threat lookup
- Covers phishing, malware, social engineering
- Rate limit: High (suitable for production)

### VirusTotal API v3  
- **Secondary validation**
- 70+ antivirus/security scanners
- Comprehensive threat analysis
- Rate limit: 1000 requests/day (free tier)

### PhishTank API
- **Community intelligence**
- Hourly updated phishing database
- Fast local caching system
- Rate limit: No restrictions

## How to Use

### Extension Icon States
- 🛡️ **Green Shield**: Site is safe
- ⚠️ **Yellow Warning**: Suspicious activity detected
- 🚨 **Red Alert**: Dangerous phishing site
- ❗ **Exclamation**: Scan error or offline

### Features
1. **Automatic Protection**: Extension scans every website automatically
2. **Popup Details**: Click the shield icon to see detailed threat analysis
3. **Warning Overlays**: Get full-screen warnings on dangerous sites
4. **Manual Rescan**: Force a fresh scan with the "Rescan" button
5. **Report Issues**: Help improve detection by reporting false positives

## Development Workflow

### Backend Development
```bash
cd api-service
python -m pytest tests/
uvicorn app:app --reload --host 0.0.0.0 --port 8000
```

### Extension Development
- Make changes in `extension/` directory
- Reload extension at `chrome://extensions/`
- Check console for debugging

### Testing
```bash
# API service tests
cd api-service && python -m pytest

# Extension tests (manual)
# Test with known phishing URLs (safely)
# Verify API integration works
```

## Security Considerations

- All API communications use HTTPS
- No user browsing history stored
- API keys stored locally only
- Rate limiting prevents abuse
- Open source for security review

## Contributing

1. Fork repository
2. Create feature branch: `git checkout -b feature/improvement`
3. Add comprehensive tests
4. Submit pull request

## License

MIT License

## Acknowledgments

- Google Safe Browsing for threat intelligence
- VirusTotal for multi-engine analysis  
- PhishTank community for phishing data
- Chrome Extensions API documentation

