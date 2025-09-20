# Phishing Detection Extension - Setup Guide

## Complete Installation & Testing Steps

### 1. Install API Backend Dependencies

```bash
cd api-service
pip install -r requirements.txt
```

### 2. Configure API Keys

```bash
# Copy the example config
cp ../config/api-keys.json.example ../config/api-keys.json

# Edit the config file with your API keys
nano ../config/api-keys.json
```

**Required API Keys:**
- **Google Safe Browsing API**: Get from [Google Cloud Console](https://console.cloud.google.com/)
  - Enable Safe Browsing API
  - Create credentials (API key)
- **VirusTotal API**: Get from [VirusTotal](https://www.virustotal.com/gui/join-us)
  - Free tier: 1000 requests/day
- **PhishTank API**: Optional, get from [PhishTank](https://www.phishtank.com/api_info.php)

### 3. Start the API Server

```bash
cd api-service
uvicorn app:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at: `http://localhost:8000`

### 4. Load Chrome Extension

1. Open Chrome browser
2. Navigate to `chrome://extensions/`
3. Enable "Developer mode" (toggle in top-right)
4. Click "Load unpacked"
5. Select the `extension/` folder
6. Extension should appear in toolbar

### 5. Test the System

#### Test API Backend:
```bash
# Test basic functionality
cd tests
python3 test_api_integration.py

# Or manually test endpoints:
curl http://localhost:8000/health
curl -X POST http://localhost:8000/scan-url -H "Content-Type: application/json" -d '{"url":"https://www.google.com"}'
```

#### Test Chrome Extension:
1. Visit any website
2. Click the extension icon (shield) in toolbar
3. Check popup shows scanning results
4. Try visiting a test phishing site (safely)

### 6. Verify Integration

✅ **API Server Running**: `http://localhost:8000` shows API info  
✅ **Extension Loaded**: Icon appears in Chrome toolbar  
✅ **Real-time Scanning**: Visit websites and check popup  
✅ **Threat Detection**: Test with known suspicious URLs  
✅ **API Integration**: All three services responding  

## Troubleshooting

### Common Issues:

1. **API Server Won't Start**:
   - Check Python dependencies installed
   - Verify port 8000 is available
   - Check API keys configuration

2. **Extension Not Loading**:
   - Ensure manifest.json is valid
   - Check Chrome developer console for errors
   - Verify all files are present

3. **No Threat Detection**:
   - Verify API keys are valid
   - Check network connectivity
   - Look at browser console for errors

4. **CORS Errors**:
   - Ensure API server is running on localhost:8000
   - Check CORS configuration in app.py

### Debug Commands:

```bash
# Check API server logs
cd api-service && uvicorn app:app --reload --log-level debug

# Test individual API endpoints
curl http://localhost:8000/health
curl http://localhost:8000/stats

# Check extension console
# In Chrome: Extensions > Phishing Detection > inspect views: background page
```

## Production Deployment

For production use:

1. **Secure API Keys**: Use environment variables
2. **HTTPS**: Deploy API with SSL certificate  
3. **Rate Limiting**: Implement additional rate limiting
4. **Error Monitoring**: Add logging and monitoring
5. **Chrome Web Store**: Package extension for distribution

## File Structure Summary

```
alx_ai_capstone/
├── extension/                 # Chrome Extension
│   ├── manifest.json         # Extension configuration
│   ├── popup/               # UI components
│   ├── content/             # Page monitoring
│   ├── background/          # Service worker
│   └── icons/               # Extension icons
├── api-service/             # FastAPI Backend
│   ├── app.py              # Main API server
│   ├── services/           # API integrations
│   ├── models/             # Data models
│   └── requirements.txt    # Dependencies
├── config/                 # Configuration
│   ├── api-keys.json       # API credentials
│   └── settings.json       # App settings
├── tests/                  # Test suite
└── README.md              # Project documentation
```

## Security Notes

- API keys are stored locally only
- No user browsing data is transmitted
- All API calls use HTTPS
- Extension follows Chrome security guidelines
- Open source for security review

## Next Steps

1. Install dependencies and configure API keys
2. Test the complete system
3. Customize threat thresholds in settings.json
4. Add additional whitelisted/blacklisted domains
5. Consider deploying API to cloud service for production use