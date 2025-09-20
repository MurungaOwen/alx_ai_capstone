from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
import json
import os
from datetime import datetime
from services.safe_browsing import SafeBrowsingService
from services.virustotal import VirusTotalService  
from services.phishtank import PhishTankService
from models.responses import ScanResponse, ThreatResult

app = FastAPI(
    title="Phishing Detection API",
    description="Multi-API phishing detection service for Chrome extension",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for development
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

class URLScanRequest(BaseModel):
    url: HttpUrl

def load_api_config():
    config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'api-keys.json')
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print("Warning: API keys config file not found. Using environment variables.")
        return {
            "google_safe_browsing": {
                "api_key": os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", ""),
                "base_url": "https://safebrowsing.googleapis.com/v4/threatMatches:find"
            },
            "virustotal": {
                "api_key": os.getenv("VIRUSTOTAL_API_KEY", ""),
                "base_url": "https://www.virustotal.com/vtapi/v2"
            },
            "phishtank": {
                "api_key": os.getenv("PHISHTANK_API_KEY", ""),
                "base_url": "https://checkurl.phishtank.com/checkurl/",
                "user_agent": "phishing-detector-chrome-extension/1.0"
            }
        }

config = load_api_config()

safe_browsing = SafeBrowsingService(config["google_safe_browsing"])
virustotal = VirusTotalService(config["virustotal"])
phishtank = PhishTankService(config["phishtank"])

@app.get("/")
async def root():
    return {
        "message": "Phishing Detection API",
        "version": "1.0.0",
        "services": ["Google Safe Browsing", "VirusTotal", "PhishTank"],
        "status": "active"
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {
            "safe_browsing": safe_browsing.is_configured(),
            "virustotal": virustotal.is_configured(), 
            "phishtank": phishtank.is_configured()
        }
    }

@app.post("/scan-url", response_model=ScanResponse)
async def scan_url(request: URLScanRequest):
    url = str(request.url)
    
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    
    if url.startswith(('chrome://', 'chrome-extension://', 'edge://', 'about:', 'file://')):
        raise HTTPException(status_code=400, detail="Cannot scan browser internal URLs")
    
    try:
        results = {}
        
        if safe_browsing.is_configured():
            try:
                sb_result = await safe_browsing.check_url(url)
                results['safe_browsing'] = sb_result
            except Exception as e:
                results['safe_browsing'] = ThreatResult(error=str(e))
        
        if virustotal.is_configured():
            try:
                vt_result = await virustotal.check_url(url) 
                print(f"VirusTotal result: is_malicious={vt_result.is_malicious}, error={vt_result.error}, details={vt_result.details}")
                results['virustotal'] = vt_result
            except Exception as e:
                print(f"VirusTotal error for {url}: {str(e)}")
                results['virustotal'] = ThreatResult(error=str(e))
        
        if phishtank.is_configured():
            try:
                pt_result = await phishtank.check_url(url)
                results['phishtank'] = pt_result
            except Exception as e:
                results['phishtank'] = ThreatResult(error=str(e))
        
        if not results:
            raise HTTPException(status_code=503, detail="No threat detection services configured")
        
        threat_score = calculate_threat_score(results)
        print(f"Calculated threat score: {threat_score}")
        
        response = ScanResponse(
            url=url,
            threat_score=threat_score,
            is_malicious=threat_score >= 70,
            is_suspicious=threat_score >= 30,
            timestamp=datetime.utcnow(),
            **results
        )
        
        return response
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

def calculate_threat_score(results: dict) -> int:
    """Calculate weighted threat score from API results"""
    score = 0
    weights = {
        'safe_browsing': 40,  # Google Safe Browsing has highest weight
        'virustotal': 35,     # VirusTotal second
        'phishtank': 25       # PhishTank third
    }
    
    for service, result in results.items():
        if result is None:
            continue
            
        # Check if it's a ThreatResult object (has attributes) or dict
        has_error = False
        is_malicious = False
        is_suspicious = False
        
        if hasattr(result, 'error'):
            has_error = result.error is not None
            is_malicious = result.is_malicious if not has_error else False
            is_suspicious = result.is_suspicious if not has_error else False
        elif isinstance(result, dict):
            has_error = 'error' in result and result['error'] is not None
            is_malicious = result.get('is_malicious', False) if not has_error else False
            is_suspicious = result.get('is_suspicious', False) if not has_error else False
        
        if not has_error:
            weight = weights.get(service, 0)
            
            if is_malicious:
                score += weight
            elif is_suspicious:
                score += weight // 2
    
    return min(score, 100)

@app.get("/stats")
async def get_stats():
    """Get API usage statistics"""
    return {
        "services_configured": sum([
            safe_browsing.is_configured(),
            virustotal.is_configured(),
            phishtank.is_configured()
        ]),
        "uptime": "Active",
        "last_updated": datetime.utcnow().isoformat()
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)