import asyncio
import aiohttp
import json
from models.responses import ThreatResult

class SafeBrowsingService:
    def __init__(self, config):
        self.api_key = config.get('api_key', '')
        self.base_url = config.get('base_url', 'https://safebrowsing.googleapis.com/v4/threatMatches:find')
        
    def is_configured(self):
        return bool(self.api_key)
    
    async def check_url(self, url: str) -> ThreatResult:
        """Check URL against Google Safe Browsing API v4"""
        if not self.is_configured():
            return ThreatResult(error="Google Safe Browsing API not configured")
        
        try:
            request_body = {
                "client": {
                    "clientId": "phishing-detector-extension",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING", 
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION"
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}?key={self.api_key}",
                    json=request_body,
                    headers={"Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_response(data, url)
                    elif response.status == 400:
                        error_text = await response.text()
                        return ThreatResult(error=f"Invalid request: {error_text}")
                    elif response.status == 401:
                        return ThreatResult(error="Invalid API key")
                    elif response.status == 429:
                        return ThreatResult(error="Rate limit exceeded")
                    else:
                        return ThreatResult(error=f"API error: {response.status}")
                        
        except asyncio.TimeoutError:
            return ThreatResult(error="Request timeout")
        except aiohttp.ClientError as e:
            return ThreatResult(error=f"Network error: {str(e)}")
        except Exception as e:
            return ThreatResult(error=f"Unexpected error: {str(e)}")
    
    def _parse_response(self, data: dict, url: str) -> ThreatResult:
        """Parse Google Safe Browsing API response"""
        matches = data.get('matches', [])
        
        if not matches:
            return ThreatResult(
                is_malicious=False,
                is_suspicious=False,
                confidence=1.0,
                source="Google Safe Browsing",
                details="No threats detected"
            )
        
        threat_types = []
        is_malicious = False
        is_suspicious = False
        
        for match in matches:
            threat_type = match.get('threatType', '')
            threat_types.append(threat_type)
            
            if threat_type in ['MALWARE', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION']:
                is_malicious = True
            elif threat_type == 'SOCIAL_ENGINEERING':
                is_malicious = True  # Phishing is definitely malicious
        
        confidence = 0.95 if is_malicious else 0.7
        
        return ThreatResult(
            is_malicious=is_malicious,
            is_suspicious=is_suspicious or is_malicious,
            confidence=confidence,
            source="Google Safe Browsing",
            details=f"Detected threats: {', '.join(threat_types)}",
            detected_threats=threat_types
        )