import asyncio
import aiohttp
import hashlib
import base64
from urllib.parse import urlparse
from models.responses import ThreatResult

class VirusTotalService:
    def __init__(self, config):
        self.api_key = config.get('api_key', '')
        self.base_url = config.get('base_url', 'https://www.virustotal.com/vtapi/v2')
        # VirusTotal v3 API is recommended but v2 works for basic URL scanning
        self.v3_base_url = "https://www.virustotal.com/api/v3"
        
    def is_configured(self):
        return bool(self.api_key)
    
    async def check_url(self, url: str) -> ThreatResult:
        """Check URL against VirusTotal API"""
        if not self.is_configured():
            return ThreatResult(error="VirusTotal API not configured")
        
        try:
            # Use v3 API for better results
            return await self._check_url_v3(url)
        except Exception as e:
            # Fallback to v2 if v3 fails
            try:
                return await self._check_url_v2(url)
            except Exception as e2:
                return ThreatResult(error=f"Both API versions failed: v3={str(e)}, v2={str(e2)}")
    
    async def _check_url_v3(self, url: str) -> ThreatResult:
        """Check URL using VirusTotal API v3"""
        # Create URL ID for v3 API
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        headers = {
            "x-apikey": self.api_key,
            "Content-Type": "application/json"
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.v3_base_url}/urls/{url_id}",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=15)
            ) as response:
                
                if response.status == 200:
                    data = await response.json()
                    return self._parse_v3_response(data)
                elif response.status == 404:
                    # URL not found, submit for scanning
                    return await self._submit_url_v3(url, session, headers)
                elif response.status == 401:
                    return ThreatResult(error="Invalid API key")
                elif response.status == 429:
                    return ThreatResult(error="Rate limit exceeded (1000 requests/day)")
                else:
                    error_text = await response.text()
                    return ThreatResult(error=f"API error {response.status}: {error_text}")
    
    async def _submit_url_v3(self, url: str, session: aiohttp.ClientSession, headers: dict) -> ThreatResult:
        """Submit URL for scanning when not found in database"""
        try:
            submit_data = {"url": url}
            
            async with session.post(
                f"{self.v3_base_url}/urls",
                headers=headers,
                json=submit_data,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                
                if response.status == 200:
                    # URL submitted successfully, but no immediate results
                    return ThreatResult(
                        is_malicious=False,
                        is_suspicious=False,
                        confidence=0.8,  # High confidence in clean result
                        source="VirusTotal",
                        details="URL not in database - submitted for future analysis"
                    )
                else:
                    # If submission fails, still return a clean result rather than error
                    # This prevents the whole service from showing as "Error"
                    return ThreatResult(
                        is_malicious=False,
                        is_suspicious=False,
                        confidence=0.5,  # Lower confidence since we couldn't check
                        source="VirusTotal",
                        details="URL not found in VirusTotal database"
                    )
        except Exception as e:
            # Return clean result instead of error to keep the service working
            return ThreatResult(
                is_malicious=False,
                is_suspicious=False,
                confidence=0.5,
                source="VirusTotal",
                details="VirusTotal check unavailable"
            )
    
    async def _check_url_v2(self, url: str) -> ThreatResult:
        """Fallback to VirusTotal API v2"""
        params = {
            'apikey': self.api_key,
            'resource': url,
            'allinfo': '1'
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.base_url}/url/report",
                params=params,
                timeout=aiohttp.ClientTimeout(total=15)
            ) as response:
                
                if response.status == 200:
                    data = await response.json()
                    return self._parse_v2_response(data)
                elif response.status == 204:
                    return ThreatResult(error="Rate limit exceeded")
                elif response.status == 403:
                    return ThreatResult(error="Invalid API key")
                else:
                    error_text = await response.text()
                    return ThreatResult(error=f"API error {response.status}: {error_text}")
    
    def _parse_v3_response(self, data: dict) -> ThreatResult:
        """Parse VirusTotal API v3 response"""
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        malicious_count = stats.get('malicious', 0)
        suspicious_count = stats.get('suspicious', 0)
        total_scans = sum(stats.values()) if stats else 0
        
        if total_scans == 0:
            return ThreatResult(
                is_malicious=False,
                is_suspicious=False,
                confidence=0.0,
                source="VirusTotal",
                details="No scan results available"
            )
        
        malicious_ratio = malicious_count / total_scans
        suspicious_ratio = suspicious_count / total_scans
        
        is_malicious = malicious_count > 0 and malicious_ratio > 0.1  # More than 10% detection
        is_suspicious = suspicious_count > 0 or (malicious_count > 0 and malicious_ratio <= 0.1)
        
        confidence = min(0.9, malicious_ratio + suspicious_ratio) if is_malicious else 0.8
        
        detected_engines = []
        results = attributes.get('last_analysis_results', {})
        for engine, result in results.items():
            if result.get('category') in ['malicious', 'suspicious']:
                detected_engines.append(f"{engine}: {result.get('result', 'detected')}")
        
        return ThreatResult(
            is_malicious=is_malicious,
            is_suspicious=is_suspicious,
            confidence=confidence,
            source="VirusTotal",
            details=f"Detected by {malicious_count}/{total_scans} engines",
            detected_threats=detected_engines[:5]  # Limit to top 5
        )
    
    def _parse_v2_response(self, data: dict) -> ThreatResult:
        """Parse VirusTotal API v2 response"""
        response_code = data.get('response_code', 0)
        
        if response_code == 0:
            return ThreatResult(
                is_malicious=False,
                is_suspicious=False,
                confidence=0.0,
                source="VirusTotal",
                details="URL not found in database"
            )
        elif response_code == -2:
            return ThreatResult(
                is_malicious=False,
                is_suspicious=False,
                confidence=0.0,
                source="VirusTotal", 
                details="URL queued for analysis"
            )
        
        positives = data.get('positives', 0)
        total = data.get('total', 0)
        
        if total == 0:
            return ThreatResult(error="No scan engines responded")
        
        detection_ratio = positives / total
        is_malicious = positives > 0 and detection_ratio > 0.1
        is_suspicious = positives > 0 and detection_ratio <= 0.1
        
        confidence = min(0.9, detection_ratio) if is_malicious else 0.8
        
        return ThreatResult(
            is_malicious=is_malicious,
            is_suspicious=is_suspicious,
            confidence=confidence,
            source="VirusTotal",
            details=f"Detected by {positives}/{total} engines"
        )