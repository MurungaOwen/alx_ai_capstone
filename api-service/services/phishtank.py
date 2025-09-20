import asyncio
import aiohttp
from urllib.parse import quote
from models.responses import ThreatResult

class PhishTankService:
    def __init__(self, config):
        self.api_key = config.get('api_key', '')
        self.base_url = config.get('base_url', 'https://checkurl.phishtank.com/checkurl/')
        self.user_agent = config.get('user_agent', 'phishing-detector-chrome-extension/1.0')
        
    def is_configured(self):
        # PhishTank API key is optional for basic usage
        return True
    
    async def check_url(self, url: str) -> ThreatResult:
        """Check URL against PhishTank database"""
        try:
            # PhishTank requires POST request with URL in form data
            data = {
                'url': url,
                'format': 'json'
            }
            
            # Add API key if available
            if self.api_key:
                data['app_key'] = self.api_key
            
            headers = {
                'User-Agent': self.user_agent,
                'Accept': 'application/json',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache'
            }
            
            async with aiohttp.ClientSession() as session:
                # Use FormData for proper form encoding
                form_data = aiohttp.FormData()
                form_data.add_field('url', url)
                form_data.add_field('format', 'json')
                if self.api_key:
                    form_data.add_field('app_key', self.api_key)
                
                async with session.post(
                    self.base_url,
                    data=form_data,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as response:
                    
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_response(data, url)
                    elif response.status == 401:
                        return ThreatResult(error="Invalid API key")
                    elif response.status == 429:
                        return ThreatResult(error="Rate limit exceeded")
                    elif response.status == 503:
                        return ThreatResult(error="PhishTank service unavailable")
                    elif response.status == 403:
                        # Cloudflare blocking - return neutral result
                        return ThreatResult(
                            is_malicious=False,
                            is_suspicious=False,
                            confidence=0.0,
                            source="PhishTank",
                            details="PhishTank blocked by Cloudflare - skipping check"
                        )
                    else:
                        error_text = await response.text()
                        # If it's HTML (Cloudflare challenge), don't include full HTML
                        if error_text.startswith('<!DOCTYPE'):
                            return ThreatResult(
                                is_malicious=False,
                                is_suspicious=False,
                                confidence=0.0,
                                source="PhishTank", 
                                details="PhishTank check unavailable due to Cloudflare protection"
                            )
                        return ThreatResult(error=f"API error {response.status}")
                        
        except asyncio.TimeoutError:
            return ThreatResult(error="Request timeout")
        except aiohttp.ClientError as e:
            return ThreatResult(error=f"Network error: {str(e)}")
        except Exception as e:
            return ThreatResult(error=f"Unexpected error: {str(e)}")
    
    def _parse_response(self, data: dict, url: str) -> ThreatResult:
        """Parse PhishTank API response"""
        try:
            # Check if response contains error
            if 'errortext' in data:
                return ThreatResult(error=f"PhishTank error: {data['errortext']}")
            
            # Check results
            results = data.get('results', {})
            in_database = results.get('in_database', False)
            is_valid = results.get('valid', False)
            
            if not in_database:
                return ThreatResult(
                    is_malicious=False,
                    is_suspicious=False,
                    confidence=0.8,  # High confidence in negative result
                    source="PhishTank",
                    details="URL not found in PhishTank database"
                )
            
            if in_database and is_valid:
                # URL is confirmed phishing site
                verified = results.get('verified', False)
                confidence = 0.95 if verified else 0.85
                
                submission_time = results.get('submission_time', 'Unknown')
                verification_time = results.get('verification_time', 'Unknown')
                
                details = f"Confirmed phishing site (submitted: {submission_time}"
                if verified:
                    details += f", verified: {verification_time}"
                details += ")"
                
                return ThreatResult(
                    is_malicious=True,
                    is_suspicious=True,
                    confidence=confidence,
                    source="PhishTank",
                    details=details
                )
            
            elif in_database and not is_valid:
                # URL was in database but marked as invalid/false positive
                return ThreatResult(
                    is_malicious=False,
                    is_suspicious=False,
                    confidence=0.9,
                    source="PhishTank",
                    details="URL was reported but marked as false positive"
                )
            
            else:
                # Unexpected state
                return ThreatResult(
                    is_malicious=False,
                    is_suspicious=True,
                    confidence=0.5,
                    source="PhishTank",
                    details="Unexpected response from PhishTank"
                )
                
        except KeyError as e:
            return ThreatResult(error=f"Invalid response format: missing {str(e)}")
        except Exception as e:
            return ThreatResult(error=f"Response parsing error: {str(e)}")
    
    async def get_phishtank_stats(self) -> dict:
        """Get PhishTank database statistics (if supported)"""
        try:
            headers = {'User-Agent': self.user_agent}
            
            async with aiohttp.ClientSession() as session:
                # This endpoint may not exist in current PhishTank API
                async with session.get(
                    'https://phishtank.org/api/stats/',
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    
                    if response.status == 200:
                        return await response.json()
                    else:
                        return {"error": f"Stats unavailable: {response.status}"}
                        
        except Exception as e:
            return {"error": f"Failed to get stats: {str(e)}"}