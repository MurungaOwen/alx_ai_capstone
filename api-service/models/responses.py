from pydantic import BaseModel, HttpUrl
from datetime import datetime
from typing import Optional, Any

class ThreatResult(BaseModel):
    is_malicious: bool = False
    is_suspicious: bool = False
    confidence: float = 0.0
    details: Optional[str] = None
    error: Optional[str] = None
    source: Optional[str] = None
    detected_threats: Optional[list] = None

class ScanResponse(BaseModel):
    url: str
    threat_score: int
    is_malicious: bool
    is_suspicious: bool
    timestamp: datetime
    safe_browsing: Optional[ThreatResult] = None
    virustotal: Optional[ThreatResult] = None
    phishtank: Optional[ThreatResult] = None
    
    class Config:
        json_encoders = {
            datetime: lambda dt: dt.isoformat()
        }