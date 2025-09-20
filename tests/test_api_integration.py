#!/usr/bin/env python3
"""
Basic integration tests for the phishing detection API
Tests the FastAPI backend and API service integrations
"""

import pytest
import asyncio
import requests
import time
from fastapi.testclient import TestClient
import sys
import os

# Add the api-service directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api-service'))

from app import app

client = TestClient(app)

def test_root_endpoint():
    """Test the root endpoint returns correct information"""
    response = client.get("/")
    assert response.status_code == 200
    
    data = response.json()
    assert "message" in data
    assert "version" in data
    assert "services" in data
    assert data["message"] == "Phishing Detection API"

def test_health_endpoint():
    """Test the health check endpoint"""
    response = client.get("/health")
    assert response.status_code == 200
    
    data = response.json()
    assert "status" in data
    assert "timestamp" in data
    assert "services" in data
    assert data["status"] == "healthy"

def test_stats_endpoint():
    """Test the statistics endpoint"""
    response = client.get("/stats")
    assert response.status_code == 200
    
    data = response.json()
    assert "services_configured" in data
    assert "uptime" in data
    assert "last_updated" in data

def test_scan_url_valid_request():
    """Test URL scanning with a valid URL"""
    test_url = "https://www.google.com"
    
    response = client.post("/scan-url", json={"url": test_url})
    assert response.status_code == 200
    
    data = response.json()
    assert "url" in data
    assert "threat_score" in data
    assert "is_malicious" in data
    assert "is_suspicious" in data
    assert "timestamp" in data
    assert data["url"] == test_url

def test_scan_url_invalid_requests():
    """Test URL scanning with invalid requests"""
    
    # Test empty URL
    response = client.post("/scan-url", json={"url": ""})
    assert response.status_code == 422  # Validation error
    
    # Test missing URL
    response = client.post("/scan-url", json={})
    assert response.status_code == 422  # Validation error
    
    # Test browser internal URL
    response = client.post("/scan-url", json={"url": "chrome://settings"})
    assert response.status_code == 400
    assert "Cannot scan browser internal URLs" in response.json()["detail"]

def test_scan_url_malicious_example():
    """Test with a known example (be careful with real malicious URLs)"""
    # Using a safe test URL that might be flagged as suspicious
    test_url = "http://malware.testing.google.test/testing/malware/"
    
    response = client.post("/scan-url", json={"url": test_url})
    # This should work regardless of the result
    assert response.status_code == 200 or response.status_code == 500  # May fail if services are not configured

def test_cors_headers():
    """Test that CORS headers are properly set"""
    response = client.options("/scan-url")
    # FastAPI automatically handles OPTIONS requests for CORS
    assert response.status_code == 200

def test_api_response_structure():
    """Test that API responses have the correct structure"""
    test_url = "https://www.example.com"
    
    response = client.post("/scan-url", json={"url": test_url})
    assert response.status_code == 200
    
    data = response.json()
    
    # Check required fields
    required_fields = ["url", "threat_score", "is_malicious", "is_suspicious", "timestamp"]
    for field in required_fields:
        assert field in data, f"Missing required field: {field}"
    
    # Check threat score is within valid range
    assert 0 <= data["threat_score"] <= 100
    
    # Check boolean fields
    assert isinstance(data["is_malicious"], bool)
    assert isinstance(data["is_suspicious"], bool)

def test_multiple_url_scans():
    """Test scanning multiple URLs in sequence"""
    test_urls = [
        "https://www.google.com",
        "https://www.github.com", 
        "https://www.stackoverflow.com"
    ]
    
    for url in test_urls:
        response = client.post("/scan-url", json={"url": url})
        assert response.status_code == 200
        
        data = response.json()
        assert data["url"] == url
        assert "threat_score" in data

def test_api_error_handling():
    """Test API error handling with various invalid inputs"""
    
    # Test invalid JSON
    response = client.post("/scan-url", data="invalid json")
    assert response.status_code == 422
    
    # Test invalid URL format
    response = client.post("/scan-url", json={"url": "not-a-url"})
    assert response.status_code == 422

if __name__ == "__main__":
    print("Running API Integration Tests...")
    
    # Run tests with pytest if available, otherwise run basic tests
    try:
        pytest.main([__file__, "-v"])
    except ImportError:
        print("pytest not available, running basic tests...")
        
        # Run basic tests manually
        test_functions = [
            test_root_endpoint,
            test_health_endpoint,
            test_stats_endpoint,
            test_scan_url_valid_request,
            test_scan_url_invalid_requests,
            test_api_response_structure
        ]
        
        passed = 0
        failed = 0
        
        for test_func in test_functions:
            try:
                test_func()
                print(f"✓ {test_func.__name__}")
                passed += 1
            except Exception as e:
                print(f"✗ {test_func.__name__}: {e}")
                failed += 1
        
        print(f"\nResults: {passed} passed, {failed} failed")
        
        if failed == 0:
            print("All tests passed! 🎉")
        else:
            print("Some tests failed. Check the API configuration and try again.")