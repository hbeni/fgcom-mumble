#!/usr/bin/env python3
"""
Band Segments API Usage Examples
This script demonstrates how to use the Band Segments API endpoints with Python
"""

import requests
import json
import sys
from typing import Optional, Dict, Any

class BandSegmentsAPI:
    """Client for the Band Segments API"""
    
    def __init__(self, base_url: str = "http://localhost:8080/api/v1/band-segments"):
        self.base_url = base_url
        self.session = requests.Session()
    
    def _make_request(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make a request to the API and return the response"""
        url = f"{self.base_url}{endpoint}"
        try:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {e}"}
    
    def list_segments(self, band: Optional[str] = None, mode: Optional[str] = None, region: Optional[int] = None) -> Dict[str, Any]:
        """List all band segments with optional filtering"""
        params = {}
        if band:
            params["band"] = band
        if mode:
            params["mode"] = mode
        if region:
            params["region"] = region
        
        return self._make_request("", params)
    
    def get_segment_by_frequency(self, frequency: float, mode: str = "SSB", region: int = 1) -> Dict[str, Any]:
        """Get band segment information for a specific frequency"""
        params = {
            "frequency": frequency,
            "mode": mode,
            "region": region
        }
        return self._make_request("/frequency", params)
    
    def get_power_limit(self, frequency: float, mode: str = "SSB", region: int = 1) -> Dict[str, Any]:
        """Get power limit for a specific frequency"""
        params = {
            "frequency": frequency,
            "mode": mode,
            "region": region
        }
        return self._make_request("/power-limit", params)
    
    def validate_power(self, frequency: float, power: float, mode: str = "SSB", region: int = 1) -> Dict[str, Any]:
        """Validate if a power level is within limits"""
        params = {
            "frequency": frequency,
            "power": power,
            "mode": mode,
            "region": region
        }
        return self._make_request("/power-validation", params)
    
    def validate_frequency(self, frequency: float, mode: str = "SSB", region: int = 1) -> Dict[str, Any]:
        """Validate if a frequency is valid for amateur radio"""
        params = {
            "frequency": frequency,
            "mode": mode,
            "region": region
        }
        return self._make_request("/frequency-validation", params)

def print_response(title: str, response: Dict[str, Any]):
    """Print a formatted API response"""
    print(f"=== {title} ===")
    print(json.dumps(response, indent=2))
    print()

def main():
    """Main function demonstrating API usage"""
    print("Band Segments API Usage Examples")
    print("=" * 50)
    print()
    
    # Initialize API client
    api = BandSegmentsAPI()
    
    # Check if API server is running
    try:
        health_response = requests.get("http://localhost:8080/health", timeout=5)
        if health_response.status_code != 200:
            print("Error: API server is not responding correctly")
            sys.exit(1)
    except requests.exceptions.RequestException:
        print("Error: API server is not running on localhost:8080")
        print("Please start the FGCom-mumble plugin with API server enabled")
        sys.exit(1)
    
    print("API server is running")
    print()
    
    # Example 1: List all band segments
    response = api.list_segments()
    print_response("List All Band Segments", response)
    
    # Example 2: Filter by band
    response = api.list_segments(band="20m")
    print_response("Filter by Band (20m)", response)
    
    # Example 3: Filter by mode
    response = api.list_segments(mode="CW")
    print_response("Filter by Mode (CW)", response)
    
    # Example 4: Filter by region
    response = api.list_segments(region=1)
    print_response("Filter by ITU Region 1", response)
    
    # Example 5: Get band segment by frequency
    response = api.get_segment_by_frequency(14100.0, "SSB", 1)
    print_response("Get Band Segment by Frequency (20m SSB)", response)
    
    # Example 6: Get power limit for 60m band
    response = api.get_power_limit(5310.0, "CW", 1)
    print_response("Get Power Limit for 60m Band", response)
    
    # Example 7: Validate power level (valid)
    response = api.validate_power(5310.0, 25.0, "CW", 1)
    print_response("Validate Power Level (25W on 60m - Valid)", response)
    
    # Example 8: Validate power level (invalid)
    response = api.validate_power(5310.0, 100.0, "CW", 1)
    print_response("Validate Power Level (100W on 60m - Invalid)", response)
    
    # Example 9: Validate frequency (valid)
    response = api.validate_frequency(14100.0, "SSB", 1)
    print_response("Validate Frequency (20m SSB - Valid)", response)
    
    # Example 10: Validate frequency (invalid)
    response = api.validate_frequency(15000.0, "SSB", 1)
    print_response("Validate Frequency (15 MHz - Invalid)", response)
    
    # Example 11: Check 2m band power limit
    response = api.get_power_limit(145000.0, "SSB", 1)
    print_response("Get Power Limit for 2m Band", response)
    
    # Example 12: Check 70cm band power limit
    response = api.get_power_limit(435000.0, "SSB", 1)
    print_response("Get Power Limit for 70cm Band", response)
    
    # Example 13: Check 23cm band power limit
    response = api.get_power_limit(1250000.0, "SSB", 1)
    print_response("Get Power Limit for 23cm Band", response)
    
    # Example 14: Get all CW segments
    response = api.list_segments(mode="CW")
    print_response("Get All CW Segments", response)
    
    # Example 15: Get all SSB segments
    response = api.list_segments(mode="SSB")
    print_response("Get All SSB Segments", response)
    
    print("=" * 50)
    print("API Examples Complete")
    print()
    print("For more information, see:")
    print("- Band Segments API Documentation: docs/BAND_SEGMENTS_API_DOCUMENTATION.md")
    print("- Main API Documentation: docs/API_DOCUMENTATION.md")
    print("- Configuration Guide: configs/README.md")

if __name__ == "__main__":
    main()
