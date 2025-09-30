#!/usr/bin/env python3
"""
Comprehensive API Testing Tool for FGCom-mumble

This tool tests all available APIs in the FGCom-mumble system including:
- Authentication APIs
- Solar Data APIs
- Weather & Lightning APIs
- Band Segments APIs
- Radio Model APIs
- AGC/Squelch APIs
- Antenna Pattern APIs
- Vehicle Dynamics APIs
- System Health APIs

Usage:
    python3 comprehensive_api_tester.py [--base-url URL] [--verbose] [--output-file FILE]
"""

import requests
import json
import sys
import time
import argparse
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import random

class TestResult(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"

@dataclass
class TestCase:
    name: str
    endpoint: str
    method: str
    expected_status: int
    data: Optional[Dict] = None
    params: Optional[Dict] = None
    headers: Optional[Dict] = None
    description: str = ""

@dataclass
class TestResult:
    test_case: TestCase
    result: TestResult
    status_code: int
    response_time: float
    response_data: Any
    error_message: str = ""
    timestamp: str = ""

class ComprehensiveAPITester:
    """Comprehensive API testing tool for FGCom-mumble"""
    
    def __init__(self, base_url: str = "http://localhost:8080", verbose: bool = False):
        self.base_url = base_url.rstrip('/')
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'FGCom-API-Tester/1.0'
        })
        self.test_results: List[TestResult] = []
        self.auth_token: Optional[str] = None
        
        # Setup logging
        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def run_test(self, test_case: TestCase) -> TestResult:
        """Run a single test case"""
        start_time = time.time()
        timestamp = datetime.now(timezone.utc).isoformat()
        
        try:
            # Prepare headers
            headers = test_case.headers or {}
            if self.auth_token and 'Authorization' not in headers:
                headers['Authorization'] = f'Bearer {self.auth_token}'
            
            # Make request
            if test_case.method.upper() == 'GET':
                response = self.session.get(
                    f"{self.base_url}{test_case.endpoint}",
                    params=test_case.params,
                    headers=headers,
                    timeout=30
                )
            elif test_case.method.upper() == 'POST':
                response = self.session.post(
                    f"{self.base_url}{test_case.endpoint}",
                    json=test_case.data,
                    params=test_case.params,
                    headers=headers,
                    timeout=30
                )
            elif test_case.method.upper() == 'PUT':
                response = self.session.put(
                    f"{self.base_url}{test_case.endpoint}",
                    json=test_case.data,
                    params=test_case.params,
                    headers=headers,
                    timeout=30
                )
            elif test_case.method.upper() == 'DELETE':
                response = self.session.delete(
                    f"{self.base_url}{test_case.endpoint}",
                    params=test_case.params,
                    headers=headers,
                    timeout=30
                )
            else:
                raise ValueError(f"Unsupported HTTP method: {test_case.method}")
            
            response_time = time.time() - start_time
            
            # Determine result
            if response.status_code == test_case.expected_status:
                result = TestResult.PASS
            else:
                result = TestResult.FAIL
            
            # Parse response data
            try:
                response_data = response.json()
            except:
                response_data = response.text
            
            test_result = TestResult(
                test_case=test_case,
                result=result,
                status_code=response.status_code,
                response_time=response_time,
                response_data=response_data,
                timestamp=timestamp
            )
            
            if result == TestResult.FAIL:
                test_result.error_message = f"Expected status {test_case.expected_status}, got {response.status_code}"
            
        except requests.exceptions.RequestException as e:
            response_time = time.time() - start_time
            test_result = TestResult(
                test_case=test_case,
                result=TestResult.ERROR,
                status_code=0,
                response_time=response_time,
                response_data=None,
                error_message=str(e),
                timestamp=timestamp
            )
        except Exception as e:
            response_time = time.time() - start_time
            test_result = TestResult(
                test_case=test_case,
                result=TestResult.ERROR,
                status_code=0,
                response_time=response_time,
                response_data=None,
                error_message=str(e),
                timestamp=timestamp
            )
        
        self.test_results.append(test_result)
        return test_result
    
    def get_health_check_tests(self) -> List[TestCase]:
        """Get health check and basic system tests"""
        return [
            TestCase(
                name="Health Check",
                endpoint="/health",
                method="GET",
                expected_status=200,
                description="Basic health check endpoint"
            ),
            TestCase(
                name="API Status",
                endpoint="/api/status",
                method="GET",
                expected_status=200,
                description="API status information"
            ),
            TestCase(
                name="API Info",
                endpoint="/api/info",
                method="GET",
                expected_status=200,
                description="API information and available features"
            )
        ]
    
    def get_authentication_tests(self) -> List[TestCase]:
        """Get authentication API tests"""
        return [
            TestCase(
                name="Login (Valid Credentials)",
                endpoint="/auth/login",
                method="POST",
                expected_status=200,
                data={
                    "username": "test_user",
                    "password": "test_password",
                    "client_type": "api_tester"
                },
                description="Test authentication with valid credentials"
            ),
            TestCase(
                name="Login (Invalid Credentials)",
                endpoint="/auth/login",
                method="POST",
                expected_status=401,
                data={
                    "username": "invalid_user",
                    "password": "invalid_password",
                    "client_type": "api_tester"
                },
                description="Test authentication with invalid credentials"
            ),
            TestCase(
                name="Token Refresh",
                endpoint="/auth/refresh",
                method="POST",
                expected_status=200,
                data={
                    "refresh_token": "test_refresh_token"
                },
                description="Test token refresh functionality"
            )
        ]
    
    def get_solar_data_tests(self) -> List[TestCase]:
        """Get solar data API tests"""
        return [
            TestCase(
                name="Get Current Solar Data",
                endpoint="/api/v1/solar-data/current",
                method="GET",
                expected_status=200,
                description="Get current solar conditions"
            ),
            TestCase(
                name="Get Solar History",
                endpoint="/api/v1/solar-data/history",
                method="GET",
                expected_status=200,
                params={
                    "start_date": "2024-01-01T00:00:00Z",
                    "end_date": "2024-01-15T23:59:59Z",
                    "data_points": 10
                },
                description="Get historical solar data"
            ),
            TestCase(
                name="Get Solar Forecast",
                endpoint="/api/v1/solar-data/forecast",
                method="GET",
                expected_status=200,
                params={"hours": 24},
                description="Get solar data forecast"
            ),
            TestCase(
                name="Submit Solar Data",
                endpoint="/api/v1/solar-data/submit",
                method="POST",
                expected_status=200,
                data={
                    "solar_flux": 155.5,
                    "k_index": 3,
                    "a_index": 12,
                    "sunspot_number": 50,
                    "solar_wind_speed": 480.0
                },
                description="Submit single solar data entry"
            ),
            TestCase(
                name="Batch Submit Solar Data",
                endpoint="/api/v1/solar-data/batch-submit",
                method="POST",
                expected_status=200,
                data={
                    "solar_data_array": [
                        {"solar_flux": 150.0, "k_index": 2, "a_index": 8},
                        {"solar_flux": 152.5, "k_index": 3, "a_index": 10},
                        {"solar_flux": 148.0, "k_index": 1, "a_index": 6}
                    ]
                },
                description="Submit batch solar data"
            ),
            TestCase(
                name="Update Solar Data",
                endpoint="/api/v1/solar-data/update",
                method="PUT",
                expected_status=200,
                data={
                    "solar_flux": 160.0,
                    "k_index": 4
                },
                description="Update existing solar data"
            )
        ]
    
    def get_weather_lightning_tests(self) -> List[TestCase]:
        """Get weather and lightning API tests"""
        return [
            TestCase(
                name="Get Current Weather",
                endpoint="/api/v1/weather-data/current",
                method="GET",
                expected_status=200,
                description="Get current weather conditions"
            ),
            TestCase(
                name="Get Weather History",
                endpoint="/api/v1/weather-data/history",
                method="GET",
                expected_status=200,
                params={
                    "start_date": "2024-01-01T00:00:00Z",
                    "end_date": "2024-01-15T23:59:59Z",
                    "data_points": 10
                },
                description="Get historical weather data"
            ),
            TestCase(
                name="Get Weather Forecast",
                endpoint="/api/v1/weather-data/forecast",
                method="GET",
                expected_status=200,
                params={"hours": 24},
                description="Get weather forecast"
            ),
            TestCase(
                name="Submit Weather Data",
                endpoint="/api/v1/weather-data/submit",
                method="POST",
                expected_status=200,
                data={
                    "temperature_celsius": 25.0,
                    "humidity_percent": 60.0,
                    "pressure_hpa": 1013.25,
                    "wind_speed_ms": 5.0,
                    "wind_direction_deg": 180.0,
                    "precipitation_mmh": 0.0,
                    "has_thunderstorms": False
                },
                description="Submit weather data"
            ),
            TestCase(
                name="Get Current Lightning",
                endpoint="/api/v1/lightning-data/current",
                method="GET",
                expected_status=200,
                description="Get current lightning data"
            ),
            TestCase(
                name="Submit Lightning Strike",
                endpoint="/api/v1/lightning-data/submit",
                method="POST",
                expected_status=200,
                data={
                    "latitude": 40.7128,
                    "longitude": -74.0060,
                    "intensity_ka": 35.5,
                    "altitude_m": 1200.0,
                    "polarity": "negative",
                    "type": "cloud_to_ground"
                },
                description="Submit lightning strike data"
            ),
            TestCase(
                name="Batch Submit Lightning",
                endpoint="/api/v1/lightning-data/batch-submit",
                method="POST",
                expected_status=200,
                data={
                    "lightning_strikes": [
                        {
                            "latitude": 40.7128,
                            "longitude": -74.0060,
                            "intensity_ka": 25.0,
                            "altitude_m": 1000.0,
                            "polarity": "negative",
                            "type": "cloud_to_ground"
                        },
                        {
                            "latitude": 40.7200,
                            "longitude": -74.0100,
                            "intensity_ka": 40.0,
                            "altitude_m": 1500.0,
                            "polarity": "positive",
                            "type": "cloud_to_ground"
                        }
                    ]
                },
                description="Submit batch lightning strikes"
            )
        ]
    
    def get_band_segments_tests(self) -> List[TestCase]:
        """Get band segments API tests"""
        return [
            TestCase(
                name="List All Band Segments",
                endpoint="/api/v1/band-segments",
                method="GET",
                expected_status=200,
                description="List all amateur radio band segments"
            ),
            TestCase(
                name="Filter Band Segments by Band",
                endpoint="/api/v1/band-segments",
                method="GET",
                expected_status=200,
                params={"band": "20m"},
                description="Filter band segments by band (20m)"
            ),
            TestCase(
                name="Filter Band Segments by Mode",
                endpoint="/api/v1/band-segments",
                method="GET",
                expected_status=200,
                params={"mode": "CW"},
                description="Filter band segments by mode (CW)"
            ),
            TestCase(
                name="Filter Band Segments by Region",
                endpoint="/api/v1/band-segments",
                method="GET",
                expected_status=200,
                params={"region": 1},
                description="Filter band segments by ITU region"
            ),
            TestCase(
                name="Get Band Segment by Frequency",
                endpoint="/api/v1/band-segments/frequency",
                method="GET",
                expected_status=200,
                params={"frequency": 14100.0, "mode": "SSB", "region": 1},
                description="Get band segment for specific frequency"
            ),
            TestCase(
                name="Get Power Limit",
                endpoint="/api/v1/band-segments/power-limit",
                method="GET",
                expected_status=200,
                params={"frequency": 5310.0, "mode": "CW", "region": 1},
                description="Get power limit for frequency"
            ),
            TestCase(
                name="Validate Power Level",
                endpoint="/api/v1/band-segments/power-validation",
                method="GET",
                expected_status=200,
                params={"frequency": 5310.0, "power": 25.0, "mode": "CW", "region": 1},
                description="Validate power level for frequency"
            ),
            TestCase(
                name="Validate Frequency",
                endpoint="/api/v1/band-segments/frequency-validation",
                method="GET",
                expected_status=200,
                params={"frequency": 14100.0, "mode": "SSB", "region": 1},
                description="Validate frequency for amateur radio"
            )
        ]
    
    def get_radio_model_tests(self) -> List[TestCase]:
        """Get radio model API tests"""
        return [
            TestCase(
                name="List Radio Models",
                endpoint="/api/v1/radio-models",
                method="GET",
                expected_status=200,
                description="List all available radio models"
            ),
            TestCase(
                name="Get Specific Radio Model",
                endpoint="/api/v1/radio-models/AN%2FPRC-152",
                method="GET",
                expected_status=200,
                description="Get specific radio model details"
            ),
            TestCase(
                name="Get Radio Model Specifications",
                endpoint="/api/v1/radio-models/AN%2FPRC-152/specifications",
                method="GET",
                expected_status=200,
                description="Get radio model specifications"
            ),
            TestCase(
                name="Get Radio Model Capabilities",
                endpoint="/api/v1/radio-models/AN%2FPRC-152/capabilities",
                method="GET",
                expected_status=200,
                description="Get radio model capabilities"
            ),
            TestCase(
                name="Search Radio Models",
                endpoint="/api/v1/radio-models/search",
                method="GET",
                expected_status=200,
                params={"q": "NATO"},
                description="Search radio models"
            ),
            TestCase(
                name="Filter Radio Models",
                endpoint="/api/v1/radio-models/filter",
                method="GET",
                expected_status=200,
                params={"country": "USA", "alliance": "NATO"},
                description="Filter radio models by criteria"
            ),
            TestCase(
                name="Compare Radio Models",
                endpoint="/api/v1/radio-models/compare",
                method="GET",
                expected_status=200,
                params={"model1": "AN%2FPRC-152", "model2": "R-105M"},
                description="Compare two radio models"
            ),
            TestCase(
                name="Get Radio Model Channels",
                endpoint="/api/v1/radio-models/AN%2FPRC-152/channels",
                method="GET",
                expected_status=200,
                description="Get radio model channels"
            ),
            TestCase(
                name="Get Radio Model Frequency Info",
                endpoint="/api/v1/radio-models/AN%2FPRC-152/frequency",
                method="GET",
                expected_status=200,
                params={"frequency": 31.25},
                description="Get frequency information for radio model"
            ),
            TestCase(
                name="Validate Radio Model Configuration",
                endpoint="/api/v1/radio-models/validate",
                method="GET",
                expected_status=200,
                params={"model": "AN%2FPRC-152", "frequency": 31.25, "channel": 100},
                description="Validate radio model configuration"
            ),
            TestCase(
                name="Get Radio Model Statistics",
                endpoint="/api/v1/radio-models/statistics",
                method="GET",
                expected_status=200,
                description="Get radio model statistics"
            )
        ]
    
    def get_preset_channel_tests(self) -> List[TestCase]:
        """Get preset channel API tests"""
        return [
            TestCase(
                name="List Preset Channels",
                endpoint="/api/v1/preset-channels",
                method="GET",
                expected_status=200,
                description="List all preset channels"
            ),
            TestCase(
                name="Get Radio Preset Channels",
                endpoint="/api/v1/preset-channels/AN%2FPRC-152",
                method="GET",
                expected_status=200,
                description="Get preset channels for specific radio"
            ),
            TestCase(
                name="Search Preset Channels",
                endpoint="/api/v1/preset-channels/search",
                method="GET",
                expected_status=200,
                params={"q": "Tactical", "radio": "AN%2FPRC-152"},
                description="Search preset channels"
            ),
            TestCase(
                name="Get Preset Channel by Frequency",
                endpoint="/api/v1/preset-channels/frequency",
                method="GET",
                expected_status=200,
                params={"frequency": 31.25, "radio": "AN%2FPRC-152"},
                description="Get preset channel by frequency"
            ),
            TestCase(
                name="Get Preset Channel by Channel Number",
                endpoint="/api/v1/preset-channels/channel",
                method="GET",
                expected_status=200,
                params={"channel": 100, "radio": "AN%2FPRC-152"},
                description="Get preset channel by channel number"
            ),
            TestCase(
                name="Get Active Preset Channels",
                endpoint="/api/v1/preset-channels/active",
                method="GET",
                expected_status=200,
                params={"radio": "AN%2FPRC-152"},
                description="Get active preset channels"
            ),
            TestCase(
                name="Get Inactive Preset Channels",
                endpoint="/api/v1/preset-channels/inactive",
                method="GET",
                expected_status=200,
                params={"radio": "AN%2FPRC-152"},
                description="Get inactive preset channels"
            ),
            TestCase(
                name="Get Preset Channel Statistics",
                endpoint="/api/v1/preset-channels/statistics",
                method="GET",
                expected_status=200,
                description="Get preset channel statistics"
            )
        ]
    
    def get_agc_squelch_tests(self) -> List[TestCase]:
        """Get AGC/Squelch API tests"""
        return [
            TestCase(
                name="Get AGC Status",
                endpoint="/api/agc/status",
                method="GET",
                expected_status=200,
                description="Get AGC system status"
            ),
            TestCase(
                name="Set AGC Mode",
                endpoint="/api/agc/mode",
                method="POST",
                expected_status=200,
                data={"mode": "automatic"},
                description="Set AGC mode"
            ),
            TestCase(
                name="Set AGC Threshold",
                endpoint="/api/agc/threshold",
                method="POST",
                expected_status=200,
                data={"threshold": -60.0},
                description="Set AGC threshold"
            ),
            TestCase(
                name="Get Squelch Status",
                endpoint="/api/squelch/status",
                method="GET",
                expected_status=200,
                description="Get squelch system status"
            ),
            TestCase(
                name="Set Squelch Threshold",
                endpoint="/api/squelch/threshold",
                method="POST",
                expected_status=200,
                data={"threshold": -70.0},
                description="Set squelch threshold"
            ),
            TestCase(
                name="Get Combined Status",
                endpoint="/api/agc-squelch/status",
                method="GET",
                expected_status=200,
                description="Get combined AGC/Squelch status"
            ),
            TestCase(
                name="Get Audio Stats",
                endpoint="/api/agc-squelch/audio-stats",
                method="GET",
                expected_status=200,
                description="Get audio processing statistics"
            ),
            TestCase(
                name="Get Available Presets",
                endpoint="/api/agc-squelch/presets",
                method="GET",
                expected_status=200,
                description="Get available AGC/Squelch presets"
            )
        ]
    
    def get_antenna_pattern_tests(self) -> List[TestCase]:
        """Get antenna pattern API tests"""
        return [
            TestCase(
                name="Get Antenna Pattern",
                endpoint="/api/antenna-patterns",
                method="GET",
                expected_status=200,
                params={"pattern_id": "dipole_20m"},
                description="Get specific antenna pattern"
            ),
            TestCase(
                name="List Antenna Patterns",
                endpoint="/api/antenna-patterns/list",
                method="GET",
                expected_status=200,
                description="List all available antenna patterns"
            ),
            TestCase(
                name="Upload Antenna Pattern",
                endpoint="/api/antenna-patterns/upload",
                method="POST",
                expected_status=200,
                data={
                    "name": "test_pattern",
                    "frequency": 14.1,
                    "pattern_data": {"azimuth": [0, 45, 90], "elevation": [0, 10, 20], "gain": [0, -3, -6]}
                },
                description="Upload new antenna pattern"
            )
        ]
    
    def get_vehicle_dynamics_tests(self) -> List[TestCase]:
        """Get vehicle dynamics API tests"""
        return [
            TestCase(
                name="Get Vehicle Dynamics",
                endpoint="/api/vehicle-dynamics",
                method="GET",
                expected_status=200,
                params={"vehicle_id": "test_vehicle"},
                description="Get vehicle dynamics information"
            ),
            TestCase(
                name="List Vehicles",
                endpoint="/api/vehicle-dynamics/list",
                method="GET",
                expected_status=200,
                description="List all tracked vehicles"
            ),
            TestCase(
                name="Get Vehicle Position",
                endpoint="/api/vehicle-dynamics/position",
                method="GET",
                expected_status=200,
                params={"vehicle_id": "test_vehicle"},
                description="Get vehicle position"
            ),
            TestCase(
                name="Update Vehicle Position",
                endpoint="/api/vehicle-dynamics/position",
                method="POST",
                expected_status=200,
                data={
                    "vehicle_id": "test_vehicle",
                    "latitude": 40.7128,
                    "longitude": -74.0060,
                    "altitude": 100.0,
                    "heading": 180.0,
                    "speed": 50.0
                },
                description="Update vehicle position"
            )
        ]
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all API tests and return results"""
        self.logger.info("Starting comprehensive API testing...")
        
        all_tests = [
            ("Health Check", self.get_health_check_tests()),
            ("Authentication", self.get_authentication_tests()),
            ("Solar Data", self.get_solar_data_tests()),
            ("Weather & Lightning", self.get_weather_lightning_tests()),
            ("Band Segments", self.get_band_segments_tests()),
            ("Radio Models", self.get_radio_model_tests()),
            ("Preset Channels", self.get_preset_channel_tests()),
            ("AGC/Squelch", self.get_agc_squelch_tests()),
            ("Antenna Patterns", self.get_antenna_pattern_tests()),
            ("Vehicle Dynamics", self.get_vehicle_dynamics_tests())
        ]
        
        total_tests = 0
        passed_tests = 0
        failed_tests = 0
        error_tests = 0
        
        for category, tests in all_tests:
            self.logger.info(f"Running {category} tests...")
            for test in tests:
                result = self.run_test(test)
                total_tests += 1
                
                if result.result == TestResult.PASS:
                    passed_tests += 1
                    self.logger.info(f"✓ {test.name}")
                elif result.result == TestResult.FAIL:
                    failed_tests += 1
                    self.logger.error(f"✗ {test.name}: {result.error_message}")
                else:
                    error_tests += 1
                    self.logger.error(f"✗ {test.name}: {result.error_message}")
                
                if self.verbose:
                    self.logger.debug(f"Response: {result.response_data}")
        
        # Generate summary
        summary = {
            "total_tests": total_tests,
            "passed": passed_tests,
            "failed": failed_tests,
            "errors": error_tests,
            "success_rate": (passed_tests / total_tests * 100) if total_tests > 0 else 0,
            "test_results": self.test_results,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        self.logger.info(f"Testing complete: {passed_tests}/{total_tests} tests passed ({summary['success_rate']:.1f}%)")
        
        return summary
    
    def generate_report(self, output_file: Optional[str] = None) -> str:
        """Generate a detailed test report"""
        if not self.test_results:
            return "No test results available"
        
        report = {
            "test_summary": {
                "total_tests": len(self.test_results),
                "passed": len([r for r in self.test_results if r.result == TestResult.PASS]),
                "failed": len([r for r in self.test_results if r.result == TestResult.FAIL]),
                "errors": len([r for r in self.test_results if r.result == TestResult.ERROR])
            },
            "test_details": []
        }
        
        for result in self.test_results:
            report["test_details"].append({
                "name": result.test_case.name,
                "endpoint": result.test_case.endpoint,
                "method": result.test_case.method,
                "result": result.result.value,
                "status_code": result.status_code,
                "response_time": result.response_time,
                "error_message": result.error_message,
                "timestamp": result.timestamp
            })
        
        report_json = json.dumps(report, indent=2)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report_json)
            self.logger.info(f"Report saved to {output_file}")
        
        return report_json

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Comprehensive API Testing Tool for FGCom-mumble")
    parser.add_argument("--base-url", default="http://localhost:8080", 
                       help="Base URL for the API server (default: http://localhost:8080)")
    parser.add_argument("--verbose", action="store_true", 
                       help="Enable verbose logging")
    parser.add_argument("--output-file", 
                       help="Output file for test report (JSON format)")
    parser.add_argument("--category", 
                       help="Run tests for specific category only")
    
    args = parser.parse_args()
    
    # Initialize tester
    tester = ComprehensiveAPITester(base_url=args.base_url, verbose=args.verbose)
    
    # Check if server is running
    try:
        response = requests.get(f"{args.base_url}/health", timeout=5)
        if response.status_code != 200:
            print(f"Error: API server returned status {response.status_code}")
            sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"Error: Cannot connect to API server at {args.base_url}")
        print("Please ensure the FGCom-mumble plugin is running with API server enabled")
        sys.exit(1)
    
    print(f"API server is running at {args.base_url}")
    print("Starting comprehensive API testing...")
    print("=" * 60)
    
    # Run tests
    if args.category:
        # Run specific category
        category_methods = {
            "health": tester.get_health_check_tests,
            "auth": tester.get_authentication_tests,
            "solar": tester.get_solar_data_tests,
            "weather": tester.get_weather_lightning_tests,
            "bands": tester.get_band_segments_tests,
            "radio": tester.get_radio_model_tests,
            "presets": tester.get_preset_channel_tests,
            "agc": tester.get_agc_squelch_tests,
            "antenna": tester.get_antenna_pattern_tests,
            "vehicle": tester.get_vehicle_dynamics_tests
        }
        
        if args.category not in category_methods:
            print(f"Unknown category: {args.category}")
            print(f"Available categories: {', '.join(category_methods.keys())}")
            sys.exit(1)
        
        tests = category_methods[args.category]()
        for test in tests:
            result = tester.run_test(test)
            status = "✓" if result.result == TestResult.PASS else "✗"
            print(f"{status} {test.name}")
    else:
        # Run all tests
        summary = tester.run_all_tests()
    
    # Generate report
    report = tester.generate_report(args.output_file)
    
    if not args.output_file:
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        print(json.dumps(json.loads(report)["test_summary"], indent=2))

if __name__ == "__main__":
    main()
