#!/usr/bin/env python3
"""
Test suite for ATIS Weather Integration System
Comprehensive testing of weather monitoring, threshold detection, and ATIS generation.
"""

import unittest
import json
import tempfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add the scripts directory to Python path
import sys
sys.path.insert(0, str(Path(__file__).parent))

from atis_weather_integration import (
    WeatherData, ATISThresholds, WeatherAPI, ATISLetterSystem, 
    ATISWeatherMonitor
)

class TestWeatherData(unittest.TestCase):
    """Test WeatherData dataclass"""
    
    def test_weather_data_creation(self):
        """Test WeatherData object creation"""
        weather = WeatherData(
            wind_speed_kts=15.0,
            wind_direction_deg=270,
            visibility_km=10.0,
            cloud_cover_percent=50,
            temperature_celsius=20.0,
            dew_point_celsius=15.0,
            qnh_hpa=1013.25,
            qfe_hpa=1012.0,
            timestamp=datetime.now(),
            airport_icao="KJFK",
            active_runway="04L",
            gusts_kts=25.0,
            wind_shift=False
        )
        
        self.assertEqual(weather.wind_speed_kts, 15.0)
        self.assertEqual(weather.wind_direction_deg, 270)
        self.assertEqual(weather.airport_icao, "KJFK")
        self.assertTrue(weather.gusts_kts > 0)

class TestATISThresholds(unittest.TestCase):
    """Test ATISThresholds configuration"""
    
    def test_default_thresholds(self):
        """Test default threshold values"""
        thresholds = ATISThresholds()
        
        self.assertEqual(thresholds.wind_direction_change_deg, 10)
        self.assertEqual(thresholds.wind_speed_change_kts, 5)
        self.assertEqual(thresholds.gust_threshold_kts, 10)
        self.assertEqual(thresholds.temperature_change_celsius, 2.0)
        self.assertEqual(thresholds.pressure_change_hpa, 0.68)
        self.assertEqual(thresholds.update_interval_minutes, 60)
        self.assertEqual(thresholds.max_age_hours, 12)
    
    def test_custom_thresholds(self):
        """Test custom threshold values"""
        thresholds = ATISThresholds(
            wind_direction_change_deg=20,
            wind_speed_change_kts=10,
            temperature_change_celsius=5.0
        )
        
        self.assertEqual(thresholds.wind_direction_change_deg, 20)
        self.assertEqual(thresholds.wind_speed_change_kts, 10)
        self.assertEqual(thresholds.temperature_change_celsius, 5.0)

class TestWeatherAPI(unittest.TestCase):
    """Test WeatherAPI class"""
    
    def setUp(self):
        """Setup test environment"""
        self.api = WeatherAPI("test_key", "https://test.api.com")
    
    def test_initialization(self):
        """Test API initialization"""
        self.assertEqual(self.api.api_key, "test_key")
        self.assertEqual(self.api.base_url, "https://test.api.com")
        self.assertIsNotNone(self.api.session)
    
    @patch('requests.Session.get')
    def test_get_metar_data_success(self, mock_get):
        """Test successful METAR data retrieval"""
        mock_response = Mock()
        mock_response.json.return_value = {
            'data': [{
                'icaoId': 'KJFK',
                'rawOb': 'KJFK 121200Z 27010KT 10SM FEW050 20/15 A3012'
            }]
        }
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        result = self.api.get_metar_data("KJFK")
        
        self.assertIsNotNone(result)
        self.assertEqual(result['icaoId'], 'KJFK')
        mock_get.assert_called_once()
    
    @patch('requests.Session.get')
    def test_get_metar_data_failure(self, mock_get):
        """Test METAR data retrieval failure"""
        mock_get.side_effect = Exception("Network error")
        
        result = self.api.get_metar_data("KJFK")
        
        self.assertIsNone(result)
    
    def test_parse_wind(self):
        """Test wind parsing from METAR"""
        # Test normal wind
        direction, speed, gusts = self.api._parse_wind("27010KT")
        self.assertEqual(direction, 270)
        self.assertEqual(speed, 10)
        self.assertIsNone(gusts)
        
        # Test wind with gusts
        direction, speed, gusts = self.api._parse_wind("27010G20KT")
        self.assertEqual(direction, 270)
        self.assertEqual(speed, 10)
        self.assertEqual(gusts, 20)
        
        # Test variable wind
        direction, speed, gusts = self.api._parse_wind("VRB05KT")
        self.assertEqual(direction, 0)
        self.assertEqual(speed, 5)
        self.assertIsNone(gusts)
    
    def test_parse_visibility(self):
        """Test visibility parsing from METAR"""
        # Test statute miles
        visibility = self.api._parse_visibility("10SM")
        self.assertEqual(visibility, 16.09)  # 10 SM in km
        
        # Test meters
        visibility = self.api._parse_visibility("9999")
        self.assertEqual(visibility, 9.999)  # 9999m in km
        
        # Test default
        visibility = self.api._parse_visibility("")
        self.assertEqual(visibility, 10.0)
    
    def test_parse_temperature_dewpoint(self):
        """Test temperature and dewpoint parsing"""
        # Test positive temperatures
        temp, dew = self.api._parse_temperature_dewpoint("20/15")
        self.assertEqual(temp, 20)
        self.assertEqual(dew, 15)
        
        # Test negative temperatures
        temp, dew = self.api._parse_temperature_dewpoint("M02/M05")
        self.assertEqual(temp, -2)
        self.assertEqual(dew, -5)
        
        # Test mixed temperatures
        temp, dew = self.api._parse_temperature_dewpoint("M10/05")
        self.assertEqual(temp, -10)
        self.assertEqual(dew, 5)
    
    def test_parse_pressure(self):
        """Test pressure parsing from METAR"""
        # Test normal pressure
        pressure = self.api._parse_pressure("A3012")
        self.assertAlmostEqual(pressure, 1022.4, places=1)  # 30.12 inHg in hPa
        
        # Test default pressure
        pressure = self.api._parse_pressure("")
        self.assertEqual(pressure, 1013.25)
    
    def test_parse_cloud_cover(self):
        """Test cloud cover parsing from METAR"""
        # Test clear sky
        coverage = self.api._parse_cloud_cover("")
        self.assertEqual(coverage, 0)
        
        # Test few clouds
        coverage = self.api._parse_cloud_cover("FEW050")
        self.assertEqual(coverage, 25)
        
        # Test scattered clouds
        coverage = self.api._parse_cloud_cover("SCT080")
        self.assertEqual(coverage, 50)
        
        # Test broken clouds
        coverage = self.api._parse_cloud_cover("BKN100")
        self.assertEqual(coverage, 75)
        
        # Test overcast
        coverage = self.api._parse_cloud_cover("OVC120")
        self.assertEqual(coverage, 100)
        
        # Test multiple layers
        coverage = self.api._parse_cloud_cover("FEW050 SCT080 BKN100")
        self.assertEqual(coverage, 100)  # Should take maximum

class TestATISLetterSystem(unittest.TestCase):
    """Test ATIS letter designation system"""
    
    def setUp(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.cache_file = Path(self.temp_dir) / "test_letters.json"
        self.letter_system = ATISLetterSystem(str(self.cache_file))
    
    def tearDown(self):
        """Cleanup test environment"""
        shutil.rmtree(self.temp_dir)
    
    def test_letter_sequence(self):
        """Test letter sequence progression"""
        letters = []
        for _ in range(5):
            letter = self.letter_system.get_next_letter()
            letters.append(letter)
        
        expected = ['A', 'B', 'C', 'D', 'E']
        self.assertEqual(letters, expected)
    
    def test_letter_wraparound(self):
        """Test letter sequence wraparound"""
        # Get all 26 letters
        letters = []
        for _ in range(26):
            letter = self.letter_system.get_next_letter()
            letters.append(letter)
        
        # Should start over
        next_letter = self.letter_system.get_next_letter()
        self.assertEqual(next_letter, 'A')
    
    def test_letter_persistence(self):
        """Test letter state persistence across restarts"""
        # Get a few letters
        self.letter_system.get_next_letter()  # A
        self.letter_system.get_next_letter()  # B
        self.letter_system.get_next_letter()  # C
        
        # Create new system with same cache file
        new_system = ATISLetterSystem(str(self.cache_file))
        
        # Should continue from D
        next_letter = new_system.get_next_letter()
        self.assertEqual(next_letter, 'D')

class TestATISWeatherMonitor(unittest.TestCase):
    """Test ATISWeatherMonitor class"""
    
    def setUp(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.config_file = Path(self.temp_dir) / "test_config.json"
        
        # Create test configuration
        test_config = {
            'weather_api_key': 'test_key',
            'airports': ['KJFK', 'KLAX'],
            'thresholds': {
                'wind_direction_change_deg': 10,
                'wind_speed_change_kts': 5,
                'gust_threshold_kts': 10,
                'temperature_change_celsius': 2.0,
                'pressure_change_hpa': 0.68,
                'visibility_change_km': 1.0,
                'cloud_cover_change_percent': 10
            },
            'update_interval_minutes': 60,
            'max_age_hours': 12,
            'output_directory': str(Path(self.temp_dir) / 'atis_recordings'),
            'tts_config': {
                'voice': 'en_US-lessac-medium',
                'speed': 1.0,
                'pitch': 1.0
            }
        }
        
        with open(self.config_file, 'w') as f:
            json.dump(test_config, f)
        
        self.monitor = ATISWeatherMonitor(str(self.config_file))
    
    def tearDown(self):
        """Cleanup test environment"""
        shutil.rmtree(self.temp_dir)
    
    def test_config_loading(self):
        """Test configuration loading"""
        self.assertEqual(self.monitor.config['weather_api_key'], 'test_key')
        self.assertEqual(self.monitor.config['airports'], ['KJFK', 'KLAX'])
        self.assertEqual(self.monitor.config['thresholds']['wind_direction_change_deg'], 10)
    
    def test_weather_change_detection(self):
        """Test weather change detection"""
        # Create initial weather data
        initial_weather = WeatherData(
            wind_speed_kts=10.0,
            wind_direction_deg=270,
            visibility_km=10.0,
            cloud_cover_percent=50,
            temperature_celsius=20.0,
            dew_point_celsius=15.0,
            qnh_hpa=1013.25,
            qfe_hpa=1012.0,
            timestamp=datetime.now(),
            airport_icao="KJFK",
            active_runway="04L"
        )
        
        # Cache initial weather
        self.monitor.weather_cache['KJFK'] = initial_weather
        self.monitor.last_weather_check['KJFK'] = datetime.now()
        
        # Create weather with significant wind change
        changed_weather = WeatherData(
            wind_speed_kts=20.0,  # 10 kt increase
            wind_direction_deg=280,  # 10 degree change
            visibility_km=10.0,
            cloud_cover_percent=50,
            temperature_celsius=20.0,
            dew_point_celsius=15.0,
            qnh_hpa=1013.25,
            qfe_hpa=1012.0,
            timestamp=datetime.now(),
            airport_icao="KJFK",
            active_runway="04L"
        )
        
        # Mock the weather API to return changed weather
        with patch.object(self.monitor.weather_api, 'get_metar_data') as mock_get_metar, \
             patch.object(self.monitor.weather_api, 'parse_metar') as mock_parse_metar:
            
            mock_get_metar.return_value = {'rawOb': 'KJFK 121200Z 28020KT 10SM FEW050 20/15 A3012'}
            mock_parse_metar.return_value = changed_weather
            
            # Check for changes
            has_changes = self.monitor.check_weather_changes('KJFK')
            
            self.assertTrue(has_changes)
    
    def test_atis_text_generation(self):
        """Test ATIS text generation"""
        weather = WeatherData(
            wind_speed_kts=15.0,
            wind_direction_deg=270,
            visibility_km=10.0,
            cloud_cover_percent=50,
            temperature_celsius=20.0,
            dew_point_celsius=15.0,
            qnh_hpa=1013.25,
            qfe_hpa=1012.0,
            timestamp=datetime.now(),
            airport_icao="KJFK",
            active_runway="04L",
            gusts_kts=25.0
        )
        
        atis_text = self.monitor.generate_atis_text(weather)
        
        self.assertIn("ATIS Information", atis_text)
        self.assertIn("KJFK", atis_text)
        self.assertIn("Wind 270 degrees at 15 knots", atis_text)
        self.assertIn("gusts to 25 knots", atis_text)
        self.assertIn("Visibility 10 kilometres or more", atis_text)
        self.assertIn("Temperature 20, dew point 15", atis_text)
        self.assertIn("QNH 1013, QFE 1012", atis_text)
        self.assertIn("Advise you have information", atis_text)

class TestIntegration(unittest.TestCase):
    """Integration tests for the complete system"""
    
    def setUp(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.config_file = Path(self.temp_dir) / "integration_config.json"
        
        # Create test configuration
        test_config = {
            'weather_api_key': 'test_key',
            'airports': ['KJFK'],
            'thresholds': {
                'wind_direction_change_deg': 10,
                'wind_speed_change_kts': 5,
                'gust_threshold_kts': 10,
                'temperature_change_celsius': 2.0,
                'pressure_change_hpa': 0.68,
                'visibility_change_km': 1.0,
                'cloud_cover_change_percent': 10
            },
            'update_interval_minutes': 1,  # Short interval for testing
            'max_age_hours': 12,
            'output_directory': str(Path(self.temp_dir) / 'atis_recordings'),
            'tts_config': {
                'voice': 'en_US-lessac-medium',
                'speed': 1.0,
                'pitch': 1.0
            }
        }
        
        with open(self.config_file, 'w') as f:
            json.dump(test_config, f)
    
    def tearDown(self):
        """Cleanup test environment"""
        shutil.rmtree(self.temp_dir)
    
    @patch('atis_weather_integration.generate_atis_audio')
    def test_complete_atis_generation(self, mock_generate_audio):
        """Test complete ATIS generation workflow"""
        mock_generate_audio.return_value = True
        
        monitor = ATISWeatherMonitor(str(self.config_file))
        
        # Create test weather data
        weather = WeatherData(
            wind_speed_kts=15.0,
            wind_direction_deg=270,
            visibility_km=10.0,
            cloud_cover_percent=50,
            temperature_celsius=20.0,
            dew_point_celsius=15.0,
            qnh_hpa=1013.25,
            qfe_hpa=1012.0,
            timestamp=datetime.now(),
            airport_icao="KJFK",
            active_runway="04L"
        )
        
        # Generate ATIS recording
        recording_path = monitor.generate_atis_recording("KJFK", weather)
        
        self.assertIsNotNone(recording_path)
        self.assertTrue(Path(recording_path).exists())
        mock_generate_audio.assert_called_once()

def run_tests():
    """Run all tests"""
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_classes = [
        TestWeatherData,
        TestATISThresholds,
        TestWeatherAPI,
        TestATISLetterSystem,
        TestATISWeatherMonitor,
        TestIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
