#!/usr/bin/env python3
"""
ATIS Weather Integration System
Automatically updates ATIS recordings when weather conditions change significantly.

This module integrates with real-time weather data APIs to monitor weather conditions
and automatically regenerate ATIS recordings when thresholds are exceeded.

Features:
- Real-time weather data monitoring
- Configurable change thresholds
- ATIS letter designation system (alpha, bravo, charlie, etc.)
- Automatic recording generation
- Weather data caching and comparison
"""

import json
import time
import logging
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
import hashlib

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class WeatherData:
    """Weather data structure for ATIS information"""
    wind_speed_kts: float
    wind_direction_deg: int
    visibility_km: float
    cloud_cover_percent: int
    temperature_celsius: float
    dew_point_celsius: float
    qnh_hpa: float  # Pressure at mean sea level
    qfe_hpa: float  # Pressure at airfield elevation
    timestamp: datetime
    airport_icao: str
    active_runway: str
    gusts_kts: Optional[float] = None
    wind_shift: bool = False

@dataclass
class ATISThresholds:
    """Configurable thresholds for ATIS updates"""
    wind_direction_change_deg: int = 10
    wind_speed_change_kts: int = 5
    gust_threshold_kts: int = 10
    temperature_change_celsius: float = 2.0
    pressure_change_hpa: float = 0.68  # 0.02 inHg = 0.68 hPa
    visibility_change_km: float = 1.0
    cloud_cover_change_percent: int = 10
    update_interval_minutes: int = 60
    max_age_hours: int = 12

class WeatherAPI:
    """Weather data API integration"""
    
    def __init__(self, api_key: str, base_url: str = "https://api.aviationweather.gov"):
        self.api_key = api_key
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'FGCom-Mumble-ATIS/1.0',
            'Accept': 'application/json'
        })
    
    def get_metar_data(self, airport_icao: str) -> Optional[Dict]:
        """Fetch METAR data for specified airport"""
        try:
            url = f"{self.base_url}/metar/taf"
            params = {
                'ids': airport_icao,
                'format': 'json',
                'taf': 'false',
                'hours': '1'
            }
            
            response = self.session.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            if data and 'data' in data and len(data['data']) > 0:
                return data['data'][0]
            
        except Exception as e:
            logger.error(f"Failed to fetch METAR data for {airport_icao}: {e}")
        
        return None
    
    def parse_metar(self, metar_data: Dict) -> Optional[WeatherData]:
        """Parse METAR data into WeatherData structure"""
        try:
            raw_text = metar_data.get('rawOb', '')
            if not raw_text:
                return None
            
            # Parse wind (e.g., "27010KT" or "VRB05KT")
            wind_match = self._parse_wind(raw_text)
            if not wind_match:
                return None
            
            wind_direction, wind_speed, gusts = wind_match
            
            # Parse visibility (e.g., "10SM" or "9999")
            visibility = self._parse_visibility(raw_text)
            
            # Parse temperature and dew point
            temp_dew = self._parse_temperature_dewpoint(raw_text)
            if not temp_dew:
                return None
            
            temperature, dew_point = temp_dew
            
            # Parse pressure (QNH)
            qnh = self._parse_pressure(raw_text)
            
            # Parse cloud cover
            cloud_cover = self._parse_cloud_cover(raw_text)
            
            # Calculate QFE (simplified - would need airport elevation)
            qfe = qnh - 0.12  # Approximate adjustment for elevation
            
            return WeatherData(
                wind_speed_kts=wind_speed,
                wind_direction_deg=wind_direction,
                visibility_km=visibility,
                cloud_cover_percent=cloud_cover,
                temperature_celsius=temperature,
                dew_point_celsius=dew_point,
                qnh_hpa=qnh,
                qfe_hpa=qfe,
                timestamp=datetime.now(),
                airport_icao=metar_data.get('icaoId', ''),
                active_runway='',  # Would need additional logic to determine
                gusts_kts=gusts,
                wind_shift=(wind_direction == 'VRB')
            )
            
        except Exception as e:
            logger.error(f"Failed to parse METAR data: {e}")
            return None
    
    def _parse_wind(self, metar: str) -> Optional[Tuple[int, float, Optional[float]]]:
        """Parse wind information from METAR"""
        import re
        
        # Pattern for wind: direction + speed + optional gusts
        wind_pattern = r'(\d{3}|VRB)(\d{2,3})(?:G(\d{2,3}))?KT'
        match = re.search(wind_pattern, metar)
        
        if match:
            direction_str, speed_str, gust_str = match.groups()
            direction = 0 if direction_str == 'VRB' else int(direction_str)
            speed = float(speed_str)
            gusts = float(gust_str) if gust_str else None
            return direction, speed, gusts
        
        return None
    
    def _parse_visibility(self, metar: str) -> float:
        """Parse visibility from METAR"""
        import re
        
        # Pattern for visibility: "10SM" or "9999" (meters)
        vis_pattern = r'(\d{1,2})SM|(\d{4})'
        match = re.search(vis_pattern, metar)
        
        if match:
            sm_vis, meter_vis = match.groups()
            if sm_vis:
                return float(sm_vis) * 1.609  # Convert SM to km
            elif meter_vis:
                return float(meter_vis) / 1000  # Convert meters to km
        
        return 10.0  # Default visibility
    
    def _parse_temperature_dewpoint(self, metar: str) -> Optional[Tuple[float, float]]:
        """Parse temperature and dew point from METAR"""
        import re
        
        # Pattern for temp/dewpoint: "M02/M05" or "02/05"
        temp_pattern = r'([M]?\d{2})/([M]?\d{2})'
        match = re.search(temp_pattern, metar)
        
        if match:
            temp_str, dew_str = match.groups()
            temp = float(temp_str[1:]) if temp_str.startswith('M') else float(temp_str)
            if temp_str.startswith('M'):
                temp = -temp
            dew = float(dew_str[1:]) if dew_str.startswith('M') else float(dew_str)
            if dew_str.startswith('M'):
                dew = -dew
            return temp, dew
        
        return None
    
    def _parse_pressure(self, metar: str) -> float:
        """Parse pressure (QNH) from METAR"""
        import re
        
        # Pattern for pressure: "A3012" (inches of mercury)
        pressure_pattern = r'A(\d{4})'
        match = re.search(pressure_pattern, metar)
        
        if match:
            pressure_inhg = float(match.group(1)) / 100
            return pressure_inhg * 33.8639  # Convert to hPa
        
        return 1013.25  # Standard pressure
    
    def _parse_cloud_cover(self, metar: str) -> int:
        """Parse cloud cover from METAR"""
        import re
        
        # Count cloud layers (simplified)
        cloud_pattern = r'(FEW|SCT|BKN|OVC)'
        matches = re.findall(cloud_pattern, metar)
        
        if not matches:
            return 0
        
        # Convert cloud coverage to percentage
        coverage_map = {
            'FEW': 25,
            'SCT': 50,
            'BKN': 75,
            'OVC': 100
        }
        
        return max(coverage_map.get(layer, 0) for layer in matches)

class ATISLetterSystem:
    """Manages ATIS letter designation system"""
    
    def __init__(self, cache_file: str = "atis_letters.json"):
        self.cache_file = Path(cache_file)
        self.letters = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        self.load_letter_state()
    
    def load_letter_state(self):
        """Load current letter state from cache"""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, 'r') as f:
                    data = json.load(f)
                    self.current_letter_index = data.get('current_letter_index', 0)
                    self.last_update = datetime.fromisoformat(data.get('last_update', datetime.now().isoformat()))
                    
                    # Reset to alpha if more than 12 hours have passed
                    if datetime.now() - self.last_update > timedelta(hours=12):
                        self.current_letter_index = 0
        except Exception as e:
            logger.error(f"Failed to load letter state: {e}")
            self.current_letter_index = 0
            self.last_update = datetime.now()
    
    def get_next_letter(self) -> str:
        """Get next ATIS letter and advance counter"""
        letter = self.letters[self.current_letter_index]
        self.current_letter_index = (self.current_letter_index + 1) % len(self.letters)
        self.last_update = datetime.now()
        self.save_letter_state()
        return letter
    
    def save_letter_state(self):
        """Save current letter state to cache"""
        try:
            data = {
                'current_letter_index': self.current_letter_index,
                'last_update': self.last_update.isoformat()
            }
            with open(self.cache_file, 'w') as f:
                json.dump(data, f)
        except Exception as e:
            logger.error(f"Failed to save letter state: {e}")

class ATISWeatherMonitor:
    """Main class for monitoring weather and updating ATIS"""
    
    def __init__(self, config_file: str = "atis_weather_config.json"):
        self.config_file = Path(config_file)
        self.load_config()
        self.weather_api = WeatherAPI(self.config.get('weather_api_key', ''))
        self.letter_system = ATISLetterSystem()
        self.weather_cache = {}
        self.last_weather_check = {}
        self.switches = self.config.get('switches', {})
        self.api_endpoints = self.config.get('api_endpoints', {})
        self.performance_settings = self.config.get('performance_settings', {})
        self.security_settings = self.config.get('security_settings', {})
        
    def load_config(self):
        """Load configuration from file"""
        default_config = {
            'weather_api_key': '',
            'airports': ['KJFK', 'KLAX', 'ENGM', 'EGLL'],
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
            'output_directory': 'atis_recordings',
            'tts_config': {
                'voice': 'en_US-lessac-medium',
                'speed': 1.0,
                'pitch': 1.0
            }
        }
        
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    self.config = {**default_config, **json.load(f)}
            else:
                self.config = default_config
                self.save_config()
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            self.config = default_config
    
    def save_config(self):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
    
    def check_weather_changes(self, airport: str) -> bool:
        """Check if weather has changed significantly for an airport"""
        try:
            # Get current weather data
            metar_data = self.weather_api.get_metar_data(airport)
            if not metar_data:
                logger.warning(f"No weather data available for {airport}")
                return False
            
            current_weather = self.weather_api.parse_metar(metar_data)
            if not current_weather:
                logger.warning(f"Failed to parse weather data for {airport}")
                return False
            
            # Check if we have previous weather data
            if airport not in self.weather_cache:
                self.weather_cache[airport] = current_weather
                self.last_weather_check[airport] = datetime.now()
                logger.info(f"Initial weather data cached for {airport}")
                return True  # First time, generate ATIS
            
            previous_weather = self.weather_cache[airport]
            thresholds = ATISThresholds(**self.config['thresholds'])
            
            # Check for significant changes
            changes_detected = []
            
            # Wind direction change
            wind_dir_diff = abs(current_weather.wind_direction_deg - previous_weather.wind_direction_deg)
            if wind_dir_diff > thresholds.wind_direction_change_deg:
                changes_detected.append(f"Wind direction changed by {wind_dir_diff}°")
            
            # Wind speed change
            wind_speed_diff = abs(current_weather.wind_speed_kts - previous_weather.wind_speed_kts)
            if wind_speed_diff > thresholds.wind_speed_change_kts:
                changes_detected.append(f"Wind speed changed by {wind_speed_diff} kts")
            
            # Gust development/change
            if current_weather.gusts_kts and current_weather.gusts_kts > thresholds.gust_threshold_kts:
                if not previous_weather.gusts_kts or abs(current_weather.gusts_kts - (previous_weather.gusts_kts or 0)) > 5:
                    changes_detected.append(f"Gusts developed/changed to {current_weather.gusts_kts} kts")
            
            # Temperature change
            temp_diff = abs(current_weather.temperature_celsius - previous_weather.temperature_celsius)
            if temp_diff > thresholds.temperature_change_celsius:
                changes_detected.append(f"Temperature changed by {temp_diff}°C")
            
            # Pressure change
            pressure_diff = abs(current_weather.qnh_hpa - previous_weather.qnh_hpa)
            if pressure_diff > thresholds.pressure_change_hpa:
                changes_detected.append(f"Pressure changed by {pressure_diff} hPa")
            
            # Visibility change
            vis_diff = abs(current_weather.visibility_km - previous_weather.visibility_km)
            if vis_diff > thresholds.visibility_change_km:
                changes_detected.append(f"Visibility changed by {vis_diff} km")
            
            # Cloud cover change
            cloud_diff = abs(current_weather.cloud_cover_percent - previous_weather.cloud_cover_percent)
            if cloud_diff > thresholds.cloud_cover_change_percent:
                changes_detected.append(f"Cloud cover changed by {cloud_diff}%")
            
            # Check if enough time has passed (forced update)
            time_since_last = datetime.now() - self.last_weather_check[airport]
            if time_since_last > timedelta(minutes=self.config['update_interval_minutes']):
                changes_detected.append("Scheduled update interval reached")
            
            if changes_detected:
                logger.info(f"Weather changes detected for {airport}: {', '.join(changes_detected)}")
                self.weather_cache[airport] = current_weather
                self.last_weather_check[airport] = datetime.now()
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking weather changes for {airport}: {e}")
            return False
    
    def generate_atis_text(self, weather: WeatherData) -> str:
        """Generate ATIS text from weather data"""
        letter = self.letter_system.get_next_letter()
        
        # Format wind information
        if weather.wind_shift:
            wind_info = f"Wind variable at {weather.wind_speed_kts:.0f} knots"
        else:
            wind_info = f"Wind {weather.wind_direction_deg:03d} degrees at {weather.wind_speed_kts:.0f} knots"
        
        if weather.gusts_kts and weather.gusts_kts > 10:
            wind_info += f", gusts to {weather.gusts_kts:.0f} knots"
        
        # Format visibility
        if weather.visibility_km >= 10:
            visibility_info = "Visibility 10 kilometres or more"
        else:
            visibility_info = f"Visibility {weather.visibility_km:.1f} kilometres"
        
        # Format temperature and dew point
        temp_info = f"Temperature {weather.temperature_celsius:.0f}, dew point {weather.dew_point_celsius:.0f}"
        
        # Format pressure
        pressure_info = f"QNH {weather.qnh_hpa:.0f}, QFE {weather.qfe_hpa:.0f}"
        
        # Format cloud cover
        if weather.cloud_cover_percent == 0:
            cloud_info = "Sky clear"
        elif weather.cloud_cover_percent < 25:
            cloud_info = "Few clouds"
        elif weather.cloud_cover_percent < 50:
            cloud_info = "Scattered clouds"
        elif weather.cloud_cover_percent < 75:
            cloud_info = "Broken clouds"
        else:
            cloud_info = "Overcast"
        
        # Construct ATIS message
        atis_text = f"""ATIS Information {letter} for {weather.airport_icao}.
{wind_info}.
{visibility_info}.
{cloud_info}.
{temp_info}.
{pressure_info}.
Advise you have information {letter}."""
        
        return atis_text
    
    def generate_atis_recording(self, airport: str, weather: WeatherData) -> str:
        """Generate ATIS recording using TTS"""
        try:
            atis_text = self.generate_atis_text(weather)
            
            # Create output directory
            output_dir = Path(self.config['output_directory'])
            output_dir.mkdir(exist_ok=True)
            
            # Generate filename with timestamp and letter
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{airport}_ATIS_{timestamp}_{weather.airport_icao}.wav"
            output_path = output_dir / filename
            
            # Use existing TTS system
            from atis_tts_generator import generate_atis_audio
            
            success = generate_atis_audio(
                text=atis_text,
                output_path=str(output_path),
                voice=self.config['tts_config']['voice'],
                speed=self.config['tts_config']['speed'],
                pitch=self.config['tts_config']['pitch']
            )
            
            if success:
                logger.info(f"Generated ATIS recording: {output_path}")
                return str(output_path)
            else:
                logger.error(f"Failed to generate ATIS recording for {airport}")
                return None
                
        except Exception as e:
            logger.error(f"Error generating ATIS recording for {airport}: {e}")
            return None
    
    def monitor_airports(self):
        """Monitor all configured airports for weather changes"""
        logger.info("Starting ATIS weather monitoring...")
        
        while True:
            try:
                for airport in self.config['airports']:
                    logger.info(f"Checking weather for {airport}...")
                    
                    if self.check_weather_changes(airport):
                        # Get current weather data
                        metar_data = self.weather_api.get_metar_data(airport)
                        if metar_data:
                            weather = self.weather_api.parse_metar(metar_data)
                            if weather:
                                # Generate new ATIS recording
                                recording_path = self.generate_atis_recording(airport, weather)
                                if recording_path:
                                    logger.info(f"ATIS updated for {airport}: {recording_path}")
                                else:
                                    logger.error(f"Failed to generate ATIS for {airport}")
                    
                    # Small delay between airport checks
                    time.sleep(2)
                
                # Wait for next check cycle
                sleep_time = self.config['update_interval_minutes'] * 60
                logger.info(f"Waiting {self.config['update_interval_minutes']} minutes until next check...")
                time.sleep(sleep_time)
                
            except KeyboardInterrupt:
                logger.info("Monitoring stopped by user")
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(60)  # Wait before retrying

def main():
    """Main function to start ATIS weather monitoring"""
    import argparse
    
    parser = argparse.ArgumentParser(description='ATIS Weather Integration System')
    parser.add_argument('--config', default='atis_weather_config.json', 
                       help='Configuration file path')
    parser.add_argument('--airport', help='Monitor specific airport only')
    parser.add_argument('--test', action='store_true', 
                       help='Test mode - check once and exit')
    
    args = parser.parse_args()
    
    # Initialize monitor
    monitor = ATISWeatherMonitor(args.config)
    
    if args.test:
        # Test mode - check once
        if args.airport:
            airports = [args.airport]
        else:
            airports = monitor.config['airports']
        
        for airport in airports:
            if monitor.check_weather_changes(airport):
                metar_data = monitor.weather_api.get_metar_data(airport)
                if metar_data:
                    weather = monitor.weather_api.parse_metar(metar_data)
                    if weather:
                        recording_path = monitor.generate_atis_recording(airport, weather)
                        if recording_path:
                            print(f"Test ATIS generated for {airport}: {recording_path}")
    else:
        # Continuous monitoring
        if args.airport:
            monitor.config['airports'] = [args.airport]
        
        monitor.monitor_airports()

if __name__ == "__main__":
    main()
