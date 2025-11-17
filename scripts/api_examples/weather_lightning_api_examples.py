#!/usr/bin/env python3
"""
Weather and Lightning Data API Examples for Game Integration

This script demonstrates how games can submit weather data (rain, temperature, etc.) 
and lightning strike data to the FGCom-mumble API for realistic atmospheric effects 
on radio propagation.
"""

import requests
import random

class WeatherLightningAPIClient:
    def __init__(self, base_url="http://localhost:8080"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'FGCom-Game-Client/1.0'
        })
    
    def submit_weather_data(self, temperature, humidity, pressure, wind_speed=0, wind_direction=0, 
                          precipitation=0, has_thunderstorms=False, **kwargs):
        """Submit weather data from a game"""
        data = {
            "temperature_celsius": temperature,
            "humidity_percent": humidity,
            "pressure_hpa": pressure,
            "wind_speed_ms": wind_speed,
            "wind_direction_deg": wind_direction,
            "precipitation_mmh": precipitation,
            "has_thunderstorms": has_thunderstorms
        }
        
        # Add optional fields
        optional_fields = ['dew_point_celsius', 'visibility_km', 'cloud_cover_percent', 
                          'uv_index', 'air_quality_index', 'pollen_count', 'storm_distance_km', 
                          'storm_intensity']
        for field in optional_fields:
            if field in kwargs:
                data[field] = kwargs[field]
        
        try:
            response = self.session.post(f"{self.base_url}/api/v1/weather-data/submit", json=data)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error submitting weather data: {e}")
            return None
    
    def submit_lightning_strike(self, latitude, longitude, intensity, altitude=0, 
                               polarity="negative", strike_type="cloud_to_ground", **kwargs):
        """Submit lightning strike data from a game"""
        data = {
            "latitude": latitude,
            "longitude": longitude,
            "intensity_ka": intensity,
            "altitude_m": altitude,
            "polarity": polarity,
            "type": strike_type
        }
        
        # Add optional fields
        optional_fields = ['temperature_celsius', 'humidity_percent', 'pressure_hpa', 
                          'wind_speed_ms', 'wind_direction_deg', 'precipitation_mmh']
        for field in optional_fields:
            if field in kwargs:
                data[field] = kwargs[field]
        
        try:
            response = self.session.post(f"{self.base_url}/api/v1/lightning-data/submit", json=data)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error submitting lightning data: {e}")
            return None
    
    def submit_batch_lightning_strikes(self, strikes):
        """Submit multiple lightning strikes"""
        data = {"lightning_strikes": strikes}
        
        try:
            response = self.session.post(f"{self.base_url}/api/v1/lightning-data/batch-submit", json=data)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error submitting batch lightning data: {e}")
            return None
    
    def get_current_weather(self):
        """Get current weather conditions"""
        try:
            response = self.session.get(f"{self.base_url}/api/v1/weather-data/current")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error getting weather data: {e}")
            return None
    
    def get_current_lightning(self):
        """Get current lightning data"""
        try:
            response = self.session.get(f"{self.base_url}/api/v1/lightning-data/current")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error getting lightning data: {e}")
            return None

def simulate_thunderstorm():
    """Simulate a thunderstorm with lightning strikes and weather effects"""
    print("Simulating Thunderstorm...")
    
    client = WeatherLightningAPIClient()
    
    # Submit thunderstorm weather conditions
    weather_result = client.submit_weather_data(
        temperature=15.0,  # Cooler during storm
        humidity=85.0,     # High humidity
        pressure=995.0,   # Low pressure
        wind_speed=25.0,  # Strong winds
        wind_direction=270.0,  # West wind
        precipitation=15.0,   # Heavy rain
        has_thunderstorms=True,
        storm_distance_km=5.0,
        storm_intensity=0.8,
        visibility_km=2.0,    # Poor visibility
        cloud_cover_percent=95.0
    )
    
    if weather_result:
        print(f"SUCCESS: Weather data submitted: {weather_result['message']}")
    
    # Simulate multiple lightning strikes
    strikes = []
    for i in range(5):
        strike = {
            "latitude": 40.7128 + random.uniform(-0.1, 0.1),
            "longitude": -74.0060 + random.uniform(-0.1, 0.1),
            "intensity_ka": random.uniform(10, 50),
            "altitude_m": random.uniform(500, 2000),
            "polarity": random.choice(["positive", "negative"]),
            "type": random.choice(["cloud_to_ground", "cloud_to_cloud"]),
            "temperature_celsius": 15.0,
            "humidity_percent": 85.0,
            "pressure_hpa": 995.0
        }
        strikes.append(strike)
    
    # Submit batch lightning strikes
    lightning_result = client.submit_batch_lightning_strikes(strikes)
    if lightning_result:
        print(f"SUCCESS: Lightning strikes submitted: {lightning_result['message']}")
    
    return weather_result, lightning_result

def simulate_rain_effects():
    """Simulate rain effects on radio propagation"""
    print("Simulating Rain Effects...")
    
    client = WeatherLightningAPIClient()
    
    # Submit rain weather conditions
    weather_result = client.submit_weather_data(
        temperature=18.0,
        humidity=75.0,
        pressure=1005.0,
        wind_speed=8.0,
        wind_direction=180.0,
        precipitation=8.0,  # Moderate rain
        has_thunderstorms=False,
        visibility_km=5.0,
        cloud_cover_percent=80.0,
        dew_point_celsius=12.0
    )
    
    if weather_result:
        print(f"SUCCESS: Rain weather data submitted: {weather_result['message']}")
    
    return weather_result

def simulate_clear_weather():
    """Simulate clear weather conditions"""
    print("Simulating Clear Weather...")
    
    client = WeatherLightningAPIClient()
    
    # Submit clear weather conditions
    weather_result = client.submit_weather_data(
        temperature=25.0,
        humidity=40.0,
        pressure=1013.25,
        wind_speed=3.0,
        wind_direction=90.0,
        precipitation=0.0,
        has_thunderstorms=False,
        visibility_km=15.0,
        cloud_cover_percent=10.0,
        uv_index=7.0
    )
    
    if weather_result:
        print(f"SUCCESS: Clear weather data submitted: {weather_result['message']}")
    
    return weather_result

def simulate_lightning_storm_sequence():
    """Simulate a complete lightning storm sequence"""
    print("Simulating Lightning Storm Sequence...")
    
    client = WeatherLightningAPIClient()
    
    # Phase 1: Storm approaching
    print("Phase 1: Storm approaching...")
    client.submit_weather_data(
        temperature=22.0,
        humidity=65.0,
        pressure=1008.0,
        wind_speed=12.0,
        wind_direction=240.0,
        precipitation=2.0,
        has_thunderstorms=True,
        storm_distance_km=25.0,
        storm_intensity=0.3
    )
    time.sleep(1)
    
    # Phase 2: Storm intensifying
    print("Phase 2: Storm intensifying...")
    client.submit_weather_data(
        temperature=18.0,
        humidity=80.0,
        pressure=1000.0,
        wind_speed=20.0,
        wind_direction=250.0,
        precipitation=12.0,
        has_thunderstorms=True,
        storm_distance_km=10.0,
        storm_intensity=0.7
    )
    time.sleep(1)
    
    # Phase 3: Lightning strikes
    print("Phase 3: Lightning strikes...")
    strikes = []
    for i in range(8):
        strike = {
            "latitude": 40.7128 + random.uniform(-0.05, 0.05),
            "longitude": -74.0060 + random.uniform(-0.05, 0.05),
            "intensity_ka": random.uniform(15, 60),
            "altitude_m": random.uniform(800, 1500),
            "polarity": random.choice(["positive", "negative"]),
            "type": "cloud_to_ground"
        }
        strikes.append(strike)
    
    client.submit_batch_lightning_strikes(strikes)
    time.sleep(1)
    
    # Phase 4: Storm passing
    print("Phase 4: Storm passing...")
    client.submit_weather_data(
        temperature=20.0,
        humidity=70.0,
        pressure=1005.0,
        wind_speed=15.0,
        wind_direction=260.0,
        precipitation=5.0,
        has_thunderstorms=True,
        storm_distance_km=15.0,
        storm_intensity=0.4
    )
    time.sleep(1)
    
    # Phase 5: Clearing
    print("Phase 5: Weather clearing...")
    client.submit_weather_data(
        temperature=24.0,
        humidity=55.0,
        pressure=1010.0,
        wind_speed=8.0,
        wind_direction=270.0,
        precipitation=0.5,
        has_thunderstorms=False,
        visibility_km=12.0
    )

def main():
    """Main function demonstrating weather and lightning API usage"""
    print("FGCom-mumble Weather & Lightning Data API Examples")
    print("=" * 60)
    
    # Initialize API client
    client = WeatherLightningAPIClient()
    
    # Example 1: Get current conditions
    print("\n1. Getting current weather conditions...")
    current_weather = client.get_current_weather()
    if current_weather:
        print(f"Current temperature: {current_weather['weather_conditions']['temperature_celsius']}°C")
        print(f"Current humidity: {current_weather['weather_conditions']['humidity_percent']}%")
        print(f"Has thunderstorms: {current_weather['weather_conditions']['has_thunderstorms']}")
    
    # Example 2: Simulate different weather conditions
    print("\n2. Simulating different weather conditions...")
    
    # Clear weather
    simulate_clear_weather()
    time.sleep(2)
    
    # Rain effects
    simulate_rain_effects()
    time.sleep(2)
    
    # Thunderstorm with lightning
    simulate_thunderstorm()
    time.sleep(2)
    
    # Example 3: Complete storm sequence
    print("\n3. Simulating complete lightning storm sequence...")
    simulate_lightning_storm_sequence()
    
    # Example 4: Individual lightning strike
    print("\n4. Submitting individual lightning strike...")
    strike_result = client.submit_lightning_strike(
        latitude=40.7128,
        longitude=-74.0060,
        intensity=35.5,
        altitude=1200.0,
        polarity="negative",
        strike_type="cloud_to_ground",
        temperature_celsius=18.0,
        humidity_percent=80.0
    )
    
    if strike_result:
        print(f"SUCCESS: Lightning strike submitted: {strike_result['message']}")
    
    print("\nWeather & Lightning API examples completed!")
    print("\nThese examples demonstrate how games can:")
    print("- Submit realistic weather conditions (temperature, humidity, pressure, rain)")
    print("- Submit lightning strike data with location and intensity")
    print("- Simulate complete storm sequences")
    print("- Affect radio propagation through atmospheric conditions")

if __name__ == "__main__":
    main()
