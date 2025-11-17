#!/usr/bin/env python3
"""
Solar Data API Examples for Game Integration

This script demonstrates how games can submit solar data to the FGCom-mumble API.
It includes examples for single submission, batch submission, and updates.
"""

import requests

class SolarDataAPIClient:
    def __init__(self, base_url="http://localhost:8080"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'FGCom-Game-Client/1.0'
        })
    
    def get_current_solar_data(self):
        """Get current solar data from the API"""
        try:
            response = self.session.get(f"{self.base_url}/api/v1/solar-data/current")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error getting current solar data: {e}")
            return None
    
    def submit_solar_data(self, solar_flux, k_index, a_index, **kwargs):
        """Submit single solar data entry"""
        data = {
            "solar_flux": solar_flux,
            "k_index": k_index,
            "a_index": a_index
        }
        
        # Add optional fields
        optional_fields = ['ap_index', 'sunspot_number', 'solar_wind_speed', 'solar_wind_density']
        for field in optional_fields:
            if field in kwargs:
                data[field] = kwargs[field]
        
        try:
            response = self.session.post(f"{self.base_url}/api/v1/solar-data/submit", json=data)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error submitting solar data: {e}")
            return None
    
    def submit_batch_solar_data(self, solar_data_array):
        """Submit multiple solar data entries"""
        data = {
            "solar_data_array": solar_data_array
        }
        
        try:
            response = self.session.post(f"{self.base_url}/api/v1/solar-data/batch-submit", json=data)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error submitting batch solar data: {e}")
            return None
    
    def update_solar_data(self, **kwargs):
        """Update existing solar data"""
        valid_fields = ['solar_flux', 'k_index', 'a_index', 'ap_index', 'sunspot_number', 'solar_wind_speed', 'solar_wind_density']
        data = {k: v for k, v in kwargs.items() if k in valid_fields}
        
        if not data:
            print("No valid fields provided for update")
            return None
        
        try:
            response = self.session.put(f"{self.base_url}/api/v1/solar-data/update", json=data)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error updating solar data: {e}")
            return None
    
    def get_solar_history(self, start_date, end_date, data_points=100):
        """Get historical solar data"""
        params = {
            "start_date": start_date,
            "end_date": end_date,
            "data_points": data_points
        }
        
        try:
            response = self.session.get(f"{self.base_url}/api/v1/solar-data/history", params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error getting solar history: {e}")
            return None
    
    def get_solar_forecast(self, hours=24):
        """Get solar data forecast"""
        params = {"hours": hours}
        
        try:
            response = self.session.get(f"{self.base_url}/api/v1/solar-data/forecast", params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error getting solar forecast: {e}")
            return None

def main():
    """Main function demonstrating solar data API usage"""
    print("FGCom-mumble Solar Data API Examples")
    print("=" * 50)
    
    # Initialize API client
    client = SolarDataAPIClient()
    
    # Example 1: Get current solar data
    print("\n1. Getting current solar data...")
    current_data = client.get_current_solar_data()
    if current_data:
        print(f"Current solar flux: {current_data['solar_data']['solar_flux']}")
        print(f"Current K-index: {current_data['solar_data']['k_index']}")
        print(f"Current A-index: {current_data['solar_data']['a_index']}")
    
    # Example 2: Submit single solar data entry
    print("\n2. Submitting single solar data entry...")
    result = client.submit_solar_data(
        solar_flux=155.5,
        k_index=3,
        a_index=12,
        sunspot_number=50,
        solar_wind_speed=480.0
    )
    if result:
        print(f"Submission result: {result['message']}")
    
    # Example 3: Submit batch solar data
    print("\n3. Submitting batch solar data...")
    batch_data = [
        {"solar_flux": 150.0, "k_index": 2, "a_index": 8},
        {"solar_flux": 152.5, "k_index": 3, "a_index": 10},
        {"solar_flux": 148.0, "k_index": 1, "a_index": 6}
    ]
    batch_result = client.submit_batch_solar_data(batch_data)
    if batch_result:
        print(f"Batch submission: {batch_result['summary']['successful_entries']} successful, {batch_result['summary']['failed_entries']} failed")
    
    # Example 4: Update solar data
    print("\n4. Updating solar data...")
    update_result = client.update_solar_data(
        solar_flux=160.0,
        k_index=4
    )
    if update_result:
        print(f"Update result: {update_result['message']}")
    
    # Example 5: Get solar history
    print("\n5. Getting solar history...")
    start_date = "2024-01-01T00:00:00Z"
    end_date = "2024-01-15T23:59:59Z"
    history = client.get_solar_history(start_date, end_date, 10)
    if history:
        print(f"Retrieved {len(history['solar_history']['data'])} historical data points")
    
    # Example 6: Get solar forecast
    print("\n6. Getting solar forecast...")
    forecast = client.get_solar_forecast(12)
    if forecast:
        print(f"Retrieved {len(forecast['forecast_data'])} forecast data points")
    
    print("\nSolar Data API examples completed!")

if __name__ == "__main__":
    main()
