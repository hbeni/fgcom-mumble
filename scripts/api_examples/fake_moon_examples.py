#!/usr/bin/env python3
"""
Fake Moon API Examples for FGcom-Mumble

This script demonstrates how to use the Fake Moon Placement API
to create, manage, and communicate with artificial moons in the
FGcom-Mumble simulation system.

Author: FGcom-mumble Development Team
Date: 2025
"""

import requests
import base64
from typing import Dict, List

class FakeMoonAPI:
    """Client for the Fake Moon Placement API"""
    
    def __init__(self, base_url: str = "http://localhost:8081/api/v1"):
        self.base_url = base_url
        self.session = requests.Session()
    
    def add_moon(self, name: str, orbital_params: Dict, physical_params: Dict, 
                 frequencies: Dict, **kwargs) -> Dict:
        """Add a new fake moon to the simulation"""
        data = {
            "name": name,
            "type": kwargs.get("type", "COMMUNICATION"),
            "mode": kwargs.get("mode", "REFLECTOR"),
            "orbital_parameters": orbital_params,
            "physical_parameters": physical_params,
            "frequencies": frequencies,
            "power": kwargs.get("power", 100),
            "antenna_gain": kwargs.get("antenna_gain", 10),
            "minimum_elevation": kwargs.get("minimum_elevation", 5),
            "maximum_range": kwargs.get("maximum_range", 500000),
            "doppler_compensation": kwargs.get("doppler_compensation", True),
            "atmospheric_effects": kwargs.get("atmospheric_effects", True),
            "signal_degradation": kwargs.get("signal_degradation", True)
        }
        
        response = self.session.post(f"{self.base_url}/moon/add", json=data)
        return response.json()
    
    def get_moon_position(self, moon_id: str) -> Dict:
        """Get current position and visibility data for a moon"""
        response = self.session.get(f"{self.base_url}/moon/position/{moon_id}")
        return response.json()
    
    def simulate_communication(self, moon_id: str, ground_station: Dict, 
                             audio_data: str, effects: Dict) -> Dict:
        """Simulate communication with a fake moon"""
        data = {
            "ground_station": ground_station,
            "audio_data": audio_data,
            "effects": effects
        }
        
        response = self.session.post(f"{self.base_url}/moon/simulate/{moon_id}", json=data)
        return response.json()
    
    def list_moons(self) -> Dict:
        """List all active fake moons"""
        response = self.session.get(f"{self.base_url}/moon/list")
        return response.json()
    
    def remove_moon(self, moon_id: str) -> Dict:
        """Remove a fake moon from the simulation"""
        response = self.session.delete(f"{self.base_url}/moon/remove/{moon_id}")
        return response.json()

def create_test_moon(api: FakeMoonAPI, name: str) -> str:
    """Create a test moon with realistic parameters"""
    print(f"Creating test moon: {name}")
    
    # Orbital parameters (similar to Earth's Moon)
    orbital_params = {
        "semi_major_axis": 384400,  # km (Earth-Moon distance)
        "eccentricity": 0.0549,    # Moon's eccentricity
        "inclination": 5.145,       # degrees
        "longitude_of_ascending_node": 0.0,
        "orbital_period": 27.3      # days (sidereal month)
    }
    
    # Physical parameters (similar to Earth's Moon)
    physical_params = {
        "radius": 1737.4,           # km (Moon radius)
        "mass": 7.342e22,           # kg (Moon mass)
        "albedo": 0.136             # Moon's albedo
    }
    
    # Communication frequencies (amateur radio bands)
    frequencies = {
        "uplink": 145.900,          # MHz (2m band)
        "downlink": 435.800         # MHz (70cm band)
    }
    
    # Additional parameters
    additional_params = {
        "power": 100,               # watts
        "antenna_gain": 10,         # dBi
        "minimum_elevation": 5,     # degrees
        "maximum_range": 500000,    # km
        "doppler_compensation": True,
        "atmospheric_effects": True,
        "signal_degradation": True
    }
    
    result = api.add_moon(name, orbital_params, physical_params, frequencies, **additional_params)
    
    if result["success"]:
        print(f"✅ Moon created successfully: {result['moon']['id']}")
        return result['moon']['id']
    else:
        print(f"❌ Failed to create moon: {result.get('error', 'Unknown error')}")
        return None

def demonstrate_moon_tracking(api: FakeMoonAPI, moon_id: str):
    """Demonstrate real-time moon tracking"""
    print(f"\n🌙 Tracking moon: {moon_id}")
    
    for i in range(5):  # Track for 5 updates
        position = api.get_moon_position(moon_id)
        
        if position["success"]:
            pos = position["position"]
            vis = position["visibility"]
            
            print(f"Update {i+1}:")
            print(f"  Position: ({pos['x']:.1f}, {pos['y']:.1f}, {pos['z']:.1f}) km")
            print(f"  Distance: {pos['distance']:.1f} km")
            print(f"  Visible: {'Yes' if vis['visible'] else 'No'}")
            print(f"  Elevation: {vis['elevation']:.1f}°")
            print(f"  Azimuth: {vis['azimuth']:.1f}°")
            print(f"  Doppler Shift: {position['doppler_shift']:.2f} Hz")
        else:
            print(f"❌ Failed to get position: {position.get('error', 'Unknown error')}")
        
        time.sleep(1)  # Wait 1 second between updates

def demonstrate_communication(api: FakeMoonAPI, moon_id: str):
    """Demonstrate communication simulation"""
    print(f"\n📡 Simulating communication with moon: {moon_id}")
    
    # Ground station location (New York City)
    ground_station = {
        "latitude": 40.7128,
        "longitude": -74.0060,
        "altitude": 0.0
    }
    
    # Simulate audio data (base64 encoded)
    audio_data = base64.b64encode(b"Test audio data for moon communication").decode('utf-8')
    
    # Communication effects
    effects = {
        "doppler_shift": True,
        "signal_degradation": True,
        "atmospheric_effects": True
    }
    
    result = api.simulate_communication(moon_id, ground_station, audio_data, effects)
    
    if result["success"]:
        comm = result["communication"]
        pos = result["position"]
        
        print(f"✅ Communication simulation successful:")
        print(f"  Signal Quality: {comm['signal_quality']:.2f}")
        print(f"  Signal Strength: {comm['signal_strength']:.1f} dBm")
        print(f"  Communication Quality: {comm['communication_quality']:.2f}")
        print(f"  Doppler Shift: {comm['doppler_shift']:.2f} Hz")
        print(f"  Uplink Frequency: {comm['uplink_frequency']:.3f} MHz")
        print(f"  Downlink Frequency: {comm['downlink_frequency']:.3f} MHz")
        print(f"  Moon Distance: {pos['distance']:.1f} km")
        print(f"  Elevation: {pos['elevation']:.1f}°")
    else:
        print(f"❌ Communication simulation failed: {result.get('error', 'Unknown error')}")

def demonstrate_moon_management(api: FakeMoonAPI):
    """Demonstrate moon management operations"""
    print("\n📋 Moon Management Operations")
    
    # List all moons
    moons = api.list_moons()
    if moons["success"]:
        print(f"Total moons: {moons['total_moons']}/{moons['max_moons']}")
        for moon in moons["moons"]:
            print(f"  - {moon['id']}: {moon['name']} ({moon['type']})")
    else:
        print(f"❌ Failed to list moons: {moons.get('error', 'Unknown error')}")

def create_multiple_moons(api: FakeMoonAPI):
    """Create multiple moons with different configurations"""
    print("\n🛰️ Creating multiple moons with different configurations")
    
    moon_configs = [
        {
            "name": "LOW-ORBIT-MOON",
            "orbital_params": {
                "semi_major_axis": 200000,  # Lower orbit
                "eccentricity": 0.0,
                "inclination": 0.0,
                "longitude_of_ascending_node": 0.0,
                "orbital_period": 10.0
            },
            "frequencies": {"uplink": 144.200, "downlink": 430.200}
        },
        {
            "name": "HIGH-ORBIT-MOON",
            "orbital_params": {
                "semi_major_axis": 500000,  # Higher orbit
                "eccentricity": 0.1,
                "inclination": 15.0,
                "longitude_of_ascending_node": 45.0,
                "orbital_period": 40.0
            },
            "frequencies": {"uplink": 146.000, "downlink": 436.000}
        },
        {
            "name": "POLAR-MOON",
            "orbital_params": {
                "semi_major_axis": 300000,
                "eccentricity": 0.05,
                "inclination": 90.0,  # Polar orbit
                "longitude_of_ascending_node": 0.0,
                "orbital_period": 20.0
            },
            "frequencies": {"uplink": 145.500, "downlink": 435.500}
        }
    ]
    
    created_moons = []
    
    for config in moon_configs:
        result = api.add_moon(
            config["name"],
            config["orbital_params"],
            {
                "radius": 1000.0,  # Smaller radius for test moons
                "mass": 1.0e20,    # Smaller mass
                "albedo": 0.1
            },
            config["frequencies"],
            power=50,
            antenna_gain=5
        )
        
        if result["success"]:
            created_moons.append(result["moon"]["id"])
            print(f"✅ Created {config['name']}: {result['moon']['id']}")
        else:
            print(f"❌ Failed to create {config['name']}: {result.get('error', 'Unknown error')}")
    
    return created_moons

def demonstrate_advanced_features(api: FakeMoonAPI, moon_id: str):
    """Demonstrate advanced API features"""
    print(f"\n🔬 Advanced Features for moon: {moon_id}")
    
    # Get detailed position information
    position = api.get_moon_position(moon_id)
    if position["success"]:
        pos = position["position"]
        vis = position["visibility"]
        
        print(f"Detailed Position Analysis:")
        print(f"  Cartesian Coordinates: ({pos['x']:.1f}, {pos['y']:.1f}, {pos['z']:.1f}) km")
        print(f"  Distance from Earth: {pos['distance']:.1f} km")
        print(f"  True Anomaly: {pos['true_anomaly']:.1f}°")
        print(f"  Visibility Status: {'Visible' if vis['visible'] else 'Not Visible'}")
        print(f"  Elevation Angle: {vis['elevation']:.1f}°")
        print(f"  Azimuth Angle: {vis['azimuth']:.1f}°")
        print(f"  Doppler Shift: {position['doppler_shift']:.2f} Hz")
        
        # Calculate orbital velocity (simplified)
        velocity = abs(position['doppler_shift']) * 299792.458 / 145.900  # km/s
        print(f"  Estimated Orbital Velocity: {velocity:.1f} km/s")

def cleanup_moons(api: FakeMoonAPI, moon_ids: List[str]):
    """Clean up created moons"""
    print(f"\n🧹 Cleaning up {len(moon_ids)} moons")
    
    for moon_id in moon_ids:
        result = api.remove_moon(moon_id)
        if result["success"]:
            print(f"✅ Removed moon: {moon_id}")
        else:
            print(f"❌ Failed to remove moon {moon_id}: {result.get('error', 'Unknown error')}")

def main():
    """Main demonstration function"""
    print("🌙 Fake Moon API Demonstration")
    print("=" * 50)
    
    # Initialize API client
    api = FakeMoonAPI()
    
    try:
        # Test API connectivity
        print("Testing API connectivity...")
        moons = api.list_moons()
        if moons["success"]:
            print("✅ API is accessible")
        else:
            print("❌ API is not accessible")
            return
        
        # Create a test moon
        moon_id = create_test_moon(api, "DEMO-MOON-1")
        if not moon_id:
            return
        
        # Demonstrate moon tracking
        demonstrate_moon_tracking(api, moon_id)
        
        # Demonstrate communication
        demonstrate_communication(api, moon_id)
        
        # Demonstrate advanced features
        demonstrate_advanced_features(api, moon_id)
        
        # Create multiple moons
        additional_moons = create_multiple_moons(api)
        
        # Demonstrate moon management
        demonstrate_moon_management(api)
        
        # Clean up
        all_moons = [moon_id] + additional_moons
        cleanup_moons(api, all_moons)
        
        print("\n✅ Demonstration completed successfully!")
        
    except requests.exceptions.ConnectionError:
        print("❌ Could not connect to the Fake Moon API server.")
        print("Make sure the server is running on http://localhost:8081")
    except Exception as e:
        print(f"❌ An error occurred: {e}")

if __name__ == "__main__":
    main()

