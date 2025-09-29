# Lightning Data Integration Documentation

## Overview

The FGCom-mumble Lightning Data Integration system provides real-time atmospheric noise simulation from lightning strikes. This system fetches lightning data from multiple sources and uses it to simulate realistic atmospheric noise conditions that affect radio communication.

## System Architecture

### Core Components

- **LightningDataProvider**: Main lightning data management system
- **AtmosphericNoiseModeler**: Lightning-based noise modeling
- **RealTimeLightningTracker**: Real-time lightning strike tracking
- **NoiseSimulationEngine**: Atmospheric noise simulation
- **PropagationEffects**: Lightning effects on radio propagation
- **DataCaching**: Lightning data caching and storage

## Lightning Data Sources

### Real-Time Lightning Data

#### Blitzortung Network
- **API Endpoint**: `https://data.blitzortung.org/`
- **Update Frequency**: Real-time (every few seconds)
- **Coverage**: Global
- **Data Format**: JSON
- **Parameters**: Latitude, longitude, timestamp, intensity

#### National Lightning Detection Network (NLDN)
- **API Endpoint**: `https://www.nldn.com/api/`
- **Update Frequency**: Every 5 minutes
- **Coverage**: United States and Canada
- **Data Format**: XML/JSON
- **Parameters**: Strike location, time, intensity, polarity

#### Global Lightning Detection Network (GLD360)
- **API Endpoint**: `https://www.vaisala.com/en/products/lightning-detection`
- **Update Frequency**: Every 10 minutes
- **Coverage**: Global
- **Data Format**: Binary/JSON
- **Parameters**: Strike location, time, intensity, type

### Lightning Data Parameters

#### Strike Information
- **Latitude/Longitude**: Strike location coordinates
- **Timestamp**: Time of strike occurrence
- **Intensity**: Peak current in kA
- **Polarity**: Positive or negative strike
- **Type**: Cloud-to-ground, cloud-to-cloud, intra-cloud
- **Distance**: Distance from receiver location

#### Atmospheric Conditions
- **Temperature**: Atmospheric temperature at strike location
- **Humidity**: Relative humidity
- **Pressure**: Atmospheric pressure
- **Wind Speed/Direction**: Wind conditions
- **Precipitation**: Rain intensity

## Configuration

### Lightning Data Configuration

```ini
# configs/lightning_data.conf
[lightning_data]
# Enable/disable lightning data integration
enabled = true

# Data sources
enable_blitzortung = true
enable_nldn = true
enable_gld360 = false

# Update intervals
blitzortung_update_interval_seconds = 30
nldn_update_interval_seconds = 300
gld360_update_interval_seconds = 600

# Data filtering
min_strike_intensity_ka = 5.0
max_distance_km = 1000.0
min_strike_age_minutes = 0
max_strike_age_hours = 24

# Noise modeling
enable_atmospheric_noise = true
noise_model = "lightning_based"
noise_update_interval_seconds = 60
noise_smoothing_factor = 0.9

# Caching
enable_data_caching = true
cache_duration_hours = 24
max_cache_size_mb = 1000
cache_cleanup_interval_hours = 6

# API endpoints
blitzortung_api_url = https://data.blitzortung.org/
nldn_api_url = https://www.nldn.com/api/
gld360_api_url = https://www.vaisala.com/api/

# API keys (if required)
blitzortung_api_key = 
nldn_api_key = 
gld360_api_key = 
```

## Data Structures

### Lightning Strike Structure

```cpp
struct fgcom_lightning_strike {
    // Strike location
    double latitude;
    double longitude;
    float altitude_m;
    
    // Strike parameters
    std::chrono::system_clock::time_point timestamp;
    float intensity_ka;
    std::string polarity; // "positive", "negative"
    std::string type; // "cloud_to_ground", "cloud_to_cloud", "intra_cloud"
    
    // Atmospheric conditions
    float temperature_celsius;
    float humidity_percent;
    float pressure_hpa;
    float wind_speed_ms;
    float wind_direction_deg;
    float precipitation_mmh;
    
    // Calculated parameters
    float distance_km;
    float bearing_deg;
    float noise_impact_db;
    float propagation_effect_db;
    
    // Data quality
    bool data_valid;
    std::string data_source;
    float confidence_score;
};
```

### Atmospheric Noise Status

```cpp
struct fgcom_atmospheric_noise_status {
    // Current noise conditions
    float noise_level_db;
    float noise_floor_db;
    float signal_to_noise_ratio_db;
    float noise_quality_factor;
    
    // Lightning activity
    int active_strikes_count;
    float average_strike_intensity_ka;
    float nearest_strike_distance_km;
    float lightning_activity_index;
    
    // Noise frequency characteristics
    std::map<float, float> noise_spectrum; // Frequency -> Noise level
    float dominant_noise_frequency_hz;
    float noise_bandwidth_hz;
    
    // Atmospheric conditions
    float temperature_celsius;
    float humidity_percent;
    float pressure_hpa;
    float wind_speed_ms;
    float precipitation_mmh;
    
    // Timestamps
    std::chrono::system_clock::time_point timestamp;
    std::chrono::system_clock::time_point last_update;
    
    // Status flags
    bool lightning_data_enabled;
    bool atmospheric_noise_enabled;
    bool real_time_tracking_enabled;
};
```

## API Endpoints

### Lightning Data Status

#### Get Lightning Data Status
```http
GET /api/v1/lightning-data/status
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "lightning_status": {
    "active_strikes_count": 15,
    "average_strike_intensity_ka": 25.5,
    "nearest_strike_distance_km": 12.3,
    "lightning_activity_index": 0.75,
    "data_sources_active": ["blitzortung", "nldn"],
    "last_update": "2024-01-15T10:30:00Z",
    "coverage_area_km": 1000.0,
    "data_quality_score": 0.92
  }
}
```

#### Get Atmospheric Noise Status
```http
GET /api/v1/lightning-data/atmospheric-noise
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "atmospheric_noise_status": {
    "noise_level_db": -85.2,
    "noise_floor_db": -95.0,
    "signal_to_noise_ratio_db": 9.8,
    "noise_quality_factor": 0.85,
    "active_strikes_count": 15,
    "average_strike_intensity_ka": 25.5,
    "nearest_strike_distance_km": 12.3,
    "lightning_activity_index": 0.75,
    "noise_spectrum": {
      "1000000": -90.0,
      "10000000": -85.0,
      "100000000": -80.0,
      "1000000000": -75.0
    },
    "dominant_noise_frequency_hz": 1000000.0,
    "noise_bandwidth_hz": 1000000.0,
    "temperature_celsius": 20.0,
    "humidity_percent": 50.0,
    "pressure_hpa": 1013.25,
    "wind_speed_ms": 5.0,
    "precipitation_mmh": 0.0,
    "lightning_data_enabled": true,
    "atmospheric_noise_enabled": true,
    "real_time_tracking_enabled": true,
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

### Lightning Strike Data

#### Get Recent Lightning Strikes
```http
GET /api/v1/lightning-data/strikes
Authorization: Bearer your_jwt_token_here
```

**Query Parameters:**
- `radius_km` (optional): Search radius in kilometers (default: 100)
- `max_age_hours` (optional): Maximum age of strikes in hours (default: 24)
- `min_intensity_ka` (optional): Minimum strike intensity in kA (default: 5.0)

**Response:**
```json
{
  "success": true,
  "strikes": [
    {
      "latitude": 40.7128,
      "longitude": -74.0060,
      "altitude_m": 1000.0,
      "timestamp": "2024-01-15T10:29:45Z",
      "intensity_ka": 25.5,
      "polarity": "negative",
      "type": "cloud_to_ground",
      "distance_km": 12.3,
      "bearing_deg": 45.0,
      "noise_impact_db": 5.2,
      "propagation_effect_db": 2.1,
      "data_valid": true,
      "data_source": "blitzortung",
      "confidence_score": 0.95
    }
  ],
  "total_strikes": 1,
  "search_radius_km": 100.0,
  "max_age_hours": 24.0
}
```

#### Get Lightning Strike by ID
```http
GET /api/v1/lightning-data/strikes/{strike_id}
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "strike": {
    "strike_id": "strike_001",
    "latitude": 40.7128,
    "longitude": -74.0060,
    "altitude_m": 1000.0,
    "timestamp": "2024-01-15T10:29:45Z",
    "intensity_ka": 25.5,
    "polarity": "negative",
    "type": "cloud_to_ground",
    "temperature_celsius": 20.0,
    "humidity_percent": 50.0,
    "pressure_hpa": 1013.25,
    "wind_speed_ms": 5.0,
    "wind_direction_deg": 180.0,
    "precipitation_mmh": 0.0,
    "distance_km": 12.3,
    "bearing_deg": 45.0,
    "noise_impact_db": 5.2,
    "propagation_effect_db": 2.1,
    "data_valid": true,
    "data_source": "blitzortung",
    "confidence_score": 0.95
  }
}
```

### Atmospheric Noise Control

#### Set Atmospheric Noise Parameters
```http
POST /api/v1/lightning-data/atmospheric-noise
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "enable_atmospheric_noise": true,
  "noise_model": "lightning_based",
  "noise_update_interval_seconds": 60,
  "noise_smoothing_factor": 0.9,
  "min_strike_intensity_ka": 5.0,
  "max_distance_km": 1000.0,
  "noise_amplification_db": 0.0
}
```

**Response:**
```json
{
  "success": true,
  "message": "Atmospheric noise parameters configured",
  "atmospheric_noise_enabled": true,
  "noise_model": "lightning_based",
  "estimated_noise_impact_db": 5.2,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## C++ API Usage

### Basic Lightning Data Access

```cpp
#include "lightning_data.h"

// Get lightning data provider instance
auto& lightning_provider = FGCom_LightningDataProvider::getInstance();

// Get current lightning status
fgcom_atmospheric_noise_status status = lightning_provider.getAtmosphericNoiseStatus();
std::cout << "Active strikes: " << status.active_strikes_count << std::endl;
std::cout << "Noise level: " << status.noise_level_db << " dB" << std::endl;
```

### Get Recent Lightning Strikes

```cpp
// Get recent lightning strikes within 100km
std::vector<fgcom_lightning_strike> strikes = lightning_provider.getRecentStrikes(100.0, 24.0);

for (const auto& strike : strikes) {
    std::cout << "Strike at " << strike.latitude << ", " << strike.longitude << std::endl;
    std::cout << "Intensity: " << strike.intensity_ka << " kA" << std::endl;
    std::cout << "Distance: " << strike.distance_km << " km" << std::endl;
    std::cout << "Noise impact: " << strike.noise_impact_db << " dB" << std::endl;
}
```

### Calculate Atmospheric Noise

```cpp
// Calculate atmospheric noise from lightning strikes
float noise_level = lightning_provider.calculateAtmosphericNoise(strikes);
std::cout << "Calculated noise level: " << noise_level << " dB" << std::endl;

// Get noise spectrum
std::map<float, float> noise_spectrum = lightning_provider.getNoiseSpectrum();
for (const auto& freq_noise : noise_spectrum) {
    std::cout << "Frequency: " << freq_noise.first << " Hz, Noise: " << freq_noise.second << " dB" << std::endl;
}
```

### Real-time Lightning Tracking

```cpp
// Enable real-time lightning tracking
lightning_provider.enableRealTimeTracking(true);

// Set up lightning strike callback
lightning_provider.setLightningStrikeCallback([](const fgcom_lightning_strike& strike) {
    std::cout << "New lightning strike detected!" << std::endl;
    std::cout << "Location: " << strike.latitude << ", " << strike.longitude << std::endl;
    std::cout << "Intensity: " << strike.intensity_ka << " kA" << std::endl;
    std::cout << "Distance: " << strike.distance_km << " km" << std::endl;
});
```

## Advanced Features

### Atmospheric Noise Modeling

```cpp
class AtmosphericNoiseModeler {
private:
    float base_noise_floor_db;
    float lightning_noise_factor;
    float atmospheric_noise_factor;
    
public:
    float calculateNoiseLevel(const std::vector<fgcom_lightning_strike>& strikes,
                            float frequency_hz,
                            float distance_km) {
        float noise_level = base_noise_floor_db;
        
        // Add lightning noise contribution
        for (const auto& strike : strikes) {
            float strike_noise = calculateStrikeNoiseContribution(strike, frequency_hz, distance_km);
            noise_level += strike_noise;
        }
        
        // Add atmospheric noise
        float atmospheric_noise = calculateAtmosphericNoise(frequency_hz, distance_km);
        noise_level += atmospheric_noise;
        
        return noise_level;
    }
    
private:
    float calculateStrikeNoiseContribution(const fgcom_lightning_strike& strike,
                                         float frequency_hz,
                                         float distance_km) {
        // Calculate noise contribution based on strike intensity and distance
        float intensity_factor = log10(strike.intensity_ka) * 10.0f;
        float distance_factor = -20.0f * log10(strike.distance_km);
        float frequency_factor = -10.0f * log10(frequency_hz / 1000000.0f);
        
        return intensity_factor + distance_factor + frequency_factor;
    }
    
    float calculateAtmosphericNoise(float frequency_hz, float distance_km) {
        // Calculate atmospheric noise based on frequency and distance
        float frequency_factor = -10.0f * log10(frequency_hz / 1000000.0f);
        float distance_factor = -20.0f * log10(distance_km);
        
        return frequency_factor + distance_factor;
    }
};
```

### Lightning Strike Detection

```cpp
class LightningStrikeDetector {
private:
    std::vector<fgcom_lightning_strike> recent_strikes;
    std::chrono::system_clock::time_point last_detection;
    
public:
    bool detectNewStrike(const fgcom_lightning_strike& strike) {
        // Check if strike is new (not in recent strikes)
        for (const auto& recent_strike : recent_strikes) {
            if (strikesAreSimilar(strike, recent_strike)) {
                return false; // Strike already detected
            }
        }
        
        // Add to recent strikes
        recent_strikes.push_back(strike);
        
        // Limit recent strikes size
        if (recent_strikes.size() > 100) {
            recent_strikes.erase(recent_strikes.begin());
        }
        
        return true; // New strike detected
    }
    
private:
    bool strikesAreSimilar(const fgcom_lightning_strike& strike1,
                          const fgcom_lightning_strike& strike2) {
        float distance = calculateDistance(strike1.latitude, strike1.longitude,
                                          strike2.latitude, strike2.longitude);
        auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(
            strike1.timestamp - strike2.timestamp).count();
        
        return distance < 1.0f && abs(time_diff) < 60; // Within 1km and 1 minute
    }
};
```

### Noise Spectrum Analysis

```cpp
class NoiseSpectrumAnalyzer {
private:
    std::map<float, float> noise_spectrum;
    float frequency_resolution_hz;
    
public:
    void analyzeNoiseSpectrum(const std::vector<fgcom_lightning_strike>& strikes) {
        noise_spectrum.clear();
        
        // Analyze noise at different frequencies
        for (float freq = 100000.0f; freq <= 1000000000.0f; freq *= 10.0f) {
            float noise_level = calculateNoiseAtFrequency(strikes, freq);
            noise_spectrum[freq] = noise_level;
        }
    }
    
    float getDominantNoiseFrequency() const {
        float max_noise = -1000.0f;
        float dominant_freq = 0.0f;
        
        for (const auto& freq_noise : noise_spectrum) {
            if (freq_noise.second > max_noise) {
                max_noise = freq_noise.second;
                dominant_freq = freq_noise.first;
            }
        }
        
        return dominant_freq;
    }
    
    float getNoiseBandwidth() const {
        float max_noise = -1000.0f;
        float min_noise = 1000.0f;
        
        for (const auto& freq_noise : noise_spectrum) {
            max_noise = std::max(max_noise, freq_noise.second);
            min_noise = std::min(min_noise, freq_noise.second);
        }
        
        return max_noise - min_noise;
    }
    
private:
    float calculateNoiseAtFrequency(const std::vector<fgcom_lightning_strike>& strikes,
                                   float frequency_hz) {
        float total_noise = 0.0f;
        
        for (const auto& strike : strikes) {
            float strike_noise = calculateStrikeNoiseAtFrequency(strike, frequency_hz);
            total_noise += strike_noise;
        }
        
        return total_noise;
    }
    
    float calculateStrikeNoiseAtFrequency(const fgcom_lightning_strike& strike,
                                         float frequency_hz) {
        // Calculate noise contribution at specific frequency
        float intensity_factor = log10(strike.intensity_ka) * 10.0f;
        float distance_factor = -20.0f * log10(strike.distance_km);
        float frequency_factor = -10.0f * log10(frequency_hz / 1000000.0f);
        
        return intensity_factor + distance_factor + frequency_factor;
    }
};
```

## Performance Optimization

### Data Caching

```cpp
class LightningDataCache {
private:
    std::map<std::string, std::vector<fgcom_lightning_strike>> cache;
    std::mutex cache_mutex;
    std::time_t cache_ttl;
    
public:
    bool getCachedStrikes(const std::string& key, std::vector<fgcom_lightning_strike>& strikes) {
        std::lock_guard<std::mutex> lock(cache_mutex);
        
        auto it = cache.find(key);
        if (it != cache.end()) {
            // Check if data is still valid
            if (std::time(nullptr) - it->second[0].timestamp.time_since_epoch().count() < cache_ttl) {
                strikes = it->second;
                return true;
            } else {
                // Remove expired data
                cache.erase(it);
            }
        }
        
        return false;
    }
    
    void setCachedStrikes(const std::string& key, const std::vector<fgcom_lightning_strike>& strikes) {
        std::lock_guard<std::mutex> lock(cache_mutex);
        cache[key] = strikes;
    }
};
```

### Real-time Processing

```cpp
class RealTimeLightningProcessor {
private:
    std::thread processing_thread;
    std::atomic<bool> processing_active;
    std::queue<fgcom_lightning_strike> strike_queue;
    std::mutex queue_mutex;
    
public:
    void startProcessing() {
        processing_active = true;
        processing_thread = std::thread(&RealTimeLightningProcessor::processingLoop, this);
    }
    
    void stopProcessing() {
        processing_active = false;
        if (processing_thread.joinable()) {
            processing_thread.join();
        }
    }
    
    void addStrike(const fgcom_lightning_strike& strike) {
        std::lock_guard<std::mutex> lock(queue_mutex);
        strike_queue.push(strike);
    }
    
private:
    void processingLoop() {
        while (processing_active) {
            std::vector<fgcom_lightning_strike> strikes_to_process;
            
            // Get strikes from queue
            {
                std::lock_guard<std::mutex> lock(queue_mutex);
                while (!strike_queue.empty()) {
                    strikes_to_process.push_back(strike_queue.front());
                    strike_queue.pop();
                }
            }
            
            // Process strikes
            for (const auto& strike : strikes_to_process) {
                processStrike(strike);
            }
            
            // Sleep for processing interval
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
    void processStrike(const fgcom_lightning_strike& strike) {
        // Process lightning strike data
        // Update noise models
        // Notify listeners
    }
};
```

## Error Handling

### Common Error Responses

```json
{
  "success": false,
  "error": {
    "code": "LIGHTNING_DATA_UNAVAILABLE",
    "message": "Lightning data source is currently unavailable",
    "details": {
      "data_source": "blitzortung",
      "last_successful_update": "2024-01-15T10:25:00Z",
      "retry_after_seconds": 300
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Error Codes

- **LIGHTNING_DATA_UNAVAILABLE**: Lightning data source unavailable
- **INVALID_STRIKE_DATA**: Invalid lightning strike data
- **NOISE_CALCULATION_FAILED**: Atmospheric noise calculation failed
- **CACHE_OPERATION_FAILED**: Data cache operation failed
- **REAL_TIME_TRACKING_FAILED**: Real-time tracking failed
- **API_RATE_LIMIT_EXCEEDED**: API rate limit exceeded

## WebSocket Real-time Updates

### Lightning Strike Updates

```json
{
  "type": "lightning_strike_update",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "strike_id": "strike_001",
    "latitude": 40.7128,
    "longitude": -74.0060,
    "intensity_ka": 25.5,
    "distance_km": 12.3,
    "noise_impact_db": 5.2
  }
}
```

### Atmospheric Noise Updates

```json
{
  "type": "atmospheric_noise_update",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "noise_level_db": -85.2,
    "noise_floor_db": -95.0,
    "signal_to_noise_ratio_db": 9.8,
    "active_strikes_count": 15,
    "lightning_activity_index": 0.75
  }
}
```

## Examples

### Python Client Example

```python
import requests
import json
import time

# Authentication
auth_response = requests.post('http://localhost:8080/auth/login', json={
    'username': 'pilot123',
    'password': 'secure_password',
    'client_type': 'flight_simulator'
})

token = auth_response.json()['token']
headers = {'Authorization': f'Bearer {token}'}

# Get lightning data status
status_response = requests.get('http://localhost:8080/api/v1/lightning-data/status', headers=headers)
lightning_status = status_response.json()['lightning_status']
print(f"Active strikes: {lightning_status['active_strikes_count']}")
print(f"Lightning activity index: {lightning_status['lightning_activity_index']}")

# Get recent lightning strikes
strikes_response = requests.get('http://localhost:8080/api/v1/lightning-data/strikes?radius_km=100&max_age_hours=24', headers=headers)
strikes = strikes_response.json()['strikes']
for strike in strikes:
    print(f"Strike at {strike['latitude']}, {strike['longitude']} - Intensity: {strike['intensity_ka']} kA")
```

### JavaScript WebSocket Example

```javascript
const ws = new WebSocket('ws://localhost:8080/ws');

ws.onopen = function() {
    console.log('Connected to Lightning Data WebSocket');
    
    // Subscribe to lightning updates
    ws.send(JSON.stringify({
        type: 'subscribe',
        channel: 'lightning_data',
        vehicle_id: 'player_001'
    }));
};

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    
    switch(data.type) {
        case 'lightning_strike_update':
            console.log('Lightning strike detected:', data.data);
            break;
        case 'atmospheric_noise_update':
            console.log('Atmospheric noise update:', data.data);
            break;
    }
};
```

This comprehensive Lightning Data Integration system provides real-time atmospheric noise simulation and lightning strike tracking for enhanced radio communication simulation in FGCom-mumble.
