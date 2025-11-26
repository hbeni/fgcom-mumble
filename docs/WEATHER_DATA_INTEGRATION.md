# Weather Data Integration Documentation

## Overview

The FGCom-mumble Weather Data Integration system provides atmospheric condition effects on radio propagation. This system fetches weather data from multiple sources and uses it to simulate realistic atmospheric effects that affect radio communication across different frequency bands.

## System Architecture

### Core Components

- **WeatherDataProvider**: Main weather data management system
- **AtmosphericModeler**: Atmospheric condition modeling
- **PropagationEffects**: Weather effects on radio propagation
- **FrequencyAnalyzer**: Frequency-specific weather effects
- **DataCaching**: Weather data caching and storage
- **RealTimeUpdates**: Real-time weather data updates

## Weather Data Sources

### Real-Time Weather Data

#### OpenWeatherMap API
- **API Endpoint**: `https://api.openweathermap.org/data/2.5/`
- **Update Frequency**: Every 10 minutes
- **Coverage**: Global
- **Data Format**: JSON
- **Parameters**: Temperature, humidity, pressure, wind, precipitation

#### National Weather Service (NWS)
- **API Endpoint**: `https://api.weather.gov/`
- **Update Frequency**: Every 15 minutes
- **Coverage**: United States
- **Data Format**: JSON
- **Parameters**: Detailed weather conditions, forecasts

#### Weather Underground
- **API Endpoint**: `https://api.wunderground.com/api/`
- **Update Frequency**: Every 5 minutes
- **Coverage**: Global
- **Data Format**: JSON
- **Parameters**: Comprehensive weather data

### Weather Parameters

#### Atmospheric Conditions
- **Temperature**: Air temperature in Celsius
- **Humidity**: Relative humidity percentage
- **Pressure**: Atmospheric pressure in hPa
- **Wind Speed**: Wind speed in m/s
- **Wind Direction**: Wind direction in degrees
- **Precipitation**: Rain/snow intensity in mm/h

#### Advanced Weather Data
- **Dew Point**: Dew point temperature
- **Visibility**: Atmospheric visibility in km
- **Cloud Cover**: Cloud coverage percentage
- **UV Index**: Ultraviolet radiation index
- **Air Quality**: Air quality index
- **Pollen Count**: Pollen concentration

## Frequency Band Effects

### VLF (3-30 kHz)
- **Atmospheric Effects**: Minimal
- **Weather Impact**: Low
- **Primary Factors**: Ground conductivity, soil moisture
- **Propagation Mode**: Ground wave

### LF (30-300 kHz)
- **Atmospheric Effects**: Moderate
- **Weather Impact**: Low
- **Primary Factors**: Ground conductivity, terrain
- **Propagation Mode**: Ground wave

### MF (300 kHz - 3 MHz)
- **Atmospheric Effects**: Moderate
- **Weather Impact**: Low
- **Primary Factors**: Ground conductivity, terrain
- **Propagation Mode**: Ground wave, sky wave

### HF (3-30 MHz)
- **Atmospheric Effects**: High
- **Weather Impact**: High
- **Primary Factors**: Ionospheric conditions, solar activity
- **Propagation Mode**: Sky wave, ground wave

### VHF (30-300 MHz)
- **Atmospheric Effects**: High
- **Weather Impact**: High
- **Primary Factors**: Tropospheric conditions, ducting
- **Propagation Mode**: Line of sight, tropospheric scatter

### UHF (300 MHz - 3 GHz)
- **Atmospheric Effects**: Moderate
- **Weather Impact**: Moderate
- **Primary Factors**: Tropospheric conditions, precipitation
- **Propagation Mode**: Line of sight, tropospheric scatter

### SHF (3-30 GHz)
- **Atmospheric Effects**: High
- **Weather Impact**: High
- **Primary Factors**: Precipitation, atmospheric absorption
- **Propagation Mode**: Line of sight

### EHF (30-300 GHz)
- **Atmospheric Effects**: Very High
- **Weather Impact**: Very High
- **Primary Factors**: Atmospheric absorption, precipitation
- **Propagation Mode**: Line of sight

## Configuration

### Weather Data Configuration

```ini
# configs/weather_data.conf
[weather_data]
# Enable/disable weather data integration
enabled = true

# Data sources
enable_openweathermap = true
enable_nws = true
enable_weather_underground = false

# Update intervals
openweathermap_update_interval_seconds = 600
nws_update_interval_seconds = 900
weather_underground_update_interval_seconds = 300

# Data filtering
min_temperature_celsius = -50.0
max_temperature_celsius = 60.0
min_humidity_percent = 0.0
max_humidity_percent = 100.0
min_pressure_hpa = 800.0
max_pressure_hpa = 1100.0

# Propagation effects
enable_tropospheric_ducting = true
enable_precipitation_effects = true
enable_temperature_effects = true
enable_humidity_effects = true
enable_pressure_effects = true

# Frequency analysis
enable_frequency_analysis = true
frequency_analysis_interval_seconds = 60
frequency_bands = ["VLF", "LF", "MF", "HF", "VHF", "UHF", "SHF", "EHF"]

# Caching
enable_data_caching = true
cache_duration_hours = 24
max_cache_size_mb = 1000
cache_cleanup_interval_hours = 6

# API endpoints
openweathermap_api_url = https://api.openweathermap.org/data/2.5/
nws_api_url = https://api.weather.gov/
weather_underground_api_url = https://api.wunderground.com/api/

# API keys (if required)
openweathermap_api_key = 
nws_api_key = 
weather_underground_api_key = 
```

## Data Structures

### Weather Conditions Structure

```cpp
struct fgcom_weather_conditions {
    // Basic weather parameters
    float temperature_celsius;
    float humidity_percent;
    float pressure_hpa;
    float wind_speed_ms;
    float wind_direction_deg;
    float precipitation_mmh;
    
    // Advanced weather parameters
    float dew_point_celsius;
    float visibility_km;
    float cloud_cover_percent;
    float uv_index;
    float air_quality_index;
    float pollen_count;
    
    // Atmospheric effects
    float atmospheric_refraction;
    float ducting_conditions;
    float absorption_loss_db;
    float scattering_loss_db;
    
    // Frequency-specific effects
    std::map<std::string, float> frequency_effects; // Frequency band -> Effect
    std::map<std::string, float> propagation_effects; // Propagation mode -> Effect
    
    // Location and time
    double latitude;
    double longitude;
    float altitude_m;
    std::chrono::system_clock::time_point timestamp;
    
    // Data quality
    bool data_valid;
    std::string data_source;
    float confidence_score;
};
```

### Weather Effects Status

```cpp
struct fgcom_weather_effects_status {
    // Current weather conditions
    fgcom_weather_conditions current_weather;
    
    // Propagation effects
    float tropospheric_ducting_factor;
    float precipitation_attenuation_db;
    float temperature_effects_db;
    float humidity_effects_db;
    float pressure_effects_db;
    
    // Frequency-specific effects
    std::map<std::string, float> band_effects; // Frequency band -> Effect
    std::map<std::string, float> mode_effects; // Propagation mode -> Effect
    
    // Overall impact
    float total_weather_impact_db;
    float weather_quality_factor;
    std::string dominant_weather_effect;
    
    // Timestamps
    std::chrono::system_clock::time_point timestamp;
    std::chrono::system_clock::time_point last_update;
    
    // Status flags
    bool weather_data_enabled;
    bool propagation_effects_enabled;
    bool frequency_analysis_enabled;
    bool real_time_updates_enabled;
};
```

## API Endpoints

### Weather Data Status

#### Get Weather Data Status
```http
GET /api/v1/weather-data/status
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "weather_status": {
    "current_weather": {
      "temperature_celsius": 20.0,
      "humidity_percent": 50.0,
      "pressure_hpa": 1013.25,
      "wind_speed_ms": 5.0,
      "wind_direction_deg": 180.0,
      "precipitation_mmh": 0.0,
      "dew_point_celsius": 10.0,
      "visibility_km": 10.0,
      "cloud_cover_percent": 30.0,
      "uv_index": 5.0,
      "air_quality_index": 50.0,
      "pollen_count": 25.0
    },
    "atmospheric_effects": {
      "atmospheric_refraction": 1.0,
      "ducting_conditions": 0.5,
      "absorption_loss_db": 2.1,
      "scattering_loss_db": 1.5
    },
    "frequency_effects": {
      "VLF": 0.1,
      "LF": 0.2,
      "MF": 0.5,
      "HF": 1.2,
      "VHF": 2.1,
      "UHF": 3.5,
      "SHF": 5.2,
      "EHF": 8.1
    },
    "propagation_effects": {
      "ground_wave": 0.5,
      "sky_wave": 1.2,
      "line_of_sight": 2.1,
      "tropospheric_scatter": 3.5
    },
    "total_weather_impact_db": 2.1,
    "weather_quality_factor": 0.85,
    "dominant_weather_effect": "humidity",
    "data_source": "openweathermap",
    "confidence_score": 0.92,
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

#### Get Weather Effects by Frequency
```http
GET /api/v1/weather-data/frequency-effects
Authorization: Bearer your_jwt_token_here
```

**Query Parameters:**
- `frequency_band` (optional): Specific frequency band (VLF, LF, MF, HF, VHF, UHF, SHF, EHF)
- `frequency_hz` (optional): Specific frequency in Hz

**Response:**
```json
{
  "success": true,
  "frequency_effects": {
    "frequency_band": "VHF",
    "frequency_hz": 100000000.0,
    "weather_effects": {
      "temperature_effects_db": 0.5,
      "humidity_effects_db": 1.2,
      "pressure_effects_db": 0.3,
      "precipitation_effects_db": 0.0,
      "wind_effects_db": 0.2,
      "total_effects_db": 2.2
    },
    "propagation_effects": {
      "line_of_sight": 2.2,
      "tropospheric_scatter": 3.5,
      "ducting": 0.8
    },
    "atmospheric_conditions": {
      "refraction_index": 1.0003,
      "ducting_height_m": 1000.0,
      "absorption_coefficient": 0.001
    },
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

### Weather Data Control

#### Set Weather Data Parameters
```http
POST /api/v1/weather-data/configure
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "enable_weather_data": true,
  "enable_propagation_effects": true,
  "enable_frequency_analysis": true,
  "update_interval_seconds": 600,
  "data_sources": ["openweathermap", "nws"],
  "frequency_bands": ["HF", "VHF", "UHF"],
  "propagation_modes": ["line_of_sight", "tropospheric_scatter", "ducting"]
}
```

**Response:**
```json
{
  "success": true,
  "message": "Weather data parameters configured",
  "weather_data_enabled": true,
  "propagation_effects_enabled": true,
  "frequency_analysis_enabled": true,
  "estimated_impact_db": 2.1,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## C++ API Usage

### Basic Weather Data Access

```cpp
#include "weather_data.h"

// Get weather data provider instance
auto& weather_provider = FGCom_WeatherDataProvider::getInstance();

// Get current weather conditions
fgcom_weather_conditions weather = weather_provider.getCurrentWeather();
std::cout << "Temperature: " << weather.temperature_celsius << "°C" << std::endl;
std::cout << "Humidity: " << weather.humidity_percent << "%" << std::endl;
std::cout << "Pressure: " << weather.pressure_hpa << " hPa" << std::endl;
```

### Calculate Weather Effects

```cpp
// Calculate weather effects on propagation
float frequency_hz = 100000000.0f; // 100 MHz
float distance_km = 50.0f;

float weather_effects = weather_provider.calculateWeatherEffects(frequency_hz, distance_km);
std::cout << "Weather effects: " << weather_effects << " dB" << std::endl;

// Get frequency-specific effects
auto frequency_effects = weather_provider.getFrequencyEffects();
for (const auto& effect : frequency_effects) {
    std::cout << "Band: " << effect.first << ", Effect: " << effect.second << " dB" << std::endl;
}
```

### Tropospheric Ducting Analysis

```cpp
// Analyze tropospheric ducting conditions
float ducting_factor = weather_provider.calculateTroposphericDucting();
std::cout << "Tropospheric ducting factor: " << ducting_factor << std::endl;

if (ducting_factor > 0.7f) {
    std::cout << "Strong ducting conditions detected" << std::endl;
} else if (ducting_factor > 0.3f) {
    std::cout << "Moderate ducting conditions" << std::endl;
} else {
    std::cout << "No significant ducting conditions" << std::endl;
}
```

## Advanced Features

### Atmospheric Modeling

```cpp
class AtmosphericModeler {
private:
    float temperature_coefficient;
    float humidity_coefficient;
    float pressure_coefficient;
    float wind_coefficient;
    
public:
    float calculateAtmosphericRefraction(float temperature_celsius,
                                       float humidity_percent,
                                       float pressure_hpa) {
        // Calculate atmospheric refraction index
        float n = 1.0f + (77.6f * pressure_hpa / (temperature_celsius + 273.15f)) * 1e-6f;
        n += (3.73f * humidity_percent * pressure_hpa / (temperature_celsius + 273.15f)) * 1e-6f;
        
        return n;
    }
    
    float calculateDuctingConditions(float temperature_celsius,
                                   float humidity_percent,
                                   float pressure_hpa,
                                   float wind_speed_ms) {
        // Calculate tropospheric ducting conditions
        float temperature_gradient = calculateTemperatureGradient(temperature_celsius);
        float humidity_gradient = calculateHumidityGradient(humidity_percent);
        float wind_effect = calculateWindEffect(wind_speed_ms);
        
        return temperature_gradient + humidity_gradient + wind_effect;
    }
    
private:
    float calculateTemperatureGradient(float temperature_celsius) {
        // Calculate temperature gradient effect on ducting
        return (temperature_celsius - 20.0f) * 0.01f;
    }
    
    float calculateHumidityGradient(float humidity_percent) {
        // Calculate humidity gradient effect on ducting
        return (humidity_percent - 50.0f) * 0.02f;
    }
    
    float calculateWindEffect(float wind_speed_ms) {
        // Calculate wind effect on ducting
        return wind_speed_ms * 0.001f;
    }
};
```

### Frequency-Specific Analysis

```cpp
class FrequencyAnalyzer {
private:
    std::map<std::string, float> frequency_bands;
    std::map<std::string, float> propagation_modes;
    
public:
    float analyzeFrequencyEffects(float frequency_hz, const fgcom_weather_conditions& weather) {
        float total_effects = 0.0f;
        
        // Temperature effects
        float temp_effects = calculateTemperatureEffects(frequency_hz, weather.temperature_celsius);
        total_effects += temp_effects;
        
        // Humidity effects
        float humidity_effects = calculateHumidityEffects(frequency_hz, weather.humidity_percent);
        total_effects += humidity_effects;
        
        // Pressure effects
        float pressure_effects = calculatePressureEffects(frequency_hz, weather.pressure_hpa);
        total_effects += pressure_effects;
        
        // Precipitation effects
        float precip_effects = calculatePrecipitationEffects(frequency_hz, weather.precipitation_mmh);
        total_effects += precip_effects;
        
        return total_effects;
    }
    
private:
    float calculateTemperatureEffects(float frequency_hz, float temperature_celsius) {
        // Calculate temperature effects on different frequencies
        if (frequency_hz < 1000000.0f) { // VLF/LF
            return (temperature_celsius - 20.0f) * 0.001f;
        } else if (frequency_hz < 100000000.0f) { // MF/HF
            return (temperature_celsius - 20.0f) * 0.005f;
        } else if (frequency_hz < 1000000000.0f) { // VHF/UHF
            return (temperature_celsius - 20.0f) * 0.01f;
        } else { // SHF/EHF
            return (temperature_celsius - 20.0f) * 0.02f;
        }
    }
    
    float calculateHumidityEffects(float frequency_hz, float humidity_percent) {
        // Calculate humidity effects on different frequencies
        if (frequency_hz < 1000000.0f) { // VLF/LF
            return (humidity_percent - 50.0f) * 0.002f;
        } else if (frequency_hz < 100000000.0f) { // MF/HF
            return (humidity_percent - 50.0f) * 0.01f;
        } else if (frequency_hz < 1000000000.0f) { // VHF/UHF
            return (humidity_percent - 50.0f) * 0.02f;
        } else { // SHF/EHF
            return (humidity_percent - 50.0f) * 0.05f;
        }
    }
    
    float calculatePressureEffects(float frequency_hz, float pressure_hpa) {
        // Calculate pressure effects on different frequencies
        if (frequency_hz < 1000000.0f) { // VLF/LF
            return (pressure_hpa - 1013.25f) * 0.001f;
        } else if (frequency_hz < 100000000.0f) { // MF/HF
            return (pressure_hpa - 1013.25f) * 0.005f;
        } else if (frequency_hz < 1000000000.0f) { // VHF/UHF
            return (pressure_hpa - 1013.25f) * 0.01f;
        } else { // SHF/EHF
            return (pressure_hpa - 1013.25f) * 0.02f;
        }
    }
    
    float calculatePrecipitationEffects(float frequency_hz, float precipitation_mmh) {
        // Calculate precipitation effects on different frequencies
        if (frequency_hz < 1000000.0f) { // VLF/LF
            return precipitation_mmh * 0.001f;
        } else if (frequency_hz < 100000000.0f) { // MF/HF
            return precipitation_mmh * 0.005f;
        } else if (frequency_hz < 1000000000.0f) { // VHF/UHF
            return precipitation_mmh * 0.01f;
        } else { // SHF/EHF
            return precipitation_mmh * 0.02f;
        }
    }
};
```

### Propagation Mode Analysis

```cpp
class PropagationModeAnalyzer {
private:
    std::map<std::string, float> mode_effects;
    
public:
    float analyzePropagationMode(const std::string& mode, 
                                float frequency_hz,
                                const fgcom_weather_conditions& weather) {
        if (mode == "ground_wave") {
            return analyzeGroundWave(frequency_hz, weather);
        } else if (mode == "sky_wave") {
            return analyzeSkyWave(frequency_hz, weather);
        } else if (mode == "line_of_sight") {
            return analyzeLineOfSight(frequency_hz, weather);
        } else if (mode == "tropospheric_scatter") {
            return analyzeTroposphericScatter(frequency_hz, weather);
        } else if (mode == "ducting") {
            return analyzeDucting(frequency_hz, weather);
        }
        
        return 0.0f;
    }
    
private:
    float analyzeGroundWave(float frequency_hz, const fgcom_weather_conditions& weather) {
        // Ground wave propagation is less affected by weather
        float effects = 0.0f;
        
        // Soil moisture effects
        effects += weather.humidity_percent * 0.001f;
        
        // Temperature effects on ground conductivity
        effects += (weather.temperature_celsius - 20.0f) * 0.002f;
        
        return effects;
    }
    
    float analyzeSkyWave(float frequency_hz, const fgcom_weather_conditions& weather) {
        // Sky wave propagation is moderately affected by weather
        float effects = 0.0f;
        
        // Atmospheric conditions affect ionospheric reflection
        effects += weather.pressure_hpa * 0.001f;
        effects += weather.temperature_celsius * 0.002f;
        effects += weather.humidity_percent * 0.003f;
        
        return effects;
    }
    
    float analyzeLineOfSight(float frequency_hz, const fgcom_weather_conditions& weather) {
        // Line of sight propagation is highly affected by weather
        float effects = 0.0f;
        
        // Atmospheric refraction
        effects += weather.temperature_celsius * 0.01f;
        effects += weather.humidity_percent * 0.02f;
        effects += weather.pressure_hpa * 0.005f;
        
        // Precipitation effects
        effects += weather.precipitation_mmh * 0.1f;
        
        return effects;
    }
    
    float analyzeTroposphericScatter(float frequency_hz, const fgcom_weather_conditions& weather) {
        // Tropospheric scatter is highly affected by weather
        float effects = 0.0f;
        
        // Atmospheric turbulence
        effects += weather.wind_speed_ms * 0.05f;
        effects += weather.temperature_celsius * 0.02f;
        effects += weather.humidity_percent * 0.03f;
        
        return effects;
    }
    
    float analyzeDucting(float frequency_hz, const fgcom_weather_conditions& weather) {
        // Ducting is very sensitive to weather conditions
        float effects = 0.0f;
        
        // Temperature inversion
        effects += (weather.temperature_celsius - 20.0f) * 0.1f;
        
        // Humidity gradient
        effects += weather.humidity_percent * 0.05f;
        
        // Wind effects
        effects += weather.wind_speed_ms * 0.02f;
        
        return effects;
    }
};
```

## Performance Optimization

### Data Caching

```cpp
class WeatherDataCache {
private:
    std::map<std::string, fgcom_weather_conditions> cache;
    std::mutex cache_mutex;
    std::time_t cache_ttl;
    
public:
    bool getCachedWeather(const std::string& key, fgcom_weather_conditions& weather) {
        std::lock_guard<std::mutex> lock(cache_mutex);
        
        auto it = cache.find(key);
        if (it != cache.end()) {
            // Check if data is still valid
            auto now = std::chrono::system_clock::now();
            auto age = std::chrono::duration_cast<std::chrono::seconds>(
                now - it->second.timestamp).count();
            
            if (age < cache_ttl) {
                weather = it->second;
                return true;
            } else {
                // Remove expired data
                cache.erase(it);
            }
        }
        
        return false;
    }
    
    void setCachedWeather(const std::string& key, const fgcom_weather_conditions& weather) {
        std::lock_guard<std::mutex> lock(cache_mutex);
        cache[key] = weather;
    }
};
```

### Real-time Processing

```cpp
class RealTimeWeatherProcessor {
private:
    std::thread processing_thread;
    std::atomic<bool> processing_active;
    std::queue<fgcom_weather_conditions> weather_queue;
    std::mutex queue_mutex;
    
public:
    void startProcessing() {
        processing_active = true;
        processing_thread = std::thread(&RealTimeWeatherProcessor::processingLoop, this);
    }
    
    void stopProcessing() {
        processing_active = false;
        if (processing_thread.joinable()) {
            processing_thread.join();
        }
    }
    
    void addWeatherData(const fgcom_weather_conditions& weather) {
        std::lock_guard<std::mutex> lock(queue_mutex);
        weather_queue.push(weather);
    }
    
private:
    void processingLoop() {
        while (processing_active) {
            std::vector<fgcom_weather_conditions> weather_to_process;
            
            // Get weather data from queue
            {
                std::lock_guard<std::mutex> lock(queue_mutex);
                while (!weather_queue.empty()) {
                    weather_to_process.push_back(weather_queue.front());
                    weather_queue.pop();
                }
            }
            
            // Process weather data
            for (const auto& weather : weather_to_process) {
                processWeatherData(weather);
            }
            
            // Sleep for processing interval
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
    void processWeatherData(const fgcom_weather_conditions& weather) {
        // Process weather data
        // Update propagation models
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
    "code": "WEATHER_DATA_UNAVAILABLE",
    "message": "Weather data source is currently unavailable",
    "details": {
      "data_source": "openweathermap",
      "last_successful_update": "2024-01-15T10:25:00Z",
      "retry_after_seconds": 600
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Error Codes

- **WEATHER_DATA_UNAVAILABLE**: Weather data source unavailable
- **INVALID_WEATHER_DATA**: Invalid weather data received
- **PROPAGATION_CALCULATION_FAILED**: Weather propagation calculation failed
- **FREQUENCY_ANALYSIS_FAILED**: Frequency analysis failed
- **CACHE_OPERATION_FAILED**: Weather data cache operation failed
- **API_RATE_LIMIT_EXCEEDED**: Weather API rate limit exceeded

## WebSocket Real-time Updates

### Weather Data Updates

```json
{
  "type": "weather_data_update",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "temperature_celsius": 20.0,
    "humidity_percent": 50.0,
    "pressure_hpa": 1013.25,
    "wind_speed_ms": 5.0,
    "precipitation_mmh": 0.0,
    "total_weather_impact_db": 2.1,
    "weather_quality_factor": 0.85
  }
}
```

### Frequency Effects Updates

```json
{
  "type": "frequency_effects_update",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "frequency_band": "VHF",
    "frequency_hz": 100000000.0,
    "weather_effects_db": 2.2,
    "propagation_effects_db": 1.5,
    "total_effects_db": 3.7
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

# Get weather data status
status_response = requests.get('http://localhost:8080/api/v1/weather-data/status', headers=headers)
weather_status = status_response.json()['weather_status']
print(f"Temperature: {weather_status['current_weather']['temperature_celsius']}°C")
print(f"Humidity: {weather_status['current_weather']['humidity_percent']}%")
print(f"Total weather impact: {weather_status['total_weather_impact_db']} dB")

# Get frequency effects
freq_response = requests.get('http://localhost:8080/api/v1/weather-data/frequency-effects?frequency_band=VHF', headers=headers)
freq_effects = freq_response.json()['frequency_effects']
print(f"VHF weather effects: {freq_effects['weather_effects']['total_effects_db']} dB")
```

### JavaScript WebSocket Example

```javascript
const ws = new WebSocket('ws://localhost:8080/ws');

ws.onopen = function() {
    console.log('Connected to Weather Data WebSocket');
    
    // Subscribe to weather updates
    ws.send(JSON.stringify({
        type: 'subscribe',
        channel: 'weather_data',
        vehicle_id: 'player_001'
    }));
};

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    
    switch(data.type) {
        case 'weather_data_update':
            console.log('Weather data update:', data.data);
            break;
        case 'frequency_effects_update':
            console.log('Frequency effects update:', data.data);
            break;
    }
};
```

This comprehensive Weather Data Integration system provides realistic atmospheric effects on radio propagation across all frequency bands for enhanced radio communication simulation in FGCom-mumble.
