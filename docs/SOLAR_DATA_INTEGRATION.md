# Solar Data Integration Documentation

## Overview

The FGCom-mumble Solar Data Integration system provides real-time NOAA/SWPC solar data for accurate propagation modeling. The system fetches solar activity data from multiple sources and uses it to calculate realistic radio propagation conditions.

## System Architecture

### Core Components

- **SolarDataProvider**: Main solar data management system
- **NOAA API Integration**: Real-time data fetching from NOAA/SWPC
- **Data Caching**: Local caching for offline operation
- **Background Updates**: Automatic data refresh system
- **Fallback System**: Offline operation with cached data
- **Propagation Integration**: Solar data integration with propagation models

## Solar Data Sources

### NOAA/SWPC API Endpoints

#### Solar Flux Index (SFI)
- **Endpoint**: `https://services.swpc.noaa.gov/json/f107cm.json`
- **Description**: 10.7 cm solar flux index
- **Update Frequency**: Every 15 minutes
- **Range**: 0-300 (typical range: 70-200)
- **Impact**: Primary indicator of ionospheric activity

#### K-Index
- **Endpoint**: `https://services.swpc.noaa.gov/json/k_index_1m.json`
- **Description**: Geomagnetic activity index
- **Update Frequency**: Every 3 hours
- **Range**: 0-9 (0-3: quiet, 4-6: unsettled, 7-9: storm)
- **Impact**: Geomagnetic storm effects on propagation

#### A-Index
- **Endpoint**: `https://services.swpc.noaa.gov/json/a_index_1m.json`
- **Description**: Daily geomagnetic activity index
- **Update Frequency**: Daily
- **Range**: 0-400 (0-7: quiet, 8-15: unsettled, 16-29: active, 30+: storm)
- **Impact**: Long-term geomagnetic activity effects

#### AP-Index
- **Endpoint**: `https://services.swpc.noaa.gov/json/ap_index_1m.json`
- **Description**: Planetary geomagnetic activity index
- **Update Frequency**: Every 3 hours
- **Range**: 0-400
- **Impact**: Global geomagnetic activity

#### Solar Wind Data
- **Endpoint**: `https://services.swpc.noaa.gov/json/solar_wind.json`
- **Description**: Solar wind speed and density
- **Update Frequency**: Every 5 minutes
- **Parameters**: Speed (km/s), Density (particles/cm³), Temperature (K)
- **Impact**: Solar wind effects on ionosphere

#### Geomagnetic Field Data
- **Endpoint**: `https://services.swpc.noaa.gov/json/geomagnetic_field.json`
- **Description**: Geomagnetic field strength and direction
- **Update Frequency**: Every minute
- **Parameters**: Bx, By, Bz components, Total field strength
- **Impact**: Geomagnetic field effects on propagation

## Configuration

### Solar Data Configuration

```ini
# configs/fgcom-mumble.conf
[solar_data]
# Enable/disable solar data functionality
enabled = true

# NOAA API base URL
noaa_api_url = https://services.swpc.noaa.gov/json/

# Update interval in seconds (15 minutes = 900 seconds)
update_interval = 900

# Fallback data file path
fallback_data_path = /usr/share/fgcom-mumble/solar_fallback.json

# Enable background updates
enable_background_updates = true

# Enable offline mode when API is unavailable
enable_offline_mode = true

# Enable forecast data
enable_forecast_data = false

# Forecast hours ahead
forecast_hours = 24

# Enable historical data
enable_historical_data = true

# Historical data retention in days
historical_days = 7

# NOAA API endpoints
sfi_endpoint = f107cm.json
k_index_endpoint = k_index_1m.json
a_index_endpoint = a_index_1m.json
ap_index_endpoint = ap_index_1m.json
solar_wind_endpoint = solar_wind.json
geomagnetic_endpoint = geomagnetic_field.json
```

### Fallback Values

```ini
# Fallback values for offline operation
fallback_sfi = 70.0
fallback_k_index = 0.0
fallback_a_index = 0.0
```

## Data Structures

### Solar Conditions Structure

```cpp
struct fgcom_solar_conditions {
    // Solar Flux Index
    float sfi;                    // 10.7 cm solar flux
    float sfi_trend;              // SFI trend (rising/falling)
    
    // Geomagnetic Indices
    float k_index;                // Current K-index
    float a_index;                // Current A-index
    float ap_index;               // Current AP-index
    
    // Solar Wind
    float solar_wind_speed;       // km/s
    float solar_wind_density;     // particles/cm³
    float solar_wind_temperature; // K
    
    // Geomagnetic Field
    float bx_component;           // nT
    float by_component;           // nT
    float bz_component;           // nT
    float total_field_strength;   // nT
    
    // Calculated Parameters
    float muf;                    // Maximum Usable Frequency
    float luf;                    // Lowest Usable Frequency
    float critical_frequency;     // foF2
    float propagation_quality;     // 0.0-1.0
    
    // Timestamps
    std::time_t timestamp;        // Data timestamp
    std::time_t last_update;      // Last successful update
    
    // Data Quality
    bool data_valid;              // Data validity flag
    bool forecast_data;           // Is this forecast data?
    std::string data_source;      // Data source identifier
};
```

### Solar Data Cache Structure

```cpp
struct SolarDataCache {
    fgcom_solar_conditions current_data;
    std::vector<fgcom_solar_conditions> historical_data;
    std::vector<fgcom_solar_conditions> forecast_data;
    
    std::time_t last_update;
    std::time_t last_successful_update;
    bool data_valid;
    
    std::shared_mutex read_write_mutex;
    size_t max_historical_entries;
    size_t max_forecast_entries;
};
```

## API Usage

### C++ API

#### Basic Usage
```cpp
#include "solar_data.h"

// Get solar data provider instance
auto& solar_provider = FGCom_SolarDataProvider::getInstance();

// Get current solar conditions
fgcom_solar_conditions conditions = solar_provider.getCurrentConditions();

// Check if data is valid
if (conditions.data_valid) {
    std::cout << "Solar Flux Index: " << conditions.sfi << std::endl;
    std::cout << "K-Index: " << conditions.k_index << std::endl;
    std::cout << "A-Index: " << conditions.a_index << std::endl;
    std::cout << "Propagation Quality: " << conditions.propagation_quality << std::endl;
}
```

#### Background Updates
```cpp
// Start background updates
solar_provider.startBackgroundUpdates();

// Check if updates are running
if (solar_provider.isUpdateRunning()) {
    std::cout << "Solar data updates are running" << std::endl;
}

// Stop background updates
solar_provider.stopBackgroundUpdates();
```

#### Manual Updates
```cpp
// Force immediate update
bool success = solar_provider.updateFromNOAA();
if (success) {
    std::cout << "Solar data updated successfully" << std::endl;
} else {
    std::cout << "Solar data update failed, using cached data" << std::endl;
}
```

#### Historical Data
```cpp
// Get historical data
auto historical_data = solar_provider.getHistoricalData(7); // Last 7 days

for (const auto& data : historical_data) {
    std::cout << "Date: " << std::ctime(&data.timestamp);
    std::cout << "SFI: " << data.sfi << std::endl;
    std::cout << "K-Index: " << data.k_index << std::endl;
}
```

#### Forecast Data
```cpp
// Get forecast data
auto forecast_data = solar_provider.getForecastData(24); // Next 24 hours

for (const auto& data : forecast_data) {
    std::cout << "Forecast Time: " << std::ctime(&data.timestamp);
    std::cout << "Predicted SFI: " << data.sfi << std::endl;
    std::cout << "Predicted K-Index: " << data.k_index << std::endl;
}
```

### REST API

#### Get Current Solar Data
```http
GET /api/v1/solar
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "solar_flux": 150.2,
  "sunspot_number": 45,
  "k_index": 2,
  "a_index": 8,
  "ap_index": 12,
  "solar_wind": {
    "speed": 450.5,
    "density": 5.2,
    "temperature": 100000.0
  },
  "geomagnetic_field": {
    "bx": 2.1,
    "by": -1.5,
    "bz": -3.2,
    "total_strength": 4.8
  },
  "calculated_parameters": {
    "muf": 25.5,
    "luf": 3.2,
    "critical_frequency": 8.5,
    "propagation_quality": 0.85
  },
  "magnetic_field": "quiet",
  "propagation_conditions": "good",
  "data_source": "noaa_swpc",
  "data_valid": true
}
```

#### Get Solar Data History
```http
GET /api/v1/solar/history?start_date=2024-01-01T00:00:00Z&end_date=2024-01-15T23:59:59Z&data_points=100
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "start_date": "2024-01-01T00:00:00Z",
  "end_date": "2024-01-15T23:59:59Z",
  "data_points": 100,
  "data": [
    {
      "timestamp": "2024-01-01T00:00:00Z",
      "solar_flux": 145.2,
      "k_index": 1,
      "a_index": 5,
      "propagation_quality": 0.82
    }
  ]
}
```

#### Get Solar Forecast
```http
GET /api/v1/solar/forecast?hours=24
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "forecast_hours": 24,
  "forecast_data": [
    {
      "timestamp": "2024-01-15T11:00:00Z",
      "predicted_solar_flux": 152.1,
      "predicted_k_index": 2,
      "predicted_a_index": 8,
      "confidence": 0.85
    }
  ]
}
```

## Solar Data Impact on Propagation

### Solar Flux Index (SFI) Effects

#### High SFI (>150)
- **Ionospheric Activity**: Increased ionization
- **MUF**: Higher maximum usable frequencies
- **HF Propagation**: Excellent long-distance communication
- **VHF/UHF**: Minimal direct impact
- **Seasonal Effects**: More pronounced in summer

#### Low SFI (<100)
- **Ionospheric Activity**: Reduced ionization
- **MUF**: Lower maximum usable frequencies
- **HF Propagation**: Poor long-distance communication
- **VHF/UHF**: Minimal direct impact
- **Seasonal Effects**: More pronounced in winter

### Geomagnetic Activity Effects

#### Quiet Conditions (K=0-3, A=0-7)
- **Propagation**: Normal conditions
- **HF**: Good long-distance communication
- **VHF/UHF**: Normal line-of-sight propagation
- **Aurora**: No auroral effects

#### Unsettled Conditions (K=4-6, A=8-15)
- **Propagation**: Slightly degraded
- **HF**: Some long-distance communication issues
- **VHF/UHF**: Minimal impact
- **Aurora**: Occasional auroral effects at high latitudes

#### Active Conditions (K=7-9, A=16-29)
- **Propagation**: Significantly degraded
- **HF**: Poor long-distance communication
- **VHF/UHF**: Some impact on long-distance paths
- **Aurora**: Strong auroral effects

#### Storm Conditions (K=9, A=30+)
- **Propagation**: Severely degraded
- **HF**: Very poor long-distance communication
- **VHF/UHF**: Significant impact on long-distance paths
- **Aurora**: Intense auroral effects

### Solar Wind Effects

#### High Solar Wind Speed (>500 km/s)
- **Geomagnetic Activity**: Increased
- **Aurora**: More frequent and intense
- **HF Propagation**: Degraded
- **VHF/UHF**: Some impact on long-distance paths

#### Low Solar Wind Speed (<300 km/s)
- **Geomagnetic Activity**: Reduced
- **Aurora**: Less frequent
- **HF Propagation**: Improved
- **VHF/UHF**: Normal conditions

## Propagation Calculations

### Maximum Usable Frequency (MUF)

```cpp
float calculateMUF(float sfi, float latitude, float longitude, float time_of_day) {
    // Base MUF calculation
    float base_muf = 3.0 + (sfi - 70.0) * 0.1;
    
    // Latitude adjustment
    float lat_factor = 1.0 + (abs(latitude) - 30.0) * 0.01;
    
    // Time of day adjustment
    float time_factor = 1.0 + sin(time_of_day * M_PI / 12.0) * 0.2;
    
    return base_muf * lat_factor * time_factor;
}
```

### Critical Frequency (foF2)

```cpp
float calculateCriticalFrequency(float sfi, float k_index, float latitude) {
    // Base critical frequency
    float base_fo = 5.0 + (sfi - 70.0) * 0.05;
    
    // K-index adjustment
    float k_factor = 1.0 - (k_index / 9.0) * 0.1;
    
    // Latitude adjustment
    float lat_factor = 1.0 + (abs(latitude) - 30.0) * 0.02;
    
    return base_fo * k_factor * lat_factor;
}
```

### Propagation Quality

```cpp
float calculatePropagationQuality(const fgcom_solar_conditions& conditions) {
    float quality = 1.0;
    
    // SFI impact
    if (conditions.sfi < 70.0) {
        quality *= 0.5;
    } else if (conditions.sfi > 200.0) {
        quality *= 0.8;
    }
    
    // K-index impact
    if (conditions.k_index > 5.0) {
        quality *= (1.0 - (conditions.k_index - 5.0) * 0.1);
    }
    
    // A-index impact
    if (conditions.a_index > 15.0) {
        quality *= (1.0 - (conditions.a_index - 15.0) * 0.05);
    }
    
    return std::max(0.0f, std::min(1.0f, quality));
}
```

## Threading and Background Updates

### Solar Data Thread

```cpp
void FGCom_ThreadManager::solarDataThreadFunction() {
    logThreadEvent("solar_data", "Thread started");
    
    while (!solar_data_shutdown.load()) {
        try {
            // Update solar data
            auto& solar_provider = FGCom_SolarDataProvider::getInstance();
            fgcom_solar_conditions current_conditions = solar_provider.getCurrentConditions();
            
            if (updateSolarData(current_conditions)) {
                updateThreadStats("solar_data", "solar_update", 100.0, true);
            } else {
                updateThreadStats("solar_data", "solar_update", 100.0, false);
                setThreadError("solar_data", "Failed to update solar data");
            }
            
        } catch (const std::exception& e) {
            setThreadError("solar_data", "Solar provider exception: " + std::string(e.what()));
        }
        
        // Sleep for configured interval
        std::this_thread::sleep_for(std::chrono::seconds(config.solar_data_interval_seconds));
    }
}
```

### Background Update Loop

```cpp
void FGCom_SolarDataProvider::backgroundUpdateLoop() {
    while (update_thread_running) {
        try {
            // Update from NOAA
            bool success = updateFromNOAA();
            
            if (success) {
                std::cout << "[Solar Data] Update successful" << std::endl;
            } else {
                std::cout << "[Solar Data] Update failed, using cached data" << std::endl;
            }
            
        } catch (const std::exception& e) {
            std::cerr << "[Solar Data] Update error: " << e.what() << std::endl;
        }
        
        // Sleep for update interval
        std::this_thread::sleep_for(std::chrono::seconds(update_interval));
    }
}
```

## Error Handling and Fallbacks

### Network Error Handling

```cpp
bool FGCom_SolarDataProvider::fetchSolarFluxIndex() {
    try {
        // Attempt to fetch from NOAA
        auto response = http_client.get(noaa_api_url + sfi_endpoint);
        
        if (response.status == 200) {
            auto data = nlohmann::json::parse(response.body);
            current_conditions.sfi = data["sfi"];
            return true;
        }
    } catch (const std::exception& e) {
        std::cerr << "Failed to fetch SFI: " << e.what() << std::endl;
    }
    
    // Use fallback data
    current_conditions.sfi = fallback_sfi;
    return false;
}
```

### Offline Mode

```cpp
void FGCom_SolarDataProvider::setFallbackConditions() {
    current_conditions.sfi = fallback_sfi;
    current_conditions.k_index = fallback_k_index;
    current_conditions.a_index = fallback_a_index;
    current_conditions.data_valid = true;
    current_conditions.data_source = "fallback";
    
    // Recalculate derived parameters
    updateSolarCalculations();
}
```

### Data Validation

```cpp
bool FGCom_SolarDataProvider::validateSolarData(const fgcom_solar_conditions& conditions) {
    // Validate SFI range
    if (conditions.sfi < 0.0 || conditions.sfi > 300.0) {
        return false;
    }
    
    // Validate K-index range
    if (conditions.k_index < 0.0 || conditions.k_index > 9.0) {
        return false;
    }
    
    // Validate A-index range
    if (conditions.a_index < 0.0 || conditions.a_index > 400.0) {
        return false;
    }
    
    return true;
}
```

## Performance Optimization

### Caching Strategy

```cpp
class SolarDataCache {
private:
    std::map<std::string, fgcom_solar_conditions> cache;
    std::mutex cache_mutex;
    std::time_t cache_ttl;
    
public:
    bool getCachedData(const std::string& key, fgcom_solar_conditions& data) {
        std::lock_guard<std::mutex> lock(cache_mutex);
        
        auto it = cache.find(key);
        if (it != cache.end()) {
            // Check if data is still valid
            if (std::time(nullptr) - it->second.timestamp < cache_ttl) {
                data = it->second;
                return true;
            } else {
                // Remove expired data
                cache.erase(it);
            }
        }
        
        return false;
    }
    
    void setCachedData(const std::string& key, const fgcom_solar_conditions& data) {
        std::lock_guard<std::mutex> lock(cache_mutex);
        cache[key] = data;
    }
};
```

### Rate Limiting

```cpp
class SolarDataRateLimiter {
private:
    std::chrono::system_clock::time_point last_request;
    std::chrono::seconds min_interval;
    
public:
    bool canMakeRequest() {
        auto now = std::chrono::system_clock::now();
        return (now - last_request) >= min_interval;
    }
    
    void recordRequest() {
        last_request = std::chrono::system_clock::now();
    }
};
```

## Monitoring and Diagnostics

### Solar Data Health Check

```cpp
bool FGCom_SolarDataProvider::performHealthCheck() {
    // Check if data is recent
    auto now = std::chrono::system_clock::now();
    auto time_since_update = std::chrono::duration_cast<std::chrono::minutes>(
        now - last_update).count();
    
    if (time_since_update > 30) { // 30 minutes
        return false;
    }
    
    // Check data validity
    if (!current_conditions.data_valid) {
        return false;
    }
    
    // Check data ranges
    if (current_conditions.sfi < 0.0 || current_conditions.sfi > 300.0) {
        return false;
    }
    
    return true;
}
```

### Diagnostic Information

```cpp
struct SolarDataDiagnostics {
    bool data_available;
    bool update_thread_running;
    std::time_t last_successful_update;
    std::time_t last_attempted_update;
    int consecutive_failures;
    std::string last_error_message;
    float data_age_minutes;
    bool using_fallback_data;
};
```

This comprehensive solar data integration system provides accurate, real-time solar activity data for realistic radio propagation modeling in FGCom-mumble.
