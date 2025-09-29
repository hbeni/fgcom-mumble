# EV Charging Station Noise Analysis Documentation

**FGCom-mumble v2.5+ EV Charging Station Noise Support**

This document describes the implementation of electric vehicle charging station noise analysis in FGCom-mumble, including noise modeling, station management, and configuration options.

## Overview

FGCom-mumble now supports comprehensive noise analysis for electric vehicle charging stations, accounting for different charging types, power levels, distance effects, and time-of-day variations. This provides realistic noise floor modeling that reflects the growing impact of EV charging infrastructure on radio communications.

## EV Charging Station Types

### Charging Type Classifications

| Charging Type | Power Range | Voltage | Current | Noise Level |
|---------------|-------------|---------|---------|-------------|
| **AC Level 1** | 1.4-1.9 kW | 120V | 12-16A | Low (1 dB) |
| **AC Level 2** | 3.3-19.2 kW | 240V | 13-80A | Medium (2 dB) |
| **DC Fast** | 50-350 kW | 400V+ | 125-875A | High (4 dB) |
| **DC Ultra Fast** | 350+ kW | 800V+ | 437A+ | Very High (6 dB) |

### Noise Characteristics

#### AC Charging (Level 1 & 2)
- **Switching Frequency**: 50-60 Hz harmonics
- **Noise Pattern**: Continuous low-level switching noise
- **Frequency Range**: Primarily affects HF bands (1-30 MHz)
- **Distance Decay**: 1/r² for point sources

#### DC Fast Charging
- **Switching Frequency**: High-frequency switching (kHz range)
- **Noise Pattern**: Pulsed high-power switching
- **Frequency Range**: Affects HF and VHF bands (1-150 MHz)
- **Distance Decay**: 1/r² for point sources

## Noise Calculation Algorithm

### Base Noise Calculation

```cpp
float calculateEVChargingNoise(double lat, double lon, float freq_mhz) {
    float ev_charging_noise = 0.0f;
    
    // Find nearby EV charging stations
    auto nearby_stations = getNearbyEVChargingStations(lat, lon, 10.0f);
    
    for (const auto& station : nearby_stations) {
        if (!station.is_active) continue;
        
        // Calculate distance to station
        float distance_km = calculateDistance(lat, lon, station.latitude, station.longitude);
        
        // Base noise from charging station type
        float station_noise = getBaseNoiseForType(station.charging_type);
        
        // Scale by power level
        station_noise *= (station.power_kw / 50.0f);
        
        // Distance decay (1/r²)
        station_noise += calculateDistanceDecay(distance_km);
        
        // Apply environmental factors
        station_noise *= getTimeOfDayFactor();
        station_noise *= getFrequencyFactor(freq_mhz);
        station_noise *= getWeatherFactor();
        
        ev_charging_noise += station_noise;
    }
    
    return ev_charging_noise;
}
```

### Distance Decay Model

| Distance | Noise Contribution | Description |
|----------|-------------------|-------------|
| **< 0.5 km** | **8 dB** | Very close charging stations |
| **0.5-2.0 km** | **4 dB** | Medium distance stations |
| **2.0-5.0 km** | **2 dB** | Distant stations |
| **> 5.0 km** | **Negligible** | Minimal impact |

### Time of Day Effects

| Time Period | Noise Factor | Description |
|-------------|---------------|-------------|
| **Day (06:00-18:00)** | **1.2x** | 20% increase during business hours |
| **Evening (18:00-22:00)** | **1.4x** | 40% increase during peak charging |
| **Night (22:00-06:00)** | **0.6x** | 40% decrease during off-peak |

### Frequency Dependencies

| Frequency Range | Noise Factor | Description |
|-----------------|---------------|-------------|
| **< 2 MHz** | **1.3x** | Higher noise from switching harmonics |
| **2-10 MHz** | **1.1x** | Medium noise in HF band |
| **10-30 MHz** | **1.0x** | Normal noise level |
| **> 30 MHz** | **0.8x** | Lower noise at higher frequencies |

## Station Management

### Adding EV Charging Stations

```cpp
EVChargingStation station;
station.latitude = 40.7128;
station.longitude = -74.0060;
station.power_kw = 150.0f;
station.charging_type = EVChargingType::DC_FAST;
station.is_active = true;
station.operator_name = "Tesla Supercharger";
station.station_id = "TESLA_NYC_001";
station.noise_factor = 1.0f;

atmosphericNoise.addEVChargingStation(station);
```

### Station Database Operations

```cpp
// Add station
atmosphericNoise.addEVChargingStation(station);

// Remove station
atmosphericNoise.removeEVChargingStation("TESLA_NYC_001");

// Update station
atmosphericNoise.updateEVChargingStation("TESLA_NYC_001", updated_station);

// Get nearby stations
auto nearby = atmosphericNoise.getNearbyEVChargingStations(lat, lon, 5.0f);

// Clear all stations
atmosphericNoise.clearEVChargingStations();

// Get station count
size_t count = atmosphericNoise.getEVChargingStationCount();
```

## Configuration

### Feature Toggle Control

```ini
# configs/feature_toggles.conf
[noise_analysis_features]
enable_ev_charging_analysis = false  # Off by default
```

### Programmatic Control

```cpp
// Enable EV charging analysis
atmosphericNoise.setFeatureEnabled("ev_charging_analysis", true);

// Disable EV charging analysis
atmosphericNoise.setFeatureEnabled("ev_charging_analysis", false);
```

## Real-World Examples

### Urban EV Charging Hubs

**Location**: Manhattan, NYC
- **Station Count**: 50+ charging stations
- **Charging Types**: Mix of Level 2 and DC Fast
- **Noise Impact**: +3-6 dB in HF bands
- **Peak Hours**: 18:00-22:00 (evening charging)

### Highway Rest Stops

**Location**: Interstate 95, New Jersey
- **Station Count**: 8-12 charging stations
- **Charging Types**: Primarily DC Fast (150-350 kW)
- **Noise Impact**: +2-4 dB within 2 km
- **Peak Hours**: 12:00-14:00 and 18:00-20:00

### Residential Areas

**Location**: Suburban neighborhoods
- **Station Count**: 2-5 charging stations
- **Charging Types**: Level 1 and Level 2
- **Noise Impact**: +1-2 dB within 1 km
- **Peak Hours**: 19:00-21:00 (home charging)

## Integration with Existing Systems

### Noise Floor Calculation

EV charging noise is integrated into the main noise floor calculation:

```cpp
float noise_floor = calculateThermalNoise();
noise_floor += calculateAtmosphericNoise(freq_mhz);
noise_floor += calculateManMadeNoise(env_type, freq_mhz);
noise_floor += calculateEVChargingNoise(lat, lon, freq_mhz);  // New
```

### Environmental Classification

EV charging stations are considered in environmental noise classification:

- **Urban Areas**: High EV charging activity
- **Suburban Areas**: Medium EV charging activity  
- **Rural Areas**: Low EV charging activity
- **Remote Areas**: Minimal EV charging activity

## Performance Considerations

### Computational Overhead

- **Station Lookup**: O(n) where n = number of stations
- **Distance Calculation**: O(1) per station
- **Noise Calculation**: O(1) per station
- **Total Complexity**: O(n) where n = nearby stations

### Memory Usage

- **Station Storage**: ~100 bytes per station
- **Typical Load**: 1000-5000 stations
- **Memory Impact**: 100KB-500KB for station database

### Optimization Strategies

1. **Spatial Indexing**: Use geographic indexing for fast station lookup
2. **Distance Culling**: Only process stations within 10 km radius
3. **Caching**: Cache noise calculations for repeated locations
4. **Background Updates**: Update station status in background threads

## API Integration

### REST API Endpoints

```http
# Get nearby EV charging stations
GET /api/ev-charging-stations?lat=40.7128&lon=-74.0060&radius=5.0

# Add EV charging station
POST /api/ev-charging-stations
{
  "latitude": 40.7128,
  "longitude": -74.0060,
  "power_kw": 150.0,
  "charging_type": "DC_FAST",
  "operator_name": "Tesla Supercharger"
}

# Update EV charging station
PUT /api/ev-charging-stations/{station_id}
{
  "is_active": false,
  "noise_factor": 0.8
}

# Delete EV charging station
DELETE /api/ev-charging-stations/{station_id}
```

### Configuration API

```http
# Enable EV charging analysis
POST /api/features/ev-charging-analysis/enable

# Disable EV charging analysis  
POST /api/features/ev-charging-analysis/disable

# Get EV charging analysis status
GET /api/features/ev-charging-analysis/status
```

## Future Enhancements

### Planned Features

1. **Real-time Station Data**: Integration with charging network APIs
2. **Predictive Modeling**: Forecast charging activity based on patterns
3. **Machine Learning**: Adaptive noise modeling based on real-world data
4. **Geographic Databases**: Integration with OpenStreetMap charging data
5. **Weather Integration**: Enhanced weather effects on charging noise

### Research Areas

1. **Harmonic Analysis**: Detailed frequency spectrum analysis
2. **Propagation Effects**: How EV charging noise propagates through terrain
3. **Mitigation Strategies**: Techniques to reduce EV charging noise impact
4. **Standardization**: Industry standards for EV charging noise measurement

## Troubleshooting

### Common Issues

1. **High Noise Levels**: Check for nearby high-power DC charging stations
2. **Unexpected Noise**: Verify station status and activity levels
3. **Performance Issues**: Consider reducing station database size
4. **Configuration Problems**: Ensure EV charging analysis is enabled

### Debug Information

```cpp
// Get debug information
auto nearby_stations = atmosphericNoise.getNearbyEVChargingStations(lat, lon, 10.0f);
for (const auto& station : nearby_stations) {
    std::cout << "Station: " << station.station_id 
              << " Type: " << static_cast<int>(station.charging_type)
              << " Power: " << station.power_kw << " kW"
              << " Active: " << (station.is_active ? "Yes" : "No") << std::endl;
}
```

## Conclusion

The EV charging station noise analysis system provides comprehensive modeling of electric vehicle charging infrastructure impact on radio communications. This system enables realistic noise floor calculations that account for the growing presence of EV charging stations and their unique noise characteristics.

The implementation supports multiple charging types, distance-based modeling, time-of-day variations, and environmental factors, providing accurate noise floor predictions for modern radio communication scenarios.
