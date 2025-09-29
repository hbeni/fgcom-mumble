# Substation and Power Station Noise Analysis Documentation

**FGCom-mumble v2.6+ Substation and Power Station Noise Support**

This document describes the implementation of electrical substation and power station noise analysis in FGCom-mumble, including noise modeling, geometry considerations, fencing effects, and capacity thresholds.

## Overview

FGCom-mumble now supports comprehensive noise analysis for electrical substations and power stations, accounting for voltage levels, capacity, geometry (including multipolygons), fencing effects, and the 2MW+ capacity threshold for power stations. This provides realistic noise floor modeling that reflects the impact of electrical infrastructure on radio communications.

## Substation Analysis

### Substation Types and Characteristics

| Substation Type | Voltage Range | Capacity Range | Base Noise | Description |
|-----------------|---------------|----------------|------------|-------------|
| **Transmission** | 69-765 kV | 50-1000 MVA | 3-8 dB | High voltage transmission substations |
| **Distribution** | 4-35 kV | 5-100 MVA | 2-4 dB | Medium voltage distribution substations |
| **Switching** | 69-500 kV | 0 MVA | 1.5 dB | Circuit switching only (no transformation) |
| **Converter** | 69-800 kV | 100-2000 MVA | 4-6 dB | AC/DC converter substations |
| **Industrial** | 4-69 kV | 10-200 MVA | 2.5-4 dB | Industrial facility substations |
| **Railway** | 15-25 kV | 5-50 MVA | 3.5-5 dB | Railway electrification substations |

### Substation Noise Calculation

#### Base Noise by Type
```cpp
switch (substation.substation_type) {
    case SubstationType::TRANSMISSION:
        station_noise = 3.0f + (substation.voltage_kv / 100.0f);
        break;
    case SubstationType::DISTRIBUTION:
        station_noise = 2.0f + (substation.voltage_kv / 50.0f);
        break;
    case SubstationType::SWITCHING:
        station_noise = 1.5f;  // Lower noise from switching only
        break;
    case SubstationType::CONVERTER:
        station_noise = 4.0f;  // High noise from AC/DC conversion
        break;
    case SubstationType::INDUSTRIAL:
        station_noise = 2.5f;  // Industrial substation noise
        break;
    case SubstationType::RAILWAY:
        station_noise = 3.5f;  // Railway electrification noise
        break;
}
```

#### Capacity Scaling
- **Formula**: `station_noise *= (capacity_mva / 100.0f)`
- **Baseline**: 100 MVA capacity
- **Effect**: Larger substations produce proportionally more noise

#### Distance Decay Model

| Distance | Noise Contribution | Description |
|----------|-------------------|-------------|
| **< 1 km** | **12 dB** | Very close substations |
| **1-5 km** | **6 dB** | Medium distance substations |
| **5-10 km** | **3 dB** | Distant substations |
| **> 10 km** | **Negligible** | Minimal impact |

#### Fencing Effects
- **Fenced Substations**: 10% noise increase due to containment effects
- **Unfenced Substations**: Baseline noise levels
- **Rationale**: Fencing can create resonant cavities and containment effects

#### Frequency Dependencies

| Frequency Range | Noise Factor | Description |
|-----------------|---------------|-------------|
| **< 1 MHz** | **1.5x** | Higher noise at very low frequencies (50/60 Hz harmonics) |
| **1-10 MHz** | **1.2x** | Medium noise in HF band |
| **10-30 MHz** | **1.0x** | Normal noise level |
| **> 30 MHz** | **0.7x** | Lower noise at higher frequencies |

## Power Station Analysis

### Power Station Types and Characteristics

| Station Type | Capacity Range | Base Noise | Description |
|--------------|----------------|------------|-------------|
| **Thermal** | 50-3000 MW | 5-8 dB | Coal, gas, oil-fired power plants |
| **Nuclear** | 500-4000 MW | 6-9 dB | Nuclear power plants |
| **Hydroelectric** | 10-2000 MW | 3-5 dB | Hydroelectric power plants |
| **Wind** | 10-500 MW | 2-3 dB | Wind farms |
| **Solar** | 5-1000 MW | 1.5-3 dB | Solar photovoltaic farms |
| **Geothermal** | 10-1000 MW | 4-6 dB | Geothermal power plants |
| **Biomass** | 10-500 MW | 4.5-7 dB | Biomass power plants |
| **Pumped Storage** | 100-3000 MW | 3.5-6 dB | Pumped storage hydroelectric |

### Power Station Noise Calculation

#### Base Noise by Type
```cpp
switch (station.station_type) {
    case PowerStationType::THERMAL:
        station_noise = 5.0f + (station.capacity_mw / 100.0f);
        break;
    case PowerStationType::NUCLEAR:
        station_noise = 6.0f + (station.capacity_mw / 100.0f);
        break;
    case PowerStationType::HYDROELECTRIC:
        station_noise = 3.0f + (station.capacity_mw / 200.0f);
        break;
    case PowerStationType::WIND:
        station_noise = 2.0f + (station.capacity_mw / 300.0f);
        break;
    case PowerStationType::SOLAR:
        station_noise = 1.5f + (station.capacity_mw / 400.0f);
        break;
    // ... other types
}
```

#### Capacity Threshold
- **Minimum Capacity**: 2 MW peak rated output capacity
- **Filtering**: Only stations with 2MW+ capacity are considered
- **Rationale**: Smaller installations have negligible RF noise impact

#### Output Scaling
- **Formula**: `station_noise *= (0.5f + 0.5f * output_factor)`
- **Output Factor**: `current_output_mw / capacity_mw`
- **Effect**: Noise scales with actual power output vs. capacity

#### Distance Decay Model

| Distance | Noise Contribution | Description |
|----------|-------------------|-------------|
| **< 2 km** | **15 dB** | Very close power stations |
| **2-10 km** | **8 dB** | Medium distance power stations |
| **10-25 km** | **4 dB** | Distant power stations |
| **> 25 km** | **Negligible** | Minimal impact |

#### Fencing Effects
- **Fenced Power Stations**: 5% noise increase
- **Unfenced Power Stations**: Baseline noise levels
- **Rationale**: Fencing can affect noise propagation and containment

## Geometry Support

### Geometry Types

| Geometry Type | Description | Use Case |
|----------------|-------------|----------|
| **POINT** | Single coordinate | Small substations, point sources |
| **POLYGON** | Simple polygon | Fenced substations, defined boundaries |
| **MULTIPOLYGON** | Multiple polygons | Complex facilities, multiple areas |
| **LINESTRING** | Line geometry | Linear facilities, transmission lines |
| **MULTILINESTRING** | Multiple lines | Complex linear facilities |

### Multipolygon Support

```cpp
struct Substation {
    GeometryType geometry_type;
    std::vector<std::vector<std::pair<double, double>>> polygons;
    // Each polygon is a vector of coordinate pairs
    // Multiple polygons for complex geometries
};
```

#### Distance Calculation
- **Point Geometry**: Simple distance calculation
- **Polygon Geometry**: Distance to nearest edge
- **Multipolygon Geometry**: Distance to nearest polygon edge
- **Future Enhancement**: Point-in-polygon detection for interior points

## Time-of-Day Effects

### Substation Activity Patterns

| Time Period | Noise Factor | Description |
|-------------|---------------|-------------|
| **Day (06:00-18:00)** | **1.3x** | 30% increase during business hours |
| **Evening (18:00-22:00)** | **1.1x** | 10% increase during transition |
| **Night (22:00-06:00)** | **0.8x** | 20% decrease during off-peak |

### Power Station Activity Patterns

| Time Period | Noise Factor | Description |
|-------------|---------------|-------------|
| **Day (06:00-18:00)** | **1.2x** | 20% increase during peak demand |
| **Evening (18:00-22:00)** | **1.1x** | 10% increase during transition |
| **Night (22:00-06:00)** | **0.9x** | 10% decrease during off-peak |

## Weather Effects

### Substation Weather Impact

| Weather Condition | Noise Factor | Description |
|-------------------|---------------|-------------|
| **Normal** | **1.0x** | Baseline conditions |
| **Precipitation** | **1.2x** | Wet conditions increase noise |
| **Thunderstorms** | **1.3x** | Storm conditions increase noise |

### Power Station Weather Impact

| Weather Condition | Noise Factor | Description |
|-------------------|---------------|-------------|
| **Normal** | **1.0x** | Baseline conditions |
| **Precipitation** | **1.15x** | Wet conditions increase noise |
| **Thunderstorms** | **1.25x** | Storm conditions increase noise |

## Station Management

### Adding Substations

```cpp
Substation substation;
substation.latitude = 40.7128;
substation.longitude = -74.0060;
substation.substation_type = SubstationType::TRANSMISSION;
substation.voltage_kv = 345.0f;
substation.capacity_mva = 500.0f;
substation.is_fenced = true;
substation.geometry_type = GeometryType::POLYGON;
substation.is_active = true;
substation.operator_name = "ConEd";
substation.substation_id = "CONED_345KV_001";
substation.noise_factor = 1.0f;

atmosphericNoise.addSubstation(substation);
```

### Adding Power Stations

```cpp
PowerStation station;
station.latitude = 40.7128;
station.longitude = -74.0060;
station.station_type = PowerStationType::THERMAL;
station.capacity_mw = 1000.0f;  // 1 GW capacity
station.current_output_mw = 800.0f;  // 800 MW current output
station.is_fenced = true;
station.geometry_type = GeometryType::MULTIPOLYGON;
station.is_active = true;
station.operator_name = "PSEG";
station.station_id = "PSEG_THERMAL_001";
station.noise_factor = 1.0f;

atmosphericNoise.addPowerStation(station);
```

### Database Operations

```cpp
// Add stations
atmosphericNoise.addSubstation(substation);
atmosphericNoise.addPowerStation(station);

// Remove stations
atmosphericNoise.removeSubstation("CONED_345KV_001");
atmosphericNoise.removePowerStation("PSEG_THERMAL_001");

// Update stations
atmosphericNoise.updateSubstation("CONED_345KV_001", updated_substation);
atmosphericNoise.updatePowerStation("PSEG_THERMAL_001", updated_station);

// Get nearby stations
auto nearby_substations = atmosphericNoise.getNearbySubstations(lat, lon, 20.0f);
auto nearby_power_stations = atmosphericNoise.getNearbyPowerStations(lat, lon, 50.0f);

// Clear all stations
atmosphericNoise.clearSubstations();
atmosphericNoise.clearPowerStations();

// Get station counts
size_t substation_count = atmosphericNoise.getSubstationCount();
size_t power_station_count = atmosphericNoise.getPowerStationCount();
```

## Configuration

### Feature Toggle Control

```ini
# configs/feature_toggles.conf
[noise_analysis_features]
enable_substation_analysis = false  # Off by default
enable_power_station_analysis = false  # Off by default
```

### Programmatic Control

```cpp
// Enable substation analysis
atmosphericNoise.setFeatureEnabled("substation_analysis", true);

// Enable power station analysis
atmosphericNoise.setFeatureEnabled("power_station_analysis", true);

// Disable analyses
atmosphericNoise.setFeatureEnabled("substation_analysis", false);
atmosphericNoise.setFeatureEnabled("power_station_analysis", false);
```

## Real-World Examples

### Urban Transmission Substation

**Location**: Manhattan, NYC
- **Type**: Transmission substation
- **Voltage**: 345 kV
- **Capacity**: 500 MVA
- **Fenced**: Yes
- **Noise Impact**: +4-6 dB in HF bands
- **Peak Hours**: 06:00-18:00 (business hours)

### Rural Power Plant

**Location**: Upstate New York
- **Type**: Nuclear power plant
- **Capacity**: 2000 MW
- **Current Output**: 1800 MW
- **Fenced**: Yes
- **Noise Impact**: +6-8 dB within 10 km
- **Peak Hours**: 06:00-22:00 (continuous operation)

### Industrial Distribution Substation

**Location**: Industrial park
- **Type**: Distribution substation
- **Voltage**: 12 kV
- **Capacity**: 50 MVA
- **Fenced**: No
- **Noise Impact**: +2-3 dB within 5 km
- **Peak Hours**: 06:00-18:00 (industrial hours)

## Integration with Existing Systems

### Noise Floor Calculation

Substation and power station noise is integrated into the main noise floor calculation:

```cpp
float noise_floor = calculateThermalNoise();
noise_floor += calculateAtmosphericNoise(freq_mhz);
noise_floor += calculateManMadeNoise(env_type, freq_mhz);
noise_floor += calculateSubstationNoise(lat, lon, freq_mhz);  // New
noise_floor += calculatePowerStationNoise(lat, lon, freq_mhz);  // New
```

### Environmental Classification

Substations and power stations are considered in environmental noise classification:

- **Urban Areas**: High substation density, medium power station density
- **Suburban Areas**: Medium substation density, low power station density
- **Rural Areas**: Low substation density, variable power station density
- **Industrial Areas**: High substation and power station density

## Performance Considerations

### Computational Overhead

- **Substation Lookup**: O(n) where n = number of substations
- **Power Station Lookup**: O(n) where n = number of power stations
- **Distance Calculation**: O(1) per station
- **Noise Calculation**: O(1) per station
- **Total Complexity**: O(n) where n = nearby stations

### Memory Usage

- **Substation Storage**: ~150 bytes per substation
- **Power Station Storage**: ~200 bytes per power station
- **Typical Load**: 100-1000 substations, 10-100 power stations
- **Memory Impact**: 15KB-200KB for station databases

### Optimization Strategies

1. **Spatial Indexing**: Use geographic indexing for fast station lookup
2. **Distance Culling**: Only process stations within search radius
3. **Capacity Filtering**: Pre-filter power stations by 2MW+ threshold
4. **Caching**: Cache noise calculations for repeated locations
5. **Background Updates**: Update station status in background threads

## API Integration

### REST API Endpoints

```http
# Get nearby substations
GET /api/substations?lat=40.7128&lon=-74.0060&radius=20.0

# Add substation
POST /api/substations
{
  "latitude": 40.7128,
  "longitude": -74.0060,
  "substation_type": "TRANSMISSION",
  "voltage_kv": 345.0,
  "capacity_mva": 500.0,
  "is_fenced": true,
  "operator_name": "ConEd"
}

# Get nearby power stations
GET /api/power-stations?lat=40.7128&lon=-74.0060&radius=50.0

# Add power station
POST /api/power-stations
{
  "latitude": 40.7128,
  "longitude": -74.0060,
  "station_type": "THERMAL",
  "capacity_mw": 1000.0,
  "current_output_mw": 800.0,
  "is_fenced": true,
  "operator_name": "PSEG"
}
```

### Configuration API

```http
# Enable substation analysis
POST /api/features/substation-analysis/enable

# Enable power station analysis
POST /api/features/power-station-analysis/enable

# Get analysis status
GET /api/features/substation-analysis/status
GET /api/features/power-station-analysis/status
```

## Future Enhancements

### Planned Features

1. **Real-time Station Data**: Integration with utility company APIs
2. **Advanced Geometry**: Full polygon and multipolygon distance calculations
3. **Predictive Modeling**: Forecast station activity based on patterns
4. **Machine Learning**: Adaptive noise modeling based on real-world data
5. **Geographic Databases**: Integration with OpenStreetMap infrastructure data

### Research Areas

1. **Harmonic Analysis**: Detailed frequency spectrum analysis for different station types
2. **Propagation Effects**: How electrical infrastructure noise propagates through terrain
3. **Mitigation Strategies**: Techniques to reduce electrical infrastructure noise impact
4. **Standardization**: Industry standards for electrical infrastructure noise measurement

## Troubleshooting

### Common Issues

1. **High Noise Levels**: Check for nearby high-voltage substations or large power stations
2. **Unexpected Noise**: Verify station status, capacity, and activity levels
3. **Performance Issues**: Consider reducing station database size or increasing search radius
4. **Configuration Problems**: Ensure substation and power station analyses are enabled

### Debug Information

```cpp
// Get debug information for substations
auto nearby_substations = atmosphericNoise.getNearbySubstations(lat, lon, 20.0f);
for (const auto& substation : nearby_substations) {
    std::cout << "Substation: " << substation.substation_id 
              << " Type: " << static_cast<int>(substation.substation_type)
              << " Voltage: " << substation.voltage_kv << " kV"
              << " Capacity: " << substation.capacity_mva << " MVA"
              << " Fenced: " << (substation.is_fenced ? "Yes" : "No") << std::endl;
}

// Get debug information for power stations
auto nearby_power_stations = atmosphericNoise.getNearbyPowerStations(lat, lon, 50.0f);
for (const auto& station : nearby_power_stations) {
    std::cout << "Power Station: " << station.station_id 
              << " Type: " << static_cast<int>(station.station_type)
              << " Capacity: " << station.capacity_mw << " MW"
              << " Output: " << station.current_output_mw << " MW"
              << " Fenced: " << (station.is_fenced ? "Yes" : "No") << std::endl;
}
```

## Conclusion

The substation and power station noise analysis system provides comprehensive modeling of electrical infrastructure impact on radio communications. This system enables realistic noise floor calculations that account for the growing electrical infrastructure and its unique noise characteristics, including voltage levels, capacity thresholds, geometry considerations, and fencing effects.

The implementation supports multiple station types, distance-based modeling, time-of-day variations, weather effects, and environmental factors, providing accurate noise floor predictions for modern radio communication scenarios with electrical infrastructure considerations.
