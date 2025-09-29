# Open Infrastructure Map Integration Documentation

**FGCom-mumble v2.7+ Open Infrastructure Map Data Source Integration**

This document describes the implementation of Open Infrastructure Map data source integration in FGCom-mumble, providing real-time electrical infrastructure data for enhanced noise floor calculations.

## Overview

FGCom-mumble now integrates with [Open Infrastructure Map](https://openinframap.org) to automatically fetch and process electrical infrastructure data including substations, power stations, and transmission lines. This integration provides comprehensive, up-to-date infrastructure information for accurate noise floor modeling.

## Open Infrastructure Map Data Source

### What is Open Infrastructure Map?

Open Infrastructure Map is a comprehensive mapping service that visualizes electrical infrastructure using OpenStreetMap (OSM) data. It provides detailed information about:

- **Substations**: Transmission, distribution, switching, and converter substations
- **Power Stations**: Thermal, nuclear, hydroelectric, wind, solar, and other power plants
- **Transmission Lines**: High-voltage transmission and distribution lines
- **Electrical Infrastructure**: Complete electrical grid mapping

### Data Source Characteristics

| Feature | Description |
|---------|-------------|
| **Data Source** | OpenStreetMap (OSM) via Overpass API |
| **Update Frequency** | Real-time (OSM data) |
| **Coverage** | Global |
| **Data Format** | JSON via Overpass API |
| **Attribution** | OpenStreetMap contributors |
| **License** | ODbL (Open Database License) |

## Integration Architecture

### Core Components

1. **FGCom_OpenInfraMapDataSource**: Main data source class
2. **Overpass API Integration**: Real-time data fetching
3. **Data Parsing**: JSON to internal data structures
4. **Caching System**: Local data storage and management
5. **Noise Analysis Integration**: Seamless integration with existing noise calculations

### Data Flow

```
OpenStreetMap → Overpass API → FGCom_OpenInfraMapDataSource → Noise Analysis System
```

## API Integration

### Overpass API Queries

#### Substation Query
```xml
[out:json];
(
  node["power"="substation"](around:50000,40.7128,-74.0060);
  way["power"="substation"](around:50000,40.7128,-74.0060);
  relation["power"="substation"](around:50000,40.7128,-74.0060);
);
out body;
>;
out skel qt;
```

#### Power Station Query
```xml
[out:json];
(
  node["power"="plant"](around:50000,40.7128,-74.0060);
  way["power"="plant"](around:50000,40.7128,-74.0060);
  relation["power"="plant"](around:50000,40.7128,-74.0060);
);
out body;
>;
out skel qt;
```

#### Transmission Line Query
```xml
[out:json];
(
  way["power"="line"](around:50000,40.7128,-74.0060);
  way["power"="cable"](around:50000,40.7128,-74.0060);
);
out body;
>;
out skel qt;
```

### Data Parsing

#### Substation Data Extraction

| OSM Tag | Internal Field | Description |
|---------|----------------|-------------|
| `power=substation` | Type | Identifies as substation |
| `substation=transmission` | SubstationType::TRANSMISSION | High voltage transmission |
| `substation=distribution` | SubstationType::DISTRIBUTION | Medium voltage distribution |
| `substation=switching` | SubstationType::SWITCHING | Circuit switching only |
| `substation=converter` | SubstationType::CONVERTER | AC/DC converter |
| `voltage=345` | voltage_kv | Voltage level in kV |
| `capacity=500` | capacity_mva | Capacity in MVA |
| `barrier=fence` | is_fenced | Fencing status |
| `operator=ConEd` | operator_name | Utility operator |
| `name=345kV_Sub` | substation_id | Station identifier |

#### Power Station Data Extraction

| OSM Tag | Internal Field | Description |
|---------|----------------|-------------|
| `power=plant` | Type | Identifies as power plant |
| `plant:source=coal` | PowerStationType::THERMAL | Thermal power plant |
| `plant:source=nuclear` | PowerStationType::NUCLEAR | Nuclear power plant |
| `plant:source=hydro` | PowerStationType::HYDROELECTRIC | Hydroelectric plant |
| `plant:source=wind` | PowerStationType::WIND | Wind farm |
| `plant:source=solar` | PowerStationType::SOLAR | Solar farm |
| `plant:output:electricity=1000` | capacity_mw | Capacity in MW |
| `plant:output:electricity:current=800` | current_output_mw | Current output in MW |
| `barrier=fence` | is_fenced | Fencing status |
| `operator=PSEG` | operator_name | Utility operator |
| `name=Coal_Plant_1` | station_id | Station identifier |

## Configuration

### Feature Toggle Control

```ini
# configs/feature_toggles.conf
[noise_analysis_features]
enable_openinframap_integration = false  # Off by default
```

### Programmatic Configuration

```cpp
// Enable Open Infrastructure Map integration
atmosphericNoise.setFeatureEnabled("openinframap_integration", true);

// Configure data source
auto& data_source = FGCom_OpenInfraMapDataSource::getInstance();
data_source.setOverpassAPIUrl("https://overpass-api.de/api/interpreter");
data_source.setTimeout(30);
data_source.setUpdateInterval(24.0f);  // 24 hours
data_source.setSearchRadius(50.0f);    // 50 km radius
data_source.enableSubstationData(true);
data_source.enablePowerStationData(true);
data_source.setCacheDirectory("./cache/openinframap/");
```

### Advanced Configuration

```cpp
// Custom configuration
FGCom_OpenInfraMapDataSource::OpenInfraMapConfig config;
config.overpass_api_url = "https://overpass-api.de/api/interpreter";
config.user_agent = "FGCom-mumble/1.0";
config.timeout_seconds = 30;
config.max_retries = 3;
config.update_interval_hours = 24.0f;
config.enable_substation_data = true;
config.enable_power_station_data = true;
config.enable_transmission_line_data = false;
config.search_radius_km = 50.0f;
config.cache_data = true;
config.cache_directory = "./cache/openinframap/";

data_source.setConfig(config);
```

## Usage Examples

### Basic Integration

```cpp
// Get data source instance
auto& data_source = FGCom_OpenInfraMapDataSource::getInstance();

// Fetch substation data for NYC area
bool success = data_source.fetchSubstationData(40.7128, -74.0060, 50.0f);
if (success) {
    auto substations = data_source.getSubstations(40.7128, -74.0060, 50.0f);
    std::cout << "Found " << substations.size() << " substations" << std::endl;
}

// Fetch power station data
success = data_source.fetchPowerStationData(40.7128, -74.0060, 50.0f);
if (success) {
    auto power_stations = data_source.getPowerStations(40.7128, -74.0060, 50.0f);
    std::cout << "Found " << power_stations.size() << " power stations" << std::endl;
}
```

### Integration with Noise Analysis

```cpp
// Enable Open Infrastructure Map integration
atmosphericNoise.enableOpenInfraMapIntegration(true);

// Update infrastructure data from Open Infrastructure Map
atmosphericNoise.updateFromOpenInfraMap(40.7128, -74.0060, 50.0f);

// Calculate noise floor with infrastructure data
float noise_floor = atmosphericNoise.calculateNoiseFloor(40.7128, -74.0060, 14.230f);
```

### Callback Integration

```cpp
// Set up callbacks for data updates
data_source.setSubstationUpdateCallback([](const std::vector<Substation>& substations) {
    std::cout << "Updated " << substations.size() << " substations" << std::endl;
    // Update noise analysis with new data
    atmosphericNoise.updateFromOpenInfraMap(40.7128, -74.0060, 50.0f);
});

data_source.setPowerStationUpdateCallback([](const std::vector<PowerStation>& power_stations) {
    std::cout << "Updated " << power_stations.size() << " power stations" << std::endl;
    // Update noise analysis with new data
    atmosphericNoise.updateFromOpenInfraMap(40.7128, -74.0060, 50.0f);
});
```

## Data Management

### Caching System

The integration includes a comprehensive caching system:

```cpp
// Enable caching
data_source.setCacheDirectory("./cache/openinframap/");

// Check cache status
if (data_source.isCacheValid("substations_nyc.json")) {
    // Load from cache
    std::string cached_data;
    data_source.loadFromCache("substations_nyc.json", cached_data);
} else {
    // Fetch fresh data
    data_source.fetchSubstationData(40.7128, -74.0060, 50.0f);
}
```

### Data Validation

```cpp
// Validate substation data
for (const auto& substation : substations) {
    if (OpenInfraMapUtils::validateSubstationData(substation)) {
        // Valid substation data
        atmosphericNoise.addSubstation(substation);
    }
}

// Validate power station data
for (const auto& station : power_stations) {
    if (OpenInfraMapUtils::validatePowerStationData(station)) {
        // Valid power station data
        atmosphericNoise.addPowerStation(station);
    }
}
```

## Performance Considerations

### API Rate Limits

- **Overpass API**: Respects rate limits and implements retry logic
- **Timeout Handling**: Configurable timeouts for API calls
- **Caching**: Reduces API calls through intelligent caching
- **Batch Processing**: Efficient data processing and storage

### Memory Usage

- **Substation Data**: ~150 bytes per substation
- **Power Station Data**: ~200 bytes per power station
- **Typical Load**: 100-1000 substations, 10-100 power stations
- **Memory Impact**: 15KB-200KB for typical datasets

### Optimization Strategies

1. **Spatial Indexing**: Efficient geographic data organization
2. **Distance Culling**: Only process relevant infrastructure
3. **Caching**: Reduce API calls through intelligent caching
4. **Background Updates**: Non-blocking data updates
5. **Batch Processing**: Efficient data processing

## Error Handling

### Common Issues

1. **API Timeouts**: Network connectivity issues
2. **Rate Limiting**: Too many API requests
3. **Data Parsing Errors**: Invalid JSON responses
4. **Cache Issues**: Corrupted or outdated cache files

### Error Recovery

```cpp
// Check for errors
std::string error = data_source.getLastError();
if (!error.empty()) {
    std::cerr << "Open Infrastructure Map error: " << error << std::endl;
}

// Retry with exponential backoff
for (int retry = 0; retry < 3; ++retry) {
    if (data_source.fetchSubstationData(40.7128, -74.0060, 50.0f)) {
        break; // Success
    }
    std::this_thread::sleep_for(std::chrono::seconds(1 << retry));
}
```

## Real-World Examples

### Urban Area (New York City)

**Location**: Manhattan, NYC
- **Substations**: 50+ transmission and distribution substations
- **Power Stations**: 5+ thermal and renewable power plants
- **Coverage**: 50 km radius
- **Data Sources**: ConEd, PSEG, other utilities
- **Update Frequency**: Daily

### Rural Area (Upstate New York)

**Location**: Rural upstate NY
- **Substations**: 10-20 distribution substations
- **Power Stations**: 2-5 hydroelectric and thermal plants
- **Coverage**: 100 km radius
- **Data Sources**: Local utilities, NYPA
- **Update Frequency**: Weekly

### Industrial Area (New Jersey)

**Location**: Industrial New Jersey
- **Substations**: 30+ industrial and transmission substations
- **Power Stations**: 10+ thermal and renewable plants
- **Coverage**: 75 km radius
- **Data Sources**: PSEG, industrial operators
- **Update Frequency**: Daily

## API Reference

### Data Source Methods

```cpp
// Configuration
void setConfig(const OpenInfraMapConfig& config);
void setOverpassAPIUrl(const std::string& url);
void setTimeout(int seconds);
void setUpdateInterval(float hours);
void setSearchRadius(float radius_km);

// Data fetching
bool fetchSubstationData(double lat, double lon, float radius_km = 50.0f);
bool fetchPowerStationData(double lat, double lon, float radius_km = 50.0f);
bool fetchAllData(double lat, double lon, float radius_km = 50.0f);

// Data access
std::vector<Substation> getSubstations(double lat, double lon, float radius_km = 50.0f);
std::vector<PowerStation> getPowerStations(double lat, double lon, float radius_km = 50.0f);

// Status and diagnostics
bool isDataAvailable() const;
std::string getStatusString() const;
std::string getLastError() const;
```

### Noise Analysis Integration

```cpp
// Enable integration
void enableOpenInfraMapIntegration(bool enable);
bool isOpenInfraMapIntegrationEnabled() const;

// Update from Open Infrastructure Map
void updateFromOpenInfraMap(double lat, double lon, float radius_km = 50.0f);

// Status
std::string getOpenInfraMapStatus() const;
```

## Future Enhancements

### Planned Features

1. **Real-time Updates**: WebSocket integration for live data updates
2. **Advanced Filtering**: Filter by voltage level, capacity, operator
3. **Historical Data**: Track infrastructure changes over time
4. **Machine Learning**: Predictive modeling for infrastructure growth
5. **Geographic Clustering**: Efficient spatial data organization

### Research Areas

1. **Data Quality**: Validation and quality assurance for OSM data
2. **Performance Optimization**: Advanced caching and indexing strategies
3. **Integration**: Enhanced integration with other data sources
4. **Standardization**: Industry standards for infrastructure data exchange

## Troubleshooting

### Common Issues

1. **No Data Retrieved**: Check API connectivity and query syntax
2. **Parsing Errors**: Validate JSON response format
3. **Performance Issues**: Optimize caching and query parameters
4. **Memory Usage**: Monitor data storage and cleanup

### Debug Information

```cpp
// Get comprehensive status
std::string status = data_source.getStatusString();
std::cout << status << std::endl;

// Check data availability
if (data_source.isDataAvailable()) {
    std::cout << "Data is available" << std::endl;
} else {
    std::cout << "No data available" << std::endl;
}

// Get error information
std::string error = data_source.getLastError();
if (!error.empty()) {
    std::cerr << "Error: " << error << std::endl;
}
```

## Conclusion

The Open Infrastructure Map integration provides comprehensive, real-time electrical infrastructure data for enhanced noise floor calculations. This integration enables accurate modeling of electrical infrastructure impact on radio communications by leveraging the extensive OpenStreetMap database through the Overpass API.

The implementation supports multiple infrastructure types, intelligent caching, error handling, and seamless integration with the existing noise analysis system, providing a robust foundation for realistic noise floor modeling with real-world infrastructure data.

## Attribution

This integration uses data from OpenStreetMap contributors and the Overpass API. Please ensure proper attribution when using this data source:

- **Data Source**: OpenStreetMap contributors
- **API**: Overpass API
- **License**: ODbL (Open Database License)
- **Website**: [https://openinframap.org](https://openinframap.org)
