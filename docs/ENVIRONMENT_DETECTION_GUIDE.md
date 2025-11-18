# Environment Detection Guide

## Overview

The FGCom-mumble system provides comprehensive environment detection capabilities for realistic noise floor calculations. This guide explains how the system automatically detects environment types from coordinates and how to manually override these settings for specific scenarios.

## Environment Detection Methods

### 1. Automatic Detection

#### GPS Coordinate-Based Detection
The system automatically detects environment type based on GPS coordinates:

```cpp
// Automatic detection from GPS coordinates
EnvironmentType env = noise.detectEnvironmentFromCoordinates(lat, lon);
float noise_floor = noise.calculateNoiseFloor(lat, lon, freq_mhz);
```

#### Current Implementation (Heuristic-Based)
```cpp
EnvironmentType FGCom_AtmosphericNoise::determineEnvironmentType(double lat, double lon) {
    if (std::abs(lat) > 60.0) {
        return EnvironmentType::REMOTE;  // Polar regions
    } else if (std::abs(lat) > 40.0) {
        return EnvironmentType::SUBURBAN;  // Temperate regions
    } else {
        return EnvironmentType::URBAN;  // Tropical/subtropical regions
    }
}
```

### 2. Maidenhead Locator Detection

#### Grid Square Environment Detection
```cpp
// Environment detection from Maidenhead locator
EnvironmentType env = noise.detectEnvironmentFromMaidenhead("JP88il");
float noise_floor = noise.calculateNoiseFloor(lat, lon, freq_mhz);
```

#### Grid Square Precision
- **2-character grid**: 10° × 20° (rough location)
- **4-character grid**: 1° × 2° (city level)
- **6-character grid**: 0.1° × 0.2° (neighborhood level)

### 3. Manual Environment Override

#### String-Based Environment Setting
```cpp
// Manual environment setting by name
noise.setManualEnvironment("industrial");
noise.setManualEnvironment("urban");
noise.setManualEnvironment("suburban");
noise.setManualEnvironment("remote");
noise.setManualEnvironment("ocean");
noise.setManualEnvironment("desert");
noise.setManualEnvironment("polar");
```

#### Enum-Based Environment Setting
```cpp
// Manual environment setting by enum
noise.setManualEnvironment(EnvironmentType::INDUSTRIAL);
noise.setManualEnvironment(EnvironmentType::URBAN);
noise.setManualEnvironment(EnvironmentType::SUBURBAN);
noise.setManualEnvironment(EnvironmentType::REMOTE);
noise.setManualEnvironment(EnvironmentType::OCEAN);
noise.setManualEnvironment(EnvironmentType::DESERT);
noise.setManualEnvironment(EnvironmentType::POLAR);
```

## Environment Type Definitions

### Industrial Environment
- **S-Meter Range**: S7-S9+
- **Noise Floor**: -100 to -85 dBm
- **Characteristics**: Manufacturing, heavy industry, power plants
- **Distance Requirements**: > 10 km for quiet RF

### Urban Environment
- **S-Meter Range**: S5-S7
- **Noise Floor**: -115 to -100 dBm
- **Characteristics**: Cities, dense population, commercial areas
- **Distance Requirements**: > 20 km for quiet RF

### Suburban Environment
- **S-Meter Range**: S3-S5
- **Noise Floor**: -125 to -115 dBm
- **Characteristics**: Residential areas, moderate population
- **Distance Requirements**: > 10 km for quiet RF

### Remote Environment
- **S-Meter Range**: S1-S3
- **Noise Floor**: -140 to -125 dBm
- **Characteristics**: Rural areas, low population
- **Distance Requirements**: Already quiet

### Ocean Environment
- **S-Meter Range**: S0-S2
- **Noise Floor**: -145 to -130 dBm
- **Characteristics**: Over water, very quiet RF environment
- **Distance Requirements**: Already quiet

### Desert Environment
- **S-Meter Range**: S0-S2
- **Noise Floor**: -145 to -130 dBm
- **Characteristics**: Remote desert, minimal noise sources
- **Distance Requirements**: Already quiet

### Polar Environment
- **S-Meter Range**: S0-S1
- **Noise Floor**: -145 to -135 dBm
- **Characteristics**: Arctic/Antarctic, quietest possible RF environment
- **Distance Requirements**: Already quiet

## Advanced Detection Features (Optional)

### ITU-R P.372 Model
```ini
[noise_floor_advanced]
enable_itu_p372_model = true
```
- **International Standard**: ITU-R P.372-14 recommendation
- **Frequency-Dependent**: Different noise per frequency band
- **Geographic Factors**: Tropical/polar enhancements
- **Seasonal Variations**: Summer/winter noise differences
- **Time of Day Effects**: Day/night noise variations
- **Solar Activity**: Solar flux and geomagnetic effects

### OpenStreetMap Integration
```ini
[noise_floor_advanced]
enable_osm_integration = true
```
- **Land Use Data**: Industrial, commercial, residential areas
- **Power Infrastructure**: Power lines and substations
- **Transportation**: Highways, railways, airports
- **Population Density**: Urban vs rural areas
- **Real-World Data**: Actual geographic features

### Population Density Analysis
```ini
[noise_floor_advanced]
enable_population_density = true
```
- **High Population**: Higher noise levels
- **Low Population**: Lower noise levels
- **Remote Areas**: Lowest noise levels
- **Automatic Detection**: Based on population data

### Power Line Analysis
```ini
[noise_floor_advanced]
enable_power_line_analysis = true
```
- **Power Line Density**: Lines per km²
- **Distance Decay**: 1/r² for point sources
- **Frequency Effects**: Higher noise at lower frequencies
- **Weather Effects**: Wet conditions increase noise

### Traffic Analysis
```ini
[noise_floor_advanced]
enable_traffic_analysis = true
```
- **Road Type Classification**: Highway, primary, secondary roads
- **Distance Decay**: Linear decay for linear sources
- **Time of Day Effects**: Rush hour vs off-peak
- **Weather Effects**: Wet roads increase noise

### Industrial Analysis
```ini
[noise_floor_advanced]
enable_industrial_analysis = true
```
- **Industrial Area Detection**: Manufacturing zones
- **Activity Levels**: Day shift vs night shift
- **Distance Decay**: 1/r² for point sources
- **Frequency Effects**: Higher noise at lower frequencies

## API Usage Examples

### Basic Environment Detection
```cpp
#include "atmospheric_noise.h"

void demonstrateEnvironmentDetection() {
    auto& noise = FGCom_AtmosphericNoise::getInstance();
    
    // Example 1: GPS-based automatic detection
    double lat = 40.7128;  // New York City
    double lon = -74.0060;
    float freq = 14.0f;
    
    EnvironmentType env = noise.detectEnvironmentFromCoordinates(lat, lon);
    float noise_floor = noise.calculateNoiseFloor(lat, lon, freq);
    
    std::cout << "Detected Environment: " << (int)env << std::endl;
    std::cout << "Noise Floor: " << noise_floor << " dBm" << std::endl;
}
```

### Manual Environment Override
```cpp
void demonstrateManualOverride() {
    auto& noise = FGCom_AtmosphericNoise::getInstance();
    
    // Example 2: Manual environment setting
    noise.setManualEnvironment("remote");
    float noise_floor = noise.calculateNoiseFloor(lat, lon, freq);
    
    std::cout << "Manual Environment: Remote" << std::endl;
    std::cout << "Noise Floor: " << noise_floor << " dBm" << std::endl;
}
```

### Maidenhead Locator Support
```cpp
void demonstrateMaidenheadDetection() {
    auto& noise = FGCom_AtmosphericNoise::getInstance();
    
    // Example 3: Maidenhead locator detection
    std::string maidenhead = "JP88il";
    EnvironmentType env = noise.detectEnvironmentFromMaidenhead(maidenhead);
    float noise_floor = noise.calculateNoiseFloor(lat, lon, freq);
    
    std::cout << "Maidenhead: " << maidenhead << std::endl;
    std::cout << "Detected Environment: " << (int)env << std::endl;
    std::cout << "Noise Floor: " << noise_floor << " dBm" << std::endl;
}
```

### Environment Status Checking
```cpp
void demonstrateEnvironmentStatus() {
    auto& noise = FGCom_AtmosphericNoise::getInstance();
    
    // Check if manual environment is set
    if (noise.isManualEnvironmentSet()) {
        EnvironmentType env = noise.getManualEnvironment();
        std::cout << "Manual Environment: " << (int)env << std::endl;
    } else {
        std::cout << "Using automatic detection" << std::endl;
    }
    
    // Clear manual environment
    noise.clearManualEnvironment();
    std::cout << "Manual environment cleared" << std::endl;
}
```

## Configuration

### Basic Configuration
```ini
[noise_floor]
enable_environmental_effects = true
enable_automatic_detection = true
enable_manual_override = true
default_environment = suburban
```

### Advanced Configuration
```ini
[noise_floor_advanced]
enable_itu_p372_model = false
enable_osm_integration = false
enable_population_density = false
enable_power_line_analysis = false
enable_traffic_analysis = false
enable_industrial_analysis = false
```

### Environment-Specific Settings
```ini
[environment_detection]
enable_maidenhead_support = true
enable_gps_detection = true
enable_manual_override = true
default_fallback_environment = suburban
```

## Best Practices

### For Automatic Detection
1. **Use GPS Coordinates**: Most accurate for automatic detection
2. **Verify Results**: Check detected environment type
3. **Manual Override**: Use manual setting when automatic detection is incorrect
4. **Update Coordinates**: Ensure coordinates are current

### For Manual Override
1. **Specific Scenarios**: Use for specific simulation scenarios
2. **Testing**: Use for testing different environment types
3. **Real-World Accuracy**: Set based on actual location characteristics
4. **Clear Override**: Clear manual setting when done

### For Maidenhead Locators
1. **Precision**: Use 6-character grid for best accuracy
2. **Verification**: Check grid square accuracy
3. **Fallback**: Use GPS coordinates if Maidenhead detection fails
4. **Manual Override**: Use manual setting for uncertain locations

## Troubleshooting

### Incorrect Environment Detection
- **Check Coordinates**: Verify GPS coordinates are correct
- **Manual Override**: Use manual environment setting
- **Update System**: Ensure latest version with improved detection
- **Report Issues**: Report detection problems for improvement

### High Noise Levels
- **Verify Environment**: Check if environment type is correct
- **Distance Check**: Ensure sufficient distance from noise sources
- **Manual Override**: Use manual setting for specific scenarios
- **Time Factors**: Consider time of day and weather effects

### Low Noise Levels
- **Environment Check**: Verify environment type is appropriate
- **Location Check**: Ensure coordinates are correct
- **Manual Override**: Use manual setting if needed
- **Distance Check**: Verify distance from noise sources

## Conclusion

The FGCom-mumble environment detection system provides flexible and accurate noise floor calculations based on location. Understanding the different detection methods and when to use manual overrides helps users achieve realistic radio simulation in flight simulators.
