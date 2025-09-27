# Noise Floor Distance Guide

## Overview

The FGCom-mumble system implements realistic noise floor calculations based on distance from various noise sources. This guide explains how different environments and distances affect radio noise levels, helping users understand where to operate for optimal RF conditions.

## Environment Types and S-Meter Classifications

### Environment Classifications

| Environment Type | S-Meter Range | Noise Floor (dBm) | Description |
|------------------|---------------|-------------------|-------------|
| **Industrial** | S7-S9+ | -100 to -85 | Manufacturing, heavy industry |
| **Urban** | S5-S7 | -115 to -100 | Cities, dense population |
| **Suburban** | S3-S5 | -125 to -115 | Residential areas, moderate noise |
| **Remote** | S1-S3 | -140 to -125 | Rural areas, low population |
| **Ocean** | S0-S2 | -145 to -130 | Over water, very quiet |
| **Desert** | S0-S2 | -145 to -130 | Remote desert, minimal noise |
| **Polar** | S0-S1 | -145 to -135 | Arctic/Antarctic, quietest possible |

## Distance-Based Noise Falloff

### Industrial Areas

Industrial noise sources follow **inverse square law (1/r²)** for point sources:

| Distance | Noise Contribution | Environment Impact |
|----------|-------------------|-------------------|
| **< 1 km** | **15 dB** | Very high noise (S7-S9+) |
| **1-5 km** | **8 dB** | High noise (S5-S7) |
| **5-10 km** | **3 dB** | Medium noise (S3-S5) |
| **> 10 km** | **Negligible** | Low noise (S1-S3) |

**Minimum Distance for Quiet RF (S0-S2)**: **> 10 km** from industrial areas

### Highway Traffic

Traffic noise follows **linear distance decay**:

| Distance | Noise Contribution | Environment Impact |
|----------|-------------------|-------------------|
| **< 1 km** | **8 dB** | High noise from close highways |
| **1-5 km** | **4 dB** | Medium noise from distant highways |
| **> 5 km** | **Negligible** | Low noise impact |

**Minimum Distance for Quiet RF**: **> 5 km** from major highways

### Power Lines

Electrical power lines generate RF noise:

| Distance | Noise Contribution | Environment Impact |
|----------|-------------------|-------------------|
| **< 5 km** | **2 dB** | Low-medium noise impact |
| **> 5 km** | **Negligible** | Minimal noise impact |

**Minimum Distance for Quiet RF**: **> 5 km** from power lines

### Railway Lines

Railway electrical systems create noise:

| Distance | Noise Contribution | Environment Impact |
|----------|-------------------|-------------------|
| **< 3 km** | **2 dB** | Low noise impact |
| **> 3 km** | **Negligible** | Minimal noise impact |

**Minimum Distance for Quiet RF**: **> 3 km** from railway lines

## Real-World Examples

### New York City (Manhattan)
- **Environment**: Industrial/Urban
- **Noise Level**: S7-S9+ (very noisy)
- **Distance to Quiet**: **> 50 km** from city center
- **Characteristics**: Close to industrial areas (0.5 km), highways (0.2 km)

### NYC Metro Area
- **Environment**: Urban
- **Noise Level**: S5-S7 (noisy)
- **Distance to Quiet**: **> 20 km** from metro area
- **Characteristics**: Medium distance to industrial (1.0 km), highways (0.5 km)

### Suburban Areas
- **Environment**: Suburban
- **Noise Level**: S3-S5 (moderate)
- **Distance to Quiet**: **> 10 km** from suburbs
- **Characteristics**: Medium distance to industrial (3.0 km), highways (2.0 km)

### Rural Areas
- **Environment**: Remote
- **Noise Level**: S1-S3 (quiet)
- **Distance to Quiet**: **Already quiet**
- **Characteristics**: Far from industrial (8.0 km), highways (5.0 km)

## Practical Distance Guidelines

### For S0-S2 (Quietest RF Environment)
- **Industrial Areas**: **> 10 km**
- **Major Highways**: **> 5 km**
- **Railway Lines**: **> 3 km**
- **Power Lines**: **> 5 km**
- **Urban Centers**: **> 20 km**

### For S1-S3 (Remote Environment)
- **Industrial Areas**: **> 5 km**
- **Major Highways**: **> 2 km**
- **Railway Lines**: **> 1 km**
- **Power Lines**: **> 2 km**
- **Urban Centers**: **> 10 km**

### For S3-S5 (Suburban Environment)
- **Industrial Areas**: **2-5 km**
- **Major Highways**: **1-2 km**
- **Railway Lines**: **0.5-1 km**
- **Power Lines**: **1-2 km**
- **Urban Centers**: **5-10 km**

## Time and Weather Effects

### Time of Day Factors
- **Night (22:00-06:00)**: **-5 dB** (lower noise)
- **Day (06:00-18:00)**: **0 dB** (normal noise)
- **Dusk/Dawn (18:00-22:00)**: **-2.5 dB** (transitional)

### Weather Effects
- **Thunderstorms**: **+20%** noise increase
- **Precipitation**: **+10%** noise increase
- **Clear Weather**: **Normal** noise levels

### Industrial Activity Levels
- **Day Shift**: **+30%** noise increase
- **Night Shift**: **-50%** noise decrease
- **Weekends**: **-20%** noise decrease

## API Usage

### Automatic Environment Detection
```cpp
// Auto-detect environment from GPS coordinates
EnvironmentType env = noise.detectEnvironmentFromCoordinates(lat, lon);
float noise_floor = noise.calculateNoiseFloor(lat, lon, freq_mhz);
```

### Manual Environment Setting
```cpp
// Manual environment override
noise.setManualEnvironment("remote");
float noise_floor = noise.calculateNoiseFloor(lat, lon, freq_mhz);
```

### Maidenhead Locator Support
```cpp
// Environment detection from Maidenhead locator
EnvironmentType env = noise.detectEnvironmentFromMaidenhead("JP88il");
float noise_floor = noise.calculateNoiseFloor(lat, lon, freq_mhz);
```

## Configuration

### Environment Detection Settings
```ini
[noise_floor]
enable_environmental_effects = true
enable_automatic_detection = true
enable_manual_override = true
default_environment = suburban
```

### Advanced Features (Optional)
```ini
[noise_floor_advanced]
enable_itu_p372_model = false
enable_osm_integration = false
enable_population_density = false
enable_power_line_analysis = false
enable_traffic_analysis = false
enable_industrial_analysis = false
```

## Best Practices

### For Quiet RF Operations
1. **Choose Remote Locations**: > 10 km from industrial areas
2. **Avoid Major Roads**: > 5 km from highways
3. **Check Power Lines**: > 5 km from electrical infrastructure
4. **Consider Time**: Operate during night hours for lower noise
5. **Weather Awareness**: Avoid operating during thunderstorms

### For Realistic Simulation
1. **Use Automatic Detection**: Let the system detect environment from coordinates
2. **Manual Override**: Set environment manually for specific scenarios
3. **Time of Day**: Consider time-based noise variations
4. **Weather Effects**: Account for weather-related noise changes

## Troubleshooting

### High Noise Levels
- **Check Distance**: Ensure sufficient distance from noise sources
- **Verify Environment**: Confirm correct environment type detection
- **Time Factors**: Consider time of day and weather effects
- **Manual Override**: Use manual environment setting if needed

### Low Noise Levels
- **Verify Location**: Ensure coordinates are correct
- **Check Environment**: Confirm environment type is appropriate
- **Distance Check**: Verify distance from noise sources
- **Time Factors**: Consider time of day effects

## Conclusion

The FGCom-mumble noise floor system provides realistic RF noise modeling based on distance from various noise sources. Understanding these distance relationships helps users choose optimal operating locations and configure realistic radio environments for flight simulation.
