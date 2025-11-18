# Propagation Modeling Updates

This document outlines the updates to propagation modeling for new bands and frequency ranges in the FGCom-mumble system.

## Overview

The propagation modeling system has been updated to support the new bands (4m, 2200m, 630m) and international frequency allocations with accurate propagation characteristics for each band.

## New Band Propagation Characteristics

### 4m Band (69.9-70.5 MHz)
- **Propagation Type**: Line of sight (LOS)
- **Atmospheric Effects**: Minimal tropospheric ducting
- **Ground Wave**: Limited ground wave propagation
- **Ionospheric Effects**: No ionospheric reflection
- **Range**: 50-200 km typical
- **Antenna Height**: Significant impact on range
- **Terrain Effects**: Major impact on propagation

### 2200m Band (135.7-137.8 kHz)
- **Propagation Type**: Ground wave dominant
- **Atmospheric Effects**: Minimal atmospheric absorption
- **Ground Wave**: Excellent ground wave propagation
- **Ionospheric Effects**: No ionospheric reflection
- **Range**: 100-500 km typical
- **Antenna Height**: Moderate impact on range
- **Terrain Effects**: Moderate impact on propagation

### 630m Band (472-479 kHz)
- **Propagation Type**: Ground wave dominant
- **Atmospheric Effects**: Minimal atmospheric absorption
- **Ground Wave**: Good ground wave propagation
- **Ionospheric Effects**: No ionospheric reflection
- **Range**: 50-300 km typical
- **Antenna Height**: Moderate impact on range
- **Terrain Effects**: Moderate impact on propagation

## Propagation Model Implementation

### Ground Wave Propagation
```cpp
// Ground wave propagation model for LF bands
class GroundWavePropagation {
public:
    float calculateGroundWaveLoss(float frequency_khz, float distance_km, 
                                 float ground_conductivity, float ground_permittivity);
    float calculateGroundWaveAttenuation(float frequency_khz, float distance_km);
    float calculateGroundWaveRange(float frequency_khz, float power_watts, 
                                  float antenna_gain, float noise_floor);
};
```

### Line of Sight Propagation
```cpp
// Line of sight propagation model for VHF bands
class LineOfSightPropagation {
public:
    float calculateLOSLoss(float frequency_mhz, float distance_km, 
                          float antenna_height_m, float target_height_m);
    float calculateLOSRange(float frequency_mhz, float power_watts, 
                           float antenna_gain, float noise_floor);
    bool isLOSBlocked(float distance_km, float antenna_height_m, 
                     float target_height_m, float terrain_height_m);
};
```

### Atmospheric Effects
```cpp
// Atmospheric effects model
class AtmosphericEffects {
public:
    float calculateTroposphericDucting(float frequency_mhz, float distance_km, 
                                       float humidity, float temperature);
    float calculateAtmosphericAbsorption(float frequency_mhz, float distance_km, 
                                        float humidity, float pressure);
    float calculateRefraction(float frequency_mhz, float distance_km, 
                              float temperature, float pressure);
};
```

## Band-Specific Models

### 4m Band Model
```cpp
// 4m band propagation model
class Band4mPropagation {
public:
    float calculateSignalStrength(float frequency_mhz, float distance_km, 
                                 float power_watts, float antenna_gain, 
                                 float antenna_height_m, float target_height_m);
    float calculatePathLoss(float frequency_mhz, float distance_km, 
                           float antenna_height_m, float target_height_m);
    bool isFrequencyValid(float frequency_mhz);
    float getMaxRange(float frequency_mhz, float power_watts, 
                     float antenna_gain, float noise_floor);
};
```

### 2200m Band Model
```cpp
// 2200m band propagation model
class Band2200mPropagation {
public:
    float calculateSignalStrength(float frequency_khz, float distance_km, 
                                 float power_watts, float antenna_gain, 
                                 float ground_conductivity);
    float calculatePathLoss(float frequency_khz, float distance_km, 
                           float ground_conductivity);
    bool isFrequencyValid(float frequency_khz);
    float getMaxRange(float frequency_khz, float power_watts, 
                     float antenna_gain, float noise_floor);
};
```

### 630m Band Model
```cpp
// 630m band propagation model
class Band630mPropagation {
public:
    float calculateSignalStrength(float frequency_khz, float distance_km, 
                                 float power_watts, float antenna_gain, 
                                 float ground_conductivity);
    float calculatePathLoss(float frequency_khz, float distance_km, 
                           float ground_conductivity);
    bool isFrequencyValid(float frequency_khz);
    float getMaxRange(float frequency_khz, float power_watts, 
                     float antenna_gain, float noise_floor);
};
```

## International Propagation Models

### ITU Region 1 (Europe, Africa, Middle East)
- **4m Band**: Line of sight propagation
- **2200m Band**: Ground wave propagation
- **630m Band**: Ground wave propagation
- **Regional Variations**: Considered in modeling

### ITU Region 2 (Americas)
- **4m Band**: Line of sight propagation
- **2200m Band**: Ground wave propagation
- **630m Band**: Ground wave propagation
- **Regional Variations**: Considered in modeling

### ITU Region 3 (Asia-Pacific)
- **4m Band**: Line of sight propagation
- **2200m Band**: Ground wave propagation
- **630m Band**: Ground wave propagation
- **Regional Variations**: Considered in modeling

## Terrain Effects

### Terrain Modeling
```cpp
// Terrain effects on propagation
class TerrainEffects {
public:
    float calculateTerrainLoss(float frequency_mhz, float distance_km, 
                              float terrain_height_m, float antenna_height_m);
    float calculateTerrainGain(float frequency_mhz, float distance_km, 
                              float terrain_height_m, float antenna_height_m);
    bool isTerrainBlocked(float distance_km, float terrain_height_m, 
                         float antenna_height_m, float target_height_m);
};
```

### Ground Conductivity
```cpp
// Ground conductivity effects
class GroundConductivity {
public:
    float getGroundConductivity(float latitude, float longitude);
    float getGroundPermittivity(float latitude, float longitude);
    float calculateGroundWaveAttenuation(float frequency_khz, float distance_km, 
                                         float ground_conductivity);
};
```

## Weather Effects

### Atmospheric Conditions
```cpp
// Weather effects on propagation
class WeatherEffects {
public:
    float calculateHumidityEffects(float frequency_mhz, float distance_km, 
                                  float humidity_percent);
    float calculateTemperatureEffects(float frequency_mhz, float distance_km, 
                                     float temperature_celsius);
    float calculatePressureEffects(float frequency_mhz, float distance_km, 
                                  float pressure_mbar);
};
```

### Seasonal Variations
```cpp
// Seasonal propagation variations
class SeasonalVariations {
public:
    float calculateSeasonalEffects(float frequency_mhz, float distance_km, 
                                  int month, float latitude);
    float calculateDayNightEffects(float frequency_mhz, float distance_km, 
                                   bool is_daytime);
    float calculateSolarEffects(float frequency_mhz, float distance_km, 
                               float solar_flux);
};
```

## Implementation Details

### Model Integration
```cpp
// Integrated propagation model
class IntegratedPropagationModel {
public:
    float calculateTotalPathLoss(float frequency_mhz, float distance_km, 
                                float power_watts, float antenna_gain, 
                                float antenna_height_m, float target_height_m,
                                float ground_conductivity, float humidity, 
                                float temperature, float pressure);
    float calculateSignalStrength(float frequency_mhz, float distance_km, 
                                 float power_watts, float antenna_gain, 
                                 float antenna_height_m, float target_height_m,
                                 float ground_conductivity, float humidity, 
                                 float temperature, float pressure);
    bool isCommunicationPossible(float frequency_mhz, float distance_km, 
                                float power_watts, float antenna_gain, 
                                float antenna_height_m, float target_height_m,
                                float ground_conductivity, float humidity, 
                                float temperature, float pressure, 
                                float noise_floor);
};
```

### Performance Optimization
```cpp
// Performance optimization
class PropagationModelOptimizer {
public:
    void precalculateCommonValues();
    void cacheFrequentCalculations();
    void optimizeForFrequency(float frequency_mhz);
    void optimizeForDistance(float distance_km);
};
```

## Validation and Testing

### Model Validation
- **Theoretical Validation**: Compare with theoretical models
- **Empirical Validation**: Compare with real-world measurements
- **Statistical Validation**: Analyze prediction accuracy
- **Performance Validation**: Ensure computational efficiency

### Test Cases
- **Frequency Range Tests**: Test all frequency ranges
- **Distance Range Tests**: Test all distance ranges
- **Terrain Tests**: Test various terrain conditions
- **Weather Tests**: Test various weather conditions

## Documentation

### User Documentation
- **Propagation Guide**: User guide for propagation modeling
- **Band Characteristics**: Characteristics of each band
- **Regional Variations**: Regional propagation differences
- **Best Practices**: Best practices for propagation modeling

### Developer Documentation
- **API Reference**: Complete API reference
- **Implementation Guide**: Implementation guide for developers
- **Testing Guide**: Testing guide for developers
- **Performance Guide**: Performance optimization guide

## Updates and Maintenance

### Regular Updates
- **Model Updates**: Regular updates to propagation models
- **Data Updates**: Regular updates to propagation data
- **Validation Updates**: Regular validation of models
- **Performance Updates**: Regular performance optimizations

### Update Process
1. **Review Changes**: Review propagation model changes
2. **Update Models**: Update propagation models
3. **Test Changes**: Test propagation model changes
4. **Validate Results**: Validate propagation model results
5. **Deploy Updates**: Deploy propagation model updates

## References

- ITU Radio Regulations
- ITU-R Recommendations
- Propagation modeling standards
- International propagation databases
- Regional propagation studies
