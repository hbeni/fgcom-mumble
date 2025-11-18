# Feature Toggle System Documentation

## Overview

The FGCom-mumble Feature Toggle System provides runtime control over 107 configurable features across 17 categories, enabling dynamic customization of system behavior without code changes or restarts.

## System Architecture

### Core Components

- **FeatureToggleManager**: Central management system for all feature toggles
- **Feature Categories**: 17 distinct categories organizing related features
- **Configuration System**: File-based and runtime configuration management
- **Performance Tracking**: Usage monitoring and impact analysis
- **Dependency Management**: Feature dependency and conflict resolution

## Feature Categories

### 1. Threading Features (7 features)
- **THREADING_SOLAR_DATA**: Solar data processing threads
- **THREADING_PROPAGATION**: Propagation calculation threads
- **THREADING_ANTENNA_PATTERNS**: Antenna pattern processing threads
- **THREADING_AUDIO_PROCESSING**: Audio processing threads
- **THREADING_API_SERVER**: API server threads
- **THREADING_LIGHTNING_DATA**: Lightning data processing threads
- **THREADING_WEATHER_DATA**: Weather data processing threads

### 2. GPU Acceleration Features (6 features)
- **GPU_ANTENNA_PATTERNS**: GPU-accelerated antenna pattern calculations
- **GPU_PROPAGATION_MODELING**: GPU-accelerated propagation modeling
- **GPU_AUDIO_PROCESSING**: GPU-accelerated audio processing
- **GPU_FILTER_APPLICATION**: GPU-accelerated filter operations
- **GPU_MEMORY_MANAGEMENT**: GPU memory optimization
- **GPU_PARALLEL_PROCESSING**: GPU parallel processing capabilities

### 3. Solar Data Features (5 features)
- **SOLAR_DATA_REAL_TIME**: Real-time solar data integration
- **SOLAR_DATA_CACHING**: Solar data caching system
- **SOLAR_DATA_PREDICTION**: Solar activity prediction
- **SOLAR_DATA_ANALYSIS**: Solar data analysis algorithms
- **SOLAR_DATA_VALIDATION**: Solar data validation and quality control

### 4. Propagation Features (8 features)
- **PROPAGATION_LINE_OF_SIGHT**: Line-of-sight propagation modeling
- **PROPAGATION_TROPOSPHERIC**: Tropospheric propagation effects
- **PROPAGATION_IONOSPHERIC**: Ionospheric propagation modeling
- **PROPAGATION_GROUND_WAVE**: Ground wave propagation
- **PROPAGATION_SKY_WAVE**: Sky wave propagation
- **PROPAGATION_DUCTING**: Atmospheric ducting effects
- **PROPAGATION_SCATTERING**: Scattering propagation models
- **PROPAGATION_ANOMALOUS**: Anomalous propagation conditions

### 5. Antenna Pattern Features (6 features)
- **ANTENNA_PATTERN_LOADING**: Antenna pattern file loading
- **ANTENNA_PATTERN_CACHING**: Antenna pattern caching
- **ANTENNA_PATTERN_INTERPOLATION**: Pattern interpolation algorithms
- **ANTENNA_PATTERN_ROTATION**: 3D antenna pattern rotation
- **ANTENNA_PATTERN_SCALING**: Pattern scaling and normalization
- **ANTENNA_PATTERN_VALIDATION**: Pattern data validation

### 6. Audio Processing Features (7 features)
- **AUDIO_FILTERING**: Audio signal filtering
- **AUDIO_COMPRESSION**: Audio compression algorithms
- **AUDIO_ENHANCEMENT**: Audio signal enhancement
- **AUDIO_NOISE_REDUCTION**: Noise reduction algorithms
- **AUDIO_EQUALIZATION**: Audio equalization
- **AUDIO_SPATIAL_PROCESSING**: Spatial audio processing
- **AUDIO_REAL_TIME**: Real-time audio processing

### 7. API Server Features (6 features)
- **API_REST_ENDPOINTS**: RESTful API endpoints
- **API_WEBSOCKET**: WebSocket real-time communication
- **API_AUTHENTICATION**: API authentication system
- **API_RATE_LIMITING**: API rate limiting
- **API_LOGGING**: API request/response logging
- **API_MONITORING**: API performance monitoring

### 8. Lightning Data Features (4 features)
- **LIGHTNING_DATA_REAL_TIME**: Real-time lightning data
- **LIGHTNING_DATA_CACHING**: Lightning data caching
- **LIGHTNING_NOISE_MODELING**: Atmospheric noise modeling
- **LIGHTNING_PROPAGATION_EFFECTS**: Lightning effects on propagation

### 9. Weather Data Features (5 features)
- **WEATHER_DATA_INTEGRATION**: Weather data integration
- **WEATHER_PROPAGATION_EFFECTS**: Weather effects on propagation
- **WEATHER_ATMOSPHERIC_MODELING**: Atmospheric condition modeling
- **WEATHER_PREDICTION**: Weather prediction algorithms
- **WEATHER_VALIDATION**: Weather data validation

### 10. Power Management Features (6 features)
- **POWER_TRANSMIT_CONTROL**: Transmit power control
- **POWER_EFFICIENCY**: Power efficiency optimization
- **POWER_MONITORING**: Power usage monitoring
- **POWER_LIMITING**: Power limiting and protection
- **POWER_THERMAL_PROTECTION**: Thermal protection systems
- **POWER_BATTERY_MANAGEMENT**: Battery management systems

### 11. Frequency Offset Features (6 features)
- **FREQUENCY_OFFSET_COMPLEX_EXPONENTIAL**: Complex exponential frequency shifting
- **FREQUENCY_OFFSET_HILBERT_TRANSFORM**: Hilbert transform frequency processing
- **FREQUENCY_OFFSET_SMOOTHING**: Frequency offset smoothing
- **FREQUENCY_OFFSET_REAL_TIME**: Real-time frequency processing
- **FREQUENCY_OFFSET_SIMD**: SIMD-optimized frequency processing
- **FREQUENCY_OFFSET_MULTI_THREADING**: Multi-threaded frequency processing

### 12. BFO Simulation Features (4 features)
- **BFO_CW_DEMODULATION**: CW demodulation with BFO
- **BFO_SSB_DEMODULATION**: SSB demodulation with BFO
- **BFO_FREQUENCY_MIXING**: Frequency mixing operations
- **BFO_PHASE_ACCUMULATION**: Phase accumulation for BFO

### 13. Filter Application Features (7 features)
- **FILTER_SSB**: Single Sideband filtering
- **FILTER_AM**: Amplitude Modulation filtering
- **FILTER_CW**: Continuous Wave filtering
- **FILTER_AVIATION**: Aviation-specific filtering
- **FILTER_MARITIME**: Maritime-specific filtering
- **FILTER_NOTCH**: Notch filtering
- **FILTER_DYNAMIC_SELECTION**: Dynamic filter selection

### 14. Fuzzy Logic Features (4 features)
- **FUZZY_PROPAGATION_MODELING**: Fuzzy logic propagation modeling
- **FUZZY_ANOMALY_DETECTION**: Anomaly detection using fuzzy logic
- **FUZZY_SPORADIC_E_SKIP**: Sporadic E skip prediction
- **FUZZY_SOLAR_FLARE_EFFECTS**: Solar flare effect modeling

### 15. Vehicle Dynamics Features (6 features)
- **VEHICLE_HEADING_TRACKING**: Vehicle heading tracking
- **VEHICLE_SPEED_TRACKING**: Vehicle speed tracking
- **VEHICLE_ATTITUDE_TRACKING**: Vehicle attitude tracking
- **VEHICLE_ALTITUDE_TRACKING**: Vehicle altitude tracking
- **VEHICLE_ANTENNA_ROTATION**: Antenna rotation tracking
- **VEHICLE_DYNAMICS_CACHING**: Vehicle dynamics caching

### 16. Debugging Features (8 features)
- **DEBUG_THREAD_OPERATIONS**: Thread operation debugging
- **DEBUG_CACHE_OPERATIONS**: Cache operation debugging
- **DEBUG_GPU_OPERATIONS**: GPU operation debugging
- **DEBUG_PROPAGATION_CALCULATIONS**: Propagation calculation debugging
- **DEBUG_AUDIO_PROCESSING**: Audio processing debugging
- **DEBUG_API_REQUESTS**: API request debugging
- **DEBUG_ERROR_LOGGING**: Error logging debugging
- **DEBUG_PERFORMANCE_LOGGING**: Performance logging debugging

### 17. Performance Monitoring Features (7 features)
- **PERFORMANCE_THREAD_STATS**: Thread performance statistics
- **PERFORMANCE_CACHE_STATS**: Cache performance statistics
- **PERFORMANCE_GPU_STATS**: GPU performance statistics
- **PERFORMANCE_MEMORY_STATS**: Memory performance statistics
- **PERFORMANCE_NETWORK_STATS**: Network performance statistics
- **PERFORMANCE_ALERTS**: Performance alert system
- **PERFORMANCE_REPORTING**: Performance reporting system

## Configuration Management

### Configuration Files

#### Primary Configuration
```ini
# configs/feature_toggles.conf
[feature_toggles]
enable_radio_communication = true
enable_terrain_analysis = true
enable_antenna_patterns = true
enable_propagation_modeling = true
```

#### Category-Specific Configuration
```ini
[radio_features]
enable_vhf_communication = true
enable_uhf_communication = true
enable_hf_communication = true
enable_amateur_radio = true
enable_military_radio = true
enable_aviation_radio = true
enable_maritime_radio = true
```

### Runtime Configuration

#### C++ API Usage
```cpp
#include "feature_toggles.h"

// Get feature toggle manager instance
auto& toggle_manager = FGCom_FeatureToggleManager::getInstance();

// Check if feature is enabled
if (toggle_manager.isFeatureEnabled(FeatureToggle::GPU_ANTENNA_PATTERNS)) {
    // Use GPU acceleration for antenna patterns
    useGPUAcceleration();
}

// Enable/disable features
toggle_manager.enableFeature(FeatureToggle::SOLAR_DATA_REAL_TIME);
toggle_manager.disableFeature(FeatureToggle::DEBUG_THREAD_OPERATIONS);

// Enable entire category
toggle_manager.enableCategory(FeatureCategory::GPU_ACCELERATION);

// Enable features by performance impact
toggle_manager.enableFeaturesByImpact("low");  // Enable only low-impact features
```

#### Configuration Loading
```cpp
// Load configuration from file
toggle_manager.loadConfigFromFile("configs/feature_toggles.conf");

// Load configuration from string
std::string config = "enable_gpu_acceleration = true\nenable_solar_data = false";
toggle_manager.loadConfigFromString(config);

// Save current configuration
toggle_manager.saveConfigToFile("configs/current_features.conf");
```

## Performance Impact Management

### Impact Levels

#### Low Impact Features
- **Memory Usage**: < 10MB additional memory
- **CPU Usage**: < 5% additional CPU
- **Network**: No additional network usage
- **Examples**: Basic logging, simple caching, lightweight monitoring

#### Medium Impact Features
- **Memory Usage**: 10-100MB additional memory
- **CPU Usage**: 5-20% additional CPU
- **Network**: Moderate network usage
- **Examples**: GPU acceleration, complex filtering, real-time data processing

#### High Impact Features
- **Memory Usage**: > 100MB additional memory
- **CPU Usage**: > 20% additional CPU
- **Network**: High network usage
- **Examples**: Full propagation modeling, comprehensive debugging, extensive monitoring

### Performance Monitoring

#### Usage Tracking
```cpp
// Record feature usage with performance impact
toggle_manager.recordFeatureUsage(FeatureToggle::GPU_ANTENNA_PATTERNS, 15.5);

// Get usage statistics
uint64_t usage_count = toggle_manager.getFeatureUsageCount(FeatureToggle::GPU_ANTENNA_PATTERNS);
double performance_impact = toggle_manager.getFeaturePerformanceImpact(FeatureToggle::GPU_ANTENNA_PATTERNS);

// Get all usage statistics
auto all_usage = toggle_manager.getAllFeatureUsageCounts();
```

#### Performance Reports
```cpp
// Generate performance report
auto report = toggle_manager.generatePerformanceReport();
std::cout << "Feature Performance Report:" << std::endl;
std::cout << "Total Features: " << report.total_features << std::endl;
std::cout << "Active Features: " << report.active_features << std::endl;
std::cout << "Average Performance Impact: " << report.average_impact << "ms" << std::endl;
```

## Dependency Management

### Feature Dependencies

#### Dependency Checking
```cpp
// Check if feature dependencies are satisfied
if (toggle_manager.checkDependencies(FeatureToggle::GPU_ANTENNA_PATTERNS)) {
    // Dependencies satisfied, can enable feature
    toggle_manager.enableFeature(FeatureToggle::GPU_ANTENNA_PATTERNS);
}

// Get dependent features
auto dependent_features = toggle_manager.getDependentFeatures(FeatureToggle::GPU_ANTENNA_PATTERNS);
```

#### Conflict Resolution
```cpp
// Check for feature conflicts
if (toggle_manager.checkConflicts(FeatureToggle::DEBUG_THREAD_OPERATIONS)) {
    // Conflicts detected, handle appropriately
    std::cout << "Feature conflicts detected!" << std::endl;
}

// Get conflicting features
auto conflicting_features = toggle_manager.getConflictingFeatures(FeatureToggle::DEBUG_THREAD_OPERATIONS);
```

### Common Dependencies

#### GPU Features
- **Requires**: GPU_ACCELERATION category enabled
- **Conflicts**: CPU-only processing features
- **Dependencies**: Memory management, parallel processing

#### Real-time Features
- **Requires**: Threading support
- **Conflicts**: Batch processing features
- **Dependencies**: Network connectivity, data sources

#### Debugging Features
- **Requires**: Logging system
- **Conflicts**: Production optimizations
- **Dependencies**: File system access, performance monitoring

## Best Practices

### Feature Toggle Strategy

#### Development Environment
```ini
# Enable all debugging features
enable_debug_logging = true
enable_performance_monitoring = true
enable_memory_tracking = true
enable_thread_monitoring = true
```

#### Production Environment
```ini
# Enable only essential features
enable_radio_communication = true
enable_terrain_analysis = true
enable_antenna_patterns = true
enable_propagation_modeling = true

# Disable debugging features
enable_debug_logging = false
enable_performance_monitoring = false
enable_memory_tracking = false
```

#### Performance-Critical Environment
```ini
# Enable only low-impact features
enable_basic_logging = true
enable_essential_caching = true
enable_minimal_monitoring = true

# Disable high-impact features
enable_gpu_acceleration = false
enable_comprehensive_debugging = false
enable_extensive_monitoring = false
```

### Configuration Management

#### Environment-Specific Configs
```bash
# Development
cp configs/feature_toggles.dev.conf configs/feature_toggles.conf

# Production
cp configs/feature_toggles.prod.conf configs/feature_toggles.conf

# Performance testing
cp configs/feature_toggles.perf.conf configs/feature_toggles.conf
```

#### Runtime Configuration Updates
```cpp
// Update configuration without restart
toggle_manager.loadConfigFromFile("configs/updated_features.conf");

// Validate configuration
if (toggle_manager.validateConfiguration()) {
    std::cout << "Configuration is valid" << std::endl;
} else {
    std::cout << "Configuration has errors" << std::endl;
}
```

## Troubleshooting

### Common Issues

#### Feature Not Working
1. **Check if feature is enabled**: `toggle_manager.isFeatureEnabled(feature)`
2. **Verify dependencies**: `toggle_manager.checkDependencies(feature)`
3. **Check for conflicts**: `toggle_manager.checkConflicts(feature)`
4. **Review configuration**: Ensure proper configuration file loading

#### Performance Issues
1. **Monitor feature usage**: Check usage statistics and performance impact
2. **Disable high-impact features**: Use `enableFeaturesByImpact("low")`
3. **Review dependencies**: Ensure only necessary features are enabled
4. **Check system resources**: Monitor CPU, memory, and network usage

#### Configuration Errors
1. **Validate configuration**: Use `validateConfiguration()`
2. **Check file syntax**: Ensure proper INI file format
3. **Verify feature names**: Use correct feature toggle names
4. **Review dependencies**: Ensure all required dependencies are met

### Debugging Tools

#### Feature Status Report
```cpp
// Generate comprehensive feature status report
auto status_report = toggle_manager.generateStatusReport();
std::cout << "Feature Status Report:" << std::endl;
std::cout << "Enabled Features: " << status_report.enabled_count << std::endl;
std::cout << "Disabled Features: " << status_report.disabled_count << std::endl;
std::cout << "Performance Impact: " << status_report.total_impact << "ms" << std::endl;
```

#### Configuration Validation
```cpp
// Validate current configuration
auto validation_result = toggle_manager.validateConfiguration();
if (validation_result.is_valid) {
    std::cout << "Configuration is valid" << std::endl;
} else {
    std::cout << "Configuration errors:" << std::endl;
    for (const auto& error : validation_result.errors) {
        std::cout << "  - " << error << std::endl;
    }
}
```

## API Reference

### Core Methods

#### Feature Control
- `bool isFeatureEnabled(FeatureToggle feature)`: Check if feature is enabled
- `bool enableFeature(FeatureToggle feature)`: Enable a feature
- `bool disableFeature(FeatureToggle feature)`: Disable a feature
- `bool toggleFeature(FeatureToggle feature)`: Toggle feature state

#### Bulk Operations
- `void enableAllFeatures()`: Enable all features
- `void disableAllFeatures()`: Disable all features
- `void enableCategory(FeatureCategory category)`: Enable category
- `void disableCategory(FeatureCategory category)`: Disable category
- `void enableFeaturesByImpact(const std::string& impact_level)`: Enable by impact

#### Configuration Management
- `bool loadConfigFromFile(const std::string& config_file)`: Load from file
- `bool saveConfigToFile(const std::string& config_file)`: Save to file
- `bool loadConfigFromString(const std::string& config_string)`: Load from string
- `std::string saveConfigToString()`: Save to string

#### Performance Monitoring
- `void recordFeatureUsage(FeatureToggle feature, double performance_impact_ms)`: Record usage
- `uint64_t getFeatureUsageCount(FeatureToggle feature)`: Get usage count
- `double getFeaturePerformanceImpact(FeatureToggle feature)`: Get performance impact
- `std::map<FeatureToggle, uint64_t> getAllFeatureUsageCounts()`: Get all usage counts

#### Dependency Management
- `bool checkDependencies(FeatureToggle feature)`: Check dependencies
- `bool checkConflicts(FeatureToggle feature)`: Check conflicts
- `std::vector<FeatureToggle> getDependentFeatures(FeatureToggle feature)`: Get dependencies
- `std::vector<FeatureToggle> getConflictingFeatures(FeatureToggle feature)`: Get conflicts

This comprehensive feature toggle system provides fine-grained control over FGCom-mumble's functionality, enabling optimal performance and resource utilization across different deployment scenarios.
