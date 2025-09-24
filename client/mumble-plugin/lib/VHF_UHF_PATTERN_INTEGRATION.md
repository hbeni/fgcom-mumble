# VHF/UHF Antenna Pattern Integration

## Overview

This document describes the implementation of antenna pattern support for VHF (30-300 MHz) and UHF (300+ MHz) radio models in FGCom-mumble. The implementation extends the existing pattern interpolation system to support VHF/UHF frequencies with vehicle-specific antenna patterns.

## Features Implemented

### 1. VHF Radio Model Enhancement (`radio_model_vhf.cpp`)

**New Capabilities:**
- **Antenna Pattern Loading**: Automatic loading of VHF antenna patterns for various vehicles
- **Pattern Interpolation**: Real-time antenna gain calculation based on elevation and azimuth angles
- **Vehicle-Specific Patterns**: Different antenna patterns for aircraft, ground vehicles, and maritime platforms
- **Backward Compatibility**: Falls back to simple power/distance model if pattern data unavailable

**Supported Vehicles:**
- **Aircraft**: Boeing 737-800, C-130 Hercules, Cessna 172, Mi-4 Hound
- **Ground Vehicles**: Leopard 1 Tank, Soviet UAZ
- **Maritime**: (Placeholder for future implementation)

**Pattern Files:**
```
antenna_patterns/aircraft/b737_800/b737_800_vhf.ez
antenna_patterns/aircraft/c130_hercules/c130_hercules_vhf.ez
antenna_patterns/aircraft/cessna_172/cessna_172_vhf.ez
antenna_patterns/aircraft/mi4_hound/mi4_hound_vhf.ez
antenna_patterns/ground_vehicles/leopard1_tank/leopard1_tank_vhf.ez
antenna_patterns/ground_vehicles/soviet_uaz/soviet_uaz_vhf.ez
```

### 2. UHF Radio Model Enhancement (`radio_model_uhf.cpp`)

**New Capabilities:**
- **UHF-Specific Patterns**: Separate pattern system for UHF frequencies (300+ MHz)
- **Military/Civilian Patterns**: Different patterns for military tactical and civilian UHF systems
- **Reduced Range**: UHF model maintains reduced range per watt characteristic
- **Pattern Integration**: Seamless integration with existing UHF propagation model

**Supported Frequencies:**
- **Military UHF**: 225-400 MHz (tactical communications)
- **Civilian UHF**: 400-1000 MHz (commercial systems)

### 3. Antenna Pattern Mapping System (`antenna_pattern_mapping.h/cpp`)

**Core Features:**
- **Vehicle Type Detection**: Automatic detection of vehicle type from vehicle name
- **Frequency Band Detection**: Automatic VHF/UHF frequency classification
- **Pattern Lookup**: Efficient pattern file lookup based on vehicle type and frequency
- **Closest Match**: Fallback to closest available pattern if exact match not found

**Vehicle Type Mapping:**
```cpp
// Aircraft detection
"Boeing 737-800" -> "aircraft"
"C-130 Hercules" -> "aircraft"
"Cessna 172" -> "aircraft"

// Ground vehicle detection  
"Leopard 1 Tank" -> "ground_vehicle"
"Soviet UAZ" -> "ground_vehicle"

// Military detection
"Military Tactical" -> "military"
```

### 4. Pattern Generation Script (`generate_vhf_uhf_patterns.sh`)

**Capabilities:**
- **Multi-Frequency Generation**: Creates patterns for multiple VHF/UHF frequencies
- **Altitude-Dependent Patterns**: Generates patterns at various altitudes (0-5000m)
- **Parallel Processing**: Uses all CPU cores for fast pattern generation
- **Index File Creation**: Creates searchable index files for pattern lookup

**Generated Frequencies:**
- **VHF**: 50, 100, 150, 200, 250, 300 MHz
- **UHF**: 400, 500, 600, 800, 1000, 1200 MHz

**Generated Altitudes:**
- 0m (ground level)
- 100m (low altitude)
- 500m (medium altitude)
- 1000m (high altitude)
- 2000m (very high altitude)
- 5000m (extreme altitude)

## Technical Implementation

### Signal Calculation Enhancement

**Before (Simple Model):**
```cpp
float ss = this->calcPowerDistance(power, slantDist);
```

**After (Pattern-Enhanced):**
```cpp
float ss = this->calcPowerDistance(power, slantDist);

// Apply antenna pattern gain
double antenna_gain_db = getAntennaGain(antenna_name, altitude_m, 
                                       frequency_mhz, theta_deg, phi_deg);
if (antenna_gain_db > -999.0) {
    double antenna_gain_linear = pow(10.0, antenna_gain_db / 10.0);
    ss *= antenna_gain_linear;
}
```

### Pattern Loading Process

1. **Initialization**: Patterns loaded on first use (lazy loading)
2. **Vehicle Detection**: Automatic vehicle type detection from vehicle name
3. **Pattern Lookup**: Find appropriate pattern file for vehicle type and frequency
4. **Gain Calculation**: Interpolate antenna gain for specific angles
5. **Signal Application**: Apply gain to signal quality calculation

### Error Handling

- **Pattern Not Found**: Falls back to default antenna gain (0 dB)
- **File Loading Error**: Continues with basic power/distance model
- **Interpolation Error**: Uses nearest available pattern point
- **Backward Compatibility**: Maintains existing behavior if patterns unavailable

## Usage Examples

### Basic VHF Pattern Usage

```cpp
// Create VHF radio model
auto vhf_model = std::make_unique<FGCom_radiowaveModel_VHF>();

// Calculate signal with antenna patterns
auto signal = vhf_model->getSignal(lat1, lon1, alt1, lat2, lon2, alt2, power);
// Signal now includes antenna pattern effects
```

### UHF Pattern Usage

```cpp
// Create UHF radio model  
auto uhf_model = std::make_unique<FGCom_radiowaveModel_UHF>();

// Calculate signal with UHF antenna patterns
auto signal = uhf_model->getSignal(lat1, lon1, alt1, lat2, lon2, alt2, power);
// Signal includes UHF-specific antenna effects
```

### Pattern Mapping Usage

```cpp
// Get antenna pattern for specific vehicle and frequency
auto pattern = getAntennaPattern("aircraft", 150.0);
std::cout << "Pattern file: " << pattern.pattern_file << std::endl;

// Check if pattern exists
if (mapping->hasVHFPattern("aircraft", 150.0)) {
    // Pattern available
}
```

## Performance Considerations

### Memory Usage
- **Pattern Caching**: Patterns loaded once and cached in memory
- **Lazy Loading**: Patterns loaded only when needed
- **Memory Management**: Automatic cleanup when radio models destroyed

### Computational Overhead
- **Interpolation**: Minimal overhead for pattern interpolation
- **Lookup**: Fast hash-based pattern lookup
- **Fallback**: No overhead if patterns unavailable

### File I/O
- **Initial Load**: One-time file loading during initialization
- **Caching**: No repeated file access during operation
- **Error Recovery**: Graceful handling of missing pattern files

## Testing

### Test Script (`test_vhf_uhf_patterns.cpp`)

**Test Coverage:**
- VHF pattern integration
- UHF pattern integration  
- Antenna pattern mapping
- Pattern file generation
- Vehicle type detection
- Frequency band detection

**Run Tests:**
```bash
g++ -o test_vhf_uhf_patterns test_vhf_uhf_patterns.cpp
./test_vhf_uhf_patterns
```

### Pattern Generation Testing

```bash
# Generate VHF/UHF patterns
./generate_vhf_uhf_patterns.sh

# Verify pattern files created
ls antenna_patterns/*/patterns/vhf/
ls antenna_patterns/*/patterns/uhf/
```

## Future Enhancements

### Planned Features
1. **Maritime VHF Patterns**: Ship and boat antenna patterns
2. **UHF Military Patterns**: Tactical UHF antenna patterns
3. **Dynamic Pattern Loading**: Runtime pattern loading based on vehicle type
4. **Pattern Optimization**: Cached pattern interpolation for better performance
5. **3D Pattern Visualization**: Real-time antenna pattern visualization

### Integration Opportunities
1. **FlightGear Integration**: Direct integration with FlightGear aircraft models
2. **Real-Time Updates**: Dynamic pattern updates based on vehicle configuration
3. **Multi-Antenna Support**: Support for vehicles with multiple antennas
4. **Pattern Validation**: Real-world pattern validation and calibration

## Troubleshooting

### Common Issues

**Pattern Files Not Found:**
- Check file paths in `antenna_pattern_mapping.cpp`
- Verify EZNEC files exist in correct directories
- Run pattern generation script to create missing patterns

**No Antenna Gain Applied:**
- Check if pattern interpolation is working
- Verify antenna name mapping
- Check for pattern file loading errors

**Performance Issues:**
- Reduce pattern resolution for better performance
- Use pattern caching for frequently accessed patterns
- Consider pattern pre-loading for critical frequencies

### Debug Information

**Enable Debug Output:**
```cpp
// Add debug output to see pattern loading
std::cout << "Loading pattern: " << pattern_file << std::endl;
std::cout << "Antenna gain: " << antenna_gain_db << " dB" << std::endl;
```

**Pattern Validation:**
```cpp
// Check if pattern is loaded correctly
if (pattern.is_loaded) {
    std::cout << "Pattern loaded successfully" << std::endl;
} else {
    std::cout << "Pattern loading failed" << std::endl;
}
```

## Conclusion

The VHF/UHF antenna pattern integration provides realistic antenna modeling for FGCom-mumble, enhancing the simulation accuracy while maintaining backward compatibility. The implementation supports multiple vehicle types, frequency bands, and provides a foundation for future enhancements.

The system is designed to be:
- **Extensible**: Easy to add new vehicle types and patterns
- **Efficient**: Minimal performance impact with smart caching
- **Robust**: Graceful error handling and fallback mechanisms
- **Compatible**: Works with existing FGCom-mumble infrastructure
