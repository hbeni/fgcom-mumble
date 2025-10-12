# Radio Propagation Fuzzing Corpus

## Overview
This corpus contains test data for fuzzing radio signal propagation calculations in FGCom-mumble.

## Test Data Files

### distance_calc.txt
- **Purpose**: Distance calculation test data
- **Format**: Coordinate pairs and distance values
- **Size**: 34 bytes
- **Usage**: Tests radio propagation distance calculations

### invalid_coords.txt
- **Purpose**: Invalid coordinate data
- **Format**: Malformed coordinate strings
- **Size**: 20 bytes
- **Usage**: Tests error handling for invalid geographic coordinates

## Fuzzing Target
- **Binary**: `test/build-fuzz/fuzz_radio_propagation`
- **Purpose**: Tests radio propagation algorithms for:
  - Geographic coordinate validation
  - Distance calculation edge cases
  - Path loss algorithm robustness
  - Radio wave physics calculations

## Expected Behaviors
- Invalid coordinates should be handled gracefully
- Distance calculations should not overflow
- Path loss formulas should handle edge cases
- Geographic calculations should be mathematically sound

## Coverage Areas
- Radio signal propagation modeling
- Path loss calculations
- Geographic distance computations
- Radio wave physics algorithms
- Coordinate system transformations
- Signal strength predictions
