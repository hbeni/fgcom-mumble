# Antenna Patterns Fuzzing Corpus

## Overview
This corpus contains test data for fuzzing antenna pattern processing in FGCom-mumble.

## Test Data Files

### array_pattern.txt
- **Purpose**: Array antenna pattern data
- **Format**: Antenna array configuration
- **Size**: 20 bytes
- **Usage**: Tests array antenna pattern calculations

### dipole.txt
- **Purpose**: Dipole antenna pattern data
- **Format**: Dipole antenna parameters
- **Size**: 15 bytes
- **Usage**: Tests dipole antenna pattern modeling

## Fuzzing Target
- **Binary**: `test/build-fuzz/fuzz_antenna_patterns`
- **Purpose**: Tests antenna patterns for:
  - Antenna pattern calculations
  - Directional antenna modeling
  - Gain pattern algorithms
  - Array antenna processing
  - Antenna physics calculations

## Expected Behaviors
- Antenna patterns should be calculated correctly
- Directional modeling should be accurate
- Gain calculations should be robust
- Array processing should handle edge cases
- Antenna physics should be mathematically sound

## Coverage Areas
- Antenna pattern processing
- Directional antenna calculations
- Gain pattern algorithms
- Array antenna systems
- Antenna physics modeling
- Pattern optimization
- Beamforming algorithms
- Antenna efficiency calculations
