# Radio Propagation Comprehensive Test Suite

This test suite provides comprehensive testing for the Radio Propagation module using all available development and testing tools.

## Test Categories

### 2.1 Line-of-Sight Tests (`test_line_of_sight.cpp`)
- [x] Direct LOS calculation
- [x] Terrain obstruction detection
- [x] Earth curvature effects
- [x] Altitude-based range calculation
- [x] Fresnel zone clearance
- [x] Multiple obstruction handling
- [x] LOS with different distances
- [x] LOS with different altitudes
- [x] LOS performance testing
- [x] LOS with terrain profile

### 2.2 Frequency-Dependent Propagation Tests (`test_frequency_propagation.cpp`)
- [x] VHF propagation (118-137 MHz)
- [x] UHF propagation (225-400 MHz)
- [x] HF propagation (3-30 MHz)
- [x] Frequency-based path loss
- [x] Atmospheric absorption
- [x] Ground wave propagation (HF)
- [x] Sky wave propagation (HF)
- [x] Ionospheric reflection
- [x] Frequency response curve
- [x] Propagation mode selection
- [x] Frequency band characteristics

### 2.3 Antenna Pattern Tests (`test_antenna_patterns.cpp`)
- [x] Omnidirectional pattern
- [x] Directional pattern (Yagi)
- [x] Vertical polarization
- [x] Horizontal polarization
- [x] Gain calculation at various angles
- [x] Front-to-back ratio
- [x] Elevation angle effects
- [x] Azimuth angle effects
- [x] Antenna pattern interpolation
- [x] Antenna pattern symmetry
- [x] Antenna pattern performance

### 2.4 Environmental Effects Tests (`test_environmental_effects.cpp`)
- [x] Weather impact (rain, fog, snow)
- [x] Temperature effects
- [x] Humidity effects
- [x] Atmospheric pressure effects
- [x] Ducting conditions
- [x] Tropospheric scatter
- [x] Combined weather effects
- [x] Environmental effects performance

### 2.5 Noise Floor Calculation Tests (`test_noise_floor.cpp`)
- [x] Atmospheric noise (ITU-R P.372)
- [x] Man-made noise
- [x] Galactic noise
- [x] EV charging station noise
- [x] Power substation noise (2MW+)
- [x] Distance-based noise attenuation
- [x] Frequency-dependent noise levels
- [x] Noise floor calculation accuracy
- [x] Noise floor with environmental conditions
- [x] Noise floor performance

## Development Tools Used

### Testing Frameworks
- **Google Test 1.14.0** - Unit testing framework
- **Google Mock 1.14.0** - Mocking framework

### Memory Analysis
- **Valgrind 3.22.0** - Memory leak detection and profiling
- **AddressSanitizer** - Memory error detection (clang/llvm)
- **ThreadSanitizer** - Race condition detection (clang/llvm)

### Code Coverage
- **Lcov 2.0** - Code coverage analysis and reporting
- **Gcov** - Built into GCC for coverage data generation

### Static Analysis
- **CppCheck 2.13.0** - Static analysis for C/C++
- **Clang-Tidy 18.1.3** - Advanced static analysis and code quality checks

### Compiler Tools
- **Clang 18.1.3** - LLVM-based C/C++ compiler with sanitizer support
- **LLVM 18.0** - Low Level Virtual Machine infrastructure

## Running the Tests

### Quick Start
```bash
cd test/radio_propagation_tests
./run_radio_propagation_tests.sh
```

### Manual Testing
```bash
# Build tests
mkdir build && cd build
cmake ..
make

# Run basic tests
./radio_propagation_tests

# Run with AddressSanitizer
./radio_propagation_tests_asan

# Run with ThreadSanitizer
./radio_propagation_tests_tsan

# Run with coverage
./radio_propagation_tests_coverage
```

### Individual Test Categories
```bash
# Run specific test categories
./radio_propagation_tests --gtest_filter="*LineOfSight*"
./radio_propagation_tests --gtest_filter="*FrequencyPropagation*"
./radio_propagation_tests --gtest_filter="*AntennaPattern*"
./radio_propagation_tests --gtest_filter="*Environmental*"
./radio_propagation_tests --gtest_filter="*NoiseFloor*"
```

### Memory Analysis
```bash
# Run with Valgrind
valgrind --tool=memcheck --leak-check=full ./radio_propagation_tests

# Run with AddressSanitizer
./radio_propagation_tests_asan

# Run with ThreadSanitizer
./radio_propagation_tests_tsan
```

### Code Coverage
```bash
# Generate coverage report
./radio_propagation_tests_coverage
lcov --capture --directory . --output-file coverage.info
lcov --remove coverage.info '/usr/*' --output-file coverage_filtered.info
genhtml coverage_filtered.info --output-directory coverage_html
```

### Static Analysis
```bash
# Run CppCheck
cppcheck --enable=all --std=c++17 ../../client/mumble-plugin/lib/terrain_elevation.cpp

# Run Clang-Tidy
clang-tidy -checks='*' ../../client/mumble-plugin/lib/terrain_elevation.cpp
```

## Test Results

The comprehensive test suite generates:
- **XML test reports** for each test category
- **HTML coverage reports** showing code coverage
- **Memory analysis reports** from Valgrind and sanitizers
- **Static analysis reports** from CppCheck and Clang-Tidy
- **Performance benchmarks** and timing analysis
- **Comprehensive HTML report** with all results

## Test Coverage

The test suite covers:
- **5 major test categories** with 100+ individual test cases
- **Line-of-sight calculations** with terrain obstruction detection
- **Frequency-dependent propagation** for VHF, UHF, and HF bands
- **Antenna pattern analysis** for omnidirectional and directional antennas
- **Environmental effects** including weather, temperature, and atmospheric conditions
- **Noise floor calculations** using ITU-R P.372 standards
- **Performance testing** with benchmarks and stress tests
- **Memory safety** with leak detection and sanitizers
- **Thread safety** with race condition detection

## Radio Propagation Physics

### Line-of-Sight Calculations
- **Direct LOS**: Basic line-of-sight between transmitter and receiver
- **Terrain Obstruction**: Detection of terrain blocking the signal path
- **Earth Curvature**: Correction for earth's curvature in long-distance calculations
- **Fresnel Zone**: Clearance requirements for optimal signal propagation
- **Altitude Effects**: Impact of antenna height on propagation range

### Frequency-Dependent Propagation
- **VHF (118-137 MHz)**: Line-of-sight propagation with tropospheric ducting
- **UHF (225-400 MHz)**: Higher path loss, more affected by atmospheric conditions
- **HF (3-30 MHz)**: Ground wave and sky wave propagation, ionospheric reflection
- **Path Loss**: Free space path loss calculation with frequency dependency
- **Atmospheric Absorption**: Frequency-dependent atmospheric attenuation

### Antenna Patterns
- **Omnidirectional**: Equal radiation in all horizontal directions
- **Directional (Yagi)**: High gain in forward direction, reduced gain in other directions
- **Polarization**: Vertical and horizontal polarization effects
- **Gain Calculation**: Antenna gain at various azimuth and elevation angles
- **Front-to-Back Ratio**: Ratio of forward to backward radiation

### Environmental Effects
- **Weather Impact**: Rain, fog, and snow attenuation
- **Temperature Effects**: Atmospheric absorption variations with temperature
- **Humidity Effects**: Water vapor absorption in the atmosphere
- **Atmospheric Pressure**: Refraction effects due to pressure variations
- **Ducting Conditions**: Tropospheric ducting for extended range
- **Tropospheric Scatter**: Scatter propagation for long distances

### Noise Floor Calculations
- **Atmospheric Noise**: ITU-R P.372 standard for atmospheric noise
- **Man-Made Noise**: Urban and industrial noise sources
- **Galactic Noise**: Cosmic background noise
- **EV Charging Stations**: High-frequency noise from electric vehicle charging
- **Power Substations**: Very high noise from electrical power systems
- **Distance Attenuation**: Noise level reduction with distance

## Requirements

- C++17 compatible compiler
- CMake 3.10+
- Google Test/Mock
- Valgrind
- Clang/LLVM with sanitizers
- CppCheck
- Clang-Tidy
- Lcov

## Notes

- All tests are designed to be deterministic and repeatable
- Radio propagation tests use realistic physics models
- Environmental tests simulate various weather conditions
- Noise floor tests use ITU-R standards
- The test suite is designed to run in CI/CD environments
- Performance tests include timing benchmarks for critical functions

