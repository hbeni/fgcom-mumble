# Geographic Module Comprehensive Test Suite

This test suite provides comprehensive testing for the Geographic Module using all available development and testing tools.

## Test Categories

### 6.1 Coordinate System Tests (`test_coordinate_system.cpp`)
- [x] Lat/lon to Cartesian conversion
- [x] Cartesian to lat/lon conversion
- [x] Great circle distance calculation
- [x] Bearing calculation
- [x] Coordinate validation
- [x] Datum conversion (WGS84)
- [x] Coordinate system performance
- [x] Coordinate system accuracy

### 6.2 Terrain Data Tests (`test_terrain_data.cpp`)
- [x] ASTER GDEM data loading
- [x] Elevation lookup
- [x] Interpolation between points
- [x] Missing data handling
- [x] Terrain profile generation
- [x] Multi-polygon support
- [x] Terrain data performance
- [x] Terrain data accuracy

### 6.3 Vehicle Dynamics Tests (`test_vehicle_dynamics.cpp`)
- [x] Position tracking
- [x] Velocity calculation
- [x] Heading/bearing
- [x] Altitude changes
- [x] Antenna orientation
- [x] Mobile vs stationary detection
- [x] Vehicle dynamics performance
- [x] Vehicle dynamics accuracy

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
cd test/geographic_module_tests
./run_geographic_module_tests.sh
```

### Manual Testing
```bash
# Build tests
mkdir build && cd build
cmake ..
make

# Run basic tests
./geographic_module_tests

# Run with AddressSanitizer
./geographic_module_tests_asan

# Run with ThreadSanitizer
./geographic_module_tests_tsan

# Run with coverage
./geographic_module_tests_coverage
```

### Individual Test Categories
```bash
# Run specific test categories
./geographic_module_tests --gtest_filter="*Coordinate*"
./geographic_module_tests --gtest_filter="*Terrain*"
./geographic_module_tests --gtest_filter="*Vehicle*"
```

### Memory Analysis
```bash
# Run with Valgrind
valgrind --tool=memcheck --leak-check=full ./geographic_module_tests

# Run with AddressSanitizer
./geographic_module_tests_asan

# Run with ThreadSanitizer
./geographic_module_tests_tsan
```

### Code Coverage
```bash
# Generate coverage report
./geographic_module_tests_coverage
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
- **3 major test categories** with 100+ individual test cases
- **Coordinate system functionality** for lat/lon conversion, distance calculation, bearing calculation, and WGS84 datum conversion
- **Terrain data functionality** for ASTER GDEM data loading, elevation lookup, interpolation, missing data handling, terrain profile generation, and multi-polygon support
- **Vehicle dynamics functionality** for position tracking, velocity calculation, heading/bearing, altitude changes, antenna orientation, and mobile vs stationary detection
- **Performance testing** with benchmarks and stress tests
- **Memory safety** with leak detection and sanitizers
- **Thread safety** with race condition detection

## Geographic Module Physics

### Coordinate System Tests
- **Lat/Lon to Cartesian Conversion**: Real-time coordinate transformation between geographic and Cartesian coordinate systems
- **Great Circle Distance Calculation**: Accurate distance calculation using the Haversine formula for spherical Earth
- **Bearing Calculation**: True and magnetic bearing calculation between geographic points
- **Coordinate Validation**: Validation of latitude, longitude, and altitude ranges
- **WGS84 Datum Conversion**: Precise coordinate system transformations using the WGS84 datum

### Terrain Data Tests
- **ASTER GDEM Data Loading**: Loading and processing of ASTER Global Digital Elevation Model data
- **Elevation Lookup**: Real-time elevation data retrieval for any geographic coordinate
- **Interpolation**: Smooth interpolation between elevation data points for accurate terrain representation
- **Missing Data Handling**: Robust handling of missing or invalid terrain data
- **Terrain Profile Generation**: Generation of elevation profiles along arbitrary paths
- **Multi-Polygon Support**: Support for complex terrain geometries with multiple polygons

### Vehicle Dynamics Tests
- **Position Tracking**: Real-time GPS coordinate tracking with high precision
- **Velocity Calculation**: Speed and course calculation in multiple units (knots, km/h, m/s)
- **Heading/Bearing**: True and magnetic heading calculation with declination correction
- **Altitude Changes**: Vertical speed calculation and altitude change detection
- **Antenna Orientation**: Antenna pointing direction and elevation angle calculation
- **Mobile vs Stationary Detection**: Automatic detection of vehicle movement status

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
- Geographic tests use realistic coordinate systems and terrain data
- Coordinate system tests validate lat/lon conversion, distance calculation, and bearing calculation
- Terrain data tests ensure proper ASTER GDEM data loading, elevation lookup, and interpolation
- Vehicle dynamics tests validate position tracking, velocity calculation, and antenna orientation
- The test suite is designed to run in CI/CD environments
- Performance tests include timing benchmarks for critical geographic functions

