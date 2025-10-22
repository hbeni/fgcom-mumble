# Antenna Pattern Module Comprehensive Test Suite

This test suite provides comprehensive testing for the Antenna Pattern Module using all available development and testing tools.

## Test Categories

### 11.1 NEC Pattern Tests (`test_nec_pattern.cpp`)
- [x] NEC file parsing
- [x] Radiation pattern extraction
- [x] Gain interpolation
- [x] Azimuth pattern lookup
- [x] Elevation pattern lookup
- [x] 3D pattern generation
- [x] NEC pattern performance
- [x] NEC pattern accuracy

### 11.2 Vehicle-Specific Antenna Tests (`test_vehicle_antenna.cpp`)
- [x] Aircraft antenna (belly-mounted)
- [x] Ground vehicle antenna (45° tie-down)
- [x] Handheld antenna (vertical)
- [x] Base station antenna (elevated)
- [x] Maritime antenna (ship-mounted)
- [x] Vehicle antenna performance
- [x] Vehicle antenna accuracy

### 11.3 Pattern Conversion Tests (`test_pattern_conversion.cpp`)
- [x] EZ to NEC conversion
- [x] EZNEC format handling
- [x] Pattern normalization
- [x] Coordinate system conversion
- [x] Pattern conversion performance
- [x] Pattern conversion accuracy

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

## Running the Tests

### Quick Start
```bash
cd test/antenna_pattern_module_tests
./run_antenna_pattern_module_tests.sh
```

### Manual Testing
```bash
# Build tests
mkdir build && cd build
cmake ..
make

# Run basic tests
./antenna_pattern_module_tests

# Run with AddressSanitizer
./antenna_pattern_module_tests_asan

# Run with ThreadSanitizer
./antenna_pattern_module_tests_tsan

# Run with coverage
./antenna_pattern_module_tests_coverage
```

### Individual Test Categories
```bash
# Run specific test categories
./antenna_pattern_module_tests --gtest_filter="*NEC*"
./antenna_pattern_module_tests --gtest_filter="*Vehicle*"
./antenna_pattern_module_tests --gtest_filter="*Pattern*"
```

### Memory Analysis
```bash
# Run with Valgrind
valgrind --tool=memcheck --leak-check=full ./antenna_pattern_module_tests

# Run with AddressSanitizer
./antenna_pattern_module_tests_asan

# Run with ThreadSanitizer
./antenna_pattern_module_tests_tsan
```

### Code Coverage
```bash
# Generate coverage report
./antenna_pattern_module_tests_coverage
lcov --capture --directory . --output-file coverage.info
lcov --remove coverage.info '/usr/*' --output-file coverage_filtered.info
genhtml coverage_filtered.info --output-directory coverage_html
```

### Static Analysis
```bash
# Run CppCheck
cppcheck --enable=all --std=c++17 ../../client/mumble-plugin/lib/pattern_interpolation.cpp

# Run Clang-Tidy
clang-tidy -checks='*' ../../client/mumble-plugin/lib/pattern_interpolation.cpp
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
- **NEC pattern functionality** for file parsing, radiation pattern extraction, gain interpolation, azimuth/elevation pattern lookup, and 3D pattern generation
- **Vehicle-specific antenna functionality** for aircraft, ground vehicle, handheld, base station, and maritime antennas
- **Pattern conversion functionality** for EZ to NEC conversion, EZNEC format handling, pattern normalization, and coordinate system conversion
- **Performance testing** with benchmarks and stress tests
- **Memory safety** with leak detection and sanitizers
- **Thread safety** with race condition detection

## Antenna Pattern Module Physics

### NEC Pattern Tests
- **NEC File Parsing**: Parsing of NEC2 antenna model files with geometry, frequency, and radiation pattern data
- **Radiation Pattern Extraction**: Extraction of radiation pattern data from NEC files
- **Gain Interpolation**: Interpolation of antenna gain values between known pattern points
- **Azimuth Pattern Lookup**: Lookup of antenna gain at specific azimuth angles
- **Elevation Pattern Lookup**: Lookup of antenna gain at specific elevation angles
- **3D Pattern Generation**: Generation of 3D radiation patterns from 2D data

### Vehicle-Specific Antenna Tests
- **Aircraft Antenna (Belly-Mounted)**: Antenna patterns for aircraft with belly-mounted antennas, affected by altitude and attitude
- **Ground Vehicle Antenna (45° Tie-Down)**: Antenna patterns for ground vehicles with 45° tied-down antennas
- **Handheld Antenna (Vertical)**: Antenna patterns for handheld vertical antennas
- **Base Station Antenna (Elevated)**: Antenna patterns for elevated base station antennas
- **Maritime Antenna (Ship-Mounted)**: Antenna patterns for ship-mounted antennas, affected by ship attitude

### Pattern Conversion Tests
- **EZ to NEC Conversion**: Conversion of EZNEC format files to NEC2 format
- **EZNEC Format Handling**: Parsing and handling of EZNEC format files
- **Pattern Normalization**: Normalization of antenna patterns to 0 dB maximum gain
- **Coordinate System Conversion**: Conversion between different coordinate systems (spherical, Cartesian)

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
- NEC pattern tests use realistic antenna model data
- Vehicle antenna tests simulate realistic vehicle scenarios
- Pattern conversion tests validate format conversions and coordinate transformations
- The test suite is designed to run in CI/CD environments
- Performance tests include timing benchmarks for critical antenna pattern functions

