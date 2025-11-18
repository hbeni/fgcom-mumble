# Frequency Management Comprehensive Test Suite

This test suite provides comprehensive testing for the Frequency Management module using all available development and testing tools.

## Test Categories

### 3.1 Band Segment Validation Tests (`test_band_segment_validation.cpp`)
- [x] Amateur radio band segments (280+ allocations)
- [x] ITU region detection (1, 2, 3)
- [x] Country-specific regulations
- [x] License class requirements
- [x] Power limit enforcement
- [x] Mode validation (CW, SSB modes, FM, AM, Digital)
- [x] Out-of-band rejection
- [x] Frequency range validation
- [x] Band segment overlap detection
- [x] Band segment performance

### 3.2 Aviation Frequency Tests (`test_aviation_frequencies.cpp`)
- [x] Civil VHF (118-137 MHz) validation
- [x] Military VHF/UHF validation
- [x] Civil HF band validation
- [x] Emergency frequency (121.5 MHz)
- [x] Guard frequency (243.0 MHz)
- [x] Aviation frequency allocation
- [x] Aviation frequency channel spacing
- [x] Aviation frequency power limits
- [x] Aviation frequency modulation
- [x] Aviation frequency performance

### 3.3 Historical Maritime Band Tests (`test_maritime_frequencies.cpp`)
- [x] Maritime HF band allocation
- [x] Distress frequencies
- [x] Working frequencies
- [x] Coast station frequencies
- [x] Maritime frequency allocation
- [x] Maritime frequency channel spacing
- [x] Maritime frequency power limits
- [x] Maritime frequency modulation
- [x] Maritime frequency band allocation
- [x] Maritime frequency performance

### 3.4 Frequency Offset Tests (`test_frequency_offsets.cpp`)
- [x] BFO (Beat Frequency Oscillator) simulation
- [x] SSB frequency offset
- [x] CW tone injection
- [x] Frequency drift simulation
- [x] Crystal accuracy simulation
- [x] Frequency offset combination
- [x] Frequency offset validation
- [x] Frequency offset performance
- [x] Frequency offset precision
- [x] Frequency offset stability

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
cd test/frequency_management_tests
./run_frequency_management_tests.sh
```

### Manual Testing
```bash
# Build tests
mkdir build && cd build
cmake ..
make

# Run basic tests
./frequency_management_tests

# Run with AddressSanitizer
./frequency_management_tests_asan

# Run with ThreadSanitizer
./frequency_management_tests_tsan

# Run with coverage
./frequency_management_tests_coverage
```

### Individual Test Categories
```bash
# Run specific test categories
./frequency_management_tests --gtest_filter="*BandSegment*"
./frequency_management_tests --gtest_filter="*Aviation*"
./frequency_management_tests --gtest_filter="*Maritime*"
./frequency_management_tests --gtest_filter="*FrequencyOffset*"
```

### Memory Analysis
```bash
# Run with Valgrind
valgrind --tool=memcheck --leak-check=full ./frequency_management_tests

# Run with AddressSanitizer
./frequency_management_tests_asan

# Run with ThreadSanitizer
./frequency_management_tests_tsan
```

### Code Coverage
```bash
# Generate coverage report
./frequency_management_tests_coverage
lcov --capture --directory . --output-file coverage.info
lcov --remove coverage.info '/usr/*' --output-file coverage_filtered.info
genhtml coverage_filtered.info --output-directory coverage_html
```

### Static Analysis
```bash
# Run CppCheck
cppcheck --enable=all --std=c++17 ../../client/mumble-plugin/lib/amateur_radio.cpp

# Run Clang-Tidy
clang-tidy -checks='*' ../../client/mumble-plugin/lib/amateur_radio.cpp
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
- **4 major test categories** with 100+ individual test cases
- **Band segment validation** for amateur radio frequencies
- **Aviation frequency management** for civil and military use
- **Maritime frequency allocation** for historical HF bands
- **Frequency offset calculations** for BFO, SSB, CW, and drift
- **Performance testing** with benchmarks and stress tests
- **Memory safety** with leak detection and sanitizers
- **Thread safety** with race condition detection

## Frequency Management Physics

### Band Segment Validation
- **Amateur Radio Bands**: 160m, 80m, 40m, 20m, 15m, 10m, 6m, 2m, 70cm
- **ITU Regions**: Region 1 (Europe/Africa), Region 2 (Americas), Region 3 (Asia-Pacific)
- **License Classes**: Foundation, Intermediate, Full, Extra
- **Operating Modes**: CW, SSB, FM, AM, Digital
- **Power Limits**: Country and license class specific

### Aviation Frequencies
- **Civil VHF**: 118.000-137.000 MHz with 25 kHz or 8.33 kHz channel spacing
- **Emergency Frequency**: 121.5 MHz for distress and emergency
- **Guard Frequency**: 243.0 MHz for military emergency
- **Power Limits**: 25 watts maximum for aviation frequencies
- **Modulation**: AM (Amplitude Modulation) for all aviation frequencies

### Maritime Frequencies
- **Maritime HF Bands**: 2 MHz, 4 MHz, 6 MHz, 8 MHz, 12 MHz
- **Distress Frequencies**: 2182.0 kHz, 4125.0 kHz, 8291.0 kHz
- **Working Frequencies**: 2187.5 kHz, 6215.0 kHz, 12290.0 kHz
- **Power Limits**: 100 watts maximum for maritime frequencies
- **Modulation**: SSB (Single Sideband) for all maritime frequencies

### Frequency Offsets
- **BFO (Beat Frequency Oscillator)**: ±5 kHz range for frequency conversion
- **SSB Frequency Offset**: ±5 kHz range for sideband selection
- **CW Tone Injection**: 400-800 Hz range for Morse code generation
- **Frequency Drift**: ±0.1 kHz per minute for oscillator stability
- **Crystal Accuracy**: ±10 ppm for frequency reference accuracy

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
- Frequency management tests use realistic radio frequency models
- Band segment tests validate ITU regulations and country-specific rules
- Aviation tests ensure compliance with ICAO standards
- Maritime tests cover historical HF band allocations
- Frequency offset tests validate oscillator and modulation accuracy
- The test suite is designed to run in CI/CD environments
- Performance tests include timing benchmarks for critical functions

