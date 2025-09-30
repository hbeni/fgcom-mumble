# ATIS Module Comprehensive Test Suite

This test suite provides comprehensive testing for the ATIS (Automated Terminal Information Service) Module using all available development and testing tools.

## Test Categories

### 7.1 Recording Tests (`test_recording.cpp`)
- [x] Voice recording start/stop
- [x] Recording duration limits
- [x] Audio quality verification
- [x] File format correctness
- [x] Storage management
- [x] Recording performance
- [x] Recording accuracy

### 7.2 Playback Tests (`test_playback.cpp`)
- [x] Playback on demand
- [x] Loop playback
- [x] Multiple simultaneous playbacks
- [x] Playback interruption
- [x] Audio sync with transmission
- [x] Playback performance
- [x] Playback accuracy

### 7.3 ATIS Content Tests (`test_atis_content.cpp`)
- [x] Airport code parsing
- [x] Weather information formatting
- [x] Runway information
- [x] Time/date stamping
- [x] Phonetic alphabet conversion
- [x] ATIS content performance
- [x] ATIS content accuracy

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
cd test/atis_module_tests
./run_atis_module_tests.sh
```

### Manual Testing
```bash
# Build tests
mkdir build && cd build
cmake ..
make

# Run basic tests
./atis_module_tests

# Run with AddressSanitizer
./atis_module_tests_asan

# Run with ThreadSanitizer
./atis_module_tests_tsan

# Run with coverage
./atis_module_tests_coverage
```

### Individual Test Categories
```bash
# Run specific test categories
./atis_module_tests --gtest_filter="*Recording*"
./atis_module_tests --gtest_filter="*Playback*"
./atis_module_tests --gtest_filter="*ATISContent*"
```

### Memory Analysis
```bash
# Run with Valgrind
valgrind --tool=memcheck --leak-check=full ./atis_module_tests

# Run with AddressSanitizer
./atis_module_tests_asan

# Run with ThreadSanitizer
./atis_module_tests_tsan
```

### Code Coverage
```bash
# Generate coverage report
./atis_module_tests_coverage
lcov --capture --directory . --output-file coverage.info
lcov --remove coverage.info '/usr/*' --output-file coverage_filtered.info
genhtml coverage_filtered.info --output-directory coverage_html
```

### Static Analysis
```bash
# Run CppCheck
cppcheck --enable=all --std=c++17 ../../server/fgcom-radio-recorder.bot.lua

# Run Clang-Tidy
clang-tidy -checks='*' ../../server/fgcom-radio-recorder.bot.lua
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
- **Recording functionality** for voice recording, duration limits, audio quality verification, file format correctness, and storage management
- **Playback functionality** for on-demand playback, loop playback, multiple simultaneous playbacks, playback interruption, and audio sync with transmission
- **ATIS content functionality** for airport code parsing, weather information formatting, runway information, time/date stamping, and phonetic alphabet conversion
- **Performance testing** with benchmarks and stress tests
- **Memory safety** with leak detection and sanitizers
- **Thread safety** with race condition detection

## ATIS Module Physics

### Recording Tests
- **Voice Recording Start/Stop**: Real-time voice recording initiation and termination
- **Recording Duration Limits**: Enforcement of maximum recording duration (120 seconds default)
- **Audio Quality Verification**: Validation of audio sample quality and frequency content
- **File Format Correctness**: Proper FGCS file format generation with headers and audio data
- **Storage Management**: Efficient storage and retrieval of recording files

### Playback Tests
- **Playback on Demand**: Real-time audio playback initiation and control
- **Loop Playback**: Continuous looped playback of recorded audio
- **Multiple Simultaneous Playbacks**: Concurrent playback of multiple audio streams
- **Playback Interruption**: Graceful handling of playback interruption and recovery
- **Audio Sync with Transmission**: Synchronization of audio playback with radio transmission

### ATIS Content Tests
- **Airport Code Parsing**: Validation and parsing of ICAO airport codes (4-letter format)
- **Weather Information Formatting**: Structured formatting of weather data (wind, visibility, ceiling, temperature, dew point)
- **Runway Information**: Formatting of runway data (runway numbers, directions, lengths)
- **Time/Date Stamping**: ISO 8601 timestamp generation and validation
- **Phonetic Alphabet Conversion**: Conversion of text to NATO phonetic alphabet for radio communication

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
- ATIS tests use realistic airport codes, weather data, and audio formats
- Recording tests validate voice recording, duration limits, audio quality, and file format correctness
- Playback tests ensure proper audio playback, loop functionality, and synchronization
- ATIS content tests validate airport code parsing, weather formatting, and phonetic alphabet conversion
- The test suite is designed to run in CI/CD environments
- Performance tests include timing benchmarks for critical ATIS functions

