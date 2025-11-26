# AGC/Squelch Comprehensive Test Suite

This test suite provides comprehensive testing for the AGC (Automatic Gain Control) and Squelch module using all available development and testing tools.

## Test Categories

### 1. Singleton Pattern Tests (`test_singleton.cpp`)
- [x] Valid instance creation
- [x] Same instance returned on multiple calls  
- [x] Thread-safe access (20+ concurrent threads)
- [x] Destroy and recreate functionality
- [x] Memory leak verification
- [x] Rapid create/destroy cycles
- [x] Concurrent destroy operations

### 2. AGC Configuration Tests (`test_agc_config.cpp`)
- [x] Default state (disabled)
- [x] Enable/disable functionality
- [x] Mode switching (FAST, MEDIUM, SLOW, OFF)
- [x] Threshold setting and clamping (-100 to 0 dB)
- [x] Attack time setting and clamping (0.1 to 1000 ms)
- [x] Release time setting and clamping (1 to 10000 ms)
- [x] Max gain setting and clamping (0 to 60 dB)
- [x] Min gain setting and clamping (-40 to 0 dB)
- [x] Config struct get/set operations
- [x] Thread-safe configuration changes
- [x] Extreme values handling
- [x] Invalid input handling (NaN, infinity)

### 3. Squelch Configuration Tests (`test_squelch_config.cpp`)
- [x] Default state (enabled)
- [x] Enable/disable functionality
- [x] Threshold setting and clamping (-120 to 0 dB)
- [x] Hysteresis setting and clamping (0 to 20 dB)
- [x] Attack time setting and clamping (0.1 to 1000 ms)
- [x] Release time setting and clamping (1 to 10000 ms)
- [x] Tone squelch enable/disable with frequency
- [x] Tone frequency clamping (50 to 3000 Hz)
- [x] Noise squelch enable/disable with threshold
- [x] Config struct get/set operations
- [x] Thread-safe configuration changes
- [x] Combined tone and noise squelch
- [x] Extreme values handling
- [x] Invalid input handling

### 4. Audio Processing Tests (`test_audio_processing.cpp`)
- [x] Zero sample count handling
- [x] Null pointer handling
- [x] Large sample count (1M+ samples)
- [x] Various sample rates (8k, 16k, 44.1k, 48k, 96k Hz)
- [x] Sine wave processing (various frequencies)
- [x] Noise processing
- [x] Silence processing
- [x] Clipping prevention
- [x] AGC gain application correctness
- [x] Squelch muting correctness
- [x] Combined AGC+Squelch processing
- [x] Buffer overflow protection
- [x] Performance benchmarks
- [x] Very small samples handling
- [x] Extreme amplitudes handling

### 5. Mathematical Functions Tests (`test_math_functions.cpp`)
- [x] RMS calculation accuracy
- [x] RMS with zero samples
- [x] RMS with silence
- [x] Peak calculation accuracy
- [x] Peak with zero samples
- [x] dB to linear conversion accuracy
- [x] Linear to dB conversion accuracy
- [x] Zero/negative input handling in conversions
- [x] Extreme value handling (+/-100 dB)
- [x] Clamp function boundary testing
- [x] Mathematical precision testing
- [x] Numerical stability testing

### 6. Tone Detection Tests (`test_tone_detection.cpp`)
- [x] Single tone detection accuracy
- [x] Multiple frequencies tested (100, 500, 1000, 2000 Hz)
- [x] Noise rejection
- [x] False positive rate testing
- [x] Amplitude threshold testing
- [x] Phase accuracy testing
- [x] Tone detection with noise
- [x] Frequency tolerance testing
- [x] Multiple tone detection
- [x] Tone detection latency
- [x] Tone detection robustness

### 7. JSON API Tests (`test_json_api.cpp`)
- [x] Valid JSON parsing
- [x] Invalid JSON handling
- [x] Malformed JSON handling
- [x] Missing fields handling
- [x] Extra fields handling
- [x] Type mismatch handling
- [x] JSON status export accuracy
- [x] Round-trip JSON export/import
- [x] JSON parsing performance
- [x] Unicode handling
- [x] Large values handling
- [x] Scientific notation handling

### 8. Thread Safety Tests (`test_thread_safety.cpp`)
- [x] Concurrent read/write on all mutexes
- [x] Deadlock detection
- [x] Race condition testing
- [x] Atomic variable consistency
- [x] Lock contention under load

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
cd test/agc_squelch_tests
./run_comprehensive_tests.sh
```

### Manual Testing
```bash
# Build tests
mkdir build && cd build
cmake ..
make

# Run basic tests
./agc_squelch_tests

# Run with AddressSanitizer
./agc_squelch_tests_asan

# Run with ThreadSanitizer
./agc_squelch_tests_tsan

# Run with coverage
./agc_squelch_tests_coverage
```

### Individual Test Categories
```bash
# Run specific test categories
./agc_squelch_tests --gtest_filter="*Singleton*"
./agc_squelch_tests --gtest_filter="*AGC*"
./agc_squelch_tests --gtest_filter="*Squelch*"
./agc_squelch_tests --gtest_filter="*Audio*"
./agc_squelch_tests --gtest_filter="*Math*"
./agc_squelch_tests --gtest_filter="*Tone*"
./agc_squelch_tests --gtest_filter="*JSON*"
./agc_squelch_tests --gtest_filter="*Thread*"
```

### Memory Analysis
```bash
# Run with Valgrind
valgrind --tool=memcheck --leak-check=full ./agc_squelch_tests

# Run with AddressSanitizer
./agc_squelch_tests_asan

# Run with ThreadSanitizer
./agc_squelch_tests_tsan
```

### Code Coverage
```bash
# Generate coverage report
./agc_squelch_tests_coverage
lcov --capture --directory . --output-file coverage.info
lcov --remove coverage.info '/usr/*' --output-file coverage_filtered.info
genhtml coverage_filtered.info --output-directory coverage_html
```

### Static Analysis
```bash
# Run CppCheck
cppcheck --enable=all --std=c++17 ../../client/mumble-plugin/lib/agc_squelch.cpp

# Run Clang-Tidy
clang-tidy -checks='*' ../../client/mumble-plugin/lib/agc_squelch.cpp
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
- **11 major test categories** with 100+ individual test cases
- **Thread safety** with 20+ concurrent threads
- **Memory safety** with leak detection and sanitizers
- **Performance** with benchmarks and stress tests
- **Edge cases** with extreme values and error conditions
- **API validation** with JSON parsing and configuration
- **Mathematical accuracy** with precision and stability tests

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
- Thread safety tests use high concurrency to stress the system
- Memory tests are designed to catch leaks and buffer overflows
- Performance tests include timing benchmarks
- The test suite is designed to run in CI/CD environments

