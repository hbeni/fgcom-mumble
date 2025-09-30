# Audio Processing Comprehensive Test Suite

This test suite provides comprehensive testing for the Audio Processing module using all available development and testing tools.

## Test Categories

### 4.1 Codec Tests (`test_codec.cpp`)
- [x] Opus encoding/decoding
- [x] Bitrate adaptation
- [x] Packet loss concealment
- [x] Forward error correction
- [x] Latency measurement
- [x] Codec performance
- [x] Codec quality assessment

### 4.2 Audio Effects Tests (`test_audio_effects.cpp`)
- [x] Background noise injection
- [x] Squelch tail elimination
- [x] Click removal
- [x] Audio limiting
- [x] Compression/expansion
- [x] Audio effects combination
- [x] Audio effects performance
- [x] Audio effects quality assessment

### 4.3 Sample Rate Conversion Tests (`test_sample_rate_conversion.cpp`)
- [x] Upsampling (8k to 48k)
- [x] Downsampling (48k to 8k)
- [x] Arbitrary rate conversion
- [x] Anti-aliasing filter verification
- [x] Interpolation accuracy
- [x] Sample rate conversion performance
- [x] Sample rate conversion quality
- [x] Sample rate conversion edge cases

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
cd test/audio_processing_tests
./run_audio_processing_tests.sh
```

### Manual Testing
```bash
# Build tests
mkdir build && cd build
cmake ..
make

# Run basic tests
./audio_processing_tests

# Run with AddressSanitizer
./audio_processing_tests_asan

# Run with ThreadSanitizer
./audio_processing_tests_tsan

# Run with coverage
./audio_processing_tests_coverage
```

### Individual Test Categories
```bash
# Run specific test categories
./audio_processing_tests --gtest_filter="*Codec*"
./audio_processing_tests --gtest_filter="*AudioEffects*"
./audio_processing_tests --gtest_filter="*SampleRate*"
```

### Memory Analysis
```bash
# Run with Valgrind
valgrind --tool=memcheck --leak-check=full ./audio_processing_tests

# Run with AddressSanitizer
./audio_processing_tests_asan

# Run with ThreadSanitizer
./audio_processing_tests_tsan
```

### Code Coverage
```bash
# Generate coverage report
./audio_processing_tests_coverage
lcov --capture --directory . --output-file coverage.info
lcov --remove coverage.info '/usr/*' --output-file coverage_filtered.info
genhtml coverage_filtered.info --output-directory coverage_html
```

### Static Analysis
```bash
# Run CppCheck
cppcheck --enable=all --std=c++17 ../../client/mumble-plugin/lib/audio.cpp

# Run Clang-Tidy
clang-tidy -checks='*' ../../client/mumble-plugin/lib/audio.cpp
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
- **Codec functionality** for Opus encoding/decoding with bitrate adaptation
- **Audio effects processing** for noise reduction and signal enhancement
- **Sample rate conversion** for upsampling, downsampling, and anti-aliasing
- **Performance testing** with benchmarks and stress tests
- **Memory safety** with leak detection and sanitizers
- **Thread safety** with race condition detection

## Audio Processing Physics

### Codec Tests
- **Opus Encoding/Decoding**: Lossy audio compression with variable bitrate
- **Bitrate Adaptation**: Dynamic bitrate adjustment based on network conditions
- **Packet Loss Concealment**: Error recovery for missing audio packets
- **Forward Error Correction**: Redundant data for error correction
- **Latency Measurement**: Real-time audio processing timing

### Audio Effects Tests
- **Background Noise Injection**: Simulated environmental noise
- **Squelch Tail Elimination**: Removal of low-level noise after signal ends
- **Click Removal**: Detection and removal of audio artifacts
- **Audio Limiting**: Prevention of signal clipping and distortion
- **Compression/Expansion**: Dynamic range control for audio signals

### Sample Rate Conversion Tests
- **Upsampling**: Increasing sample rate (8kHz to 48kHz)
- **Downsampling**: Decreasing sample rate (48kHz to 8kHz)
- **Arbitrary Rate Conversion**: Custom sample rate conversion
- **Anti-Aliasing Filtering**: Prevention of aliasing artifacts
- **Interpolation Accuracy**: High-quality sample interpolation

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
- Audio processing tests use realistic audio signal models
- Codec tests validate Opus encoding/decoding with bitrate adaptation
- Audio effects tests ensure proper noise reduction and signal enhancement
- Sample rate conversion tests validate anti-aliasing and interpolation accuracy
- The test suite is designed to run in CI/CD environments
- Performance tests include timing benchmarks for critical audio functions

