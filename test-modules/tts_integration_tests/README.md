# TTS Integration Comprehensive Test Suite

This test suite provides comprehensive testing for the TTS (Text-to-Speech) Integration module using all available development and testing tools.

## Test Categories

### 1. TTS Integration System Tests (`test_tts_integration.cpp`)
- [x] System initialization and configuration
- [x] TTS model management
- [x] Text processing and preprocessing
- [x] Audio generation and validation
- [x] Performance under various conditions
- [x] Error handling and edge cases
- [x] Thread safety and concurrency

### 2. Piper TTS Tests (`test_piper_tts.cpp`)
- [x] Piper TTS installation and setup
- [x] Model loading and management
- [x] Audio quality assessment
- [x] Multiple language support
- [x] Performance optimization
- [x] Resource usage monitoring
- [x] Error handling and recovery

### 3. ATIS Generation Tests (`test_atis_generation.cpp`)
- [x] ATIS text generation
- [x] Weather information processing
- [x] Runway information formatting
- [x] Airport code validation
- [x] Phonetic alphabet conversion
- [x] ATIS audio generation
- [x] Template processing

### 4. TTS Configuration Tests (`test_tts_configuration.cpp`)
- [x] Configuration file loading
- [x] Configuration validation
- [x] Parameter management
- [x] Default settings
- [x] Custom configuration
- [x] Configuration backup and restore
- [x] Environment variable support

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
cd test/tts_integration_tests
./run_tts_integration_tests.sh
```

### Manual Testing
```bash
# Build tests
mkdir build && cd build
cmake ..
make

# Run basic tests
./tts_integration_tests

# Run with AddressSanitizer
./tts_integration_tests_asan

# Run with ThreadSanitizer
./tts_integration_tests_tsan

# Run with Valgrind
valgrind --leak-check=full ./tts_integration_tests
```

### Coverage Analysis
```bash
# Generate coverage report
./run_coverage_analysis.sh

# View coverage report
firefox coverage/index.html
```

## Test Configuration

### TTS Test Data
- **Models**: en_US-lessac-medium, en_US-lessac-high, en_US-lessac-low
- **Languages**: English (US), English (UK), German, French, Spanish
- **Sample Rates**: 8kHz, 16kHz, 22.05kHz, 44.1kHz, 48kHz
- **Bitrates**: 16kbps, 32kbps, 64kbps, 128kbps

### Test Scenarios
- **Normal Operation**: Standard TTS generation
- **High Load**: Multiple concurrent TTS requests
- **Edge Cases**: Invalid input, missing files, system errors
- **Performance**: Large text processing, memory usage

## Expected Results

### Performance Benchmarks
- **Text Processing**: < 1ms for short text
- **Audio Generation**: < 5 seconds for 1 minute of speech
- **Model Loading**: < 2 seconds for standard models
- **Memory Usage**: < 500MB for full system

### Quality Metrics
- **Audio Quality**: PESQ score > 3.0 for good models
- **Accuracy**: > 95% word accuracy for clear text
- **Latency**: < 100ms for real-time applications
- **Error Rate**: < 0.1% for valid input

## Troubleshooting

### Common Issues
1. **Piper TTS Not Found**: Check installation and PATH
2. **Model Loading Failed**: Verify model files and permissions
3. **Audio Generation Failed**: Check output directory permissions
4. **Performance Issues**: Monitor CPU and memory usage

### Debug Options
- **Verbose Logging**: Set log level to DEBUG
- **Performance Profiling**: Enable timing measurements
- **Memory Debugging**: Use AddressSanitizer
- **Thread Debugging**: Use ThreadSanitizer

## Test Data

### Sample Texts
- **Short**: "This is a test message."
- **Medium**: "The quick brown fox jumps over the lazy dog."
- **Long**: Airport weather reports and ATIS information
- **Special Characters**: Numbers, punctuation, phonetic alphabet

### ATIS Templates
- **Standard ATIS**: Basic airport information
- **Detailed ATIS**: Comprehensive weather and runway data
- **Emergency ATIS**: Emergency procedures and information

## Contributing

When adding new tests:
1. Follow the existing test structure
2. Include comprehensive error handling
3. Add performance benchmarks
4. Update documentation
5. Run all tests before submitting

## References

- [TTS Integration Documentation](../../scripts/tts/README.md)
- [Piper TTS Integration](../../scripts/tts/piper_tts_integration.sh)
- [ATIS TTS Generator](../../scripts/tts/atis_tts_generator.py)
- [TTS Configuration](../../scripts/tts/tts_config.conf)
