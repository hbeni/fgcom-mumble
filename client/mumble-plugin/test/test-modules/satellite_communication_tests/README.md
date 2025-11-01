# Satellite Communication Comprehensive Test Suite

This test suite provides comprehensive testing for the Satellite Communication module using all available development and testing tools.

## Test Categories

### 1. Satellite Communication System Tests (`test_satellite_communication.cpp`)
- [x] System initialization and configuration
- [x] Frequency management and allocation
- [x] Communication protocols and modes
- [x] Signal processing and modulation
- [x] Error handling and edge cases
- [x] Performance under various conditions
- [x] Integration with voice encryption systems

### 2. Military Satellite Tests (`test_military_satellites.cpp`)
- [x] Strela-3 series satellite communication
- [x] FLTSATCOM series satellite communication
- [x] Tsiklon/Tsikada navigation satellites
- [x] Military frequency management
- [x] Tactical communication protocols
- [x] Store-and-forward messaging
- [x] Military satellite performance

### 3. Amateur Radio Satellite Tests (`test_amateur_satellites.cpp`)
- [x] AO-7 (AMSAT-OSCAR 7) linear transponder
- [x] FO-29 (Fuji-OSCAR 29) linear transponder
- [x] AO-73 (FUNcube-1) linear transponder
- [x] XW-2 series Chinese satellites
- [x] SO-50 FM voice repeater
- [x] AO-91, AO-85 FM voice repeaters
- [x] ISS amateur radio operations
- [x] Digital mode satellites (NO-84, LilacSat-2, AO-95)

### 4. IoT Satellite Tests (`test_iot_satellites.cpp`)
- [x] Orbcomm satellite communication
- [x] Gonets satellite communication
- [x] Machine-to-machine (M2M) protocols
- [x] Data transmission and reception
- [x] IoT satellite performance
- [x] Asset tracking functionality

### 5. Orbital Mechanics Tests (`test_orbital_mechanics.cpp`)
- [x] TLE (Two-Line Element) parsing
- [x] SGP4/SDP4 orbital calculations
- [x] Satellite position prediction
- [x] Visibility calculations
- [x] Elevation and azimuth calculations
- [x] Doppler shift compensation
- [x] Orbital mechanics performance

### 6. TLE Support Tests (`test_tle_support.cpp`)
- [x] TLE file parsing and validation
- [x] Automatic TLE updates
- [x] TLE data integrity checks
- [x] Multiple TLE source support
- [x] TLE backup and recovery
- [x] TLE update scheduling

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
cd test/satellite_communication_tests
./run_satellite_communication_tests.sh
```

### Manual Testing
```bash
# Build tests
mkdir build && cd build
cmake ..
make

# Run basic tests
./satellite_communication_tests

# Run with AddressSanitizer
./satellite_communication_tests_asan

# Run with ThreadSanitizer
./satellite_communication_tests_tsan

# Run with Valgrind
valgrind --leak-check=full ./satellite_communication_tests
```

### Coverage Analysis
```bash
# Generate coverage report
./run_coverage_analysis.sh

# View coverage report
firefox coverage/index.html
```

## Test Configuration

### Satellite Test Data
- **Military Satellites**: Strela-3, FLTSATCOM, Tsiklon
- **Amateur Satellites**: AO-7, FO-29, AO-73, XW-2 series, SO-50, AO-91, AO-85, ISS
- **IoT Satellites**: Orbcomm, Gonets
- **Test Frequencies**: 150-174 MHz (military), 144-146 MHz (2m), 430-440 MHz (70cm)

### Test Scenarios
- **Normal Operation**: Standard satellite communication
- **Poor Conditions**: Low SNR, interference, multipath
- **Edge Cases**: Invalid parameters, missing data, system errors
- **Performance**: High load, concurrent operations, memory usage

## Expected Results

### Performance Benchmarks
- **Signal Processing**: < 1ms for 128ms of audio
- **Satellite Tracking**: < 10ms for position calculation
- **TLE Updates**: < 5 seconds for file update
- **Memory Usage**: < 100MB for full system

### Quality Metrics
- **Signal Quality**: SNR > 10dB for good reception
- **Tracking Accuracy**: < 1° error in elevation/azimuth
- **Update Frequency**: TLE updates every 60 minutes
- **Error Rate**: < 0.1% for data transmission

## Troubleshooting

### Common Issues
1. **TLE File Not Found**: Check TLE source configuration
2. **Satellite Not Visible**: Verify orbital parameters and time
3. **Frequency Conflicts**: Check frequency allocation
4. **Performance Issues**: Monitor CPU and memory usage

### Debug Options
- **Verbose Logging**: Set log level to DEBUG
- **Performance Profiling**: Enable timing measurements
- **Memory Debugging**: Use AddressSanitizer
- **Thread Debugging**: Use ThreadSanitizer

## Contributing

When adding new tests:
1. Follow the existing test structure
2. Include comprehensive error handling
3. Add performance benchmarks
4. Update documentation
5. Run all tests before submitting

## References

- [Satellite Communication Documentation](../../voice-encryption/systems/satellites/docs/SATELLITE_COMMUNICATION_DOCUMENTATION.md)
- [TLE Support Documentation](../../voice-encryption/systems/satellites/orbital/tle_support.h)
- [Satellite Configuration](../../configs/satellite_config.conf)
