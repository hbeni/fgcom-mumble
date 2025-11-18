# Testing Framework

FGCom-mumble includes a comprehensive testing framework with strict quality standards and comprehensive test coverage:

## Test Suite Overview
The project includes multiple test suites covering all critical components:

### **AGC/Squelch Module Tests** (`test/agc_squelch_tests/`)
- **`test_agc_squelch_main.cpp`** - Main test framework with thread-safe fixtures and comprehensive validation
- **`test_agc_config.cpp`** - AGC configuration testing with proper bounds checking and error handling
- **`test_thread_safety.cpp`** - Thread safety testing with concurrent operations and race condition detection
- **`test_singleton.cpp`** - Singleton pattern testing with thread-safe access validation
- **Features**: Thread-safe access methods, comprehensive input validation, proper error handling, atomic operations

### **Integration Tests** (`test/integration_tests/`)
- **`test_integration_main.cpp`** - End-to-end integration testing with mock components
- **Features**: Mock client/server testing, audio processing validation, connection testing

### **Status Page Module Tests** (`test/status_page_module_tests/`)
- **`test_status_page_main.cpp`** - Status page rendering and data processing tests
- **Features**: HTML rendering validation, data processing tests, WebSocket testing

### **Error Handling Tests** (`test/error_handling_tests/`)
- **`test_error_handling_main.cpp`** - Comprehensive error handling and recovery testing
- **Features**: Exception handling, resource management, error propagation testing

### **Performance Tests** (`test/performance_tests/`)
- **`test_performance_main.cpp`** - Performance and latency testing
- **Features**: Audio encoding/decoding performance, network transmission testing, propagation calculation testing

## Test Quality Standards
All tests adhere to strict quality standards:
- **Thread Safety**: All operations are properly synchronized with mutex protection
- **Error Handling**: Comprehensive try-catch blocks with proper exception propagation
- **Memory Management**: RAII principles with proper resource cleanup
- **Input Validation**: All inputs validated with bounds checking and sanitization
- **Race Condition Prevention**: Atomic operations and proper synchronization
- **Resource Management**: Exception-safe destructors and cleanup
- **Code Quality**: Clean separation of concerns and maintainable structure

## Test Execution
```bash
# Compile individual test suites
cd test/agc_squelch_tests
g++ -std=c++17 -I../../client/mumble-plugin/lib -I. -lgtest -lgmock -pthread test_agc_squelch_main.cpp test_agc_config.cpp test_thread_safety.cpp -o agc_squelch_tests

# Run tests with sanitizers
cd test/agc_squelch_tests
make test_with_sanitizers

# Run tests with coverage
cd test/agc_squelch_tests
make test_with_coverage
```

## Test Coverage
- **Unit Tests**: Individual component testing with mock objects
- **Integration Tests**: End-to-end system testing
- **Thread Safety Tests**: Concurrent operation validation
- **Performance Tests**: Latency and throughput measurement
- **Error Handling Tests**: Exception and error recovery testing
- **Memory Safety Tests**: Memory leak detection and resource management

## Testing Framework Compilation
The comprehensive testing framework can be compiled and executed as follows:

```bash
# AGC/Squelch Module Tests
cd test/agc_squelch_tests
g++ -std=c++17 -I../../client/mumble-plugin/lib -I. -lgtest -lgmock -pthread test_agc_squelch_main.cpp test_agc_config.cpp test_thread_safety.cpp -o agc_squelch_tests

# Integration Tests
cd test/integration_tests
g++ -std=c++17 -I../../client/mumble-plugin/lib -I. -lgtest -lgmock -pthread test_integration_main.cpp -o integration_tests

# Status Page Module Tests
cd test/status_page_module_tests
g++ -std=c++17 -I../../client/mumble-plugin/lib -I. -lgtest -lgmock -pthread test_status_page_main.cpp -o status_page_tests

# Error Handling Tests
cd test/error_handling_tests
g++ -std=c++17 -I../../client/mumble-plugin/lib -I. -lgtest -lgmock -pthread test_error_handling_main.cpp -o error_handling_tests

# Performance Tests
cd test/performance_tests
g++ -std=c++17 -I../../client/mumble-plugin/lib -I. -lgtest -lgmock -pthread test_performance_main.cpp -o performance_tests
```

**All test files compile successfully and adhere to strict quality standards including thread safety, error handling, memory management, and input validation.**
