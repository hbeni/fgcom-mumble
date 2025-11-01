# Network Module Comprehensive Test Suite

This test suite provides comprehensive testing for the Network Module using all available development and testing tools.

## Test Categories

### 5.1 UDP Protocol Tests (`test_udp_protocol.cpp`)
- [x] Packet transmission
- [x] Packet reception
- [x] Packet loss handling
- [x] Out-of-order packet handling
- [x] Duplicate packet detection
- [x] Jitter buffer management
- [x] UDP protocol performance
- [x] UDP protocol reliability

### 5.2 WebSocket Tests (`test_websocket.cpp`)
- [x] Connection establishment
- [x] Message send/receive
- [x] Binary data transfer
- [x] Ping/pong keepalive
- [x] Reconnection logic
- [x] Graceful disconnect
- [x] WebSocket performance
- [x] WebSocket reliability

### 5.3 RESTful API Tests (`test_rest_api.cpp`)
- [x] GET endpoint responses
- [x] POST data validation
- [x] PUT update operations
- [x] DELETE operations
- [x] Authentication (API keys)
- [x] Rate limiting
- [x] Error response codes
- [x] JSON schema validation
- [x] RESTful API performance

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
cd test/network_module_tests
./run_network_module_tests.sh
```

### Manual Testing
```bash
# Build tests
mkdir build && cd build
cmake ..
make

# Run basic tests
./network_module_tests

# Run with AddressSanitizer
./network_module_tests_asan

# Run with ThreadSanitizer
./network_module_tests_tsan

# Run with coverage
./network_module_tests_coverage
```

### Individual Test Categories
```bash
# Run specific test categories
./network_module_tests --gtest_filter="*UDP*"
./network_module_tests --gtest_filter="*WebSocket*"
./network_module_tests --gtest_filter="*REST*"
```

### Memory Analysis
```bash
# Run with Valgrind
valgrind --tool=memcheck --leak-check=full ./network_module_tests

# Run with AddressSanitizer
./network_module_tests_asan

# Run with ThreadSanitizer
./network_module_tests_tsan
```

### Code Coverage
```bash
# Generate coverage report
./network_module_tests_coverage
lcov --capture --directory . --output-file coverage.info
lcov --remove coverage.info '/usr/*' --output-file coverage_filtered.info
genhtml coverage_filtered.info --output-directory coverage_html
```

### Static Analysis
```bash
# Run CppCheck
cppcheck --enable=all --std=c++17 ../../client/mumble-plugin/lib/io_UDPClient.cpp

# Run Clang-Tidy
clang-tidy -checks='*' ../../client/mumble-plugin/lib/io_UDPClient.cpp
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
- **UDP protocol functionality** for packet transmission, reception, and loss handling
- **WebSocket functionality** for real-time communication and binary data transfer
- **RESTful API functionality** for HTTP operations, authentication, and rate limiting
- **Performance testing** with benchmarks and stress tests
- **Memory safety** with leak detection and sanitizers
- **Thread safety** with race condition detection

## Network Module Physics

### UDP Protocol Tests
- **Packet Transmission**: Real-time UDP packet sending with various sizes
- **Packet Reception**: UDP packet receiving with timeout handling
- **Packet Loss Handling**: Detection and recovery from lost packets
- **Out-of-Order Handling**: Processing packets received out of sequence
- **Duplicate Detection**: Identification and handling of duplicate packets
- **Jitter Buffer Management**: Buffer management for network jitter compensation

### WebSocket Tests
- **Connection Establishment**: TCP-based WebSocket connection setup
- **Message Send/Receive**: Text and binary message transmission
- **Binary Data Transfer**: Efficient binary data transmission
- **Ping/Pong Keepalive**: Connection health monitoring
- **Reconnection Logic**: Automatic reconnection after connection loss
- **Graceful Disconnect**: Clean connection termination

### RESTful API Tests
- **GET Endpoints**: HTTP GET request handling and response generation
- **POST Data Validation**: HTTP POST request validation and processing
- **PUT Update Operations**: HTTP PUT request handling for updates
- **DELETE Operations**: HTTP DELETE request handling for resource removal
- **Authentication**: API key-based authentication and authorization
- **Rate Limiting**: Request rate limiting and throttling
- **Error Response Codes**: HTTP error code generation and handling
- **JSON Schema Validation**: JSON data validation and schema compliance

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
- Network tests use realistic network protocols and data formats
- UDP tests validate packet transmission, reception, and loss handling
- WebSocket tests ensure proper real-time communication
- RESTful API tests validate HTTP operations, authentication, and rate limiting
- The test suite is designed to run in CI/CD environments
- Performance tests include timing benchmarks for critical network functions

