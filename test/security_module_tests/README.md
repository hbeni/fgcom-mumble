# Security Module Comprehensive Test Suite

This test suite provides comprehensive testing for the Security Module using all available development and testing tools.

## Test Categories

### 9.1 TLS/SSL Tests (`test_tls_ssl.cpp`)
- [x] Certificate validation
- [x] Strong cipher selection
- [x] Protocol version enforcement (TLS 1.2+)
- [x] Man-in-the-middle prevention
- [x] Certificate expiration handling
- [x] TLS/SSL performance
- [x] TLS/SSL accuracy

### 9.2 Authentication Tests (`test_authentication.cpp`)
- [x] API key validation
- [x] Invalid key rejection
- [x] Key expiration
- [x] Rate limiting per key
- [x] Brute force protection
- [x] Authentication performance
- [x] Authentication accuracy

### 9.3 Input Validation Tests (`test_input_validation.cpp`)
- [x] SQL injection prevention
- [x] XSS prevention
- [x] Path traversal prevention
- [x] Buffer overflow prevention
- [x] Integer overflow prevention
- [x] Input validation performance
- [x] Input validation accuracy

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

### Security Tools
- **OpenSSL 3.0** - TLS/SSL testing and certificate validation
- **Clang 18.1.3** - LLVM-based C/C++ compiler with sanitizer support
- **LLVM 18.0** - Low Level Virtual Machine infrastructure

## Running the Tests

### Quick Start
```bash
cd test/security_module_tests
./run_security_module_tests.sh
```

### Manual Testing
```bash
# Build tests
mkdir build && cd build
cmake ..
make

# Run basic tests
./security_module_tests

# Run with AddressSanitizer
./security_module_tests_asan

# Run with ThreadSanitizer
./security_module_tests_tsan

# Run with coverage
./security_module_tests_coverage
```

### Individual Test Categories
```bash
# Run specific test categories
./security_module_tests --gtest_filter="*TLS*"
./security_module_tests --gtest_filter="*Authentication*"
./security_module_tests --gtest_filter="*InputValidation*"
```

### Memory Analysis
```bash
# Run with Valgrind
valgrind --tool=memcheck --leak-check=full ./security_module_tests

# Run with AddressSanitizer
./security_module_tests_asan

# Run with ThreadSanitizer
./security_module_tests_tsan
```

### Code Coverage
```bash
# Generate coverage report
./security_module_tests_coverage
lcov --capture --directory . --output-file coverage.info
lcov --remove coverage.info '/usr/*' --output-file coverage_filtered.info
genhtml coverage_filtered.info --output-directory coverage_html
```

### Static Analysis
```bash
# Run CppCheck
cppcheck --enable=all --std=c++17 ../../client/mumble-plugin/lib/security.cpp

# Run Clang-Tidy
clang-tidy -checks='*' ../../client/mumble-plugin/lib/security.cpp
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
- **TLS/SSL functionality** for certificate validation, cipher selection, protocol enforcement, MITM prevention, and certificate expiration handling
- **Authentication functionality** for API key validation, rate limiting, brute force protection, and key expiration
- **Input validation functionality** for SQL injection prevention, XSS prevention, path traversal prevention, buffer overflow prevention, and integer overflow prevention
- **Performance testing** with benchmarks and stress tests
- **Memory safety** with leak detection and sanitizers
- **Thread safety** with race condition detection

## Security Module Physics

### TLS/SSL Tests
- **Certificate Validation**: X.509 certificate verification and validation
- **Strong Cipher Selection**: Encryption algorithm selection and validation
- **Protocol Version Enforcement**: TLS 1.2+ protocol enforcement and validation
- **Man-in-the-Middle Prevention**: MITM attack detection and prevention
- **Certificate Expiration Handling**: Certificate lifecycle management and expiration checks

### Authentication Tests
- **API Key Validation**: API key format validation and authentication
- **Invalid Key Rejection**: Malformed and invalid key detection and rejection
- **Key Expiration**: API key lifecycle management and expiration handling
- **Rate Limiting**: Request rate limiting per API key to prevent abuse
- **Brute Force Protection**: Brute force attack detection and prevention

### Input Validation Tests
- **SQL Injection Prevention**: SQL injection attack detection and prevention
- **XSS Prevention**: Cross-site scripting attack detection and prevention
- **Path Traversal Prevention**: Directory traversal attack detection and prevention
- **Buffer Overflow Prevention**: Buffer overflow attack detection and prevention
- **Integer Overflow Prevention**: Integer overflow attack detection and prevention

## Requirements

- C++17 compatible compiler
- CMake 3.10+
- Google Test/Mock
- Valgrind
- Clang/LLVM with sanitizers
- CppCheck
- Clang-Tidy
- Lcov
- OpenSSL 3.0+

## Notes

- All tests are designed to be deterministic and repeatable
- Security tests use realistic attack patterns and security scenarios
- TLS/SSL tests validate certificate validation, cipher selection, and protocol enforcement
- Authentication tests ensure proper API key validation, rate limiting, and brute force protection
- Input validation tests validate SQL injection prevention, XSS prevention, and path traversal prevention
- The test suite is designed to run in CI/CD environments
- Performance tests include timing benchmarks for critical security functions

