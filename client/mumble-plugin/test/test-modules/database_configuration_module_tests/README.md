# Database/Configuration Module Comprehensive Test Suite

This test suite provides comprehensive testing for the Database/Configuration Module using all available development and testing tools.

## Test Categories

### 10.1 CSV File Parsing Tests (`test_csv_parsing.cpp`)
- [x] Amateur radio band segments CSV
- [x] Header parsing
- [x] Data type validation
- [x] Missing field handling
- [x] Comment line skipping
- [x] Quote handling
- [x] Delimiter detection
- [x] CSV parsing performance
- [x] CSV parsing accuracy

### 10.2 Configuration File Tests (`test_configuration_file.cpp`)
- [x] INI file parsing
- [x] Section handling
- [x] Key-value pair extraction
- [x] Comment handling
- [x] Default value handling
- [x] Invalid syntax handling
- [x] Configuration file performance
- [x] Configuration file accuracy

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
cd test/database_configuration_module_tests
./run_database_configuration_module_tests.sh
```

### Manual Testing
```bash
# Build tests
mkdir build && cd build
cmake ..
make

# Run basic tests
./database_configuration_module_tests

# Run with AddressSanitizer
./database_configuration_module_tests_asan

# Run with ThreadSanitizer
./database_configuration_module_tests_tsan

# Run with coverage
./database_configuration_module_tests_coverage
```

### Individual Test Categories
```bash
# Run specific test categories
./database_configuration_module_tests --gtest_filter="*CSV*"
./database_configuration_module_tests --gtest_filter="*Configuration*"
```

### Memory Analysis
```bash
# Run with Valgrind
valgrind --tool=memcheck --leak-check=full ./database_configuration_module_tests

# Run with AddressSanitizer
./database_configuration_module_tests_asan

# Run with ThreadSanitizer
./database_configuration_module_tests_tsan
```

### Code Coverage
```bash
# Generate coverage report
./database_configuration_module_tests_coverage
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
- **2 major test categories** with 100+ individual test cases
- **CSV file parsing functionality** for amateur radio band segments, header parsing, data type validation, missing field handling, comment line skipping, quote handling, and delimiter detection
- **Configuration file functionality** for INI file parsing, section handling, key-value pair extraction, comment handling, default value handling, and invalid syntax handling
- **Performance testing** with benchmarks and stress tests
- **Memory safety** with leak detection and sanitizers
- **Thread safety** with race condition detection

## Database/Configuration Module Physics

### CSV File Parsing Tests
- **Amateur Radio Band Segments CSV**: Parsing of amateur radio frequency allocations, power limits, and licensing requirements
- **Header Parsing**: Validation of CSV header format and field order
- **Data Type Validation**: Validation of field data types (string, float, int)
- **Missing Field Handling**: Detection and handling of missing or incomplete fields
- **Comment Line Skipping**: Proper handling of comment lines (# and ;)
- **Quote Handling**: Proper parsing of quoted fields with commas
- **Delimiter Detection**: Automatic detection of CSV delimiters (comma, semicolon, tab)

### Configuration File Tests
- **INI File Parsing**: Parsing of INI configuration files with sections and key-value pairs
- **Section Handling**: Proper handling of configuration sections [section_name]
- **Key-Value Pair Extraction**: Extraction and validation of key-value pairs
- **Comment Handling**: Proper handling of comment lines (# and ;)
- **Default Value Handling**: Provision of default values for missing configuration keys
- **Invalid Syntax Handling**: Detection and handling of invalid configuration syntax

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
- CSV parsing tests use realistic amateur radio band segment data
- Configuration file tests use realistic INI configuration scenarios
- The test suite is designed to run in CI/CD environments
- Performance tests include timing benchmarks for critical parsing functions

