cmake_minimum_required(VERSION 3.10)
project(AntennaPatternModuleTests)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(GTest REQUIRED)
# Find GMock
find_package(PkgConfig REQUIRED)
pkg_check_modules(GMOCK REQUIRED gmock)
find_package(Threads REQUIRED)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../client/mumble-plugin/lib
    ${CMAKE_CURRENT_SOURCE_DIR}/../../client/mumble-plugin
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Source files
set(TEST_SOURCES
    main.cpp
    test_antenna_pattern_main.cpp
    test_nec_pattern.cpp
    test_vehicle_antenna.cpp
    test_pattern_conversion.cpp
)

# Create test executable
add_executable(antenna_pattern_module_tests ${TEST_SOURCES})

# Link libraries
target_link_libraries(antenna_pattern_module_tests
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)

# Compiler flags for testing
target_compile_options(antenna_pattern_module_tests PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -O2
    -g
)

# AddressSanitizer flags
set(ASAN_FLAGS
    -fsanitize=address
    -fno-omit-frame-pointer
    -g
)

# ThreadSanitizer flags
set(TSAN_FLAGS
    -fsanitize=thread
    -fno-omit-frame-pointer
    -g
)

# Coverage flags
set(COVERAGE_FLAGS
    -fprofile-arcs
    -ftest-coverage
    -fPIC
)

# Create different test executables for different sanitizers
# AddressSanitizer version
add_executable(antenna_pattern_module_tests_asan ${TEST_SOURCES})
target_link_libraries(antenna_pattern_module_tests_asan
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(antenna_pattern_module_tests_asan PRIVATE ${ASAN_FLAGS})
target_link_options(antenna_pattern_module_tests_asan PRIVATE ${ASAN_FLAGS})

# ThreadSanitizer version
add_executable(antenna_pattern_module_tests_tsan ${TEST_SOURCES})
target_link_libraries(antenna_pattern_module_tests_tsan
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(antenna_pattern_module_tests_tsan PRIVATE ${TSAN_FLAGS})
target_link_options(antenna_pattern_module_tests_tsan PRIVATE ${TSAN_FLAGS})

# Coverage version
add_executable(antenna_pattern_module_tests_coverage ${TEST_SOURCES})
target_link_libraries(antenna_pattern_module_tests_coverage
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(antenna_pattern_module_tests_coverage PRIVATE ${COVERAGE_FLAGS})
target_link_options(antenna_pattern_module_tests_coverage PRIVATE ${COVERAGE_FLAGS})

# Enable testing
enable_testing()

# Add test targets
add_test(NAME AntennaPatternModule_Basic_Tests COMMAND antenna_pattern_module_tests)
add_test(NAME AntennaPatternModule_AddressSanitizer COMMAND antenna_pattern_module_tests_asan)
add_test(NAME AntennaPatternModule_ThreadSanitizer COMMAND antenna_pattern_module_tests_tsan)
add_test(NAME AntennaPatternModule_Coverage COMMAND antenna_pattern_module_tests_coverage)

# Set test properties
set_tests_properties(AntennaPatternModule_Basic_Tests PROPERTIES
    TIMEOUT 300
    LABELS "basic;antenna_pattern_module"
)

set_tests_properties(AntennaPatternModule_AddressSanitizer PROPERTIES
    TIMEOUT 600
    LABELS "sanitizer;memory;antenna_pattern_module"
)

set_tests_properties(AntennaPatternModule_ThreadSanitizer PROPERTIES
    TIMEOUT 600
    LABELS "sanitizer;thread;antenna_pattern_module"
)

set_tests_properties(AntennaPatternModule_Coverage PROPERTIES
    TIMEOUT 300
    LABELS "coverage;antenna_pattern_module"
)

# Custom targets for different test runs
add_custom_target(run_antenna_pattern_module_basic_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "basic;antenna_pattern_module"
    DEPENDS antenna_pattern_module_tests
    COMMENT "Running basic antenna pattern module tests"
)

add_custom_target(run_antenna_pattern_module_sanitizer_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "sanitizer;antenna_pattern_module"
    DEPENDS antenna_pattern_module_tests_asan antenna_pattern_module_tests_tsan
    COMMENT "Running antenna pattern module sanitizer tests"
)

add_custom_target(run_antenna_pattern_module_coverage_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "coverage;antenna_pattern_module"
    DEPENDS antenna_pattern_module_tests_coverage
    COMMENT "Running antenna pattern module coverage tests"
)

add_custom_target(run_antenna_pattern_module_all_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L antenna_pattern_module --verbose
    DEPENDS antenna_pattern_module_tests antenna_pattern_module_tests_asan antenna_pattern_module_tests_tsan antenna_pattern_module_tests_coverage
    COMMENT "Running all antenna pattern module tests"
)

