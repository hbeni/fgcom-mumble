cmake_minimum_required(VERSION 3.10)
project(ATIS_Module_Tests)

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
    ${CMAKE_CURRENT_SOURCE_DIR}/../../server
    ${CMAKE_CURRENT_SOURCE_DIR}/../../client/mumble-plugin/lib
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Source files
set(TEST_SOURCES
    main.cpp
    test_atis_module_main.cpp
    test_recording.cpp
    test_playback.cpp
    test_atis_content.cpp
)

# Create test executable
add_executable(atis_module_tests ${TEST_SOURCES})

# Link libraries
target_link_libraries(atis_module_tests
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)

# Compiler flags for testing
target_compile_options(atis_module_tests PRIVATE
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
add_executable(atis_module_tests_asan ${TEST_SOURCES})
target_link_libraries(atis_module_tests_asan
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(atis_module_tests_asan PRIVATE ${ASAN_FLAGS})
target_link_options(atis_module_tests_asan PRIVATE ${ASAN_FLAGS})

# ThreadSanitizer version
add_executable(atis_module_tests_tsan ${TEST_SOURCES})
target_link_libraries(atis_module_tests_tsan
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(atis_module_tests_tsan PRIVATE ${TSAN_FLAGS})
target_link_options(atis_module_tests_tsan PRIVATE ${TSAN_FLAGS})

# Coverage version
add_executable(atis_module_tests_coverage ${TEST_SOURCES})
target_link_libraries(atis_module_tests_coverage
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(atis_module_tests_coverage PRIVATE ${COVERAGE_FLAGS})
target_link_options(atis_module_tests_coverage PRIVATE ${COVERAGE_FLAGS})

# Enable testing
enable_testing()

# Add test targets
add_test(NAME ATIS_Module_Basic_Tests COMMAND atis_module_tests)
add_test(NAME ATIS_Module_AddressSanitizer COMMAND atis_module_tests_asan)
add_test(NAME ATIS_Module_ThreadSanitizer COMMAND atis_module_tests_tsan)
add_test(NAME ATIS_Module_Coverage COMMAND atis_module_tests_coverage)

# Set test properties
set_tests_properties(ATIS_Module_Basic_Tests PROPERTIES
    TIMEOUT 300
    LABELS "basic;atis_module"
)

set_tests_properties(ATIS_Module_AddressSanitizer PROPERTIES
    TIMEOUT 600
    LABELS "sanitizer;memory;atis_module"
)

set_tests_properties(ATIS_Module_ThreadSanitizer PROPERTIES
    TIMEOUT 600
    LABELS "sanitizer;thread;atis_module"
)

set_tests_properties(ATIS_Module_Coverage PROPERTIES
    TIMEOUT 300
    LABELS "coverage;atis_module"
)

# Custom targets for different test runs
add_custom_target(run_atis_module_basic_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "basic;atis_module"
    DEPENDS atis_module_tests
    COMMENT "Running basic ATIS module tests"
)

add_custom_target(run_atis_module_sanitizer_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "sanitizer;atis_module"
    DEPENDS atis_module_tests_asan atis_module_tests_tsan
    COMMENT "Running ATIS module sanitizer tests"
)

add_custom_target(run_atis_module_coverage_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "coverage;atis_module"
    DEPENDS atis_module_tests_coverage
    COMMENT "Running ATIS module coverage tests"
)

add_custom_target(run_atis_module_all_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L atis_module --verbose
    DEPENDS atis_module_tests atis_module_tests_asan atis_module_tests_tsan atis_module_tests_coverage
    COMMENT "Running all ATIS module tests"
)

