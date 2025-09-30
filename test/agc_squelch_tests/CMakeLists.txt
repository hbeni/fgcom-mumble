cmake_minimum_required(VERSION 3.10)
project(AGC_Squelch_Tests)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(GTest REQUIRED)
find_package(Threads REQUIRED)

# Find GMock
find_package(PkgConfig REQUIRED)
pkg_check_modules(GMOCK REQUIRED gmock)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../client/mumble-plugin/lib
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Source files
set(TEST_SOURCES
    main.cpp
    test_agc_squelch_main.cpp
    test_singleton.cpp
    test_agc_config.cpp
    test_squelch_config.cpp
    test_audio_processing.cpp
    test_math_functions.cpp
    ../../client/mumble-plugin/lib/agc_squelch.cpp
)

# Create test executable
add_executable(agc_squelch_tests ${TEST_SOURCES})

# Link libraries
target_link_libraries(agc_squelch_tests
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)

# Compiler flags for testing
target_compile_options(agc_squelch_tests PRIVATE
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
add_executable(agc_squelch_tests_asan ${TEST_SOURCES})
target_link_libraries(agc_squelch_tests_asan
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(agc_squelch_tests_asan PRIVATE ${ASAN_FLAGS})
target_link_options(agc_squelch_tests_asan PRIVATE ${ASAN_FLAGS})

# ThreadSanitizer version
add_executable(agc_squelch_tests_tsan ${TEST_SOURCES})
target_link_libraries(agc_squelch_tests_tsan
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(agc_squelch_tests_tsan PRIVATE ${TSAN_FLAGS})
target_link_options(agc_squelch_tests_tsan PRIVATE ${TSAN_FLAGS})

# Coverage version
add_executable(agc_squelch_tests_coverage ${TEST_SOURCES})
target_link_libraries(agc_squelch_tests_coverage
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(agc_squelch_tests_coverage PRIVATE ${COVERAGE_FLAGS})
target_link_options(agc_squelch_tests_coverage PRIVATE ${COVERAGE_FLAGS})

# Enable testing
enable_testing()

# Add test targets
add_test(NAME AGC_Squelch_Basic_Tests COMMAND agc_squelch_tests)
add_test(NAME AGC_Squelch_AddressSanitizer COMMAND agc_squelch_tests_asan)
add_test(NAME AGC_Squelch_ThreadSanitizer COMMAND agc_squelch_tests_tsan)
add_test(NAME AGC_Squelch_Coverage COMMAND agc_squelch_tests_coverage)

# Set test properties
set_tests_properties(AGC_Squelch_Basic_Tests PROPERTIES
    TIMEOUT 300
    LABELS "basic"
)

set_tests_properties(AGC_Squelch_AddressSanitizer PROPERTIES
    TIMEOUT 600
    LABELS "sanitizer;memory"
)

set_tests_properties(AGC_Squelch_ThreadSanitizer PROPERTIES
    TIMEOUT 600
    LABELS "sanitizer;thread"
)

set_tests_properties(AGC_Squelch_Coverage PROPERTIES
    TIMEOUT 300
    LABELS "coverage"
)

# Custom targets for different test runs
add_custom_target(run_basic_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L basic
    DEPENDS agc_squelch_tests
    COMMENT "Running basic AGC/Squelch tests"
)

add_custom_target(run_sanitizer_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L sanitizer
    DEPENDS agc_squelch_tests_asan agc_squelch_tests_tsan
    COMMENT "Running sanitizer tests"
)

add_custom_target(run_coverage_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L coverage
    DEPENDS agc_squelch_tests_coverage
    COMMENT "Running coverage tests"
)

add_custom_target(run_all_tests
    COMMAND ${CMAKE_CTEST_COMMAND} --verbose
    DEPENDS agc_squelch_tests agc_squelch_tests_asan agc_squelch_tests_tsan agc_squelch_tests_coverage
    COMMENT "Running all AGC/Squelch tests"
)
