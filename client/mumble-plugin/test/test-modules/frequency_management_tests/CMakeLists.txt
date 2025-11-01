cmake_minimum_required(VERSION 3.10)
project(Frequency_Management_Tests)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(GTest REQUIRED)
# Find GMock
find_package(PkgConfig REQUIRED)
pkg_check_modules(GMOCK REQUIRED gmock)
find_package(Threads REQUIRED)

# RapidCheck setup
set(RAPIDCHECK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../test-modul../rapidcheck_tests/lib/rapidcheck")
set(RAPIDCHECK_INCLUDE_DIR "${RAPIDCHECK_DIR}/include")
set(RAPIDCHECK_SRC_DIR "${RAPIDCHECK_DIR}/src")

# Add RapidCheck as subdirectory if not already added
if(NOT TARGET rapidcheck)
    add_subdirectory(${RAPIDCHECK_DIR} rapidcheck)
endif()

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${RAPIDCHECK_INCLUDE_DIR}
)

# Source files
set(TEST_SOURCES
    main.cpp
    test_frequency_management_main.cpp
    test_band_segment_validation.cpp
    test_aviation_frequencies.cpp
    test_maritime_frequencies.cpp
    test_frequency_offsets.cpp
    test_frequency_management_tests_properties.cpp
    # Add missing source files
    ../../lib/amateur_radio.cpp
    ../../lib/radio_model.cpp
    ../../lib/radio_model_vhf.cpp
    ../../lib/radio_model_uhf.cpp
    ../../lib/radio_model_amateur_impl.cpp
    ../../lib/radio_model_amateur_impl.cpp
    ../../lib/radio_model_aviation_hf.cpp
    ../../lib/radio_model_maritime_hf.cpp
    ../../lib/radio_model_string_impl.cpp
    ../../lib/radio_model_string_impl.cpp
    ../../lib/radio_model_hf_impl.cpp
    ../../lib/radio_model_hf_impl.cpp
    ../../lib/radio_model_uhf_impl.cpp
    ../../lib/non_amateur_hf.cpp
    ../../lib/solar_data.cpp
    ../../lib/radio_config.cpp
    ../../lib/audio_modern.cpp
    ../../lib/frequency_offset.cpp
    ../../lib/antenna_pattern_mapping.cpp
    ../../lib/propagation_physics.cpp
    ../../lib/power_management.cpp
    ../../lib/pattern_interpolation.cpp
    ../../lib/antenna_ground_system.cpp
    ../../lib/atmospheric_ducting.cpp
    ../../lib/enhanced_multipath.cpp
)

# Create test executable
add_executable(frequency_management_tests ${TEST_SOURCES})

# Link libraries
target_link_libraries(frequency_management_tests
    rapidcheck
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    rapidcheck
    Threads::Threads
    m
    pthread
)

# Compiler flags for testing
target_compile_options(frequency_management_tests PRIVATE
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
add_executable(frequency_management_tests_asan ${TEST_SOURCES})
target_link_libraries(frequency_management_tests_asan
    rapidcheck
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(frequency_management_tests_asan PRIVATE ${ASAN_FLAGS})
target_link_options(frequency_management_tests_asan PRIVATE ${ASAN_FLAGS})

# ThreadSanitizer version
add_executable(frequency_management_tests_tsan ${TEST_SOURCES})
target_link_libraries(frequency_management_tests_tsan
    rapidcheck
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(frequency_management_tests_tsan PRIVATE ${TSAN_FLAGS})
target_link_options(frequency_management_tests_tsan PRIVATE ${TSAN_FLAGS})

# Coverage version
add_executable(frequency_management_tests_coverage ${TEST_SOURCES})
target_link_libraries(frequency_management_tests_coverage
    rapidcheck
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(frequency_management_tests_coverage PRIVATE ${COVERAGE_FLAGS})
target_link_options(frequency_management_tests_coverage PRIVATE ${COVERAGE_FLAGS})

# Enable testing
enable_testing()

# Add test targets
add_test(NAME Frequency_Management_Basic_Tests COMMAND frequency_management_tests)
add_test(NAME Frequency_Management_AddressSanitizer COMMAND frequency_management_tests_asan)
add_test(NAME Frequency_Management_ThreadSanitizer COMMAND frequency_management_tests_tsan)
add_test(NAME Frequency_Management_Coverage COMMAND frequency_management_tests_coverage)

# Set test properties
set_tests_properties(Frequency_Management_Basic_Tests PROPERTIES
    TIMEOUT 300
    LABELS "basic;frequency_management"
)

set_tests_properties(Frequency_Management_AddressSanitizer PROPERTIES
    TIMEOUT 600
    LABELS "sanitizer;memory;frequency_management"
)

set_tests_properties(Frequency_Management_ThreadSanitizer PROPERTIES
    TIMEOUT 600
    LABELS "sanitizer;thread;frequency_management"
)

set_tests_properties(Frequency_Management_Coverage PROPERTIES
    TIMEOUT 300
    LABELS "coverage;frequency_management"
)

# Custom targets for different test runs
add_custom_target(run_frequency_management_basic_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "basic;frequency_management"
    DEPENDS frequency_management_tests
    COMMENT "Running basic frequency management tests"
)

add_custom_target(run_frequency_management_sanitizer_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "sanitizer;frequency_management"
    DEPENDS frequency_management_tests_asan frequency_management_tests_tsan
    COMMENT "Running frequency management sanitizer tests"
)

add_custom_target(run_frequency_management_coverage_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "coverage;frequency_management"
    DEPENDS frequency_management_tests_coverage
    COMMENT "Running frequency management coverage tests"
)

add_custom_target(run_frequency_management_all_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L frequency_management --verbose
    DEPENDS frequency_management_tests frequency_management_tests_asan frequency_management_tests_tsan frequency_management_tests_coverage
    COMMENT "Running all frequency management tests"
)

