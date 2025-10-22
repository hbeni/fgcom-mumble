cmake_minimum_required(VERSION 3.16)
project(rapidcheck_tests)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(GTEST_GMOCK REQUIRED gmock)

# Include directories
include_directories(${GTEST_GMOCK_INCLUDE_DIRS})
include_directories(../../client/mumble-plugin)
include_directories(../../client/mumble-plugin/lib)

# RapidCheck setup
set(RAPIDCHECK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib/rapidcheck")
set(RAPIDCHECK_INCLUDE_DIR "${RAPIDCHECK_DIR}/include")
set(RAPIDCHECK_SRC_DIR "${RAPIDCHECK_DIR}/src")

# Add RapidCheck as subdirectory if not already added
if(NOT TARGET rapidcheck)
    add_subdirectory(${RAPIDCHECK_DIR} rapidcheck)
endif()

# Source files for property-based tests
set(PROPERTY_TEST_SOURCES
    test_radio_propagation_properties.cpp
    test_audio_processing_properties.cpp
    test_antenna_pattern_properties.cpp
    test_frequency_management_properties.cpp
    test_environmental_effects_properties.cpp
    test_network_protocol_properties.cpp
    test_geographic_calculations_properties.cpp
    test_agc_squelch_properties.cpp
    test_atis_properties.cpp
    test_database_properties.cpp
    test_security_properties.cpp
    test_status_page_properties.cpp
    test_work_unit_distribution_properties.cpp
    test_webrtc_properties.cpp
    test_integration_properties.cpp
    test_performance_properties.cpp
    test_error_handling_properties.cpp
)

# Create test executable
add_executable(rapidcheck_tests ${PROPERTY_TEST_SOURCES})

# Link libraries
target_link_libraries(rapidcheck_tests 
    rapidcheck
    ${GTEST_GMOCK_LIBRARIES}
    pthread
    ssl
    crypto
    curl
    jsoncpp
)

# Compiler flags for property-based testing
target_compile_options(rapidcheck_tests PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -O2
    -g
)

# Enable testing
enable_testing()
add_test(NAME rapidcheck_tests COMMAND rapidcheck_tests)

# Custom target for running property-based tests
add_custom_target(run_property_tests
    COMMAND rapidcheck_tests
    DEPENDS rapidcheck_tests
    COMMENT "Running property-based tests with RapidCheck"
)

# Custom target for running with verbose output
add_custom_target(run_property_tests_verbose
    COMMAND rapidcheck_tests --verbose
    DEPENDS rapidcheck_tests
    COMMENT "Running property-based tests with verbose output"
)

# Custom target for running with specific seed
add_custom_target(run_property_tests_seed
    COMMAND rapidcheck_tests --seed=12345
    DEPENDS rapidcheck_tests
    COMMENT "Running property-based tests with specific seed"
)
