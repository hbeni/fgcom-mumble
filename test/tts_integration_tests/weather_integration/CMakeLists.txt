cmake_minimum_required(VERSION 3.16)
project(atis_weather_integration_tests)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(GTest REQUIRED)
find_package(GMock REQUIRED)
find_package(RapidCheck REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(Threads REQUIRED)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../scripts/tts
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../client/mumble-plugin
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../server
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../test
)

# Source files
set(SOURCES
    test_atis_weather_integration.cpp
)

# Create test executable
add_executable(atis_weather_integration_tests ${SOURCES})

# Link libraries
target_link_libraries(atis_weather_integration_tests
    GTest::gtest
    GTest::gtest_main
    GMock::gmock
    GMock::gmock_main
    rapidcheck
    nlohmann_json::nlohmann_json
    Threads::Threads
)

# Compiler flags
target_compile_options(atis_weather_integration_tests PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Werror
    -O2
    -g
)

# Add test to CTest
include(GoogleTest)
gtest_discover_tests(atis_weather_integration_tests)

# Add property-based tests
add_custom_target(run_property_tests
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/atis_weather_integration_tests --gtest_filter="*Property*"
    DEPENDS atis_weather_integration_tests
    COMMENT "Running property-based tests"
)

# Add integration tests
add_custom_target(run_integration_tests
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/atis_weather_integration_tests --gtest_filter="*Integration*"
    DEPENDS atis_weather_integration_tests
    COMMENT "Running integration tests"
)

# Add all tests
add_custom_target(run_all_atis_weather_tests
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/atis_weather_integration_tests
    DEPENDS atis_weather_integration_tests
    COMMENT "Running all ATIS weather integration tests"
)
