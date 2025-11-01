# Satellite Communication Tests
# CMakeLists.txt for building satellite communication tests
#
# This file configures the build system for satellite communication tests,
# including military, amateur, and IoT satellite systems.
#
# @author FGcom-mumble Development Team
# @date 2025
# @see voice-encryption/systems/satellites/

cmake_minimum_required(VERSION 3.10)
project(satellite_communication_tests)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(GTest REQUIRED)
find_package(GMock REQUIRED)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../voice-encryption/systems/satellites/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../voice-encryption/systems/satellites/military
    ${CMAKE_CURRENT_SOURCE_DIR}/../../voice-encryption/systems/satellites/amateur
    ${CMAKE_CURRENT_SOURCE_DIR}/../../voice-encryption/systems/satellites/iot
    ${CMAKE_CURRENT_SOURCE_DIR}/../../voice-encryption/systems/satellites/orbital
)

# Source files
set(SOURCES
    test_satellite_communication.cpp
    test_military_satellites.cpp
    test_amateur_satellites.cpp
    test_iot_satellites.cpp
    test_orbital_mechanics.cpp
    test_tle_support.cpp
)

# Create executable
add_executable(satellite_communication_tests ${SOURCES})

# Link libraries
target_link_libraries(satellite_communication_tests
    satellite_communication
    strela_3
    fltsatcom
    ao_7
    iss
    orbcomm
    gonets
    tle_support
    GTest::GTest
    GTest::Main
    GMock::GMock
    pthread
    m
)

# Compiler flags
target_compile_options(satellite_communication_tests PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -O2
    -g
)

# Test discovery
include(GoogleTest)
gtest_discover_tests(satellite_communication_tests)

# Install targets
install(TARGETS satellite_communication_tests
    RUNTIME DESTINATION bin
)
