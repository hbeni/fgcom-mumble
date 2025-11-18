# TTS Integration Tests
# CMakeLists.txt for building TTS integration tests
#
# This file configures the build system for TTS integration tests,
# including Piper TTS integration and ATIS generation.
#
# @author FGcom-mumble Development Team
# @date 2025
# @see scripts/tts/

cmake_minimum_required(VERSION 3.10)
project(tts_integration_tests)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(GTest REQUIRED)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../scripts/tts
    ${CMAKE_CURRENT_SOURCE_DIR}/../../scripts/tts/atis_templates
)

# Source files
set(SOURCES
    test_tts_integration.cpp
    test_piper_tts.cpp
    test_atis_generation.cpp
    test_tts_configuration.cpp
    tts_integration.cpp
    piper_tts.cpp
    atis_generator.cpp
    tts_configuration.cpp
)

# Create executable
add_executable(tts_integration_tests ${SOURCES})

# Link libraries
target_link_libraries(tts_integration_tests
    GTest::GTest
    GTest::Main
    pthread
    m
)

# Compiler flags
target_compile_options(tts_integration_tests PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -O2
    -g
)

# Test discovery
include(GoogleTest)
gtest_discover_tests(tts_integration_tests)

# Install targets
install(TARGETS tts_integration_tests
    RUNTIME DESTINATION bin
)
