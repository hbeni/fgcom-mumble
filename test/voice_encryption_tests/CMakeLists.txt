# Voice Encryption Tests
# CMakeLists.txt for building voice encryption tests
#
# This file configures the build system for voice encryption tests,
# including all Cold War era encryption systems.
#
# @author FGcom-mumble Development Team
# @date 2025
# @see voice-encryption/

cmake_minimum_required(VERSION 3.10)
project(voice_encryption_tests)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(GTest REQUIRED)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../voice-encryption/systems/yachta-t219/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../voice-encryption/systems/yachta-t219/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../voice-encryption/systems/vinson-ky57/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../voice-encryption/systems/vinson-ky57/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../voice-encryption/systems/granit/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../voice-encryption/systems/granit/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../voice-encryption/systems/stanag-4197/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../voice-encryption/systems/stanag-4197/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../voice-encryption/systems/freedv/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../voice-encryption/systems/freedv/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../voice-encryption/systems/melpe/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../voice-encryption/systems/melpe/src
)

# Source files
set(SOURCES
    test_yachta_t219.cpp
    test_vinson_ky57.cpp
    test_granit.cpp
    test_stanag_4197.cpp
    test_freedv.cpp
    test_melpe.cpp
)

# Create executable
add_executable(voice_encryption_tests ${SOURCES})

# Link libraries
target_link_libraries(voice_encryption_tests
    yachta_t219
    vinson_ky57
    granit
    stanag_4197
    freedv
    melpe
    GTest::GTest
    GTest::Main
    pthread
    m
)

# Compiler flags
target_compile_options(voice_encryption_tests PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -O2
    -g
)

# Test discovery
include(GoogleTest)
gtest_discover_tests(voice_encryption_tests)

# Install targets
install(TARGETS voice_encryption_tests
    RUNTIME DESTINATION bin
)