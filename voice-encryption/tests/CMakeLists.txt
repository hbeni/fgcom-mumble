# Voice Encryption Tests
# CMakeLists.txt for building the voice encryption test suite
#
# This file configures the build system for the voice encryption test suite,
# including all test cases and their dependencies.
#
# @author FGcom-mumble Development Team
# @date 2025
# @see docs/VOICE_ENCRYPTION_MODULE.md

cmake_minimum_required(VERSION 3.10)
project(voice_encryption_tests)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(GTest REQUIRED)
find_package(GMock REQUIRED)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../systems/yachta-t219/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../systems/yachta-t219/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../systems/vinson-ky57/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../systems/vinson-ky57/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../systems/granit/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../systems/granit/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../systems/stanag-4197/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../systems/stanag-4197/src
)

# Source files
set(SOURCES
    test_voice_encryption.cpp
    test_yachta_t219.cpp
    test_vinson_ky57.cpp
    test_granit.cpp
    test_stanag_4197.cpp
)

# Create executable
add_executable(voice_encryption_tests ${SOURCES})

# Link libraries
target_link_libraries(voice_encryption_tests
    voice_encryption
    yachta_t219
    vinson_ky57
    granit
    stanag_4197
    GTest::GTest
    GTest::Main
    GMock::GMock
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

# Add test to CTest
enable_testing()
add_test(NAME voice_encryption_tests COMMAND voice_encryption_tests)

# Set test properties
set_tests_properties(voice_encryption_tests PROPERTIES
    TIMEOUT 300
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
