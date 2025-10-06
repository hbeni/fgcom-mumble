# Voice Encryption Module
# CMakeLists.txt for building the voice encryption system
#
# This file configures the build system for the voice encryption module,
# including all encryption systems and their dependencies.
#
# @author FGcom-mumble Development Team
# @date 2025
# @see docs/VOICE_ENCRYPTION_MODULE.md

cmake_minimum_required(VERSION 3.10)
project(voice_encryption)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Source files
set(SOURCES
    src/voice_encryption.cpp
)

# Header files
set(HEADERS
    include/voice_encryption.h
)

# Create library
add_library(voice_encryption STATIC ${SOURCES} ${HEADERS})

# Compiler flags
target_compile_options(voice_encryption PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -O2
    -g
)

# Link libraries
target_link_libraries(voice_encryption
    pthread
    m
)

# Install targets
install(TARGETS voice_encryption
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES ${HEADERS}
    DESTINATION include/voice_encryption
)

# Add subdirectories
add_subdirectory(systems/yachta-t219)
add_subdirectory(systems/vinson-ky57)
add_subdirectory(systems/granit)
add_subdirectory(systems/stanag-4197)
add_subdirectory(tests)
