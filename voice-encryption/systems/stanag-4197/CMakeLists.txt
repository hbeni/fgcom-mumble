# STANAG 4197 NATO QPSK OFDM Voice Encryption System
# CMakeLists.txt for building the STANAG 4197 system
#
# This file configures the build system for the STANAG 4197 NATO QPSK OFDM
# voice encryption system. It defines the library target, includes directories,
# and links necessary libraries.
#
# @author FGcom-mumble Development Team
# @date 2025
# @see docs/STANAG_4197_DOCUMENTATION.md

cmake_minimum_required(VERSION 3.10)
project(stanag_4197)

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
    src/stanag_4197.cpp
)

# Header files
set(HEADERS
    include/stanag_4197.h
)

# Create library
add_library(stanag_4197 STATIC ${SOURCES} ${HEADERS})

# Set target properties
set_target_properties(stanag_4197 PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

# Compiler flags
target_compile_options(stanag_4197 PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -O2
    -fPIC
)

# Link libraries
target_link_libraries(stanag_4197
    pthread
    m
)

# Install targets
install(TARGETS stanag_4197
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES ${HEADERS}
    DESTINATION include/stanag_4197
)

# Tests are now in the main tests directory
