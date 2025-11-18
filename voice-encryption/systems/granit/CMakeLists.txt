# Granit Soviet Time-Scrambling Voice Encryption System
# CMakeLists.txt for building the Granit system
#
# This file configures the build system for the Granit Soviet time-scrambling
# voice encryption system. It defines the library target, includes directories,
# and links necessary libraries.
#
# @author FGcom-mumble Development Team
# @date 2025
# @see docs/GRANIT_DOCUMENTATION.md

cmake_minimum_required(VERSION 3.10)
project(granit)

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
    src/granit.cpp
)

# Header files
set(HEADERS
    include/granit.h
)

# Create library
add_library(granit STATIC ${SOURCES} ${HEADERS})

# Set target properties
set_target_properties(granit PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

# Compiler flags
target_compile_options(granit PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -O2
    -fPIC
)

# Link libraries
target_link_libraries(granit
    pthread
    m
)

# Install targets
install(TARGETS granit
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES ${HEADERS}
    DESTINATION include/granit
)

# Tests are now in the main tests directory
