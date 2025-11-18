# VINSON KY-57/KY-58 NATO Secure Voice System
# CMakeLists.txt for building the VINSON KY-57 system
#
# This file configures the build system for the VINSON KY-57 NATO secure
# voice system. It defines the library target, includes directories, and
# links necessary libraries.
#
# @author FGcom-mumble Development Team
# @date 2025
# @see docs/VINSON_KY57_DOCUMENTATION.md

cmake_minimum_required(VERSION 3.10)
project(vinson_ky57)

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
    src/vinson_ky57.cpp
)

# Header files
set(HEADERS
    include/vinson_ky57.h
)

# Create library
add_library(vinson_ky57 STATIC ${SOURCES} ${HEADERS})

# Set target properties
set_target_properties(vinson_ky57 PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

# Compiler flags
target_compile_options(vinson_ky57 PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -O2
    -fPIC
)

# Link libraries
target_link_libraries(vinson_ky57
    pthread
    m
)

# Install targets
install(TARGETS vinson_ky57
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES ${HEADERS}
    DESTINATION include/vinson_ky57
)

# Tests are now in the main tests directory
