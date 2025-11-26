# Yachta T-219 Soviet Analog Voice Scrambler
# CMakeLists.txt for building the Yachta T-219 system
#
# This file configures the build system for the Yachta T-219 Soviet
# analog voice scrambler system. It defines the library target,
# includes directories, and links necessary libraries.
#
# @author FGcom-mumble Development Team
# @date 2025
# @see docs/YACHTA_T219_DOCUMENTATION.md

cmake_minimum_required(VERSION 3.10)
project(yachta_t219)

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
    src/yachta_t219.cpp
)

# Header files
set(HEADERS
    include/yachta_t219.h
)

# Create library
add_library(yachta_t219 STATIC ${SOURCES} ${HEADERS})

# Compiler flags
target_compile_options(yachta_t219 PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -O2
    -g
)

# Link libraries
target_link_libraries(yachta_t219
    pthread
    m
)

# Install targets
install(TARGETS yachta_t219
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES ${HEADERS}
    DESTINATION include/yachta_t219
)

# Tests are now in the main tests directory
