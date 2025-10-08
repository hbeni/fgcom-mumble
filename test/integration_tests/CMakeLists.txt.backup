cmake_minimum_required(VERSION 3.16)
project(integration_tests)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(GTEST_GMOCK REQUIRED gmock)

# Include directories
include_directories(${GTEST_GMOCK_INCLUDE_DIRS})

# Source files
set(TEST_SOURCES
    test_integration_main.cpp
    test_end_to_end.cpp
    test_multi_client.cpp
    test_stress.cpp
)

# Create test executable
add_executable(integration_tests ${TEST_SOURCES})

# Link libraries
target_link_libraries(integration_tests 
    ${GTEST_GMOCK_LIBRARIES}
    pthread
)

# Enable testing
enable_testing()
add_test(NAME integration_tests COMMAND integration_tests)
