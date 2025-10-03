cmake_minimum_required(VERSION 3.10)
project(OpenStreetMap_Infrastructure_Tests)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(GTest REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(GMOCK REQUIRED gmock)
find_package(Threads REQUIRED)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../client/mumble-plugin/lib
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Source files
set(TEST_SOURCES
    test_openinframap_integration.cpp
    test_openstreetmap_integration.cpp
    test_openstreetmap_infrastructure_main.cpp
)

# Create test executable
add_executable(openstreetmap_infrastructure_tests ${TEST_SOURCES})

# Link libraries
target_link_libraries(openstreetmap_infrastructure_tests
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)

# Compiler flags for testing
target_compile_options(openstreetmap_infrastructure_tests PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -O2
    -g
)

# AddressSanitizer flags
set(ASAN_FLAGS
    -fsanitize=address
    -fno-omit-frame-pointer
    -g
)

# ThreadSanitizer flags
set(TSAN_FLAGS
    -fsanitize=thread
    -fno-omit-frame-pointer
    -g
)

# Coverage flags
set(COVERAGE_FLAGS
    -fprofile-arcs
    -ftest-coverage
    -fPIC
)

# Create different test executables for different sanitizers
# AddressSanitizer version
add_executable(openstreetmap_infrastructure_tests_asan ${TEST_SOURCES})
target_link_libraries(openstreetmap_infrastructure_tests_asan
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(openstreetmap_infrastructure_tests_asan PRIVATE ${ASAN_FLAGS})
target_link_options(openstreetmap_infrastructure_tests_asan PRIVATE ${ASAN_FLAGS})

# ThreadSanitizer version
add_executable(openstreetmap_infrastructure_tests_tsan ${TEST_SOURCES})
target_link_libraries(openstreetmap_infrastructure_tests_tsan
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(openstreetmap_infrastructure_tests_tsan PRIVATE ${TSAN_FLAGS})
target_link_options(openstreetmap_infrastructure_tests_tsan PRIVATE ${TSAN_FLAGS})

# Coverage version
add_executable(openstreetmap_infrastructure_tests_coverage ${TEST_SOURCES})
target_link_libraries(openstreetmap_infrastructure_tests_coverage
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(openstreetmap_infrastructure_tests_coverage PRIVATE ${COVERAGE_FLAGS})
target_link_options(openstreetmap_infrastructure_tests_coverage PRIVATE ${COVERAGE_FLAGS})

# Enable testing
enable_testing()

# Add test targets
add_test(NAME OpenStreetMap_Infrastructure_Basic_Tests COMMAND openstreetmap_infrastructure_tests)
add_test(NAME OpenStreetMap_Infrastructure_AddressSanitizer COMMAND openstreetmap_infrastructure_tests_asan)
add_test(NAME OpenStreetMap_Infrastructure_ThreadSanitizer COMMAND openstreetmap_infrastructure_tests_tsan)
add_test(NAME OpenStreetMap_Infrastructure_Coverage COMMAND openstreetmap_infrastructure_tests_coverage)

# Set test properties
set_tests_properties(OpenStreetMap_Infrastructure_Basic_Tests PROPERTIES
    TIMEOUT 300
    LABELS "basic;openstreetmap;infrastructure"
)

set_tests_properties(OpenStreetMap_Infrastructure_AddressSanitizer PROPERTIES
    TIMEOUT 600
    LABELS "sanitizer;memory;openstreetmap;infrastructure"
)

set_tests_properties(OpenStreetMap_Infrastructure_ThreadSanitizer PROPERTIES
    TIMEOUT 600
    LABELS "sanitizer;thread;openstreetmap;infrastructure"
)

set_tests_properties(OpenStreetMap_Infrastructure_Coverage PROPERTIES
    TIMEOUT 300
    LABELS "coverage;openstreetmap;infrastructure"
)



