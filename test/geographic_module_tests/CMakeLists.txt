cmake_minimum_required(VERSION 3.10)
project(Geographic_Module_Tests)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(GTest REQUIRED)
# Find GMock
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
    test_geographic_module_main.cpp
    test_coordinate_system.cpp
    test_terrain_data.cpp
    test_vehicle_dynamics.cpp
)

# Create test executable
add_executable(geographic_module_tests ${TEST_SOURCES})

# Link libraries
target_link_libraries(geographic_module_tests
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)

# Compiler flags for testing
target_compile_options(geographic_module_tests PRIVATE
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
add_executable(geographic_module_tests_asan ${TEST_SOURCES})
target_link_libraries(geographic_module_tests_asan
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(geographic_module_tests_asan PRIVATE ${ASAN_FLAGS})
target_link_options(geographic_module_tests_asan PRIVATE ${ASAN_FLAGS})

# ThreadSanitizer version
add_executable(geographic_module_tests_tsan ${TEST_SOURCES})
target_link_libraries(geographic_module_tests_tsan
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(geographic_module_tests_tsan PRIVATE ${TSAN_FLAGS})
target_link_options(geographic_module_tests_tsan PRIVATE ${TSAN_FLAGS})

# Coverage version
add_executable(geographic_module_tests_coverage ${TEST_SOURCES})
target_link_libraries(geographic_module_tests_coverage
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(geographic_module_tests_coverage PRIVATE ${COVERAGE_FLAGS})
target_link_options(geographic_module_tests_coverage PRIVATE ${COVERAGE_FLAGS})

# Enable testing
enable_testing()

# Add test targets
add_test(NAME Geographic_Module_Basic_Tests COMMAND geographic_module_tests)
add_test(NAME Geographic_Module_AddressSanitizer COMMAND geographic_module_tests_asan)
add_test(NAME Geographic_Module_ThreadSanitizer COMMAND geographic_module_tests_tsan)
add_test(NAME Geographic_Module_Coverage COMMAND geographic_module_tests_coverage)

# Set test properties
set_tests_properties(Geographic_Module_Basic_Tests PROPERTIES
    TIMEOUT 300
    LABELS "basic;geographic_module"
)

set_tests_properties(Geographic_Module_AddressSanitizer PROPERTIES
    TIMEOUT 600
    LABELS "sanitizer;memory;geographic_module"
)

set_tests_properties(Geographic_Module_ThreadSanitizer PROPERTIES
    TIMEOUT 600
    LABELS "sanitizer;thread;geographic_module"
)

set_tests_properties(Geographic_Module_Coverage PROPERTIES
    TIMEOUT 300
    LABELS "coverage;geographic_module"
)

# Custom targets for different test runs
add_custom_target(run_geographic_module_basic_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "basic;geographic_module"
    DEPENDS geographic_module_tests
    COMMENT "Running basic geographic module tests"
)

add_custom_target(run_geographic_module_sanitizer_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "sanitizer;geographic_module"
    DEPENDS geographic_module_tests_asan geographic_module_tests_tsan
    COMMENT "Running geographic module sanitizer tests"
)

add_custom_target(run_geographic_module_coverage_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "coverage;geographic_module"
    DEPENDS geographic_module_tests_coverage
    COMMENT "Running geographic module coverage tests"
)

add_custom_target(run_geographic_module_all_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L geographic_module --verbose
    DEPENDS geographic_module_tests geographic_module_tests_asan geographic_module_tests_tsan geographic_module_tests_coverage
    COMMENT "Running all geographic module tests"
)

