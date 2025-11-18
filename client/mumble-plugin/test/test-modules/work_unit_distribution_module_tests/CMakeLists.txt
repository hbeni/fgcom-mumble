cmake_minimum_required(VERSION 3.10)
project(WorkUnitDistributionModuleTests)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(GTest REQUIRED)

# Dynamic GPU Scaling Configuration
add_definitions(-DDYNAMIC_GPU_SCALING_ENABLED)
add_definitions(-DMAX_LOCAL_GPUS=4)
add_definitions(-DMAX_NETWORK_GPUS=8)
add_definitions(-DSCALING_THRESHOLDS="20,50,100,150,200")
add_definitions(-DNETWORK_BANDWIDTH_LIMIT_MBPS=1000)
add_definitions(-DNETWORK_LATENCY_LIMIT_MS=100)

# RapidCheck setup
set(RAPIDCHECK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../test-modul../rapidcheck_tests/lib/rapidcheck")
set(RAPIDCHECK_INCLUDE_DIR "${RAPIDCHECK_DIR}/include")
set(RAPIDCHECK_SRC_DIR "${RAPIDCHECK_DIR}/src")

# Add RapidCheck as subdirectory if not already added
if(NOT TARGET rapidcheck)
    add_subdirectory(${RAPIDCHECK_DIR} rapidcheck)
endif()

# Find GMock
find_package(PkgConfig REQUIRED)

# RapidCheck setup
set(RAPIDCHECK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../test-modul../rapidcheck_tests/lib/rapidcheck")
set(RAPIDCHECK_INCLUDE_DIR "${RAPIDCHECK_DIR}/include")
set(RAPIDCHECK_SRC_DIR "${RAPIDCHECK_DIR}/src")

# Add RapidCheck as subdirectory if not already added
if(NOT TARGET rapidcheck)
    add_subdirectory(${RAPIDCHECK_DIR} rapidcheck)
endif()

pkg_check_modules(GMOCK REQUIRED gmock)
find_package(Threads REQUIRED)

# RapidCheck setup
set(RAPIDCHECK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../test-modul../rapidcheck_tests/lib/rapidcheck")
set(RAPIDCHECK_INCLUDE_DIR "${RAPIDCHECK_DIR}/include")
set(RAPIDCHECK_SRC_DIR "${RAPIDCHECK_DIR}/src")

# Add RapidCheck as subdirectory if not already added
if(NOT TARGET rapidcheck)
    add_subdirectory(${RAPIDCHECK_DIR} rapidcheck)
endif()


# Include directories
include_directories(
    ${RAPIDCHECK_INCLUDE_DIR}

    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib
    ${CMAKE_CURRENT_SOURCE_DIR}/../../client/mumble-plugin
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Source files
set(TEST_SOURCES
    test_work_unit_distribution_module_tests_properties.cpp

    test_work_unit_distribution_rewritten.cpp
)

# Create test executable
add_executable(work_unit_distribution_module_tests ${TEST_SOURCES})

# Link libraries
target_link_libraries(work_unit_distribution_module_tests
    rapidcheck
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)

# Compiler flags for testing
target_compile_options(work_unit_distribution_module_tests PRIVATE
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
add_executable(work_unit_distribution_module_tests_asan ${TEST_SOURCES})
target_link_libraries(work_unit_distribution_module_tests_asan
    rapidcheck
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(work_unit_distribution_module_tests_asan PRIVATE ${ASAN_FLAGS})
target_link_options(work_unit_distribution_module_tests_asan PRIVATE ${ASAN_FLAGS})

# ThreadSanitizer version
add_executable(work_unit_distribution_module_tests_tsan ${TEST_SOURCES})
target_link_libraries(work_unit_distribution_module_tests_tsan
    rapidcheck
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(work_unit_distribution_module_tests_tsan PRIVATE ${TSAN_FLAGS})
target_link_options(work_unit_distribution_module_tests_tsan PRIVATE ${TSAN_FLAGS})

# Coverage version
add_executable(work_unit_distribution_module_tests_coverage ${TEST_SOURCES})
target_link_libraries(work_unit_distribution_module_tests_coverage
    rapidcheck
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(work_unit_distribution_module_tests_coverage PRIVATE ${COVERAGE_FLAGS})
target_link_options(work_unit_distribution_module_tests_coverage PRIVATE ${COVERAGE_FLAGS})

# Enable testing
enable_testing()

# Add test targets
add_test(NAME WorkUnitDistributionModule_Basic_Tests COMMAND work_unit_distribution_module_tests)
add_test(NAME WorkUnitDistributionModule_AddressSanitizer COMMAND work_unit_distribution_module_tests_asan)
add_test(NAME WorkUnitDistributionModule_ThreadSanitizer COMMAND work_unit_distribution_module_tests_tsan)
add_test(NAME WorkUnitDistributionModule_Coverage COMMAND work_unit_distribution_module_tests_coverage)

# Set test properties
set_tests_properties(WorkUnitDistributionModule_Basic_Tests PROPERTIES
    TIMEOUT 300
    LABELS "basic;work_unit_distribution_module"
)

set_tests_properties(WorkUnitDistributionModule_AddressSanitizer PROPERTIES
    TIMEOUT 600
    LABELS "sanitizer;memory;work_unit_distribution_module"
)

set_tests_properties(WorkUnitDistributionModule_ThreadSanitizer PROPERTIES
    TIMEOUT 600
    LABELS "sanitizer;thread;work_unit_distribution_module"
)

set_tests_properties(WorkUnitDistributionModule_Coverage PROPERTIES
    TIMEOUT 300
    LABELS "coverage;work_unit_distribution_module"
)

# Custom targets for different test runs
add_custom_target(run_work_unit_distribution_module_basic_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "basic;work_unit_distribution_module"
    DEPENDS work_unit_distribution_module_tests
    COMMENT "Running basic work unit distribution module tests"
)

add_custom_target(run_work_unit_distribution_module_sanitizer_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "sanitizer;work_unit_distribution_module"
    DEPENDS work_unit_distribution_module_tests_asan work_unit_distribution_module_tests_tsan
    COMMENT "Running work unit distribution module sanitizer tests"
)

add_custom_target(run_work_unit_distribution_module_coverage_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "coverage;work_unit_distribution_module"
    DEPENDS work_unit_distribution_module_tests_coverage
    COMMENT "Running work unit distribution module coverage tests"
)

add_custom_target(run_work_unit_distribution_module_all_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L work_unit_distribution_module --verbose
    DEPENDS work_unit_distribution_module_tests work_unit_distribution_module_tests_asan work_unit_distribution_module_tests_tsan work_unit_distribution_module_tests_coverage
    COMMENT "Running all work unit distribution module tests"
)

