cmake_minimum_required(VERSION 3.10)
project(Radio_Propagation_Tests)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(GTest REQUIRED)

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
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Source files
set(TEST_SOURCES
    test_solar_data_impact.cpp
    test_radio_propagation_tests_properties.cpp
    test_real_city_pairs.cpp
    test_itu_r_validation.cpp
    test_critical_fixes_validation.cpp

    main.cpp
    test_radio_propagation_main.cpp
    test_line_of_sight.cpp
    test_frequency_propagation.cpp
    test_antenna_patterns.cpp
    test_environmental_effects.cpp
    test_noise_floor.cpp
    test_radio_propagation_edge_cases.cpp
    ../../lib/propagation_physics.cpp
)

# Create test executable
add_executable(radio_propagation_tests ${TEST_SOURCES})

# Link libraries
target_link_libraries(radio_propagation_tests
    rapidcheck
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)

# Compiler flags for testing
target_compile_options(radio_propagation_tests PRIVATE
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
add_executable(radio_propagation_tests_asan ${TEST_SOURCES})
target_link_libraries(radio_propagation_tests_asan
    rapidcheck
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(radio_propagation_tests_asan PRIVATE ${ASAN_FLAGS})
target_link_options(radio_propagation_tests_asan PRIVATE ${ASAN_FLAGS})

# ThreadSanitizer version
add_executable(radio_propagation_tests_tsan ${TEST_SOURCES})
target_link_libraries(radio_propagation_tests_tsan
    rapidcheck
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(radio_propagation_tests_tsan PRIVATE ${TSAN_FLAGS})
target_link_options(radio_propagation_tests_tsan PRIVATE ${TSAN_FLAGS})

# Coverage version
add_executable(radio_propagation_tests_coverage ${TEST_SOURCES})
target_link_libraries(radio_propagation_tests_coverage
    rapidcheck
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(radio_propagation_tests_coverage PRIVATE ${COVERAGE_FLAGS})
target_link_options(radio_propagation_tests_coverage PRIVATE ${COVERAGE_FLAGS})

# Enable testing
enable_testing()

# Add test targets
add_test(NAME Radio_Propagation_Basic_Tests COMMAND radio_propagation_tests)
add_test(NAME Radio_Propagation_AddressSanitizer COMMAND radio_propagation_tests_asan)
add_test(NAME Radio_Propagation_ThreadSanitizer COMMAND radio_propagation_tests_tsan)
add_test(NAME Radio_Propagation_Coverage COMMAND radio_propagation_tests_coverage)

# Set test properties
set_tests_properties(Radio_Propagation_Basic_Tests PROPERTIES
    TIMEOUT 300
    LABELS "basic;radio_propagation"
)

set_tests_properties(Radio_Propagation_AddressSanitizer PROPERTIES
    TIMEOUT 600
    LABELS "sanitizer;memory;radio_propagation"
)

set_tests_properties(Radio_Propagation_ThreadSanitizer PROPERTIES
    TIMEOUT 600
    LABELS "sanitizer;thread;radio_propagation"
)

set_tests_properties(Radio_Propagation_Coverage PROPERTIES
    TIMEOUT 300
    LABELS "coverage;radio_propagation"
)

# Custom targets for different test runs
add_custom_target(run_radio_propagation_basic_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "basic;radio_propagation"
    DEPENDS radio_propagation_tests
    COMMENT "Running basic radio propagation tests"
)

add_custom_target(run_radio_propagation_sanitizer_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "sanitizer;radio_propagation"
    DEPENDS radio_propagation_tests_asan radio_propagation_tests_tsan
    COMMENT "Running radio propagation sanitizer tests"
)

add_custom_target(run_radio_propagation_coverage_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "coverage;radio_propagation"
    DEPENDS radio_propagation_tests_coverage
    COMMENT "Running radio propagation coverage tests"
)

add_custom_target(run_radio_propagation_all_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L radio_propagation --verbose
    DEPENDS radio_propagation_tests radio_propagation_tests_asan radio_propagation_tests_tsan radio_propagation_tests_coverage
    COMMENT "Running all radio propagation tests"
)
