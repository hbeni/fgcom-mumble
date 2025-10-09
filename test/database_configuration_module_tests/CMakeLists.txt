cmake_minimum_required(VERSION 3.10)
project(DatabaseConfigurationModuleTests)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(GTest REQUIRED)

# RapidCheck setup
set(RAPIDCHECK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../rapidcheck_tests/lib/rapidcheck")
set(RAPIDCHECK_INCLUDE_DIR "${RAPIDCHECK_DIR}/include")
set(RAPIDCHECK_SRC_DIR "${RAPIDCHECK_DIR}/src")

# Add RapidCheck as subdirectory if not already added
if(NOT TARGET rapidcheck)
    add_subdirectory(${RAPIDCHECK_DIR} rapidcheck)
endif()

# Find GMock
find_package(PkgConfig REQUIRED)

# RapidCheck setup
set(RAPIDCHECK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../rapidcheck_tests/lib/rapidcheck")
set(RAPIDCHECK_INCLUDE_DIR "${RAPIDCHECK_DIR}/include")
set(RAPIDCHECK_SRC_DIR "${RAPIDCHECK_DIR}/src")

# Add RapidCheck as subdirectory if not already added
if(NOT TARGET rapidcheck)
    add_subdirectory(${RAPIDCHECK_DIR} rapidcheck)
endif()

pkg_check_modules(GMOCK REQUIRED gmock)
find_package(Threads REQUIRED)

# RapidCheck setup
set(RAPIDCHECK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../rapidcheck_tests/lib/rapidcheck")
set(RAPIDCHECK_INCLUDE_DIR "${RAPIDCHECK_DIR}/include")
set(RAPIDCHECK_SRC_DIR "${RAPIDCHECK_DIR}/src")

# Add RapidCheck as subdirectory if not already added
if(NOT TARGET rapidcheck)
    add_subdirectory(${RAPIDCHECK_DIR} rapidcheck)
endif()


# Include directories
include_directories(
    ${RAPIDCHECK_INCLUDE_DIR}

    ${CMAKE_CURRENT_SOURCE_DIR}/../../client/mumble-plugin/lib
    ${CMAKE_CURRENT_SOURCE_DIR}/../../client/mumble-plugin
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Source files
set(TEST_SOURCES
    test_database_configuration_module_tests_properties.cpp

    test_database_configuration_main.cpp
    test_csv_parsing.cpp
    test_configuration_file.cpp
)

# Create test executable
add_executable(database_configuration_module_tests ${TEST_SOURCES})

# Link libraries
target_link_libraries(database_configuration_module_tests
    rapidcheck
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)

# Compiler flags for testing
target_compile_options(database_configuration_module_tests PRIVATE
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
add_executable(database_configuration_module_tests_asan ${TEST_SOURCES})
target_link_libraries(database_configuration_module_tests_asan
    rapidcheck
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(database_configuration_module_tests_asan PRIVATE ${ASAN_FLAGS})
target_link_options(database_configuration_module_tests_asan PRIVATE ${ASAN_FLAGS})

# ThreadSanitizer version
add_executable(database_configuration_module_tests_tsan ${TEST_SOURCES})
target_link_libraries(database_configuration_module_tests_tsan
    rapidcheck
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(database_configuration_module_tests_tsan PRIVATE ${TSAN_FLAGS})
target_link_options(database_configuration_module_tests_tsan PRIVATE ${TSAN_FLAGS})

# Coverage version
add_executable(database_configuration_module_tests_coverage ${TEST_SOURCES})
target_link_libraries(database_configuration_module_tests_coverage
    rapidcheck
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(database_configuration_module_tests_coverage PRIVATE ${COVERAGE_FLAGS})
target_link_options(database_configuration_module_tests_coverage PRIVATE ${COVERAGE_FLAGS})

# Enable testing
enable_testing()

# Add test targets
add_test(NAME DatabaseConfigurationModule_Basic_Tests COMMAND database_configuration_module_tests)
add_test(NAME DatabaseConfigurationModule_AddressSanitizer COMMAND database_configuration_module_tests_asan)
add_test(NAME DatabaseConfigurationModule_ThreadSanitizer COMMAND database_configuration_module_tests_tsan)
add_test(NAME DatabaseConfigurationModule_Coverage COMMAND database_configuration_module_tests_coverage)

# Set test properties
set_tests_properties(DatabaseConfigurationModule_Basic_Tests PROPERTIES
    TIMEOUT 300
    LABELS "basic;database_configuration_module"
)

set_tests_properties(DatabaseConfigurationModule_AddressSanitizer PROPERTIES
    TIMEOUT 600
    LABELS "sanitizer;memory;database_configuration_module"
)

set_tests_properties(DatabaseConfigurationModule_ThreadSanitizer PROPERTIES
    TIMEOUT 600
    LABELS "sanitizer;thread;database_configuration_module"
)

set_tests_properties(DatabaseConfigurationModule_Coverage PROPERTIES
    TIMEOUT 300
    LABELS "coverage;database_configuration_module"
)

# Custom targets for different test runs
add_custom_target(run_database_configuration_module_basic_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "basic;database_configuration_module"
    DEPENDS database_configuration_module_tests
    COMMENT "Running basic database configuration module tests"
)

add_custom_target(run_database_configuration_module_sanitizer_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "sanitizer;database_configuration_module"
    DEPENDS database_configuration_module_tests_asan database_configuration_module_tests_tsan
    COMMENT "Running database configuration module sanitizer tests"
)

add_custom_target(run_database_configuration_module_coverage_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "coverage;database_configuration_module"
    DEPENDS database_configuration_module_tests_coverage
    COMMENT "Running database configuration module coverage tests"
)

add_custom_target(run_database_configuration_module_all_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L database_configuration_module --verbose
    DEPENDS database_configuration_module_tests database_configuration_module_tests_asan database_configuration_module_tests_tsan database_configuration_module_tests_coverage
    COMMENT "Running all database configuration module tests"
)

