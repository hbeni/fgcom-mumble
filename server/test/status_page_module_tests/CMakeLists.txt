cmake_minimum_required(VERSION 3.10)
project(StatusPageModuleTests)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(GTest REQUIRED)

# RapidCheck setup
set(RAPIDCHECK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../client/mumble-plugin/test/test-modules/rapidcheck_tests/lib/rapidcheck")
set(RAPIDCHECK_INCLUDE_DIR "${RAPIDCHECK_DIR}/include")
set(RAPIDCHECK_SRC_DIR "${RAPIDCHECK_DIR}/src")

# Add RapidCheck as subdirectory if not already added
if(NOT TARGET rapidcheck)
    add_subdirectory(${RAPIDCHECK_DIR} rapidcheck)
endif()

find_package(Threads REQUIRED)

# RapidCheck setup
set(RAPIDCHECK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../client/mumble-plugin/test/test-modules/rapidcheck_tests/lib/rapidcheck")
set(RAPIDCHECK_INCLUDE_DIR "${RAPIDCHECK_DIR}/include")
set(RAPIDCHECK_SRC_DIR "${RAPIDCHECK_DIR}/src")

# Add RapidCheck as subdirectory if not already added
if(NOT TARGET rapidcheck)
    add_subdirectory(${RAPIDCHECK_DIR} rapidcheck)
endif()


# Find GMock
find_package(PkgConfig REQUIRED)

# RapidCheck setup
set(RAPIDCHECK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../client/mumble-plugin/test/test-modules/rapidcheck_tests/lib/rapidcheck")
set(RAPIDCHECK_INCLUDE_DIR "${RAPIDCHECK_DIR}/include")
set(RAPIDCHECK_SRC_DIR "${RAPIDCHECK_DIR}/src")

# Add RapidCheck as subdirectory if not already added
if(NOT TARGET rapidcheck)
    add_subdirectory(${RAPIDCHECK_DIR} rapidcheck)
endif()

pkg_check_modules(GMOCK REQUIRED gmock)

# Include directories
include_directories(
    ${RAPIDCHECK_INCLUDE_DIR}

    ${CMAKE_CURRENT_SOURCE_DIR}/../../statuspage
    ${CMAKE_CURRENT_SOURCE_DIR}/../..
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Source files
set(TEST_SOURCES
    test_status_page_module_tests_properties.cpp

    main.cpp
    test_status_page_main.cpp
    test_web_interface.cpp
    test_data_accuracy.cpp
)

# Create test executable
add_executable(status_page_module_tests ${TEST_SOURCES})

# Link libraries
target_link_libraries(status_page_module_tests
    rapidcheck
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)

# Compiler flags for testing
target_compile_options(status_page_module_tests PRIVATE
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
add_executable(status_page_module_tests_asan ${TEST_SOURCES})
target_link_libraries(status_page_module_tests_asan
    rapidcheck
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(status_page_module_tests_asan PRIVATE ${ASAN_FLAGS})
target_link_options(status_page_module_tests_asan PRIVATE ${ASAN_FLAGS})

# ThreadSanitizer version
add_executable(status_page_module_tests_tsan ${TEST_SOURCES})
target_link_libraries(status_page_module_tests_tsan
    rapidcheck
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(status_page_module_tests_tsan PRIVATE ${TSAN_FLAGS})
target_link_options(status_page_module_tests_tsan PRIVATE ${TSAN_FLAGS})

# Coverage version
add_executable(status_page_module_tests_coverage ${TEST_SOURCES})
target_link_libraries(status_page_module_tests_coverage
    rapidcheck
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(status_page_module_tests_coverage PRIVATE ${COVERAGE_FLAGS})
target_link_options(status_page_module_tests_coverage PRIVATE ${COVERAGE_FLAGS})

# Enable testing
enable_testing()

# Add test targets
add_test(NAME StatusPageModule_Basic_Tests COMMAND status_page_module_tests)
add_test(NAME StatusPageModule_AddressSanitizer COMMAND status_page_module_tests_asan)
add_test(NAME StatusPageModule_ThreadSanitizer COMMAND status_page_module_tests_tsan)
add_test(NAME StatusPageModule_Coverage COMMAND status_page_module_tests_coverage)

# Set test properties
set_tests_properties(StatusPageModule_Basic_Tests PROPERTIES
    TIMEOUT 300
    LABELS "basic;status_page_module"
)

set_tests_properties(StatusPageModule_AddressSanitizer PROPERTIES
    TIMEOUT 600
    LABELS "sanitizer;memory;status_page_module"
)

set_tests_properties(StatusPageModule_ThreadSanitizer PROPERTIES
    TIMEOUT 600
    LABELS "sanitizer;thread;status_page_module"
)

set_tests_properties(StatusPageModule_Coverage PROPERTIES
    TIMEOUT 300
    LABELS "coverage;status_page_module"
)

# Custom targets for different test runs
add_custom_target(run_status_page_module_basic_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "basic;status_page_module"
    DEPENDS status_page_module_tests
    COMMENT "Running basic status page module tests"
)

add_custom_target(run_status_page_module_sanitizer_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "sanitizer;status_page_module"
    DEPENDS status_page_module_tests_asan status_page_module_tests_tsan
    COMMENT "Running status page module sanitizer tests"
)

add_custom_target(run_status_page_module_coverage_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "coverage;status_page_module"
    DEPENDS status_page_module_tests_coverage
    COMMENT "Running status page module coverage tests"
)

add_custom_target(run_status_page_module_all_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L status_page_module --verbose
    DEPENDS status_page_module_tests status_page_module_tests_asan status_page_module_tests_tsan status_page_module_tests_coverage
    COMMENT "Running all status page module tests"
)
