cmake_minimum_required(VERSION 3.10)
project(ClientPluginModuleTests)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(GTest REQUIRED)

# RapidCheck setup - try system package first, then local
find_path(RAPIDCHECK_INCLUDE_DIR
    NAMES rapidcheck/rapidcheck.hpp
    PATHS
        /usr/include
        /usr/local/include
        "${CMAKE_CURRENT_SOURCE_DIR}/../../rapidcheck_tests/lib/rapidcheck/include"
)

if(RAPIDCHECK_INCLUDE_DIR)
    message(STATUS "Found RapidCheck at: ${RAPIDCHECK_INCLUDE_DIR}")
    # Try to find RapidCheck library
    find_library(RAPIDCHECK_LIBRARY
        NAMES rapidcheck
        PATHS
            /usr/lib
            /usr/local/lib
            /usr/lib/x86_64-linux-gnu
    )
    if(RAPIDCHECK_LIBRARY)
        message(STATUS "Found RapidCheck library: ${RAPIDCHECK_LIBRARY}")
        add_library(rapidcheck INTERFACE)
        target_include_directories(rapidcheck INTERFACE ${RAPIDCHECK_INCLUDE_DIR})
        target_link_libraries(rapidcheck INTERFACE ${RAPIDCHECK_LIBRARY})
    else()
        message(STATUS "RapidCheck headers found but library not found, headers-only mode")
        add_library(rapidcheck INTERFACE)
        target_include_directories(rapidcheck INTERFACE ${RAPIDCHECK_INCLUDE_DIR})
    endif()
else()
    message(STATUS "RapidCheck not found, continuing without it")
    set(RAPIDCHECK_INCLUDE_DIR "")
endif()

# Find GMock
find_package(PkgConfig REQUIRED)
pkg_check_modules(GMOCK REQUIRED gmock)
find_package(Threads REQUIRED)


# Include directories
# Add plugin root directory (where lib/ is) - needed for includes like "lib/json/json.hpp"
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../..  # client/mumble-plugin/ (plugin root)
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../lib  # client/mumble-plugin/lib/
    ${CMAKE_CURRENT_SOURCE_DIR}/../..
    ${CMAKE_CURRENT_SOURCE_DIR}
)
# Add RapidCheck include if available
if(RAPIDCHECK_INCLUDE_DIR)
    include_directories(${RAPIDCHECK_INCLUDE_DIR})
endif()

# Source files
set(TEST_SOURCES
    test_white_noise_generation.cpp
    test_client_plugin_module_simple.cpp
    ../../../fgcom-mumble.cpp
    ../../../lib/io_plugin.cpp
    ../../../lib/io_UDPClient.cpp
    ../../../lib/io_UDPServer.cpp
    ../../../lib/radio_model.cpp
    ../../../lib/radio_model_vhf.cpp
    ../../../lib/radio_model_hf_impl.cpp
    ../../../lib/radio_model_uhf.cpp
    ../../../lib/radio_model_uhf_impl.cpp
    ../../../lib/radio_model_amateur_impl.cpp
    ../../../lib/radio_model_string_impl.cpp
    ../../../lib/radio_model_aviation_hf.cpp
    ../../../lib/radio_model_maritime_hf.cpp
    ../../../lib/frequency_offset.cpp
    ../../../lib/non_amateur_hf.cpp
    ../../../lib/garbage_collector.cpp
    ../../../lib/solar_data.cpp
    ../../../lib/shared_data.cpp
    ../../../lib/audio.cpp
    ../../../lib/antenna_pattern_mapping.cpp
    ../../../lib/pattern_interpolation.cpp
    ../../../lib/atmospheric_ducting.cpp
    ../../../lib/enhanced_multipath.cpp
    ../../../lib/propagation_physics.cpp
    ../../../lib/power_management.cpp
    ../../../lib/amateur_radio.cpp
    ../../../lib/radio_config.cpp
    ../../../lib/atmospheric_noise.cpp
)

# Create test executable
add_executable(client_plugin_module_tests ${TEST_SOURCES})

# Link libraries
target_link_libraries(client_plugin_module_tests
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
    curl
    ssl
    crypto
)
# Add RapidCheck if available
if(TARGET rapidcheck)
    target_link_libraries(client_plugin_module_tests rapidcheck)
endif()

# Compiler flags for testing
target_compile_options(client_plugin_module_tests PRIVATE
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
add_executable(client_plugin_module_tests_asan ${TEST_SOURCES})
target_link_libraries(client_plugin_module_tests_asan
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
    curl
    ssl
    crypto
)
if(TARGET rapidcheck)
    target_link_libraries(client_plugin_module_tests_asan rapidcheck)
endif()
target_compile_options(client_plugin_module_tests_asan PRIVATE ${ASAN_FLAGS})
target_link_options(client_plugin_module_tests_asan PRIVATE ${ASAN_FLAGS})

# ThreadSanitizer version
add_executable(client_plugin_module_tests_tsan ${TEST_SOURCES})
target_link_libraries(client_plugin_module_tests_tsan
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
    curl
    ssl
    crypto
)
if(TARGET rapidcheck)
    target_link_libraries(client_plugin_module_tests_tsan rapidcheck)
endif()
target_compile_options(client_plugin_module_tests_tsan PRIVATE ${TSAN_FLAGS})
target_link_options(client_plugin_module_tests_tsan PRIVATE ${TSAN_FLAGS})

# Coverage version
add_executable(client_plugin_module_tests_coverage ${TEST_SOURCES})
target_link_libraries(client_plugin_module_tests_coverage
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
    curl
    ssl
    crypto
)
if(TARGET rapidcheck)
    target_link_libraries(client_plugin_module_tests_coverage rapidcheck)
endif()
target_compile_options(client_plugin_module_tests_coverage PRIVATE ${COVERAGE_FLAGS})
target_link_options(client_plugin_module_tests_coverage PRIVATE ${COVERAGE_FLAGS})

# Enable testing
enable_testing()

# Add test targets
add_test(NAME ClientPluginModule_Basic_Tests COMMAND client_plugin_module_tests)
add_test(NAME ClientPluginModule_AddressSanitizer COMMAND client_plugin_module_tests_asan)
add_test(NAME ClientPluginModule_ThreadSanitizer COMMAND client_plugin_module_tests_tsan)
add_test(NAME ClientPluginModule_Coverage COMMAND client_plugin_module_tests_coverage)

# Set test properties
set_tests_properties(ClientPluginModule_Basic_Tests PROPERTIES
    TIMEOUT 300
    LABELS "basic;client_plugin_module"
)

set_tests_properties(ClientPluginModule_AddressSanitizer PROPERTIES
    TIMEOUT 600
    LABELS "sanitizer;memory;client_plugin_module"
)

set_tests_properties(ClientPluginModule_ThreadSanitizer PROPERTIES
    TIMEOUT 600
    LABELS "sanitizer;thread;client_plugin_module"
)

set_tests_properties(ClientPluginModule_Coverage PROPERTIES
    TIMEOUT 300
    LABELS "coverage;client_plugin_module"
)

# Custom targets for different test runs
add_custom_target(run_client_plugin_module_basic_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "basic;client_plugin_module"
    DEPENDS client_plugin_module_tests
    COMMENT "Running basic client plugin module tests"
)

add_custom_target(run_client_plugin_module_sanitizer_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "sanitizer;client_plugin_module"
    DEPENDS client_plugin_module_tests_asan client_plugin_module_tests_tsan
    COMMENT "Running client plugin module sanitizer tests"
)

add_custom_target(run_client_plugin_module_coverage_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "coverage;client_plugin_module"
    DEPENDS client_plugin_module_tests_coverage
    COMMENT "Running client plugin module coverage tests"
)

add_custom_target(run_client_plugin_module_all_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L client_plugin_module --verbose
    DEPENDS client_plugin_module_tests client_plugin_module_tests_asan client_plugin_module_tests_tsan client_plugin_module_tests_coverage
    COMMENT "Running all client plugin module tests"
)

