cmake_minimum_required(VERSION 3.10)
project(ClientPluginModuleTests)

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
    ${CMAKE_CURRENT_SOURCE_DIR}/../../client/mumble-plugin
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Source files
set(TEST_SOURCES
    test_client_plugin_module_tests_properties.cpp

    test_client_plugin_module_simple.cpp
    ../../client/mumble-plugin/fgcom-mumble.cpp
    ../../lib/io_plugin.cpp
    ../../lib/io_UDPClient.cpp
    ../../lib/io_UDPServer.cpp
    ../../lib/radio_model.cpp
    ../../lib/radio_model_vhf.cpp
    ../../lib/radio_model_hf_impl.cpp
    ../../lib/radio_model_hf_impl.cpp
    ../../lib/radio_model_uhf.cpp
    ../../lib/radio_model_uhf_impl.cpp
    ../../lib/radio_model_amateur_impl.cpp
    ../../lib/radio_model_amateur_impl.cpp
    ../../lib/radio_model_string_impl.cpp
    ../../lib/radio_model_string_impl.cpp
    ../../lib/radio_model_aviation_hf.cpp
    ../../lib/radio_model_maritime_hf.cpp
    ../../lib/frequency_offset_processor.cpp
    ../../lib/non_amateur_hf_impl.cpp
    ../../lib/garbage_collector.cpp
    ../../lib/solar_data.cpp
    ../../lib/shared_data.cpp
    ../../lib/audio_modern.cpp
    ../../lib/antenna_pattern_mapping.cpp
    ../../lib/pattern_interpolation.cpp
    ../../lib/atmospheric_ducting.cpp
    ../../lib/enhanced_multipath.cpp
    ../../lib/propagation_physics.cpp
    ../../lib/power_management.cpp
    ../../lib/amateur_radio.cpp
    ../../lib/radio_config.cpp
)

# Create test executable
add_executable(client_plugin_module_tests ${TEST_SOURCES})

# Link libraries
target_link_libraries(client_plugin_module_tests
    rapidcheck
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)

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
    rapidcheck
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(client_plugin_module_tests_asan PRIVATE ${ASAN_FLAGS})
target_link_options(client_plugin_module_tests_asan PRIVATE ${ASAN_FLAGS})

# ThreadSanitizer version
add_executable(client_plugin_module_tests_tsan ${TEST_SOURCES})
target_link_libraries(client_plugin_module_tests_tsan
    rapidcheck
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(client_plugin_module_tests_tsan PRIVATE ${TSAN_FLAGS})
target_link_options(client_plugin_module_tests_tsan PRIVATE ${TSAN_FLAGS})

# Coverage version
add_executable(client_plugin_module_tests_coverage ${TEST_SOURCES})
target_link_libraries(client_plugin_module_tests_coverage
    rapidcheck
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
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

