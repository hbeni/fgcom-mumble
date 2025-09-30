cmake_minimum_required(VERSION 3.10)
project(Network_Module_Tests)

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
    ${CMAKE_CURRENT_SOURCE_DIR}/../../client/mumble-plugin
    ${CMAKE_CURRENT_SOURCE_DIR}/../../client/mumble-plugin/lib
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Source files
set(TEST_SOURCES
    test_network_module_main.cpp
    test_udp_protocol.cpp
    test_websocket.cpp
    test_rest_api.cpp
    ../../client/mumble-plugin/fgcom-mumble.cpp
    ../../client/mumble-plugin/lib/io_UDPClient.cpp
    ../../client/mumble-plugin/lib/io_plugin.cpp
    ../../client/mumble-plugin/lib/io_UDPServer.cpp
    ../../client/mumble-plugin/lib/radio_config.cpp
    ../../client/mumble-plugin/lib/radio_model.cpp
    ../../client/mumble-plugin/lib/radio_model_vhf.cpp
    ../../client/mumble-plugin/lib/radio_model_hf.cpp
    ../../client/mumble-plugin/lib/radio_model_uhf.cpp
    ../../client/mumble-plugin/lib/radio_model_string.cpp
    ../../client/mumble-plugin/lib/radio_model_amateur.cpp
    ../../client/mumble-plugin/lib/radio_model_aviation_hf.cpp
    ../../client/mumble-plugin/lib/radio_model_maritime_hf.cpp
    ../../client/mumble-plugin/lib/frequency_offset_processor.cpp
    ../../client/mumble-plugin/lib/non_amateur_hf_impl.cpp
    ../../client/mumble-plugin/lib/radio_model_hf_impl.cpp
    ../../client/mumble-plugin/lib/radio_model_string_impl.cpp
    ../../client/mumble-plugin/lib/radio_model_amateur_impl.cpp
    ../../client/mumble-plugin/lib/radio_model_uhf_impl.cpp
    ../../client/mumble-plugin/lib/radio_model_aviation_hf.cpp
    ../../client/mumble-plugin/lib/radio_model_maritime_hf.cpp
    ../../client/mumble-plugin/lib/audio.cpp
    ../../client/mumble-plugin/lib/antenna_pattern_mapping.cpp
    ../../client/mumble-plugin/lib/pattern_interpolation.cpp
    ../../client/mumble-plugin/lib/atmospheric_ducting.cpp
    ../../client/mumble-plugin/lib/enhanced_multipath.cpp
    ../../client/mumble-plugin/lib/propagation_physics.cpp
    ../../client/mumble-plugin/lib/power_management.cpp
    ../../client/mumble-plugin/lib/amateur_radio.cpp
    ../../client/mumble-plugin/lib/solar_data.cpp
    ../../client/mumble-plugin/lib/shared_data.cpp
    ../../client/mumble-plugin/lib/garbage_collector.cpp
)

# Create test executable
add_executable(network_module_tests ${TEST_SOURCES})

# Link libraries
target_link_libraries(network_module_tests
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)

# Compiler flags for testing
target_compile_options(network_module_tests PRIVATE
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
add_executable(network_module_tests_asan ${TEST_SOURCES})
target_link_libraries(network_module_tests_asan
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(network_module_tests_asan PRIVATE ${ASAN_FLAGS})
target_link_options(network_module_tests_asan PRIVATE ${ASAN_FLAGS})

# ThreadSanitizer version
add_executable(network_module_tests_tsan ${TEST_SOURCES})
target_link_libraries(network_module_tests_tsan
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(network_module_tests_tsan PRIVATE ${TSAN_FLAGS})
target_link_options(network_module_tests_tsan PRIVATE ${TSAN_FLAGS})

# Coverage version
add_executable(network_module_tests_coverage ${TEST_SOURCES})
target_link_libraries(network_module_tests_coverage
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(network_module_tests_coverage PRIVATE ${COVERAGE_FLAGS})
target_link_options(network_module_tests_coverage PRIVATE ${COVERAGE_FLAGS})

# Enable testing
enable_testing()

# Add test targets
add_test(NAME Network_Module_Basic_Tests COMMAND network_module_tests)
add_test(NAME Network_Module_AddressSanitizer COMMAND network_module_tests_asan)
add_test(NAME Network_Module_ThreadSanitizer COMMAND network_module_tests_tsan)
add_test(NAME Network_Module_Coverage COMMAND network_module_tests_coverage)

# Set test properties
set_tests_properties(Network_Module_Basic_Tests PROPERTIES
    TIMEOUT 300
    LABELS "basic;network_module"
)

set_tests_properties(Network_Module_AddressSanitizer PROPERTIES
    TIMEOUT 600
    LABELS "sanitizer;memory;network_module"
)

set_tests_properties(Network_Module_ThreadSanitizer PROPERTIES
    TIMEOUT 600
    LABELS "sanitizer;thread;network_module"
)

set_tests_properties(Network_Module_Coverage PROPERTIES
    TIMEOUT 300
    LABELS "coverage;network_module"
)

# Custom targets for different test runs
add_custom_target(run_network_module_basic_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "basic;network_module"
    DEPENDS network_module_tests
    COMMENT "Running basic network module tests"
)

add_custom_target(run_network_module_sanitizer_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "sanitizer;network_module"
    DEPENDS network_module_tests_asan network_module_tests_tsan
    COMMENT "Running network module sanitizer tests"
)

add_custom_target(run_network_module_coverage_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "coverage;network_module"
    DEPENDS network_module_tests_coverage
    COMMENT "Running network module coverage tests"
)

add_custom_target(run_network_module_all_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L network_module --verbose
    DEPENDS network_module_tests network_module_tests_asan network_module_tests_tsan network_module_tests_coverage
    COMMENT "Running all network module tests"
)

