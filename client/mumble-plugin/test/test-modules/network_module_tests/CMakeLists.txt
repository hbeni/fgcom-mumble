cmake_minimum_required(VERSION 3.10)
project(Network_Module_Tests)

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

    ${CMAKE_CURRENT_SOURCE_DIR}/../../client/mumble-plugin
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Add compiler flags for better compatibility
add_compile_options(-Wno-unused-parameter -Wno-unused-variable)

# Source files - include all necessary components with modern audio
set(TEST_SOURCES
    test_network_module_tests_properties.cpp

    test_network_module_main.cpp
    test_udp_protocol.cpp
    test_websocket.cpp
    test_rest_api.cpp
    ../../client/mumble-plugin/fgcom-mumble.cpp
    ../../lib/io_UDPClient.cpp
    ../../lib/io_plugin.cpp
    ../../lib/io_UDPServer.cpp
    ../../lib/radio_config.cpp
    ../../lib/radio_model.cpp
    ../../lib/radio_model_vhf.cpp
    ../../lib/radio_model_hf_impl.cpp
    ../../lib/radio_model_uhf.cpp
    ../../lib/radio_model_string_impl.cpp
    ../../lib/radio_model_amateur_impl.cpp
    ../../lib/radio_model_aviation_hf.cpp
    ../../lib/radio_model_maritime_hf.cpp
    ../../lib/frequency_offset_processor.cpp
    ../../lib/non_amateur_hf_impl.cpp
    ../../lib/radio_model_hf_impl.cpp
    ../../lib/radio_model_string_impl.cpp
    ../../lib/radio_model_amateur_impl.cpp
    ../../lib/radio_model_uhf_impl.cpp
    ../../lib/radio_model_aviation_hf.cpp
    ../../lib/radio_model_maritime_hf.cpp
    ../../lib/audio_modern.cpp
    ../../lib/antenna_pattern_mapping.cpp
    ../../lib/pattern_interpolation.cpp
    ../../lib/atmospheric_ducting.cpp
    ../../lib/enhanced_multipath.cpp
    ../../lib/propagation_physics.cpp
    ../../lib/power_management.cpp
    ../../lib/amateur_radio.cpp
    ../../lib/solar_data.cpp
    ../../lib/shared_data.cpp
    ../../lib/garbage_collector.cpp
)

# Create test executable
add_executable(network_module_tests ${TEST_SOURCES})

# Link libraries
target_link_libraries(network_module_tests 
    rapidcheck
    GTest::GTest 
    Threads::Threads
)

# Create ASAN version
add_executable(network_module_tests_asan ${TEST_SOURCES})
target_compile_options(network_module_tests_asan PRIVATE -fsanitize=address -g)
target_link_options(network_module_tests_asan PRIVATE -fsanitize=address)
target_link_libraries(network_module_tests_asan 
    rapidcheck
    GTest::GTest 
    Threads::Threads
)

# Create TSAN version
add_executable(network_module_tests_tsan ${TEST_SOURCES})
target_compile_options(network_module_tests_tsan PRIVATE -fsanitize=thread -g)
target_link_options(network_module_tests_tsan PRIVATE -fsanitize=thread)
target_link_libraries(network_module_tests_tsan 
    rapidcheck
    GTest::GTest 
    Threads::Threads
)

# Create coverage version
add_executable(network_module_tests_coverage ${TEST_SOURCES})
target_compile_options(network_module_tests_coverage PRIVATE --coverage -g)
target_link_options(network_module_tests_coverage PRIVATE --coverage)
target_link_libraries(network_module_tests_coverage 
    rapidcheck
    GTest::GTest 
    Threads::Threads
)