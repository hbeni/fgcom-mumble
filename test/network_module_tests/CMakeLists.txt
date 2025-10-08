cmake_minimum_required(VERSION 3.10)
project(Network_Module_Tests)

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

    ${CMAKE_CURRENT_SOURCE_DIR}/../../client/mumble-plugin
    ${CMAKE_CURRENT_SOURCE_DIR}/../../client/mumble-plugin/lib
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
    ../../client/mumble-plugin/lib/audio_modern.cpp
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