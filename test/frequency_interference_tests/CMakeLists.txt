cmake_minimum_required(VERSION 3.16)

# RapidCheck setup
set(RAPIDCHECK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../rapidcheck_tests/lib/rapidcheck")
set(RAPIDCHECK_INCLUDE_DIR "${RAPIDCHECK_DIR}/include")
set(RAPIDCHECK_SRC_DIR "${RAPIDCHECK_DIR}/src")

# Add RapidCheck as subdirectory if not already added
if(NOT TARGET rapidcheck)
    add_subdirectory(${RAPIDCHECK_DIR} rapidcheck)
endif()
project(frequency_interference_tests)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(GTest REQUIRED)
find_package(Threads REQUIRED)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../client/mumble-plugin/lib
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Source files
set(TEST_SOURCES
    main.cpp
    test_frequency_interference.cpp
    test_frequency_interference_properties.cpp
    ../../client/mumble-plugin/lib/frequency_offset.cpp
    ../../client/mumble-plugin/lib/radio_model.cpp
    ../../client/mumble-plugin/lib/radio_model_vhf.cpp
    ../../client/mumble-plugin/lib/radio_model_uhf.cpp
    ../../client/mumble-plugin/lib/radio_model_hf_impl.cpp
    ../../client/mumble-plugin/lib/radio_model_amateur_impl.cpp
    ../../client/mumble-plugin/lib/radio_model_string_impl.cpp
    ../../client/mumble-plugin/lib/radio_model_uhf_impl.cpp
    ../../client/mumble-plugin/lib/radio_model_aviation_hf.cpp
    ../../client/mumble-plugin/lib/radio_model_maritime_hf.cpp
    ../../client/mumble-plugin/lib/amateur_radio.cpp
    ../../client/mumble-plugin/lib/non_amateur_hf_impl.cpp
    ../../client/mumble-plugin/lib/solar_data.cpp
    ../../client/mumble-plugin/lib/propagation_physics.cpp
    ../../client/mumble-plugin/lib/power_management.cpp
    ../../client/mumble-plugin/lib/antenna_pattern_mapping.cpp
    ../../client/mumble-plugin/lib/pattern_interpolation.cpp
    ../../client/mumble-plugin/lib/antenna_ground_system.cpp
    ../../client/mumble-plugin/lib/atmospheric_ducting.cpp
    ../../client/mumble-plugin/lib/enhanced_multipath.cpp
    ../../client/mumble-plugin/lib/audio_modern.cpp
    ../../client/mumble-plugin/lib/radio_config.cpp
)

# Create test executable
add_executable(frequency_interference_tests ${TEST_SOURCES})

# Link libraries
target_link_libraries(frequency_interference_tests
    rapidcheck
    GTest::GTest
    GTest::Main
    Threads::Threads
    m
    pthread
)

# Enable testing
enable_testing()

# Add tests
add_test(NAME frequency_interference_tests COMMAND frequency_interference_tests)

# Fuzzing support
option(ENABLE_FUZZING "Enable AFL++ fuzzing and Mull mutation testing" OFF)
option(ENABLE_AFL "Enable AFL++ fuzzing" OFF)
option(ENABLE_MULL "Enable Mull mutation testing" OFF)

# AFL++ configuration
if(ENABLE_AFL OR ENABLE_FUZZING)
    find_program(AFL_CC afl-clang-fast)
    find_program(AFL_CXX afl-clang-fast++)
    if(AFL_CC AND AFL_CXX)
        set(CMAKE_C_COMPILER ${AFL_CC})
        set(CMAKE_CXX_COMPILER ${AFL_CXX})
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -g -fsanitize=address,undefined")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -g -fsanitize=address,undefined")
        message(STATUS "AFL++ fuzzing enabled")
    else()
        message(WARNING "AFL++ not found, fuzzing disabled")
    endif()
endif()

# Mull configuration
if(ENABLE_MULL OR ENABLE_FUZZING)
    find_program(MULL_CXX mull-cxx)
    if(MULL_CXX)
        message(STATUS "Mull mutation testing enabled")
    else()
        message(WARNING "Mull not found, mutation testing disabled")
    endif()
endif()

# Fuzzing targets
if(ENABLE_AFL OR ENABLE_FUZZING)
    add_executable(fuzz_frequency_interference fuzz_frequency_interference.cpp)
    target_compile_options(fuzz_frequency_interference PRIVATE -O3 -g -fsanitize=address,undefined)
    target_link_libraries(fuzz_frequency_interference ${GTEST_GMOCK_LIBRARIES} Threads::Threads m pthread rapidcheck)
endif()

# Mutation testing targets
if(ENABLE_MULL OR ENABLE_FUZZING)
    add_executable(mutation_frequency_interference mutation_frequency_interference.cpp)
    target_compile_options(mutation_frequency_interference PRIVATE -O2 -g)
    target_link_libraries(mutation_frequency_interference ${GTEST_GMOCK_LIBRARIES} Threads::Threads m pthread rapidcheck)
endif()
