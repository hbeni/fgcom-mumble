cmake_minimum_required(VERSION 3.16)

# RapidCheck setup
set(RAPIDCHECK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../test-modul../rapidcheck_tests/lib/rapidcheck")
set(RAPIDCHECK_INCLUDE_DIR "${RAPIDCHECK_DIR}/include")
set(RAPIDCHECK_SRC_DIR "${RAPIDCHECK_DIR}/src")

# Add RapidCheck as subdirectory if not already added
if(NOT TARGET rapidcheck)
    add_subdirectory(${RAPIDCHECK_DIR} rapidcheck)
endif()

project(jsimconnect_build_tests)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(GTest REQUIRED)
find_package(Threads REQUIRED)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Source files
set(TEST_SOURCES
    test_jsimconnect_build_main.cpp
    test_jsimconnect_build_tests_properties.cpp
    main.cpp
)

# Create test executable
add_executable(jsimconnect_build_tests ${TEST_SOURCES})

# Link libraries
target_link_libraries(jsimconnect_build_tests
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
add_test(NAME jsimconnect_build_tests COMMAND jsimconnect_build_tests)

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
    add_executable(fuzz_jsimconnect_build_tests fuzz_jsimconnect_build_tests.cpp)
    target_compile_options(fuzz_jsimconnect_build_tests PRIVATE -O3 -g -fsanitize=address,undefined)
    target_link_libraries(fuzz_jsimconnect_build_tests ${GTEST_GMOCK_LIBRARIES} Threads::Threads m pthread rapidcheck)
endif()

# Mutation testing targets
if(ENABLE_MULL OR ENABLE_FUZZING)
    add_executable(mutation_jsimconnect_build_tests mutation_jsimconnect_build_tests.cpp)
    target_compile_options(mutation_jsimconnect_build_tests PRIVATE -O2 -g)
    target_link_libraries(mutation_jsimconnect_build_tests ${GTEST_GMOCK_LIBRARIES} Threads::Threads m pthread rapidcheck)
endif()
