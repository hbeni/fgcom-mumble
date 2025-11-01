cmake_minimum_required(VERSION 3.10)
project(Professional_Audio_Tests)

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

# Test sources
set(TEST_SOURCES
    test_professional_audio_tests_properties.cpp

    test_simple_iir1.cpp
)

# Create test executable
add_executable(professional_audio_tests ${TEST_SOURCES})

# Link libraries
target_link_libraries(professional_audio_tests 
    rapidcheck
    GTest::GTest 
    Threads::Threads
)

# Create ASAN version
add_executable(professional_audio_tests_asan ${TEST_SOURCES})
target_compile_options(professional_audio_tests_asan PRIVATE -fsanitize=address -g)
target_link_options(professional_audio_tests_asan PRIVATE -fsanitize=address)
target_link_libraries(professional_audio_tests_asan 
    rapidcheck
    GTest::GTest 
    Threads::Threads
)

# Create TSAN version
add_executable(professional_audio_tests_tsan ${TEST_SOURCES})
target_compile_options(professional_audio_tests_tsan PRIVATE -fsanitize=thread -g)
target_link_options(professional_audio_tests_tsan PRIVATE -fsanitize=thread)
target_link_libraries(professional_audio_tests_tsan 
    rapidcheck
    GTest::GTest 
    Threads::Threads
)

# Create coverage version
add_executable(professional_audio_tests_coverage ${TEST_SOURCES})
target_compile_options(professional_audio_tests_coverage PRIVATE --coverage -g)
target_link_options(professional_audio_tests_coverage PRIVATE --coverage)
target_link_libraries(professional_audio_tests_coverage 
    rapidcheck
    GTest::GTest 
    Threads::Threads
)
