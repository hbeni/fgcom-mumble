cmake_minimum_required(VERSION 3.10)

# RapidCheck setup
set(RAPIDCHECK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../test-modul../rapidcheck_tests/lib/rapidcheck")
set(RAPIDCHECK_INCLUDE_DIR "${RAPIDCHECK_DIR}/include")
set(RAPIDCHECK_SRC_DIR "${RAPIDCHECK_DIR}/src")

# Add RapidCheck as subdirectory if not already added
if(NOT TARGET rapidcheck)
    add_subdirectory(${RAPIDCHECK_DIR} rapidcheck)
endif()
project(AGC_Squelch_Tests)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(GTest REQUIRED)
find_package(Threads REQUIRED)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib
    ${CMAKE_CURRENT_SOURCE_DIR}
)

set(TEST_SOURCES
    main.cpp
    test_agc_squelch_main.cpp
    test_singleton.cpp
    test_agc_config.cpp
    test_squelch_config.cpp
    test_audio_processing.cpp
    test_math_functions.cpp
    ../../lib/agc_squelch.cpp
)

add_executable(agc_squelch_tests ${TEST_SOURCES})

target_link_libraries(agc_squelch_tests
    GTest::GTest
    GTest::Main
    Threads::Threads
    m
    pthread
)
