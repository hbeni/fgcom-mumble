cmake_minimum_required(VERSION 3.10)
project(Audio_Processing_Tests)

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
    ${CMAKE_CURRENT_SOURCE_DIR}/../../client/mumble-plugin/lib
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Source files
set(TEST_SOURCES
    main.cpp
    test_audio_processing_main.cpp
    test_codec.cpp
    test_audio_effects.cpp
    test_sample_rate_conversion.cpp
    ../../client/mumble-plugin/lib/audio_modern.cpp
    ../../client/mumble-plugin/lib/agc_squelch.cpp
    ../../client/mumble-plugin/lib/frequency_offset.cpp
)

# Create test executable
add_executable(audio_processing_tests ${TEST_SOURCES})

# Link libraries
target_link_libraries(audio_processing_tests
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)

# Compiler flags for testing
target_compile_options(audio_processing_tests PRIVATE
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
add_executable(audio_processing_tests_asan ${TEST_SOURCES})
target_link_libraries(audio_processing_tests_asan
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(audio_processing_tests_asan PRIVATE ${ASAN_FLAGS})
target_link_options(audio_processing_tests_asan PRIVATE ${ASAN_FLAGS})

# ThreadSanitizer version
add_executable(audio_processing_tests_tsan ${TEST_SOURCES})
target_link_libraries(audio_processing_tests_tsan
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(audio_processing_tests_tsan PRIVATE ${TSAN_FLAGS})
target_link_options(audio_processing_tests_tsan PRIVATE ${TSAN_FLAGS})

# Coverage version
add_executable(audio_processing_tests_coverage ${TEST_SOURCES})
target_link_libraries(audio_processing_tests_coverage
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    Threads::Threads
    m
    pthread
)
target_compile_options(audio_processing_tests_coverage PRIVATE ${COVERAGE_FLAGS})
target_link_options(audio_processing_tests_coverage PRIVATE ${COVERAGE_FLAGS})

# Enable testing
enable_testing()

# Add test targets
add_test(NAME Audio_Processing_Basic_Tests COMMAND audio_processing_tests)
add_test(NAME Audio_Processing_AddressSanitizer COMMAND audio_processing_tests_asan)
add_test(NAME Audio_Processing_ThreadSanitizer COMMAND audio_processing_tests_tsan)
add_test(NAME Audio_Processing_Coverage COMMAND audio_processing_tests_coverage)

# Set test properties
set_tests_properties(Audio_Processing_Basic_Tests PROPERTIES
    TIMEOUT 300
    LABELS "basic;audio_processing"
)

set_tests_properties(Audio_Processing_AddressSanitizer PROPERTIES
    TIMEOUT 600
    LABELS "sanitizer;memory;audio_processing"
)

set_tests_properties(Audio_Processing_ThreadSanitizer PROPERTIES
    TIMEOUT 600
    LABELS "sanitizer;thread;audio_processing"
)

set_tests_properties(Audio_Processing_Coverage PROPERTIES
    TIMEOUT 300
    LABELS "coverage;audio_processing"
)

# Custom targets for different test runs
add_custom_target(run_audio_processing_basic_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "basic;audio_processing"
    DEPENDS audio_processing_tests
    COMMENT "Running basic audio processing tests"
)

add_custom_target(run_audio_processing_sanitizer_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "sanitizer;audio_processing"
    DEPENDS audio_processing_tests_asan audio_processing_tests_tsan
    COMMENT "Running audio processing sanitizer tests"
)

add_custom_target(run_audio_processing_coverage_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "coverage;audio_processing"
    DEPENDS audio_processing_tests_coverage
    COMMENT "Running audio processing coverage tests"
)

add_custom_target(run_audio_processing_all_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L audio_processing --verbose
    DEPENDS audio_processing_tests audio_processing_tests_asan audio_processing_tests_tsan audio_processing_tests_coverage
    COMMENT "Running all audio processing tests"
)

