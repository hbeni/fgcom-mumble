cmake_minimum_required(VERSION 3.10)
project(WebRTC_API_Tests)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(GTest REQUIRED)
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)

# Find GMock
pkg_check_modules(GMOCK REQUIRED gmock)

# Find JSON library
pkg_check_modules(JSONCPP REQUIRED jsoncpp)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../client/mumble-plugin/lib
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../docs
    ${JSONCPP_INCLUDE_DIRS}
)

# Source files
set(TEST_SOURCES
    main.cpp
    webrtc_test_framework.cpp
    test_webrtc_connection.cpp
    test_protocol_translation.cpp
    test_audio_processing.cpp
    test_web_interface.cpp
    test_authentication.cpp
    test_webrtc_mumble_integration.cpp
    test_multi_client.cpp
    test_audio_quality.cpp
    test_performance.cpp
    test_full_workflow.cpp
    test_mobile_compatibility.cpp
    test_cross_platform.cpp
    test_error_recovery.cpp
)

# Create test executable
add_executable(webrtc_api_tests ${TEST_SOURCES})

# Link libraries
target_link_libraries(webrtc_api_tests
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    ${JSONCPP_LIBRARIES}
    Threads::Threads
    m
    pthread
    ssl
    crypto
)

# Compiler flags for testing
target_compile_options(webrtc_api_tests PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -O2
    -g
    -DWEBRTC_TESTING=1
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
add_executable(webrtc_api_tests_asan ${TEST_SOURCES})
target_link_libraries(webrtc_api_tests_asan
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    ${JSONCPP_LIBRARIES}
    Threads::Threads
    m
    pthread
    ssl
    crypto
)
target_compile_options(webrtc_api_tests_asan PRIVATE ${ASAN_FLAGS})
target_link_options(webrtc_api_tests_asan PRIVATE ${ASAN_FLAGS})

# ThreadSanitizer version
add_executable(webrtc_api_tests_tsan ${TEST_SOURCES})
target_link_libraries(webrtc_api_tests_tsan
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    ${JSONCPP_LIBRARIES}
    Threads::Threads
    m
    pthread
    ssl
    crypto
)
target_compile_options(webrtc_api_tests_tsan PRIVATE ${TSAN_FLAGS})
target_link_options(webrtc_api_tests_tsan PRIVATE ${TSAN_FLAGS})

# Coverage version
add_executable(webrtc_api_tests_coverage ${TEST_SOURCES})
target_link_libraries(webrtc_api_tests_coverage
    GTest::GTest
    GTest::Main
    ${GMOCK_LIBRARIES}
    ${JSONCPP_LIBRARIES}
    Threads::Threads
    m
    pthread
    ssl
    crypto
)
target_compile_options(webrtc_api_tests_coverage PRIVATE ${COVERAGE_FLAGS})
target_link_options(webrtc_api_tests_coverage PRIVATE ${COVERAGE_FLAGS})

# Enable testing
enable_testing()

# Add test targets
add_test(NAME WebRTC_API_Basic_Tests COMMAND webrtc_api_tests)
add_test(NAME WebRTC_API_AddressSanitizer COMMAND webrtc_api_tests_asan)
add_test(NAME WebRTC_API_ThreadSanitizer COMMAND webrtc_api_tests_tsan)
add_test(NAME WebRTC_API_Coverage COMMAND webrtc_api_tests_coverage)

# Set test properties
set_tests_properties(WebRTC_API_Basic_Tests PROPERTIES
    TIMEOUT 300
    LABELS "basic;webrtc"
)

set_tests_properties(WebRTC_API_AddressSanitizer PROPERTIES
    TIMEOUT 600
    LABELS "sanitizer;memory;webrtc"
)

set_tests_properties(WebRTC_API_ThreadSanitizer PROPERTIES
    TIMEOUT 600
    LABELS "sanitizer;thread;webrtc"
)

set_tests_properties(WebRTC_API_Coverage PROPERTIES
    TIMEOUT 300
    LABELS "coverage;webrtc"
)

# Custom targets for different test runs
add_custom_target(run_webrtc_basic_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L basic
    DEPENDS webrtc_api_tests
    COMMENT "Running basic WebRTC API tests"
)

add_custom_target(run_webrtc_sanitizer_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L sanitizer
    DEPENDS webrtc_api_tests_asan webrtc_api_tests_tsan
    COMMENT "Running WebRTC sanitizer tests"
)

add_custom_target(run_webrtc_coverage_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L coverage
    DEPENDS webrtc_api_tests_coverage
    COMMENT "Running WebRTC coverage tests"
)

add_custom_target(run_webrtc_all_tests
    COMMAND ${CMAKE_CTEST_COMMAND} --verbose
    DEPENDS webrtc_api_tests webrtc_api_tests_asan webrtc_api_tests_tsan webrtc_api_tests_coverage
    COMMENT "Running all WebRTC API tests"
)

# WebRTC-specific test targets
add_custom_target(run_webrtc_connection_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "webrtc;connection"
    DEPENDS webrtc_api_tests
    COMMENT "Running WebRTC connection tests"
)

add_custom_target(run_webrtc_audio_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "webrtc;audio"
    DEPENDS webrtc_api_tests
    COMMENT "Running WebRTC audio tests"
)

add_custom_target(run_webrtc_protocol_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L "webrtc;protocol"
    DEPENDS webrtc_api_tests
    COMMENT "Running WebRTC protocol tests"
)
