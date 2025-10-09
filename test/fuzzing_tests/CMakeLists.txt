cmake_minimum_required(VERSION 3.16)
project(fuzzing_tests)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(GTest REQUIRED)
find_package(Threads REQUIRED)

# AFL++ configuration
set(AFL_CC "afl-clang-fast")
set(AFL_CXX "afl-clang-fast++")

# AFL++ compiler flags
set(AFL_CFLAGS "-O3 -g -fsanitize=address,undefined -fno-omit-frame-pointer")
set(AFL_CXXFLAGS "-O3 -g -fsanitize=address,undefined -fno-omit-frame-pointer")

# Mull configuration
set(MULL_CXX "mull-cxx")
set(MULL_FLAGS "-compilation-flags=\"-O2 -g\"")

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../client/mumble-plugin/lib
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# AFL++ fuzzing targets
set(AFL_TARGETS
    fuzz_radio_propagation
    fuzz_audio_processing
    fuzz_antenna_patterns
    fuzz_frequency_management
    fuzz_agc_squelch
    fuzz_network_protocol
    fuzz_geographic_calculations
    fuzz_atis_processing
    fuzz_database_operations
    fuzz_security_functions
    fuzz_status_page
    fuzz_webrtc_operations
    fuzz_integration_tests
    fuzz_performance_tests
    fuzz_error_handling
)

# Create AFL++ fuzzing targets
foreach(target ${AFL_TARGETS})
    add_executable(${target} ${target}.cpp)
    target_compile_options(${target} PRIVATE ${AFL_CFLAGS})
    target_link_libraries(${target} 
        Threads::Threads
        m
        pthread
    )
    
    # Set AFL++ environment variables
    set_target_properties(${target} PROPERTIES
        COMPILE_FLAGS "${AFL_CFLAGS}"
        LINK_FLAGS "${AFL_CFLAGS}"
    )
endforeach()

# Mull mutation testing targets
set(MULL_TARGETS
    mutation_radio_propagation
    mutation_audio_processing
    mutation_antenna_patterns
    mutation_frequency_management
    mutation_agc_squelch
    mutation_network_protocol
    mutation_geographic_calculations
    mutation_atis_processing
    mutation_database_operations
    mutation_security_functions
    mutation_status_page
    mutation_webrtc_operations
    mutation_integration_tests
    mutation_performance_tests
    mutation_error_handling
)

# Create Mull mutation testing targets
foreach(target ${MULL_TARGETS})
    add_executable(${target} ${target}.cpp)
    target_compile_options(${target} PRIVATE "-O2 -g")
    target_link_libraries(${target} 
        GTest::GTest
        GTest::Main
        Threads::Threads
        m
        pthread
    )
endforeach()

# Custom targets for fuzzing
add_custom_target(build_afl_targets
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target fuzz_radio_propagation fuzz_audio_processing
    COMMENT "Building AFL++ fuzzing targets"
)

add_custom_target(build_mull_targets
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target mutation_radio_propagation mutation_audio_processing
    COMMENT "Building Mull mutation testing targets"
)

# Fuzzing corpus setup
add_custom_target(setup_corpus
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/corpus/radio_propagation
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/corpus/audio_processing
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/corpus/antenna_patterns
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/corpus/frequency_management
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/corpus/agc_squelch
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/corpus/network_protocol
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/corpus/geographic_calculations
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/corpus/atis_processing
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/corpus/database_operations
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/corpus/security_functions
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/corpus/status_page
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/corpus/webrtc_operations
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/corpus/integration_tests
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/corpus/performance_tests
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/corpus/error_handling
    COMMENT "Setting up fuzzing corpus directories"
)

# Output directories setup
add_custom_target(setup_outputs
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/outputs/afl++
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/outputs/mull
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/outputs/reports
    COMMENT "Setting up output directories"
)

# AFL++ fuzzing execution
add_custom_target(run_afl_fuzzing
    DEPENDS build_afl_targets setup_corpus setup_outputs
    COMMAND afl-fuzz -i ${CMAKE_BINARY_DIR}/corpus/radio_propagation -o ${CMAKE_BINARY_DIR}/outputs/afl++/radio_propagation -t 10000 -- ${CMAKE_BINARY_DIR}/fuzz_radio_propagation @@
    COMMENT "Running AFL++ fuzzing for radio propagation"
)

# Mull mutation testing execution
add_custom_target(run_mull_mutation
    DEPENDS build_mull_targets setup_outputs
    COMMAND mull-cxx -compilation-flags="-O2 -g" -compilation-database ${CMAKE_BINARY_DIR}/compile_commands.json -reporters=json -reporters=html -output=${CMAKE_BINARY_DIR}/outputs/mull/mutation_report.json -output=${CMAKE_BINARY_DIR}/outputs/mull/mutation_report.html
    COMMENT "Running Mull mutation testing"
)

# Combined fuzzing and mutation testing
add_custom_target(run_all_fuzzing
    DEPENDS run_afl_fuzzing run_mull_mutation
    COMMENT "Running all fuzzing and mutation testing"
)

# Clean targets
add_custom_target(clean_fuzzing
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/outputs
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/corpus
    COMMENT "Cleaning fuzzing outputs and corpus"
)

# Help target
add_custom_target(help_fuzzing
    COMMAND ${CMAKE_COMMAND} -E echo "Available fuzzing targets:"
    COMMAND ${CMAKE_COMMAND} -E echo "  build_afl_targets    - Build AFL++ fuzzing targets"
    COMMAND ${CMAKE_COMMAND} -E echo "  build_mull_targets   - Build Mull mutation testing targets"
    COMMAND ${CMAKE_COMMAND} -E echo "  run_afl_fuzzing      - Run AFL++ fuzzing"
    COMMAND ${CMAKE_COMMAND} -E echo "  run_mull_mutation    - Run Mull mutation testing"
    COMMAND ${CMAKE_COMMAND} -E echo "  run_all_fuzzing      - Run all fuzzing and mutation testing"
    COMMAND ${CMAKE_COMMAND} -E echo "  clean_fuzzing        - Clean fuzzing outputs"
    COMMENT "Fuzzing help information"
)

# Enable testing
enable_testing()

# Add tests for fuzzing targets
add_test(NAME fuzzing_targets_build COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target build_afl_targets)
add_test(NAME mutation_targets_build COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target build_mull_targets)
