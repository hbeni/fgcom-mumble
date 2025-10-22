#!/bin/bash

# FGCom LibFuzzer Compilation Script
# Compiles all fuzzing harnesses with proper sanitizers and flags

set -e

echo "=== COMPILING FGCOM FUZZING HARNESSES ==="

# Check for required tools
if ! command -v clang++ &> /dev/null; then
    echo "Error: clang++ not found. Please install clang++"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo "Error: python3 not found. Please install python3"
    exit 1
fi

# Create build directory
mkdir -p build
cd build

# Compilation flags
CXX_FLAGS="-g -O1 -fsanitize=fuzzer,address,undefined -fsanitize-recover=all"
CXX_FLAGS="$CXX_FLAGS -fno-omit-frame-pointer -fno-optimize-sibling-calls"
CXX_FLAGS="$CXX_FLAGS -fno-common -fno-builtin"
CXX_FLAGS="$CXX_FLAGS -std=c++17 -Wall -Wextra"

# Include paths (simplified for standalone fuzzing)
INCLUDE_PATHS="-I../harnesses"
INCLUDE_PATHS="$INCLUDE_PATHS -I/usr/include/fuzzer"

# Library paths (none needed for standalone fuzzers)
LIB_PATHS=""

# Libraries (minimal dependencies)
LIBS="-lm -lpthread"

# Compile each harness
echo "Compiling fuzz_radio_propagation..."
clang++ $CXX_FLAGS $INCLUDE_PATHS $LIB_PATHS \
    ../harnesses/fuzz_radio_propagation.cpp \
    -o fuzz_radio_propagation \
    $LIBS

echo "Compiling fuzz_audio_processing..."
clang++ $CXX_FLAGS $INCLUDE_PATHS $LIB_PATHS \
    ../harnesses/fuzz_audio_processing.cpp \
    -o fuzz_audio_processing \
    $LIBS

echo "Compiling fuzz_network_protocol..."
clang++ $CXX_FLAGS $INCLUDE_PATHS $LIB_PATHS \
    ../harnesses/fuzz_network_protocol.cpp \
    -o fuzz_network_protocol \
    $LIBS

echo "Compiling fuzz_security_functions..."
clang++ $CXX_FLAGS $INCLUDE_PATHS $LIB_PATHS \
    ../harnesses/fuzz_security_functions.cpp \
    -o fuzz_security_functions \
    $LIBS

echo "Compiling fuzz_data_parsing..."
clang++ $CXX_FLAGS $INCLUDE_PATHS $LIB_PATHS \
    ../harnesses/fuzz_data_parsing.cpp \
    -o fuzz_data_parsing \
    $LIBS

echo "Compiling fuzz_mathematical_calculations..."
clang++ $CXX_FLAGS $INCLUDE_PATHS $LIB_PATHS \
    ../harnesses/fuzz_mathematical_calculations.cpp \
    -o fuzz_mathematical_calculations \
    $LIBS

echo "Compiling fuzz_file_io..."
clang++ $CXX_FLAGS $INCLUDE_PATHS $LIB_PATHS \
    ../harnesses/fuzz_file_io.cpp \
    -o fuzz_file_io \
    $LIBS

# Generate corpus files
echo "Generating corpus files..."
cd ..
python3 scripts/generate_corpus.py

# Create run script
cat > run_fuzzers.sh << 'EOF'
#!/bin/bash

# FGCom Fuzzer Execution Script
# Runs all fuzzers with 12-hour timeout and crash handling

set -e

echo "=== RUNNING FGCOM FUZZERS ==="

# Fuzzer execution flags
FUZZ_FLAGS="-max_total_time=43200"  # 12 hours
FUZZ_FLAGS="$FUZZ_FLAGS -error_exitcode=0"  # Continue on crashes
FUZZ_FLAGS="$FUZZ_FLAGS -timeout=25"  # 25 second timeout
FUZZ_FLAGS="$FUZZ_FLAGS -hang=25"  # 25 second hang timeout
FUZZ_FLAGS="$FUZZ_FLAGS -rss_limit_mb=4096"  # 4GB memory limit
FUZZ_FLAGS="$FUZZ_FLAGS -print_final_stats=1"  # Print stats
FUZZ_FLAGS="$FUZZ_FLAGS -artifact_prefix=crashes/"  # Crash output
FUZZ_FLAGS="$FUZZ_FLAGS -print_coverage=1"  # Coverage info

# Create crashes directory
mkdir -p crashes

# Run each fuzzer
echo "Running fuzz_radio_propagation..."
./build/fuzz_radio_propagation $FUZZ_FLAGS corpus/ &

echo "Running fuzz_audio_processing..."
./build/fuzz_audio_processing $FUZZ_FLAGS corpus/ &

echo "Running fuzz_network_protocol..."
./build/fuzz_network_protocol $FUZZ_FLAGS corpus/ &

echo "Running fuzz_security_functions..."
./build/fuzz_security_functions $FUZZ_FLAGS corpus/ &

echo "Running fuzz_data_parsing..."
./build/fuzz_data_parsing $FUZZ_FLAGS corpus/ &

echo "Running fuzz_mathematical_calculations..."
./build/fuzz_mathematical_calculations $FUZZ_FLAGS corpus/ &

echo "Running fuzz_file_io..."
./build/fuzz_file_io $FUZZ_FLAGS corpus/ &

echo "All fuzzers started. They will run for 12 hours."
echo "Check crashes/ directory for any crashes found."
echo "Use 'ps aux | grep fuzz' to see running fuzzers."
echo "Use 'killall fuzz_*' to stop all fuzzers."

wait
EOF

chmod +x run_fuzzers.sh

echo ""
echo "=== COMPILATION COMPLETE ==="
echo "Built fuzzers:"
ls -la build/
echo ""
echo "Generated corpus files:"
ls -la corpus/
echo ""
echo "To run fuzzers: ./run_fuzzers.sh"
echo "To run individual fuzzer: ./build/fuzz_radio_propagation -max_total_time=43200 -error_exitcode=0 -timeout=25 -rss_limit_mb=4096 corpus/"
