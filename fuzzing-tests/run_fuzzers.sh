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
