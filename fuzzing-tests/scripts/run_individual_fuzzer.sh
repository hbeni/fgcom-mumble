#!/bin/bash

# Individual Fuzzer Runner
# Usage: ./run_individual_fuzzer.sh <fuzzer_name> [duration_hours]

set -e

FUZZER_NAME=$1
DURATION_HOURS=${2:-12}

if [ -z "$FUZZER_NAME" ]; then
    echo "Usage: $0 <fuzzer_name> [duration_hours]"
    echo "Available fuzzers:"
    ls build/fuzz_* 2>/dev/null | sed 's/build\///' || echo "No fuzzers found. Run compile_fuzzers.sh first."
    exit 1
fi

FUZZER_PATH="build/$FUZZER_NAME"
if [ ! -f "$FUZZER_PATH" ]; then
    echo "Error: Fuzzer $FUZZER_PATH not found"
    echo "Available fuzzers:"
    ls build/fuzz_* 2>/dev/null | sed 's/build\///' || echo "No fuzzers found. Run compile_fuzzers.sh first."
    exit 1
fi

# Calculate duration in seconds
DURATION_SECONDS=$((DURATION_HOURS * 3600))

echo "=== RUNNING INDIVIDUAL FUZZER ==="
echo "Fuzzer: $FUZZER_NAME"
echo "Duration: $DURATION_HOURS hours ($DURATION_SECONDS seconds)"
echo "Start time: $(date)"
echo ""

# Fuzzer execution flags
FUZZ_FLAGS="-max_total_time=$DURATION_SECONDS"
FUZZ_FLAGS="$FUZZ_FLAGS -error_exitcode=0"  # Continue on crashes
FUZZ_FLAGS="$FUZZ_FLAGS -timeout=25"  # 25 second timeout
FUZZ_FLAGS="$FUZZ_FLAGS -hang=25"  # 25 second hang timeout
FUZZ_FLAGS="$FUZZ_FLAGS -rss_limit_mb=4096"  # 4GB memory limit
FUZZ_FLAGS="$FUZZ_FLAGS -print_final_stats=1"  # Print stats
FUZZ_FLAGS="$FUZZ_FLAGS -artifact_prefix=crashes/"  # Crash output
FUZZ_FLAGS="$FUZZ_FLAGS -print_coverage=1"  # Coverage info
FUZZ_FLAGS="$FUZZ_FLAGS -print_corpus_stats=1"  # Corpus stats

# Create crashes directory
mkdir -p crashes

# Run the fuzzer
echo "Starting fuzzer with flags: $FUZZ_FLAGS"
echo ""

./$FUZZER_PATH $FUZZ_FLAGS corpus/

echo ""
echo "=== FUZZER COMPLETED ==="
echo "End time: $(date)"
echo "Check crashes/ directory for any crashes found."
echo "Check fuzzer output above for coverage and statistics."
