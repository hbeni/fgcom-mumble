#!/bin/bash

# Comprehensive Fuzzing Script for FGCom-Mumble
# Runs 15 fuzzing targets with AFL++ for 12 hours (43200 seconds)
# Uses 28 cores with priority-based allocation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TOTAL_CORES=28
TOTAL_TIME_SECONDS=43200  # 12 hours
TIMEOUT_PER_TARGET=43200

# Fuzzing targets array with their corresponding binaries
declare -A TARGET_BINARIES=(
    ["fuzz_agc"]="./test/build-fuzz/fuzz_agc"
    ["fuzz_antenna_patterns"]="./test/build-fuzz/fuzz_antenna_patterns"
    ["fuzz_atis_processing"]="./test/build-fuzz/fuzz_atis_processing"
    ["fuzz_audio_processing"]="./test/build-fuzz/fuzz_audio_processing"
    ["fuzz_database_operations"]="./test/build-fuzz/fuzz_database_operations"
    ["fuzz_error_handling"]="./test/build-fuzz/fuzz_error_handling"
    ["fuzz_frequency_management"]="./test/build-fuzz/fuzz_frequency_management"
    ["fuzz_geographic_calculations"]="./test/build-fuzz/fuzz_geographic_calculations"
    ["fuzz_input_validation"]="./test/build-fuzz/fuzz_input_validation"
    ["fuzz_integration_tests"]="./test/build-fuzz/fuzz_integration_tests"
    ["fuzz_memory_operations"]="./test/build-fuzz/fuzz_memory_operations"
    ["fuzz_network_protocol"]="./test/build-fuzz/fuzz_network_protocol"
    ["fuzz_performance_tests"]="./test/build-fuzz/fuzz_performance_tests"
    ["fuzz_radio_propagation"]="./test/build-fuzz/fuzz_radio_propagation"
    ["fuzz_satellite_communication"]="./test/build-fuzz/fuzz_satellite_communication"
    ["fuzz_security_functions"]="./test/build-fuzz/fuzz_security_functions"
    ["fuzz_voice_encryption"]="./test/build-fuzz/fuzz_voice_encryption"
    ["fuzz_webrtc_operations"]="./test/build-fuzz/fuzz_webrtc_operations"
)

# Get target names for iteration
TARGETS=($(printf '%s\n' "${!TARGET_BINARIES[@]}" | sort))

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if AFL++ is installed
    if ! command -v afl-fuzz &> /dev/null; then
        print_error "AFL++ is not installed. Please install it first."
        exit 1
    fi
    
    # Check if we have enough cores
    AVAILABLE_CORES=$(nproc)
    if [ "$AVAILABLE_CORES" -lt "$TOTAL_CORES" ]; then
        print_warning "Only $AVAILABLE_CORES cores available, but $TOTAL_CORES requested"
        print_warning "Consider reducing TOTAL_CORES or using fewer parallel targets"
    fi
    
    # Check if target binaries exist
    MISSING_TARGETS=()
    for target in "${TARGETS[@]}"; do
        binary_path="${TARGET_BINARIES[$target]}"
        if [ ! -f "$binary_path" ]; then
            MISSING_TARGETS+=("$target ($binary_path)")
        fi
    done
    
    if [ ${#MISSING_TARGETS[@]} -gt 0 ]; then
        print_error "Missing target binaries: ${MISSING_TARGETS[*]}"
        print_error "Please build the fuzzing targets first"
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

# Function to setup directories
setup_directories() {
    print_status "Setting up directories..."
    
    # Create corpus, results, and logs directories
    mkdir -p logs
    for target in "${TARGETS[@]}"; do
        mkdir -p corpus/$target
        mkdir -p results/$target
        
        # Create sample input files if corpus is empty
        if [ ! "$(ls -A corpus/$target 2>/dev/null)" ]; then
            echo "sample input for $target" > corpus/$target/sample1.txt
            echo "test data for $target" > corpus/$target/sample2.txt
            echo "fuzzing input for $target" > corpus/$target/sample3.txt
            print_status "Created sample corpus for $target"
        fi
    done
    
    print_success "Directories setup complete"
}

# Function to start fuzzing
start_fuzzing() {
    print_status "Starting fuzzing for ${#TARGETS[@]} targets..."
    print_status "Total time: $((TOTAL_TIME_SECONDS / 3600)) hours"
    print_status "Using $TOTAL_CORES cores"
    
    # Start fuzzing for each target
    for target in "${TARGETS[@]}"; do
        print_status "Starting fuzzing for $target..."
        
        # Set AFL environment variables
        export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
        export AFL_SKIP_CPUFREQ=1
        
        # Get the binary path for this target
        binary_path="${TARGET_BINARIES[$target]}"
        
        # Start AFL fuzzing in background
        timeout $TIMEOUT_PER_TARGET \
        afl-fuzz -i corpus/$target -o results/$target -t 10000 -- "$binary_path" @@ \
        > logs/$target.log 2>&1 &
        
        # Store process ID for monitoring
        echo $! >> fuzzing_pids.txt
        
        # Small delay to prevent resource conflicts
        sleep 2
    done
    
    print_success "All fuzzing targets started"
    print_status "Monitor progress with: ./monitor_fuzzing.sh"
    print_status "Check status with: watch -n 30 'afl-whatsup results/'"
}

# Function to wait for completion
wait_for_completion() {
    print_status "Waiting for all fuzzing to complete..."
    
    # Wait for all background processes
    wait
    
    print_success "All fuzzing complete"
    
    # Generate summary
    generate_summary
}

# Function to generate summary
generate_summary() {
    print_status "Generating fuzzing summary..."
    
    echo ""
    echo "=== FUZZING SUMMARY ==="
    echo "Timestamp: $(date)"
    echo "Total targets: ${#TARGETS[@]}"
    echo "Total time: $((TOTAL_TIME_SECONDS / 3600)) hours"
    echo "Total core-hours: $((TOTAL_CORES * TOTAL_TIME_SECONDS / 3600))"
    echo ""
    
    echo "=== RESULTS BY TARGET ==="
    for target in "${TARGETS[@]}"; do
        if [ -d "results/$target" ]; then
            echo "Target: $target"
            afl-whatsup results/$target 2>/dev/null | head -10
            echo ""
        fi
    done
    
    echo "=== CRASHES FOUND ==="
    CRASH_COUNT=0
    for target in "${TARGETS[@]}"; do
        if [ -d "results/$target/crashes" ]; then
            crashes=$(find results/$target/crashes -name "id:*" 2>/dev/null | wc -l)
            if [ "$crashes" -gt 0 ]; then
                echo "$target: $crashes crashes found"
                CRASH_COUNT=$((CRASH_COUNT + crashes))
            fi
        fi
    done
    
    if [ $CRASH_COUNT -eq 0 ]; then
        echo "No crashes found"
    else
        echo "Total crashes found: $CRASH_COUNT"
    fi
    
    echo ""
    echo "=== HANGS FOUND ==="
    HANG_COUNT=0
    for target in "${TARGETS[@]}"; do
        if [ -d "results/$target/hangs" ]; then
            hangs=$(find results/$target/hangs -name "id:*" 2>/dev/null | wc -l)
            if [ "$hangs" -gt 0 ]; then
                echo "$target: $hangs hangs found"
                HANG_COUNT=$((HANG_COUNT + hangs))
            fi
        fi
    done
    
    if [ $HANG_COUNT -eq 0 ]; then
        echo "No hangs found"
    else
        echo "Total hangs found: $HANG_COUNT"
    fi
}

# Function to cleanup on exit
cleanup() {
    print_status "Cleaning up..."
    
    # Kill any remaining fuzzing processes
    if [ -f fuzzing_pids.txt ]; then
        while read -r pid; do
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null || true
            fi
        done < fuzzing_pids.txt
        rm -f fuzzing_pids.txt
    fi
    
    print_success "Cleanup complete"
}

# Set up signal handlers
trap cleanup EXIT INT TERM

# Main execution
main() {
    echo "=========================================="
    echo "FGCom-Mumble Comprehensive Fuzzing Script"
    echo "=========================================="
    echo "Targets: ${#TARGETS[@]}"
    echo "Cores: $TOTAL_CORES"
    echo "Time: $((TOTAL_TIME_SECONDS / 3600)) hours"
    echo "=========================================="
    echo ""
    
    check_prerequisites
    setup_directories
    start_fuzzing
    wait_for_completion
}

# Run main function
main "$@"
