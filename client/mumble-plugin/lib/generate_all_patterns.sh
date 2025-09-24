#!/bin/bash

# FGCom-Mumble Radiation Pattern Generator
# This script generates all missing radiation pattern files using parallel processing

set -e

# Configuration
SCRIPT_DIR="$(dirname "$0")"
ANTENNA_PATTERNS_DIR="$SCRIPT_DIR/antenna_patterns"
AMATEUR_BANDS=(1.8 3.5 5.3 7.0 10.1 14.0 18.1 21.0 24.9 28.0 50.0)
MILITARY_FREQUENCIES=(3.0 5.0 7.0 9.0)
MAX_PARALLEL_JOBS=20

# Logging functions
log_info() {
    echo "[INFO] $1"
}

log_success() {
    echo "[SUCCESS] $1"
}

log_warning() {
    echo "[WARNING] $1"
}

log_error() {
    echo "[ERROR] $1"
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    
    if ! command -v nec2c &> /dev/null; then
        log_error "nec2c not found. Please install nec2c."
        exit 1
    fi
    
    if ! command -v bc &> /dev/null; then
        log_error "bc not found. Please install bc."
        exit 1
    fi
    
    if [ ! -f "$SCRIPT_DIR/eznec2nec.sh" ]; then
        log_error "eznec2nec.sh not found in $SCRIPT_DIR"
        exit 1
    fi
    
    if [ ! -f "$SCRIPT_DIR/extract_pattern_advanced.sh" ]; then
        log_error "extract_pattern_advanced.sh not found in $SCRIPT_DIR"
        exit 1
    fi
    
    log_success "All dependencies found"
}

# Source the pattern extraction script
source "$SCRIPT_DIR/extract_pattern_advanced.sh"

# Generate patterns for a single EZNEC file
generate_pattern_for_file() {
    local eznec_file="$1"
    local frequency_mhz="$2"
    local altitude_m="$3"
    local vehicle_name="$4"
    
    if [ ! -f "$eznec_file" ]; then
        return 1
    fi
    
    local base_name=$(basename "$eznec_file" .ez)
    local output_dir="$(dirname "$eznec_file")"
    local final_dir="$output_dir/patterns/${frequency_mhz}mhz"
    local final_pattern="$final_dir/${base_name}_${frequency_mhz}MHz_${altitude_m}m_pattern.txt"
    
    # Skip if pattern already exists
    if [ -f "$final_pattern" ]; then
        echo "Pattern already exists: $final_pattern"
        return 0
    fi
    
    local work_dir="/tmp/nec_work_$$_${RANDOM}"
    
    # Create temporary working directory
    mkdir -p "$work_dir"
    cd "$work_dir"
    
    # Copy original EZNEC file
    cp "$eznec_file" "${base_name}.ez"
    
    # Update frequency in EZNEC file
    sed -i "s/^FR.*/FR 0 1 0 0 ${frequency_mhz} 0/" "${base_name}.ez"
    
    # Convert to NEC2 format
    if bash "/home/haaken/github-projects/fgcom-mumble/client/mumble-plugin/lib/eznec2nec.sh" "${base_name}.ez" "${base_name}.nec" 2>/dev/null; then
        echo "EZNEC conversion successful for $vehicle_name at ${frequency_mhz}MHz"
        # Run NEC2 simulation
        if nec2c -i "${base_name}.nec" -o "${base_name}.out" 2>/dev/null; then
            echo "NEC2 simulation successful for $vehicle_name at ${frequency_mhz}MHz"
            # Extract radiation pattern
            if extract_radiation_pattern_advanced "${base_name}.out" "${base_name}_pattern.txt" "$frequency_mhz" "$altitude_m" 2>/dev/null; then
                echo "Pattern extraction successful for $vehicle_name at ${frequency_mhz}MHz"
                # Create proper directory structure and move pattern file
                mkdir -p "$final_dir"
                mv "${base_name}_pattern.txt" "$final_pattern"
                echo "Generated: $final_pattern"
            else
                echo "Pattern extraction failed for $vehicle_name at ${frequency_mhz}MHz"
            fi
        else
            echo "NEC2 simulation failed for $vehicle_name at ${frequency_mhz}MHz"
        fi
    else
        echo "EZNEC conversion failed for $vehicle_name at ${frequency_mhz}MHz"
    fi
    
    # Cleanup
    cd - > /dev/null
    rm -rf "$work_dir"
    return 0
}

# Export function for parallel execution
export -f generate_pattern_for_file
export SCRIPT_DIR

# Main generation function
main() {
    log_info "Starting pattern generation using $MAX_PARALLEL_JOBS CPU cores..."
    log_info "This will generate missing radiation patterns using all CPU cores!"
    
    check_dependencies
    
    # Create job list for parallel processing
    local job_file="/tmp/pattern_jobs_$$.txt"
    > "$job_file"
    
    # Find all EZNEC files and create jobs
    log_info "Processing EZNEC files..."
    find "$ANTENNA_PATTERNS_DIR" -name "*.ez" -type f | while read eznec_file; do
        # Convert to absolute path
        eznec_file="$(realpath "$eznec_file")"
        local vehicle_name=$(basename "$(dirname "$eznec_file")")
        
        # Determine frequencies based on vehicle type
        if [[ "$eznec_file" =~ military-land ]]; then
            # Military vehicles use military frequencies
            for frequency in "${MILITARY_FREQUENCIES[@]}"; do
                echo "generate_pattern_for_file '$eznec_file' '$frequency' '0' '$vehicle_name'" >> "$job_file"
            done
        else
            # All other vehicles use amateur bands
            for frequency in "${AMATEUR_BANDS[@]}"; do
                # For aircraft, generate altitude variations
                if [[ "$eznec_file" =~ aircraft ]]; then
                    for altitude in $(seq 50 1000 15000); do
                        echo "generate_pattern_for_file '$eznec_file' '$frequency' '$altitude' '$vehicle_name'" >> "$job_file"
                    done
                else
                    # Ground level only for other vehicles
                    echo "generate_pattern_for_file '$eznec_file' '$frequency' '0' '$vehicle_name'" >> "$job_file"
                fi
            done
        fi
    done
    
    local total_jobs=$(wc -l < "$job_file")
    log_info "Total jobs to process: $total_jobs"
    
    # Process jobs in parallel using 12 CPU cores
    log_info "Processing jobs using $MAX_PARALLEL_JOBS CPU cores..."
    cat "$job_file" | xargs -n 1 -P "$MAX_PARALLEL_JOBS" -I {} bash -c '{}'
    
    # Cleanup
    rm -f "$job_file"
    
    # Count generated patterns
    local pattern_count=$(find "$ANTENNA_PATTERNS_DIR" -name "*_pattern.txt" | wc -l)
    log_success "Pattern generation completed!"
    log_info "Total radiation patterns generated: $pattern_count"
    
    # Show breakdown by vehicle type
    log_info "Pattern breakdown:"
    for vehicle_type in military-land aircraft vehicle boat ship Ground-based; do
        local count=$(find "$ANTENNA_PATTERNS_DIR/$vehicle_type" -name "*_pattern.txt" 2>/dev/null | wc -l)
        if [ "$count" -gt 0 ]; then
            log_info "  $vehicle_type: $count patterns"
        fi
    done
}

# Run main function
main "$@"