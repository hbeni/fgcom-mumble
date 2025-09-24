#!/bin/bash
# generate_fast_patterns.sh - Fast multi-core radiation pattern generation
# Uses GNU parallel for optimal CPU utilization

set -e

# Source the pattern extraction function
source "$(dirname "$0")/extract_pattern_advanced.sh"

# Configuration
SCRIPT_DIR="$(dirname "$0")"
ANTENNA_PATTERNS_DIR="$SCRIPT_DIR/antenna_patterns"
MILITARY_FREQUENCIES=(3.0 5.0 7.0 9.0)
AMATEUR_BANDS=(1.8 3.5 5.3 7.0 10.1 14.0 18.1 21.0 24.9 28.0 50.0)
MAX_PARALLEL_JOBS=$(nproc)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Generate single pattern (for parallel execution)
generate_single_pattern() {
    local eznec_file="$1"
    local frequency_mhz="$2"
    local altitude_m="$3"
    local vehicle_name="$4"
    
    if [ ! -f "$eznec_file" ]; then
        echo "ERROR: EZNEC file not found: $eznec_file"
        return 1
    fi
    
    local base_name=$(basename "$eznec_file" .ez)
    local output_dir="$(dirname "$eznec_file")"
    local work_dir="/tmp/nec_work_$$_${RANDOM}"
    
    # Create temporary working directory
    mkdir -p "$work_dir"
    cd "$work_dir"
    
    # Create frequency-specific EZNEC file
    local freq_eznec="${base_name}_${frequency_mhz}MHz.ez"
    cp "$eznec_file" "$freq_eznec"
    
    # Update frequency in EZNEC file
    sed -i "s/^FR.*/FR 0 1 0 0 ${frequency_mhz} 0/" "$freq_eznec"
    
    # Convert to NEC2 format
    if ! "$SCRIPT_DIR/eznec2nec.sh" "$freq_eznec" "${base_name}_${frequency_mhz}MHz.nec"; then
        echo "ERROR: Failed to convert EZNEC to NEC2 format for $vehicle_name at ${frequency_mhz}MHz"
        cd - > /dev/null
        rm -rf "$work_dir"
        return 1
    fi
    
    # Run NEC2 simulation
    local nec_file="${base_name}_${frequency_mhz}MHz.nec"
    local out_file="${base_name}_${frequency_mhz}MHz.out"
    
    if ! nec2c -i "$nec_file" -o "$out_file" 2>/dev/null; then
        # Try with shorter filename to avoid path length issues
        local short_nec="short.nec"
        local short_out="short.out"
        cp "$nec_file" "$short_nec"
        if nec2c -i "$short_nec" -o "$short_out" 2>/dev/null; then
            mv "$short_out" "$out_file"
            rm -f "$short_nec"
        else
            echo "ERROR: NEC2 simulation failed for $vehicle_name at ${frequency_mhz}MHz"
            cd - > /dev/null
            rm -rf "$work_dir"
            return 1
        fi
    fi
    
    # Extract radiation pattern
    local pattern_file="${base_name}_${frequency_mhz}MHz_pattern.txt"
    
    if ! extract_radiation_pattern_advanced "$out_file" "$pattern_file" "$frequency_mhz" "$altitude_m"; then
        echo "ERROR: Pattern extraction failed for $vehicle_name at ${frequency_mhz}MHz"
        cd - > /dev/null
        rm -rf "$work_dir"
        return 1
    fi
    
    # Move pattern file to correct location
    local final_pattern_dir="$output_dir/${vehicle_name}_patterns/${frequency_mhz}mhz"
    mkdir -p "$final_pattern_dir"
    local final_pattern="$final_pattern_dir/${vehicle_name}_${frequency_mhz}MHz_${altitude_m}m_pattern.txt"
    mv "$pattern_file" "$final_pattern"
    
    # Cleanup
    cd - > /dev/null
    rm -rf "$work_dir"
    
    echo "SUCCESS: Generated pattern for $vehicle_name at ${frequency_mhz}MHz (${altitude_m}m)"
    return 0
}

# Export function for parallel execution
export -f generate_single_pattern
export SCRIPT_DIR

# Create job list for parallel processing
create_job_list() {
    local job_file="/tmp/pattern_jobs_$$.txt"
    > "$job_file"
    
    # Military vehicles
    local military_files=(
        "$ANTENNA_PATTERNS_DIR/military-land/nato_jeep_10ft_whip_45deg.ez"
        "$ANTENNA_PATTERNS_DIR/military-land/soviet_uaz_4m_whip_45deg.ez"
        "$ANTENNA_PATTERNS_DIR/military-land/leopard1_nato_mbt/leopard1_nato_mbt.ez"
        "$ANTENNA_PATTERNS_DIR/military-land/t55_soviet_mbt/t55_soviet_mbt.ez"
    )
    
    local military_names=("nato_jeep" "soviet_uaz" "leopard1" "t55")
    
    for i in "${!military_files[@]}"; do
        if [ -f "${military_files[$i]}" ]; then
            for frequency in "${MILITARY_FREQUENCIES[@]}"; do
                echo "generate_single_pattern '${military_files[$i]}' '$frequency' '0' '${military_names[$i]}'" >> "$job_file"
            done
        fi
    done
    
    # Aircraft (with altitude variations)
    local aircraft_files=(
        "$ANTENNA_PATTERNS_DIR/aircraft/b737_800/b737_800_realistic.ez"
        "$ANTENNA_PATTERNS_DIR/aircraft/cessna_172/cessna_172_realistic_final.ez"
        "$ANTENNA_PATTERNS_DIR/aircraft/c130_hercules/c130_hercules_realistic.ez"
        "$ANTENNA_PATTERNS_DIR/aircraft/bell_uh1_huey/bell_uh1_huey_realistic.ez"
        "$ANTENNA_PATTERNS_DIR/aircraft/tu95_bear/tu95_bear_realistic.ez"
        "$ANTENNA_PATTERNS_DIR/aircraft/mil_mi4_hound/mil_mi4_hound_fixed.ez"
    )
    
    local aircraft_names=("b737" "cessna_172" "c130" "huey" "bear" "hound")
    
    for i in "${!aircraft_files[@]}"; do
        if [ -f "${aircraft_files[$i]}" ]; then
            for frequency in "${AMATEUR_BANDS[@]}"; do
                for altitude in $(seq 0 2000 15000); do  # Reduced altitude steps for faster generation
                    echo "generate_single_pattern '${aircraft_files[$i]}' '$frequency' '$altitude' '${aircraft_names[$i]}'" >> "$job_file"
                done
            done
        fi
    done
    
    # Ground vehicles
    local ground_files=(
        "$ANTENNA_PATTERNS_DIR/vehicle/ford_transit/ford_transit_camper_vertical.ez"
        "$ANTENNA_PATTERNS_DIR/vehicle/vw_passat/vw_passat_hf_loaded_vertical.ez"
    )
    
    local ground_names=("ford_transit" "vw_passat")
    
    for i in "${!ground_files[@]}"; do
        if [ -f "${ground_files[$i]}" ]; then
            for frequency in "${AMATEUR_BANDS[@]}"; do
                echo "generate_single_pattern '${ground_files[$i]}' '$frequency' '0' '${ground_names[$i]}'" >> "$job_file"
            done
        fi
    done
    
    # Boats
    local boat_files=(
        "$ANTENNA_PATTERNS_DIR/boat/sailboat_whip/sailboat_23ft_whip_20m.ez"
        "$ANTENNA_PATTERNS_DIR/boat/sailboat_backstay/sailboat_backstay_40m.ez"
    )
    
    local boat_names=("sailboat_whip" "sailboat_backstay")
    
    for i in "${!boat_files[@]}"; do
        if [ -f "${boat_files[$i]}" ]; then
            for frequency in "${AMATEUR_BANDS[@]}"; do
                echo "generate_single_pattern '${boat_files[$i]}' '$frequency' '0' '${boat_names[$i]}'" >> "$job_file"
            done
        fi
    done
    
    # Ships
    local ship_files=(
        "$ANTENNA_PATTERNS_DIR/ship/containership/containership_80m_loop.ez"
    )
    
    local ship_names=("containership")
    
    for i in "${!ship_files[@]}"; do
        if [ -f "${ship_files[$i]}" ]; then
            for frequency in "${AMATEUR_BANDS[@]}"; do
                echo "generate_single_pattern '${ship_files[$i]}' '$frequency' '0' '${ship_names[$i]}'" >> "$job_file"
            done
        fi
    done
    
    echo "$job_file"
}

# Main function
main() {
    log_info "Starting fast parallel radiation pattern generation using $MAX_PARALLEL_JOBS CPU cores..."
    log_info "This will generate all missing radiation patterns using all CPU cores!"
    
    # Check dependencies
    if ! command -v nec2c &> /dev/null; then
        log_error "nec2c not found. Please install NEC2 simulation software."
        exit 1
    fi
    
    if ! command -v bc &> /dev/null; then
        log_error "bc calculator not found. Please install bc."
        exit 1
    fi
    
    log_success "All dependencies found"
    
    # Create job list
    log_info "Creating job list..."
    local job_file=$(create_job_list)
    local total_jobs=$(wc -l < "$job_file")
    log_info "Total jobs to process: $total_jobs"
    
    # Process jobs in parallel
    log_info "Processing jobs using $MAX_PARALLEL_JOBS CPU cores..."
    
    # Use GNU parallel if available, otherwise use xargs
    if command -v parallel &> /dev/null; then
        log_info "Using GNU parallel for optimal performance..."
        parallel -j "$MAX_PARALLEL_JOBS" --line-buffer bash -c '{}' < "$job_file"
    else
        log_info "Using xargs for parallel processing..."
        cat "$job_file" | xargs -n 1 -P "$MAX_PARALLEL_JOBS" -I {} bash -c '{}'
    fi
    
    # Cleanup
    rm -f "$job_file"
    
    # Count generated patterns
    local pattern_count=$(find "$ANTENNA_PATTERNS_DIR" -name "*_pattern.txt" | wc -l)
    log_success "Fast parallel pattern generation completed!"
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
