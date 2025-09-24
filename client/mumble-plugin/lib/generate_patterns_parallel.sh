#!/bin/bash
# generate_patterns_parallel.sh - Multi-core parallel radiation pattern generation
# This script uses all 24 CPU cores for fast pattern generation

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
        log_error "EZNEC file not found: $eznec_file"
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
        log_error "Failed to convert EZNEC to NEC2 format"
        cd - > /dev/null
        rm -rf "$work_dir"
        return 1
    fi
    
    # Run NEC2 simulation
    local nec_file="${base_name}_${frequency_mhz}MHz.nec"
    local out_file="${base_name}_${frequency_mhz}MHz.out"
    
    if ! nec2c -i "$nec_file" -o "$out_file" 2>/dev/null; then
        log_warning "NEC2 simulation failed, trying with shorter filename..."
        local short_nec="short.nec"
        local short_out="short.out"
        cp "$nec_file" "$short_nec"
        if nec2c -i "$short_nec" -o "$short_out" 2>/dev/null; then
            mv "$short_out" "$out_file"
            rm -f "$short_nec"
        else
            log_error "NEC2 simulation failed completely"
            cd - > /dev/null
            rm -rf "$work_dir"
            return 1
        fi
    fi
    
    # Extract radiation pattern
    local pattern_file="${base_name}_${frequency_mhz}MHz_pattern.txt"
    
    if ! extract_radiation_pattern_advanced "$out_file" "$pattern_file" "$frequency_mhz" "$altitude_m"; then
        log_error "Pattern extraction failed"
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
    
    echo "Generated pattern for $vehicle_name at ${frequency_mhz}MHz (${altitude_m}m)"
    return 0
}

# Export function for parallel execution
export -f generate_single_pattern
export SCRIPT_DIR
export -f log_info log_success log_warning log_error

# Generate military patterns in parallel
generate_military_patterns_parallel() {
    log_info "Generating military patterns using $MAX_PARALLEL_JOBS CPU cores..."
    
    local jobs=()
    
    # NATO Jeep
    local nato_jeep_eznec="$ANTENNA_PATTERNS_DIR/military-land/nato_jeep_10ft_whip_45deg.ez"
    if [ -f "$nato_jeep_eznec" ]; then
        for frequency in "${MILITARY_FREQUENCIES[@]}"; do
            jobs+=("generate_single_pattern '$nato_jeep_eznec' '$frequency' '0' 'nato_jeep'")
        done
    fi
    
    # Soviet UAZ
    local soviet_uaz_eznec="$ANTENNA_PATTERNS_DIR/military-land/soviet_uaz_4m_whip_45deg.ez"
    if [ -f "$soviet_uaz_eznec" ]; then
        for frequency in "${MILITARY_FREQUENCIES[@]}"; do
            jobs+=("generate_single_pattern '$soviet_uaz_eznec' '$frequency' '0' 'soviet_uaz'")
        done
    fi
    
    # Leopard 1
    local leopard_eznec="$ANTENNA_PATTERNS_DIR/military-land/leopard1_nato_mbt/leopard1_nato_mbt.ez"
    if [ -f "$leopard_eznec" ]; then
        for frequency in "${MILITARY_FREQUENCIES[@]}"; do
            jobs+=("generate_single_pattern '$leopard_eznec' '$frequency' '0' 'leopard1'")
        done
    fi
    
    # T-55
    local t55_eznec="$ANTENNA_PATTERNS_DIR/military-land/t55_soviet_mbt/t55_soviet_mbt.ez"
    if [ -f "$t55_eznec" ]; then
        for frequency in "${MILITARY_FREQUENCIES[@]}"; do
            jobs+=("generate_single_pattern '$t55_eznec' '$frequency' '0' 't55'")
        done
    fi
    
    # Execute jobs in parallel
    printf '%s\n' "${jobs[@]}" | xargs -n 1 -P "$MAX_PARALLEL_JOBS" -I {} bash -c '{}'
}

# Generate aircraft patterns in parallel
generate_aircraft_patterns_parallel() {
    log_info "Generating aircraft patterns using $MAX_PARALLEL_JOBS CPU cores..."
    
    local jobs=()
    
    # B737
    local b737_eznec="$ANTENNA_PATTERNS_DIR/aircraft/b737_800/b737_800_realistic.ez"
    if [ -f "$b737_eznec" ]; then
        for frequency in "${AMATEUR_BANDS[@]}"; do
            for altitude in $(seq 0 1000 15000); do
                jobs+=("generate_single_pattern '$b737_eznec' '$frequency' '$altitude' 'b737'")
            done
        done
    fi
    
    # Cessna 172
    local cessna_eznec="$ANTENNA_PATTERNS_DIR/aircraft/cessna_172/cessna_172_realistic_final.ez"
    if [ -f "$cessna_eznec" ]; then
        for frequency in "${AMATEUR_BANDS[@]}"; do
            for altitude in $(seq 0 1000 15000); do
                jobs+=("generate_single_pattern '$cessna_eznec' '$frequency' '$altitude' 'cessna_172'")
            done
        done
    fi
    
    # C-130 Hercules
    local c130_eznec="$ANTENNA_PATTERNS_DIR/aircraft/c130_hercules/c130_hercules_realistic.ez"
    if [ -f "$c130_eznec" ]; then
        for frequency in "${AMATEUR_BANDS[@]}"; do
            for altitude in $(seq 0 1000 15000); do
                jobs+=("generate_single_pattern '$c130_eznec' '$frequency' '$altitude' 'c130'")
            done
        done
    fi
    
    # UH-1 Huey
    local huey_eznec="$ANTENNA_PATTERNS_DIR/aircraft/bell_uh1_huey/bell_uh1_huey_realistic.ez"
    if [ -f "$huey_eznec" ]; then
        for frequency in "${AMATEUR_BANDS[@]}"; do
            for altitude in $(seq 0 1000 15000); do
                jobs+=("generate_single_pattern '$huey_eznec' '$frequency' '$altitude' 'huey'")
            done
        done
    fi
    
    # Tu-95 Bear
    local bear_eznec="$ANTENNA_PATTERNS_DIR/aircraft/tu95_bear/tu95_bear_realistic.ez"
    if [ -f "$bear_eznec" ]; then
        for frequency in "${AMATEUR_BANDS[@]}"; do
            for altitude in $(seq 0 1000 15000); do
                jobs+=("generate_single_pattern '$bear_eznec' '$frequency' '$altitude' 'bear'")
            done
        done
    fi
    
    # Mi-4 Hound
    local hound_eznec="$ANTENNA_PATTERNS_DIR/aircraft/mil_mi4_hound/mil_mi4_hound_fixed.ez"
    if [ -f "$hound_eznec" ]; then
        for frequency in "${AMATEUR_BANDS[@]}"; do
            for altitude in $(seq 0 1000 15000); do
                jobs+=("generate_single_pattern '$hound_eznec' '$frequency' '$altitude' 'hound'")
            done
        done
    fi
    
    # Execute jobs in parallel
    printf '%s\n' "${jobs[@]}" | xargs -n 1 -P "$MAX_PARALLEL_JOBS" -I {} bash -c '{}'
}

# Generate ground vehicle patterns in parallel
generate_ground_vehicle_patterns_parallel() {
    log_info "Generating ground vehicle patterns using $MAX_PARALLEL_JOBS CPU cores..."
    
    local jobs=()
    
    # Ford Transit
    local ford_eznec="$ANTENNA_PATTERNS_DIR/vehicle/ford_transit/ford_transit_camper_vertical.ez"
    if [ -f "$ford_eznec" ]; then
        for frequency in "${AMATEUR_BANDS[@]}"; do
            jobs+=("generate_single_pattern '$ford_eznec' '$frequency' '0' 'ford_transit'")
        done
    fi
    
    # VW Passat
    local vw_eznec="$ANTENNA_PATTERNS_DIR/vehicle/vw_passat/vw_passat_hf_loaded_vertical.ez"
    if [ -f "$vw_eznec" ]; then
        for frequency in "${AMATEUR_BANDS[@]}"; do
            jobs+=("generate_single_pattern '$vw_eznec' '$frequency' '0' 'vw_passat'")
        done
    fi
    
    # Execute jobs in parallel
    printf '%s\n' "${jobs[@]}" | xargs -n 1 -P "$MAX_PARALLEL_JOBS" -I {} bash -c '{}'
}

# Generate boat patterns in parallel
generate_boat_patterns_parallel() {
    log_info "Generating boat patterns using $MAX_PARALLEL_JOBS CPU cores..."
    
    local jobs=()
    
    # Sailboat Whip
    local sailboat_whip_eznec="$ANTENNA_PATTERNS_DIR/boat/sailboat_whip/sailboat_23ft_whip_20m.ez"
    if [ -f "$sailboat_whip_eznec" ]; then
        for frequency in "${AMATEUR_BANDS[@]}"; do
            jobs+=("generate_single_pattern '$sailboat_whip_eznec' '$frequency' '0' 'sailboat_whip'")
        done
    fi
    
    # Sailboat Backstay
    local sailboat_backstay_eznec="$ANTENNA_PATTERNS_DIR/boat/sailboat_backstay/sailboat_backstay_40m.ez"
    if [ -f "$sailboat_backstay_eznec" ]; then
        for frequency in "${AMATEUR_BANDS[@]}"; do
            jobs+=("generate_single_pattern '$sailboat_backstay_eznec' '$frequency' '0' 'sailboat_backstay'")
        done
    fi
    
    # Execute jobs in parallel
    printf '%s\n' "${jobs[@]}" | xargs -n 1 -P "$MAX_PARALLEL_JOBS" -I {} bash -c '{}'
}

# Generate ship patterns in parallel
generate_ship_patterns_parallel() {
    log_info "Generating ship patterns using $MAX_PARALLEL_JOBS CPU cores..."
    
    local jobs=()
    
    # Container Ship
    local ship_eznec="$ANTENNA_PATTERNS_DIR/ship/containership/containership_80m_loop.ez"
    if [ -f "$ship_eznec" ]; then
        for frequency in "${AMATEUR_BANDS[@]}"; do
            jobs+=("generate_single_pattern '$ship_eznec' '$frequency' '0' 'containership'")
        done
    fi
    
    # Execute jobs in parallel
    printf '%s\n' "${jobs[@]}" | xargs -n 1 -P "$MAX_PARALLEL_JOBS" -I {} bash -c '{}'
}

# Main function
main() {
    log_info "Starting parallel radiation pattern generation using $MAX_PARALLEL_JOBS CPU cores..."
    log_info "This will generate all missing radiation patterns much faster!"
    
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
    
    # Generate patterns for each vehicle type in parallel
    generate_military_patterns_parallel
    generate_aircraft_patterns_parallel
    generate_ground_vehicle_patterns_parallel
    generate_boat_patterns_parallel
    generate_ship_patterns_parallel
    
    # Count generated patterns
    local pattern_count=$(find "$ANTENNA_PATTERNS_DIR" -name "*_pattern.txt" | wc -l)
    log_success "Parallel pattern generation completed!"
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
