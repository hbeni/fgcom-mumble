#!/bin/bash

# Simple 3D Pattern Generation Script
# This script generates 3D attitude patterns for aircraft and maritime vehicles

set -e

# Configuration
BASE_DIR="client/mumble-plugin/lib/antenna_patterns"
UTILITIES_DIR="scripts/utilities"
JOBS=4
OVERWRITE=false

# Attitude angles
AIRCRAFT_ROLL_ANGLES=(-180 -150 -120 -90 -60 -30 0 30 60 90 120 150 180)
AIRCRAFT_PITCH_ANGLES=(-180 -150 -120 -90 -60 -30 0 30 60 90 120 150 180)
MARITIME_ROLL_ANGLES=(-80 -60 -40 -20 0 20 40 60 80)
MARITIME_PITCH_ANGLES=(-80 -60 -40 -20 0 20 40 60 80)

# Altitude intervals
ALL_ALTITUDES=(0 25 50 100 150 200 250 300 500 650 800 1000 1500 2000 2500 3000 4000 5000 6000 7000 8000 9000 10000 12000 14000 16000 18000 20000)

# Logging functions
log_info() {
    echo "[INFO] $1"
}

log_success() {
    echo "[SUCCESS] $1"
}

log_error() {
    echo "[ERROR] $1"
}

# Function to get frequency from EZNEC file
get_frequency() {
    local eznec_file="$1"
    if [ ! -f "$eznec_file" ]; then
        echo "125.0"
        return
    fi
    
    local freq=$(grep "^FR.*[0-9]" "$eznec_file" | head -1 | grep -oE "[0-9]+\.[0-9]+" | head -1)
    if [ -n "$freq" ]; then
        echo "$freq"
    else
        echo "125.0"
    fi
}

# Function to generate 3D patterns for a single antenna
generate_3d_patterns() {
    local antenna_file="$1"
    local antenna_name="$2"
    local is_aircraft="$3"
    
    log_info "Generating 3D patterns for $antenna_name"
    
    # Get frequency
    local freq=$(get_frequency "$BASE_DIR/$antenna_file")
    log_info "Using frequency: $freq MHz"
    
    # Create patterns directory
    local patterns_dir="$BASE_DIR/$(dirname "$antenna_file")/patterns"
    mkdir -p "$patterns_dir"
    
    # Set attitude angles based on vehicle type
    if [ "$is_aircraft" = "true" ]; then
        local roll_angles=("${AIRCRAFT_ROLL_ANGLES[@]}")
        local pitch_angles=("${AIRCRAFT_PITCH_ANGLES[@]}")
        local altitudes=("${ALL_ALTITUDES[@]}")
    else
        local roll_angles=("${MARITIME_ROLL_ANGLES[@]}")
        local pitch_angles=("${MARITIME_PITCH_ANGLES[@]}")
        local altitudes=(0)
    fi
    
    # Create frequency directory
    local freq_dir="$patterns_dir/${freq}mhz"
    mkdir -p "$freq_dir"
    
    # Process each altitude
    for alt in "${altitudes[@]}"; do
        local alt_dir="$freq_dir/${alt}m"
        mkdir -p "$alt_dir"
        
        # Process each roll angle
        for roll in "${roll_angles[@]}"; do
            # Process each pitch angle
            for pitch in "${pitch_angles[@]}"; do
                local base_name=$(basename "$antenna_file" .ez)
                local pattern_file="$alt_dir/roll_${roll}_pitch_${pitch}.txt"
                
                # Skip if pattern already exists and not overwriting
                if [ -f "$pattern_file" ] && [ "$OVERWRITE" = "false" ]; then
                    continue
                fi
                
                log_info "Generating pattern: $antenna_name at $freq MHz, ${alt}m, roll=${roll}°, pitch=${pitch}°"
                
                # Create attitude-specific model
                local model_file="$alt_dir/${base_name}_${freq}.0MHz_roll_${roll}_pitch_${pitch}.ez"
                cp "$BASE_DIR/$antenna_file" "$model_file"
                
                # Add attitude comment
                echo "# Attitude: roll=${roll}°, pitch=${pitch}°" >> "$model_file"
                
                # Convert to NEC2 format
                local nec_file="${model_file%.ez}.nec"
                "$UTILITIES_DIR/eznec2nec.sh" "$model_file" "$nec_file"
                
                # Run NEC2 simulation
                local out_file="${nec_file%.nec}.out"
                nec2c "$nec_file" > "$out_file" 2>/dev/null || {
                    log_error "NEC2 simulation failed for $model_file"
                    continue
                }
                
                # Extract pattern
                "$UTILITIES_DIR/extract_pattern_advanced.sh" "$out_file" "$pattern_file" "$freq" "$alt"
                
                # Clean up temporary files
                rm -f "$model_file" "$nec_file" "$out_file"
                
                log_success "Generated: $pattern_file"
            done
        done
    done
}

# Main execution
main() {
    log_info "Starting 3D pattern generation"
    
    # Check dependencies
    if [ ! -f "$UTILITIES_DIR/eznec2nec.sh" ]; then
        log_error "eznec2nec.sh not found"
        exit 1
    fi
    
    if [ ! -f "$UTILITIES_DIR/extract_pattern_advanced.sh" ]; then
        log_error "extract_pattern_advanced.sh not found"
        exit 1
    fi
    
    # Aircraft patterns
    log_info "Generating aircraft 3D patterns"
    generate_3d_patterns "aircraft/Civil/cessna_172/cessna-hf.ez" "Cessna 172 HF" "true"
    generate_3d_patterns "aircraft/Civil/cessna_172/cessna-final.ez" "Cessna 172 VHF" "true"
    generate_3d_patterns "aircraft/Military/mi4_hound/mi4-vhf.ez" "MI-4 Hound" "true"
    generate_3d_patterns "aircraft/Military/tu95_bear/tu95-vhf.ez" "TU-95 Bear" "true"
    
    # Maritime patterns
    log_info "Generating maritime 3D patterns"
    generate_3d_patterns "Marine/ship/containership/containership-loop.ez" "Container Ship" "false"
    generate_3d_patterns "Marine/boat/sailboat_backstay/sailboat-40m.ez" "Sailboat" "false"
    
    log_success "3D pattern generation completed!"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --overwrite)
            OVERWRITE=true
            shift
            ;;
        --jobs)
            JOBS="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run main function
main
