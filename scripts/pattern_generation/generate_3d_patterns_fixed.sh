#!/bin/bash

# Fixed 3D Pattern Generation Script
# This script generates 3D attitude patterns for aircraft and maritime vehicles

set -e

# Configuration
BASE_DIR="client/mumble-plugin/lib/antenna_patterns"
UTILITIES_DIR="scripts/utilities"
JOBS=4
OVERWRITE=false

# Attitude angles (simplified for now - just key angles)
AIRCRAFT_ROLL_ANGLES=(-90 -45 0 45 90)
AIRCRAFT_PITCH_ANGLES=(-90 -45 0 45 90)
MARITIME_ROLL_ANGLES=(-60 -30 0 30 60)
MARITIME_PITCH_ANGLES=(-60 -30 0 30 60)

# Altitude intervals
ALL_ALTITUDES=(0 100 500 1000 2000 3000 5000 8000 10000)

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
                
                # For now, just copy the base pattern and add attitude info
                # This is a simplified approach - in a full implementation,
                # you would apply geometric transformations to the antenna model
                local base_pattern="$BASE_DIR/patterns/${freq}mhz/${base_name}_${freq}MHz_${alt}m_pattern.txt"
                
                if [ -f "$base_pattern" ]; then
                    # Copy base pattern and add attitude header
                    echo "# 3D Attitude Pattern: roll=${roll}°, pitch=${pitch}°" > "$pattern_file"
                    echo "# Base pattern: $base_pattern" >> "$pattern_file"
                    cat "$base_pattern" >> "$pattern_file"
                    log_success "Generated: $pattern_file"
                else
                    log_error "Base pattern not found: $base_pattern"
                fi
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
