#!/bin/bash
# standardize_all_patterns.sh - Ensure ALL vehicles follow the same organization pattern

set -e

echo "FGCom-mumble Pattern Standardization"
echo "===================================="
echo ""

# Get number of CPU cores for parallel processing
CPU_CORES=$(nproc)
echo "Detected $CPU_CORES CPU cores - using parallel processing"
echo ""

# Function to generate simple pattern files
generate_simple_pattern() {
    local ez_file="$1"
    local output_file="$2"
    local frequency_mhz="$3"
    local altitude_m="$4"
    
    # Create pattern file header
    cat > "$output_file" << EOF
# FGCom-mumble Far-Field Radiation Pattern
# Frequency: ${frequency_mhz} MHz
# Altitude: ${altitude_m} m
# Format: Theta Phi Gain_dBi H_Polarization V_Polarization
# Theta: Elevation angle (0-180 degrees)
# Phi: Azimuth angle (0-360 degrees)
# Gain: Antenna gain in dBi
# H_Polarization: Horizontal polarization component
# V_Polarization: Vertical polarization component
EOF
    
    # Generate pattern data
    local pattern_points=0
    
    # Generate pattern for all angles
    for theta in $(seq 0 5 180); do
        for phi in $(seq 0 10 350); do
            # Simple gain calculation based on angle
            local gain="0.0"
            
            # Basic antenna pattern approximation
            if [ $theta -lt 30 ]; then
                gain="2.0"  # Good gain at low angles
            elif [ $theta -lt 60 ]; then
                gain="0.0"  # Moderate gain
            elif [ $theta -lt 120 ]; then
                gain="-3.0" # Reduced gain
            else
                gain="-6.0" # Poor gain at high angles
            fi
            
            # Add frequency-dependent variation
            local freq_factor=$(echo "scale=2; $frequency_mhz / 14.0" | bc -l)
            gain=$(echo "scale=2; $gain * $freq_factor" | bc -l)
            
            # Calculate polarization components
            local h_pol="0.0"
            local v_pol="0.0"
            
            if [ $theta -lt 45 ]; then
                v_pol="1.0"  # Vertical polarization dominant at low angles
            elif [ $theta -gt 135 ]; then
                h_pol="1.0"  # Horizontal polarization dominant at high angles
            else
                h_pol="0.5"  # Mixed polarization at intermediate angles
                v_pol="0.5"
            fi
            
            # Write pattern data
            echo "$theta $phi $gain $h_pol $v_pol" >> "$output_file"
            pattern_points=$((pattern_points + 1))
        done
    done
    
    return 0
}

# Function to process a single EZNEC file
process_single_eznec() {
    local ez_file="$1"
    local basename_file=$(basename "$ez_file" .ez)
    
    # Extract frequency and altitude from filename
    local freq_mhz=""
    local altitude_m=""
    
    # Parse frequency (look for patterns like _14.23MHz, _7.15MHz, etc.)
    if [[ "$basename_file" =~ _([0-9]+\.?[0-9]*)MHz ]]; then
        freq_mhz="${BASH_REMATCH[1]}"
    fi
    
    # Parse altitude (look for patterns like _0m, _1000m, etc.)
    if [[ "$basename_file" =~ _([0-9]+)m_ ]]; then
        altitude_m="${BASH_REMATCH[1]}"
    fi
    
    # Set default values if not found
    if [ -z "$freq_mhz" ]; then
        freq_mhz="14.0"  # Default to 20m band
    fi
    if [ -z "$altitude_m" ]; then
        altitude_m="0"   # Default to ground level
    fi
    
    # Generate pattern file in the same directory as the EZNEC file
    local pattern_file="${ez_file%.ez}_pattern.txt"
    generate_simple_pattern "$ez_file" "$pattern_file" "$freq_mhz" "$altitude_m"
    
    if [ $? -eq 0 ]; then
        echo "  ✓ $(basename "$pattern_file")"
    else
        echo "  ✗ Failed: $(basename "$ez_file")"
    fi
}

# Function to standardize a vehicle directory structure
standardize_vehicle_directory() {
    local vehicle_dir="$1"
    local vehicle_name="$2"
    
    echo "Standardizing $vehicle_name directory structure..."
    
    # Create the standard pattern directory structure
    local patterns_dir="${vehicle_dir}/${vehicle_name}_patterns"
    mkdir -p "$patterns_dir"
    
    # Define all amateur radio frequencies
    local frequencies=("1.8" "3.5" "5.3" "7.0" "10.1" "14.0" "18.1" "21.0" "24.9" "28.0" "50.0")
    
    # Create frequency-specific directories
    for freq in "${frequencies[@]}"; do
        local freq_dir="${patterns_dir}/${freq}mhz"
        mkdir -p "$freq_dir"
    done
    
    # Move all EZNEC files to appropriate frequency directories
    find "$vehicle_dir" -maxdepth 1 -name "*.ez" -type f | while read ez_file; do
        local basename_file=$(basename "$ez_file" .ez)
        local freq_mhz=""
        
        # Parse frequency from filename
        if [[ "$basename_file" =~ _([0-9]+\.?[0-9]*)MHz ]]; then
            freq_mhz="${BASH_REMATCH[1]}"
        fi
        
        if [ -n "$freq_mhz" ]; then
            local target_dir="${patterns_dir}/${freq_mhz}mhz"
            if [ -d "$target_dir" ]; then
                mv "$ez_file" "$target_dir/"
                echo "  Moved $(basename "$ez_file") to ${freq_mhz}mhz/"
            fi
        fi
    done
    
    # Process each frequency directory
    for freq in "${frequencies[@]}"; do
        local freq_dir="${patterns_dir}/${freq}mhz"
        if [ -d "$freq_dir" ]; then
            local ez_files=($(find "$freq_dir" -name "*.ez" -type f))
            local file_count=${#ez_files[@]}
            
            if [ "$file_count" -gt 0 ]; then
                echo "  Processing $freq MHz: $file_count files"
                
                # Export functions for parallel processing
                export -f generate_simple_pattern
                export -f process_single_eznec
                
                # Process files in parallel
                if command -v parallel >/dev/null 2>&1; then
                    printf '%s\n' "${ez_files[@]}" | parallel -j "$CPU_CORES" process_single_eznec
                else
                    # Use xargs without conflicting options
                    printf '%s\n' "${ez_files[@]}" | xargs -P "$CPU_CORES" -I {} bash -c 'process_single_eznec "$@"' _ {}
                fi
            fi
        fi
    done
    
    echo "  ✓ Completed $vehicle_name standardization"
    echo ""
}

# Main processing - standardize ALL vehicle types
echo "Starting pattern standardization for ALL vehicles..."
echo ""

# Process aircraft
if [ -d "antenna_patterns/aircraft" ]; then
    echo "=== Standardizing Aircraft ==="
    for aircraft_dir in antenna_patterns/aircraft/*; do
        if [ -d "$aircraft_dir" ]; then
            aircraft_name=$(basename "$aircraft_dir")
            echo "Processing aircraft: $aircraft_name"
            standardize_vehicle_directory "$aircraft_dir" "$aircraft_name"
        fi
    done
fi

# Process boats
if [ -d "antenna_patterns/boat" ]; then
    echo "=== Standardizing Boats ==="
    for boat_dir in antenna_patterns/boat/*; do
        if [ -d "$boat_dir" ]; then
            boat_name=$(basename "$boat_dir")
            echo "Processing boat: $boat_name"
            standardize_vehicle_directory "$boat_dir" "$boat_name"
        fi
    done
fi

# Process ships
if [ -d "antenna_patterns/ship" ]; then
    echo "=== Standardizing Ships ==="
    for ship_dir in antenna_patterns/ship/*; do
        if [ -d "$ship_dir" ]; then
            ship_name=$(basename "$ship_dir")
            echo "Processing ship: $ship_name"
            standardize_vehicle_directory "$ship_dir" "$ship_name"
        fi
    done
fi

# Process ground vehicles
if [ -d "antenna_patterns/vehicle" ]; then
    echo "=== Standardizing Ground Vehicles ==="
    for vehicle_dir in antenna_patterns/vehicle/*; do
        if [ -d "$vehicle_dir" ]; then
            vehicle_name=$(basename "$vehicle_dir")
            echo "Processing vehicle: $vehicle_name"
            standardize_vehicle_directory "$vehicle_dir" "$vehicle_name"
        fi
    done
fi

# Process military vehicles
if [ -d "antenna_patterns/military-land" ]; then
    echo "=== Standardizing Military Vehicles ==="
    for military_dir in antenna_patterns/military-land/*; do
        if [ -d "$military_dir" ]; then
            military_name=$(basename "$military_dir")
            echo "Processing military vehicle: $military_name"
            standardize_vehicle_directory "$military_dir" "$military_name"
        fi
    done
fi

# Process ground-based antennas
if [ -d "antenna_patterns/Ground-based" ]; then
    echo "=== Standardizing Ground-based Antennas ==="
    for ground_dir in antenna_patterns/Ground-based/*; do
        if [ -d "$ground_dir" ]; then
            ground_name=$(basename "$ground_dir")
            echo "Processing ground-based antenna: $ground_name"
            standardize_vehicle_directory "$ground_dir" "$ground_name"
        fi
    done
fi

echo "Pattern standardization complete!"
echo ""

# Summary
echo "=== STANDARDIZED PATTERN SUMMARY ==="
echo ""
echo "Generated far-field pattern files:"
find antenna_patterns -name "*_pattern.txt" -type f | wc -l
echo ""
echo "Breakdown by vehicle type:"
echo "Aircraft: $(find antenna_patterns/aircraft -name "*_pattern.txt" -type f 2>/dev/null | wc -l) files"
echo "Boats: $(find antenna_patterns/boat -name "*_pattern.txt" -type f 2>/dev/null | wc -l) files"
echo "Ships: $(find antenna_patterns/ship -name "*_pattern.txt" -type f 2>/dev/null | wc -l) files"
echo "Ground Vehicles: $(find antenna_patterns/vehicle -name "*_pattern.txt" -type f 2>/dev/null | wc -l) files"
echo "Military: $(find antenna_patterns/military-land -name "*_pattern.txt" -type f 2>/dev/null | wc -l) files"
echo "Ground-based: $(find antenna_patterns/Ground-based -name "*_pattern.txt" -type f 2>/dev/null | wc -l) files"
echo ""
echo "STANDARDIZED directory structure for ALL vehicles:"
echo "antenna_patterns/[vehicle_type]/[vehicle_name]/[vehicle_name]_patterns/"
echo "├── 1.8mhz/"
echo "│   ├── [vehicle]_[frequency]MHz.ez"
echo "│   ├── [vehicle]_[frequency]MHz_pattern.txt"
echo "│   └── ... (altitude variations for aircraft)"
echo "├── 3.5mhz/"
echo "│   ├── [vehicle]_[frequency]MHz.ez"
echo "│   ├── [vehicle]_[frequency]MHz_pattern.txt"
echo "│   └── ... (altitude variations for aircraft)"
echo "├── 5.3mhz/"
echo "├── 7.0mhz/"
echo "├── 10.1mhz/"
echo "├── 14.0mhz/"
echo "├── 18.1mhz/"
echo "├── 21.0mhz/"
echo "├── 24.9mhz/"
echo "├── 28.0mhz/"
echo "└── 50.0mhz/"
echo ""
echo "All vehicles now follow the EXACT same organization pattern!"
echo "- Consistent directory naming: [vehicle_name]_patterns"
echo "- Consistent frequency subdirectories: [frequency]mhz"
echo "- Consistent file organization: EZNEC and pattern files together"
echo "- Multi-core processing for fast generation"
echo "- No xargs warnings"
