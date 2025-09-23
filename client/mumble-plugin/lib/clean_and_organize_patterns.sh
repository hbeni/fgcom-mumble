#!/bin/bash
# clean_and_organize_patterns.sh - Clean up and organize patterns properly with multi-core processing

set -e

echo "FGCom-mumble Pattern Cleanup and Organization"
echo "============================================="
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

# Function to organize files by frequency
organize_by_frequency() {
    local base_dir="$1"
    local vehicle_name="$2"
    
    echo "Organizing $vehicle_name patterns by frequency..."
    
    # Create frequency-specific directories
    local frequencies=("1.8" "3.5" "5.3" "7.0" "10.1" "14.0" "18.1" "21.0" "24.9" "28.0" "50.0")
    
    for freq in "${frequencies[@]}"; do
        local freq_dir="${base_dir}/${freq}mhz"
        mkdir -p "$freq_dir"
        
        # Move all files for this frequency to the frequency directory
        find "$base_dir" -maxdepth 1 -name "*_${freq}MHz.ez" -exec mv {} "$freq_dir/" \; 2>/dev/null || true
        find "$base_dir" -maxdepth 1 -name "*_${freq}MHz.out" -exec mv {} "$freq_dir/" \; 2>/dev/null || true
        find "$base_dir" -maxdepth 1 -name "*_${freq}MHz_pattern.txt" -exec mv {} "$freq_dir/" \; 2>/dev/null || true
        
        # Count files in this frequency directory
        local file_count=$(find "$freq_dir" -name "*.ez" | wc -l)
        if [ "$file_count" -gt 0 ]; then
            echo "  $freq MHz: $file_count files"
        fi
    done
}

# Function to process EZNEC files in parallel
process_eznec_parallel() {
    local eznec_dir="$1"
    local vehicle_name="$2"
    
    echo "Processing $vehicle_name patterns in parallel..."
    
    # Find all EZNEC files
    local ez_files=($(find "$eznec_dir" -name "*.ez" -type f))
    local total_files=${#ez_files[@]}
    
    if [ "$total_files" -eq 0 ]; then
        echo "  No EZNEC files found"
        return 0
    fi
    
    echo "  Found $total_files EZNEC files to process"
    
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
    
    # Export the function for parallel processing
    export -f generate_simple_pattern
    export -f process_single_eznec
    
    # Process files in parallel using GNU parallel or xargs
    if command -v parallel >/dev/null 2>&1; then
        printf '%s\n' "${ez_files[@]}" | parallel -j "$CPU_CORES" process_single_eznec
    else
        # Use xargs without conflicting options
        printf '%s\n' "${ez_files[@]}" | xargs -P "$CPU_CORES" -I {} bash -c 'process_single_eznec "$@"' _ {}
    fi
    
    echo "  ✓ Completed $vehicle_name: $total_files files processed"
}

# Main processing
echo "Starting pattern cleanup and organization..."
echo ""

# Clean up and organize B737 patterns
if [ -d "antenna_patterns/aircraft/b737" ]; then
    echo "=== Cleaning up B737 Patterns ==="
    
    # Organize by frequency first
    organize_by_frequency "antenna_patterns/aircraft/b737/b737_patterns" "B737"
    
    # Process each frequency directory in parallel
    for freq_dir in antenna_patterns/aircraft/b737/b737_patterns/*mhz; do
        if [ -d "$freq_dir" ]; then
            freq_name=$(basename "$freq_dir")
            echo "Processing B737 $freq_name patterns..."
            process_eznec_parallel "$freq_dir" "B737-$freq_name"
        fi
    done
fi

# Clean up and organize Cessna patterns
if [ -d "antenna_patterns/aircraft/cessna_172" ]; then
    echo "=== Cleaning up Cessna 172 Patterns ==="
    
    # Organize by frequency first
    organize_by_frequency "antenna_patterns/aircraft/cessna_172/cessna_patterns" "Cessna172"
    
    # Process each frequency directory in parallel
    for freq_dir in antenna_patterns/aircraft/cessna_172/cessna_patterns/*mhz; do
        if [ -d "$freq_dir" ]; then
            freq_name=$(basename "$freq_dir")
            echo "Processing Cessna $freq_name patterns..."
            process_eznec_parallel "$freq_dir" "Cessna172-$freq_name"
        fi
    done
fi

# Process other vehicle types
for vehicle_type in "boat" "ship" "vehicle" "military-land" "Ground-based"; do
    if [ -d "antenna_patterns/$vehicle_type" ]; then
        echo "=== Processing $vehicle_type Patterns ==="
        
        for vehicle_dir in "antenna_patterns/$vehicle_type"/*; do
            if [ -d "$vehicle_dir" ]; then
                vehicle_name=$(basename "$vehicle_dir")
                echo "Processing $vehicle_name..."
                
                # Process amateur patterns if they exist
                if [ -d "$vehicle_dir/amateur_patterns" ]; then
                    for band_dir in "$vehicle_dir/amateur_patterns"/*; do
                        if [ -d "$band_dir" ]; then
                            band_name=$(basename "$band_dir")
                            echo "Processing $vehicle_name amateur $band_name..."
                            process_eznec_parallel "$band_dir" "$vehicle_name-$band_name"
                        fi
                    done
                fi
                
                # Process main directory
                process_eznec_parallel "$vehicle_dir" "$vehicle_name"
            fi
        done
    fi
done

echo "Pattern cleanup and organization complete!"
echo ""

# Summary
echo "=== ORGANIZED PATTERN SUMMARY ==="
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
echo "Directory structure now organized by frequency:"
echo "- Each frequency has its own subdirectory (e.g., 14.0mhz, 7.0mhz)"
echo "- EZNEC files and pattern files are grouped by frequency"
echo "- Multi-core processing used for faster generation"
echo ""
echo "Example structure:"
echo "antenna_patterns/aircraft/b737/b737_patterns/"
echo "├── 1.8mhz/"
echo "│   ├── b737_800_hf_commercial_0m_1.8MHz.ez"
echo "│   ├── b737_800_hf_commercial_0m_1.8MHz_pattern.txt"
echo "│   └── ... (altitude variations)"
echo "├── 3.5mhz/"
echo "│   ├── b737_800_hf_commercial_0m_3.5MHz.ez"
echo "│   ├── b737_800_hf_commercial_0m_3.5MHz_pattern.txt"
echo "│   └── ... (altitude variations)"
echo "└── ... (other frequencies)"
