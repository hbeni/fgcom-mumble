#!/bin/bash
# generate_simple_patterns.sh - Generate simple far-field pattern files

set -e

echo "FGCom-mumble Simple Far-Field Pattern Generator"
echo "=============================================="
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
    
    echo "Generated $pattern_points radiation pattern points"
    return 0
}

# Function to process all EZNEC files
process_all_patterns() {
    local input_dir="$1"
    local output_dir="$2"
    local vehicle_type="$3"
    
    echo "Processing $vehicle_type patterns..."
    echo "Input: $input_dir"
    echo "Output: $output_dir"
    echo ""
    
    # Create output directory
    mkdir -p "$output_dir"
    
    # Find all EZNEC files
    local ez_files=$(find "$input_dir" -name "*.ez" -type f)
    local total_files=$(echo "$ez_files" | wc -l)
    local processed=0
    
    echo "Found $total_files EZNEC files to process"
    echo ""
    
    # Process each EZNEC file
    for ez_file in $ez_files; do
        processed=$((processed + 1))
        echo "[$processed/$total_files] Processing: $(basename "$ez_file")"
        
        # Extract frequency and altitude from filename
        local basename_file=$(basename "$ez_file" .ez)
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
        
        echo "  Frequency: ${freq_mhz}MHz, Altitude: ${altitude_m}m"
        
        # Generate pattern file
        local pattern_file="${output_dir}/${basename_file}_pattern.txt"
        generate_simple_pattern "$ez_file" "$pattern_file" "$freq_mhz" "$altitude_m"
        
        if [ $? -eq 0 ]; then
            echo "  ✓ Generated far-field pattern: $(basename "$pattern_file")"
        else
            echo "  ✗ Failed to generate pattern"
        fi
        
        echo ""
    done
    
    echo "Completed $vehicle_type: $processed files processed"
    echo ""
}

# Main processing
echo "Starting simple far-field pattern generation..."
echo ""

# Process aircraft patterns
if [ -d "antenna_patterns/aircraft" ]; then
    process_all_patterns "antenna_patterns/aircraft" "farfield_patterns/aircraft" "Aircraft"
fi

# Process boat patterns
if [ -d "antenna_patterns/boat" ]; then
    process_all_patterns "antenna_patterns/boat" "farfield_patterns/boat" "Boats"
fi

# Process ship patterns
if [ -d "antenna_patterns/ship" ]; then
    process_all_patterns "antenna_patterns/ship" "farfield_patterns/ship" "Ships"
fi

# Process vehicle patterns
if [ -d "antenna_patterns/vehicle" ]; then
    process_all_patterns "antenna_patterns/vehicle" "farfield_patterns/vehicle" "Ground Vehicles"
fi

# Process military patterns
if [ -d "antenna_patterns/military-land" ]; then
    process_all_patterns "antenna_patterns/military-land" "farfield_patterns/military" "Military Vehicles"
fi

# Process ground-based patterns
if [ -d "antenna_patterns/Ground-based" ]; then
    process_all_patterns "antenna_patterns/Ground-based" "farfield_patterns/ground-based" "Ground-based Antennas"
fi

echo "Simple far-field pattern generation complete!"
echo ""

# Summary
echo "=== FAR-FIELD PATTERN SUMMARY ==="
echo ""
echo "Generated far-field pattern files:"
find farfield_patterns -name "*_pattern.txt" -type f 2>/dev/null | wc -l
echo ""
echo "Breakdown by vehicle type:"
echo "Aircraft: $(find farfield_patterns/aircraft -name "*_pattern.txt" -type f 2>/dev/null | wc -l) files"
echo "Boats: $(find farfield_patterns/boat -name "*_pattern.txt" -type f 2>/dev/null | wc -l) files"
echo "Ships: $(find farfield_patterns/ship -name "*_pattern.txt" -type f 2>/dev/null | wc -l) files"
echo "Ground Vehicles: $(find farfield_patterns/vehicle -name "*_pattern.txt" -type f 2>/dev/null | wc -l) files"
echo "Military: $(find farfield_patterns/military -name "*_pattern.txt" -type f 2>/dev/null | wc -l) files"
echo "Ground-based: $(find farfield_patterns/ground-based -name "*_pattern.txt" -type f 2>/dev/null | wc -l) files"
echo ""
echo "Pattern file format:"
echo "- Theta/Phi coordinates (spherical coordinates)"
echo "- Gain values in dBi with frequency information"
echo "- Polarization components (vertical/horizontal)"
echo "- ASCII format for easy parsing"
echo ""
echo "Each pattern file contains:"
echo "- 1,332 radiation pattern points (37 theta × 36 phi)"
echo "- 5-degree theta resolution (0-180 degrees)"
echo "- 10-degree phi resolution (0-350 degrees)"
echo "- Frequency and altitude metadata"
echo "- Polarization component data"
echo ""
echo "Next steps:"
echo "1. Integrate pattern files with FGCom_PatternInterpolator"
echo "2. Implement real-time pattern lookup in propagation engine"
echo "3. Add polarization-specific signal calculations"
echo "4. Optimize pattern loading and caching"
