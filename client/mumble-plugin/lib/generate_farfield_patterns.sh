#!/bin/bash
# generate_farfield_patterns.sh - Generate far-field pattern files from EZNEC files

set -e

echo "FGCom-mumble Far-Field Pattern Generator"
echo "========================================"
echo ""

# Function to process EZNEC files and generate far-field patterns
process_eznec_to_farfield() {
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
        
        # Convert EZNEC to NEC2 format
        local nec_file="${output_dir}/${basename_file}.nec"
        ./eznec2nec.sh "$ez_file" "$nec_file"
        
        if [ $? -ne 0 ]; then
            echo "  ✗ Failed to convert EZNEC to NEC2"
            continue
        fi
        
        # Run nec2c to generate far-field pattern
        local out_file="${output_dir}/${basename_file}.out"
        nec2c "$nec_file" > "$out_file" 2>/dev/null
        
        if [ $? -ne 0 ]; then
            echo "  ✗ Failed to generate far-field pattern"
            continue
        fi
        
        # Extract and format radiation pattern data
        local pattern_file="${output_dir}/${basename_file}_pattern.txt"
        source ./extract_pattern_advanced.sh
        extract_radiation_pattern_advanced "$out_file" "$pattern_file" "$freq_mhz" "$altitude_m"
        
        if [ $? -eq 0 ]; then
            echo "  ✓ Generated far-field pattern: $(basename "$pattern_file")"
        else
            echo "  ✗ Failed to extract radiation pattern"
        fi
        
        # Clean up intermediate files
        rm -f "$nec_file" "$out_file"
        
        echo ""
    done
    
    echo "Completed $vehicle_type: $processed files processed"
    echo ""
}

# Function to extract radiation pattern data from nec2c output
extract_radiation_pattern() {
    local nec2c_output="$1"
    local pattern_file="$2"
    local frequency_mhz="$3"
    local altitude_m="$4"
    
    # Create pattern file header
    cat > "$pattern_file" << EOF
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
    
    # Extract radiation pattern data from nec2c output
    # Look for the radiation pattern section in the output
    local in_pattern=false
    local theta_phi_found=false
    
    while IFS= read -r line; do
        # Check if we're in the radiation pattern section
        if [[ "$line" =~ "RADIATION PATTERN" ]] || [[ "$line" =~ "FAR FIELD" ]]; then
            in_pattern=true
            continue
        fi
        
        # Skip header lines
        if [ "$in_pattern" = true ] && [[ "$line" =~ "THETA" ]] && [[ "$line" =~ "PHI" ]]; then
            theta_phi_found=true
            continue
        fi
        
        # Extract pattern data lines
        if [ "$in_pattern" = true ] && [ "$theta_phi_found" = true ]; then
            # Skip empty lines and section headers
            if [[ -z "$line" ]] || [[ "$line" =~ "^[[:space:]]*$" ]] || [[ "$line" =~ "^-" ]]; then
                continue
            fi
            
            # Parse the radiation pattern line
            # Expected format: Theta Phi Gain_dBi (and possibly polarization data)
            if [[ "$line" =~ ^[[:space:]]*([0-9]+\.?[0-9]*)[[:space:]]+([0-9]+\.?[0-9]*)[[:space:]]+([+-]?[0-9]+\.?[0-9]*)[[:space:]]* ]]; then
                local theta="${BASH_REMATCH[1]}"
                local phi="${BASH_REMATCH[2]}"
                local gain="${BASH_REMATCH[3]}"
                
                # For now, set polarization components to 0 (can be enhanced later)
                local h_pol="0.0"
                local v_pol="0.0"
                
                # Write pattern data
                echo "$theta $phi $gain $h_pol $v_pol" >> "$pattern_file"
            fi
        fi
        
        # Stop if we hit another section
        if [ "$in_pattern" = true ] && [[ "$line" =~ "^[[:space:]]*[A-Z]" ]] && [[ ! "$line" =~ "THETA" ]] && [[ ! "$line" =~ "PHI" ]]; then
            break
        fi
    done < "$nec2c_output"
    
    # Check if we got any pattern data
    local pattern_lines=$(grep -v "^#" "$pattern_file" | wc -l)
    if [ "$pattern_lines" -eq 0 ]; then
        echo "Warning: No radiation pattern data found in nec2c output"
        return 1
    fi
    
    echo "Extracted $pattern_lines radiation pattern points"
    return 0
}

# Main processing
echo "Starting far-field pattern generation..."
echo ""

# Process aircraft patterns
if [ -d "antenna_patterns/aircraft" ]; then
    process_eznec_to_farfield "antenna_patterns/aircraft" "farfield_patterns/aircraft" "Aircraft"
fi

# Process boat patterns
if [ -d "antenna_patterns/boat" ]; then
    process_eznec_to_farfield "antenna_patterns/boat" "farfield_patterns/boat" "Boats"
fi

# Process ship patterns
if [ -d "antenna_patterns/ship" ]; then
    process_eznec_to_farfield "antenna_patterns/ship" "farfield_patterns/ship" "Ships"
fi

# Process vehicle patterns
if [ -d "antenna_patterns/vehicle" ]; then
    process_eznec_to_farfield "antenna_patterns/vehicle" "farfield_patterns/vehicle" "Ground Vehicles"
fi

# Process military patterns
if [ -d "antenna_patterns/military-land" ]; then
    process_eznec_to_farfield "antenna_patterns/military-land" "farfield_patterns/military" "Military Vehicles"
fi

# Process ground-based patterns
if [ -d "antenna_patterns/Ground-based" ]; then
    process_eznec_to_farfield "antenna_patterns/Ground-based" "farfield_patterns/ground-based" "Ground-based Antennas"
fi

echo "Far-field pattern generation complete!"
echo ""

# Summary
echo "=== FAR-FIELD PATTERN SUMMARY ==="
echo ""
echo "Generated far-field pattern files:"
find farfield_patterns -name "*_pattern.txt" -type f | wc -l
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
echo "Next steps:"
echo "1. Integrate pattern files with FGCom_PatternInterpolator"
echo "2. Implement real-time pattern lookup in propagation engine"
echo "3. Add polarization-specific signal calculations"
echo "4. Optimize pattern loading and caching"
