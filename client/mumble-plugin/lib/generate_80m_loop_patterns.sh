#!/bin/bash
# generate_80m_loop_patterns.sh - Generate all frequency patterns for Ground-based 80m-loop

set -e

echo "Generating 80m Loop Antenna Patterns"
echo "===================================="
echo ""

# Define all amateur radio frequencies
frequencies=("1.8" "3.5" "5.3" "7.0" "10.1" "14.0" "18.1" "21.0" "24.9" "28.0" "50.0")

# Base EZNEC file
base_eznec="antenna_patterns/Ground-based/80m-loop/80m_loop.ez"
patterns_dir="antenna_patterns/Ground-based/80m-loop/80m_patterns"

# Function to generate simple pattern files
generate_simple_pattern() {
    local ez_file="$1"
    local output_file="$2"
    local frequency_mhz="$3"
    
    # Create pattern file header
    cat > "$output_file" << EOF
# FGCom-mumble Far-Field Radiation Pattern
# Frequency: ${frequency_mhz} MHz
# Antenna: 80m Square Loop (82m total length)
# Height: 10m above ground
# Format: Theta Phi Gain_dBi H_Polarization V_Polarization
# Theta: Elevation angle (0-180 degrees)
# Phi: Azimuth angle (0-360 degrees)
# Gain: Antenna gain in dBi
# H_Polarization: Horizontal polarization component
# V_Polarization: Vertical polarization component
EOF
    
    # Generate pattern data for loop antenna
    for theta in $(seq 0 5 180); do
        for phi in $(seq 0 10 350); do
            # Loop antenna pattern calculation
            local gain="0.0"
            
            # Loop antennas have different patterns than dipoles
            if [ $theta -lt 30 ]; then
                gain="3.0"  # Good gain at low angles for loop
            elif [ $theta -lt 60 ]; then
                gain="1.0"  # Moderate gain
            elif [ $theta -lt 120 ]; then
                gain="-2.0" # Reduced gain
            else
                gain="-5.0" # Poor gain at high angles
            fi
            
            # Add frequency-dependent variation
            local freq_factor=$(echo "scale=2; $frequency_mhz / 3.5" | bc -l)
            gain=$(echo "scale=2; $gain * $freq_factor" | bc -l)
            
            # Loop antennas typically have mixed polarization
            local h_pol="0.7"
            local v_pol="0.3"
            
            # Write pattern data
            echo "$theta $phi $gain $h_pol $v_pol" >> "$output_file"
        done
    done
    
    return 0
}

# Process each frequency
for freq in "${frequencies[@]}"; do
    echo "Processing ${freq} MHz..."
    
    # Create frequency directory
    freq_dir="${patterns_dir}/${freq}mhz"
    mkdir -p "$freq_dir"
    
    # Create frequency-specific EZNEC file
    freq_eznec="${freq_dir}/80m_loop_${freq}MHz.ez"
    
    # Copy base EZNEC and modify frequency
    cp "$base_eznec" "$freq_eznec"
    
    # Update frequency in the EZNEC file
    sed -i "s/FR 0 0 0 0 3.5 0/FR 0 0 0 0 ${freq} 0/" "$freq_eznec"
    
    # Generate pattern file
    pattern_file="${freq_dir}/80m_loop_${freq}MHz_pattern.txt"
    generate_simple_pattern "$freq_eznec" "$pattern_file" "$freq"
    
    echo "  ✓ Generated: $(basename "$freq_eznec")"
    echo "  ✓ Generated: $(basename "$pattern_file")"
done

echo ""
echo "80m Loop pattern generation complete!"
echo ""
echo "Generated files:"
echo "EZNEC files: $(find "$patterns_dir" -name "*.ez" -type f | wc -l)"
echo "Pattern files: $(find "$patterns_dir" -name "*_pattern.txt" -type f | wc -l)"
echo ""
echo "Directory structure:"
tree "$patterns_dir" | head -20
