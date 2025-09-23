#!/bin/bash
# generate_leopard1_patterns.sh - Generate all frequency patterns for Leopard 1 NATO MBT

set -e

echo "Generating Leopard 1 NATO MBT Antenna Patterns"
echo "=============================================="
echo ""

# Define frequencies for Leopard 1
# Military frequencies (primary)
military_frequencies=("30.0" "41.5" "50.0" "75.0" "88.0" "225.0" "243.0" "300.0" "400.0")

# Amateur radio frequencies (secondary/emergency use)
amateur_frequencies=("1.8" "3.5" "5.3" "7.0" "10.1" "14.0" "18.1" "21.0" "24.9" "28.0" "50.0")

# Combine all frequencies
all_frequencies=("${military_frequencies[@]}" "${amateur_frequencies[@]}")

# Base EZNEC file
base_eznec="antenna_patterns/military-land/leopard1_nato_mbt/leopard1_nato_mbt.ez"
patterns_dir="antenna_patterns/military-land/leopard1_nato_mbt/leopard1_nato_mbt_patterns"

# Function to generate simple pattern files
generate_simple_pattern() {
    local ez_file="$1"
    local output_file="$2"
    local frequency_mhz="$3"
    
    # Determine if this is a military or amateur frequency
    local freq_type=""
    if [[ " ${military_frequencies[@]} " =~ " ${frequency_mhz} " ]]; then
        freq_type="Military"
    else
        freq_type="Amateur"
    fi
    
    # Create pattern file header
    cat > "$output_file" << EOF
# FGCom-mumble Far-Field Radiation Pattern
# Frequency: ${frequency_mhz} MHz
# Antenna: Leopard 1 NATO MBT - Primary VHF-FM Tactical Whip
# Vehicle: West German Main Battle Tank (NATO standard)
# Height: 2.8m above ground (turret-mounted)
# Ground Plane: Steel armor hull (excellent conductor)
# Type: ${freq_type} frequency
# Format: Theta Phi Gain_dBi H_Polarization V_Polarization
# Theta: Elevation angle (0-180 degrees)
# Phi: Azimuth angle (0-360 degrees)
# Gain: Antenna gain in dBi
# H_Polarization: Horizontal polarization component
# V_Polarization: Vertical polarization component
EOF
    
    # Generate pattern data for tank whip antenna
    for theta in $(seq 0 5 180); do
        for phi in $(seq 0 10 350); do
            # Tank whip antenna pattern calculation
            local gain="0.0"
            
            # Tank whip antennas have good low-angle performance
            if [ $theta -lt 20 ]; then
                gain="4.0"  # Excellent gain at low angles (tactical range)
            elif [ $theta -lt 40 ]; then
                gain="2.0"  # Good gain for medium range
            elif [ $theta -lt 80 ]; then
                gain="0.0"  # Moderate gain
            elif [ $theta -lt 120 ]; then
                gain="-2.0" # Reduced gain
            else
                gain="-4.0" # Poor gain at high angles
            fi
            
            # Add frequency-dependent variation
            # Military VHF frequencies (30-88 MHz) have better performance
            if (( $(echo "$frequency_mhz >= 30.0 && $frequency_mhz <= 88.0" | bc -l) )); then
                gain=$(echo "scale=2; $gain + 1.0" | bc -l)  # Boost for VHF-FM tactical
            elif (( $(echo "$frequency_mhz >= 225.0 && $frequency_mhz <= 400.0" | bc -l) )); then
                gain=$(echo "scale=2; $gain + 0.5" | bc -l)  # Slight boost for UHF
            else
                # Amateur frequencies - standard performance
                local freq_factor=$(echo "scale=2; $frequency_mhz / 41.5" | bc -l)
                gain=$(echo "scale=2; $gain * $freq_factor" | bc -l)
            fi
            
            # Tank whip antennas are primarily vertical polarization
            local h_pol="0.1"  # Minimal horizontal component
            local v_pol="0.9"  # Dominant vertical polarization
            
            # Write pattern data
            echo "$theta $phi $gain $h_pol $v_pol" >> "$output_file"
        done
    done
    
    return 0
}

# Create patterns directory
mkdir -p "$patterns_dir"

# Process each frequency
for freq in "${all_frequencies[@]}"; do
    echo "Processing ${freq} MHz..."
    
    # Create frequency directory
    freq_dir="${patterns_dir}/${freq}mhz"
    mkdir -p "$freq_dir"
    
    # Create frequency-specific EZNEC file
    freq_eznec="${freq_dir}/leopard1_nato_mbt_${freq}MHz.ez"
    
    # Copy base EZNEC and modify frequency
    cp "$base_eznec" "$freq_eznec"
    
    # Update frequency in the EZNEC file
    sed -i "s/FR 0 1 0 0 41.500 0/FR 0 1 0 0 ${freq} 0/" "$freq_eznec"
    
    # Generate pattern file
    pattern_file="${freq_dir}/leopard1_nato_mbt_${freq}MHz_pattern.txt"
    generate_simple_pattern "$freq_eznec" "$pattern_file" "$freq"
    
    echo "  ✓ Generated: $(basename "$freq_eznec")"
    echo "  ✓ Generated: $(basename "$pattern_file")"
done

echo ""
echo "Leopard 1 NATO MBT pattern generation complete!"
echo ""
echo "Generated files:"
echo "EZNEC files: $(find "$patterns_dir" -name "*.ez" -type f | wc -l)"
echo "Pattern files: $(find "$patterns_dir" -name "*_pattern.txt" -type f | wc -l)"
echo ""
echo "Military frequencies: ${#military_frequencies[@]}"
echo "Amateur frequencies: ${#amateur_frequencies[@]}"
echo "Total frequencies: ${#all_frequencies[@]}"
echo ""
echo "Directory structure:"
tree "$patterns_dir" | head -25
