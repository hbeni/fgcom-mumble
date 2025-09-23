#!/bin/bash
# generate_t55_patterns.sh - Generate Soviet military frequency patterns for T-55 MBT

set -e

echo "Generating T-55 Soviet MBT Antenna Patterns"
echo "==========================================="
echo ""

# Define Soviet military frequencies only (no amateur radio!)
# Soviet VHF-FM tactical frequencies (R-123M system)
soviet_vhf_frequencies=("20.0" "25.0" "30.0" "36.0" "42.0" "48.0" "52.0")

# Soviet HF frequencies (R-130 system for higher command)
soviet_hf_frequencies=("3.0" "5.0" "7.0" "10.0" "12.0" "15.0" "18.0")

# Combine all Soviet military frequencies
all_frequencies=("${soviet_vhf_frequencies[@]}" "${soviet_hf_frequencies[@]}")

# Base EZNEC file
base_eznec="antenna_patterns/military-land/t55_soviet_mbt/t55_soviet_mbt.ez"
patterns_dir="antenna_patterns/military-land/t55_soviet_mbt/t55_soviet_mbt_patterns"

# Function to generate simple pattern files
generate_simple_pattern() {
    local ez_file="$1"
    local output_file="$2"
    local frequency_mhz="$3"
    
    # Determine if this is VHF or HF frequency
    local freq_type=""
    if [[ " ${soviet_vhf_frequencies[@]} " =~ " ${frequency_mhz} " ]]; then
        freq_type="Soviet VHF-FM Tactical (R-123M)"
    else
        freq_type="Soviet HF Command (R-130)"
    fi
    
    # Create pattern file header
    cat > "$output_file" << EOF
# FGCom-mumble Far-Field Radiation Pattern
# Frequency: ${frequency_mhz} MHz
# Antenna: T-55 Soviet MBT - Primary VHF-FM R-123M Tactical Whip
# Vehicle: Soviet Main Battle Tank (Warsaw Pact standard)
# Height: 2.5m above ground (turret-mounted)
# Ground Plane: Steel armor hull (Soviet grade steel)
# Type: ${freq_type}
# Format: Theta Phi Gain_dBi H_Polarization V_Polarization
# Theta: Elevation angle (0-180 degrees)
# Phi: Azimuth angle (0-360 degrees)
# Gain: Antenna gain in dBi
# H_Polarization: Horizontal polarization component
# V_Polarization: Vertical polarization component
EOF
    
    # Generate pattern data for Soviet tank whip antenna
    for theta in $(seq 0 5 180); do
        for phi in $(seq 0 10 350); do
            # Soviet tank whip antenna pattern calculation
            local gain="0.0"
            
            # Soviet whip antennas - simpler but effective
            if [ $theta -lt 25 ]; then
                gain="3.5"  # Good gain at low angles (Soviet tactical range)
            elif [ $theta -lt 45 ]; then
                gain="1.5"  # Moderate gain for medium range
            elif [ $theta -lt 85 ]; then
                gain="0.0"  # Average gain
            elif [ $theta -lt 125 ]; then
                gain="-1.5" # Reduced gain
            else
                gain="-3.5" # Poor gain at high angles
            fi
            
            # Add frequency-dependent variation
            # Soviet VHF frequencies (20-52 MHz) have good performance
            if [[ " ${soviet_vhf_frequencies[@]} " =~ " ${frequency_mhz} " ]]; then
                # VHF-FM tactical frequencies - optimized for Soviet doctrine
                gain=$(echo "scale=2; $gain + 0.5" | bc -l)  # Boost for VHF-FM
            else
                # HF frequencies - standard performance
                local freq_factor=$(echo "scale=2; $frequency_mhz / 36.0" | bc -l)
                gain=$(echo "scale=2; $gain * $freq_factor" | bc -l)
            fi
            
            # Soviet whip antennas are primarily vertical polarization
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
    freq_eznec="${freq_dir}/t55_soviet_mbt_${freq}MHz.ez"
    
    # Copy base EZNEC and modify frequency
    cp "$base_eznec" "$freq_eznec"
    
    # Update frequency in the EZNEC file
    sed -i "s/FR 0 1 0 0 36.000 0/FR 0 1 0 0 ${freq} 0/" "$freq_eznec"
    
    # Generate pattern file
    pattern_file="${freq_dir}/t55_soviet_mbt_${freq}MHz_pattern.txt"
    generate_simple_pattern "$freq_eznec" "$pattern_file" "$freq"
    
    echo "  ✓ Generated: $(basename "$freq_eznec")"
    echo "  ✓ Generated: $(basename "$pattern_file")"
done

echo ""
echo "T-55 Soviet MBT pattern generation complete!"
echo ""
echo "Generated files:"
echo "EZNEC files: $(find "$patterns_dir" -name "*.ez" -type f | wc -l)"
echo "Pattern files: $(find "$patterns_dir" -name "*_pattern.txt" -type f | wc -l)"
echo ""
echo "Soviet VHF-FM frequencies: ${#soviet_vhf_frequencies[@]}"
echo "Soviet HF frequencies: ${#soviet_hf_frequencies[@]}"
echo "Total Soviet military frequencies: ${#all_frequencies[@]}"
echo ""
echo "Directory structure:"
tree "$patterns_dir" | head -25
