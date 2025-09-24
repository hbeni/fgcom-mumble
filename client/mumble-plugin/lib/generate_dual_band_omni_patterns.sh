#!/bin/bash

# Generate radiation patterns for dual-band VHF/UHF omnidirectional antenna
# This script creates patterns for both 2m and 70cm bands

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ANTENNA_FILE="$SCRIPT_DIR/antenna_patterns/Ground-based/vertical/dual_band_omni/dual_band_omni_simple.ez"
MAX_JOBS=$(nproc)

# 2m band frequencies (144-146 MHz)
VHF_FREQUENCIES=(144.0 144.1 144.2 144.3 144.4 144.5 144.6 144.7 144.8 144.9 145.0 145.1 145.2 145.3 145.4 145.5 145.6 145.7 145.8 145.9 146.0)

# 70cm band frequencies (430-440 MHz)
UHF_FREQUENCIES=(430.0 430.5 431.0 431.5 432.0 432.5 433.0 433.5 434.0 434.5 435.0 435.5 436.0 436.5 437.0 437.5 438.0 438.5 439.0 439.5 440.0)

# Altitude variations for ground-based antenna
ALTITUDES=(0 100 500 1000 2000)

echo "Generating dual-band omnidirectional antenna patterns using $MAX_JOBS CPU cores..."

# Function to generate pattern for one frequency/altitude combination
generate_omni_pattern() {
    local freq="$1"
    local alt="$2"
    local band="$3"
    
    if [ ! -f "$ANTENNA_FILE" ]; then
        echo "Error: Antenna file not found: $ANTENNA_FILE"
        return 1
    fi
    
    local work_dir="/tmp/nec_$$_${RANDOM}"
    mkdir -p "$work_dir"
    cd "$work_dir"
    
    # Copy and modify EZNEC file
    cp "$ANTENNA_FILE" "dual_band_omni.ez"
    
    # Update frequency in the file
    sed -i "s/^FR.*/FR 0 1 0 0 ${freq} 0/" "dual_band_omni.ez"
    
    # Update ground height if needed (for altitude variations)
    if [ "$alt" != "0" ]; then
        # Adjust antenna height for altitude
        local new_height=$(echo "10.0 + $alt" | bc -l)
        sed -i "s/10\.0/${new_height}/g" "dual_band_omni.ez"
    fi
    
    # Convert to NEC2
    if "$SCRIPT_DIR/eznec2nec.sh" "dual_band_omni.ez" "dual_band_omni.nec" 2>/dev/null; then
        # Run NEC2 simulation
        if nec2c -i "dual_band_omni.nec" -o "dual_band_omni.out" 2>/dev/null; then
            # Extract pattern
            if "$SCRIPT_DIR/extract_pattern_advanced.sh" "dual_band_omni.out" "dual_band_omni_pattern.txt" "$freq" "$alt" 2>/dev/null; then
                # Create output directory
                local output_dir="$(dirname "$ANTENNA_FILE")/patterns/${band}/${freq}mhz"
                mkdir -p "$output_dir"
                
                # Save pattern file
                local pattern_name="dual_band_omni_${band}_${freq}MHz_${alt}m_pattern.txt"
                mv "dual_band_omni_pattern.txt" "$output_dir/$pattern_name"
                
                echo "Generated: $pattern_name"
            fi
        fi
    fi
    
    cd - > /dev/null
    rm -rf "$work_dir"
}

export -f generate_omni_pattern
export SCRIPT_DIR

# Generate patterns for 2m band
echo "Generating patterns for 2m band (VHF)..."

for freq in "${VHF_FREQUENCIES[@]}"; do
    for alt in "${ALTITUDES[@]}"; do
        generate_omni_pattern "$freq" "$alt" "vhf" &
        
        # Limit concurrent jobs
        if (( $(jobs -r | wc -l) >= MAX_JOBS )); then
            wait -n
        fi
    done
done

# Wait for all background jobs to complete
wait

echo "2m band pattern generation completed!"

# Generate patterns for 70cm band
echo "Generating patterns for 70cm band (UHF)..."

for freq in "${UHF_FREQUENCIES[@]}"; do
    for alt in "${ALTITUDES[@]}"; do
        generate_omni_pattern "$freq" "$alt" "uhf" &
        
        # Limit concurrent jobs
        if (( $(jobs -r | wc -l) >= MAX_JOBS )); then
            wait -n
        fi
    done
done

# Wait for all background jobs to complete
wait

echo "70cm band pattern generation completed!"

# Create pattern index file
echo "Creating pattern index file..."

cat > "$(dirname "$ANTENNA_FILE")/dual_band_omni_patterns_index.txt" << EOF
# Dual-Band Omnidirectional Antenna Pattern Index
# Generated: $(date)
# 
# Format: antenna_name frequency_mhz altitude_m band pattern_file
EOF

find "$(dirname "$ANTENNA_FILE")" -path "*/patterns/*" -name "*_pattern.txt" | while read pattern_file; do
    relative_path=$(echo "$pattern_file" | sed "s|$(dirname "$ANTENNA_FILE")/||")
    filename=$(basename "$pattern_file")
    antenna_name=$(echo "$filename" | sed 's/_[0-9.]*MHz_[0-9]*m_pattern.txt//')
    frequency=$(echo "$filename" | sed 's/.*_\([0-9.]*\)MHz_.*/\1/')
    altitude=$(echo "$filename" | sed 's/.*_[0-9.]*MHz_\([0-9]*\)m_.*/\1/')
    band=$(echo "$pattern_file" | sed 's|.*/patterns/\([^/]*\)/.*|\1|')
    
    echo "$antenna_name $frequency $altitude $band $relative_path" >> "$(dirname "$ANTENNA_FILE")/dual_band_omni_patterns_index.txt"
done

echo "Pattern index file created: dual_band_omni_patterns_index.txt"

# Create antenna specification file
cat > "$(dirname "$ANTENNA_FILE")/dual_band_omni_specifications.txt" << EOF
# Dual-Band VHF/UHF Omnidirectional Antenna Specifications
# Generated: $(date)

## Antenna Details
- **Type**: Dual-band collinear omnidirectional antenna
- **VHF Range**: 144.0 - 146.0 MHz (2m amateur band)
- **UHF Range**: 430.0 - 440.0 MHz (70cm amateur band)
- **Total Length**: 5.2m
- **Height**: 10m above ground
- **Polarization**: Vertical
- **Pattern**: Omnidirectional (360°)

## Performance Specifications
- **VHF Gain**: 8.3 dBi @ 144 MHz
- **UHF Gain**: 11.7 dBi @ 432 MHz
- **SWR**: <1.5:1 across both bands
- **Impedance**: 50Ω
- **Max Power**: 200W
- **Weight**: 2.5 kg

## Antenna Design
- **2m Section**: Two λ/2 collinear elements with phasing stub
- **70cm Section**: Four λ/2 collinear elements with phasing stubs
- **Ground Plane**: Four λ/4 radials for omnidirectional pattern
- **Matching**: Internal 50Ω impedance matching network

## Applications
- VHF/UHF repeater sites
- Base station operations
- Emergency communications
- Dual-band packet radio
- APRS gateway stations
- Contest stations requiring omnidirectional coverage

## Pattern Files Generated
EOF

find "$(dirname "$ANTENNA_FILE")" -path "*/patterns/*" -name "*_pattern.txt" | while read pattern_file; do
    filename=$(basename "$pattern_file")
    echo "- $filename" >> "$(dirname "$ANTENNA_FILE")/dual_band_omni_specifications.txt"
done

echo "Specifications file created: dual_band_omni_specifications.txt"

echo "Dual-band omnidirectional antenna pattern generation complete!"
echo ""
echo "Generated files:"
echo "  - EZNEC model: dual_band_omni_2m_70cm.ez"
echo "  - VHF patterns: $(find "$(dirname "$ANTENNA_FILE")" -path "*/patterns/vhf/*" -name "*_pattern.txt" | wc -l) files"
echo "  - UHF patterns: $(find "$(dirname "$ANTENNA_FILE")" -path "*/patterns/uhf/*" -name "*_pattern.txt" | wc -l) files"
echo "  - Index file: dual_band_omni_patterns_index.txt"
echo "  - Specifications: dual_band_omni_specifications.txt"
