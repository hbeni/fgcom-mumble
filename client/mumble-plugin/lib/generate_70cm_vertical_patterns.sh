#!/bin/bash

# Generate radiation patterns for 70cm vertical antenna
# This script creates patterns for the 70cm band (430-440 MHz)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ANTENNA_FILE="$SCRIPT_DIR/antenna_patterns/Ground-based/vertical/70cm_vertical/70cm_vertical_antenna.ez"
MAX_JOBS=$(nproc)

# 70cm band frequencies (430-440 MHz)
UHF_FREQUENCIES=(430.0 430.5 431.0 431.5 432.0 432.5 433.0 433.5 434.0 434.5 435.0 435.5 436.0 436.5 437.0 437.5 438.0 438.5 439.0 439.5 440.0)

echo "Generating 70cm vertical antenna patterns using $MAX_JOBS CPU cores..."

# Create patterns directory
mkdir -p "$(dirname "$ANTENNA_FILE")/patterns"

# Function to generate a single pattern
generate_single_pattern() {
    local frequency="$1"
    local antenna_file="$2"
    local temp_dir="/tmp/70cm_vertical_${frequency}MHz_$$"
    
    mkdir -p "$temp_dir"
    cd "$temp_dir"
    
    # Copy antenna file
    cp "$antenna_file" "70cm_vertical.ez"
    
    # Convert to NEC format
    "$SCRIPT_DIR/eznec2nec.sh" "70cm_vertical.ez" "70cm_vertical.nec"
    
    # Run NEC2 simulation
    nec2c -i "70cm_vertical.nec" -o "70cm_vertical.out"
    
    # Extract pattern
    "$SCRIPT_DIR/extract_pattern_advanced.sh" "70cm_vertical.out" "70cm_vertical_pattern.txt" "$frequency" 0
    
    # Move pattern to final location
    local pattern_dir="$(dirname "$ANTENNA_FILE")/patterns/${frequency}mhz"
    mkdir -p "$pattern_dir"
    mv "70cm_vertical_pattern.txt" "$pattern_dir/70cm_vertical_${frequency}MHz_0m_pattern.txt"
    
    # Cleanup
    cd /
    rm -rf "$temp_dir"
}

# Generate patterns for all frequencies
echo "Generating patterns for 70cm band (UHF)..."
for freq in "${UHF_FREQUENCIES[@]}"; do
    (
        generate_single_pattern "$freq" "$ANTENNA_FILE"
        echo "Generated pattern for ${freq} MHz"
    ) &
    
    # Limit concurrent jobs
    if (( $(jobs -r | wc -l) >= MAX_JOBS )); then
        wait -n
    fi
done

# Wait for all jobs to complete
wait

echo "70cm band pattern generation completed!"

# Create pattern index file
cat > "$(dirname "$ANTENNA_FILE")/70cm_vertical_patterns_index.txt" << EOF
# 70cm Vertical Antenna Pattern Index
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
    
    echo "$antenna_name $frequency $altitude $band $relative_path" >> "$(dirname "$ANTENNA_FILE")/70cm_vertical_patterns_index.txt"
done

echo "Pattern index file created: 70cm_vertical_patterns_index.txt"

# Create antenna specification file
cat > "$(dirname "$ANTENNA_FILE")/70cm_vertical_specifications.txt" << EOF
# 70cm Vertical Antenna Specifications

## Antenna Type
- **Model**: 70cm Vertical Dipole
- **Frequency Range**: 430-440 MHz (70cm amateur band)
- **Height**: 10m above ground
- **Polarization**: Vertical
- **Pattern**: Omnidirectional

## Technical Specifications
- **Elements**: 2 (lower and upper λ/4 elements)
- **Total Length**: 0.35m (0.175m each element)
- **Ground Radials**: 4 × 0.35m
- **Impedance**: ~50Ω
- **SWR**: <2:1 across band
- **Gain**: ~2-3 dBi

## Applications
- UHF amateur radio operations
- Repeater access
- APRS and digital modes
- Local communication

## Pattern Files Generated
EOF

find "$(dirname "$ANTENNA_FILE")" -path "*/patterns/*" -name "*_pattern.txt" | while read pattern_file; do
    filename=$(basename "$pattern_file")
    echo "- $filename" >> "$(dirname "$ANTENNA_FILE")/70cm_vertical_specifications.txt"
done

echo "Specifications file created: 70cm_vertical_specifications.txt"

echo "70cm vertical antenna pattern generation complete!"
echo ""
echo "Generated files:"
echo "  - EZNEC model: 70cm_vertical_antenna.ez"
echo "  - UHF patterns: $(find "$(dirname "$ANTENNA_FILE")/patterns" -name "*_pattern.txt" | wc -l) files"
echo "  - Index file: 70cm_vertical_patterns_index.txt"
echo "  - Specifications: 70cm_vertical_specifications.txt"

