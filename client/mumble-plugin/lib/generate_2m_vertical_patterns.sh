#!/bin/bash

# Generate radiation patterns for 2m vertical antenna
# This script creates patterns for the 2m band (144-146 MHz)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ANTENNA_FILE="$SCRIPT_DIR/antenna_patterns/Ground-based/vertical/2m_vertical/2m_vertical_antenna.ez"
MAX_JOBS=$(nproc)

# 2m band frequencies (144-146 MHz)
VHF_FREQUENCIES=(144.0 144.1 144.2 144.3 144.4 144.5 144.6 144.7 144.8 144.9 145.0 145.1 145.2 145.3 145.4 145.5 145.6 145.7 145.8 145.9 146.0)

echo "Generating 2m vertical antenna patterns using $MAX_JOBS CPU cores..."

# Create patterns directory
mkdir -p "$(dirname "$ANTENNA_FILE")/patterns"

# Function to generate a single pattern
generate_single_pattern() {
    local frequency="$1"
    local antenna_file="$2"
    local temp_dir="/tmp/2m_vertical_${frequency}MHz_$$"
    
    mkdir -p "$temp_dir"
    cd "$temp_dir"
    
    # Copy antenna file
    cp "$antenna_file" "2m_vertical.ez"
    
    # Convert to NEC format
    "$SCRIPT_DIR/eznec2nec.sh" "2m_vertical.ez" "2m_vertical.nec"
    
    # Run NEC2 simulation
    nec2c -i "2m_vertical.nec" -o "2m_vertical.out"
    
    # Extract pattern
    "$SCRIPT_DIR/extract_pattern_advanced.sh" "2m_vertical.out" "2m_vertical_pattern.txt" "$frequency" 0
    
    # Move pattern to final location
    local pattern_dir="$(dirname "$ANTENNA_FILE")/patterns/${frequency}mhz"
    mkdir -p "$pattern_dir"
    mv "2m_vertical_pattern.txt" "$pattern_dir/2m_vertical_${frequency}MHz_0m_pattern.txt"
    
    # Cleanup
    cd /
    rm -rf "$temp_dir"
}

# Generate patterns for all frequencies
echo "Generating patterns for 2m band (VHF)..."
for freq in "${VHF_FREQUENCIES[@]}"; do
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

echo "2m band pattern generation completed!"

# Create pattern index file
cat > "$(dirname "$ANTENNA_FILE")/2m_vertical_patterns_index.txt" << EOF
# 2m Vertical Antenna Pattern Index
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
    
    echo "$antenna_name $frequency $altitude $band $relative_path" >> "$(dirname "$ANTENNA_FILE")/2m_vertical_patterns_index.txt"
done

echo "Pattern index file created: 2m_vertical_patterns_index.txt"

# Create antenna specification file
cat > "$(dirname "$ANTENNA_FILE")/2m_vertical_specifications.txt" << EOF
# 2m Vertical Antenna Specifications

## Antenna Type
- **Model**: 2m Vertical Dipole
- **Frequency Range**: 144-146 MHz (2m amateur band)
- **Height**: 10m above ground
- **Polarization**: Vertical
- **Pattern**: Omnidirectional

## Technical Specifications
- **Elements**: 2 (lower and upper λ/4 elements)
- **Total Length**: 1.0m (0.5m each element)
- **Ground Radials**: 4 × 1.0m
- **Impedance**: ~50Ω
- **SWR**: <2:1 across band
- **Gain**: ~2-3 dBi

## Applications
- VHF amateur radio operations
- Repeater access
- APRS and digital modes
- Local communication

## Pattern Files Generated
EOF

find "$(dirname "$ANTENNA_FILE")" -path "*/patterns/*" -name "*_pattern.txt" | while read pattern_file; do
    filename=$(basename "$pattern_file")
    echo "- $filename" >> "$(dirname "$ANTENNA_FILE")/2m_vertical_specifications.txt"
done

echo "Specifications file created: 2m_vertical_specifications.txt"

echo "2m vertical antenna pattern generation complete!"
echo ""
echo "Generated files:"
echo "  - EZNEC model: 2m_vertical_antenna.ez"
echo "  - VHF patterns: $(find "$(dirname "$ANTENNA_FILE")/patterns" -name "*_pattern.txt" | wc -l) files"
echo "  - Index file: 2m_vertical_patterns_index.txt"
echo "  - Specifications: 2m_vertical_specifications.txt"

