#!/bin/bash

# Generate radiation patterns for 11-element 2m Yagi antenna (144-145 MHz)
# This script creates patterns for the professional VHF beam antenna

set -e

SCRIPT_DIR="$(dirname "$0")"
ANTENNA_FILE="$SCRIPT_DIR/antenna_patterns/Ground-based/yagi_144mhz/yagi_144mhz_11element.ez"
MAX_JOBS=$(nproc)

# 2m band frequencies (144-145 MHz)
FREQUENCIES=(144.0 144.1 144.2 144.3 144.4 144.5 144.6 144.7 144.8 144.9 145.0)

# Altitude variations for ground-based antenna
ALTITUDES=(0 100 500 1000 2000)

echo "Generating 2m Yagi antenna patterns using $MAX_JOBS CPU cores..."

# Function to generate pattern for one frequency/altitude combination
generate_yagi_pattern() {
    local freq="$1"
    local alt="$2"
    
    if [ ! -f "$ANTENNA_FILE" ]; then
        echo "Error: Antenna file not found: $ANTENNA_FILE"
        return 1
    fi
    
    local work_dir="/tmp/nec_$$_${RANDOM}"
    mkdir -p "$work_dir"
    cd "$work_dir"
    
    # Copy and modify EZNEC file
    cp "$ANTENNA_FILE" "yagi_144mhz.ez"
    
    # Update frequency in the file
    sed -i "s/^FR.*/FR 0 1 0 0 ${freq} 0/" "yagi_144mhz.ez"
    
    # Update ground height if needed (for altitude variations)
    if [ "$alt" != "0" ]; then
        # Adjust antenna height for altitude
        local new_height=$(echo "10.0 + $alt" | bc -l)
        sed -i "s/10\.0/${new_height}/g" "yagi_144mhz.ez"
    fi
    
    # Convert to NEC2
    if "$SCRIPT_DIR/eznec2nec.sh" "yagi_144mhz.ez" "yagi_144mhz.nec" 2>/dev/null; then
        # Run NEC2 simulation
        if nec2c -i "yagi_144mhz.nec" -o "yagi_144mhz.out" 2>/dev/null; then
            # Extract pattern
            if "$SCRIPT_DIR/extract_pattern_advanced.sh" "yagi_144mhz.out" "yagi_144mhz_pattern.txt" "$freq" "$alt" 2>/dev/null; then
                # Create output directory
                local output_dir="$(dirname "$ANTENNA_FILE")/patterns/${freq}mhz"
                mkdir -p "$output_dir"
                
                # Save pattern file
                local pattern_name="yagi_144mhz_${freq}MHz_${alt}m_pattern.txt"
                mv "yagi_144mhz_pattern.txt" "$output_dir/$pattern_name"
                
                echo "Generated: $pattern_name"
            fi
        fi
    fi
    
    cd - > /dev/null
    rm -rf "$work_dir"
}

export -f generate_yagi_pattern
export SCRIPT_DIR

# Generate patterns for all frequency/altitude combinations
echo "Generating patterns for 2m Yagi antenna..."

for freq in "${FREQUENCIES[@]}"; do
    for alt in "${ALTITUDES[@]}"; do
        generate_yagi_pattern "$freq" "$alt" &
        
        # Limit concurrent jobs
        if (( $(jobs -r | wc -l) >= MAX_JOBS )); then
            wait -n
        fi
    done
done

# Wait for all background jobs to complete
wait

echo "2m Yagi pattern generation completed!"

# Create pattern index file
echo "Creating pattern index file..."

cat > "$(dirname "$ANTENNA_FILE")/yagi_144mhz_patterns_index.txt" << EOF
# 2m Yagi Antenna Pattern Index
# Generated: $(date)
# 
# Format: antenna_name frequency_mhz altitude_m pattern_file
EOF

find "$(dirname "$ANTENNA_FILE")" -path "*/patterns/*" -name "*_pattern.txt" | while read pattern_file; do
    local relative_path=$(echo "$pattern_file" | sed "s|$(dirname "$ANTENNA_FILE")/||")
    local filename=$(basename "$pattern_file")
    local antenna_name=$(echo "$filename" | sed 's/_[0-9.]*MHz_[0-9]*m_pattern.txt//')
    local frequency=$(echo "$filename" | sed 's/.*_\([0-9.]*\)MHz_.*/\1/')
    local altitude=$(echo "$filename" | sed 's/.*_[0-9.]*MHz_\([0-9]*\)m_.*/\1/')
    
    echo "$antenna_name $frequency $altitude $relative_path" >> "$(dirname "$ANTENNA_FILE")/yagi_144mhz_patterns_index.txt"
done

echo "Pattern index file created: yagi_144mhz_patterns_index.txt"

# Create antenna specification file
cat > "$(dirname "$ANTENNA_FILE")/yagi_144mhz_specifications.txt" << EOF
# 11-Element 2m Yagi Antenna Specifications
# Generated: $(date)

## Antenna Details
- **Type**: 11-element Yagi beam antenna
- **Frequency Range**: 144.0 - 145.0 MHz (2m amateur band)
- **Boom Length**: 5.72m (572 cm)
- **Elements**: 11 (1 reflector, 1 driven, 9 directors)
- **Height**: 10m above ground
- **Polarization**: Horizontal

## Performance Specifications
- **Gain**: 14.8 dBi (typical)
- **Front/Back Ratio**: 27 dB
- **Beamwidth**: ~30° horizontal, ~35° vertical
- **SWR**: <1.5:1 across band
- **Impedance**: 50Ω (with 4:1 balun)
- **Max Power**: 500W
- **Weight**: 6.95 kg

## Element Specifications
- **Reflector**: 105cm length, -2.50m position
- **Driven Element**: 97cm length, -1.80m position
- **Directors**: 93-83cm (progressively shorter)
- **Element Material**: 6mm diameter aluminum rod
- **Boom Material**: 25mm diameter aluminum tube

## Applications
- VHF weak signal communication (EME, MS)
- Contest operation and DXpeditions
- Repeater and digipeater access
- APRS and digital modes
- Satellite communication (linear transponders)

## Pattern Files Generated
EOF

find "$(dirname "$ANTENNA_FILE")" -path "*/patterns/*" -name "*_pattern.txt" | while read pattern_file; do
    local filename=$(basename "$pattern_file")
    echo "- $filename" >> "$(dirname "$ANTENNA_FILE")/yagi_144mhz_specifications.txt"
done

echo "Specifications file created: yagi_144mhz_specifications.txt"

echo "2m Yagi antenna pattern generation complete!"
echo ""
echo "Generated files:"
echo "  - EZNEC model: yagi_144mhz_11element.ez"
echo "  - Pattern files: $(find "$(dirname "$ANTENNA_FILE")" -name "*_pattern.txt" | wc -l) files"
echo "  - Index file: yagi_144mhz_patterns_index.txt"
echo "  - Specifications: yagi_144mhz_specifications.txt"
