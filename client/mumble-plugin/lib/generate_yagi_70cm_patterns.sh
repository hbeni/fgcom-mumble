#!/bin/bash

# Generate radiation patterns for 16-element 70cm Yagi antenna (430-440 MHz)
# This script creates patterns for the high-performance UHF beam antenna

set -e

SCRIPT_DIR="$(dirname "$0")"
ANTENNA_FILE="$SCRIPT_DIR/antenna_patterns/Ground-based/yagi_70cm/yagi_70cm_16element.ez"
MAX_JOBS=$(nproc)

# 70cm band frequencies (430-440 MHz)
FREQUENCIES=(430.0 430.5 431.0 431.5 432.0 432.5 433.0 433.5 434.0 434.5 435.0 435.5 436.0 436.5 437.0 437.5 438.0 438.5 439.0 439.5 440.0)

# Altitude variations for ground-based antenna
ALTITUDES=(0 100 500 1000 2000)

echo "Generating 70cm Yagi antenna patterns using $MAX_JOBS CPU cores..."

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
    cp "$ANTENNA_FILE" "yagi_70cm.ez"
    
    # Update frequency in the file
    sed -i "s/^FR.*/FR 0 1 0 0 ${freq} 0/" "yagi_70cm.ez"
    
    # Update ground height if needed (for altitude variations)
    if [ "$alt" != "0" ]; then
        # Adjust antenna height for altitude
        local new_height=$(echo "10.0 + $alt" | bc -l)
        sed -i "s/10\.0/${new_height}/g" "yagi_70cm.ez"
    fi
    
    # Convert to NEC2
    if "$SCRIPT_DIR/eznec2nec.sh" "yagi_70cm.ez" "yagi_70cm.nec" 2>/dev/null; then
        # Run NEC2 simulation
        if nec2c -i "yagi_70cm.nec" -o "yagi_70cm.out" 2>/dev/null; then
            # Extract pattern
            if "$SCRIPT_DIR/extract_pattern_advanced.sh" "yagi_70cm.out" "yagi_70cm_pattern.txt" "$freq" "$alt" 2>/dev/null; then
                # Create output directory
                local output_dir="$(dirname "$ANTENNA_FILE")/patterns/${freq}mhz"
                mkdir -p "$output_dir"
                
                # Save pattern file
                local pattern_name="yagi_70cm_${freq}MHz_${alt}m_pattern.txt"
                mv "yagi_70cm_pattern.txt" "$output_dir/$pattern_name"
                
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
echo "Generating patterns for 70cm Yagi antenna..."

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

echo "70cm Yagi pattern generation completed!"

# Create pattern index file
echo "Creating pattern index file..."

cat > "$(dirname "$ANTENNA_FILE")/yagi_70cm_patterns_index.txt" << EOF
# 70cm Yagi Antenna Pattern Index
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
    
    echo "$antenna_name $frequency $altitude $relative_path" >> "$(dirname "$ANTENNA_FILE")/yagi_70cm_patterns_index.txt"
done

echo "Pattern index file created: yagi_70cm_patterns_index.txt"

# Create antenna specification file
cat > "$(dirname "$ANTENNA_FILE")/yagi_70cm_specifications.txt" << EOF
# 16-Element 70cm Yagi Antenna Specifications
# Generated: $(date)

## Antenna Details
- **Type**: 16-element Yagi beam antenna
- **Frequency Range**: 430.0 - 440.0 MHz (70cm amateur band)
- **Boom Length**: 3.10m (310 cm)
- **Elements**: 16 (1 reflector, 1 driven, 14 directors)
- **Height**: 10m above ground
- **Polarization**: Horizontal

## Performance Specifications
- **Gain**: 16.56 dBi (free space)
- **Front/Back Ratio**: 32 dB
- **Beamwidth**: ~24° horizontal, ~26° vertical
- **SWR**: <1.3:1 across band
- **Impedance**: 50Ω (with 4:1 balun)
- **Max Power**: 1000W
- **Tapered Boom**: 25-30-25mm aluminum

## Element Specifications
- **Reflector**: 35cm length, -1.40m position
- **Driven Element**: 32.4cm length, -1.10m position
- **Directors**: 31.6-26cm (progressively shorter)
- **Element Material**: 3mm diameter aluminum rod
- **Boom Material**: Tapered aluminum (25-30-25mm)

## Applications
- UHF weak signal communication (EME, MS)
- Contest operation and DXpeditions
- Repeater and digipeater access
- APRS and digital modes
- Satellite communication (linear transponders)

## Pattern Files Generated
EOF

find "$(dirname "$ANTENNA_FILE")" -path "*/patterns/*" -name "*_pattern.txt" | while read pattern_file; do
    local filename=$(basename "$pattern_file")
    echo "- $filename" >> "$(dirname "$ANTENNA_FILE")/yagi_70cm_specifications.txt"
done

echo "Specifications file created: yagi_70cm_specifications.txt"

echo "70cm Yagi antenna pattern generation complete!"
echo ""
echo "Generated files:"
echo "  - EZNEC model: yagi_70cm_16element.ez"
echo "  - Pattern files: $(find "$(dirname "$ANTENNA_FILE")" -name "*_pattern.txt" | wc -l) files"
echo "  - Index file: yagi_70cm_patterns_index.txt"
echo "  - Specifications: yagi_70cm_specifications.txt"
