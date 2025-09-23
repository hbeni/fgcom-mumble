#!/bin/bash
# altitude_sweep.sh - Generate radiation patterns at multiple altitudes for aircraft
# This script creates altitude-dependent radiation patterns for aircraft antennas
# Critical for accurate propagation modeling at different flight levels

ANTENNA_FILE="$1"
FREQUENCY="$2"
OUTPUT_DIR="$3"

if [ $# -lt 2 ]; then
    echo "Usage: $0 antenna.ez frequency_mhz [output_directory]"
    echo "Example: $0 tu95_bear_hf_sigint.ez 5.733"
    exit 1
fi

# Set default output directory if not provided
if [ -z "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="./altitude_patterns"
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Extract antenna name for file naming
ANTENNA_NAME=$(basename "$ANTENNA_FILE" .ez)

echo "Generating altitude-dependent patterns for $ANTENNA_NAME at ${FREQUENCY}MHz"
echo "Output directory: $OUTPUT_DIR"

# Define altitude-dependent ground parameters
# Critical Altitude Ranges for Aircraft:

# Ground Effect Transition Zone: 0-1000m (dense sampling)
ground_effect_altitudes=(0 50 100 150 200 300 400 500 600 700 800 900 1000)

# Low Altitude Operations: 1000-3000m (moderate sampling)
low_altitude_altitudes=(1000 1200 1500 1800 2100 2400 2700 3000)

# Medium Altitude: 3000-8000m (wider intervals)
medium_altitude_altitudes=(3000 4000 5000 6000 7000 8000)

# High Altitude: 8000-15000m (wide intervals, approaching free space)
high_altitude_altitudes=(8000 10000 12000 15000)

# Combine all altitudes
all_altitudes=("${ground_effect_altitudes[@]}" "${low_altitude_altitudes[@]}" "${medium_altitude_altitudes[@]}" "${high_altitude_altitudes[@]}")

# Remove duplicates and sort
altitudes=($(printf '%s\n' "${all_altitudes[@]}" | sort -n | uniq))

echo "Simulating at ${#altitudes[@]} altitude levels..."

for alt in "${altitudes[@]}"; do
    echo "Processing ${alt}m altitude..."
    
    # Create altitude-specific EZNEC file
    output_file="${OUTPUT_DIR}/${ANTENNA_NAME}_${alt}m_${FREQUENCY}MHz.ez"
    
    # Copy original file
    cp "$ANTENNA_FILE" "$output_file"
    
    # Calculate ground parameters based on altitude
    if [ $alt -eq 0 ]; then
        # On ground - full ground effects
        ground_type="GD 0 0 0 0 0.005 0.013  ; On ground - average soil"
        echo "  Ground level - full ground effects"
    elif [ $alt -lt 500 ]; then
        # Very low altitude - significant ground effects
        ground_type="GD 0 0 0 0 0.005 0.013  ; Very low altitude - strong ground effects"
        echo "  Very low altitude (${alt}m) - strong ground effects"
    elif [ $alt -lt 1000 ]; then
        # Low altitude - moderate ground effects
        ground_type="GD 0 0 0 0 0.003 0.012  ; Low altitude - moderate ground effects"
        echo "  Low altitude (${alt}m) - moderate ground effects"
    elif [ $alt -lt 3000 ]; then
        # Medium-low altitude - reduced ground effects
        ground_type="GD 0 0 0 0 0.001 0.010  ; Medium-low altitude - reduced ground effects"
        echo "  Medium-low altitude (${alt}m) - reduced ground effects"
    elif [ $alt -lt 8000 ]; then
        # Medium altitude - minimal ground effects
        ground_type="GD 0 0 0 0 0.0005 0.008  ; Medium altitude - minimal ground effects"
        echo "  Medium altitude (${alt}m) - minimal ground effects"
    else
        # High altitude - approaching free space
        ground_type="GD -1 0 0 0 0 0  ; High altitude - free space conditions"
        echo "  High altitude (${alt}m) - free space conditions"
    fi
    
    # Replace ground line in EZNEC file
    sed -i "s/^GD.*/$ground_type/" "$output_file"
    
    # Update frequency if specified
    if [ ! -z "$FREQUENCY" ]; then
        sed -i "s/^FR 0 1 0 0 [0-9.]* 0/FR 0 1 0 0 $FREQUENCY 0/" "$output_file"
    fi
    
    # Add altitude-specific comments
    echo "; Altitude: ${alt}m" >> "$output_file"
    echo "; Ground effects: $([ $alt -lt 1000 ] && echo "Significant" || [ $alt -lt 3000 ] && echo "Moderate" || [ $alt -lt 8000 ] && echo "Minimal" || echo "Negligible")" >> "$output_file"
    echo "; Pattern characteristics: $([ $alt -lt 500 ] && echo "Ground wave dominant, multipath interference" || [ $alt -lt 2000 ] && echo "Mixed ground/sky wave, transitional effects" || [ $alt -lt 5000 ] && echo "Sky wave dominant, pattern stabilizing" || echo "Free space conditions, stable patterns")" >> "$output_file"
    
done

echo ""
echo "Altitude sweep complete!"
echo "Generated ${#altitudes[@]} pattern files in $OUTPUT_DIR"
echo ""
echo "Altitude ranges covered:"
echo "  Ground Effect Zone (0-1000m): ${#ground_effect_altitudes[@]} samples"
echo "  Low Altitude (1000-3000m): ${#low_altitude_altitudes[@]} samples"  
echo "  Medium Altitude (3000-8000m): ${#medium_altitude_altitudes[@]} samples"
echo "  High Altitude (8000-15000m): ${#high_altitude_altitudes[@]} samples"
echo ""
echo "Next steps:"
echo "  1. Run 4NEC2 on each generated .ez file"
echo "  2. Export radiation patterns (.out files)"
echo "  3. Use pattern_interpolation.cpp to create altitude-dependent lookup tables"
echo ""
echo "Example 4NEC2 batch processing:"
echo "  for file in $OUTPUT_DIR/*.ez; do"
echo "    echo \"Processing \$file...\""
echo "    4nec2 -i \"\$file\" -o \"\${file%.ez}.out\""
echo "  done"
