#!/bin/bash
# test_altitude_sweep.sh - Test the altitude sweep functionality
# This script demonstrates how to generate altitude-dependent patterns for aircraft

echo "FGCom-Mumble Altitude Sweep Test"
echo "================================="
echo ""

# Test with different aircraft types
AIRCRAFT_TYPES=(
    "tu95_bear_hf_sigint"
    "c130_hercules_hf_nato" 
    "b737_800_hf_commercial"
    "cessna_172_hf_amateur"
    "mil_mi4_hound_soviet"
    "bell_uh1_huey_nato"
)

FREQUENCIES=(
    "5.733"   # Soviet military HF
    "6.750"   # NATO military HF
    "8.900"   # Aeronautical HF
    "14.230"  # 20m amateur
    "7.150"   # Soviet helicopter HF
    "41.500"  # NATO VHF-FM
)

echo "Testing altitude sweep for aircraft antennas..."
echo ""

# Create test output directory
TEST_DIR="./test_altitude_patterns"
mkdir -p "$TEST_DIR"

# Test each aircraft type
for i in "${!AIRCRAFT_TYPES[@]}"; do
    AIRCRAFT="${AIRCRAFT_TYPES[$i]}"
    FREQUENCY="${FREQUENCIES[$i]}"
    
    echo "Testing $AIRCRAFT at ${FREQUENCY}MHz..."
    
    # Check if aircraft file exists
    AIRCRAFT_FILE="./antenna_patterns/aircraft/${AIRCRAFT}.ez"
    if [ ! -f "$AIRCRAFT_FILE" ]; then
        echo "  Warning: Aircraft file not found: $AIRCRAFT_FILE"
        continue
    fi
    
    # Run altitude sweep
    OUTPUT_DIR="${TEST_DIR}/${AIRCRAFT}_${FREQUENCY}MHz"
    ./altitude_sweep.sh "$AIRCRAFT_FILE" "$FREQUENCY" "$OUTPUT_DIR"
    
    if [ $? -eq 0 ]; then
        echo "  ✓ Successfully generated altitude patterns"
        echo "  Output directory: $OUTPUT_DIR"
        
        # Count generated files
        FILE_COUNT=$(find "$OUTPUT_DIR" -name "*.ez" | wc -l)
        echo "  Generated $FILE_COUNT altitude-specific pattern files"
        
        # Show altitude range
        ALTITUDES=$(find "$OUTPUT_DIR" -name "*.ez" | sed 's/.*_\([0-9]*\)m_.*/\1/' | sort -n)
        FIRST_ALT=$(echo "$ALTITUDES" | head -1)
        LAST_ALT=$(echo "$ALTITUDES" | tail -1)
        echo "  Altitude range: ${FIRST_ALT}m to ${LAST_ALT}m"
        
    else
        echo "  ✗ Failed to generate altitude patterns"
    fi
    
    echo ""
done

echo "Altitude sweep test complete!"
echo ""
echo "Next steps for 4NEC2 processing:"
echo "1. Install 4NEC2 if not already installed"
echo "2. Run 4NEC2 on each generated .ez file:"
echo "   for file in $TEST_DIR/*/*.ez; do"
echo "     echo \"Processing \$file...\""
echo "     4nec2 -i \"\$file\" -o \"\${file%.ez}.out\""
echo "   done"
echo ""
echo "3. Use pattern_interpolation.cpp to create lookup tables"
echo "4. Integrate with FGCom-Mumble propagation engine"
echo ""
echo "Example 4NEC2 batch processing script:"
cat << 'EOF'
#!/bin/bash
# batch_4nec2.sh - Process all altitude pattern files with 4NEC2

PATTERN_DIR="$1"
if [ -z "$PATTERN_DIR" ]; then
    echo "Usage: $0 pattern_directory"
    exit 1
fi

echo "Processing 4NEC2 files in $PATTERN_DIR..."

find "$PATTERN_DIR" -name "*.ez" | while read -r file; do
    output_file="${file%.ez}.out"
    echo "Processing: $(basename "$file")"
    
    # Run 4NEC2 (adjust command based on your 4NEC2 installation)
    if command -v 4nec2 >/dev/null 2>&1; then
        4nec2 -i "$file" -o "$output_file"
    elif command -v nec2c >/dev/null 2>&1; then
        nec2c "$file" > "$output_file"
    else
        echo "  Warning: 4NEC2 not found, skipping $file"
        continue
    fi
    
    if [ $? -eq 0 ]; then
        echo "  ✓ Generated: $(basename "$output_file")"
    else
        echo "  ✗ Failed to process: $(basename "$file")"
    fi
done

echo "4NEC2 batch processing complete!"
EOF

echo "Batch processing script saved as: batch_4nec2.sh"
chmod +x batch_4nec2.sh

echo ""
echo "Summary of altitude-dependent pattern generation:"
echo "- Ground Effect Zone (0-1000m): Dense sampling (50-100m intervals)"
echo "- Low Altitude (1000-3000m): Moderate sampling (200-300m intervals)"
echo "- Medium Altitude (3000-8000m): Wide intervals (500-1000m)"
echo "- High Altitude (8000-15000m): Very wide intervals (1000-2000m)"
echo ""
echo "This provides accurate radiation pattern modeling for aircraft"
echo "at all operational altitudes with appropriate sampling density."
