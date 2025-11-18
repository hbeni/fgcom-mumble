#!/bin/bash

# Test script to generate a single pattern
echo "Testing single pattern generation..."

# Set up variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UTILITIES_DIR="$SCRIPT_DIR/../utilities"
BASE_DIR="/home/haaken/github-projects/fgcom-mumble/client/mumble-plugin/lib/antenna_patterns"

# Test file
NEC_FILE="$BASE_DIR/Ground-based/coastal_stations/inverted_antenna/inverted-ew.nec"
ALTITUDE=0
ROLL=0
PITCH=0

echo "Testing file: $NEC_FILE"
echo "Parameters: altitude=$ALTITUDE, roll=$ROLL, pitch=$PITCH"

# Check if file exists
if [ ! -f "$NEC_FILE" ]; then
    echo "ERROR: NEC file not found: $NEC_FILE"
    exit 1
fi

# Get frequency
FREQUENCY=$(grep "^FR" "$NEC_FILE" 2>/dev/null | head -1 | awk '{print $6}')
if [[ ! "$FREQUENCY" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    echo "ERROR: Could not extract frequency from $NEC_FILE"
    exit 1
fi

echo "Frequency: ${FREQUENCY}MHz"

# Create temp files
TEMP_NEC=$(mktemp /tmp/test_nec_XXXXXX.nec)
TEMP_OUT=$(mktemp /tmp/test_out_XXXXXX.txt)

# Create output directory
OUTPUT_DIR="$BASE_DIR/Ground-based/coastal_stations/inverted_antenna/patterns/${FREQUENCY}mhz"
mkdir -p "$OUTPUT_DIR"
PATTERN_FILE="$OUTPUT_DIR/${ALTITUDE}m_roll_${ROLL}_pitch_${PITCH}.txt"

echo "Output file: $PATTERN_FILE"

# Copy NEC file
cp "$NEC_FILE" "$TEMP_NEC"

# For fixed installations (altitude=0, roll=0, pitch=0), no modification needed
if [ "$ALTITUDE" -eq 0 ] && [ "$ROLL" -eq 0 ] && [ "$PITCH" -eq 0 ]; then
    echo "Fixed installation - no coordinate modification needed"
else
    echo "ERROR: This test only supports fixed installations (0,0,0)"
    exit 1
fi

# Run NEC2 simulation
echo "Running nec2c simulation..."
if nec2c -i "$TEMP_NEC" -o "$TEMP_OUT"; then
    echo "NEC2 simulation successful"
    
    # Extract pattern
    echo "Extracting pattern..."
    if "$UTILITIES_DIR/extract_pattern_advanced.sh" "$TEMP_OUT" "$PATTERN_FILE" "$FREQUENCY" "$ALTITUDE"; then
        echo "Pattern extraction successful"
        echo "Pattern file created: $PATTERN_FILE"
        
        # Check file size
        if [ -f "$PATTERN_FILE" ] && [ -s "$PATTERN_FILE" ]; then
            SIZE=$(wc -l < "$PATTERN_FILE")
            echo "Pattern file has $SIZE lines"
            echo "SUCCESS: Pattern generation completed!"
        else
            echo "ERROR: Pattern file is empty or not created"
        fi
    else
        echo "ERROR: Pattern extraction failed"
    fi
else
    echo "ERROR: NEC2 simulation failed"
fi

# Cleanup
rm -f "$TEMP_NEC" "$TEMP_OUT"

echo "Test completed."
