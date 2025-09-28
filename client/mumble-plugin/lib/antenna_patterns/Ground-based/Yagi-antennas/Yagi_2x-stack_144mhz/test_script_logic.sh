#!/bin/bash

# Test the exact logic from the pattern generation script
input_nec="yagi2x11.nec"
output_file="test_output.txt"

# Create very short temporary filenames (8.3 format for maximum compatibility)  
temp_dir="${TMPDIR:-/tmp}"
unique_id="$$_$(date +%s%N | cut -b1-10)_$RANDOM"
short_input="$temp_dir/n${unique_id}.nec"
short_output="$temp_dir/n${unique_id}.out"

echo "Testing script logic..."
echo "Input: $input_nec"
echo "Output: $output_file"
echo "Short input: $short_input"
echo "Short output: $short_output"

# Copy input to short filename
if ! cp "$input_nec" "$short_input"; then
    echo "ERROR: Failed to copy to temporary file: $short_input"
    exit 1
fi

echo "Temp file created successfully"
echo "Temp file size: $(wc -c < "$short_input") bytes"

# Test NEC2 execution
echo "Testing NEC2 execution..."
if nec2c -i "$short_input" -o "$short_output" 2>&1; then
    echo "NEC2 executed successfully"
    if [ -f "$short_output" ] && [ -s "$short_output" ]; then
        echo "Output file created: $(wc -c < "$short_output") bytes"
        if cp "$short_output" "$output_file"; then
            echo "SUCCESS: Pattern generated"
        else
            echo "ERROR: Failed to copy output back"
        fi
    else
        echo "ERROR: Output file missing or empty"
    fi
else
    echo "ERROR: NEC2 execution failed"
fi

# Cleanup
rm -f "$short_input" "$short_output"
