#!/bin/bash

# Minimal test to debug script execution context
echo "=== Script Execution Context Debug ==="
echo "PID: $$"
echo "Working directory: $(pwd)"
echo "User: $(whoami)"
echo "PATH: $PATH"

# Test NEC2 directly
echo "Testing NEC2 directly..."
if /usr/bin/nec2c -h >/dev/null 2>&1; then
    echo "NEC2 direct execution: OK"
else
    echo "NEC2 direct execution: FAILED"
fi

# Test with variables (like the script does)
input_file="client/mumble-plugin/lib/antenna_patterns/Ground-based/Yagi-antennas/Yagi_2x-stack_144mhz/yagi2x11.nec"
output_file="test_output.txt"

echo "Input file: $input_file"
echo "Output file: $output_file"

# Test file operations
if [ -f "$input_file" ]; then
    echo "Input file exists: OK"
    echo "Input file size: $(wc -c < "$input_file") bytes"
else
    echo "Input file missing: FAILED"
    exit 1
fi

# Test temporary file creation
temp_dir="${TMPDIR:-/tmp}"
unique_id="$$_$(date +%s%N)_${BASHPID:-$$}_$RANDOM"
short_input="$temp_dir/n${unique_id}.nec"
short_output="$temp_dir/n${unique_id}.out"

echo "Temp input: $short_input"
echo "Temp output: $short_output"

# Copy input to temporary file
if cp "$input_file" "$short_input"; then
    echo "Temp file creation: OK"
    echo "Temp file size: $(wc -c < "$short_input") bytes"
else
    echo "Temp file creation: FAILED"
    exit 1
fi

# Test NEC2 execution with temporary files
echo "Testing NEC2 with temporary files..."
if /usr/bin/nec2c -i "$short_input" -o "$short_output" 2>&1; then
    echo "NEC2 execution: OK"
    if [ -f "$short_output" ] && [ -s "$short_output" ]; then
        echo "Output file created: OK ($(wc -c < "$short_output") bytes)"
        if cp "$short_output" "$output_file"; then
            echo "Final copy: OK"
        else
            echo "Final copy: FAILED"
        fi
    else
        echo "Output file missing or empty: FAILED"
    fi
else
    echo "NEC2 execution: FAILED"
fi

# Cleanup
rm -f "$short_input" "$short_output"

echo "=== Debug Complete ==="
