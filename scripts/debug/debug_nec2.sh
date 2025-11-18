#!/bin/bash

# Test NEC2 execution in script context
echo "Testing NEC2 execution in script..."

# Create a simple test NEC file
cat > test_simple.nec << 'NEC_EOF'
CE
GW 1 1 0 0 0 0 0 1 0.001
GE 1
FR 0 1 0 0 144 0
EX 0 1 1 0 1 0
RP 0 1 1 1000 0 0 0 0
EN
NEC_EOF

echo "Created test NEC file"

# Test direct NEC2 execution
echo "Testing direct NEC2 execution..."
if /usr/bin/nec2c -itest_simple.nec -otest_simple.out 2>&1; then
    echo "SUCCESS: NEC2 executed successfully"
    if [ -f test_simple.out ] && [ -s test_simple.out ]; then
        echo "SUCCESS: Output file created and has content ($(wc -c < test_simple.out) bytes)"
    else
        echo "ERROR: Output file missing or empty"
    fi
else
    echo "ERROR: NEC2 execution failed"
fi

# Test with script variables (like the pattern generator does)
input_file="test_simple.nec"
output_file="test_simple_script.out"

echo "Testing with script variables..."
if /usr/bin/nec2c -i"$input_file" -o"$output_file" 2>&1; then
    echo "SUCCESS: NEC2 with variables executed successfully"
    if [ -f "$output_file" ] && [ -s "$output_file" ]; then
        echo "SUCCESS: Variable output file created and has content ($(wc -c < "$output_file") bytes)"
    else
        echo "ERROR: Variable output file missing or empty"
    fi
else
    echo "ERROR: NEC2 with variables execution failed"
fi

# Cleanup
rm -f test_simple.nec test_simple.out test_simple_script.out
