#!/bin/bash

# Simple script to generate missing radiation patterns
# Uses all CPU cores for fast generation

set -e

SCRIPT_DIR="$(dirname "$0")"
ANTENNA_PATTERNS_DIR="$SCRIPT_DIR/antenna_patterns"
MAX_JOBS=$(nproc)

# Amateur radio frequencies
FREQUENCIES=(1.8 3.5 5.3 7.0 10.1 14.0 18.1 21.0 24.9 28.0 50.0)

# Military frequencies  
MILITARY_FREQ=(3.0 5.0 7.0 9.0)

echo "Starting pattern generation using $MAX_JOBS CPU cores..."

# Function to generate pattern for one EZNEC file
generate_pattern() {
    local eznec_file="$1"
    local freq="$2"
    local alt="$3"
    
    if [ ! -f "$eznec_file" ]; then
        return 1
    fi
    
    local base_name=$(basename "$eznec_file" .ez)
    local work_dir="/tmp/nec_$$_${RANDOM}"
    
    mkdir -p "$work_dir"
    cd "$work_dir"
    
    # Copy and modify EZNEC file
    cp "$eznec_file" "${base_name}.ez"
    sed -i "s/^FR.*/FR 0 1 0 0 ${freq} 0/" "${base_name}.ez"
    
    # Convert to NEC2
    if "$SCRIPT_DIR/eznec2nec.sh" "${base_name}.ez" "${base_name}.nec" 2>/dev/null; then
        # Run NEC2 simulation
        if nec2c -i "${base_name}.nec" -o "${base_name}.out" 2>/dev/null; then
            # Extract pattern
            if "$SCRIPT_DIR/extract_pattern_advanced.sh" "${base_name}.out" "${base_name}_pattern.txt" "$freq" "$alt" 2>/dev/null; then
                # Create output directory
                local output_dir="$(dirname "$eznec_file")/patterns/${freq}mhz"
                mkdir -p "$output_dir"
                
                # Save pattern file
                local pattern_name="${base_name}_${freq}MHz_${alt}m_pattern.txt"
                mv "${base_name}_pattern.txt" "$output_dir/$pattern_name"
                
                echo "Generated: $pattern_name"
            fi
        fi
    fi
    
    cd - > /dev/null
    rm -rf "$work_dir"
}

export -f generate_pattern
export SCRIPT_DIR

# Find all EZNEC files and generate patterns
echo "Finding EZNEC files..."
find "$ANTENNA_PATTERNS_DIR" -name "*.ez" | while read eznec_file; do
    echo "Processing: $eznec_file"
    
    # Determine frequencies based on file location
    if [[ "$eznec_file" =~ military-land ]]; then
        # Military vehicles use military frequencies
        for freq in "${MILITARY_FREQ[@]}"; do
            echo "generate_pattern '$eznec_file' '$freq' '0'" >> /tmp/jobs_$$.txt
        done
    else
        # All other vehicles use amateur bands
        for freq in "${FREQUENCIES[@]}"; do
            if [[ "$eznec_file" =~ aircraft ]]; then
                # Aircraft: generate altitude variations
                for alt in $(seq 0 2000 15000); do
                    echo "generate_pattern '$eznec_file' '$freq' '$alt'" >> /tmp/jobs_$$.txt
                done
            else
                # Ground level for other vehicles
                echo "generate_pattern '$eznec_file' '$freq' '0'" >> /tmp/jobs_$$.txt
            fi
        done
    fi
done

# Process all jobs in parallel
echo "Processing $(wc -l < /tmp/jobs_$$.txt) jobs using $MAX_JOBS CPU cores..."
cat /tmp/jobs_$$.txt | xargs -n 1 -P "$MAX_JOBS" -I {} bash -c '{}'

# Cleanup
rm -f /tmp/jobs_$$.txt

# Count results
PATTERN_COUNT=$(find "$ANTENNA_PATTERNS_DIR" -name "*_pattern.txt" | wc -l)
echo "Generated $PATTERN_COUNT radiation patterns"

# Show breakdown
echo "Pattern breakdown:"
for dir in aircraft military-land vehicle boat ship Ground-based; do
    count=$(find "$ANTENNA_PATTERNS_DIR/$dir" -name "*_pattern.txt" 2>/dev/null | wc -l)
    if [ "$count" -gt 0 ]; then
        echo "  $dir: $count patterns"
    fi
done
