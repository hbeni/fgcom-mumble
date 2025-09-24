#!/bin/bash

# Generate VHF/UHF radiation patterns for FGCom-mumble
# This script creates antenna patterns for VHF (30-300 MHz) and UHF (300+ MHz) frequencies

set -e

SCRIPT_DIR="$(dirname "$0")"
ANTENNA_PATTERNS_DIR="$SCRIPT_DIR/antenna_patterns"
MAX_JOBS=$(nproc)

# VHF frequencies (30-300 MHz)
VHF_FREQUENCIES=(50.0 100.0 150.0 200.0 250.0 300.0)

# UHF frequencies (300+ MHz)  
UHF_FREQUENCIES=(400.0 500.0 600.0 800.0 1000.0 1200.0)

echo "Starting VHF/UHF pattern generation using $MAX_JOBS CPU cores..."

# Function to generate pattern for one EZNEC file
generate_vhf_uhf_pattern() {
    local eznec_file="$1"
    local freq="$2"
    local alt="$3"
    local band="$4"  # "vhf" or "uhf"
    
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
                local output_dir="$(dirname "$eznec_file")/patterns/${band}/${freq}mhz"
                mkdir -p "$output_dir"
                
                # Save pattern file
                local pattern_name="${base_name}_${freq}MHz_${alt}m_${band}_pattern.txt"
                mv "${base_name}_pattern.txt" "$output_dir/$pattern_name"
                
                echo "Generated: $pattern_name"
            fi
        fi
    fi
    
    cd - > /dev/null
    rm -rf "$work_dir"
}

export -f generate_vhf_uhf_pattern
export SCRIPT_DIR

# Find all VHF EZNEC files and generate patterns
echo "Finding VHF EZNEC files..."
find "$ANTENNA_PATTERNS_DIR" -name "*vhf*.ez" | while read eznec_file; do
    echo "Processing VHF file: $eznec_file"
    
    # Generate patterns for each VHF frequency
    for freq in "${VHF_FREQUENCIES[@]}"; do
        for alt in 0 100 500 1000 2000 5000; do
            generate_vhf_uhf_pattern "$eznec_file" "$freq" "$alt" "vhf" &
            
            # Limit concurrent jobs
            if (( $(jobs -r | wc -l) >= MAX_JOBS )); then
                wait -n
            fi
        done
    done
done

# Find all UHF EZNEC files and generate patterns
echo "Finding UHF EZNEC files..."
find "$ANTENNA_PATTERNS_DIR" -name "*uhf*.ez" | while read eznec_file; do
    echo "Processing UHF file: $eznec_file"
    
    # Generate patterns for each UHF frequency
    for freq in "${UHF_FREQUENCIES[@]}"; do
        for alt in 0 100 500 1000 2000 5000; do
            generate_vhf_uhf_pattern "$eznec_file" "$freq" "$alt" "uhf" &
            
            # Limit concurrent jobs
            if (( $(jobs -r | wc -l) >= MAX_JOBS )); then
                wait -n
            fi
        done
    done
done

# Wait for all background jobs to complete
wait

echo "VHF/UHF pattern generation completed!"

# Create pattern index files
echo "Creating pattern index files..."

# VHF pattern index
cat > "$ANTENNA_PATTERNS_DIR/vhf_patterns_index.txt" << EOF
# VHF Antenna Pattern Index
# Generated: $(date)
# 
# Format: antenna_name frequency_mhz altitude_m pattern_file
EOF

find "$ANTENNA_PATTERNS_DIR" -path "*/patterns/vhf/*" -name "*_pattern.txt" | while read pattern_file; do
    local relative_path=$(echo "$pattern_file" | sed "s|$ANTENNA_PATTERNS_DIR/||")
    local filename=$(basename "$pattern_file")
    local antenna_name=$(echo "$filename" | sed 's/_[0-9.]*MHz_[0-9]*m_vhf_pattern.txt//')
    local frequency=$(echo "$filename" | sed 's/.*_\([0-9.]*\)MHz_.*/\1/')
    local altitude=$(echo "$filename" | sed 's/.*_[0-9.]*MHz_\([0-9]*\)m_.*/\1/')
    
    echo "$antenna_name $frequency $altitude $relative_path" >> "$ANTENNA_PATTERNS_DIR/vhf_patterns_index.txt"
done

# UHF pattern index
cat > "$ANTENNA_PATTERNS_DIR/uhf_patterns_index.txt" << EOF
# UHF Antenna Pattern Index
# Generated: $(date)
# 
# Format: antenna_name frequency_mhz altitude_m pattern_file
EOF

find "$ANTENNA_PATTERNS_DIR" -path "*/patterns/uhf/*" -name "*_pattern.txt" | while read pattern_file; do
    local relative_path=$(echo "$pattern_file" | sed "s|$ANTENNA_PATTERNS_DIR/||")
    local filename=$(basename "$pattern_file")
    local antenna_name=$(echo "$filename" | sed 's/_[0-9.]*MHz_[0-9]*m_uhf_pattern.txt//')
    local frequency=$(echo "$filename" | sed 's/.*_\([0-9.]*\)MHz_.*/\1/')
    local altitude=$(echo "$filename" | sed 's/.*_[0-9.]*MHz_\([0-9]*\)m_.*/\1/')
    
    echo "$antenna_name $frequency $altitude $relative_path" >> "$ANTENNA_PATTERNS_DIR/uhf_patterns_index.txt"
done

echo "Pattern index files created:"
echo "  - vhf_patterns_index.txt"
echo "  - uhf_patterns_index.txt"

echo "VHF/UHF pattern generation complete!"
