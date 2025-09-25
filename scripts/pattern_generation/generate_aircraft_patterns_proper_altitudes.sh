#!/bin/bash

# FGCom-mumble Aircraft Pattern Generation with Proper Altitude Intervals
# Generates radiation patterns for all aircraft using recommended altitude intervals

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PATTERNS_DIR="$PROJECT_ROOT/client/mumble-plugin/lib/antenna_patterns"

# Recommended altitude intervals - 28 total points
ALL_ALTITUDES=(0 25 50 100 150 200 250 300 500 650 800 1000 1500 2000 2500 3000 4000 5000 6000 7000 8000 9000 10000 12000 14000 16000 18000 20000)

# Aircraft EZNEC files to process
AIRCRAFT_FILES=(
    "aircraft/b737_800/b737-real.ez"
    "aircraft/b737_800/b737-vhf.ez"
    "aircraft/bell_uh1_huey/huey-real.ez"
    "aircraft/c130_hercules/c130-realistic.ez"
    "aircraft/c130_hercules/c130-hf.ez"
    "aircraft/mi4_hound/mi4-vhf.ez"
    "aircraft/mil_mi4_hound/mil-mi4-fixed.ez"
    "aircraft/cessna_172/cessna-hf.ez"
    "aircraft/cessna_172/cessna-final.ez"
)

# Function to get frequency from EZNEC file
get_frequency() {
    local eznec_file="$1"
    if [ ! -f "$eznec_file" ]; then
        echo "unknown"
        return
    fi
    
    # Try to extract frequency from FR command
    local freq=$(grep -E "^FR\s+[0-9]" "$eznec_file" | head -1 | awk '{print $6}')
    if [ -n "$freq" ] && [ "$freq" != "0" ]; then
        echo "$freq"
    else
        echo "unknown"
    fi
}

# Function to get vehicle type from path
get_vehicle_type() {
    local path="$1"
    if [[ "$path" == *"aircraft"* ]]; then
        echo "aircraft"
    elif [[ "$path" == *"ship"* ]] || [[ "$path" == *"boat"* ]]; then
        echo "maritime"
    elif [[ "$path" == *"military"* ]]; then
        echo "military"
    else
        echo "ground"
    fi
}

# Function to generate pattern for single aircraft file
generate_aircraft_patterns() {
    local eznec_file="$1"
    local aircraft_name="$2"
    local frequency="$3"
    
    echo "[INFO] Generating patterns for $aircraft_name at $frequency MHz"
    
    # Create frequency directory
    local freq_dir="$PATTERNS_DIR/patterns/${frequency}mhz"
    mkdir -p "$freq_dir"
    
    # Generate patterns for all altitudes
    for altitude in "${ALL_ALTITUDES[@]}"; do
        local pattern_file="${freq_dir}/${aircraft_name}_${frequency}MHz_${altitude}m_pattern.txt"
        
        echo "  [INFO] Generating pattern at ${altitude}m altitude"
        
        # Convert EZNEC to NEC2
        local nec_file="${eznec_file%.ez}.nec"
        if ! "$SCRIPT_DIR/../utilities/eznec2nec.sh" "$eznec_file" "$nec_file"; then
            echo "  [ERROR] Failed to convert EZNEC to NEC2"
            continue
        fi
        
        # Run NEC2 simulation
        local nec2_output="${nec_file%.nec}.out"
        if ! nec2c "$nec_file" > "$nec2_output" 2>&1; then
            echo "  [ERROR] NEC2 simulation failed"
            continue
        fi
        
        # Extract radiation pattern
        if ! "$SCRIPT_DIR/../utilities/extract_pattern_advanced.sh" "$nec2_output" "$pattern_file" "$frequency" "$altitude"; then
            echo "  [ERROR] Failed to extract radiation pattern"
            continue
        fi
        
        # Validate pattern
        if grep -q "999.99" "$pattern_file" 2>/dev/null; then
            echo "  [WARNING] Pattern contains invalid data (-999.99)"
        else
            echo "  [SUCCESS] Generated valid pattern: $pattern_file"
        fi
        
        # Cleanup temporary files
        rm -f "$nec_file" "$nec2_output"
    done
}

# Main execution
echo "[SECTION] FGCom-mumble Aircraft Pattern Generation with Proper Altitudes"
echo "[INFO] Using recommended altitude intervals:"
echo "  Ground effect zone (0-300m): 0, 25, 50, 100, 150, 200, 250, 300"
echo "  Pattern to low cruise (300m-3000m): 300, 500, 650, 800, 1000, 1500, 2000, 2500, 3000"
echo "  Medium to high altitude (3000m-20000m): 3000, 4000, 5000, 6000, 7000, 8000, 9000, 10000, 12000, 14000, 16000, 18000, 20000"
echo "  Total altitudes: ${#ALL_ALTITUDES[@]}"

echo "[INFO] Processing ${#AIRCRAFT_FILES[@]} aircraft files"

# Process each aircraft file
for eznec_file in "${AIRCRAFT_FILES[@]}"; do
    full_path="$PATTERNS_DIR/$eznec_file"
    
    if [ ! -f "$full_path" ]; then
        echo "[WARNING] EZNEC file not found: $full_path"
        continue
    fi
    
    # Extract aircraft name from path
    aircraft_name=$(basename "$eznec_file" .ez)
    
    # Get frequency
    frequency=$(get_frequency "$full_path")
    if [ "$frequency" = "unknown" ]; then
        echo "[WARNING] Could not determine frequency for $aircraft_name, skipping"
        continue
    fi
    
    # Generate patterns
    generate_aircraft_patterns "$full_path" "$aircraft_name" "$frequency"
done

echo "[SUCCESS] Aircraft pattern generation completed!"
echo "[INFO] Total patterns generated: $(find "$PATTERNS_DIR" -name "*_pattern.txt" | wc -l)"
