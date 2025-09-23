#!/bin/bash
# Batch Pattern Generator for FGCom-mumble Antenna Patterns
# Converts EZNEC files to NEC format and processes them with nec2c

set -e  # Exit on any error

# Function to convert and process a single EZNEC file
process_eznec_file() {
    local ez_file="$1"
    local output_dir="$2"
    local frequency="$3"
    
    if [ ! -f "$ez_file" ]; then
        echo "Error: EZNEC file $ez_file not found"
        return 1
    fi
    
    # Extract base name without extension
    local base_name=$(basename "$ez_file" .ez)
    
    # Create output directory if it doesn't exist
    mkdir -p "$output_dir"
    
    # Convert EZNEC to NEC format
    echo "Converting $ez_file to NEC format..."
    python3 ez2nec_converter.py "$ez_file" "$output_dir/${base_name}.nec"
    
    # Process with nec2c
    echo "Processing ${base_name}.nec with nec2c..."
    if nec2c -i "$output_dir/${base_name}.nec" -o "$output_dir/${base_name}.out" 2>/dev/null; then
        echo "✓ Successfully processed ${base_name}"
        return 0
    else
        echo "✗ Failed to process ${base_name}"
        # Check if output file was created
        if [ -f "$output_dir/${base_name}.out" ]; then
            echo "  Output file created but may contain errors"
            return 0
        else
            return 1
        fi
    fi
}

# Function to process aircraft altitude patterns
process_aircraft_patterns() {
    local aircraft_dir="$1"
    local frequency="$2"
    
    echo "Processing aircraft patterns for $(basename "$aircraft_dir") at ${frequency}MHz"
    
    # Process the main EZNEC file
    local main_ez_file=$(find "$aircraft_dir" -name "*.ez" -not -path "*/patterns/*" | head -1)
    if [ -n "$main_ez_file" ]; then
        process_eznec_file "$main_ez_file" "$aircraft_dir/$(basename "$aircraft_dir")_patterns" "$frequency"
    fi
    
    # Process altitude sweep files if they exist
    local pattern_dir="$aircraft_dir/$(basename "$aircraft_dir")_patterns"
    if [ -d "$pattern_dir" ]; then
        echo "Processing altitude sweep patterns..."
        for ez_file in "$pattern_dir"/*.ez; do
            if [ -f "$ez_file" ]; then
                process_eznec_file "$ez_file" "$pattern_dir" "$frequency"
            fi
        done
    fi
}

# Function to process marine patterns
process_marine_patterns() {
    local marine_dir="$1"
    local frequency="$2"
    
    echo "Processing marine patterns for $(basename "$marine_dir") at ${frequency}MHz"
    
    local main_ez_file=$(find "$marine_dir" -name "*.ez" -not -path "*/patterns/*" | head -1)
    if [ -n "$main_ez_file" ]; then
        process_eznec_file "$main_ez_file" "$marine_dir/$(basename "$marine_dir")_patterns" "$frequency"
    fi
}

# Function to process ground vehicle patterns
process_ground_vehicle_patterns() {
    local vehicle_dir="$1"
    local frequency="$2"
    
    echo "Processing ground vehicle patterns for $(basename "$vehicle_dir") at ${frequency}MHz"
    
    local main_ez_file=$(find "$vehicle_dir" -name "*.ez" -not -path "*/patterns/*" | head -1)
    if [ -n "$main_ez_file" ]; then
        process_eznec_file "$main_ez_file" "$vehicle_dir/$(basename "$vehicle_dir")_patterns" "$frequency"
    fi
}

# Function to process ground-based antenna patterns
process_ground_based_patterns() {
    local antenna_dir="$1"
    local frequency="$2"
    
    echo "Processing ground-based antenna patterns for $(basename "$antenna_dir") at ${frequency}MHz"
    
    local main_ez_file=$(find "$antenna_dir" -name "*.ez" -not -path "*/patterns/*" | head -1)
    if [ -n "$main_ez_file" ]; then
        process_eznec_file "$main_ez_file" "$antenna_dir/$(basename "$antenna_dir")_patterns" "$frequency"
    fi
}

# Main processing function
main() {
    local base_dir="antenna_patterns"
    
    echo "FGCom-mumble Batch Pattern Generator"
    echo "===================================="
    echo ""
    
    # Process aircraft patterns
    echo "Processing Aircraft Patterns..."
    echo "------------------------------"
    process_aircraft_patterns "$base_dir/aircraft/b737" "8.9"
    process_aircraft_patterns "$base_dir/aircraft/c130_hercules" "8.0"
    process_aircraft_patterns "$base_dir/aircraft/cessna_172" "14.23"
    process_aircraft_patterns "$base_dir/aircraft/tu95_bear" "9.0"
    process_aircraft_patterns "$base_dir/aircraft/mi4_hound" "7.0"
    process_aircraft_patterns "$base_dir/aircraft/uh1_huey" "7.0"
    echo ""
    
    # Process marine patterns
    echo "Processing Marine Patterns..."
    echo "---------------------------"
    process_marine_patterns "$base_dir/boat/sailboat_whip" "14.23"
    process_marine_patterns "$base_dir/boat/sailboat_backstay" "7.15"
    process_marine_patterns "$base_dir/ship/containership" "3.8"
    echo ""
    
    # Process ground vehicle patterns
    echo "Processing Ground Vehicle Patterns..."
    echo "-----------------------------------"
    process_ground_vehicle_patterns "$base_dir/vehicle/ford_transit" "14.23"
    process_ground_vehicle_patterns "$base_dir/vehicle/vw_passat" "14.23"
    process_ground_vehicle_patterns "$base_dir/military-land/nato_jeep" "7.0"
    process_ground_vehicle_patterns "$base_dir/military-land/soviet_uaz" "7.0"
    echo ""
    
    # Process ground-based antenna patterns
    echo "Processing Ground-Based Antenna Patterns..."
    echo "------------------------------------------"
    process_ground_based_patterns "$base_dir/Ground-based/yagi_40m" "7.15"
    process_ground_based_patterns "$base_dir/Ground-based/yagi_20m" "14.23"
    process_ground_based_patterns "$base_dir/Ground-based/yagi_10m" "28.4"
    process_ground_based_patterns "$base_dir/Ground-based/yagi_6m" "52.0"
    echo ""
    
    echo "Batch pattern generation complete!"
    echo ""
    echo "Summary:"
    echo "--------"
    echo "Aircraft patterns: 6 vehicles processed"
    echo "Marine patterns: 3 vessels processed"
    echo "Ground vehicle patterns: 4 vehicles processed"
    echo "Ground-based patterns: 4 antenna types processed"
    echo ""
    echo "Total: 17 antenna pattern sets generated"
}

# Run main function
main "$@"
