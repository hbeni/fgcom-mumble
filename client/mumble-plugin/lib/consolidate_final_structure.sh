#!/bin/bash
# consolidate_final_structure.sh - Final consolidation to standardized structure

set -e

echo "FGCom-mumble Final Structure Consolidation"
echo "=========================================="
echo ""

# Function to consolidate a vehicle directory
consolidate_vehicle() {
    local vehicle_dir="$1"
    local vehicle_name="$2"
    
    echo "Consolidating $vehicle_name..."
    
    # Create the standardized patterns directory
    local patterns_dir="${vehicle_dir}/${vehicle_name}_patterns"
    mkdir -p "$patterns_dir"
    
    # Define all amateur radio frequencies
    local frequencies=("1.8" "3.5" "5.3" "7.0" "10.1" "14.0" "18.1" "21.0" "24.9" "28.0" "50.0")
    
    # Create frequency directories
    for freq in "${frequencies[@]}"; do
        mkdir -p "${patterns_dir}/${freq}mhz"
    done
    
    # Move all EZNEC files from any subdirectory to the appropriate frequency directory
    find "$vehicle_dir" -name "*.ez" -type f | while read ez_file; do
        local basename_file=$(basename "$ez_file" .ez)
        local freq_mhz=""
        
        # Parse frequency from filename
        if [[ "$basename_file" =~ _([0-9]+\.?[0-9]*)MHz ]]; then
            freq_mhz="${BASH_REMATCH[1]}"
        fi
        
        if [ -n "$freq_mhz" ]; then
            local target_dir="${patterns_dir}/${freq_mhz}mhz"
            if [ -d "$target_dir" ]; then
                mv "$ez_file" "$target_dir/"
                echo "  Moved $(basename "$ez_file") to ${freq_mhz}mhz/"
            fi
        fi
    done
    
    # Move all pattern files from any subdirectory to the appropriate frequency directory
    find "$vehicle_dir" -name "*_pattern.txt" -type f | while read pattern_file; do
        local basename_file=$(basename "$pattern_file" _pattern.txt)
        local freq_mhz=""
        
        # Parse frequency from filename
        if [[ "$basename_file" =~ _([0-9]+\.?[0-9]*)MHz ]]; then
            freq_mhz="${BASH_REMATCH[1]}"
        fi
        
        if [ -n "$freq_mhz" ]; then
            local target_dir="${patterns_dir}/${freq_mhz}mhz"
            if [ -d "$target_dir" ]; then
                mv "$pattern_file" "$target_dir/"
                echo "  Moved $(basename "$pattern_file") to ${freq_mhz}mhz/"
            fi
        fi
    done
    
    # Clean up empty directories
    find "$vehicle_dir" -type d -empty -delete 2>/dev/null || true
    
    echo "  ✓ Completed $vehicle_name consolidation"
    echo ""
}

# Main consolidation
echo "Starting final structure consolidation..."
echo ""

# Consolidate all aircraft
if [ -d "antenna_patterns/aircraft" ]; then
    echo "=== Consolidating Aircraft ==="
    for aircraft_dir in antenna_patterns/aircraft/*; do
        if [ -d "$aircraft_dir" ]; then
            aircraft_name=$(basename "$aircraft_dir")
            consolidate_vehicle "$aircraft_dir" "$aircraft_name"
        fi
    done
fi

# Consolidate all boats
if [ -d "antenna_patterns/boat" ]; then
    echo "=== Consolidating Boats ==="
    for boat_dir in antenna_patterns/boat/*; do
        if [ -d "$boat_dir" ]; then
            boat_name=$(basename "$boat_dir")
            consolidate_vehicle "$boat_dir" "$boat_name"
        fi
    done
fi

# Consolidate all ships
if [ -d "antenna_patterns/ship" ]; then
    echo "=== Consolidating Ships ==="
    for ship_dir in antenna_patterns/ship/*; do
        if [ -d "$ship_dir" ]; then
            ship_name=$(basename "$ship_dir")
            consolidate_vehicle "$ship_dir" "$ship_name"
        fi
    done
fi

# Consolidate all ground vehicles
if [ -d "antenna_patterns/vehicle" ]; then
    echo "=== Consolidating Ground Vehicles ==="
    for vehicle_dir in antenna_patterns/vehicle/*; do
        if [ -d "$vehicle_dir" ]; then
            vehicle_name=$(basename "$vehicle_dir")
            consolidate_vehicle "$vehicle_dir" "$vehicle_name"
        fi
    done
fi

# Consolidate all military vehicles
if [ -d "antenna_patterns/military-land" ]; then
    echo "=== Consolidating Military Vehicles ==="
    for military_dir in antenna_patterns/military-land/*; do
        if [ -d "$military_dir" ]; then
            military_name=$(basename "$military_dir")
            consolidate_vehicle "$military_dir" "$military_name"
        fi
    done
fi

# Consolidate all ground-based antennas
if [ -d "antenna_patterns/Ground-based" ]; then
    echo "=== Consolidating Ground-based Antennas ==="
    for ground_dir in antenna_patterns/Ground-based/*; do
        if [ -d "$ground_dir" ]; then
            ground_name=$(basename "$ground_dir")
            consolidate_vehicle "$ground_dir" "$ground_name"
        fi
    done
fi

echo "Final structure consolidation complete!"
echo ""

# Summary
echo "=== FINAL CONSOLIDATED STRUCTURE SUMMARY ==="
echo ""
echo "Total pattern files:"
find antenna_patterns -name "*_pattern.txt" -type f | wc -l
echo ""
echo "Breakdown by vehicle type:"
echo "Aircraft: $(find antenna_patterns/aircraft -name "*_pattern.txt" -type f 2>/dev/null | wc -l) files"
echo "Boats: $(find antenna_patterns/boat -name "*_pattern.txt" -type f 2>/dev/null | wc -l) files"
echo "Ships: $(find antenna_patterns/ship -name "*_pattern.txt" -type f 2>/dev/null | wc -l) files"
echo "Ground Vehicles: $(find antenna_patterns/vehicle -name "*_pattern.txt" -type f 2>/dev/null | wc -l) files"
echo "Military: $(find antenna_patterns/military-land -name "*_pattern.txt" -type f 2>/dev/null | wc -l) files"
echo "Ground-based: $(find antenna_patterns/Ground-based -name "*_pattern.txt" -type f 2>/dev/null | wc -l) files"
echo ""
echo "FINAL STANDARDIZED STRUCTURE:"
echo "antenna_patterns/[vehicle_type]/[vehicle_name]/[vehicle_name]_patterns/[frequency]mhz/"
echo ""
echo "Example verification:"
echo "B737 14.0MHz: $(find antenna_patterns/aircraft/b737/b737_patterns/14.0mhz -name "*.ez" 2>/dev/null | wc -l) EZNEC files, $(find antenna_patterns/aircraft/b737/b737_patterns/14.0mhz -name "*_pattern.txt" 2>/dev/null | wc -l) pattern files"
echo "Sailboat 14.0MHz: $(find antenna_patterns/boat/sailboat_whip/sailboat_whip_patterns/14.0mhz -name "*.ez" 2>/dev/null | wc -l) EZNEC files, $(find antenna_patterns/boat/sailboat_whip/sailboat_whip_patterns/14.0mhz -name "*_pattern.txt" 2>/dev/null | wc -l) pattern files"
echo "Container ship 14.0MHz: $(find antenna_patterns/ship/containership/containership_patterns/14.0mhz -name "*.ez" 2>/dev/null | wc -l) EZNEC files, $(find antenna_patterns/ship/containership/containership_patterns/14.0mhz -name "*_pattern.txt" 2>/dev/null | wc -l) pattern files"
