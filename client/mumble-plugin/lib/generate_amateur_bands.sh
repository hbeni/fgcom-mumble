#!/bin/bash
# generate_amateur_bands.sh - Generate complete amateur radio band patterns

set -e

echo "FGCom-mumble Complete Amateur Radio Band Generator"
echo "================================================"
echo ""

# Amateur radio bands from the CSV data
AMATEUR_BANDS="1.8 3.5 5.3 7.0 10.1 14.0 18.1 21.0 24.9 28.0 50.0"

# Function to generate amateur band patterns for a vehicle
generate_amateur_bands() {
    local vehicle_type="$1"
    local vehicle_name="$2"
    local ez_file="$3"
    
    echo "Processing $vehicle_name amateur radio bands..."
    
    # Create amateur patterns directory
    mkdir -p "antenna_patterns/$vehicle_type/amateur_patterns"
    
    # Process each amateur band
    for band in $AMATEUR_BANDS; do
        echo "  Generating amateur band ${band}MHz..."
        
        # Create band-specific directory
        band_dir="antenna_patterns/$vehicle_type/amateur_patterns/${band}mhz"
        mkdir -p "$band_dir"
        
        # Generate altitude sweep (for aircraft) or single pattern (for boats/ships)
        if [[ "$vehicle_type" == *"aircraft"* ]]; then
            # Aircraft: generate altitude-dependent patterns
            ./altitude_sweep.sh "$ez_file" "$band" > /dev/null 2>&1
        else
            # Boats/ships: generate single pattern (no altitude variation)
            cp "$ez_file" "altitude_patterns/$(basename "$ez_file" .ez)_${band}MHz.ez"
            # Modify frequency in the copied file
            sed -i "s/^FR 0 1 0 0 .*/FR 0 1 0 0 ${band} 0/" "altitude_patterns/$(basename "$ez_file" .ez)_${band}MHz.ez"
        fi
        
        # Move generated files to band directory
        if [ -d "altitude_patterns" ]; then
            mv altitude_patterns/* "$band_dir/" 2>/dev/null || true
            rmdir altitude_patterns 2>/dev/null || true
        fi
        
        echo "    ✓ Generated $(ls "$band_dir"/*.ez 2>/dev/null | wc -l) pattern files"
    done
    
    echo "  ✓ Completed $vehicle_name amateur bands"
    echo ""
}

# Generate amateur bands for civilian aircraft
echo "=== Civilian Aircraft Amateur Bands ==="
generate_amateur_bands "aircraft/b737" "Boeing 737" "antenna_patterns/aircraft/b737/b737_800_hf_commercial.ez"
generate_amateur_bands "aircraft/cessna_172" "Cessna 172" "antenna_patterns/aircraft/cessna_172/cessna_172_hf_amateur.ez"

# Generate amateur bands for boats
echo "=== Boat Amateur Bands ==="
generate_amateur_bands "boat/sailboat_whip" "Sailboat Whip" "antenna_patterns/boat/sailboat_whip/sailboat_23ft_whip_20m.ez"
generate_amateur_bands "boat/sailboat_backstay" "Sailboat Backstay" "antenna_patterns/boat/sailboat_backstay/sailboat_backstay_40m.ez"

# Generate amateur bands for ships
echo "=== Ship Amateur Bands ==="
generate_amateur_bands "ship/containership" "Container Ship" "antenna_patterns/ship/containership/containership_80m_loop.ez"

echo "Amateur radio band generation complete!"
echo ""
echo "Summary of generated amateur bands:"
echo "==================================="

for vehicle in "aircraft/b737" "aircraft/cessna_172" "boat/sailboat_whip" "boat/sailboat_backstay" "ship/containership"; do
    if [ -d "antenna_patterns/$vehicle/amateur_patterns" ]; then
        band_count=$(ls -d antenna_patterns/$vehicle/amateur_patterns/*mhz 2>/dev/null | wc -l)
        echo "$vehicle: $band_count amateur bands"
    fi
done

echo ""
echo "Amateur bands generated:"
echo "- 160m (1.8 MHz)"
echo "- 80m (3.5 MHz)" 
echo "- 60m (5.3 MHz)"
echo "- 40m (7.0 MHz)"
echo "- 30m (10.1 MHz)"
echo "- 20m (14.0 MHz)"
echo "- 17m (18.1 MHz)"
echo "- 15m (21.0 MHz)"
echo "- 12m (24.9 MHz)"
echo "- 10m (28.0 MHz)"
echo "- 6m (50.0 MHz)"
echo ""
echo "Next steps:"
echo "1. Process EZNEC files with nec2c to generate .out files"
echo "2. Integrate with FGCom_AmateurRadio class"
echo "3. Add band-specific propagation characteristics"
