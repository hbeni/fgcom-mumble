#!/bin/bash
# process_patterns_simple.sh - Simple pattern processor with short filenames

set -e

# Function to process a single EZNEC file with short names
process_file() {
    local ez_file="$1"
    local output_dir="$2"
    local short_name="$3"
    
    if [ ! -f "$ez_file" ]; then
        echo "Error: $ez_file not found"
        return 1
    fi
    
    mkdir -p "$output_dir"
    
    # Use short filenames
    local nec_file="$output_dir/${short_name}.nec"
    local out_file="$output_dir/${short_name}.out"
    
    echo "Processing $short_name..."
    
    # Convert EZNEC to NEC
    ./eznec2nec.sh "$ez_file" "$nec_file"
    
    # Process with nec2c
    if nec2c -i "$nec_file" -o "$out_file" 2>/dev/null; then
        if [ -f "$out_file" ] && [ -s "$out_file" ]; then
            local lines=$(wc -l < "$out_file")
            echo "  ✓ Success: $lines lines"
            return 0
        else
            echo "  ✗ Failed: Empty output"
            return 1
        fi
    else
        echo "  ✗ Failed: nec2c error"
        return 1
    fi
}

echo "FGCom-mumble Simple Pattern Processor"
echo "===================================="
echo ""

# Process aircraft
echo "Processing Aircraft..."
process_file "antenna_patterns/aircraft/b737/b737_800_hf_commercial.ez" "antenna_patterns/aircraft/b737/patterns" "b737"
process_file "antenna_patterns/aircraft/c130_hercules/c130_hercules_hf_nato.ez" "antenna_patterns/aircraft/c130_hercules/patterns" "c130"
process_file "antenna_patterns/aircraft/cessna_172/cessna_172_hf_amateur.ez" "antenna_patterns/aircraft/cessna_172/patterns" "c172"
process_file "antenna_patterns/aircraft/tu95_bear/tu95_bear_hf_sigint.ez" "antenna_patterns/aircraft/tu95_bear/patterns" "tu95"
process_file "antenna_patterns/aircraft/mi4_hound/mil_mi4_hound_soviet.ez" "antenna_patterns/aircraft/mi4_hound/patterns" "mi4"
process_file "antenna_patterns/aircraft/uh1_huey/bell_uh1_huey_nato.ez" "antenna_patterns/aircraft/uh1_huey/patterns" "uh1"

echo ""
echo "Processing Marine..."
# Check if marine files exist first
if [ -f "antenna_patterns/boat/sailboat_whip/sailboat_23ft_whip_20m.ez" ]; then
    process_file "antenna_patterns/boat/sailboat_whip/sailboat_23ft_whip_20m.ez" "antenna_patterns/boat/sailboat_whip/patterns" "sailboat_whip"
fi

if [ -f "antenna_patterns/boat/sailboat_backstay/sailboat_backstay_40m.ez" ]; then
    process_file "antenna_patterns/boat/sailboat_backstay/sailboat_backstay_40m.ez" "antenna_patterns/boat/sailboat_backstay/patterns" "sailboat_backstay"
fi

if [ -f "antenna_patterns/ship/containership/containership_80m_loop.ez" ]; then
    process_file "antenna_patterns/ship/containership/containership_80m_loop.ez" "antenna_patterns/ship/containership/patterns" "containership"
fi

echo ""
echo "Processing Ground Vehicles..."
# Check if vehicle files exist first
if [ -f "antenna_patterns/vehicle/ford_transit/ford_transit_camper_vertical.ez" ]; then
    process_file "antenna_patterns/vehicle/ford_transit/ford_transit_camper_vertical.ez" "antenna_patterns/vehicle/ford_transit/patterns" "ford_transit"
fi

if [ -f "antenna_patterns/vehicle/vw_passat/vw_passat_hf_loaded_vertical.ez" ]; then
    process_file "antenna_patterns/vehicle/vw_passat/vw_passat_hf_loaded_vertical.ez" "antenna_patterns/vehicle/vw_passat/patterns" "vw_passat"
fi

if [ -f "antenna_patterns/military-land/nato_jeep/nato_jeep_10ft_whip_45deg.ez" ]; then
    process_file "antenna_patterns/military-land/nato_jeep/nato_jeep_10ft_whip_45deg.ez" "antenna_patterns/military-land/nato_jeep/patterns" "nato_jeep"
fi

if [ -f "antenna_patterns/military-land/soviet_uaz/soviet_uaz_4m_whip_45deg.ez" ]; then
    process_file "antenna_patterns/military-land/soviet_uaz/soviet_uaz_4m_whip_45deg.ez" "antenna_patterns/military-land/soviet_uaz/patterns" "soviet_uaz"
fi

echo ""
echo "Processing Ground-Based Antennas..."
# Check if ground-based files exist first
if [ -f "antenna_patterns/Ground-based/yagi_40m/hy_gain_th3dxx_40m.ez" ]; then
    process_file "antenna_patterns/Ground-based/yagi_40m/hy_gain_th3dxx_40m.ez" "antenna_patterns/Ground-based/yagi_40m/patterns" "yagi_40m"
fi

if [ -f "antenna_patterns/Ground-based/yagi_20m/cushcraft_a3ws_20m.ez" ]; then
    process_file "antenna_patterns/Ground-based/yagi_20m/cushcraft_a3ws_20m.ez" "antenna_patterns/Ground-based/yagi_20m/patterns" "yagi_20m"
fi

if [ -f "antenna_patterns/Ground-based/yagi_10m/hy_gain_th4dxx_10m.ez" ]; then
    process_file "antenna_patterns/Ground-based/yagi_10m/hy_gain_th4dxx_10m.ez" "antenna_patterns/Ground-based/yagi_10m/patterns" "yagi_10m"
fi

if [ -f "antenna_patterns/Ground-based/yagi_6m/hy_gain_vb64fm_6m.ez" ]; then
    process_file "antenna_patterns/Ground-based/yagi_6m/hy_gain_vb64fm_6m.ez" "antenna_patterns/Ground-based/yagi_6m/patterns" "yagi_6m"
fi

echo ""
echo "Pattern generation complete!"
echo ""
echo "Generated files:"
find antenna_patterns -name "*.out" -type f | sort
