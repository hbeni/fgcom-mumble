#!/bin/bash
# generate_missing_frequencies.sh - Generate missing frequency patterns for all aircraft

set -e

echo "FGCom-mumble Missing Frequency Pattern Generator"
echo "=============================================="
echo ""

# Function to generate frequency patterns for an aircraft
generate_aircraft_frequencies() {
    local aircraft="$1"
    local ez_file="$2"
    local frequencies="$3"
    local aircraft_name="$4"
    
    echo "Processing $aircraft_name..."
    
    # Create main patterns directory if it doesn't exist
    mkdir -p "antenna_patterns/aircraft/$aircraft/${aircraft}_patterns"
    
    # Process each frequency
    for freq in $frequencies; do
        echo "  Generating patterns for ${freq}MHz..."
        
        # Create frequency-specific directory
        freq_dir="antenna_patterns/aircraft/$aircraft/${aircraft}_patterns/${freq}mhz"
        mkdir -p "$freq_dir"
        
        # Generate altitude sweep
        ./altitude_sweep.sh "$ez_file" "$freq" > /dev/null 2>&1
        
        # Move generated files to frequency directory
        if [ -d "altitude_patterns" ]; then
            mv altitude_patterns/* "$freq_dir/" 2>/dev/null || true
            rmdir altitude_patterns 2>/dev/null || true
        fi
        
        echo "    ✓ Generated $(ls "$freq_dir"/*.ez 2>/dev/null | wc -l) altitude patterns"
    done
    
    echo "  ✓ Completed $aircraft_name"
    echo ""
}

# B737 - Multiple MWARA frequencies
echo "=== Boeing 737 ==="
generate_aircraft_frequencies "b737" "antenna_patterns/aircraft/b737/b737_800_hf_commercial.ez" "2.85 3.4 5.5 6.5 8.9 11.3 13.3 17.9" "Boeing 737"

# C-130 Hercules - NATO tactical frequencies  
echo "=== C-130 Hercules ==="
generate_aircraft_frequencies "c130_hercules" "antenna_patterns/aircraft/c130_hercules/c130_hercules_hf_nato.ez" "6.0 8.0 10.0 12.0" "C-130 Hercules"

# Cessna 172 - Amateur radio bands (already have 14.23 and 7.15, but let's add more)
echo "=== Cessna 172 ==="
generate_aircraft_frequencies "cessna_172" "antenna_patterns/aircraft/cessna_172/cessna_172_hf_amateur.ez" "3.5 7.0 10.1 14.0 18.1 21.0 24.9 28.0" "Cessna 172"

# Tu-95 Bear - Soviet strategic frequencies
echo "=== Tu-95 Bear ==="
generate_aircraft_frequencies "tu95_bear" "antenna_patterns/aircraft/tu95_bear/tu95_bear_hf_sigint.ez" "5.0 7.0 9.0 11.0 13.0" "Tu-95 Bear"

# Mi-4 Hound - Soviet military helicopter
echo "=== Mi-4 Hound ==="
generate_aircraft_frequencies "mi4_hound" "antenna_patterns/aircraft/mi4_hound/mil_mi4_hound_soviet.ez" "3.0 5.0 7.0 9.0" "Mi-4 Hound"

# UH-1 Huey - NATO military helicopter
echo "=== UH-1 Huey ==="
generate_aircraft_frequencies "uh1_huey" "antenna_patterns/aircraft/uh1_huey/bell_uh1_huey_nato.ez" "3.0 5.0 7.0 9.0 11.0" "UH-1 Huey"

echo "Frequency pattern generation complete!"
echo ""
echo "Summary of generated patterns:"
echo "=============================="

for aircraft in b737 c130_hercules cessna_172 tu95_bear mi4_hound uh1_huey; do
    if [ -d "antenna_patterns/aircraft/$aircraft/${aircraft}_patterns" ]; then
        freq_count=$(ls -d antenna_patterns/aircraft/$aircraft/${aircraft}_patterns/*mhz 2>/dev/null | wc -l)
        echo "$aircraft: $freq_count frequency bands"
    fi
done

echo ""
echo "Next steps:"
echo "1. Process EZNEC files with nec2c to generate .out files"
echo "2. Integrate with FGCom_PatternInterpolator class"
echo "3. Add altitude-dependent pattern interpolation"
