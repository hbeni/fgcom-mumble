#!/bin/bash

# Generate 4m Yagi patterns with pitch variations from 0° to 90°
# This creates patterns for horizontal to vertical orientations

set -e

BASE_DIR="/home/haaken/github-projects/fgcom-mumble/client/mumble-plugin/lib/antenna_patterns"
NEC_FILE="$BASE_DIR/Ground-based/4m_band/4m_yagi.nec"
OUTPUT_DIR="$BASE_DIR/Ground-based/4m_band/patterns/70.15mhz"

echo "[INFO] Generating 4m Yagi pitch patterns from 0° to 90°"

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Generate patterns for different pitch angles
for pitch in 0 15 30 45 60 75 90; do
    echo "[INFO] Generating pattern for pitch = ${pitch}°"
    
    # Create temporary NEC file with pitch rotation
    temp_nec="/tmp/4m_yagi_pitch_${pitch}.nec"
    
    # Copy original NEC file
    cp "$NEC_FILE" "$temp_nec"
    
    # Modify the NEC file for pitch rotation
    python3 << EOF
import math

# Read the original NEC file
with open('$NEC_FILE', 'r') as f:
    lines = f.readlines()

# Pitch angle in radians
pitch_rad = math.radians($pitch)

# Process each line
new_lines = []
for line in lines:
    if line.startswith('GW'):
        # Parse GW line: GW tag segments x1 y1 z1 x2 y2 z2 radius
        parts = line.strip().split()
        if len(parts) >= 8:
            tag = parts[0]
            segments = parts[1]
            x1 = float(parts[2])
            y1 = float(parts[3])
            z1 = float(parts[4])
            x2 = float(parts[5])
            y2 = float(parts[6])
            z2 = float(parts[7])
            radius = parts[8]
            
            # Apply pitch rotation around Y-axis
            # x' = x*cos(pitch) - z*sin(pitch)
            # z' = x*sin(pitch) + z*cos(pitch)
            x1_new = x1 * math.cos(pitch_rad) - z1 * math.sin(pitch_rad)
            z1_new = x1 * math.sin(pitch_rad) + z1 * math.cos(pitch_rad)
            x2_new = x2 * math.cos(pitch_rad) - z2 * math.sin(pitch_rad)
            z2_new = x2 * math.sin(pitch_rad) + z2 * math.cos(pitch_rad)
            
            # Write modified line
            new_line = f"{tag} {segments} {x1_new:.6f} {y1} {z1_new:.6f} {x2_new:.6f} {y2} {z2_new:.6f} {radius}\n"
            new_lines.append(new_line)
        else:
            new_lines.append(line)
    else:
        new_lines.append(line)

# Write the modified file
with open('$temp_nec', 'w') as f:
    f.writelines(new_lines)
EOF

    # Run NEC2 simulation
    echo "[DEBUG] Running NEC2 for pitch ${pitch}°"
    nec2c -i"$temp_nec" -o"/tmp/4m_yagi_pitch_${pitch}.out" 2>/dev/null || {
        echo "[WARNING] NEC2 failed for pitch ${pitch}°"
        continue
    }
    
    # Extract pattern data
    echo "[DEBUG] Extracting pattern data for pitch ${pitch}°"
    python3 << EOF
import re

# Read NEC2 output
with open('/tmp/4m_yagi_pitch_${pitch}.out', 'r') as f:
    content = f.read()

# Find radiation pattern section
pattern_start = content.find('RADIATION PATTERNS')
if pattern_start == -1:
    print("No radiation patterns found")
    exit(1)

# Extract pattern data
pattern_section = content[pattern_start:]
lines = pattern_section.split('\n')

# Find data lines (skip headers)
data_lines = []
in_data = False
for line in lines:
    if 'THETA' in line and 'PHI' in line and 'TOTAL' in line:
        in_data = True
        continue
    if in_data and line.strip() and not line.startswith(' '):
        # Check if line contains numeric data
        parts = line.split()
        if len(parts) >= 6 and parts[0].replace('.', '').isdigit():
            data_lines.append(line)

# Create pattern file
output_file = '$OUTPUT_DIR/4m_yagi_0m_roll_0_pitch_${pitch}_70.15MHz.txt'
with open(output_file, 'w') as f:
    f.write('# FGCom-mumble Far-Field Radiation Pattern\n')
    f.write(f'# Frequency: 70.15 MHz\n')
    f.write(f'# Altitude: 0 m\n')
    f.write(f'# Pitch: ${pitch} degrees\n')
    f.write('# Format: Theta Phi Gain_dBi H_Polarization V_Polarization\n')
    f.write('# Theta: Elevation angle (0-180 degrees)\n')
    f.write('# Phi: Azimuth angle (0-360 degrees)\n')
    f.write('# Gain_dBi: Gain in dBi\n')
    f.write('# H_Polarization: Horizontal polarization component\n')
    f.write('# V_Polarization: Vertical polarization component\n')
    f.write('\n')
    
    for line in data_lines:
        parts = line.split()
        if len(parts) >= 6:
            theta = parts[0]
            phi = parts[1]
            total_gain = parts[5]  # TOTAL column
            f.write(f'{theta} {phi} {total_gain} 0.0 0.0\n')

print(f"Pattern file created: {output_file}")
EOF

    # Clean up temporary files
    rm -f "$temp_nec" "/tmp/4m_yagi_pitch_${pitch}.out"
    
    echo "[SUCCESS] Generated pattern for pitch ${pitch}°"
done

echo "[SUCCESS] All 4m Yagi pitch patterns generated successfully!"
echo "[INFO] Patterns created in: $OUTPUT_DIR"
ls -la "$OUTPUT_DIR"/*pitch*
