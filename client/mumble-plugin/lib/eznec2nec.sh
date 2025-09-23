#!/bin/bash
# eznec2nec.sh - Convert EZNEC to NEC2 format

if [ $# -eq 0 ]; then
    echo "Usage: $0 input.ez [output.nec]"
    exit 1
fi

INPUT="$1"
OUTPUT="${2:-${1%.ez}.nec}"

# NEC2 header
cat > "$OUTPUT" << 'EOF'
CM EZNEC Model Converted to NEC2
CE
EOF

# Convert geometry (W lines to GW)
sed -n '/^W[0-9]/p' "$INPUT" | \
    awk '{printf "GW %d %d %.3f %.3f %.3f %.3f %.3f %.3f %.6f\n", 
          substr($1,2), $9, $2, $3, $4, $5, $6, $7, $8}' >> "$OUTPUT"

# Ground termination
echo "GE 0" >> "$OUTPUT"

# Convert source (SY SRC to EX)
sed -n '/^SY SRC/p' "$INPUT" | \
    awk '{printf "EX 0 %d %d 0 1.0 0.0\n", substr($3,2), $4}' >> "$OUTPUT"

# Convert ground (GD to GN)
sed -n '/^GD/p' "$INPUT" | \
    sed 's/GD -1/GN -1/' | \
    sed 's/GD 0/GN 2/' | \
    sed 's/;.*$//' >> "$OUTPUT"

# Convert loads
sed -n '/^LD/p' "$INPUT" | sed 's/;.*$//' >> "$OUTPUT"

# Convert frequency
sed -n '/^FR/p' "$INPUT" | sed 's/;.*$//' >> "$OUTPUT"

# Convert radiation pattern
sed -n '/^RP/p' "$INPUT" >> "$OUTPUT"

# NEC2 termination
echo "EN" >> "$OUTPUT"

echo "Converted $INPUT to $OUTPUT"
