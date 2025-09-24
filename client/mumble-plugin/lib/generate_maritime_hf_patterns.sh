#!/bin/bash

# Maritime HF Antenna Pattern Generation Script
# Generates radiation patterns for historical maritime HF antennas

echo "Generating Maritime HF Antenna Patterns..."

# Set working directory
cd "$(dirname "$0")/antenna_patterns/Ground-based/maritime_hf"

# Check if EZNEC is available
if ! command -v eznec &> /dev/null; then
    echo "Error: EZNEC not found. Please install EZNEC to generate patterns."
    exit 1
fi

# Generate patterns for T-Type 500 kHz antenna
echo "Generating T-Type 500 kHz patterns..."
if [ -f "t_type_500khz.ez" ]; then
    eznec t_type_500khz.ez
    if [ $? -eq 0 ]; then
        echo "✓ T-Type 500 kHz patterns generated successfully"
    else
        echo "✗ Failed to generate T-Type 500 kHz patterns"
    fi
else
    echo "✗ T-Type 500 kHz EZNEC file not found"
fi

# Generate patterns for Long Wire 2 MHz antenna
echo "Generating Long Wire 2 MHz patterns..."
if [ -f "long_wire_2mhz.ez" ]; then
    eznec long_wire_2mhz.ez
    if [ $? -eq 0 ]; then
        echo "✓ Long Wire 2 MHz patterns generated successfully"
    else
        echo "✗ Failed to generate Long Wire 2 MHz patterns"
    fi
else
    echo "✗ Long Wire 2 MHz EZNEC file not found"
fi

# Generate patterns for Inverted-L 630m antenna
echo "Generating Inverted-L 630m patterns..."
if [ -f "inverted_l_630m.ez" ]; then
    eznec inverted_l_630m.ez
    if [ $? -eq 0 ]; then
        echo "✓ Inverted-L 630m patterns generated successfully"
    else
        echo "✗ Failed to generate Inverted-L 630m patterns"
    fi
else
    echo "✗ Inverted-L 630m EZNEC file not found"
fi

# Generate patterns for Long Wire 2200m antenna
echo "Generating Long Wire 2200m patterns..."
if [ -f "long_wire_2200m.ez" ]; then
    eznec long_wire_2200m.ez
    if [ $? -eq 0 ]; then
        echo "✓ Long Wire 2200m patterns generated successfully"
    else
        echo "✗ Failed to generate Long Wire 2200m patterns"
    fi
else
    echo "✗ Long Wire 2200m EZNEC file not found"
fi

echo "Maritime HF antenna pattern generation complete!"
echo ""
echo "Generated patterns:"
echo "- T-Type 500 kHz (International distress frequency)"
echo "- Long Wire 2 MHz (Marine MF/HF-SSB radios)"
echo "- Inverted-L 630m (Maritime distress frequency)"
echo "- Long Wire 2200m (Maritime navigation)"
echo ""
echo "These patterns represent historical maritime HF antennas"
echo "used on ships before the GMDSS era (1990s-2000s)."

