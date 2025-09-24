#!/bin/bash

# Coastal Station HF Antenna Pattern Generation Script
# Generates radiation patterns for historical coastal station HF antennas

echo "Generating Coastal Station HF Antenna Patterns..."

# Set working directory
cd "$(dirname "$0")/antenna_patterns/Ground-based/coastal_stations"

# Check if EZNEC is available
if ! command -v eznec &> /dev/null; then
    echo "Error: EZNEC not found. Please install EZNEC to generate patterns."
    exit 1
fi

# Generate patterns for T-Type 500 kHz coastal antenna
echo "Generating T-Type 500 kHz coastal patterns..."
if [ -f "t_type_500khz_coastal.ez" ]; then
    eznec t_type_500khz_coastal.ez
    if [ $? -eq 0 ]; then
        echo "✓ T-Type 500 kHz coastal patterns generated successfully"
    else
        echo "✗ Failed to generate T-Type 500 kHz coastal patterns"
    fi
else
    echo "✗ T-Type 500 kHz coastal EZNEC file not found"
fi

# Generate patterns for Long Wire 2 MHz coastal antenna
echo "Generating Long Wire 2 MHz coastal patterns..."
if [ -f "long_wire_2mhz_coastal.ez" ]; then
    eznec long_wire_2mhz_coastal.ez
    if [ $? -eq 0 ]; then
        echo "✓ Long Wire 2 MHz coastal patterns generated successfully"
    else
        echo "✗ Failed to generate Long Wire 2 MHz coastal patterns"
    fi
else
    echo "✗ Long Wire 2 MHz coastal EZNEC file not found"
fi

# Generate patterns for Inverted-L 630m coastal antenna
echo "Generating Inverted-L 630m coastal patterns..."
if [ -f "inverted_l_630m_coastal.ez" ]; then
    eznec inverted_l_630m_coastal.ez
    if [ $? -eq 0 ]; then
        echo "✓ Inverted-L 630m coastal patterns generated successfully"
    else
        echo "✗ Failed to generate Inverted-L 630m coastal patterns"
    fi
else
    echo "✗ Inverted-L 630m coastal EZNEC file not found"
fi

# Generate patterns for Long Wire 2200m coastal antenna
echo "Generating Long Wire 2200m coastal patterns..."
if [ -f "long_wire_2200m_coastal.ez" ]; then
    eznec long_wire_2200m_coastal.ez
    if [ $? -eq 0 ]; then
        echo "✓ Long Wire 2200m coastal patterns generated successfully"
    else
        echo "✗ Failed to generate Long Wire 2200m coastal patterns"
    fi
else
    echo "✗ Long Wire 2200m coastal EZNEC file not found"
fi

echo "Coastal station HF antenna pattern generation complete!"
echo ""
echo "Generated patterns:"
echo "- T-Type 500 kHz (International distress frequency)"
echo "- Long Wire 2 MHz (Marine MF/HF-SSB radios)"
echo "- Inverted-L 630m (Maritime distress frequency)"
echo "- Long Wire 2200m (Maritime navigation)"
echo ""
echo "These patterns represent historical coastal station HF antennas"
echo "used for maritime communications before the GMDSS era (1990s-2000s)."
echo ""
echo "Key features:"
echo "- 30m height above ground (vs 10m on ships)"
echo "- Copper plates in sea water for ground system"
echo "- North-South and East-West ground orientation"
echo "- Higher power handling (2000-5000W vs 100-1000W on ships)"
echo "- No ATU required (properly tuned)"

