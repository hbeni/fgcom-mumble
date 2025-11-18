#!/bin/bash

echo "=== Quick Pattern Validation ==="

# Check aircraft patterns
echo "=== AIRCRAFT PATTERNS ==="
aircraft_count=$(find client/mumble-plugin/lib/antenna_patterns/aircraft -name "*.txt" | wc -l)
echo "Found $aircraft_count aircraft pattern files"

# Sample a few aircraft patterns
aircraft_sample=$(find client/mumble-plugin/lib/antenna_patterns/aircraft -name "*.txt" | head -3)
for file in $aircraft_sample; do
    if [ -f "$file" ]; then
        size=$(wc -c < "$file")
        lines=$(wc -l < "$file")
        if [ "$size" -gt 100 ] && [ "$lines" -gt 10 ]; then
            echo "✓ Valid: $(basename "$file") ($size bytes, $lines lines)"
        else
            echo "✗ Invalid: $(basename "$file") ($size bytes, $lines lines)"
        fi
    fi
done

# Check ground-based patterns
echo "=== GROUND-BASED PATTERNS ==="
ground_count=$(find client/mumble-plugin/lib/antenna_patterns/Ground-based -name "*.txt" | wc -l)
echo "Found $ground_count ground-based pattern files"

# Sample a few ground-based patterns
ground_sample=$(find client/mumble-plugin/lib/antenna_patterns/Ground-based -name "*.txt" | head -3)
for file in $ground_sample; do
    if [ -f "$file" ]; then
        size=$(wc -c < "$file")
        lines=$(wc -l < "$file")
        if [ "$size" -gt 100 ] && [ "$lines" -gt 10 ]; then
            echo "✓ Valid: $(basename "$file") ($size bytes, $lines lines)"
        else
            echo "✗ Invalid: $(basename "$file") ($size bytes, $lines lines)"
        fi
    fi
done

# Check military land patterns
echo "=== MILITARY LAND PATTERNS ==="
military_count=$(find client/mumble-plugin/lib/antenna_patterns/military-land -name "*.txt" | wc -l)
echo "Found $military_count military land pattern files"

# Sample a few military patterns
military_sample=$(find client/mumble-plugin/lib/antenna_patterns/military-land -name "*.txt" | head -3)
for file in $military_sample; do
    if [ -f "$file" ]; then
        size=$(wc -c < "$file")
        lines=$(wc -l < "$file")
        if [ "$size" -gt 100 ] && [ "$lines" -gt 10 ]; then
            echo "✓ Valid: $(basename "$file") ($size bytes, $lines lines)"
        else
            echo "✗ Invalid: $(basename "$file") ($size bytes, $lines lines)"
        fi
    fi
done

# Check marine patterns
echo "=== MARINE PATTERNS ==="
marine_count=$(find client/mumble-plugin/lib/antenna_patterns/Marine -name "*.txt" | wc -l)
echo "Found $marine_count marine pattern files"

# Sample a few marine patterns
marine_sample=$(find client/mumble-plugin/lib/antenna_patterns/Marine -name "*.txt" | head -3)
for file in $marine_sample; do
    if [ -f "$file" ]; then
        size=$(wc -c < "$file")
        lines=$(wc -l < "$file")
        if [ "$size" -gt 100 ] && [ "$lines" -gt 10 ]; then
            echo "✓ Valid: $(basename "$file") ($size bytes, $lines lines)"
        else
            echo "✗ Invalid: $(basename "$file") ($size bytes, $lines lines)"
        fi
    fi
done

echo "=== SUMMARY ==="
total_count=$((aircraft_count + ground_count + military_count + marine_count))
echo "Total pattern files: $total_count"
echo "Aircraft: $aircraft_count"
echo "Ground-based: $ground_count"
echo "Military Land: $military_count"
echo "Marine: $marine_count"
