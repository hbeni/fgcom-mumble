#!/bin/bash

# Simple Pattern Validation Test
echo "=== Simple Pattern Validation Test ==="

# Test 1: Check if patterns exist
echo "Test 1: Pattern file existence"
pattern_count=$(find client/mumble-plugin/lib/antenna_patterns -name "*.txt" | wc -l)
echo "Found $pattern_count pattern files"

if [ "$pattern_count" -gt 0 ]; then
    echo "✓ PASS: Pattern files exist"
else
    echo "✗ FAIL: No pattern files found"
    exit 1
fi

# Test 2: Check file sizes
echo "Test 2: File size validation"
small_files=$(find client/mumble-plugin/lib/antenna_patterns -name "*.txt" -size -500c | wc -l)
echo "Files smaller than 500 bytes: $small_files"

if [ "$small_files" -eq 0 ]; then
    echo "✓ PASS: All files are properly sized"
else
    echo "✗ FAIL: Found $small_files files that are too small"
fi

# Test 3: Check headers
echo "Test 3: Header validation"
sample_files=$(find client/mumble-plugin/lib/antenna_patterns -name "*.txt" | head -5)
header_issues=0

for file in $sample_files; do
    if ! head -5 "$file" | grep -q "Radiation Pattern Data\|FGCom-mumble Far-Field Radiation Pattern"; then
        ((header_issues++))
        echo "✗ Invalid header in: $(basename "$file")"
    fi
done

if [ "$header_issues" -eq 0 ]; then
    echo "✓ PASS: All sample files have proper headers"
else
    echo "✗ FAIL: $header_issues files have invalid headers"
fi

# Test 4: Check categories
echo "Test 4: Category coverage"
categories=("aircraft" "Ground-based" "military-land" "Marine")
missing_categories=0

for category in "${categories[@]}"; do
    if [ -d "client/mumble-plugin/lib/antenna_patterns/$category" ]; then
        count=$(find "client/mumble-plugin/lib/antenna_patterns/$category" -name "*.txt" | wc -l)
        echo "✓ $category: $count files"
    else
        echo "✗ Missing category: $category"
        ((missing_categories++))
    fi
done

if [ "$missing_categories" -eq 0 ]; then
    echo "✓ PASS: All categories present"
else
    echo "✗ FAIL: $missing_categories categories missing"
fi

echo "=== Test Complete ==="
