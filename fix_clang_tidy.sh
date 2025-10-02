#!/bin/bash

# Fix Clang-Tidy configurations in all test scripts
# Replace overly broad checks with focused, practical ones

echo "🔧 Fixing Clang-Tidy configurations in test scripts..."

# Find all test scripts with problematic Clang-Tidy configurations
find test -name "*.sh" -exec grep -l "clang-tidy.*-checks='\*'" {} \; | while read -r file; do
    echo "Fixing: $file"
    
    # Replace the problematic Clang-Tidy configuration
    sed -i "s/clang-tidy -checks='\*' -header-filter='\.\*'/clang-tidy -checks='modernize-*,readability-*,performance-*,cppcoreguidelines-*' -header-filter='client\/mumble-plugin\/lib\/.*'/g" "$file"
    
    # Also fix any other variations
    sed -i "s/-checks='\*'/-checks='modernize-*,readability-*,performance-*,cppcoreguidelines-*'/g" "$file"
    sed -i "s/-header-filter='\.\*'/-header-filter='client\/mumble-plugin\/lib\/.*'/g" "$file"
done

echo "✅ Clang-Tidy configurations fixed!"
echo "📋 Changes made:"
echo "   - Replaced -checks='*' with focused checks"
echo "   - Replaced -header-filter='.*' with project-specific filter"
echo "   - This will reduce warnings from hundreds of thousands to manageable levels"
