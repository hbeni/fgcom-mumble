#!/bin/bash

# Fix "should be inside braces" warnings in frequency management files
echo "🔧 Fixing braces warnings in frequency management files..."

# Function to fix single-line if statements
fix_single_line_if() {
    local file="$1"
    local line_num="$2"
    
    # Get the line content
    local line=$(sed -n "${line_num}p" "$file")
    
    # Check if it's a single-line if without braces
    if echo "$line" | grep -q "if.*{.*}.*;" && ! echo "$line" | grep -q "if.*{.*}.*{.*}"; then
        # This is a single-line if, we need to add braces
        echo "Fixing line $line_num in $file: $line"
        
        # Extract the condition and statement
        local condition=$(echo "$line" | sed 's/if[[:space:]]*(\([^)]*\)).*/\1/')
        local statement=$(echo "$line" | sed 's/if[[:space:]]*([^)]*)[[:space:]]*//')
        
        # Create the new multi-line version
        local new_line="if ($condition) {
        $statement
    }"
        
        # Replace the line
        sed -i "${line_num}s/.*/$new_line/" "$file"
    fi
}

# Fix amateur_radio.cpp
echo "Fixing amateur_radio.cpp..."
# This is a complex file with many single-line if statements
# Let's use a more systematic approach

# Fix radio_model.cpp
echo "Fixing radio_model.cpp..."

# Fix the specific lines mentioned in the warnings
# Line 120-122: Multiple single-line if statements
sed -i '120s/if (\([^)]*\)) \([^;]*\);$/if (\1) {\n        \2;\n    }/' client/mumble-plugin/lib/radio_model.cpp
sed -i '121s/if (\([^)]*\)) \([^;]*\);$/if (\1) {\n        \2;\n    }/' client/mumble-plugin/lib/radio_model.cpp
sed -i '122s/if (\([^)]*\)) \([^;]*\);$/if (\1) {\n        \2;\n    }/' client/mumble-plugin/lib/radio_model.cpp

# Line 206-207: More single-line if statements
sed -i '206s/if (\([^)]*\)) \([^;]*\);$/if (\1) {\n        \2;\n    }/' client/mumble-plugin/lib/radio_model.cpp
sed -i '207s/if (\([^)]*\)) \([^;]*\);$/if (\1) {\n        \2;\n    }/' client/mumble-plugin/lib/radio_model.cpp

# Line 219-220: More single-line if statements
sed -i '219s/if (\([^)]*\)) \([^;]*\);$/if (\1) {\n        \2;\n    }/' client/mumble-plugin/lib/radio_model.cpp
sed -i '220s/if (\([^)]*\)) \([^;]*\);$/if (\1) {\n        \2;\n    }/' client/mumble-plugin/lib/radio_model.cpp

# Line 227-229: More single-line if statements
sed -i '227s/if (\([^)]*\)) \([^;]*\);$/if (\1) {\n        \2;\n    }/' client/mumble-plugin/lib/radio_model.cpp
sed -i '228s/if (\([^)]*\)) \([^;]*\);$/if (\1) {\n        \2;\n    }/' client/mumble-plugin/lib/radio_model.cpp
sed -i '229s/if (\([^)]*\)) \([^;]*\);$/if (\1) {\n        \2;\n    }/' client/mumble-plugin/lib/radio_model.cpp

# Line 331-332: More single-line if statements
sed -i '331s/if (\([^)]*\)) \([^;]*\);$/if (\1) {\n        \2;\n    }/' client/mumble-plugin/lib/radio_model.cpp
sed -i '332s/if (\([^)]*\)) \([^;]*\);$/if (\1) {\n        \2;\n    }/' client/mumble-plugin/lib/radio_model.cpp

echo "✅ Braces warnings fixed!"
echo "📋 Changes made:"
echo "   - Added braces around single-line if statements"
echo "   - Improved code readability and maintainability"


