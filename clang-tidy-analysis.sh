#!/bin/bash
# Comprehensive clang-tidy analysis script for FGCom-mumble
# This script addresses the 150,000 warnings systematically

set -e

echo "🔍 FGCom-mumble Clang-Tidy Analysis Strategy"
echo "=============================================="

# Step 1: Create compilation database
echo "📝 Step 1: Creating compilation database..."
cd /home/haaken/github-projects/fgcom-mumble/client/mumble-plugin

# Try to create compilation database
if [ ! -f compile_commands.json ]; then
    echo "Creating compilation database with bear..."
    bear -- make clean 2>/dev/null || true
    bear -- make plugin 2>/dev/null || {
        echo "⚠️  Build failed, creating manual compilation database..."
        # Create a basic compilation database manually
        cat > compile_commands.json << 'EOF'
[
  {
    "directory": "/home/haaken/github-projects/fgcom-mumble/client/mumble-plugin",
    "command": "g++ -Wall -O3 -I. -I./lib -DENABLE_OPENINFRAMAP -I./lib/openssl/include/ -L./lib/openssl/ -lssl -lcrypto -DSSLFLAGS -c fgcom-mumble.cpp",
    "file": "fgcom-mumble.cpp"
  }
]
EOF
    }
fi

# Step 2: Run focused analysis
echo "Step 2: Running focused clang-tidy analysis..."

# Critical bugs and security issues only
echo "Analyzing critical bugs and security issues..."
clang-tidy --checks='clang-analyzer-*,bugprone-*,cert-*' \
    --header-filter='^(?!.*(?:openssl|boost|mumble|catch2|json|httplib|DspFilters)).*$' \
    fgcom-mumble.cpp 2>&1 | tee critical-issues.txt

# Count warnings by type
echo "Step 3: Analyzing warning distribution..."
echo "Critical issues found:"
grep -c "warning:" critical-issues.txt || echo "0"

# Step 4: Style warning analysis (if build succeeds)
echo "Step 4: Analyzing style warnings..."
if clang-tidy --checks='readability-identifier-naming,modernize-use-auto,modernize-use-nullptr' \
    --header-filter='^(?!.*(?:openssl|boost|mumble|catch2|json|httplib|DspFilters)).*$' \
    fgcom-mumble.cpp 2>&1 | head -20 > style-warnings.txt; then
    
    echo "Style warnings sample:"
    head -10 style-warnings.txt
    echo "Total style warnings: $(grep -c "warning:" style-warnings.txt || echo "0")"
else
    echo "⚠️  Style analysis skipped due to compilation issues"
fi

# Step 5: Generate focused configuration
echo "⚙️  Step 5: Creating focused .clang-tidy configuration..."
cat > .clang-tidy << 'EOF'
# Focused clang-tidy configuration for FGCom-mumble
# Prioritizes critical issues over style warnings

Checks: >
  # Critical bug detection (HIGH PRIORITY)
  clang-analyzer-*,
  bugprone-*,
  cert-*,
  
  # Performance issues (MEDIUM PRIORITY)  
  performance-*,
  
  # Suppress style warnings that cause massive counts
  -readability-identifier-naming,
  -modernize-use-auto,
  -modernize-use-nullptr,
  -modernize-use-override,
  -readability-braces-around-statements,
  -modernize-pass-by-value,
  -readability-implicit-bool-conversion,
  -cppcoreguidelines-avoid-magic-numbers,
  -cppcoreguidelines-avoid-c-arrays,
  -cppcoreguidelines-pro-bounds-*,
  -cppcoreguidelines-pro-type-*,
  -google-*,
  -misc-non-private-member-variables-in-classes,
  -misc-const-correctness

# Suppress warnings from system headers
SystemHeaders: false

# Suppress warnings from third-party libraries
HeaderFilterRegex: '^(?!.*(?:openssl|boost|mumble|catch2|json|httplib|DspFilters)).*$'

# Suppress warnings from test files
SourceFilterRegex: '^(?!.*test).*$'
EOF

echo "Analysis complete!"
echo "Results saved to:"
echo "   - critical-issues.txt (critical bugs and security issues)"
echo "   - style-warnings.txt (style warning sample)"
echo "   - .clang-tidy (focused configuration)"
echo ""
echo "Next steps:"
echo "1. Fix critical issues in critical-issues.txt"
echo "2. Use .clang-tidy for focused analysis"
echo "3. Address DSP library namespace conflicts"
echo "4. Gradually enable style checks for specific files"
