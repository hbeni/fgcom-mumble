#!/bin/bash
# Fix wire definition formatting in EZNEC files
# Removes extra spaces between coordinates to ensure proper 8-field format

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
TOTAL_FILES=0
FIXED_FILES=0

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to fix wire formatting in a single file
fix_wire_formatting() {
    local file="$1"
    local changes=0
    
    log_info "Fixing wire formatting in: $file"
    
    # Create backup
    cp "$file" "$file.backup"
    
    # Fix wire definitions with extra spaces
    # Pattern: W###  -x.x  y.y  z.z  x.x  y.y  z.z  radius  segments
    # Should be: W### -x.x y.y z.z x.x y.y z.z radius segments
    
    # Use sed to remove extra spaces between coordinates
    sed -i 's/^W\([0-9][0-9][0-9]\)  \([0-9-]\)/W\1 \2/g' "$file"
    sed -i 's/^W\([0-9][0-9][0-9]\)  \([0-9-]\)/W\1 \2/g' "$file"  # Run twice to catch nested spaces
    
    # Count changes by comparing with backup
    if ! diff -q "$file" "$file.backup" > /dev/null; then
        changes=1
        log_success "Fixed wire formatting in: $file"
        ((FIXED_FILES++))
    else
        log_info "No formatting issues found in: $file"
    fi
    
    # Remove backup
    rm "$file.backup"
    
    return $changes
}

# Main function
main() {
    log_info "Starting wire formatting fix..."
    echo "=========================================="
    
    # Find all EZNEC files
    local eznec_files=($(find client/mumble-plugin/lib/antenna_patterns -name "*.ez" | sort))
    TOTAL_FILES=${#eznec_files[@]}
    
    log_info "Found $TOTAL_FILES EZNEC files to check"
    echo "=========================================="
    
    # Process each file
    for file in "${eznec_files[@]}"; do
        echo ""
        fix_wire_formatting "$file"
    done
    
    # Final summary
    echo ""
    echo "=========================================="
    log_info "WIRE FORMATTING FIX SUMMARY"
    echo "=========================================="
    log_info "Total files processed: $TOTAL_FILES"
    log_success "Files with formatting fixes: $FIXED_FILES"
    
    if [ "$FIXED_FILES" -gt 0 ]; then
        log_success "Wire formatting has been fixed in $FIXED_FILES files!"
    else
        log_info "No wire formatting issues found"
    fi
    
    return 0
}

# Run main function
main "$@"
