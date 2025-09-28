#!/bin/bash

# Comprehensive Pattern Validation Script
# Validates all antenna radiation pattern files across all vehicle types

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
TOTAL_PATTERNS=0
VALID_PATTERNS=0
INVALID_PATTERNS=0
MISSING_PATTERNS=0

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

# Validate a single pattern file
validate_pattern_file() {
    local file="$1"
    local relative_path="${file#client/mumble-plugin/lib/antenna_patterns/}"
    
    if [ ! -f "$file" ]; then
        log_error "Pattern file missing: $relative_path"
        ((MISSING_PATTERNS++))
        return 1
    fi
    
    # Check file size
    local file_size=$(wc -c < "$file")
    if [ "$file_size" -lt 100 ]; then
        log_error "Pattern file too small ($file_size bytes): $relative_path"
        ((INVALID_PATTERNS++))
        return 1
    fi
    
    # Check for required header
    if ! head -5 "$file" | grep -q "FGCom-mumble Far-Field Radiation Pattern"; then
        log_error "Missing required header in: $relative_path"
        ((INVALID_PATTERNS++))
        return 1
    fi
    
    # Check for frequency information
    if ! head -10 "$file" | grep -q "Frequency:"; then
        log_error "Missing frequency information in: $relative_path"
        ((INVALID_PATTERNS++))
        return 1
    fi
    
    # Check for data lines (not just comments)
    local data_lines=$(grep -v "^#" "$file" | grep -v "^$" | wc -l)
    if [ "$data_lines" -lt 10 ]; then
        log_error "Insufficient data lines ($data_lines) in: $relative_path"
        ((INVALID_PATTERNS++))
        return 1
    fi
    
    # Check for valid gain values (should be numeric)
    local invalid_gains=$(grep -v "^#" "$file" | grep -v "^$" | awk '{print $3}' | grep -v "^[+-]*[0-9]*\.*[0-9]*$" | wc -l)
    if [ "$invalid_gains" -gt 0 ]; then
        log_warning "Found $invalid_gains invalid gain values in: $relative_path"
    fi
    
    log_success "Valid pattern: $relative_path ($file_size bytes, $data_lines data lines)"
    ((VALID_PATTERNS++))
    return 0
}

# Validate patterns in a directory
validate_directory() {
    local dir="$1"
    local category="$2"
    
    if [ ! -d "$dir" ]; then
        log_warning "Directory not found: $dir"
        return 0
    fi
    
    log_info "Validating $category patterns in: $dir"
    
    # Find all .txt pattern files
    local pattern_files=$(find "$dir" -name "*.txt" -type f | sort)
    
    if [ -z "$pattern_files" ]; then
        log_warning "No pattern files found in: $dir"
        return 0
    fi
    
    local count=0
    while IFS= read -r file; do
        if [ -n "$file" ]; then
            ((TOTAL_PATTERNS++))
            ((count++))
            validate_pattern_file "$file"
        fi
    done <<< "$pattern_files"
    
    log_info "Found $count pattern files in $category"
}

# Main validation function
main() {
    log_info "=== FGCom-mumble Pattern Validation ==="
    log_info "Starting comprehensive pattern validation..."
    
    local base_dir="client/mumble-plugin/lib/antenna_patterns"
    
    # Validate Aircraft patterns
    log_info "=== AIRCRAFT PATTERNS ==="
    validate_directory "$base_dir/aircraft" "Aircraft"
    
    # Validate Ground-based patterns
    log_info "=== GROUND-BASED PATTERNS ==="
    validate_directory "$base_dir/Ground-based" "Ground-based"
    
    # Validate Military Land patterns
    log_info "=== MILITARY LAND PATTERNS ==="
    validate_directory "$base_dir/military-land" "Military Land"
    
    # Validate Marine patterns
    log_info "=== MARINE PATTERNS ==="
    validate_directory "$base_dir/Marine" "Marine"
    
    # Summary
    log_info "=== VALIDATION SUMMARY ==="
    log_info "Total patterns found: $TOTAL_PATTERNS"
    log_success "Valid patterns: $VALID_PATTERNS"
    log_error "Invalid patterns: $INVALID_PATTERNS"
    log_warning "Missing patterns: $MISSING_PATTERNS"
    
    local success_rate=0
    if [ "$TOTAL_PATTERNS" -gt 0 ]; then
        success_rate=$((VALID_PATTERNS * 100 / TOTAL_PATTERNS))
    fi
    
    log_info "Success rate: $success_rate%"
    
    if [ "$INVALID_PATTERNS" -eq 0 ] && [ "$MISSING_PATTERNS" -eq 0 ]; then
        log_success "All patterns are valid!"
        exit 0
    else
        log_error "Pattern validation failed with $INVALID_PATTERNS invalid and $MISSING_PATTERNS missing patterns"
        exit 1
    fi
}

# Run main function
main "$@"
