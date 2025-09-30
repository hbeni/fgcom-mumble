#!/bin/bash

# Efficient Pattern Validation Script
# Validates pattern files by category with sampling

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
    
    if [ ! -f "$file" ]; then
        return 1
    fi
    
    # Check file size
    local file_size=$(wc -c < "$file")
    if [ "$file_size" -lt 100 ]; then
        return 1
    fi
    
    # Check for required header
    if ! head -5 "$file" | grep -q "FGCom-mumble Far-Field Radiation Pattern"; then
        return 1
    fi
    
    # Check for data lines
    local data_lines=$(grep -v "^#" "$file" | grep -v "^$" | wc -l)
    if [ "$data_lines" -lt 10 ]; then
        return 1
    fi
    
    return 0
}

# Validate patterns in a category with sampling
validate_category() {
    local category="$1"
    local pattern_dir="$2"
    local sample_size="$3"
    
    log_info "=== $category PATTERNS ==="
    
    if [ ! -d "$pattern_dir" ]; then
        log_warning "Directory not found: $pattern_dir"
        return 0
    fi
    
    # Find all pattern files
    local all_files=$(find "$pattern_dir" -name "*.txt" -type f | sort)
    local total_files=$(echo "$all_files" | wc -l)
    
    if [ "$total_files" -eq 0 ]; then
        log_warning "No pattern files found in: $pattern_dir"
        return 0
    fi
    
    log_info "Found $total_files pattern files in $category"
    
    # Sample files for validation
    local sample_files
    if [ "$total_files" -le "$sample_size" ]; then
        sample_files="$all_files"
    else
        sample_files=$(echo "$all_files" | head -"$sample_size")
    fi
    
    local valid_count=0
    local invalid_count=0
    local checked_count=0
    
    while IFS= read -r file; do
        if [ -n "$file" ]; then
            ((checked_count++))
            ((TOTAL_PATTERNS++))
            
            if validate_pattern_file "$file"; then
                ((valid_count++))
                ((VALID_PATTERNS++))
            else
                ((invalid_count++))
                ((INVALID_PATTERNS++))
                log_error "Invalid pattern: ${file#client/mumble-plugin/lib/antenna_patterns/}"
            fi
        fi
    done <<< "$sample_files"
    
    log_info "Checked $checked_count files (sampled from $total_files)"
    log_success "Valid: $valid_count"
    if [ "$invalid_count" -gt 0 ]; then
        log_error "Invalid: $invalid_count"
    fi
    
    # Calculate success rate for this category
    local success_rate=0
    if [ "$checked_count" -gt 0 ]; then
        success_rate=$((valid_count * 100 / checked_count))
    fi
    log_info "Success rate: $success_rate%"
}

# Main validation function
main() {
    log_info "=== FGCom-mumble Pattern Validation (Efficient) ==="
    log_info "Validating patterns with sampling for efficiency..."
    
    local base_dir="client/mumble-plugin/lib/antenna_patterns"
    
    # Validate each category with sampling
    validate_category "AIRCRAFT" "$base_dir/aircraft" 50
    validate_category "GROUND-BASED" "$base_dir/Ground-based" 30
    validate_category "MILITARY LAND" "$base_dir/military-land" 50
    validate_category "MARINE" "$base_dir/Marine" 30
    
    # Summary
    log_info "=== VALIDATION SUMMARY ==="
    log_info "Total patterns checked: $TOTAL_PATTERNS"
    log_success "Valid patterns: $VALID_PATTERNS"
    log_error "Invalid patterns: $INVALID_PATTERNS"
    
    local success_rate=0
    if [ "$TOTAL_PATTERNS" -gt 0 ]; then
        success_rate=$((VALID_PATTERNS * 100 / TOTAL_PATTERNS))
    fi
    
    log_info "Overall success rate: $success_rate%"
    
    if [ "$INVALID_PATTERNS" -eq 0 ]; then
        log_success "All sampled patterns are valid!"
        exit 0
    else
        log_error "Pattern validation found $INVALID_PATTERNS invalid patterns"
        exit 1
    fi
}

# Run main function
main "$@"
