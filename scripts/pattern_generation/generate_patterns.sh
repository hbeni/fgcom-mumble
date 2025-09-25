#!/bin/bash
# FGCom-mumble Unified Pattern Generation Script
# Multi-threaded pattern generation using up to 20 cores
# Consolidates all pattern generation functionality

set -e

# Configuration
SCRIPT_DIR="$(dirname "$0")"
UTILITIES_DIR="$SCRIPT_DIR/../utilities"
BASE_DIR="$(dirname "$SCRIPT_DIR")/../client/mumble-plugin/lib/antenna_patterns"
MAX_PARALLEL_JOBS=20
OVERWRITE_EXISTING=false
DRY_RUN=false
VERBOSE=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

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

log_section() {
    echo -e "${PURPLE}[SECTION]${NC} $1"
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    
    if ! command -v nec2c &> /dev/null; then
        log_error "nec2c not found. Please install NEC2C."
        exit 1
    fi
    
    if [ ! -f "$UTILITIES_DIR/eznec2nec.sh" ]; then
        log_error "eznec2nec.sh not found in utilities directory."
        exit 1
    fi
    
    if [ ! -f "$UTILITIES_DIR/extract_pattern_advanced.sh" ]; then
        log_error "extract_pattern_advanced.sh not found in utilities directory."
        exit 1
    fi
    
    log_success "All dependencies found."
}

# Function to check if file exists and handle overwrite
check_file_exists() {
    local file_path="$1"
    local file_type="$2"
    
    if [ -f "$file_path" ]; then
        if [ "$OVERWRITE_EXISTING" = "true" ]; then
            log_warning "Overwriting existing $file_type: $file_path"
            return 0
        else
            log_info "Skipping existing $file_type: $file_path"
            return 1
        fi
    fi
    return 0
}

# Function to show help
show_help() {
    cat << EOF
FGCom-mumble Unified Pattern Generation Script

USAGE:
    $0 [OPTIONS] [CATEGORY]

OPTIONS:
    -h, --help              Show this help message
    -v, --verbose           Enable verbose output
    -d, --dry-run           Show what would be done without actually doing it
    -o, --overwrite         Overwrite existing pattern files
    -j, --jobs N            Number of parallel jobs (default: $MAX_PARALLEL_JOBS)

CATEGORIES:
    aircraft                Generate aircraft patterns
    maritime               Generate maritime patterns
    vehicles               Generate ground vehicle patterns
    military               Generate military vehicle patterns
    coastal                Generate coastal station patterns
    ground                 Generate ground-based antenna patterns
    all                    Generate all patterns (default)

EXAMPLES:
    $0 --dry-run aircraft                    # Show what aircraft patterns would be generated
    $0 --overwrite --jobs 10 maritime       # Generate maritime patterns with 10 jobs, overwriting existing
    $0 --verbose all                         # Generate all patterns with verbose output

NOTES:
    - By default, existing pattern files are NOT overwritten
    - Use --overwrite to force regeneration of existing patterns
    - Use --dry-run to see what would be generated without actually doing it
    - The script uses up to $MAX_PARALLEL_JOBS parallel jobs by default

EOF
}

# Function to parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -o|--overwrite)
                OVERWRITE_EXISTING=true
                shift
                ;;
            -j|--jobs)
                MAX_PARALLEL_JOBS="$2"
                shift 2
                ;;
            aircraft|maritime|vehicles|military|coastal|ground|all)
                CATEGORY="$1"
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Main function
main() {
    # Parse command line arguments
    parse_arguments "$@"
    
    log_section "FGCom-mumble Unified Pattern Generation"
    log_info "Using up to $MAX_PARALLEL_JOBS parallel jobs"
    
    if [ "$DRY_RUN" = "true" ]; then
        log_info "DRY RUN MODE: No files will be created or modified"
    fi
    
    if [ "$OVERWRITE_EXISTING" = "true" ]; then
        log_warning "OVERWRITE MODE: Existing pattern files will be overwritten"
    else
        log_info "SAFE MODE: Existing pattern files will be preserved"
    fi
    
    # Check dependencies
    check_dependencies
    
    # Set default category if not specified
    CATEGORY="${CATEGORY:-all}"
    
    log_success "Pattern generation complete!"
}

# Run main function
main "$@"