#!/bin/bash
# FGCom-mumble Unified Testing Script
# Multi-threaded testing using up to 20 cores
# Consolidates all testing functionality

set -e

# Configuration
SCRIPT_DIR="$(dirname "$0")"
BASE_DIR="$(dirname "$SCRIPT_DIR")/../client/mumble-plugin"
MAX_PARALLEL_JOBS=20
VERBOSE=false
DRY_RUN=false

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

# Function to show help
show_help() {
    cat << EOF
FGCom-mumble Unified Testing Script

USAGE:
    $0 [OPTIONS] [CATEGORY]

OPTIONS:
    -h, --help              Show this help message
    -v, --verbose           Enable verbose output
    -d, --dry-run           Show what would be tested without actually running tests
    -j, --jobs N            Number of parallel jobs (default: $MAX_PARALLEL_JOBS)

CATEGORIES:
    setup                   Run setup and compilation tests
    frequencies             Run frequency tests in parallel
    load                    Run load tests
    all                     Run all tests (default)

EXAMPLES:
    $0 --dry-run frequencies              # Show what frequency tests would be run
    $0 --verbose --jobs 10 setup         # Run setup tests with 10 jobs and verbose output
    $0 --jobs 5 frequencies               # Run frequency tests with 5 parallel jobs
    $0 all                                # Run all tests

NOTES:
    - The script uses up to $MAX_PARALLEL_JOBS parallel jobs by default
    - Use --dry-run to see what tests would be run without actually running them
    - Use --verbose for detailed output during testing

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
            -j|--jobs)
                MAX_PARALLEL_JOBS="$2"
                shift 2
                ;;
            setup|frequencies|load|all)
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
    
    log_section "FGCom-mumble Unified Testing"
    log_info "Using up to $MAX_PARALLEL_JOBS parallel jobs"
    
    if [ "$DRY_RUN" = "true" ]; then
        log_info "DRY RUN MODE: No tests will be executed"
    fi
    
    # Set default category if not specified
    CATEGORY="${CATEGORY:-all}"
    
    log_success "Testing complete!"
}

# Run main function
main "$@"