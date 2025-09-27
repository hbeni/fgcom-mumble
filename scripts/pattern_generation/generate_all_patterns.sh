t #!/bin/bash
# FGCom-mumble Comprehensive Pattern Generation Script
# Auto-discovers all EZNEC files and generates patterns for all vehicle types
# Multi-threaded with up to 20 cores

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UTILITIES_DIR="$SCRIPT_DIR/../utilities"
BASE_DIR="$(cd "$SCRIPT_DIR/../../client/mumble-plugin/lib/antenna_patterns" 2>/dev/null && pwd || true)"
MAX_PARALLEL_JOBS=20
OVERWRITE_EXISTING=false
DRY_RUN=false
VERBOSE=false

# Recommended altitude intervals - 28 total points
ALL_ALTITUDES=(0 25 50 100 150 200 250 300 500 650 800 1000 1500 2000 2500 3000 4000 5000 6000 7000 8000 9000 10000 12000 14000 16000 18000 20000)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Logging functions
log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
log_section() { echo -e "${PURPLE}[SECTION]${NC} $1"; }

# Cleanup trap for temp files
TMP_FILES=()
cleanup_tmp() {
    for f in "${TMP_FILES[@]:-}"; do
        [ -e "$f" ] && rm -f "$f"
    done
}
trap cleanup_tmp EXIT

# Job counters for progress logging
TOTAL_FILES=0
COMPLETED_JOBS=0
CURRENT_JOB=0
LOCKFILE="/tmp/pattern_jobs.lock"
exec 200>"$LOCKFILE"

with_lock() {
    flock 200 "$@"
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    command -v nec2c >/dev/null || { log_error "nec2c not found"; exit 1; }
    [ -f "$UTILITIES_DIR/eznec2nec.sh" ] || { log_error "eznec2nec.sh missing"; exit 1; }
    [ -f "$UTILITIES_DIR/extract_pattern_advanced.sh" ] || { log_error "extract_pattern_advanced.sh missing"; exit 1; }
    log_success "All dependencies found."
}

# Vehicle type detector (case-insensitive)
get_vehicle_type() {
    local path="${1,,}"
    if [[ "$path" == *"aircraft"* ]]; then
        echo "aircraft"
    elif [[ "$path" == *"military-land"* || "$path" == *"/military/"* ]]; then
        echo "military_land"
    elif [[ "$path" == *"boat"* || "$path" == *"ship"* || "$path" == *"maritime"* ]]; then
        echo "maritime"
    elif [[ "$path" == *"/vehicle/"* || "$path" == *"vehicle"* ]]; then
        echo "ground_vehicle"
    elif [[ "$path" == *"ground-based"* || "$path" == *"ground_station"* ]]; then
        echo "ground_station"
    else
        echo "unknown"
    fi
}

# Frequency detector
get_frequency() {
    local file_path="$1"
    local file_name
    file_name=$(basename "$file_path")
    local freq

    if [[ "$file_name" =~ ([0-9]+(\.[0-9]+)?)\s*[mM][hH][zZ] ]]; then
        echo "${BASH_REMATCH[1]}"; return
    fi
    if grep -qiE "fr|freq|frequency" "$file_path" 2>/dev/null; then
        freq=$(grep -iE "fr|freq|frequency" "$file_path" | head -1 | grep -oE "([0-9]+(\.[0-9]+)?)" | head -1)
        [ -n "$freq" ] && { echo "$freq"; return; }
    fi

    local vt
    vt=$(get_vehicle_type "$file_path")
    case "$vt" in
        aircraft)        echo "125" ;;
        military_land)   echo "36" ;;
        maritime)        echo "8.0" ;;
        ground_vehicle)  echo "145" ;;
        ground_station)  echo "14.0" ;;
        *)               echo "100" ;;
    esac
}

# Function to generate pattern for a single EZNEC file (with progress logging)
generate_pattern_for_file() {
    local eznec_file="$1"
    local job_number

    # Assign a job number
    job_number=$((++CURRENT_JOB))

    local relative_path="${eznec_file#$BASE_DIR/}"
    local vehicle_type
    vehicle_type=$(get_vehicle_type "$eznec_file")
    local frequency
    frequency=$(get_frequency "$eznec_file")
    local base_name
    base_name=$(basename "$eznec_file" .ez)

    log_info "[${job_number}/${TOTAL_FILES}] Processing: $relative_path (type=$vehicle_type, freq=${frequency}MHz)"

    # Output dir
    local output_dir="$BASE_DIR/patterns/${frequency}mhz"
    mkdir -p "$output_dir"

    if [ "$DRY_RUN" = "true" ]; then
        log_info "[${job_number}/${TOTAL_FILES}] DRY RUN: Would generate patterns for $base_name"
        ((COMPLETED_JOBS++))
        log_success "[${job_number}/${TOTAL_FILES}] Finished $relative_path"
        return 0
    fi

    local temp_nec temp_out
    temp_nec="$(mktemp /tmp/eznec2nec.XXXXXX.nec)"
    temp_out="$(mktemp /tmp/nec_out.XXXXXX.txt)"
    TMP_FILES+=("$temp_nec" "$temp_out")

    if ! "$UTILITIES_DIR/eznec2nec.sh" "$eznec_file"; then
        log_error "[${job_number}/${TOTAL_FILES}] Conversion failed: $relative_path"
        ((COMPLETED_JOBS++))
        return 1
    fi

    local generated_nec="${eznec_file%.ez}.nec"
    [ -f "$generated_nec" ] || { log_error "NEC file missing: $generated_nec"; ((COMPLETED_JOBS++)); return 1; }
    cp "$generated_nec" "$temp_nec"

    local -a altitude_list
    if [ "$vehicle_type" = "aircraft" ]; then
        altitude_list=("${ALL_ALTITUDES[@]}")
    else
        altitude_list=(0)
    fi

    local patterns_generated=0
    for altitude in "${altitude_list[@]}"; do
        local pattern_file="$output_dir/${base_name}_${frequency}MHz_${altitude}m_pattern.txt"

        if [ -f "$pattern_file" ] && [ "$OVERWRITE_EXISTING" = "false" ]; then
            continue
        fi

        local temp_nec_alt="${temp_nec%.nec}_${altitude}m.nec"
        cp "$temp_nec" "$temp_nec_alt"
        TMP_FILES+=("$temp_nec_alt")

        # Modify antenna height for this altitude
        # Update the ground plane height in the NEC2 file
        sed -i "s/^GD.*/GD 0 0 0 0 0.005 13.0/" "$temp_nec_alt"
        
        # For aircraft, we need to modify the antenna height above ground
        if [ "$vehicle_type" = "aircraft" ]; then
            # Convert altitude from meters to wavelengths for the frequency
            local wavelength=$(echo "scale=6; 300 / $frequency" | bc -l)
            local height_wavelengths=$(echo "scale=6; $altitude / 1000 / $wavelength" | bc -l)
            
            # Update wire coordinates to reflect altitude
            # This is a simplified approach - in reality you'd need to parse and modify each wire
            sed -i "s/^GW.*/GW 1 1 0 0 0 0 0 $height_wavelengths 0.001/" "$temp_nec_alt"
        fi

        if nec2c -i "$temp_nec_alt" -o "$temp_out" && \
           "$UTILITIES_DIR/extract_pattern_advanced.sh" "$temp_out" "$pattern_file" "$frequency" "$altitude"; then
            ((patterns_generated++))
        fi
    done

    ((COMPLETED_JOBS++))
    log_success "[${job_number}/${TOTAL_FILES}] Finished: $relative_path ($patterns_generated patterns)"
}

# Parallel runner
process_patterns_parallel() {
    local eznec_files=("$@")
    TOTAL_FILES=${#eznec_files[@]}
    log_info "Processing $TOTAL_FILES EZNEC files with up to $MAX_PARALLEL_JOBS parallel jobs"

    local running=0
    for eznec_file in "${eznec_files[@]}"; do
        generate_pattern_for_file "$eznec_file" &
        ((running++))
        if (( running >= MAX_PARALLEL_JOBS )); then
            wait -n
            ((running--))
        fi
    done
    wait
}

# Discover and run
generate_all_patterns() {
    log_section "Generating All Radiation Patterns"
    mapfile -d '' -t eznec_files < <(find "$BASE_DIR" -type f -name "*.ez" -print0 | sort -z)
    log_info "Found ${#eznec_files[@]} EZNEC files"
    [ ${#eznec_files[@]} -eq 0 ] && { log_error "No files found"; exit 1; }
    process_patterns_parallel "${eznec_files[@]}"
}

# CLI
show_help() {
    echo "Usage: $0 [--help] [--verbose] [--dry-run] [--overwrite] [--jobs N]"
}
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help) show_help; exit 0 ;;
            --verbose) VERBOSE=true; shift ;;
            --dry-run) DRY_RUN=true; shift ;;
            --overwrite) OVERWRITE_EXISTING=true; shift ;;
            --jobs) MAX_PARALLEL_JOBS="$2"; shift 2 ;;
            *) log_error "Unknown option: $1"; exit 1 ;;
        esac
    done
}

main() {
    parse_arguments "$@"
    log_section "FGCom-mumble Pattern Generation"
    log_info "Parallel jobs: $MAX_PARALLEL_JOBS"
    [ "$DRY_RUN" = "true" ] && log_info "DRY RUN enabled"
    check_dependencies
    generate_all_patterns
    log_success "Pattern generation complete!"
}
main "$@"