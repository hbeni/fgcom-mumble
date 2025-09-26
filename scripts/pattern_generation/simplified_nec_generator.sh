#!/bin/bash
# FGCom-mumble Comprehensive Attitude Pattern Generation Script
# Generates radiation patterns for all altitude/roll/pitch combinations
# Multi-threaded with up to 20 cores

set -euo pipefail

# Process management
declare -a BACKGROUND_PIDS=()
declare -a TMP_FILES=()

# Cleanup function to kill all background processes
cleanup() {
    echo "Cleaning up background processes..."
    for pid in "${BACKGROUND_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            echo "Killing process $pid"
            kill -TERM "$pid" 2>/dev/null || true
            sleep 1
            if kill -0 "$pid" 2>/dev/null; then
                echo "Force killing process $pid"
                kill -KILL "$pid" 2>/dev/null || true
            fi
        fi
    done
    
    # Clean up temporary files
    for tmp_file in "${TMP_FILES[@]}"; do
        rm -f "$tmp_file" 2>/dev/null || true
    done
    
    echo "Cleanup completed"
    exit 1
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM EXIT

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UTILITIES_DIR="$SCRIPT_DIR/../utilities"
BASE_DIR="$(cd "$SCRIPT_DIR/../../client/mumble-plugin/lib/antenna_patterns" 2>/dev/null && pwd || true)"
MAX_PARALLEL_JOBS=10  # Reduced from 20 to prevent system overload
OVERWRITE_EXISTING=false
DRY_RUN=false
VERBOSE=false
SAFETY_MODE=true  # Enable safety mode by default

# Altitude intervals for aircraft (28 points)
AIRCRAFT_ALTITUDES=(0 25 50 100 150 200 250 300 500 650 800 1000 1500 2000 2500 3000 4000 5000 6000 7000 8000 9000 10000 12000 14000 16000 18000 20000)

# Roll angles (15 points)
ROLL_ANGLES=(-180 -120 -90 -60 -45 -30 -15 0 15 30 45 60 90 120 180)

# Pitch angles (13 points)
PITCH_ANGLES=(-120 -90 -60 -45 -30 -15 0 15 30 45 60 90 120)

# Ground vehicles/ships use only 0m altitude
GROUND_ALTITUDES=(0)

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

# Job counters for progress logging
TOTAL_COMBINATIONS=0
COMPLETED_JOBS=0
CURRENT_JOB=0

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    command -v nec2c >/dev/null || { log_error "nec2c not found"; exit 1; }
    command -v bc >/dev/null || { log_error "bc not found"; exit 1; }
    [ -f "$UTILITIES_DIR/extract_pattern_advanced.sh" ] || { log_error "extract_pattern_advanced.sh missing"; exit 1; }
    log_success "All dependencies found."
}

# Vehicle type detector
get_vehicle_type() {
    local path="${1,,}"
    echo "DEBUG: Processing path: $path" >&2
    if [[ "$path" == *"aircraft"* ]]; then
        echo "aircraft"
    elif [[ "$path" == *"military-land"* || "$path" == *"/military/"* ]]; then
        echo "military_land"
    elif [[ "$path" == *"boat"* || "$path" == *"ship"* || "$path" == *"marine"* ]]; then
        echo "marine"
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

    # Try to extract from filename first
    if [[ "$file_name" =~ ([0-9]+(\.[0-9]+)?)\s*[mM][hH][zZ] ]]; then
        echo "${BASH_REMATCH[1]}"; return
    fi

    # Try to extract from NEC FR command (most reliable for NEC files)
    if [ -f "$file_path" ]; then
        freq=$(grep "^FR" "$file_path" 2>/dev/null | head -1 | awk '{print $6}')
        if [[ "$freq" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
            echo "$freq"; return
        fi
    fi

    # Default based on vehicle type
    local vt
    vt=$(get_vehicle_type "$file_path")
    case "$vt" in
        aircraft)        echo "125" ;;
        military_land)   echo "36" ;;
        marine)          echo "8.0" ;;
        ground_vehicle)  echo "145" ;;
        ground_station)  echo "14.0" ;;
        *)               echo "100" ;;
    esac
}

# Get vehicle name from path
get_vehicle_name() {
    local file_path="$1"
    local dir_name
    dir_name=$(dirname "$file_path")
    basename "$dir_name"
}

# Modify NEC file for specific attitude and altitude
modify_nec_for_attitude() {
    local input_nec="$1"
    local output_nec="$2"
    local altitude_m="$3"
    local roll_deg="$4"
    local pitch_deg="$5"
    local frequency="$6"

    # Copy original file
    cp "$input_nec" "$output_nec"

    # Convert angles to radians
    local roll_rad=$(echo "scale=6; $roll_deg * 3.14159265359 / 180" | bc -l)
    local pitch_rad=$(echo "scale=6; $pitch_deg * 3.14159265359 / 180" | bc -l)

    # Convert altitude to wavelengths
    local wavelength=$(echo "scale=6; 300 / $frequency" | bc -l)
    local height_wavelengths=$(echo "scale=6; $altitude_m / 1000 / $wavelength" | bc -l)

    # Modify ground plane
    sed -i "s/^GD.*/GD 0 0 0 0 0.005 13.0/" "$output_nec"

    # Apply rotation matrix to wire coordinates (simplified approach)
    # This is a basic implementation - more sophisticated geometry transformation needed
    awk -v alt="$height_wavelengths" -v roll="$roll_rad" -v pitch="$pitch_rad" '
    /^GW/ {
        # Basic coordinate transformation for attitude
        # This is simplified - real implementation needs full 3D rotation matrices
        if (NF >= 10) {
            x1 = $4; y1 = $5; z1 = $6 + alt
            x2 = $7; y2 = $8; z2 = $9 + alt

            # Apply basic pitch rotation (around Y axis)
            new_x1 = x1 * cos(pitch) + z1 * sin(pitch)
            new_z1 = -x1 * sin(pitch) + z1 * cos(pitch)
            new_x2 = x2 * cos(pitch) + z2 * sin(pitch)
            new_z2 = -x2 * sin(pitch) + z2 * cos(pitch)

            # Apply basic roll rotation (around X axis)
            new_y1 = y1 * cos(roll) - new_z1 * sin(roll)
            new_z1 = y1 * sin(roll) + new_z1 * cos(roll)
            new_y2 = y2 * cos(roll) - new_z2 * sin(roll)
            new_z2 = y2 * sin(roll) + new_z2 * cos(roll)

            printf "GW %s %s %s %.6f %.6f %.6f %.6f %.6f %.6f %.6f\n",
                   $2, $3, $4, new_x1, new_y1, new_z1, new_x2, new_y2, new_z2, $10
        } else {
            print $0
        }
    }
    !/^GW/ { print $0 }
    ' "$output_nec" > "${output_nec}.tmp" && mv "${output_nec}.tmp" "$output_nec"
}

# Generate pattern for specific attitude combination
generate_attitude_pattern() {
    local nec_file="$1"
    local altitude="$2"
    local roll="$3"
    local pitch="$4"

    local vehicle_name
    vehicle_name=$(get_vehicle_name "$nec_file")
    local frequency
    frequency=$(get_frequency "$nec_file")
    local base_name
    base_name=$(basename "$nec_file" .nec)

    # Determine altitude band based on altitude
    local altitude_band
    if [ "$altitude" -le 300 ]; then
        altitude_band="ground_effects"
    elif [ "$altitude" -le 1500 ]; then
        altitude_band="boundary_layer"
    else
        altitude_band="free_space"
    fi
    
    # Create output directory structure
    local output_dir="$BASE_DIR/$(dirname "${nec_file#$BASE_DIR/}")/patterns/${frequency}mhz/${altitude_band}"
    mkdir -p "$output_dir"

    # Generate pattern filename
    local pattern_file="$output_dir/${altitude}m_roll_${roll}_pitch_${pitch}.txt"

    if [ -f "$pattern_file" ] && [ "$OVERWRITE_EXISTING" = "false" ]; then
        return 0
    fi

    if [ "$DRY_RUN" = "true" ]; then
        echo "    Would generate: $(basename "$pattern_file")"
        return 0
    fi

    # Create temporary NEC file with attitude modifications
    local temp_nec="$(mktemp /tmp/attitude_XXXXXX.nec)"
    local temp_out="$(mktemp /tmp/nec_out_XXXXXX.txt)"

    # Modify NEC file for this attitude
    modify_nec_for_attitude "$nec_file" "$temp_nec" "$altitude" "$roll" "$pitch" "$frequency"

    # Run NEC2 simulation
    if nec2c -i "$temp_nec" -o "$temp_out" 2>/dev/null && \
       "$UTILITIES_DIR/extract_pattern_advanced.sh" "$temp_out" "$pattern_file" "$frequency" "$altitude" 2>/dev/null; then
        local success=true
    else
        local success=false
    fi

    # Cleanup temp files
    rm -f "$temp_nec" "$temp_out" 2>/dev/null

    if [ "$success" = true ]; then
        [ "$VERBOSE" = "true" ] && log_info "Generated: ${altitude}m roll_${roll} pitch_${pitch}"
        return 0
    else
        [ "$VERBOSE" = "true" ] && log_warning "Failed: ${altitude}m roll_${roll} pitch_${pitch}"
        return 1
    fi
}

# Process all attitude combinations for a single NEC file
process_nec_file() {
    local nec_file="$1"
    local job_number=$((++CURRENT_JOB))

    local relative_path="${nec_file#$BASE_DIR/}"
    local vehicle_type
    vehicle_type=$(get_vehicle_type "$nec_file")
    local frequency
    frequency=$(get_frequency "$nec_file")

    log_info "[${job_number}] Processing: $relative_path (type=$vehicle_type, freq=${frequency}MHz)"

    # Select altitude list based on vehicle type
    local -a altitude_list
    if [ "$vehicle_type" = "aircraft" ]; then
        altitude_list=("${AIRCRAFT_ALTITUDES[@]}")
    else
        altitude_list=("${GROUND_ALTITUDES[@]}")
    fi

    local patterns_generated=0
    local total_combinations=$((${#altitude_list[@]} * ${#ROLL_ANGLES[@]} * ${#PITCH_ANGLES[@]}))

    log_info "[${job_number}] Will generate $total_combinations attitude patterns"

    # Add timeout protection - if this takes too long, kill it
    local timeout_seconds=3600  # 1 hour timeout per file
    (
        # Generate all attitude combinations
        local combination_count=0
        for altitude in "${altitude_list[@]}"; do
            for roll in "${ROLL_ANGLES[@]}"; do
                for pitch in "${PITCH_ANGLES[@]}"; do
                    ((combination_count++))
                    if [ $((combination_count % 100)) -eq 0 ] || [ $combination_count -eq 1 ]; then
                        log_info "[${job_number}] Progress: $combination_count/$total_combinations (${altitude}m, roll=${roll}°, pitch=${pitch}°)"
                    fi
                    if generate_attitude_pattern "$nec_file" "$altitude" "$roll" "$pitch"; then
                        ((patterns_generated++))
                    fi
                done
            done
        done
        
        ((COMPLETED_JOBS++))
        log_success "[${job_number}] Finished: $relative_path ($patterns_generated/$total_combinations patterns)"
    ) &
    
    local process_pid=$!
    
    # Wait for completion with timeout
    if timeout "$timeout_seconds" wait "$process_pid"; then
        log_info "[${job_number}] Completed successfully"
    else
        log_error "[${job_number}] Process timed out after ${timeout_seconds}s - killing"
        kill -TERM "$process_pid" 2>/dev/null || true
        sleep 2
        kill -KILL "$process_pid" 2>/dev/null || true
        return 1
    fi
}

# Sequential processing (for reliable output)
process_patterns_sequential() {
    local nec_files=("$@")
    local total_files=${#nec_files[@]}

    log_info "Starting sequential processing of $total_files files"

    # Calculate total combinations
    local aircraft_files=0
    local ground_files=0

    echo "DEBUG: Starting vehicle type classification loop" >&2

    for nec_file in "${nec_files[@]}"; do
        echo "DEBUG: Processing file: $nec_file" >&2
        local vehicle_type
        vehicle_type=$(get_vehicle_type "$nec_file")
        log_info "File: $(basename "$nec_file") -> Type: $vehicle_type"

        if [ "$vehicle_type" = "aircraft" ]; then
            ((++aircraft_files))
            echo "DEBUG: Incremented aircraft_files to $aircraft_files" >&2
        else
            ((++ground_files))
            echo "DEBUG: Incremented ground_files to $ground_files" >&2
        fi
    done

    echo "DEBUG: Finished classification loop. Aircraft: $aircraft_files, Ground: $ground_files" >&2

    local aircraft_combinations=$((aircraft_files * ${#AIRCRAFT_ALTITUDES[@]} * ${#ROLL_ANGLES[@]} * ${#PITCH_ANGLES[@]}))
    local ground_combinations=$((ground_files * ${#GROUND_ALTITUDES[@]} * ${#ROLL_ANGLES[@]} * ${#PITCH_ANGLES[@]}))
    TOTAL_COMBINATIONS=$((aircraft_combinations + ground_combinations))

    log_info "Processing $total_files NEC files"
    log_info "Aircraft files: $aircraft_files (${aircraft_combinations} combinations)"
    log_info "Ground files: $ground_files (${ground_combinations} combinations)"
    log_info "Total combinations to generate: $TOTAL_COMBINATIONS"
    
    # Safety check to prevent system overload
    if [ "$SAFETY_MODE" = "true" ] && [ "$TOTAL_COMBINATIONS" -gt 50000 ]; then
        log_error "SAFETY MODE: Total combinations ($TOTAL_COMBINATIONS) exceeds safety limit (50,000)"
        log_error "This could cause system overload and hanging processes."
        log_error "To override, run with --force flag (NOT RECOMMENDED)"
        log_error "Consider using --dry-run first to check the scope"
        exit 1
    fi

    # Process each file
    local file_count=0
    for nec_file in "${nec_files[@]}"; do
        ((file_count++))
        log_info "[$file_count/$total_files] Processing: $(basename "$nec_file")"
        process_nec_file "$nec_file"
        log_info "[$file_count/$total_files] Completed: $(basename "$nec_file")"
    done
}

# Parallel processing (for speed)
process_patterns_parallel() {
    local nec_files=("$@")
    local total_files=${#nec_files[@]}
    
    log_info "Starting parallel processing of $total_files files with up to $MAX_PARALLEL_JOBS parallel jobs"
    
    # Calculate total combinations
    local aircraft_files=0
    local ground_files=0
    
    echo "DEBUG: Starting vehicle type classification loop" >&2
    
    for nec_file in "${nec_files[@]}"; do
        echo "DEBUG: Processing file: $nec_file" >&2
        local vehicle_type
        vehicle_type=$(get_vehicle_type "$nec_file")
        log_info "File: $(basename "$nec_file") -> Type: $vehicle_type"
        
        if [ "$vehicle_type" = "aircraft" ]; then
            ((++aircraft_files))
            echo "DEBUG: Incremented aircraft_files to $aircraft_files" >&2
        else
            ((++ground_files))
            echo "DEBUG: Incremented ground_files to $ground_files" >&2
        fi
    done
    
    echo "DEBUG: Finished classification loop. Aircraft: $aircraft_files, Ground: $ground_files" >&2
    
    local aircraft_combinations=$((aircraft_files * ${#AIRCRAFT_ALTITUDES[@]} * ${#ROLL_ANGLES[@]} * ${#PITCH_ANGLES[@]}))
    local ground_combinations=$((ground_files * ${#GROUND_ALTITUDES[@]} * ${#ROLL_ANGLES[@]} * ${#PITCH_ANGLES[@]}))
    TOTAL_COMBINATIONS=$((aircraft_combinations + ground_combinations))
    
    log_info "Processing $total_files NEC files"
    log_info "Aircraft files: $aircraft_files (${aircraft_combinations} combinations)"
    log_info "Ground files: $ground_files (${ground_combinations} combinations)"
    log_info "Total combinations to generate: $TOTAL_COMBINATIONS"
    
    # Safety check to prevent system overload
    if [ "$SAFETY_MODE" = "true" ] && [ "$TOTAL_COMBINATIONS" -gt 50000 ]; then
        log_error "SAFETY MODE: Total combinations ($TOTAL_COMBINATIONS) exceeds safety limit (50,000)"
        log_error "This could cause system overload and hanging processes."
        log_error "To override, run with --force flag (NOT RECOMMENDED)"
        log_error "Consider using --dry-run first to check the scope"
        exit 1
    fi
    
    # Process files in parallel
    local running=0
    local file_count=0
    
    for nec_file in "${nec_files[@]}"; do
        ((file_count++))
        log_info "[$file_count/$total_files] Starting: $(basename "$nec_file")"
        
        # Start background job and track PID
        process_nec_file "$nec_file" &
        local job_pid=$!
        BACKGROUND_PIDS+=("$job_pid")
        
        ((running++))
        
        # Wait if we've reached the job limit
        if (( running >= MAX_PARALLEL_JOBS )); then
            wait -n  # Wait for any job to complete
            ((running--))
        fi
    done
    
    # Wait for all remaining jobs to complete
    log_info "Waiting for all background jobs to complete..."
    for pid in "${BACKGROUND_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            wait "$pid" || log_warning "Job $pid exited with error"
        fi
    done
    
    # Clear the PID array
    BACKGROUND_PIDS=()
    log_success "All parallel processing completed!"
}

# Discover and run
generate_all_patterns() {
    log_section "Generating All Attitude-based Radiation Patterns"
    mapfile -d '' -t nec_files < <(find "$BASE_DIR" -type f -name "*.nec" -print0 | sort -z)
    log_info "Found ${#nec_files[@]} NEC files"
    [ ${#nec_files[@]} -eq 0 ] && { log_error "No NEC files found in $BASE_DIR"; exit 1; }

    if [ "$VERBOSE" = "true" ]; then
        log_info "NEC files found:"
        for f in "${nec_files[@]}"; do
            echo "  ${f#$BASE_DIR/}"
        done
    fi

    if [ "$MAX_PARALLEL_JOBS" -gt 1 ]; then
        process_patterns_parallel "${nec_files[@]}"
    else
        process_patterns_sequential "${nec_files[@]}"
    fi
}

# CLI
show_help() {
    echo "Usage: $0 [--help] [--verbose] [--dry-run] [--overwrite] [--jobs N] [--force] [--no-safety]"
    echo ""
    echo "Options:"
    echo "  --help      Show this help message"
    echo "  --verbose   Enable verbose logging"
    echo "  --dry-run   Show what would be done without actually doing it"
    echo "  --overwrite Overwrite existing pattern files"
    echo "  --jobs N    Set maximum parallel jobs (default: 10, max: 20)"
    echo "  --force     Override safety limits (NOT RECOMMENDED)"
    echo "  --no-safety Disable safety mode (NOT RECOMMENDED)"
    echo ""
    echo "SAFETY FEATURES:"
    echo "  - Maximum 50,000 combinations to prevent system overload"
    echo "  - Process cleanup on interruption (Ctrl+C)"
    echo "  - Timeout protection for individual files"
    echo "  - Reduced default parallel jobs (10 instead of 20)"
    echo ""
    echo "This script generates comprehensive radiation patterns for all aircraft"
    echo "attitude combinations (roll/pitch) at multiple altitudes, and ground"
    echo "vehicle attitude combinations at ground level."
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help) show_help; exit 0 ;;
            --verbose) VERBOSE=true; shift ;;
            --dry-run) DRY_RUN=true; shift ;;
            --overwrite) OVERWRITE_EXISTING=true; shift ;;
            --jobs) 
                MAX_PARALLEL_JOBS="$2"
                if [ "$MAX_PARALLEL_JOBS" -gt 20 ]; then
                    log_warning "Limiting parallel jobs to 20 (requested: $MAX_PARALLEL_JOBS)"
                    MAX_PARALLEL_JOBS=20
                fi
                shift 2 
                ;;
            --force) SAFETY_MODE=false; shift ;;
            --no-safety) SAFETY_MODE=false; shift ;;
            *) log_error "Unknown option: $1"; exit 1 ;;
        esac
    done
}

main() {
    parse_arguments "$@"
    log_section "FGCom-mumble Comprehensive Attitude Pattern Generation"
    log_info "Base directory: $BASE_DIR"
    log_info "Altitudes for aircraft: ${#AIRCRAFT_ALTITUDES[@]} points"
    log_info "Roll angles: ${#ROLL_ANGLES[@]} points"
    log_info "Pitch angles: ${#PITCH_ANGLES[@]} points"
    log_info "Max parallel jobs: $MAX_PARALLEL_JOBS"
    log_info "Safety mode: $SAFETY_MODE"
    [ "$DRY_RUN" = "true" ] && log_info "DRY RUN enabled"
    [ "$OVERWRITE_EXISTING" = "true" ] && log_info "Will overwrite existing patterns"

    check_dependencies
    generate_all_patterns
    log_success "Comprehensive pattern generation complete!"
    log_info "Generated patterns organized by vehicle in: $BASE_DIR/*/patterns/"

    exit 0
}

main "$@"
