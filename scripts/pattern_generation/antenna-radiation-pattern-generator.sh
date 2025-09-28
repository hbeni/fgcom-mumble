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
}

# Set up signal handlers - removed EXIT trap to prevent premature termination
trap cleanup SIGINT SIGTERM

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UTILITIES_DIR="$SCRIPT_DIR/../utilities"
BASE_DIR="${BASE_DIR:-$(cd "$SCRIPT_DIR/../../client/mumble-plugin/lib/antenna_patterns" 2>/dev/null && pwd || echo "")}"
MAX_PARALLEL_JOBS=10
OVERWRITE_EXISTING=false
DRY_RUN=false
VERBOSE=false
SAFETY_MODE=true
SELECTED_FOLDERS=""
SELECTED_AIRCRAFT=""
SELECTED_VEHICLES=""
SELECTED_MARINE=""

# Altitude intervals for aircraft (28 points)
AIRCRAFT_ALTITUDES=(0 25 50 100 150 200 250 300 500 650 800 1000 1500 2000 2500 3000 4000 5000 6000 7000 8000 9000 10000 12000 14000 16000 18000 20000)

# Roll angles (15 points)
ROLL_ANGLES=(-180 -120 -90 -60 -45 -30 -15 0 15 30 45 60 90 120 180)

# Pitch angles (13 points)
PITCH_ANGLES=(-120 -90 -60 -45 -30 -15 0 15 30 45 60 90 120)

# Special pitch angles for Yagi antennas 6m and above (horizontal to vertical)
# More sensible steps focusing on practical antenna orientations
YAGI_PITCH_ANGLES=(0 5 10 15 20 25 30 35 40 45 50 55 60 65 70 75 80 85 90)

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
log_info()    { echo -e "${BLUE}[INFO]${NC} $1" >&2; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1" >&2; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1" >&2; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1" >&2; }
log_section() { echo -e "${PURPLE}[SECTION]${NC} $1" >&2; }
log_debug()   { [ "$VERBOSE" = "true" ] && echo -e "[DEBUG] $1" >&2; }

# Job counters for progress logging
TOTAL_COMBINATIONS=0
COMPLETED_JOBS=0
CURRENT_JOB=0

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    
    local missing_deps=0
    
    # Check for nec2c
    if ! command -v nec2c >/dev/null 2>&1; then
        log_error "nec2c not found in PATH"
        ((missing_deps++))
    else
        log_debug "Found nec2c: $(which nec2c)"
    fi
    
    # Check for bc
    if ! command -v bc >/dev/null 2>&1; then
        log_error "bc (basic calculator) not found"
        ((missing_deps++))
    else
        log_debug "Found bc: $(which bc)"
    fi
    
    # Check for python3
    if ! command -v python3 >/dev/null 2>&1; then
        log_error "python3 not found in PATH"
        ((missing_deps++))
    else
        log_debug "Found python3: $(which python3)"
    fi
    
    # Check BASE_DIR
    if [ -z "$BASE_DIR" ] || [ ! -d "$BASE_DIR" ]; then
        log_error "Base directory not found or not set: '$BASE_DIR'"
        log_error "Set BASE_DIR environment variable or check directory structure"
        ((missing_deps++))
    else
        log_debug "Base directory: $BASE_DIR"
    fi
    
    # Check UTILITIES_DIR
    if [ ! -d "$UTILITIES_DIR" ]; then
        log_error "Utilities directory not found: $UTILITIES_DIR"
        ((missing_deps++))
    else
        log_debug "Utilities directory: $UTILITIES_DIR"
    fi
    
    # Check for extract_pattern_advanced.sh
    if [ ! -f "$UTILITIES_DIR/extract_pattern_advanced.sh" ]; then
        log_error "extract_pattern_advanced.sh missing at $UTILITIES_DIR/extract_pattern_advanced.sh"
        ((missing_deps++))
    elif [ ! -x "$UTILITIES_DIR/extract_pattern_advanced.sh" ]; then
        log_warning "Making extract_pattern_advanced.sh executable"
        if ! chmod +x "$UTILITIES_DIR/extract_pattern_advanced.sh"; then
            log_error "Cannot make extract_pattern_advanced.sh executable"
            ((missing_deps++))
        fi
    else
        log_debug "Found extract script: $UTILITIES_DIR/extract_pattern_advanced.sh"
    fi
    
    if [ $missing_deps -gt 0 ]; then
        log_error "$missing_deps dependencies missing. Cannot continue."
        exit 1
    fi
    
    log_success "All dependencies found."
}

# Vehicle type detector
get_vehicle_type() {
    local path="${1,,}"  # Convert to lowercase
    log_debug "Analyzing path: $path"
    
    if [[ "$path" == *"aircraft"* ]]; then
        echo "aircraft"
    elif [[ "$path" == *"ground-based"* ]]; then
        # Special handling for Yagi antennas 6m and above - treat as ground_station for attitude variations
        if is_yagi_6m_and_above "$1"; then
            echo "ground_station"
        else
            echo "fixed_installation"
        fi
    elif [[ "$path" == *"marine"* ]]; then
        echo "marine"
    elif [[ "$path" == *"military-land"* ]]; then
        echo "ground_vehicle"
    elif [[ "$path" == *"civilian-vehicles"* ]]; then
        echo "ground_vehicle"
    else
        # Default fallback
        echo "ground_station"
    fi
}

# Frequency detector with better error handling
get_frequency() {
    local file_path="$1"
    local file_name
    file_name=$(basename "$file_path")
    
    # Try to extract from filename first (pattern: number followed by mhz)
    if [[ "$file_name" =~ ([0-9]+(\.[0-9]+)?)[_\-\s]*[mM][hH][zZ] ]]; then
        echo "${BASH_REMATCH[1]}"
        return 0
    fi

    # Try to extract from NEC FR command
    if [ -f "$file_path" ] && [ -r "$file_path" ]; then
        local freq
        freq=$(grep -i "^FR" "$file_path" 2>/dev/null | head -1 | awk '{print $6}' | sed 's/[^0-9.]//g')
        if [[ "$freq" =~ ^[0-9]+(\.[0-9]+)?$ ]] && [ "$(echo "$freq > 0" | bc -l)" -eq 1 ]; then
            echo "$freq"
            return 0
        fi
    fi

    # Default based on vehicle type
    local vt
    vt=$(get_vehicle_type "$file_path")
    case "$vt" in
        aircraft)          echo "125" ;;
        marine)            echo "8.0" ;;
        military_land)     echo "36" ;;
        ground_vehicle)    echo "145" ;;
        ground_station)    echo "14.0" ;;
        fixed_installation) echo "14.0" ;;
        *)                 echo "100" ;;
    esac
}

# Detect if antenna is a Yagi 6 meters and above that needs pitch variations
is_yagi_6m_and_above() {
    local file_path="$1"
    local path_lower="${file_path,,}"  # Convert to lowercase
    local filename
    filename=$(basename "$file_path")
    filename_lower="${filename,,}"
    
    # Check if it's a Yagi antenna
    if [[ "$path_lower" == *"yagi"* ]] || [[ "$filename_lower" == *"yagi"* ]]; then
        # Check if it's 6 meters and above (include 2m/144MHz and 70cm/432MHz as they are above 6m)
        if [[ "$path_lower" == *"yagi_4m"* ]] || [[ "$path_lower" == *"4m_yagi"* ]] || [[ "$path_lower" == *"yagi_6m"* ]] || [[ "$path_lower" == *"yagi_10m"* ]] || \
           [[ "$path_lower" == *"yagi_15m"* ]] || [[ "$path_lower" == *"yagi_20m"* ]] || \
           [[ "$path_lower" == *"yagi_30m"* ]] || [[ "$path_lower" == *"yagi_40m"* ]] || \
           [[ "$path_lower" == *"yagi_144mhz"* ]] || [[ "$path_lower" == *"yagi_2x-stack_144mhz"* ]] || \
           [[ "$path_lower" == *"yagi_70cm"* ]]; then
            log_debug "Detected Yagi 6m+ antenna: $file_path"
            return 0
        fi
    fi
    
    return 1
}

# Get vehicle name from path
get_vehicle_name() {
    local file_path="$1"
    local dir_name
    dir_name=$(dirname "$file_path")
    basename "$dir_name"
}

# NEC2 EXTERNAL TOOL INTERFACE
# This function provides a safe interface to the NEC2 electromagnetic simulation tool
# NEC2 is a numerical electromagnetic code that calculates antenna radiation patterns
# 
# NEC2 FILE FORMAT REQUIREMENTS:
# - Input files must have .nec extension
# - Output files must have .out extension  
# - File paths must be short (8.3 format) for maximum compatibility
# - NEC2 expects specific command format: nec2c -i input.nec -o output.out
#
# NEC2 COMMAND LINE INTERFACE:
# nec2c -i <input_file> -o <output_file>
#   -i: Input NEC file (antenna geometry)
#   -o: Output file (radiation pattern data)
#   Returns: 0 on success, non-zero on failure
#
# NEC2 OUTPUT FORMAT:
# The output file contains radiation pattern data in NEC2 format:
# - Header with antenna information
# - Radiation pattern data (gain vs angle)
# - Frequency and power information
# - Error messages if simulation fails
run_nec_simulation_safe() {
    local input_nec="$1"    # Input NEC file path
    local output_file="$2"  # Output file path
    
    # NEC2 FILENAME LENGTH LIMITATION WORKAROUND:
    # NEC2 has issues with long filenames, so we create short temporary files
    # This ensures maximum compatibility across different systems and NEC2 versions
    local temp_dir="${TMPDIR:-/tmp}"
    local unique_id="$$_$(date +%s%N)_${BASHPID:-$$}_$RANDOM"
    local short_input="$temp_dir/n${unique_id}.nec"   # Short input filename
    local short_output="$temp_dir/n${unique_id}.out"  # Short output filename
    
    log_debug "nec2c workaround: $input_nec -> $short_input"
    
    # FILE COPY OPERATION:
    # Copy input file to short filename for NEC2 compatibility
    # This step is critical - NEC2 may fail with long or complex filenames
    if ! cp "$input_nec" "$short_input"; then
        log_error "Failed to copy to temporary file: $short_input"
        return 1
    fi
    
    # NEC2 EXECUTION:
    # Run the NEC2 electromagnetic simulation with short filenames
    # NEC2 calculates antenna radiation patterns using numerical methods
    local nec_result=1
    if nec2c -i "$short_input" -o "$short_output" 2>&1; then
        # OUTPUT VERIFICATION:
        # Verify that NEC2 produced valid output with content
        # Empty output files indicate simulation failure
        if [ -f "$short_output" ] && [ -s "$short_output" ]; then
            # COPY RESULT:
            # Copy the simulation result back to the desired output location
            if cp "$short_output" "$output_file"; then
                nec_result=0
                log_debug "nec2c completed successfully"
            else
                log_error "Failed to copy output back to: $output_file"
            fi
        else
            log_debug "nec2c produced empty or no output file"
        fi
    else
        log_debug "nec2c execution failed"
    fi
    
    # DEBUGGING SUPPORT:
    # Keep temporary files for debugging NEC2 issues
    # Remove the comment below to clean up temporary files
    # rm -f "$short_input" "$short_output" 2>/dev/null
    
    return $nec_result
}

# FIXED: Modify NEC file for specific attitude and altitude
modify_nec_for_attitude() {
    local input_nec="$1"
    local output_nec="$2" 
    local altitude_m="$3"
    local roll_deg="$4"
    local pitch_deg="$5"
    local frequency="$6"

    log_debug "Modifying NEC: alt=${altitude_m}m, roll=${roll_deg}°, pitch=${pitch_deg}°, freq=${frequency}MHz"

    # Validate inputs
    if [ ! -f "$input_nec" ] || [ ! -r "$input_nec" ]; then
        log_error "Cannot read input NEC file: $input_nec"
        return 1
    fi

    # Copy original file
    if ! cp "$input_nec" "$output_nec"; then
        log_error "Failed to copy NEC file: $input_nec -> $output_nec"
        return 1
    fi

    # Convert frequency to ensure it's numeric
    if ! [[ "$frequency" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        log_error "Invalid frequency: $frequency"
        return 1
    fi

    # Convert altitude to wavelengths (more accurate)
    local wavelength_m altitude_wavelengths
    wavelength_m=$(echo "scale=6; 299.792458 / $frequency" | bc -l 2>/dev/null || echo "2.99792458")
    altitude_wavelengths=$(echo "scale=6; $altitude_m / $wavelength_m" | bc -l 2>/dev/null || echo "0")
    
    # Pre-calculate trigonometric values using bc
    local roll_rad pitch_rad
    roll_rad=$(echo "scale=6; $roll_deg * 3.14159265359 / 180" | bc -l)
    pitch_rad=$(echo "scale=6; $pitch_deg * 3.14159265359 / 180" | bc -l)
    
    local cos_roll sin_roll cos_pitch sin_pitch
    cos_roll=$(echo "scale=6; c($roll_rad)" | bc -l)
    sin_roll=$(echo "scale=6; s($roll_rad)" | bc -l)
    cos_pitch=$(echo "scale=6; c($pitch_rad)" | bc -l)
    sin_pitch=$(echo "scale=6; s($pitch_rad)" | bc -l)
    
    # COORDINATE TRANSFORMATION SYSTEM:
    # This Python script performs 3D coordinate transformations for antenna orientation
    # It handles aircraft attitude (pitch/roll) and altitude adjustments for NEC2 files
    # 
    # TRANSFORMATION ORDER:
    # 1. Altitude offset (add height above ground)
    # 2. Pitch rotation (nose up/down around Y axis)  
    # 3. Roll rotation (wing up/down around X axis)
    # 
    # This matches standard aircraft attitude conventions and ensures proper
    # antenna orientation for different vehicle attitudes and altitudes.
    python3 -c "
import sys
import math

# COORDINATE TRANSFORMATION PARAMETERS:
# These values are pre-calculated using bc for maximum precision
# They represent the trigonometric functions needed for 3D rotations
alt_offset = $altitude_wavelengths  # Altitude in wavelengths (for NEC2 scaling)
freq = $frequency                   # Frequency in MHz (for reference)
cos_roll = $cos_roll               # Cosine of roll angle (rotation around X axis)
sin_roll = $sin_roll               # Sine of roll angle (rotation around X axis)  
cos_pitch = $cos_pitch             # Cosine of pitch angle (rotation around Y axis)
sin_pitch = $sin_pitch             # Sine of pitch angle (rotation around Y axis)

# FIXED INSTALLATION DETECTION:
# Check if this is a fixed installation (no rotation needed)
# Fixed installations have roll=0° and pitch=0° (cos=1, sin=0)
# This optimization skips expensive 3D transformations for ground stations
is_fixed_installation = (abs(cos_roll - 1.0) < 0.001 and abs(sin_roll) < 0.001 and 
                        abs(cos_pitch - 1.0) < 0.001 and abs(sin_pitch) < 0.001)

# NEC2 FILE PROCESSING:
# Process each line of the NEC2 file and transform geometry as needed
with open('$output_nec', 'r') as f:
    for line in f:
        line = line.strip()
        if line.startswith('GW'):
            # CRITICAL: NEC2 GW FORMAT REQUIREMENTS
            # The GW (wire geometry) format is exactly: GW tag# segments# x1 y1 z1 x2 y2 z2 radius
            # Do NOT add extra fields or the coordinate parsing will be shifted!
            # This format is position-sensitive - any deviation breaks NEC2 geometry parsing
            # The NEC2 parser expects exactly 9 fields: GW + 8 parameters
            parts = line.split()
            if len(parts) >= 9:  # Must have exactly 9 fields (GW + 8 parameters)
                try:
                    # PARSE NEC2 GW LINE:
                    # Extract all wire geometry parameters from the GW line
                    tag = int(parts[1])        # Wire tag number (unique identifier)
                    segments = int(parts[2])   # Number of segments (affects accuracy)
                    x1 = float(parts[3])       # Start point X coordinate (meters)
                    y1 = float(parts[4])       # Start point Y coordinate (meters)
                    z1 = float(parts[5])       # Start point Z coordinate (meters)
                    x2 = float(parts[6])      # End point X coordinate (meters)
                    y2 = float(parts[7])      # End point Y coordinate (meters)
                    z2 = float(parts[8])      # End point Z coordinate (meters)
                    radius = float(parts[9])  # Wire radius (meters)
                    
                    if is_fixed_installation:
                        # FIXED INSTALLATION PATH:
                        # No rotation needed - just add altitude offset to Z coordinates
                        # This is much faster and avoids unnecessary calculations
                        new_z1 = z1 + alt_offset  # Add altitude to start point
                        new_z2 = z2 + alt_offset  # Add altitude to end point
                        # OUTPUT: GW tag segments x1 y1 z1 x2 y2 z2 radius (9 fields exactly)
                        print(f'GW {tag} {segments} {x1:.6f} {y1:.6f} {new_z1:.6f} {x2:.6f} {y2:.6f} {new_z2:.6f} {radius:.6f}')
                    else:
                        # 3D COORDINATE TRANSFORMATION PATH:
                        # Apply full 3D rotation transformations for moving vehicles
                        # Transformations are applied in order: altitude → pitch → roll
                        # This matches aircraft attitude conventions (pitch then roll)
                        
                        # STEP 1: ALTITUDE OFFSET
                        # Add altitude offset to Z coordinates (height above ground)
                        z1_alt = z1 + alt_offset  # Start point with altitude
                        z2_alt = z2 + alt_offset  # End point with altitude
                        
                        # STEP 2: PITCH ROTATION (rotation around Y axis)
                        # This rotates the antenna up/down (nose up/down)
                        # Pitch affects X and Z coordinates (forward/backward and up/down)
                        new_x1 = x1 * cos_pitch + z1_alt * sin_pitch
                        new_z1_temp = -x1 * sin_pitch + z1_alt * cos_pitch
                        new_x2 = x2 * cos_pitch + z2_alt * sin_pitch
                        new_z2_temp = -x2 * sin_pitch + z2_alt * cos_pitch

                        # STEP 3: ROLL ROTATION (rotation around X axis)
                        # This rotates the antenna left/right (wing up/down)
                        # Roll affects Y and Z coordinates (left/right and up/down)
                        new_y1 = y1 * cos_roll - new_z1_temp * sin_roll
                        new_z1 = y1 * sin_roll + new_z1_temp * cos_roll
                        new_y2 = y2 * cos_roll - new_z2_temp * sin_roll
                        new_z2 = y2 * sin_roll + new_z2_temp * cos_roll

                        # OUTPUT: GW tag segments x1 y1 z1 x2 y2 z2 radius (9 fields exactly)
                        # Any deviation from this format breaks NEC2 geometry parsing!
                        print(f'GW {tag} {segments} {new_x1:.6f} {new_y1:.6f} {new_z1:.6f} {new_x2:.6f} {new_y2:.6f} {new_z2:.6f} {radius:.6f}')
                except (ValueError, IndexError):
                    # ERROR HANDLING: Malformed GW line - pass through unchanged
                    # This prevents the script from crashing on invalid geometry
                    print(line)
            else:
                # ERROR HANDLING: Malformed GW line - pass through unchanged
                # This ensures all lines are processed even if some are invalid
                print(line)
        elif line.startswith('FR'):
            # Frequency command - update with specified frequency
            print(f'FR 0 1 0 0 {freq:.3f} 0')
        elif line.startswith('GD'):
            # Ground plane command - ensure proper ground plane
            print('GD 0 0 0 0 0.005 13.0')
        else:
            # All other commands pass through unchanged
            print(line)
" > "${output_nec}.tmp"
    
    # Check if Python transformation succeeded
    if [ $? -eq 0 ] && [ -f "${output_nec}.tmp" ]; then
        mv "${output_nec}.tmp" "$output_nec"
        return 0
    else
        log_error "Python coordinate transformation failed"
        rm -f "${output_nec}.tmp"
        return 1
    fi
}

# Generate pattern for specific attitude combination
generate_attitude_pattern() {
    local nec_file="$1"
    local altitude="$2" 
    local roll="$3"
    local pitch="$4"

    local vehicle_name frequency
    vehicle_name=$(get_vehicle_name "$nec_file")
    frequency=$(get_frequency "$nec_file")

    log_debug "Generating: ${vehicle_name} alt=${altitude}m roll=${roll}° pitch=${pitch}° freq=${frequency}MHz"

    # Create output directory structure
    local output_dir
    if [ "$altitude" -eq 0 ]; then
        output_dir="$BASE_DIR/$(dirname "${nec_file#$BASE_DIR/}")/patterns/${frequency}mhz"
    else
        local altitude_band
        if [ "$altitude" -le 300 ]; then
            altitude_band="ground_effects"
        elif [ "$altitude" -le 1500 ]; then
            altitude_band="boundary_layer"  
        else
            altitude_band="free_space"
        fi
        output_dir="$BASE_DIR/$(dirname "${nec_file#$BASE_DIR/}")/patterns/${frequency}mhz/${altitude_band}"
    fi
    
    if ! mkdir -p "$output_dir"; then
        log_error "Failed to create output directory: $output_dir"
        return 1
    fi

    # Generate pattern filename with antenna name and frequency
    local antenna_name=$(basename "$nec_file" .nec)
    local pattern_file="$output_dir/${antenna_name}_${altitude}m_roll_${roll}_pitch_${pitch}_${frequency}MHz.txt"

    # Skip if exists and not overwriting
    if [ -f "$pattern_file" ] && [ "$OVERWRITE_EXISTING" = "false" ]; then
        log_debug "Skipping existing: $(basename "$pattern_file")"
        return 0
    fi

    # Dry run mode
    if [ "$DRY_RUN" = "true" ]; then
        echo "Would generate: $pattern_file"
        return 0
    fi

    # Create temporary files with shorter names for NEC2 compatibility
    local temp_nec temp_out
    temp_nec=$(mktemp "${TMPDIR:-/tmp}/a_XXXXXX.nec") || return 1
    temp_out=$(mktemp "${TMPDIR:-/tmp}/o_XXXXXX.txt") || {
        rm -f "$temp_nec"
        return 1
    }
    
    # Track temp files for cleanup
    TMP_FILES+=("$temp_nec" "$temp_out")

    # Modify NEC file for this attitude
    if ! modify_nec_for_attitude "$nec_file" "$temp_nec" "$altitude" "$roll" "$pitch" "$frequency"; then
        log_error "Failed to modify NEC file"
        rm -f "$temp_nec" "$temp_out"
        return 1
    fi

    # Run NEC2 simulation using the safe wrapper
    local nec_success=false
    if run_nec_simulation_safe "$temp_nec" "$temp_out"; then
        nec_success=true
        log_debug "NEC2 completed: ${altitude}m_${roll}_${pitch}"
    else
        log_debug "NEC2 failed: ${altitude}m_${roll}_${pitch}"
        rm -f "$temp_nec" "$temp_out"  
        return 1
    fi

    # Extract pattern if NEC2 succeeded
    local extract_success=false
    if [ "$nec_success" = "true" ] && [ -f "$temp_out" ] && [ -s "$temp_out" ]; then
        if "$UTILITIES_DIR/extract_pattern_advanced.sh" "$temp_out" "$pattern_file" "$frequency" "$altitude" >/dev/null 2>&1; then
            extract_success=true
            log_debug "Pattern extracted: $(basename "$pattern_file")"
        else
            log_debug "Extraction failed: ${altitude}m_${roll}_${pitch}"
        fi
    fi

    # Cleanup temp files
    rm -f "$temp_nec" "$temp_out"

    [ "$extract_success" = "true" ] && return 0 || return 1
}

# Process all attitude combinations for a single NEC file
process_nec_file() {
    local nec_file="$1"
    
    # Validate input
    if [ ! -f "$nec_file" ] || [ ! -r "$nec_file" ]; then
        log_error "Cannot read NEC file: $nec_file"
        return 1
    fi

    local job_number=$((++CURRENT_JOB))
    local relative_path="${nec_file#$BASE_DIR/}"
    local vehicle_type frequency
    
    vehicle_type=$(get_vehicle_type "$nec_file")
    frequency=$(get_frequency "$nec_file")

    log_info "[$job_number] Processing: $relative_path (${vehicle_type}, ${frequency}MHz)"

    # Select altitude list based on vehicle type
    local -a altitude_list
    case "$vehicle_type" in
        aircraft)
            altitude_list=("${AIRCRAFT_ALTITUDES[@]}")
            ;;
        fixed_installation)
            altitude_list=(0)  # Only ground level
            ;;
        *)
            altitude_list=("${GROUND_ALTITUDES[@]}")
            ;;
    esac

    local patterns_generated=0
    local total_combinations
    
    # Calculate total combinations for this file
    if [ "$vehicle_type" = "fixed_installation" ]; then
        total_combinations=1  # Only one pattern (0° roll, 0° pitch)
    else
        # Select pitch angles based on antenna type for calculation
        local pitch_count
        if is_yagi_6m_and_above "$nec_file"; then
            # Yagi antennas: only pitch variations, no roll
            pitch_count=${#YAGI_PITCH_ANGLES[@]}
            total_combinations=$((${#altitude_list[@]} * pitch_count))
        else
            # Other antennas: full roll and pitch combinations
            pitch_count=${#PITCH_ANGLES[@]}
            total_combinations=$((${#altitude_list[@]} * ${#ROLL_ANGLES[@]} * pitch_count))
        fi
    fi

    log_debug "[$job_number] Will generate $total_combinations patterns"

    # Generate patterns
    local combination_count=0
    local failed_count=0
    
    if [ "$vehicle_type" = "fixed_installation" ]; then
        # Fixed installations: single pattern at 0° roll/pitch
        if generate_attitude_pattern "$nec_file" 0 0 0; then
            ((patterns_generated++))
        else
            ((failed_count++))
        fi
    else
        # Select pitch angles based on antenna type
        local -a pitch_list
        if is_yagi_6m_and_above "$nec_file"; then
            pitch_list=("${YAGI_PITCH_ANGLES[@]}")
            log_info "[$job_number] Using Yagi 6m+ pitch angles: ${YAGI_PITCH_ANGLES[*]}"
        else
            pitch_list=("${PITCH_ANGLES[@]}")
        fi
        
        # Generate all attitude combinations
        for altitude in "${altitude_list[@]}"; do
            if is_yagi_6m_and_above "$nec_file"; then
                # Yagi antennas: only pitch variations, no roll (fixed installations)
                for pitch in "${pitch_list[@]}"; do
                    ((combination_count++))
                    
                    # Progress reporting
                    if [ $((combination_count % 50)) -eq 0 ]; then
                        log_debug "[$job_number] Progress: $combination_count/$total_combinations"
                    fi
                    
                    if generate_attitude_pattern "$nec_file" "$altitude" 0 "$pitch"; then
                        ((patterns_generated++))
                    else
                        ((failed_count++))
                    fi
                done
            else
                # Other antennas: full roll and pitch combinations
                for roll in "${ROLL_ANGLES[@]}"; do
                    for pitch in "${pitch_list[@]}"; do
                        ((combination_count++))
                        
                        # Progress reporting
                        if [ $((combination_count % 50)) -eq 0 ]; then
                            log_debug "[$job_number] Progress: $combination_count/$total_combinations"
                        fi
                        
                        if generate_attitude_pattern "$nec_file" "$altitude" "$roll" "$pitch"; then
                            ((patterns_generated++))
                        else
                            ((failed_count++))
                        fi
                    done
                done
            fi
        done
    fi
    
    ((COMPLETED_JOBS++))
    
    if [ $failed_count -eq 0 ]; then
        log_success "[$job_number] Complete: $patterns_generated/$total_combinations patterns"
    else
        log_warning "[$job_number] Complete: $patterns_generated/$total_combinations patterns ($failed_count failed)"
    fi
    
    return 0
}

# Sequential processing 
process_patterns_sequential() {
    local nec_files=("$@")
    local total_files=${#nec_files[@]}
    local failed_files=0

    log_info "Sequential processing: $total_files files"

    for ((i=0; i<total_files; i++)); do
        local nec_file="${nec_files[$i]}"
        local file_num=$((i + 1))
        
        log_info "[$file_num/$total_files] Starting: $(basename "$nec_file")"
        
        if ! process_nec_file "$nec_file"; then
            log_error "[$file_num/$total_files] Failed: $(basename "$nec_file")"
            ((failed_files++))
        fi
    done
    
    if [ $failed_files -gt 0 ]; then
        log_warning "Sequential processing completed: $failed_files/$total_files files failed"
        return 1
    else
        log_success "Sequential processing completed successfully"
        return 0
    fi
}

# Parallel processing
process_patterns_parallel() {
    local nec_files=("$@")
    local total_files=${#nec_files[@]}
    
    log_info "Parallel processing: $total_files files (max $MAX_PARALLEL_JOBS jobs)"
    
    local failed_files=0
    local current_job=0
    
    # Process files in batches
    for ((i=0; i<total_files; i+=MAX_PARALLEL_JOBS)); do
        local batch_end=$((i + MAX_PARALLEL_JOBS))
        if (( batch_end > total_files )); then
            batch_end=$total_files
        fi
        
        log_info "Processing batch: files $((i+1))-$batch_end"
        
        # Start batch of jobs
        local batch_pids=()
        for ((j=i; j<batch_end; j++)); do
            local nec_file="${nec_files[$j]}"
            local file_num=$((j + 1))
            
            log_info "[$file_num/$total_files] Starting: $(basename "$nec_file")"
            
            # Start background job
            (
                if process_nec_file "$nec_file"; then
                    exit 0
                else
                    exit 1
                fi
            ) &
            
            local job_pid=$!
            batch_pids+=("$job_pid")
            BACKGROUND_PIDS+=("$job_pid")
        done
        
        # Wait for all jobs in this batch to complete
        log_info "Waiting for batch to complete..."
        for pid in "${batch_pids[@]}"; do
            if wait "$pid"; then
                log_debug "Job $pid completed successfully"
            else
                log_debug "Job $pid failed"
                ((failed_files++))
            fi
        done
        
        log_info "Batch completed"
    done
    
    BACKGROUND_PIDS=()
    
    if [ $failed_files -gt 0 ]; then
        log_warning "Parallel processing completed: $failed_files files failed"
        return 1
    else
        log_success "Parallel processing completed successfully"
        return 0
    fi
}

# Main pattern generation function
generate_all_patterns() {
    log_section "Generating Attitude-based Radiation Patterns"
    
    # Build find command
    local find_args=("$BASE_DIR" -type f -name "*.nec")
    
    # Add filters if specified
    if [ -n "$SELECTED_FOLDERS$SELECTED_AIRCRAFT$SELECTED_VEHICLES$SELECTED_MARINE" ]; then
        local -a path_filters=()
        
        # Folder filters
        if [ -n "$SELECTED_FOLDERS" ]; then
            IFS=',' read -ra folders <<< "$SELECTED_FOLDERS"
            for folder in "${folders[@]}"; do
                folder=$(echo "$folder" | xargs)  # Trim whitespace
                path_filters+=("*/$folder/*")
            done
        fi
        
        # Aircraft filters  
        if [ -n "$SELECTED_AIRCRAFT" ]; then
            IFS=',' read -ra aircraft <<< "$SELECTED_AIRCRAFT"
            for ac in "${aircraft[@]}"; do
                path_filters+=("*/aircraft/*/${ac// /}/*")
            done
        fi
        
        # Vehicle filters
        if [ -n "$SELECTED_VEHICLES" ]; then
            IFS=',' read -ra vehicles <<< "$SELECTED_VEHICLES"
            for vehicle in "${vehicles[@]}"; do
                path_filters+=("*/civilian-vehicles/*/${vehicle// /}/*")
                path_filters+=("*/military-land/*/${vehicle// /}/*")
            done
        fi
        
        # Marine filters
        if [ -n "$SELECTED_MARINE" ]; then
            IFS=',' read -ra marine <<< "$SELECTED_MARINE"
            for vessel in "${marine[@]}"; do
                path_filters+=("*/Marine/*/${vessel// /}/*")
            done
        fi
        
        # Build OR condition
        if [ ${#path_filters[@]} -gt 0 ]; then
            find_args+=(\()  # Start parentheses
            find_args+=(-path "${path_filters[0]}")
            for ((i=1; i<${#path_filters[@]}; i++)); do
                find_args+=(-o -path "${path_filters[$i]}")
            done
            find_args+=(\))  # End parentheses
        fi
    fi
    
    # Debug: Show find command
    log_debug "Find command: find ${find_args[*]}"
    
    # Execute find command
    mapfile -t nec_files < <(find "${find_args[@]}" | sort)
    
    log_info "Found ${#nec_files[@]} NEC files"
    
    if [ ${#nec_files[@]} -eq 0 ]; then
        log_error "No NEC files found matching criteria"
        return 1
    fi

    # Show files in verbose mode
    if [ "$VERBOSE" = "true" ]; then
        log_info "Files to process:"
        for f in "${nec_files[@]}"; do
            echo "  ${f#$BASE_DIR/}"
        done
    fi

    # Calculate total combinations for safety check
    if [ "$SAFETY_MODE" = "true" ]; then
        local total_estimated=0
        for nec_file in "${nec_files[@]}"; do
            local vt
            vt=$(get_vehicle_type "$nec_file")
            if [ "$vt" = "aircraft" ]; then
                # Select pitch angles based on antenna type
                local pitch_count
                if is_yagi_6m_and_above "$nec_file"; then
                    # Yagi antennas: only pitch variations, no roll
                    pitch_count=${#YAGI_PITCH_ANGLES[@]}
                    total_estimated=$((total_estimated + ${#AIRCRAFT_ALTITUDES[@]} * pitch_count))
                else
                    pitch_count=${#PITCH_ANGLES[@]}
                    total_estimated=$((total_estimated + ${#AIRCRAFT_ALTITUDES[@]} * ${#ROLL_ANGLES[@]} * pitch_count))
                fi
            elif [ "$vt" = "fixed_installation" ]; then
                total_estimated=$((total_estimated + 1))
            else
                # Select pitch angles based on antenna type
                local pitch_count
                if is_yagi_6m_and_above "$nec_file"; then
                    # Yagi antennas: only pitch variations, no roll
                    pitch_count=${#YAGI_PITCH_ANGLES[@]}
                    total_estimated=$((total_estimated + ${#GROUND_ALTITUDES[@]} * pitch_count))
                else
                    pitch_count=${#PITCH_ANGLES[@]}
                    total_estimated=$((total_estimated + ${#GROUND_ALTITUDES[@]} * ${#ROLL_ANGLES[@]} * pitch_count))
                fi
            fi
        done
        
        if [ $total_estimated -gt 50000 ]; then
            log_error "SAFETY: Estimated $total_estimated combinations exceed limit (50,000)"
            log_error "Use --force to override or reduce scope with filters"
            return 1
        fi
        
        log_info "Estimated total combinations: $total_estimated"
    fi

    # Process files
    if [ "$MAX_PARALLEL_JOBS" -gt 1 ]; then
        process_patterns_parallel "${nec_files[@]}"
    else
        process_patterns_sequential "${nec_files[@]}"
    fi
}

#
# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --verbose|-v)
                VERBOSE=true
                shift
                ;;
            --overwrite)
                OVERWRITE_EXISTING=true
                shift
                ;;
            --force)
                SAFETY_MODE=false
                shift
                ;;
            --jobs|-j)
                MAX_PARALLEL_JOBS="$2"
                shift 2
                ;;
            --folders)
                SELECTED_FOLDERS="$2"
                shift 2
                ;;
            --aircraft)
                SELECTED_AIRCRAFT="$2"
                shift 2
                ;;
            --vehicles)
                SELECTED_VEHICLES="$2"
                shift 2
                ;;
            --marine)
                SELECTED_MARINE="$2"
                shift 2
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Show help information
show_help() {
    cat << EOF
FGCom-mumble Antenna Radiation Pattern Generator

USAGE:
    $0 [OPTIONS]

OPTIONS:
    --dry-run              Show what would be generated without creating files
    --verbose, -v          Enable verbose output
    --overwrite            Overwrite existing pattern files
    --force                Disable safety checks (use with caution)
    --jobs, -j N           Maximum parallel jobs (default: 10)
    --folders LIST         Comma-separated list of folders to process
    --aircraft LIST        Comma-separated list of aircraft to process
    --vehicles LIST        Comma-separated list of vehicles to process
    --marine LIST          Comma-separated list of marine vessels to process
    --help, -h             Show this help message

EXAMPLES:
    $0 --dry-run --verbose
    $0 --aircraft "cessna_172,b737_800"
    $0 --folders "aircraft/Civil" --jobs 5
    $0 --overwrite --force

DESCRIPTION:
    Generates radiation patterns for all antenna models in the BASE_DIR.
    Supports attitude-based pattern generation for aircraft with multiple
    altitude, roll, and pitch combinations.

    The script uses Python for reliable coordinate transformations and
    pre-calculates trigonometric values using bc for precision.

EOF
}

# Main execution
main() {
    log_section "FGCom-mumble Antenna Radiation Pattern Generator"
    log_info "Starting pattern generation process..."
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Check dependencies
    check_dependencies
    
    # Generate all patterns
    generate_all_patterns
    
    log_success "Pattern generation completed successfully!"
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
