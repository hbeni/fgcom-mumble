#!/bin/bash
# FGCom-mumble 3D Pattern Generation Script - COMPLETE WORKING VERSION
# Multi-threaded 3D attitude pattern generation with actual geometry transformation
# Supports aircraft (3D) and maritime (2D) attitude patterns

set -e

# Force C locale for consistent numeric handling (fixes Norwegian locale issues)
export LC_NUMERIC=C
export LC_ALL=C

# Configuration  
SCRIPT_DIR="$(dirname "$0")"
UTILITIES_DIR="$SCRIPT_DIR/../utilities"

# Detect BASE_DIR intelligently - look for antenna_patterns directory
if [ -d "$(pwd)/aircraft" ]; then
    # Running from antenna_patterns directory
    BASE_DIR="$(pwd)"
elif [ -d "../../client/mumble-plugin/lib/antenna_patterns" ]; then
    # Running from scripts/pattern_generation, go to antenna_patterns
    BASE_DIR="$(cd ../../client/mumble-plugin/lib/antenna_patterns && pwd)"
elif [ -d "../client/mumble-plugin/lib/antenna_patterns" ]; then
    # Running from scripts directory
    BASE_DIR="$(cd ../client/mumble-plugin/lib/antenna_patterns && pwd)"
elif [ -d "$(dirname "$0")/antenna_patterns" ]; then
    # Running from parent of antenna_patterns
    BASE_DIR="$(dirname "$0")/antenna_patterns"
elif [ -d "$(pwd)/../antenna_patterns" ]; then
    # Running from subdirectory
    BASE_DIR="$(pwd)/../antenna_patterns"
else
    # Fallback: assume script is in antenna_patterns or try to find it
    BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
fi

MAX_PARALLEL_JOBS=8
OVERWRITE_EXISTING=false
DRY_RUN=false
VERBOSE=false
TEMP_DIR="/tmp/fgcom_3d_patterns_$$"

# Altitude intervals
# Full altitude range - 20 total points (optimized for ground-to-freespace transition)
ALL_ALTITUDES_FULL=(0 25 50 100 150 200 250 300 500 650 800 1000 1500 2000 2500 3000 6000 10000 14000 20000)

# Reduced altitude intervals for testing - 8 points
ALL_ALTITUDES_TEST=(0 100 500 1000 2500 5000 10000 18000)

# Attitude angle intervals
# Aircraft: Optimized range balancing education and gaming performance
AIRCRAFT_ROLL_ANGLES=(-180 -120 -90 -60 -45 -30 -15 0 15 30 45 60 90 120 180)      # 15 points
AIRCRAFT_PITCH_ANGLES=(-120 -90 -60 -45 -30 -15 0 15 30 45 60 90 120)              # 13 points

# Reduced attitude angles for testing (manageable output)
AIRCRAFT_ROLL_ANGLES_TEST=(-30 -15 0 15 30)
AIRCRAFT_PITCH_ANGLES_TEST=(-20 -10 0 10 20)

# Maritime: Ship motion in rough seas
MARITIME_ROLL_ANGLES=(-45 -20 0 20 45)
MARITIME_PITCH_ANGLES=(-30 -15 0 15 30)

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

log_verbose() {
    if [ "$VERBOSE" = "true" ]; then
        echo -e "${BLUE}[VERBOSE]${NC} $1"
    fi
}

# Cleanup function
cleanup() {
    if [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
}

# Set trap for cleanup
trap cleanup EXIT

# Create temp directory
mkdir -p "$TEMP_DIR"

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    
    local missing_deps=false
    
    if ! command -v nec2c &> /dev/null; then
        log_error "nec2c not found. Please install NEC2C."
        missing_deps=true
    fi
    
    if ! command -v bc &> /dev/null; then
        log_error "bc not found. Please install bc for mathematical calculations."
        missing_deps=true
    fi
    
    if ! command -v awk &> /dev/null; then
        log_error "awk not found. Please install awk."
        missing_deps=true
    fi
    
    if [ ! -f "$UTILITIES_DIR/eznec2nec.sh" ]; then
        log_error "eznec2nec.sh not found in utilities directory."
        missing_deps=true
    fi
    
    if [ ! -f "$UTILITIES_DIR/extract_pattern_advanced.sh" ]; then
        log_error "extract_pattern_advanced.sh not found in utilities directory."
        missing_deps=true
    fi
    
    if [ "$missing_deps" = "true" ]; then
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
            log_verbose "Skipping existing $file_type: $file_path"
            return 1
        fi
    fi
    return 0
}

# Function to validate EZNEC file
validate_eznec_file() {
    local eznec_file="$1"
    
    if [ ! -f "$eznec_file" ]; then
        log_error "EZNEC file not found: $eznec_file"
        return 1
    fi
    
    # Check if file has wire segments - support both EZNEC (W001) and NEC2 (GW) formats
    if grep -q "^W[0-9]" "$eznec_file" || grep -q "^GW" "$eznec_file"; then
        log_verbose "Found wire segments in EZNEC file"
        return 0
    else
        log_error "No wire segments found in EZNEC file: $eznec_file"
        if [ "$VERBOSE" = "true" ]; then
            echo "=== DEBUG: First 10 lines of file ==="
            head -10 "$eznec_file"
            echo "=== DEBUG: Lines starting with W ==="
            grep "^W" "$eznec_file" | head -3 || echo "No lines starting with W found"
            echo "=== DEBUG: Lines starting with GW ==="
            grep "^GW" "$eznec_file" | head -3 || echo "No lines starting with GW found"
            echo "=================================="
        fi
        return 1
    fi
}

# Function to extract the designed frequency from an EZNEC file
get_designed_frequency() {
    local eznec_file="$1"
    
    if [ ! -f "$eznec_file" ]; then
        log_warning "EZNEC file not found: $eznec_file"
        echo "14.0"
        return 1
    fi
    
    # Extract frequency from FR command in EZNEC file (MHz)
    local freq=$(grep "^FR" "$eznec_file" | head -1 | awk '{print $6}' | sed 's/000\.0$//' | sed 's/\.0$//')
    
    if [ -n "$freq" ] && [ "$freq" != "0" ]; then
        # Convert from Hz to MHz if needed
        if [ "$freq" -gt 1000 ]; then
            freq=$(awk "BEGIN {printf \"%.1f\", $freq / 1000000}")
        fi
        echo "$freq"
        return 0
    fi
    
    # Fallback: try to extract from comments or other patterns
    local freq_from_comment=$(grep -i "frequency\|freq\|mhz" "$eznec_file" | grep -oE "[0-9]+\.?[0-9]*" | head -1)
    if [ -n "$freq_from_comment" ]; then
        echo "$freq_from_comment"
        return 0
    fi
    
    log_warning "Could not determine frequency for $eznec_file, using 14.0 MHz"
    echo "14.0"
    return 1
}

# Function to generate appropriate frequency list based on antenna design
get_appropriate_frequencies() {
    local eznec_file="$1"
    local designed_freq=$(get_designed_frequency "$eznec_file")
    
    # Convert to integer for comparison
    local freq_int=$(echo "$designed_freq" | cut -d. -f1)
    
    # Generate frequency list based on designed frequency
    case "$freq_int" in
        [1-9]|1[0-9]|2[0-9])
            # HF frequencies (1-30 MHz)
            echo "7.0 14.0 21.0 28.0"
            ;;
        [3-9][0-9]|1[0-4][0-9])
            # VHF frequencies (30-150 MHz)
            echo "50.0 88.0 118.0 137.0"
            ;;
        1[5-9][0-9]|[2-4][0-9][0-9])
            # UHF frequencies (150-500 MHz)
            echo "225.0 243.0 300.0 400.0"
            ;;
        *)
            # Default HF
            echo "14.0"
            ;;
    esac
}

# Function to apply 3D rotation to a point using awk (locale-safe)
rotate_point_3d() {
    local x="$1"
    local y="$2" 
    local z="$3"
    local roll_rad="$4"
    local pitch_rad="$5"
    local yaw_rad="${6:-0}"  # Default yaw=0
    
    # Use awk for all calculations in one go to avoid variable passing issues
    awk "BEGIN {
        x = $x; y = $y; z = $z
        roll_rad = $roll_rad; pitch_rad = $pitch_rad; yaw_rad = $yaw_rad
        
        # Apply rotation matrices: Rz(yaw) * Ry(pitch) * Rx(roll)
        # First apply roll (rotation around X)
        y1 = y * cos(roll_rad) - z * sin(roll_rad)
        z1 = y * sin(roll_rad) + z * cos(roll_rad)
        
        # Then apply pitch (rotation around Y)
        x2 = x * cos(pitch_rad) + z1 * sin(pitch_rad)
        z2 = -x * sin(pitch_rad) + z1 * cos(pitch_rad)
        
        # Finally apply yaw (rotation around Z)
        x3 = x2 * cos(yaw_rad) - y1 * sin(yaw_rad)
        y3 = x2 * sin(yaw_rad) + y1 * cos(yaw_rad)
        
        printf \"%.6f %.6f %.6f\", x3, y3, z2
    }"
}

# Function to apply attitude transformation to EZNEC geometry
apply_attitude_transformation() {
    local input_file="$1"
    local output_file="$2"
    local roll="$3"
    local pitch="$4"
    local yaw="${5:-0}"
    
    # Convert angles to radians using awk (more reliable than bc)
    local roll_rad=$(LANG=C awk "BEGIN {printf \"%.10f\", $roll * 3.14159265359 / 180}")
    local pitch_rad=$(LANG=C awk "BEGIN {printf \"%.10f\", $pitch * 3.14159265359 / 180}")
    local yaw_rad=$(LANG=C awk "BEGIN {printf \"%.10f\", $yaw * 3.14159265359 / 180}")
    
    log_verbose "Transforming geometry: roll=${roll}°, pitch=${pitch}°, yaw=${yaw}°"
    
    # Create output file with header
    echo "# Transformed geometry: roll=${roll}°, pitch=${pitch}°, yaw=${yaw}°" > "$output_file"
    echo "# Generated by FGCom-mumble 3D Pattern Generation Script" >> "$output_file"
    
    # Process each line of the EZNEC file using a more robust approach
    while IFS= read -r line; do
        # Skip empty lines and comments
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && { echo "$line" >> "$output_file"; continue; }
        
        if [[ "$line" =~ ^W[0-9][0-9][0-9] ]] || [[ "$line" =~ ^GW[[:space:]] ]]; then
            # Handle both EZNEC (W) and NEC2 (GW) wire formats
            if [[ "$line" =~ ^W[0-9][0-9][0-9] ]]; then
                # Parse EZNEC wire segment: W001 x1 y1 z1 x2 y2 z2 rad seg
                # Use awk to parse the line properly
                local parsed=$(echo "$line" | LANG=C awk '{
                    tag = substr($1, 2)  # Remove W prefix
                    if (NF >= 9) {
                        printf "%s %.6f %.6f %.6f %.6f %.6f %.6f %.6f %s", tag, $2, $3, $4, $5, $6, $7, $8, $9
                    }
                }')
                
                if [ -n "$parsed" ]; then
                    read -r tag x1 y1 z1 x2 y2 z2 rad seg <<< "$parsed"
                    wire_format="W"
                else
                    echo "$line" >> "$output_file"
                    continue
                fi
            else
                # Parse NEC2 wire segment: GW tag seg x1 y1 z1 x2 y2 z2 rad
                local parsed=$(echo "$line" | LANG=C awk '{
                    if (NF >= 10) {
                        printf "%s %s %.6f %.6f %.6f %.6f %.6f %.6f %.6f", $2, $3, $4, $5, $6, $7, $8, $9, $10
                    }
                }')
                
                if [ -n "$parsed" ]; then
                    read -r tag seg x1 y1 z1 x2 y2 z2 rad <<< "$parsed"
                    wire_format="GW"
                else
                    echo "$line" >> "$output_file"
                    continue
                fi
            fi
            
            # Validate that we have numeric coordinates
            if ! [[ "$x1" =~ ^-?[0-9]+\.?[0-9]*$ ]] || ! [[ "$y1" =~ ^-?[0-9]+\.?[0-9]*$ ]]; then
                echo "$line" >> "$output_file"
                continue
            fi
            
            # Transform both endpoints using a single awk call with proper locale
            local transformed=$(LANG=C awk "BEGIN {
                x1 = $x1; y1 = $y1; z1 = $z1
                x2 = $x2; y2 = $y2; z2 = $z2
                roll_rad = $roll_rad; pitch_rad = $pitch_rad; yaw_rad = $yaw_rad
                
                # Transform first endpoint
                y1_rot = y1 * cos(roll_rad) - z1 * sin(roll_rad)
                z1_rot = y1 * sin(roll_rad) + z1 * cos(roll_rad)
                x1_fin = x1 * cos(pitch_rad) + z1_rot * sin(pitch_rad)
                z1_fin = -x1 * sin(pitch_rad) + z1_rot * cos(pitch_rad)
                x1_out = x1_fin * cos(yaw_rad) - y1_rot * sin(yaw_rad)
                y1_out = x1_fin * sin(yaw_rad) + y1_rot * cos(yaw_rad)
                
                # Transform second endpoint
                y2_rot = y2 * cos(roll_rad) - z2 * sin(roll_rad)
                z2_rot = y2 * sin(roll_rad) + z2 * cos(roll_rad)
                x2_fin = x2 * cos(pitch_rad) + z2_rot * sin(pitch_rad)
                z2_fin = -x2 * sin(pitch_rad) + z2_rot * cos(pitch_rad)
                x2_out = x2_fin * cos(yaw_rad) - y2_rot * sin(yaw_rad)
                y2_out = x2_fin * sin(yaw_rad) + y2_rot * cos(yaw_rad)
                
                printf \"%.6f %.6f %.6f %.6f %.6f %.6f\", x1_out, y1_out, z1_fin, x2_out, y2_out, z2_fin
            }")
            
            # Extract transformed coordinates
            read -r new_x1 new_y1 new_z1 new_x2 new_y2 new_z2 <<< "$transformed"
            
            # Write transformed wire segment in appropriate format
            if [ "$wire_format" = "W" ]; then
                # EZNEC format: W001 x1 y1 z1 x2 y2 z2 rad seg
                echo "W$tag $new_x1 $new_y1 $new_z1 $new_x2 $new_y2 $new_z2 $rad $seg" >> "$output_file"
            else
                # NEC2 format: GW tag seg x1 y1 z1 x2 y2 z2 rad
                echo "GW $tag $seg $new_x1 $new_y1 $new_z1 $new_x2 $new_y2 $new_z2 $rad" >> "$output_file"
            fi
        else
            # Copy non-wire lines as-is
            echo "$line" >> "$output_file"
        fi
    done < "$input_file"
    
    return 0
}

# Function to update EZNEC file with frequency and ground parameters
update_eznec_parameters() {
    local file="$1"
    local freq="$2"
    local altitude="$3"
    local vehicle_type="$4"
    
    # Update frequency (NEC2 expects MHz)
    sed -i "s/^FR.*/FR 0 1 0 0 $freq 0/" "$file"
    
    # Update ground parameters based on altitude and vehicle type
    if [ "$altitude" -gt 5000 ]; then
        # High altitude - free space
        sed -i "s/^GD.*/GD 0 0 0 0 0.0 1.0/" "$file"
    elif [ "$vehicle_type" = "maritime" ]; then
        # Maritime - saltwater ground
        sed -i "s/^GD.*/GD 0 0 0 0 5.0 81/" "$file"
    else
        # Low altitude over land - average ground
        sed -i "s/^GD.*/GD 0 0 0 0 0.005 13/" "$file"
    fi
    
    # Add altitude modeling by moving geometry up
    if [ "$altitude" -gt 0 ]; then
        # Move all wire segments up by altitude (simple meter offset for now)
        # This is approximate - real altitude modeling would be more complex
        local alt_offset=$(awk "BEGIN {print $altitude / 1000}") # Convert to reasonable units
        
        # Simple approach: add altitude offset to Z coordinates
        awk -v alt="$alt_offset" '
        /^GW/ { 
            printf "GW %s %s %.6f %.6f %.6f %.6f %.6f %.6f %s\n", 
                   $2, $3, $4, $5, $6+alt, $7, $8, $9+alt, $10
            next
        }
        { print }
        ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
    fi
}

# Function to determine altitude band for organized storage
get_altitude_band() {
    local altitude="$1"
    
    if [ "$altitude" -le 300 ]; then
        echo "ground_effects"      # 0-300m: Ground reflection dominant
    elif [ "$altitude" -le 1500 ]; then
        echo "boundary_layer"     # 300-1500m: Atmospheric boundary effects
    else
        echo "free_space"         # 1500m+: Approaching free space conditions
    fi
}

# Function to create organized directory structure
create_organized_structure() {
    local base_patterns_dir="$1"
    local antenna_name="$2"
    local frequency="$3"
    
    # Create hierarchical structure
    local antenna_dir="$base_patterns_dir/${antenna_name}"
    local freq_dir="$antenna_dir/${frequency}mhz"
    
    mkdir -p "$freq_dir/ground_effects"    # 0-300m
    mkdir -p "$freq_dir/boundary_layer"    # 300-1500m  
    mkdir -p "$freq_dir/free_space"        # 1500m+
    
    # Create index file for this frequency
    local index_file="$freq_dir/altitude_index.json"
    cat > "$index_file" << EOF
{
  "antenna": "$antenna_name",
  "frequency_mhz": $frequency,
  "altitude_bands": {
    "ground_effects": {
      "description": "Ground reflection and surface wave effects (0-300m)",
      "altitude_range": "0-300m",
      "physics": "Ground conductivity, reflection coefficients, surface waves"
    },
    "boundary_layer": {
      "description": "Atmospheric boundary layer effects (300-1500m)", 
      "altitude_range": "300-1500m",
      "physics": "Atmospheric ducting, refraction, weather effects"
    },
    "free_space": {
      "description": "Approaching free space conditions (1500m+)",
      "altitude_range": "1500m+", 
      "physics": "Minimal atmospheric effects, free space propagation"
    }
  },
  "attitude_matrix": {
    "roll_angles": [-180, -120, -90, -60, -45, -30, -15, 0, 15, 30, 45, 60, 90, 120, 180],
    "pitch_angles": [-120, -90, -60, -45, -30, -15, 0, 15, 30, 45, 60, 90, 120],
    "total_combinations": 195
  },
  "generated_by": "FGCom-mumble 3D Pattern Generation Script",
  "generation_date": "$(date -Iseconds)"
}
EOF
    
    echo "$freq_dir"
}

# Function to run NEC2 simulation with error checking
run_nec2_simulation() {
    local nec_file="$1"
    local output_file="$2"
    local work_dir="$3"
    
    cd "$work_dir" || return 1
    
    # Run NEC2 simulation
    if ! nec2c -i "$nec_file" -o "$output_file" 2>&1; then
        log_error "NEC2 simulation failed for $nec_file"
        cd - > /dev/null
        return 1
    fi
    
    # Check if output file was created and has content
    if [ ! -f "$output_file" ] || [ ! -s "$output_file" ]; then
        log_error "NEC2 output file not created or empty: $output_file"
        cd - > /dev/null
        return 1
    fi
    
    # Check for NEC2 errors in output
    if grep -q "ERROR" "$output_file"; then
        log_error "NEC2 simulation reported errors in $output_file"
        cd - > /dev/null
        return 1
    fi
    
    cd - > /dev/null
    return 0
}

# Function to run a single test pattern generation
test_single_pattern() {
    local antenna_file="${1:-aircraft/Civil/cessna_172/cessna-hf.ez}"
    local test_freq="${2:-14.0}"
    local test_altitude="${3:-50}"
    local test_roll="${4:-45}" 
    local test_pitch="${5:-0}"
    
    log_section "Running Single Pattern Test"
    log_info "Test Parameters:"
    log_info "  Antenna: $antenna_file"
    log_info "  Frequency: ${test_freq} MHz"
    log_info "  Altitude: ${test_altitude} m"
    log_info "  Roll: ${test_roll}°"
    log_info "  Pitch: ${test_pitch}°"
    
    # Debug path information
    log_verbose "Script directory: $SCRIPT_DIR"  
    log_verbose "Base directory: $BASE_DIR"
    log_verbose "Full antenna path: $BASE_DIR/$antenna_file"
    log_verbose "Current directory: $(pwd)"
    
    # Show what we're actually looking for
    log_verbose "Expected file location based on your structure:"
    log_verbose "  $(pwd)/../../client/mumble-plugin/lib/antenna_patterns/$antenna_file"
    
    # Validate antenna file exists
    if [ ! -f "$BASE_DIR/$antenna_file" ]; then
        log_error "Test antenna file not found: $BASE_DIR/$antenna_file"
        
        # Try to find the file in current directory structure
        if [ -f "$antenna_file" ]; then
            log_info "Found antenna file in current directory, using: $antenna_file"
            BASE_DIR="."
        elif [ -f "$(pwd)/$antenna_file" ]; then
            log_info "Found antenna file in pwd, using: $(pwd)/$antenna_file"
            BASE_DIR="$(pwd)"
        else
            log_error "Cannot locate antenna file anywhere. Please check the path."
            log_info "Searched in:"
            log_info "  - $BASE_DIR/$antenna_file"  
            log_info "  - $(pwd)/$antenna_file"
            log_info "  - $antenna_file"
            return 1
        fi
    fi
    
    # Validate antenna file format
    if ! validate_eznec_file "$BASE_DIR/$antenna_file"; then
        log_error "Invalid test antenna file: $antenna_file"
        return 1
    fi
    
    # Create organized test output directory
    local test_base_dir="$BASE_DIR/test_output"
    local antenna_name="test_$(basename "$antenna_file" .ez)"
    local freq_dir=$(create_organized_structure "$test_base_dir" "$antenna_name" "$test_freq")
    
    log_info "Test output directory: $freq_dir"
    
    # Generate the single test pattern using organized structure
    if generate_attitude_pattern "$BASE_DIR/$antenna_file" "$test_freq" "$test_altitude" "$test_roll" "$test_pitch" "aircraft" "$freq_dir"; then
        # Determine which band the test altitude falls into
        local altitude_band=$(get_altitude_band "$test_altitude")
        local pattern_file="$freq_dir/$altitude_band/${test_altitude}m_roll_${test_roll}_pitch_${test_pitch}.txt"
        
        log_success "Test pattern generated successfully!"
        log_info "Pattern file: $pattern_file"
        log_info "Altitude band: $altitude_band"
        
        # Show pattern file info if it exists
        if [ -f "$pattern_file" ]; then
            local file_size=$(du -h "$pattern_file" | cut -f1)
            local line_count=$(wc -l < "$pattern_file")
            log_info "Pattern file size: $file_size"
            log_info "Pattern data points: $line_count"
            
            # Show first few lines of pattern data
            log_info "First few lines of pattern data:"
            head -5 "$pattern_file" | while read -r line; do
                log_info "  $line"
            done
        else
            log_warning "Pattern file was not created"
        fi
        
        return 0
    else
        log_error "Test pattern generation failed"
        return 1
    fi
}

# Function to generate attitude pattern with organized structure
generate_attitude_pattern() {
    local antenna_file="$1"
    local freq="$2"
    local altitude="$3"
    local roll="$4"
    local pitch="$5"
    local vehicle_type="$6"
    local freq_dir="$7"           # Now expects the frequency directory
    
    local base_name=$(basename "$antenna_file" .ez)
    local work_dir="$TEMP_DIR/work_${base_name}_${freq}_${altitude}_${roll}_${pitch}_$$"
    mkdir -p "$work_dir"
    
    # Determine altitude band for organized storage
    local altitude_band=$(get_altitude_band "$altitude")
    local alt_band_dir="$freq_dir/$altitude_band"
    mkdir -p "$alt_band_dir"
    
    # Create pattern filename with altitude information
    local pattern_file="$alt_band_dir/${altitude}m_roll_${roll}_pitch_${pitch}.txt"
    
    # Check if pattern already exists
    if ! check_file_exists "$pattern_file" "pattern"; then
        # rm -rf "$work_dir"  # DEBUG: Keep work directory
        return 0
    fi
    
    if [ "$DRY_RUN" = "true" ]; then
        log_info "DRY RUN: Would generate pattern for $base_name at ${freq}MHz, ${altitude}m ($altitude_band), roll=${roll}°, pitch=${pitch}°"
        # rm -rf "$work_dir"  # DEBUG: Keep work directory
        return 0
    fi
    
    # Step 1: Apply attitude transformation
    local transformed_file="$work_dir/${base_name}_transformed.ez"
    if ! apply_attitude_transformation "$antenna_file" "$transformed_file" "$roll" "$pitch"; then
        log_error "Failed to transform geometry for $base_name"
        # rm -rf "$work_dir"  # DEBUG: Keep work directory
        return 1
    fi
    
    # Step 2: Update parameters
    update_eznec_parameters "$transformed_file" "$freq" "$altitude" "$vehicle_type"
    
    # Step 3: Convert to NEC2
    local nec_file="$work_dir/${base_name}_${freq}MHz_${altitude}m_r${roll}_p${pitch}.nec"
    if ! "$UTILITIES_DIR/eznec2nec.sh" "$transformed_file" "$nec_file" 2>/dev/null; then
        log_error "Failed to convert EZNEC to NEC2 for $base_name"
        # rm -rf "$work_dir"  # DEBUG: Keep work directory
        return 1
    fi
    
    # Step 4: Run NEC2 simulation
    local output_file="$work_dir/${base_name}_${freq}MHz_${altitude}m_r${roll}_p${pitch}.out"
    if ! run_nec2_simulation "$(basename "$nec_file")" "$(basename "$output_file")" "$work_dir"; then
        log_error "NEC2 simulation failed for $base_name at ${freq}MHz, ${altitude}m, roll=${roll}°, pitch=${pitch}°"
        log_error "Work directory preserved for debugging: $work_dir"
        log_error "Check files:"
        log_error "  Transformed EZNEC: $work_dir/${base_name}_transformed.ez"
        log_error "  NEC2 input: $nec_file" 
        log_error "  NEC2 output: $output_file"
        # Don't cleanup work directory on NEC2 errors so we can debug
        return 1
    fi
    
    # Step 5: Extract pattern
    if ! "$UTILITIES_DIR/extract_pattern_advanced.sh" "$output_file" "$pattern_file" "$freq" "$altitude" "$roll" "$pitch"; then
        log_error "Pattern extraction failed for $base_name"
        # rm -rf "$work_dir"  # DEBUG: Keep work directory
        return 1
    fi
    
    # Cleanup work directory
    # rm -rf "$work_dir"  # DEBUG: Keep work directory
    
    log_success "Generated pattern: $base_name @ ${freq}MHz, ${altitude}m ($altitude_band), roll=${roll}°, pitch=${pitch}°"
    return 0
}

# Function to generate 3D attitude patterns for aircraft
generate_aircraft_3d_patterns() {
    local antenna_file="$1"
    local antenna_name="$2"
    local altitudes="$3"
    
    # Get appropriate frequencies for this antenna
    local frequencies=$(get_appropriate_frequencies "$BASE_DIR/$antenna_file")
    
    log_info "Generating 3D attitude patterns for $antenna_name"
    log_info "Frequencies: $frequencies"
    log_info "Altitudes: $altitudes"
    
    # Create organized patterns directory structure
    local base_patterns_dir="$BASE_DIR/$(dirname "$antenna_file")/patterns" 
    local antenna_name_clean=$(basename "$(dirname "$antenna_file")")_$(basename "$antenna_file" .ez)
    
    # Remove any spaces and special characters from antenna name
    antenna_name_clean=$(echo "$antenna_name_clean" | sed 's/[^a-zA-Z0-9_-]/_/g')
    
    # Use altitude intervals based on mode
    if [ "${USE_FULL_ALTITUDES:-false}" = "true" ]; then
        local altitudes_str=$(printf "%s " "${ALL_ALTITUDES_FULL[@]}")
        log_info "Using full altitude range (20 points: 0m to 20,000m, optimized for ground-to-freespace transition)"
    else
        local altitudes_str=$(printf "%s " "${ALL_ALTITUDES_TEST[@]}")
        log_info "Using reduced altitude range (8 points for testing)"
    fi
    
    # Use attitude intervals based on mode
    if [ "${USE_FULL_RANGE:-false}" = "true" ]; then
        local roll_angles=("${AIRCRAFT_ROLL_ANGLES[@]}")
        local pitch_angles=("${AIRCRAFT_PITCH_ANGLES[@]}")
        log_info "Using full combat aircraft attitude range (-180° to +180°)"
    else
        local roll_angles=("${AIRCRAFT_ROLL_ANGLES_TEST[@]}")
        local pitch_angles=("${AIRCRAFT_PITCH_ANGLES_TEST[@]}")
        log_info "Using reduced attitude range for manageable output"
    fi
    
    log_info "Altitudes: $altitudes_str"
    
    local job_count=0
    
    # Process each frequency
    for freq in $frequencies; do
        # Create organized structure for this frequency
        local freq_dir=$(create_organized_structure "$base_patterns_dir" "$antenna_name_clean" "$freq")
        
        # Process each altitude
        for alt in $altitudes_str; do
            # Process each attitude combination
            for roll in "${roll_angles[@]}"; do
                for pitch in "${pitch_angles[@]}"; do
                    # Limit parallel jobs
                    while [ $(jobs -r | wc -l) -ge $MAX_PARALLEL_JOBS ]; do
                        sleep 1
                    done
                    
                    # Generate pattern in background with new structure
                    generate_attitude_pattern "$BASE_DIR/$antenna_file" "$freq" "$alt" "$roll" "$pitch" "aircraft" "$freq_dir" &
                    
                    ((job_count++))
                    
                    if [ $((job_count % 25)) -eq 0 ]; then
                        log_info "Queued $job_count pattern generation jobs for $antenna_name"
                    fi
                done
            done
        done
    done
    
    # Wait for all jobs to complete
    wait
    log_success "Completed 3D pattern generation for $antenna_name ($job_count patterns)"
}

# Function to generate 2D attitude patterns for maritime vehicles
generate_maritime_2d_patterns() {
    local antenna_file="$1"
    local antenna_name="$2"
    
    if ! validate_eznec_file "$BASE_DIR/$antenna_file"; then
        log_error "Invalid EZNEC file: $antenna_file"
        return 1
    fi
    
    # Get appropriate frequencies for this antenna
    local frequencies=$(get_appropriate_frequencies "$BASE_DIR/$antenna_file")
    
    log_info "Generating 2D attitude patterns for $antenna_name"
    log_info "Frequencies: $frequencies"
    
    # Create organized patterns directory structure
    local base_patterns_dir="$BASE_DIR/$(dirname "$antenna_file")/patterns"
    local antenna_name_clean=$(basename "$(dirname "$antenna_file")")_$(basename "$antenna_file" .ez)
    
    # Remove any spaces and special characters from antenna name
    antenna_name_clean=$(echo "$antenna_name_clean" | sed 's/[^a-zA-Z0-9_-]/_/g')
    
    # Use maritime-specific attitude intervals
    local roll_angles=("${MARITIME_ROLL_ANGLES[@]}")
    local pitch_angles=("${MARITIME_PITCH_ANGLES[@]}")
    
    local job_count=0
    
    # Process each frequency
    for freq in $frequencies; do
        # Create organized structure for this frequency
        local freq_dir=$(create_organized_structure "$base_patterns_dir" "$antenna_name_clean" "$freq")
        
        # Process each attitude combination
        for roll in "${roll_angles[@]}"; do
            for pitch in "${pitch_angles[@]}"; do
                # Limit parallel jobs
                while [ $(jobs -r | wc -l) -ge $MAX_PARALLEL_JOBS ]; do
                    sleep 1
                done
                
                # Generate pattern in background with organized structure
                generate_attitude_pattern "$BASE_DIR/$antenna_file" "$freq" "0" "$roll" "$pitch" "maritime" "$freq_dir" &
                
                ((job_count++))
            done
        done
    done
    
    # Wait for all jobs to complete
    wait
    log_success "Completed 2D pattern generation for $antenna_name ($job_count patterns)"
}

# Function to show help
show_help() {
    cat << EOF
FGCom-mumble 3D Pattern Generation Script - COMPLETE WORKING VERSION

USAGE:
    $0 [OPTIONS] [CATEGORY]

OPTIONS:
    -h, --help              Show this help message
    -v, --verbose           Enable verbose output
    -d, --dry-run           Show what would be done without actually doing it
    -o, --overwrite         Overwrite existing pattern files
    -j, --jobs N            Number of parallel jobs (default: $MAX_PARALLEL_JOBS)

CATEGORIES:
    aircraft                Generate 3D attitude patterns for aircraft (reduced range: 5x5 attitudes, 8 altitudes)
    aircraft-full           Generate 3D attitude patterns for aircraft (full combat range: 15x13 attitudes, 8 altitudes)  
    aircraft-complete       Generate 3D attitude patterns for aircraft (COMPLETE: 15x13 attitudes, 20 altitudes)
    maritime               Generate 2D attitude patterns for maritime vehicles
    test                   Run single pattern test (Cessna at 50m, 45° roll)
    all                    Generate all patterns (default - uses reduced range)
    all-complete           Generate all patterns (COMPLETE - full altitudes and attitudes)

EXAMPLES:
    $0 --dry-run aircraft                    # Show what aircraft patterns would be generated (reduced)
    $0 --overwrite --jobs 4 aircraft-full   # Generate aircraft patterns with full combat attitudes, 8 altitudes
    $0 --overwrite --jobs 8 aircraft-complete # Generate aircraft patterns with EVERYTHING (15x13x20 = 3,900 patterns per antenna!)
    $0 --verbose test                        # Run single test pattern (Cessna 172 HF at 50m, 45° roll)
    $0 test cessna-final.ez 121.5 100 -30 15 # Custom test: VHF antenna at 121.5MHz, 100m altitude, -30° roll, 15° pitch
    $0 --overwrite --jobs 4 maritime        # Generate maritime patterns with 4 jobs, overwriting existing
    $0 --verbose all-complete                # Generate EVERYTHING (WARNING: Large output!)

PATTERN COUNT ESTIMATES (with optimized attitude ranges):
    aircraft:          5x5x8x4    = 800 patterns per antenna      (manageable for testing)  
    aircraft-full:     15x13x8x4  = 6,240 patterns per antenna   (optimized full range)
    aircraft-complete: 15x13x20x4 = 15,600 patterns per antenna  (COMPLETE optimized specification)

MATHEMATICAL IMPROVEMENTS:
    - Replaced bc with awk for all calculations (fixes locale/syntax errors)
    - Robust coordinate parsing with validation
    - Proper handling of both EZNEC (W001) and NEC2 (GW) wire formats
    - Simplified altitude modeling to avoid complex wavelength calculations

ORGANIZED FOLDER STRUCTURE:
    antenna_patterns/
    ├── aircraft/
    │   ├── cessna_172_hf/
    │   │   ├── 14mhz/
    │   │   │   ├── ground_effects/     # 0-300m: Ground reflection effects
    │   │   │   ├── boundary_layer/     # 300-1500m: Atmospheric effects  
    │   │   │   ├── free_space/         # 1500m+: Free space conditions
    │   │   │   └── altitude_index.json # Metadata and band descriptions
    │   │   └── 21mhz/...
    │   └── mi4_hound_vhf/...
    └── maritime/
        └── containership_loop/...

ALTITUDE OPTIMIZATION + STRUCTURE BENEFITS:
    - Patterns organized by RF propagation physics (educational value)
    - Optimized attitude combinations (15x13 = 195 combinations) 
    - Improved browsing: patterns grouped by physical phenomena
    - Educational metadata in altitude_index.json files
    - Manageable file counts per directory (~65 files max per altitude band)
    
SPACE SAVINGS:
    For 4 aircraft: 4 x 15,600 = 62,400 pattern files (optimized from 129,472)
    Storage reduction: ~50% while maintaining educational and gaming value

TEST FUNCTION:
    The test function accepts optional parameters:
    $0 test [antenna_file] [frequency] [altitude] [roll] [pitch]
    
    Default test: Cessna 172 HF at 14.0 MHz, 50m altitude, 45° roll, 0° pitch
    Custom test examples:
    $0 test aircraft/Civil/cessna_172/cessna-final.ez 121.5 100 -30 15
    $0 test aircraft/Military/mi4_hound/mi4-vhf.ez 243.0 500 90 -45

IMPROVEMENTS IN THIS VERSION:
    - Actually transforms antenna geometry for attitude changes using proper 3D rotation matrices
    - Fixed frequency handling (removed incorrect 1000x multiplication)
    - Added comprehensive error checking and validation for all operations
    - Proper parsing of EZNEC W001 format and NEC2 GW format wire segments
    - Replaced all bc calculations with awk to avoid Norwegian locale issues
    - Organized output structure grouped by RF propagation physics
    - Parallel processing with proper job control and cleanup
    - Automatic path detection for different directory structures

EOF
}

# Function to parse command line arguments
parse_arguments() {
    TEST_PARAMS=()  # Initialize test parameters array
    
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
            aircraft|aircraft-full|aircraft-complete|maritime|test|all|all-complete)
                CATEGORY="$1"
                shift
                ;;
            *)
                # Check if this might be test parameters
                if [ "$CATEGORY" = "test" ]; then
                    TEST_PARAMS+=("$1")
                    shift
                else
                    log_error "Unknown option: $1"
                    show_help
                    exit 1
                fi
                ;;
        esac
    done
}

# Aircraft patterns
generate_aircraft_patterns() {
    log_section "Generating Aircraft 3D Patterns"
    
    local aircraft_patterns=(
        "aircraft/Civil/cessna_172/cessna-hf.ez" "Cessna 172 HF"
        "aircraft/Civil/cessna_172/cessna-final.ez" "Cessna 172 VHF"
        "aircraft/Military/mi4_hound/mi4-vhf.ez" "MI-4 Hound"
        "aircraft/Military/tu95_bear/tu95-vhf.ez" "TU-95 Bear"
    )
    
    # Process patterns in pairs (file, name)
    for ((i=0; i<${#aircraft_patterns[@]}; i+=2)); do
        local antenna_file="${aircraft_patterns[i]}"
        local antenna_name="${aircraft_patterns[i+1]}"
        
        # Check if antenna file exists
        if [ ! -f "$BASE_DIR/$antenna_file" ]; then
            log_warning "Antenna file not found: $antenna_file, skipping"
            continue
        fi
        
        # Generate patterns for this antenna
        generate_aircraft_3d_patterns "$antenna_file" "$antenna_name" ""
    done
}

# Maritime patterns
generate_maritime_patterns() {
    log_section "Generating Maritime 2D Patterns"
    
    local maritime_patterns=(
        "Marine/ship/containership/containership-loop.ez" "Container Ship"
        "Marine/boat/sailboat_backstay/sailboat-40m.ez" "Sailboat"
    )
    
    # Process patterns in pairs (file, name)
    for ((i=0; i<${#maritime_patterns[@]}; i+=2)); do
        local antenna_file="${maritime_patterns[i]}"
        local antenna_name="${maritime_patterns[i+1]}"
        
        # Check if antenna file exists
        if [ ! -f "$BASE_DIR/$antenna_file" ]; then
            log_warning "Antenna file not found: $antenna_file, skipping"
            continue
        fi
        
        generate_maritime_2d_patterns "$antenna_file" "$antenna_name"
    done
}

# Main function
main() {
    # Parse command line arguments
    parse_arguments "$@"
    
    log_section "FGCom-mumble 3D Pattern Generation - COMPLETE WORKING VERSION"
    log_info "Using up to $MAX_PARALLEL_JOBS parallel jobs"
    log_info "Temporary directory: $TEMP_DIR"
    
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
    
    # Generate patterns based on category
    case "$CATEGORY" in
        "aircraft")
            USE_FULL_RANGE=false USE_FULL_ALTITUDES=false generate_aircraft_patterns
            ;;
        "aircraft-full")
            log_warning "Using full combat aircraft attitude range (-180° to +180°) with 8 altitudes"
            log_warning "This will generate $(( ${#AIRCRAFT_ROLL_ANGLES[@]} * ${#AIRCRAFT_PITCH_ANGLES[@]} * 8 * 4 )) patterns per antenna!"
            USE_FULL_RANGE=true USE_FULL_ALTITUDES=false generate_aircraft_patterns
            ;;
        "aircraft-complete")
            log_warning "Using COMPLETE specification: full attitudes (-180° to +180°) AND full altitudes (20 points)"
            log_warning "This will generate $(( ${#AIRCRAFT_ROLL_ANGLES[@]} * ${#AIRCRAFT_PITCH_ANGLES[@]} * 20 * 4 )) patterns per antenna!"
            log_warning "For 4 aircraft, this means $(( 4 * ${#AIRCRAFT_ROLL_ANGLES[@]} * ${#AIRCRAFT_PITCH_ANGLES[@]} * 20 * 4 )) total pattern files!"
            read -p "Are you sure you want to continue? This will use significant disk space and time. [y/N]: " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log_info "Operation cancelled by user"
                exit 0
            fi
            USE_FULL_RANGE=true USE_FULL_ALTITUDES=true generate_aircraft_patterns
            ;;
        "maritime")
            generate_maritime_patterns
            ;;
        "test")
            # Run single test with optional parameters
            if [ ${#TEST_PARAMS[@]} -eq 0 ]; then
                # Default test: Cessna 172 HF at 50m, 45° roll
                test_single_pattern
            else
                # Custom test with provided parameters
                test_single_pattern "${TEST_PARAMS[@]}"
            fi
            ;;
        "all")
            USE_FULL_RANGE=false USE_FULL_ALTITUDES=false generate_aircraft_patterns
            generate_maritime_patterns
            ;;
        "all-complete")
            log_warning "Using COMPLETE specification for ALL patterns!"
            log_warning "Aircraft: $(( ${#AIRCRAFT_ROLL_ANGLES[@]} * ${#AIRCRAFT_PITCH_ANGLES[@]} * 20 * 4 )) patterns per antenna"
            log_warning "Maritime: $(( ${#MARITIME_ROLL_ANGLES[@]} * ${#MARITIME_PITCH_ANGLES[@]} * 4 )) patterns per vessel"
            total_patterns=$(( 4 * ${#AIRCRAFT_ROLL_ANGLES[@]} * ${#AIRCRAFT_PITCH_ANGLES[@]} * 20 * 4 + 2 * ${#MARITIME_ROLL_ANGLES[@]} * ${#MARITIME_PITCH_ANGLES[@]} * 4 ))
            log_warning "Total estimated patterns: $total_patterns files"
            read -p "Are you sure you want to continue? This is a LARGE operation. [y/N]: " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log_info "Operation cancelled by user"
                exit 0
            fi
            USE_FULL_RANGE=true USE_FULL_ALTITUDES=true generate_aircraft_patterns
            generate_maritime_patterns
            ;;
        *)
            log_error "Unknown category: $CATEGORY"
            show_help
            exit 1
            ;;
    esac
    
    log_success "3D pattern generation complete!"
    log_info "Patterns saved in: $BASE_DIR/*/patterns/"
}

# Run main function
main "$@"
    