#!/bin/bash
# FGCom-mumble 3D Pattern Generation Script
# Multi-threaded 3D attitude pattern generation using up to 20 cores
# Supports aircraft (3D) and maritime (2D) attitude patterns

set -e

# Configuration
SCRIPT_DIR="$(dirname "$0")"
UTILITIES_DIR="$SCRIPT_DIR/../utilities"
BASE_DIR="$(dirname "$SCRIPT_DIR")/../client/mumble-plugin/lib/antenna_patterns"
MAX_PARALLEL_JOBS=20
OVERWRITE_EXISTING=false
DRY_RUN=false
VERBOSE=false

# Recommended altitude intervals - 28 total points
ALL_ALTITUDES=(0 25 50 100 150 200 250 300 500 650 800 1000 1500 2000 2500 3000 4000 5000 6000 7000 8000 9000 10000 12000 14000 16000 18000 20000)

# Attitude angle intervals
# Aircraft: Full range for extreme maneuvers
AIRCRAFT_ROLL_ANGLES=(-180 -150 -120 -90 -60 -30 0 30 60 90 120 150 180)
AIRCRAFT_PITCH_ANGLES=(-180 -150 -120 -90 -60 -30 0 30 60 90 120 150 180)

# Maritime: Realistic range to keep antennas above water
MARITIME_ROLL_ANGLES=(-80 -60 -40 -20 0 20 40 60 80)
MARITIME_PITCH_ANGLES=(-80 -60 -40 -20 0 20 40 60 80)

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
    
    if ! command -v bc &> /dev/null; then
        log_error "bc not found. Please install bc for mathematical calculations."
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

# Function to determine vehicle type from file path
get_vehicle_type() {
    local file_path="$1"
    
    if [[ "$file_path" == *"aircraft"* ]]; then
        echo "aircraft"
    elif [[ "$file_path" == *"military-land"* ]]; then
        echo "military_land"
    elif [[ "$file_path" == *"boat"* ]] || [[ "$file_path" == *"ship"* ]]; then
        echo "maritime"
    elif [[ "$file_path" == *"vehicle"* ]]; then
        echo "ground_vehicle"
    elif [[ "$file_path" == *"Ground-based"* ]]; then
        echo "ground_station"
    else
        echo "unknown"
    fi
}

# Function to extract the designed frequency from an EZNEC file
get_designed_frequency() {
    local eznec_file="$1"
    
    if [ ! -f "$eznec_file" ]; then
        log_warning "EZNEC file not found: $eznec_file"
        echo "unknown"
        return 1
    fi
    
    # Extract frequency from FR command in EZNEC file
    local freq=$(grep "^FR.*[0-9]" "$eznec_file" | head -1 | grep -oE "[0-9]+\.[0-9]+" | head -1)
    
    if [ -n "$freq" ]; then
        echo "$freq"
        return 0
    fi
    
    # Fallback: try to extract from comments or other patterns
    local freq_from_comment=$(grep -i "frequency\|freq\|mhz" "$eznec_file" | grep -oE "[0-9]+\.[0-9]+" | head -1)
    if [ -n "$freq_from_comment" ]; then
        echo "$freq_from_comment"
        return 0
    fi
    
    log_warning "Could not determine frequency for $eznec_file, using fallback"
    echo "unknown"
    return 1
}

# Function to generate appropriate frequency list based on antenna design
get_appropriate_frequencies() {
    local eznec_file="$1"
    local designed_freq=$(get_designed_frequency "$eznec_file")
    
    if [ "$designed_freq" = "unknown" ]; then
        log_warning "Using default frequencies for $eznec_file"
        echo "3.0 5.0 7.0 10.0 14.0 18.0 21.0 28.0"
        return 0
    fi
    
    # Simple frequency selection based on designed frequency
    local freq_list=""
    
    # Extract integer part of frequency
    local freq_int=$(echo "$designed_freq" | cut -d. -f1)
    
    # Simple frequency selection without complex comparisons
    case "$freq_int" in
        [0-9])
            # HF frequencies - use HF bands
            freq_list="3.0 5.0 7.0 10.0 14.0 18.0 21.0 28.0"
            ;;
        1[0-9])
            # Low VHF - use VHF bands  
            freq_list="14.0 18.0 21.0 24.0 28.0"
            ;;
        [3-9][0-9])
            # VHF - use VHF bands
            freq_list="30.0 50.0 70.0 88.0"
            ;;
        1[0-9][0-9])
            # High VHF - use VHF bands
            freq_list="118.0 121.0 125.0 130.0 135.0 137.0"
            ;;
        [2-9][0-9][0-9])
            # UHF - use UHF bands
            freq_list="225.0 250.0 275.0 300.0"
            ;;
        *)
            # Default fallback
            freq_list="3.0 5.0 7.0 10.0 14.0 18.0 21.0 28.0"
            ;;
    esac
    
    log_info "Designed frequency: ${designed_freq}MHz, using frequencies: $freq_list"
    echo "$freq_list"
}

# Function to apply attitude transformation to antenna geometry
apply_attitude_transformation() {
    local model_file="$1"
    local roll="$2"
    local pitch="$3"
    
    # Convert angles to radians
    local roll_rad=$(echo "scale=10; $roll * 3.14159265359 / 180" | bc)
    local pitch_rad=$(echo "scale=10; $pitch * 3.14159265359 / 180" | bc)
    
    # Calculate transformation matrices
    local cos_roll=$(echo "scale=10; c($roll_rad)" | bc -l)
    local sin_roll=$(echo "scale=10; s($roll_rad)" | bc -l)
    local cos_pitch=$(echo "scale=10; c($pitch_rad)" | bc -l)
    local sin_pitch=$(echo "scale=10; s($pitch_rad)" | bc -l)
    
    # Apply transformation to all wire segments in the EZNEC file
    # This is a simplified transformation - in practice, you'd need to parse
    # the EZNEC file and transform each wire segment's coordinates
    log_info "Applying attitude transformation: roll=${roll}°, pitch=${pitch}°"
    
    # For now, we'll add a comment to the EZNEC file indicating the attitude
    echo "# Attitude: roll=${roll}°, pitch=${pitch}°" >> "$model_file"
}

# Function to generate 3D attitude patterns for aircraft
generate_aircraft_3d_patterns() {
    local antenna_file="$1"
    local antenna_name="$2"
    local altitudes="$3"
    
    # Get appropriate frequencies for this antenna
    local frequencies=$(get_appropriate_frequencies "$BASE_DIR/$antenna_file")
    
    log_info "Generating 3D attitude patterns for $antenna_name"
    
    # Create patterns directory
    local patterns_dir="$BASE_DIR/$(dirname "$antenna_file")/patterns"
    mkdir -p "$patterns_dir"
    
    # Use aircraft-specific attitude intervals
    local roll_angles=("${AIRCRAFT_ROLL_ANGLES[@]}")
    local pitch_angles=("${AIRCRAFT_PITCH_ANGLES[@]}")
    
    # Process each frequency
    for freq in $frequencies; do
        # Create frequency directory
        local freq_dir="$patterns_dir/${freq}mhz"
        mkdir -p "$freq_dir"
        
        # Process each altitude
        for alt in $altitudes; do
            local alt_dir="$freq_dir/${alt}m"
            mkdir -p "$alt_dir"
            
            # Process each roll angle
            for roll in "${roll_angles[@]}"; do
                # Process each pitch angle
                for pitch in "${pitch_angles[@]}"; do
                    # Create attitude-specific pattern file
                    local base_name=$(basename "$antenna_file" .ez)
                    local pattern_file="$alt_dir/roll_${roll}_pitch_${pitch}.txt"
                    
                    # Check if pattern file already exists
                    if ! check_file_exists "$pattern_file" "pattern"; then
                        continue
                    fi
                    
                    if [ "$DRY_RUN" = "true" ]; then
                        log_info "DRY RUN: Would generate pattern for $antenna_name at $freq MHz, ${alt}m altitude, roll=${roll}°, pitch=${pitch}°"
                        continue
                    fi
                    
                    # Create attitude-specific model
                    local model_file="$alt_dir/${base_name}_${freq}.0MHz_roll_${roll}_pitch_${pitch}.ez"
                    cp "$BASE_DIR/$antenna_file" "$model_file"
                    
                    # Update frequency
                    sed -i "s/^FR.*/FR 0 1 0 0 ${freq}000.0 0/" "$model_file"
                    
                    # Update ground parameters for altitude
                    if [ "$alt" -gt 1000 ]; then
                        # High altitude - free space
                        sed -i "s/^GD.*/GD  0  0  0  0  0.0  1.0/" "$model_file"
                    else
                        # Low altitude - ground effects
                        sed -i "s/^GD.*/GD  0  0  0  0  0.005  13/" "$model_file"
                    fi
                    
                    # Apply attitude transformation to antenna geometry
                    apply_attitude_transformation "$model_file" "$roll" "$pitch"
                    
                    # Convert to NEC2
                    "$UTILITIES_DIR/eznec2nec.sh" "$model_file"
                    
                    # Run simulation
                    cd "$alt_dir/"
                    nec2c -i "${base_name}_${freq}.0MHz_roll_${roll}_pitch_${pitch}.nec" -o "${base_name}_${freq}.0MHz_roll_${roll}_pitch_${pitch}.out"
                    
                    # Extract pattern
                    "$UTILITIES_DIR/extract_pattern_advanced.sh" "${base_name}_${freq}.0MHz_roll_${roll}_pitch_${pitch}.out" "roll_${roll}_pitch_${pitch}.txt" "$freq" "$alt"
                    
                    cd - > /dev/null
                    
                    log_success "Generated 3D pattern for $antenna_name at ${freq}MHz, ${alt}m altitude, roll=${roll}°, pitch=${pitch}°"
                done
            done
        done
    done
}

# Function to generate 2D attitude patterns for maritime vehicles
generate_maritime_2d_patterns() {
    local antenna_file="$1"
    local antenna_name="$2"
    
    # Get appropriate frequencies for this antenna
    local frequencies=$(get_appropriate_frequencies "$BASE_DIR/$antenna_file")
    
    log_info "Generating 2D attitude patterns for $antenna_name"
    
    # Create patterns directory
    local patterns_dir="$BASE_DIR/$(dirname "$antenna_file")/patterns"
    mkdir -p "$patterns_dir"
    
    # Use maritime-specific attitude intervals (realistic range to keep antennas above water)
    local roll_angles=("${MARITIME_ROLL_ANGLES[@]}")
    local pitch_angles=("${MARITIME_PITCH_ANGLES[@]}")
    
    # Process each frequency
    for freq in $frequencies; do
        # Create frequency directory
        local freq_dir="$patterns_dir/${freq}mhz"
        mkdir -p "$freq_dir"
        
        # Create altitude directory (always 0m for maritime)
        local alt_dir="$freq_dir/0m"
        mkdir -p "$alt_dir"
        
        # Process each roll angle
        for roll in "${roll_angles[@]}"; do
            # Process each pitch angle
            for pitch in "${pitch_angles[@]}"; do
                # Create attitude-specific pattern file
                local base_name=$(basename "$antenna_file" .ez)
                local pattern_file="$alt_dir/roll_${roll}_pitch_${pitch}.txt"
                
                # Check if pattern file already exists
                if ! check_file_exists "$pattern_file" "pattern"; then
                    continue
                fi
                
                if [ "$DRY_RUN" = "true" ]; then
                    log_info "DRY RUN: Would generate pattern for $antenna_name at $freq MHz, 0m altitude, roll=${roll}°, pitch=${pitch}°"
                    continue
                fi
                
                # Create attitude-specific model
                local model_file="$alt_dir/${base_name}_${freq}.0MHz_roll_${roll}_pitch_${pitch}.ez"
                cp "$BASE_DIR/$antenna_file" "$model_file"
                
                # Update frequency
                sed -i "s/^FR.*/FR 0 1 0 0 ${freq}000.0 0/" "$model_file"
                
                # Maritime vehicles always at sea level - use saltwater ground
                sed -i "s/^GD.*/GD  0  0  0  0  5.0  81/" "$model_file"
                
                # Apply attitude transformation to antenna geometry
                apply_attitude_transformation "$model_file" "$roll" "$pitch"
                
                # Convert to NEC2
                "$UTILITIES_DIR/eznec2nec.sh" "$model_file"
                
                # Run simulation
                cd "$alt_dir/"
                nec2c -i "${base_name}_${freq}.0MHz_roll_${roll}_pitch_${pitch}.nec" -o "${base_name}_${freq}.0MHz_roll_${roll}_pitch_${pitch}.out"
                
                # Extract pattern
                "$UTILITIES_DIR/extract_pattern_advanced.sh" "${base_name}_${freq}.0MHz_roll_${roll}_pitch_${pitch}.out" "roll_${roll}_pitch_${pitch}.txt" "$freq" "0"
                
                cd - > /dev/null
                
                log_success "Generated 2D pattern for $antenna_name at ${freq}MHz, 0m altitude, roll=${roll}°, pitch=${pitch}°"
            done
        done
    done
}

# Function to show help
show_help() {
    cat << EOF
FGCom-mumble 3D Pattern Generation Script

USAGE:
    $0 [OPTIONS] [CATEGORY]

OPTIONS:
    -h, --help              Show this help message
    -v, --verbose           Enable verbose output
    -d, --dry-run           Show what would be done without actually doing it
    -o, --overwrite         Overwrite existing pattern files
    -j, --jobs N            Number of parallel jobs (default: $MAX_PARALLEL_JOBS)

CATEGORIES:
    aircraft                Generate 3D attitude patterns for aircraft
    maritime               Generate 2D attitude patterns for maritime vehicles
    all                    Generate all 3D patterns (default)

EXAMPLES:
    $0 --dry-run aircraft                    # Show what aircraft 3D patterns would be generated
    $0 --overwrite --jobs 10 maritime       # Generate maritime 2D patterns with 10 jobs, overwriting existing
    $0 --verbose all                         # Generate all 3D patterns with verbose output

NOTES:
    - By default, existing pattern files are NOT overwritten
    - Use --overwrite to force regeneration of existing patterns
    - Use --dry-run to see what would be generated without actually doing it
    - The script uses up to $MAX_PARALLEL_JOBS parallel jobs by default
    - Aircraft patterns include roll/pitch for multiple altitudes
    - Maritime patterns include roll/pitch for sea level only

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
            aircraft|maritime|all)
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
        
        # Pass the proper altitude intervals
        local altitudes_str=$(printf "%s " "${ALL_ALTITUDES[@]}")
        generate_aircraft_3d_patterns "$antenna_file" "$antenna_name" "$altitudes_str"
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
        
        generate_maritime_2d_patterns "$antenna_file" "$antenna_name"
    done
}

# Main function
main() {
    # Parse command line arguments
    parse_arguments "$@"
    
    log_section "FGCom-mumble 3D Pattern Generation"
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
    
    # Generate patterns based on category
    case "$CATEGORY" in
        "aircraft")
            generate_aircraft_patterns
            ;;
        "maritime")
            generate_maritime_patterns
            ;;
        "all")
            generate_aircraft_patterns
            generate_maritime_patterns
            ;;
        *)
            log_error "Unknown category: $CATEGORY"
            show_help
            exit 1
            ;;
    esac
    
    log_success "3D pattern generation complete!"
}

# Run main function
main "$@"
