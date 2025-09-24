#!/bin/bash
# generate_military_patterns.sh - Generate missing military vehicle radiation patterns
# This script specifically addresses the missing military vehicle patterns mentioned in the documentation

set -e

# Source the pattern extraction function
source "$(dirname "$0")/extract_pattern_advanced.sh"

# Configuration
SCRIPT_DIR="$(dirname "$0")"
ANTENNA_PATTERNS_DIR="$SCRIPT_DIR/antenna_patterns"
MILITARY_FREQUENCIES=(3.0 5.0 7.0 9.0)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Generate pattern for a single military vehicle
generate_military_vehicle_pattern() {
    local eznec_file="$1"
    local vehicle_name="$2"
    
    if [ ! -f "$eznec_file" ]; then
        log_error "EZNEC file not found: $eznec_file"
        return 1
    fi
    
    log_info "Processing military vehicle: $vehicle_name"
    
    # Create patterns directory
    local patterns_dir="$(dirname "$eznec_file")/${vehicle_name}_patterns"
    mkdir -p "$patterns_dir"
    
    # Generate patterns for each military frequency
    for frequency in "${MILITARY_FREQUENCIES[@]}"; do
        local freq_dir="$patterns_dir/${frequency}mhz"
        mkdir -p "$freq_dir"
        
        local base_name=$(basename "$eznec_file" .ez)
        local pattern_file="$freq_dir/${vehicle_name}_${frequency}MHz_pattern.txt"
        
        if [ ! -f "$pattern_file" ]; then
            log_info "Generating pattern for $vehicle_name at ${frequency}MHz (ground level)"
            
            # Create frequency-specific EZNEC file
            local freq_eznec="$freq_dir/${vehicle_name}_${frequency}MHz.ez"
            cp "$eznec_file" "$freq_eznec"
            
            # Update frequency in EZNEC file
            sed -i "s/^FR.*/FR 0 1 0 0 ${frequency} 0/" "$freq_eznec"
            
            # Convert to NEC2 format
            local nec_file="$freq_dir/${vehicle_name}_${frequency}MHz.nec"
            if ! "$SCRIPT_DIR/eznec2nec.sh" "$freq_eznec" "$nec_file"; then
                log_error "Failed to convert EZNEC to NEC2 format"
                continue
            fi
            
            # Run NEC2 simulation
            cd "$freq_dir"
            local out_file="${vehicle_name}_${frequency}MHz.out"
            if ! nec2c -i "$(basename "$nec_file")" -o "$out_file" 2>/dev/null; then
                log_warning "NEC2 simulation failed, generating synthetic pattern..."
                generate_synthetic_military_pattern "$pattern_file" "$frequency" "$vehicle_name"
            else
                # Extract radiation pattern
                if ! extract_radiation_pattern_advanced "$out_file" "$pattern_file" "$frequency" "0"; then
                    log_warning "Pattern extraction failed, generating synthetic pattern..."
                    generate_synthetic_military_pattern "$pattern_file" "$frequency" "$vehicle_name"
                fi
            fi
            cd - > /dev/null
            
            # Cleanup temporary files
            rm -f "$freq_eznec" "$nec_file" "$out_file"
            
            log_success "Generated pattern for $vehicle_name at ${frequency}MHz"
        else
            log_info "Pattern already exists: $pattern_file"
        fi
    done
}

# Generate synthetic military pattern
generate_synthetic_military_pattern() {
    local pattern_file="$1"
    local frequency_mhz="$2"
    local vehicle_name="$3"
    
    log_info "Generating synthetic military pattern for $vehicle_name"
    
    # Create pattern file header
    cat > "$pattern_file" << EOF
# FGCom-mumble Far-Field Radiation Pattern (Synthetic Military)
# Frequency: ${frequency_mhz} MHz
# Altitude: 0 m (Ground level)
# Vehicle: $vehicle_name (Military)
# Format: Theta Phi Gain_dBi H_Polarization V_Polarization
# Theta: Elevation angle (0-180 degrees)
# Phi: Azimuth angle (0-360 degrees)
# Gain: Antenna gain in dBi
# H_Polarization: Horizontal polarization component
# V_Polarization: Vertical polarization component
EOF
    
    # Generate synthetic military antenna pattern
    for theta in $(seq 0 5 180); do
        for phi in $(seq 0 10 350); do
            # Military antenna pattern (whip antenna tied down at 45°)
            local gain="0.0"
            
            # Military whip antenna pattern characteristics
            if (( $(echo "$theta > 0 && $theta < 180" | bc -l) )); then
                # Good performance at low angles (ground wave)
                if (( $(echo "$theta < 20" | bc -l) )); then
                    gain="3.0"  # Excellent ground wave performance
                elif (( $(echo "$theta < 45" | bc -l) )); then
                    gain="1.0"  # Good performance
                elif (( $(echo "$theta < 90" | bc -l) )); then
                    gain="-2.0" # Moderate performance
                else
                    gain="-5.0" # Poor performance at high angles
                fi
            fi
            
            # Add frequency-dependent variation for military bands
            local freq_factor="1.0"
            if (( $(echo "$frequency_mhz < 5.0" | bc -l) )); then
                freq_factor="1.2"  # Better at lower frequencies
            elif (( $(echo "$frequency_mhz > 7.0" | bc -l) )); then
                freq_factor="0.8"  # Reduced performance at higher frequencies
            fi
            
            gain=$(echo "scale=2; $gain * $freq_factor" | bc -l)
            
            # Calculate polarization components for military whip
            local h_pol="0.0"
            local v_pol="0.0"
            
            # Military whip antennas are typically vertical polarized
            if (( $(echo "$theta < 60" | bc -l) )); then
                v_pol="1.0"  # Dominant vertical polarization
                h_pol="0.1"  # Minimal horizontal component
            elif (( $(echo "$theta < 120" | bc -l) )); then
                v_pol="0.7"  # Mixed polarization
                h_pol="0.3"
            else
                v_pol="0.3"  # Reduced vertical component
                h_pol="0.7"  # More horizontal component
            fi
            
            echo "$theta $phi $gain $h_pol $v_pol" >> "$pattern_file"
        done
    done
    
    log_success "Generated synthetic military pattern with $(wc -l < "$pattern_file") lines"
}

# Main function
main() {
    log_info "Generating missing military vehicle radiation patterns..."
    log_info "This addresses the 0 pattern files issue mentioned in the documentation"
    
    # Check if nec2c is available
    if ! command -v nec2c &> /dev/null; then
        log_warning "nec2c not found, will generate synthetic patterns only"
    fi
    
    # Check if bc is available
    if ! command -v bc &> /dev/null; then
        log_error "bc calculator not found. Please install bc."
        exit 1
    fi
    
    # Generate patterns for NATO Jeep
    local nato_jeep_eznec="$ANTENNA_PATTERNS_DIR/military-land/nato_jeep_10ft_whip_45deg.ez"
    if [ -f "$nato_jeep_eznec" ]; then
        generate_military_vehicle_pattern "$nato_jeep_eznec" "nato_jeep"
    else
        log_warning "NATO Jeep EZNEC file not found: $nato_jeep_eznec"
    fi
    
    # Generate patterns for Soviet UAZ
    local soviet_uaz_eznec="$ANTENNA_PATTERNS_DIR/military-land/soviet_uaz_4m_whip_45deg.ez"
    if [ -f "$soviet_uaz_eznec" ]; then
        generate_military_vehicle_pattern "$soviet_uaz_eznec" "soviet_uaz"
    else
        log_warning "Soviet UAZ EZNEC file not found: $soviet_uaz_eznec"
    fi
    
    # Generate patterns for existing military vehicles
    local leopard_eznec="$ANTENNA_PATTERNS_DIR/military-land/leopard1_nato_mbt/leopard1_nato_mbt.ez"
    if [ -f "$leopard_eznec" ]; then
        generate_military_vehicle_pattern "$leopard_eznec" "leopard1"
    fi
    
    local t55_eznec="$ANTENNA_PATTERNS_DIR/military-land/t55_soviet_mbt/t55_soviet_mbt.ez"
    if [ -f "$t55_eznec" ]; then
        generate_military_vehicle_pattern "$t55_eznec" "t55"
    fi
    
    log_success "Military pattern generation completed!"
    log_info "Generated patterns are located in the military-land directory"
    
    # Count generated patterns
    local pattern_count=$(find "$ANTENNA_PATTERNS_DIR/military-land" -name "*_pattern.txt" | wc -l)
    log_info "Total military patterns generated: $pattern_count"
}

# Run main function
main "$@"
