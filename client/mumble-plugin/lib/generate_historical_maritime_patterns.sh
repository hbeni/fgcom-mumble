#!/bin/bash

# Generate radiation patterns for historical maritime HF antennas
# Uses correct frequencies for each antenna type

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANTENNA_PATTERNS_DIR="$SCRIPT_DIR/antenna_patterns"

# Logging functions
log_info() {
    echo "[INFO] $1"
}

log_success() {
    echo "[SUCCESS] $1"
}

log_error() {
    echo "[ERROR] $1"
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    
    if ! command -v nec2c &> /dev/null; then
        log_error "nec2c not found. Please install nec2c."
        exit 1
    fi
    
    if [ ! -f "$SCRIPT_DIR/eznec2nec.sh" ]; then
        log_error "eznec2nec.sh not found in $SCRIPT_DIR"
        exit 1
    fi
    
    if [ ! -f "$SCRIPT_DIR/extract_pattern_advanced.sh" ]; then
        log_error "extract_pattern_advanced.sh not found in $SCRIPT_DIR"
        exit 1
    fi
    
    log_success "All dependencies found"
}

# Source the pattern extraction script
source "$SCRIPT_DIR/extract_pattern_advanced.sh"

# Generate patterns for historical maritime antennas
generate_historical_patterns() {
    log_info "Generating patterns for historical maritime HF antennas..."
    
    # Maritime HF antennas (ship-based) - original orientations
    local maritime_antennas=(
        "Ground-based/maritime_hf/t_type_500khz.ez:0.5"
        "Ground-based/maritime_hf/long_wire_2mhz.ez:2.0"
        "Ground-based/maritime_hf/inverted_l_630m.ez:0.472"
        "Ground-based/maritime_hf/long_wire_2200m.ez:0.136"
    )
    
    # Maritime HF antennas - North-South orientations
    local maritime_antennas_ns=(
        "Ground-based/maritime_hf/t_type_500khz_ns.ez:0.5"
        "Ground-based/maritime_hf/long_wire_2mhz_ns.ez:2.0"
        "Ground-based/maritime_hf/inverted_l_630m_ns.ez:0.472"
        "Ground-based/maritime_hf/long_wire_2200m_ns.ez:0.136"
    )
    
    # Maritime HF antennas - East-West orientations
    local maritime_antennas_ew=(
        "Ground-based/maritime_hf/t_type_500khz_ew.ez:0.5"
        "Ground-based/maritime_hf/long_wire_2mhz_ew.ez:2.0"
        "Ground-based/maritime_hf/inverted_l_630m_ew.ez:0.472"
        "Ground-based/maritime_hf/long_wire_2200m_ew.ez:0.136"
    )
    
    # Coastal station antennas - North-South orientations
    local coastal_antennas_ns=(
        "Ground-based/coastal_stations/t_type_500khz_coastal_ns.ez:0.5"
        "Ground-based/coastal_stations/long_wire_2mhz_coastal_ns.ez:2.0"
        "Ground-based/coastal_stations/inverted_l_630m_coastal_ns.ez:0.472"
        "Ground-based/coastal_stations/long_wire_2200m_coastal_ns.ez:0.136"
    )
    
    # Coastal station antennas - East-West orientations
    local coastal_antennas_ew=(
        "Ground-based/coastal_stations/t_type_500khz_coastal_ew.ez:0.5"
        "Ground-based/coastal_stations/long_wire_2mhz_coastal_ew.ez:2.0"
        "Ground-based/coastal_stations/inverted_l_630m_coastal_ew.ez:0.472"
        "Ground-based/coastal_stations/long_wire_2200m_coastal_ew.ez:0.136"
    )
    
    # VHF/UHF antennas
    local vhf_uhf_antennas=(
        "Ground-based/yagi_144mhz/yagi_144mhz_11element.ez:144.0"
        "Ground-based/yagi_70cm/yagi_70cm_16element.ez:432.0"
        "Ground-based/dual_band_omni/dual_band_omni_2m_70cm.ez:144.0"
        "Ground-based/dual_band_omni/dual_band_omni_2m_70cm.ez:432.0"
    )
    
    # Process maritime antennas (original orientations)
    for antenna_spec in "${maritime_antennas[@]}"; do
        local eznec_file="${antenna_spec%:*}"
        local frequency="${antenna_spec#*:}"
        
        if [ -f "$ANTENNA_PATTERNS_DIR/$eznec_file" ]; then
            log_info "Processing maritime antenna: $eznec_file at ${frequency}MHz"
            generate_single_pattern "$ANTENNA_PATTERNS_DIR/$eznec_file" "$frequency" "0" "maritime"
        else
            log_error "File not found: $ANTENNA_PATTERNS_DIR/$eznec_file"
        fi
    done
    
    # Process maritime antennas (North-South orientations)
    for antenna_spec in "${maritime_antennas_ns[@]}"; do
        local eznec_file="${antenna_spec%:*}"
        local frequency="${antenna_spec#*:}"
        
        if [ -f "$ANTENNA_PATTERNS_DIR/$eznec_file" ]; then
            log_info "Processing maritime antenna (N-S): $eznec_file at ${frequency}MHz"
            generate_single_pattern "$ANTENNA_PATTERNS_DIR/$eznec_file" "$frequency" "0" "maritime_ns"
        else
            log_error "File not found: $ANTENNA_PATTERNS_DIR/$eznec_file"
        fi
    done
    
    # Process maritime antennas (East-West orientations)
    for antenna_spec in "${maritime_antennas_ew[@]}"; do
        local eznec_file="${antenna_spec%:*}"
        local frequency="${antenna_spec#*:}"
        
        if [ -f "$ANTENNA_PATTERNS_DIR/$eznec_file" ]; then
            log_info "Processing maritime antenna (E-W): $eznec_file at ${frequency}MHz"
            generate_single_pattern "$ANTENNA_PATTERNS_DIR/$eznec_file" "$frequency" "0" "maritime_ew"
        else
            log_error "File not found: $ANTENNA_PATTERNS_DIR/$eznec_file"
        fi
    done
    
    # Process coastal station antennas (North-South orientations)
    for antenna_spec in "${coastal_antennas_ns[@]}"; do
        local eznec_file="${antenna_spec%:*}"
        local frequency="${antenna_spec#*:}"
        
        if [ -f "$ANTENNA_PATTERNS_DIR/$eznec_file" ]; then
            log_info "Processing coastal station antenna (N-S): $eznec_file at ${frequency}MHz"
            generate_single_pattern "$ANTENNA_PATTERNS_DIR/$eznec_file" "$frequency" "0" "coastal_ns"
        else
            log_error "File not found: $ANTENNA_PATTERNS_DIR/$eznec_file"
        fi
    done
    
    # Process coastal station antennas (East-West orientations)
    for antenna_spec in "${coastal_antennas_ew[@]}"; do
        local eznec_file="${antenna_spec%:*}"
        local frequency="${antenna_spec#*:}"
        
        if [ -f "$ANTENNA_PATTERNS_DIR/$eznec_file" ]; then
            log_info "Processing coastal station antenna (E-W): $eznec_file at ${frequency}MHz"
            generate_single_pattern "$ANTENNA_PATTERNS_DIR/$eznec_file" "$frequency" "0" "coastal_ew"
        else
            log_error "File not found: $ANTENNA_PATTERNS_DIR/$eznec_file"
        fi
    done
    
    # Process VHF/UHF antennas
    for antenna_spec in "${vhf_uhf_antennas[@]}"; do
        local eznec_file="${antenna_spec%:*}"
        local frequency="${antenna_spec#*:}"
        
        if [ -f "$ANTENNA_PATTERNS_DIR/$eznec_file" ]; then
            log_info "Processing VHF/UHF antenna: $eznec_file at ${frequency}MHz"
            generate_single_pattern "$ANTENNA_PATTERNS_DIR/$eznec_file" "$frequency" "0" "vhf_uhf"
        else
            log_error "File not found: $ANTENNA_PATTERNS_DIR/$eznec_file"
        fi
    done
}

# Generate pattern for a single antenna
generate_single_pattern() {
    local eznec_file="$1"
    local frequency_mhz="$2"
    local altitude_m="$3"
    local antenna_type="$4"
    
    if [ ! -f "$eznec_file" ]; then
        log_error "EZNEC file not found: $eznec_file"
        return 1
    fi
    
    local base_name=$(basename "$eznec_file" .ez)
    local output_dir="$(dirname "$eznec_file")"
    local final_dir="$output_dir/patterns/${frequency_mhz}mhz"
    local final_pattern="$final_dir/${base_name}_${frequency_mhz}MHz_${altitude_m}m_pattern.txt"
    
    # Skip if pattern already exists
    if [ -f "$final_pattern" ]; then
        log_info "Pattern already exists: $final_pattern"
        return 0
    fi
    
    local work_dir="/tmp/nec_work_$$_${RANDOM}"
    
    # Create temporary working directory
    mkdir -p "$work_dir"
    cd "$work_dir"
    
    # Copy original EZNEC file (use absolute path)
    cp "$eznec_file" "${base_name}.ez"
    
    # Update frequency in EZNEC file
    sed -i "s/^FR.*/FR 0 1 0 0 ${frequency_mhz} 0/" "${base_name}.ez"
    
    # Convert to NEC2 format
    if bash "$SCRIPT_DIR/eznec2nec.sh" "${base_name}.ez" "${base_name}.nec" 2>/dev/null; then
        log_info "EZNEC conversion successful for $antenna_type at ${frequency_mhz}MHz"
        
        # Run NEC2 simulation
        if nec2c -i "${base_name}.nec" -o "${base_name}.out" 2>/dev/null; then
            log_info "NEC2 simulation successful for $antenna_type at ${frequency_mhz}MHz"
            
            # Extract radiation pattern
            if extract_radiation_pattern_advanced "${base_name}.out" "${base_name}_pattern.txt" "$frequency_mhz" "$altitude_m" 2>/dev/null; then
                log_success "Pattern extraction successful for $antenna_type at ${frequency_mhz}MHz"
                
                # Create proper directory structure and move pattern file
                mkdir -p "$final_dir"
                mv "${base_name}_pattern.txt" "$final_pattern"
                log_success "Generated: $final_pattern"
            else
                log_error "Pattern extraction failed for $antenna_type at ${frequency_mhz}MHz"
            fi
        else
            log_error "NEC2 simulation failed for $antenna_type at ${frequency_mhz}MHz"
        fi
    else
        log_error "EZNEC conversion failed for $antenna_type at ${frequency_mhz}MHz"
    fi
    
    # Cleanup
    cd - > /dev/null
    rm -rf "$work_dir"
    return 0
}

# Main function
main() {
    log_info "Starting historical maritime pattern generation..."
    log_info "This will generate radiation patterns using CORRECT frequencies for each antenna type"
    
    check_dependencies
    generate_historical_patterns
    
    # Count generated patterns
    local pattern_count=$(find "$ANTENNA_PATTERNS_DIR" -name "*_pattern.txt" | wc -l)
    log_success "Pattern generation completed!"
    log_info "Total radiation patterns generated: $pattern_count"
    
    # Show breakdown by antenna type
    log_info "Pattern breakdown:"
    for antenna_type in maritime_hf coastal_stations yagi_144mhz yagi_70cm dual_band_omni; do
        local count=$(find "$ANTENNA_PATTERNS_DIR/Ground-based/$antenna_type" -name "*_pattern.txt" 2>/dev/null | wc -l)
        if [ "$count" -gt 0 ]; then
            log_info "  $antenna_type: $count patterns"
        fi
    done
}

# Run main function
main "$@"
