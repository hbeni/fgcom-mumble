#!/bin/bash
# Rename EZNEC files to shorter, more manageable names
# This fixes the NEC2 filename length limitation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

# Function to generate short name
get_short_name() {
    local file_path="$1"
    local base_name=$(basename "$file_path" .ez)
    local dir_name=$(dirname "$file_path")
    local parent_dir=$(basename "$dir_name")
    
    # Extract vehicle type and antenna type
    case "$parent_dir" in
        "cessna_172")
            if [[ "$base_name" == *"hf"* ]] || [[ "$base_name" == *"HF"* ]]; then
                echo "cessna-hf"
            elif [[ "$base_name" == *"vhf"* ]] || [[ "$base_name" == *"VHF"* ]]; then
                echo "cessna-vhf"
            else
                echo "cessna-${base_name##*_}"
            fi
            ;;
        "b737_800")
            if [[ "$base_name" == *"realistic"* ]]; then
                echo "b737-real"
            elif [[ "$base_name" == *"vhf"* ]]; then
                echo "b737-vhf"
            else
                echo "b737-${base_name##*_}"
            fi
            ;;
        "c130_hercules")
            if [[ "$base_name" == *"hf"* ]]; then
                echo "c130-hf"
            elif [[ "$base_name" == *"vhf"* ]]; then
                echo "c130-vhf"
            else
                echo "c130-${base_name##*_}"
            fi
            ;;
        "tu95_bear")
            if [[ "$base_name" == *"realistic"* ]]; then
                echo "tu95-real"
            elif [[ "$base_name" == *"vhf"* ]]; then
                echo "tu95-vhf"
            else
                echo "tu95-${base_name##*_}"
            fi
            ;;
        "mi4_hound")
            if [[ "$base_name" == *"vhf"* ]]; then
                echo "mi4-vhf"
            else
                echo "mi4-${base_name##*_}"
            fi
            ;;
        "bell_uh1_huey")
            if [[ "$base_name" == *"realistic"* ]]; then
                echo "huey-real"
            elif [[ "$base_name" == *"vhf"* ]]; then
                echo "huey-vhf"
            else
                echo "huey-${base_name##*_}"
            fi
            ;;
        "t55_soviet_mbt")
            echo "t55-tank"
            ;;
        "leopard1_nato_mbt")
            echo "leopard1-tank"
            ;;
        *)
            # Generic shortening
            if [[ ${#base_name} -gt 15 ]]; then
                # Take first part and last part
                local first_part=$(echo "$base_name" | cut -d'_' -f1)
                local last_part=$(echo "$base_name" | rev | cut -d'_' -f1 | rev)
                echo "${first_part}-${last_part}"
            else
                echo "$base_name"
            fi
            ;;
    esac
}

# Function to rename a single file
rename_eznec_file() {
    local old_file="$1"
    local short_name=$(get_short_name "$old_file")
    local dir_name=$(dirname "$old_file")
    local new_file="$dir_name/${short_name}.ez"
    
    if [ "$old_file" != "$new_file" ]; then
        log_info "Renaming: $(basename "$old_file") -> ${short_name}.ez"
        mv "$old_file" "$new_file"
        log_success "Renamed to: $new_file"
    else
        log_info "No rename needed: $(basename "$old_file")"
    fi
}

# Main function
main() {
    log_info "Starting EZNEC file renaming to shorter names..."
    echo "=========================================="
    
    # Find all EZNEC files
    local eznec_files=($(find client/mumble-plugin/lib/antenna_patterns -name "*.ez" | sort))
    local total_files=${#eznec_files[@]}
    
    log_info "Found $total_files EZNEC files to rename"
    echo "=========================================="
    
    # Rename each file
    for file in "${eznec_files[@]}"; do
        echo ""
        rename_eznec_file "$file"
    done
    
    # Final summary
    echo ""
    echo "=========================================="
    log_success "EZNEC file renaming complete!"
    log_info "Total files processed: $total_files"
    echo "=========================================="
}

# Run main function
main "$@"
