#!/bin/bash
# generate_all_patterns.sh - Generate antenna patterns for all vehicles in FGCom-mumble
# Uses the working eznec2nec.sh converter and nec2c

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to process a single EZNEC file
process_eznec_file() {
    local ez_file="$1"
    local output_dir="$2"
    local frequency="$3"
    local vehicle_name="$4"
    
    if [ ! -f "$ez_file" ]; then
        print_error "EZNEC file $ez_file not found"
        return 1
    fi
    
    # Extract base name without extension
    local base_name=$(basename "$ez_file" .ez)
    
    # Create output directory if it doesn't exist
    mkdir -p "$output_dir"
    
    # Convert EZNEC to NEC format
    print_status "Converting $vehicle_name ($base_name) to NEC format..."
    if ./eznec2nec.sh "$ez_file" "$output_dir/${base_name}.nec"; then
        print_success "Converted $base_name to NEC format"
    else
        print_error "Failed to convert $base_name"
        return 1
    fi
    
    # Process with nec2c
    print_status "Processing ${base_name}.nec with nec2c..."
    if nec2c -i "$output_dir/${base_name}.nec" -o "$output_dir/${base_name}.out" 2>/dev/null; then
        # Check if output file was created and has content
        if [ -f "$output_dir/${base_name}.out" ] && [ -s "$output_dir/${base_name}.out" ]; then
            local lines=$(wc -l < "$output_dir/${base_name}.out")
            print_success "Successfully processed $base_name ($lines lines)"
            return 0
        else
            print_error "Output file created but is empty for $base_name"
            return 1
        fi
    else
        print_error "Failed to process $base_name with nec2c"
        return 1
    fi
}

# Function to process aircraft patterns
process_aircraft_patterns() {
    local aircraft_dir="$1"
    local frequency="$2"
    local vehicle_name="$3"
    
    print_status "Processing aircraft patterns for $vehicle_name at ${frequency}MHz"
    
    # Process the main EZNEC file
    local main_ez_file=$(find "$aircraft_dir" -name "*.ez" -not -path "*/patterns/*" | head -1)
    if [ -n "$main_ez_file" ]; then
        local pattern_dir="$aircraft_dir/$(basename "$aircraft_dir")_patterns"
        if process_eznec_file "$main_ez_file" "$pattern_dir" "$frequency" "$vehicle_name"; then
            print_success "Main pattern generated for $vehicle_name"
        else
            print_error "Failed to generate main pattern for $vehicle_name"
        fi
    else
        print_warning "No main EZNEC file found for $vehicle_name"
    fi
}

# Function to process marine patterns
process_marine_patterns() {
    local marine_dir="$1"
    local frequency="$2"
    local vehicle_name="$3"
    
    print_status "Processing marine patterns for $vehicle_name at ${frequency}MHz"
    
    local main_ez_file=$(find "$marine_dir" -name "*.ez" -not -path "*/patterns/*" | head -1)
    if [ -n "$main_ez_file" ]; then
        local pattern_dir="$marine_dir/$(basename "$marine_dir")_patterns"
        if process_eznec_file "$main_ez_file" "$pattern_dir" "$frequency" "$vehicle_name"; then
            print_success "Marine pattern generated for $vehicle_name"
        else
            print_error "Failed to generate marine pattern for $vehicle_name"
        fi
    else
        print_warning "No main EZNEC file found for $vehicle_name"
    fi
}

# Function to process ground vehicle patterns
process_ground_vehicle_patterns() {
    local vehicle_dir="$1"
    local frequency="$2"
    local vehicle_name="$3"
    
    print_status "Processing ground vehicle patterns for $vehicle_name at ${frequency}MHz"
    
    local main_ez_file=$(find "$vehicle_dir" -name "*.ez" -not -path "*/patterns/*" | head -1)
    if [ -n "$main_ez_file" ]; then
        local pattern_dir="$vehicle_dir/$(basename "$vehicle_dir")_patterns"
        if process_eznec_file "$main_ez_file" "$pattern_dir" "$frequency" "$vehicle_name"; then
            print_success "Ground vehicle pattern generated for $vehicle_name"
        else
            print_error "Failed to generate ground vehicle pattern for $vehicle_name"
        fi
    else
        print_warning "No main EZNEC file found for $vehicle_name"
    fi
}

# Function to process ground-based antenna patterns
process_ground_based_patterns() {
    local antenna_dir="$1"
    local frequency="$2"
    local antenna_name="$3"
    
    print_status "Processing ground-based antenna patterns for $antenna_name at ${frequency}MHz"
    
    local main_ez_file=$(find "$antenna_dir" -name "*.ez" -not -path "*/patterns/*" | head -1)
    if [ -n "$main_ez_file" ]; then
        local pattern_dir="$antenna_dir/$(basename "$antenna_dir")_patterns"
        if process_eznec_file "$main_ez_file" "$pattern_dir" "$frequency" "$antenna_name"; then
            print_success "Ground-based antenna pattern generated for $antenna_name"
        else
            print_error "Failed to generate ground-based antenna pattern for $antenna_name"
        fi
    else
        print_warning "No main EZNEC file found for $antenna_name"
    fi
}

# Main processing function
main() {
    local base_dir="antenna_patterns"
    local success_count=0
    local total_count=0
    
    echo "=========================================="
    echo "FGCom-mumble Antenna Pattern Generator"
    echo "=========================================="
    echo ""
    
    # Check if eznec2nec.sh exists
    if [ ! -f "./eznec2nec.sh" ]; then
        print_error "eznec2nec.sh not found in current directory"
        exit 1
    fi
    
    # Check if nec2c is available
    if ! command -v nec2c &> /dev/null; then
        print_error "nec2c not found. Please install nec2c"
        exit 1
    fi
    
    print_status "Starting antenna pattern generation..."
    echo ""
    
    # Process aircraft patterns
    echo "=========================================="
    echo "Processing Aircraft Patterns"
    echo "=========================================="
    
    process_aircraft_patterns "$base_dir/aircraft/b737" "8.9" "Boeing 737"
    ((total_count++))
    if [ $? -eq 0 ]; then ((success_count++)); fi
    
    process_aircraft_patterns "$base_dir/aircraft/c130_hercules" "8.0" "C-130 Hercules"
    ((total_count++))
    if [ $? -eq 0 ]; then ((success_count++)); fi
    
    process_aircraft_patterns "$base_dir/aircraft/cessna_172" "14.23" "Cessna 172"
    ((total_count++))
    if [ $? -eq 0 ]; then ((success_count++)); fi
    
    process_aircraft_patterns "$base_dir/aircraft/tu95_bear" "9.0" "Tu-95 Bear"
    ((total_count++))
    if [ $? -eq 0 ]; then ((success_count++)); fi
    
    process_aircraft_patterns "$base_dir/aircraft/mi4_hound" "7.0" "Mi-4 Hound"
    ((total_count++))
    if [ $? -eq 0 ]; then ((success_count++)); fi
    
    process_aircraft_patterns "$base_dir/aircraft/uh1_huey" "7.0" "UH-1 Huey"
    ((total_count++))
    if [ $? -eq 0 ]; then ((success_count++)); fi
    
    echo ""
    
    # Process marine patterns
    echo "=========================================="
    echo "Processing Marine Patterns"
    echo "=========================================="
    
    process_marine_patterns "$base_dir/boat/sailboat_whip" "14.23" "Sailboat Whip"
    ((total_count++))
    if [ $? -eq 0 ]; then ((success_count++)); fi
    
    process_marine_patterns "$base_dir/boat/sailboat_backstay" "7.15" "Sailboat Backstay"
    ((total_count++))
    if [ $? -eq 0 ]; then ((success_count++)); fi
    
    process_marine_patterns "$base_dir/ship/containership" "3.8" "Container Ship"
    ((total_count++))
    if [ $? -eq 0 ]; then ((success_count++)); fi
    
    echo ""
    
    # Process ground vehicle patterns
    echo "=========================================="
    echo "Processing Ground Vehicle Patterns"
    echo "=========================================="
    
    process_ground_vehicle_patterns "$base_dir/vehicle/ford_transit" "14.23" "Ford Transit"
    ((total_count++))
    if [ $? -eq 0 ]; then ((success_count++)); fi
    
    process_ground_vehicle_patterns "$base_dir/vehicle/vw_passat" "14.23" "VW Passat"
    ((total_count++))
    if [ $? -eq 0 ]; then ((success_count++)); fi
    
    process_ground_vehicle_patterns "$base_dir/military-land/nato_jeep" "7.0" "NATO Jeep"
    ((total_count++))
    if [ $? -eq 0 ]; then ((success_count++)); fi
    
    process_ground_vehicle_patterns "$base_dir/military-land/soviet_uaz" "7.0" "Soviet UAZ"
    ((total_count++))
    if [ $? -eq 0 ]; then ((success_count++)); fi
    
    echo ""
    
    # Process ground-based antenna patterns
    echo "=========================================="
    echo "Processing Ground-Based Antenna Patterns"
    echo "=========================================="
    
    process_ground_based_patterns "$base_dir/Ground-based/yagi_40m" "7.15" "Yagi 40m"
    ((total_count++))
    if [ $? -eq 0 ]; then ((success_count++)); fi
    
    process_ground_based_patterns "$base_dir/Ground-based/yagi_20m" "14.23" "Yagi 20m"
    ((total_count++))
    if [ $? -eq 0 ]; then ((success_count++)); fi
    
    process_ground_based_patterns "$base_dir/Ground-based/yagi_10m" "28.4" "Yagi 10m"
    ((total_count++))
    if [ $? -eq 0 ]; then ((success_count++)); fi
    
    process_ground_based_patterns "$base_dir/Ground-based/yagi_6m" "52.0" "Yagi 6m"
    ((total_count++))
    if [ $? -eq 0 ]; then ((success_count++)); fi
    
    echo ""
    echo "=========================================="
    echo "Pattern Generation Complete!"
    echo "=========================================="
    echo ""
    echo "Summary:"
    echo "--------"
    echo "Total vehicles processed: $total_count"
    echo "Successful: $success_count"
    echo "Failed: $((total_count - success_count))"
    echo ""
    
    if [ $success_count -eq $total_count ]; then
        print_success "All antenna patterns generated successfully!"
    else
        print_warning "Some patterns failed to generate. Check the output above for details."
    fi
    
    echo ""
    echo "Generated pattern files:"
    echo "------------------------"
    find "$base_dir" -name "*.out" -type f | sort | while read -r file; do
        local lines=$(wc -l < "$file")
        echo "  $file ($lines lines)"
    done
}

# Run main function
main "$@"
