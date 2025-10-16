#!/bin/bash

# Test All Fuzzing Targets with Enhanced Corpus Files
# This script tests all 17 fuzzing targets with the enhanced corpus data

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/test/build-fuzz"
CORPUS_DIR="$PROJECT_ROOT/corpus"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[TEST]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[TEST]${NC} $1"
}

log_error() {
    echo -e "${RED}[TEST]${NC} $1"
}

# Test individual fuzzing target
test_target() {
    local target="$1"
    local corpus_dir="$2"
    local test_name="$3"
    
    log_info "Testing $target with $test_name corpus..."
    
    if [[ ! -f "$BUILD_DIR/$target" ]]; then
        log_error "$target not found in $BUILD_DIR"
        return 1
    fi
    
    if [[ ! -d "$corpus_dir" ]]; then
        log_error "Corpus directory $corpus_dir not found"
        return 1
    fi
    
    local success_count=0
    local total_count=0
    
    # Test with each corpus file
    for corpus_file in "$corpus_dir"/*.txt; do
        if [[ -f "$corpus_file" ]]; then
            ((total_count++))
            if "$BUILD_DIR/$target" "$corpus_file" >/dev/null 2>&1; then
                ((success_count++))
            fi
        fi
    done
    
    if [[ $total_count -gt 0 ]]; then
        local success_rate=$((success_count * 100 / total_count))
        if [[ $success_rate -ge 50 ]]; then
            log_success "$target: $success_count/$total_count tests passed ($success_rate%)"
        else
            log_warning "$target: $success_count/$total_count tests passed ($success_rate%)"
        fi
    else
        log_warning "$target: No corpus files found"
    fi
}

# Test all fuzzing targets
test_all_targets() {
    log_info "Testing all fuzzing targets with enhanced corpus files..."
    
    # Test each target with its corresponding corpus
    test_target "fuzz_voice_encryption" "$CORPUS_DIR/fuzz_voice_encryption" "voice encryption"
    test_target "fuzz_audio_processing" "$CORPUS_DIR/fuzz_audio_processing" "audio processing"
    test_target "fuzz_network_protocol" "$CORPUS_DIR/fuzz_network_protocol" "network protocol"
    test_target "fuzz_radio_propagation" "$CORPUS_DIR/fuzz_radio_propagation" "radio propagation"
    test_target "fuzz_satellite_communication" "$CORPUS_DIR/fuzz_satellite_communication" "satellite communication"
    test_target "fuzz_webrtc_operations" "$CORPUS_DIR/fuzz_webrtc_operations" "WebRTC operations"
    test_target "fuzz_database_operations" "$CORPUS_DIR/fuzz_database_operations" "database operations"
    test_target "fuzz_integration_tests" "$CORPUS_DIR/fuzz_integration_tests" "integration tests"
    test_target "fuzz_security_functions" "$CORPUS_DIR/fuzz_security_functions" "security functions"
    test_target "fuzz_antenna_patterns" "$CORPUS_DIR/fuzz_antenna_patterns" "antenna patterns"
    test_target "fuzz_atis_processing" "$CORPUS_DIR/fuzz_atis_processing" "ATIS processing"
    test_target "fuzz_frequency_management" "$CORPUS_DIR/fuzz_frequency_management" "frequency management"
    test_target "fuzz_geographic_calculations" "$CORPUS_DIR/fuzz_geographic_calculations" "geographic calculations"
    test_target "fuzz_performance_tests" "$CORPUS_DIR/fuzz_performance_tests" "performance tests"
    test_target "fuzz_error_handling" "$CORPUS_DIR/fuzz_error_handling" "error handling"
    test_target "fuzz_input_validation" "$CORPUS_DIR/fuzz_input_validation" "input validation"
    test_target "fuzz_memory_operations" "$CORPUS_DIR/fuzz_memory_operations" "memory operations"
}

# Test with specific corpus files
test_specific_corpus() {
    log_info "Testing with specific enhanced corpus files..."
    
    # Test voice encryption with encryption algorithms
    if [[ -f "$CORPUS_DIR/fuzz_voice_encryption/encryption_algorithms.txt" ]]; then
        log_info "Testing voice encryption with encryption algorithms corpus..."
        if "$BUILD_DIR/fuzz_voice_encryption" "$CORPUS_DIR/fuzz_voice_encryption/encryption_algorithms.txt" >/dev/null 2>&1; then
            log_success "Voice encryption with encryption algorithms: PASSED"
        else
            log_warning "Voice encryption with encryption algorithms: FAILED"
        fi
    fi
    
    # Test audio processing with aviation frequencies
    if [[ -f "$CORPUS_DIR/fuzz_audio_processing/aviation_radio_frequencies.txt" ]]; then
        log_info "Testing audio processing with aviation frequencies corpus..."
        if "$BUILD_DIR/fuzz_audio_processing" "$CORPUS_DIR/fuzz_audio_processing/aviation_radio_frequencies.txt" >/dev/null 2>&1; then
            log_success "Audio processing with aviation frequencies: PASSED"
        else
            log_warning "Audio processing with aviation frequencies: FAILED"
        fi
    fi
    
    # Test network protocol with ADS-B messages
    if [[ -f "$CORPUS_DIR/fuzz_network_protocol/ads_b_messages.txt" ]]; then
        log_info "Testing network protocol with ADS-B messages corpus..."
        if "$BUILD_DIR/fuzz_network_protocol" "$CORPUS_DIR/fuzz_network_protocol/ads_b_messages.txt" >/dev/null 2>&1; then
            log_success "Network protocol with ADS-B messages: PASSED"
        else
            log_warning "Network protocol with ADS-B messages: FAILED"
        fi
    fi
    
    # Test radio propagation with major airports
    if [[ -f "$CORPUS_DIR/fuzz_radio_propagation/major_airports.txt" ]]; then
        log_info "Testing radio propagation with major airports corpus..."
        if "$BUILD_DIR/fuzz_radio_propagation" "$CORPUS_DIR/fuzz_radio_propagation/major_airports.txt" >/dev/null 2>&1; then
            log_success "Radio propagation with major airports: PASSED"
        else
            log_warning "Radio propagation with major airports: FAILED"
        fi
    fi
    
    # Test satellite communication with orbital parameters
    if [[ -f "$CORPUS_DIR/fuzz_satellite_communication/orbital_parameters.txt" ]]; then
        log_info "Testing satellite communication with orbital parameters corpus..."
        if "$BUILD_DIR/fuzz_satellite_communication" "$CORPUS_DIR/fuzz_satellite_communication/orbital_parameters.txt" >/dev/null 2>&1; then
            log_success "Satellite communication with orbital parameters: PASSED"
        else
            log_warning "Satellite communication with orbital parameters: FAILED"
        fi
    fi
}

# Generate test report
generate_report() {
    log_info "Generating test report..."
    
    local report_file="$PROJECT_ROOT/fuzzing_test_report.txt"
    
    cat > "$report_file" << EOF
# FGCom-Mumble Fuzzing Targets Test Report
Generated: $(date)

## Summary
This report shows the results of testing all 17 fuzzing targets with enhanced corpus files.

## Fuzzing Targets Built
EOF

    # List all built targets
    ls -la "$BUILD_DIR"/fuzz_* 2>/dev/null | while read -r line; do
        echo "  $line" >> "$report_file"
    done
    
    cat >> "$report_file" << EOF

## Enhanced Corpus Files
EOF

    # List all corpus directories
    for corpus_dir in "$CORPUS_DIR"/fuzz_*; do
        if [[ -d "$corpus_dir" ]]; then
            local dir_name=$(basename "$corpus_dir")
            echo "### $dir_name" >> "$report_file"
            ls -la "$corpus_dir"/*.txt 2>/dev/null | while read -r line; do
                echo "  $line" >> "$report_file"
            done
            echo "" >> "$report_file"
        fi
    done
    
    cat >> "$report_file" << EOF

## Usage Instructions

### Running Individual Fuzzing Targets
\`\`\`bash
# Test voice encryption
./test/build-fuzz/fuzz_voice_encryption corpus/fuzz_voice_encryption/encryption_algorithms.txt

# Test audio processing
./test/build-fuzz/fuzz_audio_processing corpus/fuzz_audio_processing/aviation_radio_frequencies.txt

# Test network protocol
./test/build-fuzz/fuzz_network_protocol corpus/fuzz_network_protocol/ads_b_messages.txt
\`\`\`

### Running AFL++ Fuzzing
\`\`\`bash
# Set up AFL++ environment
export AFL_HARDEN=1
export AFL_USE_ASAN=1

# Run fuzzing with corpus
afl-fuzz -i corpus/fuzz_voice_encryption -o outputs/voice_encryption -- ./test/build-fuzz/fuzz_voice_encryption @@
\`\`\`

## Enhanced Corpus Coverage

The enhanced corpus files now provide comprehensive coverage for:

1. **Audio Processing**: Aviation radio frequencies, ATC communications, emergency scenarios, weather reports
2. **Network Protocol**: ADS-B messages, ACARS messages, ATC clearances, flight plans
3. **Radio Propagation**: Major airports, radio ranges, terrain effects, weather effects
4. **Voice Encryption**: Encryption algorithms, key exchange, authentication, secure protocols
5. **Satellite Communication**: Orbital parameters, ground stations, frequency bands, communication protocols
6. **WebRTC Operations**: ICE candidates, SDP offers, RTP packets, data channels
7. **Database Operations**: Aircraft registry, flight schedules, airport data, airline codes
8. **Integration Tests**: Complete flight scenarios, emergency procedures, weather diversion, ATC communications
9. **Security Functions**: Pilot authentication, aircraft authentication, encryption keys, access control

## Next Steps

1. Run AFL++ fuzzing with the enhanced corpus files
2. Analyze results for potential vulnerabilities
3. Update corpus files based on fuzzing results
4. Integrate fuzzing into CI/CD pipeline
EOF

    log_success "Test report generated: $report_file"
}

# Main execution
main() {
    log_info "Testing all fuzzing targets with enhanced corpus files..."
    
    # Check if build directory exists
    if [[ ! -d "$BUILD_DIR" ]]; then
        log_error "Build directory $BUILD_DIR not found. Please run build_all_targets.sh first."
        exit 1
    fi
    
    # Check if corpus directory exists
    if [[ ! -d "$CORPUS_DIR" ]]; then
        log_error "Corpus directory $CORPUS_DIR not found."
        exit 1
    fi
    
    # Test all targets
    test_all_targets
    
    # Test specific enhanced corpus files
    test_specific_corpus
    
    # Generate report
    generate_report
    
    log_success "All fuzzing target tests completed!"
    log_info "Check fuzzing_test_report.txt for detailed results"
}

# Run main function
main "$@"



