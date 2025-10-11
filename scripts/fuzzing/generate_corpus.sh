#!/bin/bash

# FGCom-mumble High-Quality Corpus Generator
# Implements best practices for fuzzing corpus creation

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CORPUS_DIR="$PROJECT_ROOT/corpus"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[CORPUS]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[CORPUS]${NC} $1"
}

# Create diverse, high-quality corpus
create_quality_corpus() {
    local target="$1"
    local corpus_dir="$CORPUS_DIR/$target"
    
    log_info "Creating high-quality corpus for $target..."
    mkdir -p "$corpus_dir"
    
    case "$target" in
        "fuzz_security_functions")
            # Security corpus: authentication, encryption, validation
            echo "admin" > "$corpus_dir/minimal_auth.txt"
            echo "user:pass:role:admin:session:token" > "$corpus_dir/complex_auth.txt"
            echo "" > "$corpus_dir/empty_input.txt"
            echo "admin@domain.com" > "$corpus_dir/email_auth.txt"
            echo "管理员:пароль" > "$corpus_dir/unicode_auth.txt"
            echo "admin:password:invalid:format" > "$corpus_dir/malformed_auth.txt"
            ;;
        "fuzz_network_protocol")
            # Network corpus: UDP packets, protocol messages
            echo "PING" > "$corpus_dir/minimal_ping.txt"
            echo "RADIO:118.100:TX:1000:40.7128:-74.0060" > "$corpus_dir/radio_message.txt"
            echo "" > "$corpus_dir/empty_packet.txt"
            echo "STATUS:CONNECTED:CHANNEL:1:QUALITY:85" > "$corpus_dir/status_message.txt"
            echo "RADIO:118.100:TX:invalid:40.7128:-74.0060" > "$corpus_dir/malformed_radio.txt"
            ;;
        "fuzz_audio_processing")
            # Audio corpus: tones, formats, samples
            echo "SILENCE" > "$corpus_dir/silence.txt"
            echo "TONE:440" > "$corpus_dir/single_tone.txt"
            echo "MULTI_TONE:440:880:1320" > "$corpus_dir/multi_tone.txt"
            echo "FORMAT:PCM:44100:16:STEREO" > "$corpus_dir/pcm_format.txt"
            echo "TONE:invalid" > "$corpus_dir/invalid_frequency.txt"
            ;;
        "fuzz_frequency_management")
            # Frequency corpus: aviation frequencies, ranges
            echo "118.100" > "$corpus_dir/ground_freq.txt"
            echo "121.500" > "$corpus_dir/emergency_freq.txt"
            echo "118.000:118.975" > "$corpus_dir/freq_range.txt"
            echo "118.000" > "$corpus_dir/min_frequency.txt"
            echo "136.975" > "$corpus_dir/max_frequency.txt"
            echo "invalid" > "$corpus_dir/invalid_freq.txt"
            ;;
        "fuzz_radio_propagation")
            # Radio corpus: coordinates, distances, calculations
            echo "40.7128,-74.0060" > "$corpus_dir/nyc_coords.txt"
            echo "51.5074,-0.1278" > "$corpus_dir/london_coords.txt"
            echo "40.7128,-74.0060:40.7589,-73.9851" > "$corpus_dir/distance_calc.txt"
            echo "90,0" > "$corpus_dir/north_pole.txt"
            echo "-90,0" > "$corpus_dir/south_pole.txt"
            echo "invalid,coordinates" > "$corpus_dir/invalid_coords.txt"
            ;;
        "fuzz_antenna_patterns")
            # Antenna corpus: patterns, types, configurations
            echo "OMNI:0:360:0" > "$corpus_dir/omnidirectional.txt"
            echo "DIPOLE:0:180:0" > "$corpus_dir/dipole.txt"
            echo "YAGI:0:60:0" > "$corpus_dir/yagi.txt"
            echo "ARRAY:0:360:0:4:0.5" > "$corpus_dir/array_pattern.txt"
            echo "INVALID:0:360:0" > "$corpus_dir/invalid_type.txt"
            ;;
        "fuzz_atis_processing")
            # ATIS corpus: weather reports, aviation information
            echo "ATIS A" > "$corpus_dir/minimal_atis.txt"
            echo "WIND 270 AT 10" > "$corpus_dir/wind_info.txt"
            echo "ATIS A WIND 270 AT 10 VISIBILITY 10 MILES" > "$corpus_dir/full_atis.txt"
            echo "WIND CALM" > "$corpus_dir/calm_wind.txt"
            echo "ATIS INVALID" > "$corpus_dir/invalid_atis.txt"
            ;;
    esac
    
    local file_count=$(ls -1 "$corpus_dir" | wc -l)
    log_success "$target corpus created with $file_count high-quality files"
}

# Main execution
main() {
    log_info "Generating high-quality fuzzing corpus..."
    
    # Create corpus for all fuzzing targets
    create_quality_corpus "fuzz_security_functions"
    create_quality_corpus "fuzz_network_protocol"
    create_quality_corpus "fuzz_audio_processing"
    create_quality_corpus "fuzz_frequency_management"
    create_quality_corpus "fuzz_radio_propagation"
    create_quality_corpus "fuzz_antenna_patterns"
    create_quality_corpus "fuzz_atis_processing"
    
    log_success "High-quality corpus generation completed!"
    log_info "Corpus files available in: $CORPUS_DIR"
}

# Run main function
main "$@"
