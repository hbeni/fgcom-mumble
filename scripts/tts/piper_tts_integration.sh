#!/bin/bash

# Piper TTS Integration for FGcom-Mumble ATIS Generation
# This script provides automatic ATIS recording generation using Piper TTS
# Integrates with existing FGcom-Mumble ATIS module and server infrastructure

set -e

# Configuration - integrate with existing FGcom-Mumble paths
PIPER_DIR="${PIPER_DIR:-/opt/piper}"
MODELS_DIR="${MODELS_DIR:-$PIPER_DIR/models}"
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/fgcom-atis}"
FGCOM_SERVER_DIR="${FGCOM_SERVER_DIR:-/home/haaken/github-projects/fgcom-mumble-dev/server}"
FGCOM_RECORDINGS_DIR="${FGCOM_RECORDINGS_DIR:-$FGCOM_SERVER_DIR/recordings}"
DEFAULT_MODEL="en_US-lessac-medium"
DEFAULT_LANGUAGE="en_US"

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

# Check if Piper is installed
check_piper_installation() {
    if [ ! -f "$PIPER_DIR/piper" ]; then
        log_error "Piper not found at $PIPER_DIR/piper"
        log_info "Please install Piper first using:"
        log_info "  wget https://github.com/rhasspy/piper/releases/latest/download/piper_amd64.tar.gz"
        log_info "  tar -xzf piper_amd64.tar.gz"
        log_info "  sudo mv piper /opt/piper/"
        return 1
    fi
    return 0
}

# Download and setup Piper model
setup_model() {
    local model_name="${1:-$DEFAULT_MODEL}"
    local model_file="$MODELS_DIR/${model_name}.onnx"
    local config_file="$MODELS_DIR/${model_name}.onnx.json"
    
    if [ -f "$model_file" ] && [ -f "$config_file" ]; then
        log_success "Model $model_name already exists"
        return 0
    fi
    
    log_info "Downloading model: $model_name"
    
    # Create models directory if it doesn't exist
    mkdir -p "$MODELS_DIR"
    
    # Download model files
    local model_url="https://huggingface.co/rhasspy/piper-voices/resolve/v1.0.0/${model_name}/${model_name}.onnx"
    local config_url="https://huggingface.co/rhasspy/piper-voices/resolve/v1.0.0/${model_name}/${model_name}.onnx.json"
    
    log_info "Downloading model file..."
    if ! wget -q --show-progress -O "$model_file" "$model_url"; then
        log_error "Failed to download model file"
        return 1
    fi
    
    log_info "Downloading config file..."
    if ! wget -q --show-progress -O "$config_file" "$config_url"; then
        log_error "Failed to download config file"
        return 1
    fi
    
    log_success "Model $model_name downloaded successfully"
    return 0
}

# Generate ATIS audio from text
generate_atis_audio() {
    local text="$1"
    local output_file="$2"
    local model_name="${3:-$DEFAULT_MODEL}"
    local voice_speed="${4:-1.0}"
    
    if [ -z "$text" ] || [ -z "$output_file" ]; then
        log_error "Usage: generate_atis_audio <text> <output_file> [model] [speed]"
        return 1
    fi
    
    # Check if Piper is available
    if ! check_piper_installation; then
        return 1
    fi
    
    # Setup model if needed
    if ! setup_model "$model_name"; then
        return 1
    fi
    
    # Create output directory
    mkdir -p "$(dirname "$output_file")"
    
    # Generate audio using Piper
    log_info "Generating ATIS audio: $output_file"
    
    # Create temporary text file
    local temp_text_file=$(mktemp)
    echo "$text" > "$temp_text_file"
    
    # Run Piper TTS
    if "$PIPER_DIR/piper" \
        --model "$MODELS_DIR/$model_name" \
        --output_file "$output_file" \
        --length_scale "$voice_speed" \
        < "$temp_text_file"; then
        
        log_success "ATIS audio generated: $output_file"
        rm -f "$temp_text_file"
        return 0
    else
        log_error "Failed to generate ATIS audio"
        rm -f "$temp_text_file"
        return 1
    fi
}

# Generate standard ATIS format compatible with FGcom-Mumble
generate_standard_atis() {
    local airport_code="$1"
    local wind_direction="$2"
    local wind_speed="$3"
    local visibility="$4"
    local weather="$5"
    local temperature="$6"
    local altimeter="$7"
    local output_file="$8"
    local model_name="${9:-$DEFAULT_MODEL}"
    
    # Generate ATIS text in standard format
    local atis_letter=$((RANDOM % 26 + 1))
    local atis_letter_name=$(printf "%c" $((64 + atis_letter)))
    
    local atis_text="This is $airport_code information $atis_letter_name. Wind $wind_direction at $wind_speed knots. Visibility $visibility. $weather. Temperature $temperature. Altimeter $altimeter. Advise on initial contact you have information $atis_letter_name."
    
    # Generate audio
    generate_atis_audio "$atis_text" "$output_file" "$model_name"
}

# Generate ATIS compatible with FGcom-Mumble server format
generate_fgcom_atis() {
    local airport_code="$1"
    local frequency="$2"
    local output_file="$3"
    local model_name="${4:-$DEFAULT_MODEL}"
    
    # Get current weather data (simplified for demo)
    local wind_dir=$((RANDOM % 360))
    local wind_speed=$((RANDOM % 30 + 5))
    local visibility=$((RANDOM % 10 + 5))
    local weather_conditions=("Clear" "Few clouds" "Scattered clouds" "Broken clouds" "Overcast")
    local weather=${weather_conditions[$((RANDOM % ${#weather_conditions[@]}))]}
    local temp=$((RANDOM % 30 + 10))
    local altimeter=$((RANDOM % 5 + 29))
    local altimeter_decimal=$((RANDOM % 100))
    
    # Generate ATIS in FGcom-Mumble format
    local atis_letter=$((RANDOM % 26 + 1))
    local atis_letter_name=$(printf "%c" $((64 + atis_letter)))
    
    local atis_text="This is $airport_code information $atis_letter_name. Wind $wind_dir at $wind_speed knots. Visibility $visibility miles. $weather. Temperature $temp degrees Celsius. Altimeter $altimeter point $altimeter_decimal. Advise on initial contact you have information $atis_letter_name."
    
    # Generate audio
    generate_atis_audio "$atis_text" "$output_file" "$model_name"
    
    # Create FGCS format file for FGcom-Mumble server
    local fgcs_file="${output_file%.*}.fgcs"
    create_fgcs_file "$fgcs_file" "$output_file" "$airport_code" "$frequency"
}

# Create FGCS format file for FGcom-Mumble server
create_fgcs_file() {
    local fgcs_file="$1"
    local audio_file="$2"
    local airport_code="$3"
    local frequency="$4"
    
    log_info "Creating FGCS file: $fgcs_file"
    
    # FGCS header format (based on FGcom-Mumble server format)
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local file_size=$(stat -c%s "$audio_file" 2>/dev/null || echo "0")
    
    # Create FGCS file with header
    {
        echo "FGCS"
        echo "VERSION:1.0"
        echo "AIRPORT:$airport_code"
        echo "FREQUENCY:$frequency"
        echo "TIMESTAMP:$timestamp"
        echo "DURATION:30"
        echo "SAMPLE_RATE:48000"
        echo "CHANNELS:1"
        echo "BITS_PER_SAMPLE:16"
        echo "FORMAT:PCM"
        echo "POWER:100"
        echo "LATITUDE:0.0"
        echo "LONGITUDE:0.0"
        echo "ALTITUDE:0"
        echo "HEADER_END"
    } > "$fgcs_file"
    
    # Append audio data
    cat "$audio_file" >> "$fgcs_file"
    
    log_success "FGCS file created: $fgcs_file"
}

# Generate ATIS for specific airport and frequency
generate_airport_atis() {
    local airport_code="$1"
    local frequency="$2"
    local model_name="${3:-$DEFAULT_MODEL}"
    
    # Create output directory
    local output_dir="$FGCOM_RECORDINGS_DIR/atis/$airport_code"
    mkdir -p "$output_dir"
    
    # Generate ATIS audio
    local audio_file="$output_dir/atis_${airport_code}_$(date +%Y%m%d_%H%M%S).wav"
    local fgcs_file="$output_dir/atis_${airport_code}_$(date +%Y%m%d_%H%M%S).fgcs"
    
    log_info "Generating ATIS for $airport_code on frequency $frequency"
    
    if generate_fgcom_atis "$airport_code" "$frequency" "$audio_file" "$model_name"; then
        log_success "ATIS generated for $airport_code: $audio_file"
        log_info "FGCS file: $fgcs_file"
        return 0
    else
        log_error "Failed to generate ATIS for $airport_code"
        return 1
    fi
}

# Batch generate ATIS for multiple airports
batch_generate_atis() {
    local airports_file="$1"
    local model_name="${2:-$DEFAULT_MODEL}"
    
    if [ ! -f "$airports_file" ]; then
        log_error "Airports file not found: $airports_file"
        return 1
    fi
    
    log_info "Batch generating ATIS from: $airports_file"
    
    while IFS=',' read -r airport_code frequency; do
        if [ -n "$airport_code" ] && [ -n "$frequency" ]; then
            log_info "Processing: $airport_code on $frequency"
            generate_airport_atis "$airport_code" "$frequency" "$model_name"
        fi
    done < "$airports_file"
    
    log_success "Batch ATIS generation completed"
}

# List available models
list_models() {
    log_info "Available Piper models:"
    echo "  - en_US-lessac-medium (Default, English US)"
    echo "  - en_US-lessac-high (High quality English US)"
    echo "  - en_GB-lessac-medium (English UK)"
    echo "  - de_DE-thorsten-medium (German)"
    echo "  - fr_FR-siwis-medium (French)"
    echo "  - es_ES-sharvard-medium (Spanish)"
    echo "  - it_IT-riccardo-medium (Italian)"
    echo "  - pt_BR-faber-medium (Portuguese Brazil)"
    echo "  - nl_NL-mls-medium (Dutch)"
    echo "  - pl_PL-darkman-medium (Polish)"
    echo "  - ru_RU-dmitri-medium (Russian)"
    echo "  - ja_JP-nanami-medium (Japanese)"
    echo "  - ko_KR-kss-medium (Korean)"
    echo "  - zh_CN-huihui-medium (Chinese)"
    echo ""
    log_info "For more models, visit: https://huggingface.co/rhasspy/piper-voices"
}

# Create sample airports configuration
create_sample_config() {
    local config_file="$1"
    
    if [ -z "$config_file" ]; then
        config_file="$FGCOM_SERVER_DIR/atis_airports.csv"
    fi
    
    log_info "Creating sample airports configuration: $config_file"
    
    cat > "$config_file" << EOF
# FGcom-Mumble ATIS Airports Configuration
# Format: AIRPORT_CODE,FREQUENCY
KJFK,121.650
KLAX,121.650
KORD,121.650
KDFW,121.650
KATL,121.650
KLAS,121.650
KPHX,121.650
KSEA,121.650
KIAH,121.650
KMIA,121.650
EGLL,121.650
EGKK,121.650
EGGW,121.650
EGPH,121.650
EGCC,121.650
LFPG,121.650
LFPO,121.650
LFMN,121.650
LFML,121.650
EDDF,121.650
EDDM,121.650
EDDH,121.650
EOF
    
    log_success "Sample configuration created: $config_file"
}

# Main function
main() {
    case "${1:-help}" in
        "generate")
            shift
            generate_atis_audio "$@"
            ;;
        "standard")
            shift
            generate_standard_atis "$@"
            ;;
        "fgcom")
            shift
            generate_fgcom_atis "$@"
            ;;
        "airport")
            shift
            generate_airport_atis "$@"
            ;;
        "batch")
            shift
            batch_generate_atis "$@"
            ;;
        "setup-model")
            shift
            setup_model "$@"
            ;;
        "list-models")
            list_models
            ;;
        "check")
            check_piper_installation
            ;;
        "create-config")
            shift
            create_sample_config "$@"
            ;;
        "help"|*)
            echo "Piper TTS Integration for FGcom-Mumble"
            echo ""
            echo "Usage: $0 <command> [options]"
            echo ""
            echo "Commands:"
            echo "  generate <text> <output_file> [model] [speed]"
            echo "    Generate ATIS audio from text"
            echo ""
            echo "  standard <airport> <wind_dir> <wind_speed> <visibility> <weather> <temp> <altimeter> <output_file> [model]"
            echo "    Generate standard ATIS format"
            echo ""
            echo "  fgcom <airport> <frequency> <output_file> [model]"
            echo "    Generate FGcom-Mumble compatible ATIS"
            echo ""
            echo "  airport <airport_code> <frequency> [model]"
            echo "    Generate ATIS for specific airport"
            echo ""
            echo "  batch <airports_file> [model]"
            echo "    Batch generate ATIS for multiple airports"
            echo ""
            echo "  setup-model [model_name]"
            echo "    Download and setup a Piper model"
            echo ""
            echo "  list-models"
            echo "    List available models"
            echo ""
            echo "  create-config [config_file]"
            echo "    Create sample airports configuration"
            echo ""
            echo "  check"
            echo "    Check Piper installation"
            echo ""
            echo "Environment Variables:"
            echo "  PIPER_DIR           - Piper installation directory (default: /opt/piper)"
            echo "  MODELS_DIR          - Models directory (default: \$PIPER_DIR/models)"
            echo "  OUTPUT_DIR          - Default output directory (default: /tmp/fgcom-atis)"
            echo "  FGCOM_SERVER_DIR    - FGcom-Mumble server directory"
            echo "  FGCOM_RECORDINGS_DIR - FGcom-Mumble recordings directory"
            echo ""
            echo "Examples:"
            echo "  $0 generate \"This is ATIS information Alpha\" /tmp/atis.wav"
            echo "  $0 fgcom KORD 121.650 /tmp/kord_atis.wav"
            echo "  $0 airport KJFK 121.650"
            echo "  $0 batch /path/to/airports.csv"
            echo "  $0 create-config"
            ;;
    esac
}

# Run main function with all arguments
main "$@"
