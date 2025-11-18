#!/bin/bash

# FGCom-mumble Configuration Setup Helper
# This script guides users through setting up all configuration files

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration variables
CONFIG_DIR="$(dirname "$0")/../configs"
ENV_FILE="$(dirname "$0")/../.env"
BACKUP_DIR="$(dirname "$0")/../configs/backup"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Function to print colored output
print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

print_success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

print_error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

print_info() {
    echo -e "${CYAN}[INFO] $1${NC}"
}

# Function to ask yes/no questions
ask_yes_no() {
    local prompt="$1"
    local default="${2:-n}"
    
    while true; do
        if [[ "$default" == "y" ]]; then
            read -p "$prompt [Y/n]: " -r response
            response=${response:-y}
        else
            read -p "$prompt [y/N]: " -r response
            response=${response:-n}
        fi
        
        case $response in
            [Yy]|[Yy][Ee][Ss]) return 0 ;;
            [Nn]|[Nn][Oo]) return 1 ;;
            *) echo "Please answer yes or no." ;;
        esac
    done
}

# Function to ask for input with optional skip
ask_input() {
    local prompt="$1"
    local var_name="$2"
    local default="${3:-}"
    local required="${4:-false}"
    
    while true; do
        if [[ -n "$default" ]]; then
            read -p "$prompt [$default]: " -r response
            response=${response:-$default}
        else
            read -p "$prompt (press Enter to skip): " -r response
        fi
        
        if [[ -z "$response" && "$required" == "true" ]]; then
            echo "This field is required. Please enter a value."
            continue
        elif [[ -z "$response" && "$required" == "false" ]]; then
            eval "$var_name=''"
            return 0
        else
            eval "$var_name='$response'"
            return 0
        fi
    done
}

# Function to generate secure API key
generate_api_key() {
    openssl rand -hex 32 2>/dev/null || python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || echo "fgcom_$(date +%s)_$(shuf -i 1000-9999 -n 1)"
}

# Function to backup existing config
backup_config() {
    local file="$1"
    if [[ -f "$file" ]]; then
        cp "$file" "$BACKUP_DIR/$(basename "$file").backup.$(date +%Y%m%d_%H%M%S)"
        print_success "Backed up existing $file"
    fi
}

# Main setup function
main() {
    print_header "FGCom-mumble Configuration Setup"
    echo "This script will help you configure FGCom-mumble with all necessary settings."
    echo "You can press Enter to skip any optional fields."
    echo ""
    
    # Check if running from correct directory
    if [[ ! -d "$CONFIG_DIR" ]]; then
        print_error "Configuration directory not found. Please run this script from the FGCom-mumble root directory."
        exit 1
    fi
    
    print_info "Starting configuration setup..."
    
    # =============================================================================
    # CORE APPLICATION SETTINGS
    # =============================================================================
    print_header "Core Application Settings"
    
    # Generate API key if needed
    if ask_yes_no "Do you want to generate a secure API key for FGCom-mumble?" "y"; then
        FGCOM_API_KEY=$(generate_api_key)
        print_success "Generated API key: $FGCOM_API_KEY"
    else
        ask_input "Enter your FGCom API key" "FGCOM_API_KEY" "" "true"
    fi
    
    # Database settings
    if ask_yes_no "Do you want to configure database settings?" "n"; then
        ask_input "Database host" "DB_HOST" "localhost"
        ask_input "Database port" "DB_PORT" "5432"
        ask_input "Database name" "DB_NAME" "fgcom_mumble"
        ask_input "Database username" "DB_USER" "fgcom_user"
        ask_input "Database password" "DB_PASSWORD" "" "true"
    fi
    
    # =============================================================================
    # EXTERNAL DATA SOURCES
    # =============================================================================
    print_header "External Data Sources"
    print_info "FGCom-mumble can integrate with various external data sources for enhanced realism."
    print_info "You can skip any services you don't have access to."
    
    # NOAA Space Weather
    if ask_yes_no "Do you have NOAA Space Weather Prediction Center API access?" "n"; then
        print_info "Get API key from: https://www.swpc.noaa.gov/"
        ask_input "NOAA SWPC API key" "NOAA_SWPC_API_KEY"
        ask_input "NOAA SWPC username" "NOAA_SWPC_USERNAME"
        ask_input "NOAA SWPC password" "NOAA_SWPC_PASSWORD"
    fi
    
    # NASA API
    if ask_yes_no "Do you have NASA API access?" "n"; then
        print_info "Get API key from: https://api.nasa.gov/"
        ask_input "NASA API key" "NASA_API_KEY"
        ask_input "NASA username" "NASA_USERNAME"
        ask_input "NASA password" "NASA_PASSWORD"
    fi
    
    # OpenWeatherMap
    if ask_yes_no "Do you have OpenWeatherMap API access?" "n"; then
        print_info "Get API key from: https://openweathermap.org/api"
        ask_input "OpenWeatherMap API key" "OPENWEATHERMAP_API_KEY"
        ask_input "OpenWeatherMap username" "OPENWEATHERMAP_USERNAME"
        ask_input "OpenWeatherMap password" "OPENWEATHERMAP_PASSWORD"
    fi
    
    # NOAA Weather
    if ask_yes_no "Do you have NOAA Weather API access?" "n"; then
        print_info "Get API key from: https://www.weather.gov/documentation/services-web-api"
        ask_input "NOAA Weather API key" "NOAA_WEATHER_API_KEY"
        ask_input "NOAA Weather username" "NOAA_WEATHER_USERNAME"
        ask_input "NOAA Weather password" "NOAA_WEATHER_PASSWORD"
    fi
    
    # USGS Elevation Data
    if ask_yes_no "Do you have USGS National Elevation Dataset access?" "n"; then
        print_info "Get API key from: https://www.usgs.gov/centers/eros/science-services"
        ask_input "USGS API key" "USGS_API_KEY"
        ask_input "USGS username" "USGS_USERNAME"
        ask_input "USGS password" "USGS_PASSWORD"
    fi
    
    # Lightning Data
    if ask_yes_no "Do you have lightning data access (WWLLN or Vaisala)?" "n"; then
        print_info "Lightning data enhances atmospheric effects simulation"
        ask_input "Lightning API key" "LIGHTNING_API_KEY"
        ask_input "Lightning username" "LIGHTNING_USERNAME"
        ask_input "Lightning password" "LIGHTNING_PASSWORD"
    fi
    
    # =============================================================================
    # GPU ACCELERATION SETTINGS
    # =============================================================================
    print_header "GPU Acceleration Settings"
    
    if ask_yes_no "Do you want to enable GPU acceleration?" "y"; then
        print_info "GPU acceleration can significantly improve performance for radio propagation calculations"
        
        # GPU Mode
        echo "GPU acceleration modes:"
        echo "1) Client mode - Use your local GPU"
        echo "2) Server mode - Use server GPU for all clients"
        echo "3) Hybrid mode - Distribute work between client and server"
        echo "4) Disabled - Use CPU only"
        
        while true; do
            read -p "Choose GPU mode (1-4) [3]: " -r gpu_mode_choice
            gpu_mode_choice=${gpu_mode_choice:-3}
            
            case $gpu_mode_choice in
                1) GPU_MODE="client"; break ;;
                2) GPU_MODE="server"; break ;;
                3) GPU_MODE="hybrid"; break ;;
                4) GPU_MODE="disabled"; break ;;
                *) echo "Please choose 1, 2, 3, or 4" ;;
            esac
        done
        
        if [[ "$GPU_MODE" != "disabled" ]]; then
            # GPU Type
            echo "GPU acceleration types:"
            echo "1) CUDA (NVIDIA GPUs)"
            echo "2) OpenCL (AMD/Intel GPUs)"
            echo "3) Metal (Apple Silicon)"
            echo "4) Auto-detect"
            
            while true; do
                read -p "Choose GPU type (1-4) [4]: " -r gpu_type_choice
                gpu_type_choice=${gpu_type_choice:-4}
                
                case $gpu_type_choice in
                    1) GPU_TYPE="cuda"; break ;;
                    2) GPU_TYPE="opencl"; break ;;
                    3) GPU_TYPE="metal"; break ;;
                    4) GPU_TYPE="auto"; break ;;
                    *) echo "Please choose 1, 2, 3, or 4" ;;
                esac
            done
            
            # GPU Memory
            ask_input "GPU memory limit (in MB)" "GPU_MEMORY_LIMIT" "1024"
            
            # Shared GPU Computing
            if ask_yes_no "Do you want to enable shared GPU computing?" "n"; then
                print_info "Shared GPU computing allows multiple GPUs to work together"
                ask_input "Number of GPUs to use" "GPU_COUNT" "1"
                ask_input "GPU device IDs (comma-separated)" "GPU_DEVICE_IDS" "0"
            fi
        fi
    else
        GPU_MODE="disabled"
    fi
    
    # =============================================================================
    # FEATURE TOGGLES
    # =============================================================================
    print_header "Feature Configuration"
    print_info "You can enable/disable specific features based on your needs"
    
    # Core features
    if ask_yes_no "Enable terrain analysis?" "y"; then
        ENABLE_TERRAIN_ANALYSIS="true"
    else
        ENABLE_TERRAIN_ANALYSIS="false"
    fi
    
    if ask_yes_no "Enable antenna pattern modeling?" "y"; then
        ENABLE_ANTENNA_PATTERNS="true"
    else
        ENABLE_ANTENNA_PATTERNS="false"
    fi
    
    if ask_yes_no "Enable solar data integration?" "y"; then
        ENABLE_SOLAR_DATA="true"
    else
        ENABLE_SOLAR_DATA="false"
    fi
    
    if ask_yes_no "Enable audio effects and processing?" "y"; then
        ENABLE_AUDIO_EFFECTS="true"
    else
        ENABLE_AUDIO_EFFECTS="false"
    fi
    
    # Advanced features
    if ask_yes_no "Enable distributed computing?" "n"; then
        ENABLE_DISTRIBUTED_COMPUTING="true"
    else
        ENABLE_DISTRIBUTED_COMPUTING="false"
    fi
    
    if ask_yes_no "Enable EME (Earth-Moon-Earth) calculations?" "n"; then
        ENABLE_EME_CALCULATIONS="true"
    else
        ENABLE_EME_CALCULATIONS="false"
    fi

    # ATIS Weather Integration
    if ask_yes_no "Enable ATIS Weather Integration (automatic ATIS updates based on weather)?" "n"; then
        ENABLE_ATIS_WEATHER="true"
        print_info "ATIS Weather Integration will be configured in the next section"
    else
        ENABLE_ATIS_WEATHER="false"
    fi
    
    # =============================================================================
    # NETWORK SETTINGS
    # =============================================================================
    print_header "Network Configuration"
    
    ask_input "UDP port for client communication" "UDP_PORT" "12345"
    ask_input "WebSocket port for real-time updates" "WEBSOCKET_PORT" "8080"
    ask_input "REST API port" "REST_API_PORT" "8081"
    
    if ask_yes_no "Enable secure communication (HTTPS/WSS)?" "n"; then
        ENABLE_SECURE_COMM="true"
        ask_input "SSL certificate path" "SSL_CERT_PATH"
        ask_input "SSL private key path" "SSL_KEY_PATH"
    else
        ENABLE_SECURE_COMM="false"
    fi
    
    # =============================================================================
    # MONITORING AND LOGGING
    # =============================================================================
    print_header "Monitoring and Logging"
    
    echo "Log levels: DEBUG, INFO, WARN, ERROR"
    ask_input "Log level" "LOG_LEVEL" "INFO"
    
    if ask_yes_no "Enable debug logging?" "n"; then
        DEBUG_LOGGING="true"
    else
        DEBUG_LOGGING="false"
    fi
    
    if ask_yes_no "Enable GPU monitoring?" "n"; then
        ENABLE_GPU_MONITORING="true"
    else
        ENABLE_GPU_MONITORING="false"
    fi
    

    # =============================================================================
    # ATIS WEATHER INTEGRATION CONFIGURATION
    # =============================================================================
    if [ "$ENABLE_ATIS_WEATHER" = "true" ]; then
        print_header "ATIS Weather Integration Configuration"
        print_info "Configure automatic ATIS updates based on weather changes"
        
        # Weather API Configuration
        ask_input "Aviation Weather API Key" "AVIATION_WEATHER_API_KEY" ""
        ask_input "OpenWeatherMap API Key (fallback)" "OPENWEATHER_API_KEY" ""
        
        # Airport Configuration
        print_info "Enter airports to monitor (comma-separated, e.g., KJFK,ENGM,EGLL):"
        ask_input "Airports to monitor" "ATIS_AIRPORTS" "KJFK,ENGM,EGLL"
        
        # Weather Thresholds
        print_info "Configure weather change thresholds:"
        ask_input "Wind direction change threshold (degrees)" "WIND_DIRECTION_THRESHOLD" "10"
        ask_input "Wind speed change threshold (knots)" "WIND_SPEED_THRESHOLD" "5"
        ask_input "Temperature change threshold (Celsius)" "TEMPERATURE_THRESHOLD" "2.0"
        ask_input "Pressure change threshold (hPa)" "PRESSURE_THRESHOLD" "0.68"
        
        # Update Settings
        ask_input "ATIS update interval (minutes)" "ATIS_UPDATE_INTERVAL" "60"
        ask_input "Maximum age for weather data (hours)" "WEATHER_MAX_AGE" "12"
        
        # TTS Configuration
        if ask_yes_no "Configure TTS settings for ATIS generation?" "y"; then
            ask_input "TTS Voice" "TTS_VOICE" "en_US-lessac-medium"
            ask_input "TTS Speed" "TTS_SPEED" "1.0"
            ask_input "TTS Pitch" "TTS_PITCH" "1.0"
        fi
        
        print_success "ATIS Weather Integration configuration completed"
    fi
    # =============================================================================
    # GENERATE CONFIGURATION FILES
    # =============================================================================
    print_header "Generating Configuration Files"
    
    # Backup existing files
    backup_config "$ENV_FILE"
    backup_config "$CONFIG_DIR/gpu_acceleration.conf"
    backup_config "$CONFIG_DIR/feature_toggles.conf"
    
    # Generate .env file
    print_info "Generating .env file..."
    cat > "$ENV_FILE" << EOF
# FGCom-mumble Environment Variables
# Generated by setup_configuration.sh on $(date)

# Core Application Settings
FGCOM_API_KEY="$FGCOM_API_KEY"
DB_HOST="$DB_HOST"
DB_PORT="$DB_PORT"
DB_NAME="$DB_NAME"
DB_USER="$DB_USER"
DB_PASSWORD="$DB_PASSWORD"

# External Data Sources
NOAA_SWPC_API_KEY="$NOAA_SWPC_API_KEY"
NOAA_SWPC_USERNAME="$NOAA_SWPC_USERNAME"
NOAA_SWPC_PASSWORD="$NOAA_SWPC_PASSWORD"
NASA_API_KEY="$NASA_API_KEY"
NASA_USERNAME="$NASA_USERNAME"
NASA_PASSWORD="$NASA_PASSWORD"
OPENWEATHERMAP_API_KEY="$OPENWEATHERMAP_API_KEY"
OPENWEATHERMAP_USERNAME="$OPENWEATHERMAP_USERNAME"
OPENWEATHERMAP_PASSWORD="$OPENWEATHERMAP_PASSWORD"
NOAA_WEATHER_API_KEY="$NOAA_WEATHER_API_KEY"
NOAA_WEATHER_USERNAME="$NOAA_WEATHER_USERNAME"
NOAA_WEATHER_PASSWORD="$NOAA_WEATHER_PASSWORD"
USGS_API_KEY="$USGS_API_KEY"
USGS_USERNAME="$USGS_USERNAME"
USGS_PASSWORD="$USGS_PASSWORD"
LIGHTNING_API_KEY="$LIGHTNING_API_KEY"
LIGHTNING_USERNAME="$LIGHTNING_USERNAME"
LIGHTNING_PASSWORD="$LIGHTNING_PASSWORD"

# Network Settings
UDP_PORT="$UDP_PORT"
WEBSOCKET_PORT="$WEBSOCKET_PORT"
REST_API_PORT="$REST_API_PORT"
ENABLE_SECURE_COMM="$ENABLE_SECURE_COMM"
SSL_CERT_PATH="$SSL_CERT_PATH"
SSL_KEY_PATH="$SSL_KEY_PATH"

# Monitoring and Logging
LOG_LEVEL="$LOG_LEVEL"
DEBUG_LOGGING="$DEBUG_LOGGING"
ENABLE_GPU_MONITORING="$ENABLE_GPU_MONITORING"

# ATIS Weather Integration
ENABLE_ATIS_WEATHER="$ENABLE_ATIS_WEATHER"
AVIATION_WEATHER_API_KEY="$AVIATION_WEATHER_API_KEY"
OPENWEATHER_API_KEY="$OPENWEATHER_API_KEY"
ATIS_AIRPORTS="$ATIS_AIRPORTS"
WIND_DIRECTION_THRESHOLD="$WIND_DIRECTION_THRESHOLD"
WIND_SPEED_THRESHOLD="$WIND_SPEED_THRESHOLD"
TEMPERATURE_THRESHOLD="$TEMPERATURE_THRESHOLD"
PRESSURE_THRESHOLD="$PRESSURE_THRESHOLD"
ATIS_UPDATE_INTERVAL="$ATIS_UPDATE_INTERVAL"
WEATHER_MAX_AGE="$WEATHER_MAX_AGE"
TTS_VOICE="$TTS_VOICE"
TTS_SPEED="$TTS_SPEED"
TTS_PITCH="$TTS_PITCH"
EOF
    
    # Generate GPU acceleration config
    print_info "Generating GPU acceleration configuration..."
    cat > "$CONFIG_DIR/gpu_acceleration.conf" << EOF
# GPU Acceleration Configuration
# Generated by setup_configuration.sh on $(date)

[gpu_acceleration]
enable_gpu_acceleration = $([[ "$GPU_MODE" != "disabled" ]] && echo "true" || echo "false")
gpu_mode = $GPU_MODE
gpu_device_id = 0
gpu_memory_limit = $((GPU_MEMORY_LIMIT * 1024 * 1024))  # Convert MB to bytes
gpu_work_group_size = 256
gpu_max_concurrent_operations = 4

# CUDA settings
[cuda]
enable_cuda = $([[ "$GPU_TYPE" == "cuda" || "$GPU_TYPE" == "auto" ]] && echo "true" || echo "false")
cuda_device_count = ${GPU_COUNT:-1}
cuda_device_id = 0
cuda_memory_pool_size = $((GPU_MEMORY_LIMIT * 1024 * 1024 / 2))  # Half of total memory
cuda_stream_count = 4
cuda_block_size = 256
cuda_grid_size = 1024

# OpenCL settings
[opencl]
enable_opencl = $([[ "$GPU_TYPE" == "opencl" || "$GPU_TYPE" == "auto" ]] && echo "true" || echo "false")
opencl_platform_id = 0
opencl_device_id = 0
opencl_device_type = GPU
opencl_memory_pool_size = $((GPU_MEMORY_LIMIT * 1024 * 1024 / 2))
opencl_queue_count = 4
opencl_work_group_size = 256

# Metal settings (Apple)
[metal]
enable_metal = $([[ "$GPU_TYPE" == "metal" || "$GPU_TYPE" == "auto" ]] && echo "true" || echo "false")
metal_device_id = 0
metal_memory_pool_size = $((GPU_MEMORY_LIMIT * 1024 * 1024 / 2))
metal_queue_count = 4

# Shared GPU Computing
[shared_computing]
enable_shared_gpu = $([[ -n "$GPU_COUNT" && "$GPU_COUNT" -gt 1 ]] && echo "true" || echo "false")
gpu_count = ${GPU_COUNT:-1}
gpu_device_ids = ${GPU_DEVICE_IDS:-0}
work_distribution = workload

# Performance settings
[performance]
gpu_timeout = 5000
gpu_retry_count = 3
gpu_fallback_to_cpu = true
gpu_benchmark_mode = false
gpu_profiling_enabled = false
gpu_memory_optimization = true

# Monitoring
[monitoring]
enable_gpu_monitoring = $ENABLE_GPU_MONITORING
monitor_gpu_usage = $ENABLE_GPU_MONITORING
monitor_gpu_memory = $ENABLE_GPU_MONITORING
monitor_gpu_temperature = $ENABLE_GPU_MONITORING
gpu_monitoring_interval = 1000
EOF
    
    # Generate feature toggles config
    print_info "Generating feature toggles configuration..."
    cat > "$CONFIG_DIR/feature_toggles.conf" << EOF
# Feature Toggles Configuration
# Generated by setup_configuration.sh on $(date)

[feature_toggles]
# Core Features
enable_radio_communication = true
enable_terrain_analysis = $ENABLE_TERRAIN_ANALYSIS
enable_antenna_patterns = $ENABLE_ANTENNA_PATTERNS
enable_propagation_modeling = true

# Advanced Features
enable_gpu_acceleration = $([[ "$GPU_MODE" != "disabled" ]] && echo "true" || echo "false")
enable_distributed_computing = $ENABLE_DISTRIBUTED_COMPUTING
enable_eme_calculations = $ENABLE_EME_CALCULATIONS
enable_solar_data_integration = $ENABLE_SOLAR_DATA

# Audio Features
enable_audio_effects = $ENABLE_AUDIO_EFFECTS
enable_noise_reduction = $ENABLE_AUDIO_EFFECTS
enable_agc_squelch = $ENABLE_AUDIO_EFFECTS
enable_frequency_offset = $ENABLE_AUDIO_EFFECTS

# Network Features
enable_udp_communication = true
enable_websocket_api = true
enable_rest_api = true
enable_secure_communication = $ENABLE_SECURE_COMM

# External Data Integration
enable_noaa_swpc = $([[ -n "$NOAA_SWPC_API_KEY" ]] && echo "true" || echo "false")
enable_nasa_data = $([[ -n "$NASA_API_KEY" ]] && echo "true" || echo "false")
enable_weather_data = $([[ -n "$OPENWEATHERMAP_API_KEY" || -n "$NOAA_WEATHER_API_KEY" ]] && echo "true" || echo "false")
enable_lightning_data = $([[ -n "$LIGHTNING_API_KEY" ]] && echo "true" || echo "false")
enable_elevation_data = $([[ -n "$USGS_API_KEY" ]] && echo "true" || echo "false")

# ATIS Weather Integration Features
enable_atis_weather_integration = $ENABLE_ATIS_WEATHER
enable_atis_weather_monitoring = $ENABLE_ATIS_WEATHER
enable_automatic_atis_generation = $ENABLE_ATIS_WEATHER
enable_atis_letter_system = $ENABLE_ATIS_WEATHER
enable_atis_pressure_correction = $ENABLE_ATIS_WEATHER
enable_atis_runway_detection = $ENABLE_ATIS_WEATHER
enable_atis_gust_detection = $ENABLE_ATIS_WEATHER
enable_atis_visibility_monitoring = $ENABLE_ATIS_WEATHER
enable_atis_cloud_cover_monitoring = $ENABLE_ATIS_WEATHER
enable_atis_temperature_monitoring = $ENABLE_ATIS_WEATHER
enable_atis_wind_monitoring = $ENABLE_ATIS_WEATHER
enable_atis_dew_point_monitoring = $ENABLE_ATIS_WEATHER
enable_atis_qnh_monitoring = $ENABLE_ATIS_WEATHER
enable_atis_qfe_monitoring = $ENABLE_ATIS_WEATHER
enable_atis_notifications = false
enable_atis_webhook_notifications = false
enable_atis_email_notifications = false
enable_atis_debug_logging = false
enable_atis_verbose_logging = false
enable_atis_performance_monitoring = $ENABLE_ATIS_WEATHER
enable_atis_error_recovery = $ENABLE_ATIS_WEATHER
enable_atis_fallback_apis = $ENABLE_ATIS_WEATHER
enable_atis_caching = $ENABLE_ATIS_WEATHER
enable_atis_persistence = $ENABLE_ATIS_WEATHER

# Monitoring
enable_debug_logging = $DEBUG_LOGGING
enable_gpu_monitoring = $ENABLE_GPU_MONITORING
log_level = $LOG_LEVEL
EOF
    
    # Set proper permissions
    chmod 600 "$ENV_FILE"
    
    print_success "Configuration files generated successfully!"
    print_info "Environment file: $ENV_FILE"
    print_info "GPU config: $CONFIG_DIR/gpu_acceleration.conf"
    print_info "Feature toggles: $CONFIG_DIR/feature_toggles.conf"
    print_info "Backup files: $BACKUP_DIR/"
    
    # =============================================================================
    # FINAL INSTRUCTIONS
    # =============================================================================
    print_header "Setup Complete!"
    
    print_success "FGCom-mumble has been configured successfully!"
    echo ""
    print_info "Next steps:"
    echo "1. Review the generated configuration files"
    echo "2. Test your setup with: make test"
    echo "3. Start the server with: make start-server"
    echo "4. Connect clients and begin flying!"
    echo ""
    print_warning "Remember to keep your .env file secure and never commit it to version control!"
    echo ""
    print_info "For more information, see the documentation in the docs/ directory."
}

# Run the main function
main "$@"
