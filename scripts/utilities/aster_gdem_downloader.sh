#!/bin/bash

# ASTER GDEM Terrain Data Downloader
# Downloads ASTER Global Digital Elevation Model data for specific countries/counties
# Requires NASA Earthdata account and credentials

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOWNLOAD_DIR="${SCRIPT_DIR}/../terrain_data"
LOG_FILE="${SCRIPT_DIR}/aster_download.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

# Check dependencies
check_dependencies() {
    log "Checking dependencies..."
    
    if ! command -v wget &> /dev/null; then
        error "wget is required but not installed. Please install wget."
    fi
    
    if ! command -v gdalinfo &> /dev/null; then
        warning "GDAL is not installed. Some features may not work properly."
        warning "Install GDAL for better terrain data processing: sudo apt-get install gdal-bin"
    fi
    
    if ! command -v unzip &> /dev/null; then
        error "unzip is required but not installed. Please install unzip."
    fi
}

# Create download directory
setup_directories() {
    log "Setting up directories..."
    mkdir -p "$DOWNLOAD_DIR"
    mkdir -p "${DOWNLOAD_DIR}/raw"
    mkdir -p "${DOWNLOAD_DIR}/processed"
}

# Display available countries/regions
show_available_regions() {
    cat << EOF

Available Countries/Regions for ASTER GDEM:

NORTH AMERICA:
  - United States (USA)
  - Canada (CAN)
  - Mexico (MEX)

EUROPE:
  - United Kingdom (GBR)
  - Germany (DEU)
  - France (FRA)
  - Italy (ITA)
  - Spain (ESP)
  - Norway (NOR)
  - Sweden (SWE)
  - Finland (FIN)

ASIA:
  - Japan (JPN)
  - China (CHN)
  - India (IND)
  - Australia (AUS)
  - New Zealand (NZL)

AFRICA:
  - South Africa (ZAF)
  - Egypt (EGY)
  - Kenya (KEN)

SOUTH AMERICA:
  - Brazil (BRA)
  - Argentina (ARG)
  - Chile (CHL)

Note: Enter country code (3-letter ISO code) or full country name
EOF
}

# Get NASA Earthdata credentials
get_credentials() {
    if [[ -z "$NASA_USERNAME" || -z "$NASA_PASSWORD" ]]; then
        info "NASA Earthdata credentials not found in environment variables."
        echo
        echo "Please provide your NASA Earthdata credentials:"
        echo "You can get a free account at: https://urs.earthdata.nasa.gov/"
        echo
        read -p "Enter NASA Earthdata username: " NASA_USERNAME
        read -s -p "Enter NASA Earthdata password: " NASA_PASSWORD
        echo
    fi
}

# Download ASTER GDEM data for specific region
download_aster_data() {
    local region="$1"
    local region_name="$2"
    
    log "Starting ASTER GDEM download for $region_name..."
    
    # NASA Earthdata ASTER GDEM collection URL
    local base_url="https://e4ftl01.cr.usgs.gov/ASTT/ASTGTM.003/2000.02.01"
    
    # Create region-specific directory
    local region_dir="${DOWNLOAD_DIR}/raw/${region}"
    mkdir -p "$region_dir"
    
    log "Downloading ASTER GDEM tiles for $region_name..."
    
    # Note: This is a simplified example. In practice, you would need to:
    # 1. Query the NASA Earthdata API for available tiles
    # 2. Filter by geographic bounds for the specific country/region
    # 3. Download the relevant tiles
    
    # Example tile naming pattern: ASTGTM2_N{lat}E{lon}_dem.tif
    # You would need to determine the appropriate tile coordinates for your region
    
    warning "This is a template script. Actual implementation requires:"
    warning "1. NASA Earthdata API integration"
    warning "2. Geographic coordinate mapping for countries"
    warning "3. Tile boundary calculations"
    warning "4. Authentication with NASA Earthdata"
    
    # Placeholder for actual download logic
    log "Would download tiles for region: $region_name"
    log "Target directory: $region_dir"
}

# Process downloaded terrain data
process_terrain_data() {
    local region="$1"
    local region_name="$2"
    
    log "Processing terrain data for $region_name..."
    
    local raw_dir="${DOWNLOAD_DIR}/raw/${region}"
    local processed_dir="${DOWNLOAD_DIR}/processed/${region}"
    mkdir -p "$processed_dir"
    
    if [[ ! -d "$raw_dir" || -z "$(ls -A "$raw_dir" 2>/dev/null)" ]]; then
        warning "No raw data found for $region_name. Skipping processing."
        return
    fi
    
    # Check if GDAL is available for processing
    if command -v gdalinfo &> /dev/null; then
        log "Using GDAL for terrain data processing..."
        
        # Example GDAL processing commands
        # gdalwarp -t_srs EPSG:4326 input.tif output.tif
        # gdal_translate -of GTiff input.tif output.tif
        
        log "Terrain data processing completed for $region_name"
    else
        warning "GDAL not available. Raw data saved to: $raw_dir"
        warning "Install GDAL for terrain data processing: sudo apt-get install gdal-bin"
    fi
}

# Main function
main() {
    log "ASTER GDEM Terrain Data Downloader"
    log "=================================="
    
    # Check dependencies
    check_dependencies
    
    # Setup directories
    setup_directories
    
    # Show available regions
    show_available_regions
    
    # Get user input
    echo
    read -p "Enter country name or 3-letter code: " user_input
    
    # Convert to uppercase for consistency
    user_input=$(echo "$user_input" | tr '[:lower:]' '[:upper:]')
    
    # Map user input to region codes
    case "$user_input" in
        "USA"|"UNITED STATES"|"US")
            region="USA"
            region_name="United States"
            ;;
        "CAN"|"CANADA")
            region="CAN"
            region_name="Canada"
            ;;
        "GBR"|"UNITED KINGDOM"|"UK")
            region="GBR"
            region_name="United Kingdom"
            ;;
        "DEU"|"GERMANY")
            region="DEU"
            region_name="Germany"
            ;;
        "FRA"|"FRANCE")
            region="FRA"
            region_name="France"
            ;;
        "JPN"|"JAPAN")
            region="JPN"
            region_name="Japan"
            ;;
        "AUS"|"AUSTRALIA")
            region="AUS"
            region_name="Australia"
            ;;
        *)
            error "Unsupported region: $user_input"
            ;;
    esac
    
    log "Selected region: $region_name ($region)"
    
    # Get NASA credentials
    get_credentials
    
    # Download data
    download_aster_data "$region" "$region_name"
    
    # Process data
    process_terrain_data "$region" "$region_name"
    
    log "Download and processing completed for $region_name"
    log "Data saved to: ${DOWNLOAD_DIR}/processed/${region}"
    log "Log file: $LOG_FILE"
}

# Run main function
main "$@"
