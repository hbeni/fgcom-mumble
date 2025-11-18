#!/bin/bash

# TLE Updater Setup Script
# This script sets up the automatic TLE updater for 24-hour updates

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TLE_UPDATER_BIN="${PROJECT_ROOT}/voice-encryption/systems/satellites/orbital/tle_updater"
TLE_DATA_DIR="${PROJECT_ROOT}/tle_data"
LOG_DIR="${PROJECT_ROOT}/logs"
SERVICE_FILE="/etc/systemd/system/fgcom-tle-updater.service"
TIMER_FILE="/etc/systemd/system/fgcom-tle-updater.timer"
CRON_FILE="/etc/cron.d/fgcom-tle-updater"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}[$(date '+%Y-%m-%d %H:%M:%S')] ${message}${NC}"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_status "${RED}" "Error: This script must be run as root for system installation"
        print_status "${BLUE}" "For user installation, use: $0 --user"
        exit 1
    fi
}

# Function to check dependencies
check_dependencies() {
    print_status "${BLUE}" "Checking dependencies..."
    
    # Check if curl is available
    if ! command -v curl &> /dev/null; then
        print_status "${RED}" "Error: curl is required but not installed"
        print_status "${BLUE}" "Install with: apt-get install curl (Ubuntu/Debian) or yum install curl (RHEL/CentOS)"
        exit 1
    fi
    
    # Check if libcurl development headers are available
    if ! pkg-config --exists libcurl; then
        print_status "${RED}" "Error: libcurl development headers are required"
        print_status "${BLUE}" "Install with: apt-get install libcurl4-openssl-dev (Ubuntu/Debian) or yum install libcurl-devel (RHEL/CentOS)"
        exit 1
    fi
    
    # Check if cmake is available
    if ! command -v cmake &> /dev/null; then
        print_status "${RED}" "Error: cmake is required but not installed"
        print_status "${BLUE}" "Install with: apt-get install cmake (Ubuntu/Debian) or yum install cmake (RHEL/CentOS)"
        exit 1
    fi
    
    print_status "${GREEN}" "Dependencies check passed"
}

# Function to build TLE updater
build_tle_updater() {
    print_status "${BLUE}" "Building TLE updater..."
    
    # Create build directory
    local build_dir="${PROJECT_ROOT}/voice-encryption/systems/satellites/orbital/build"
    mkdir -p "${build_dir}"
    cd "${build_dir}"
    
    # Configure with cmake
    cmake ..
    if [[ $? -ne 0 ]]; then
        print_status "${RED}" "Error: CMake configuration failed"
        exit 1
    fi
    
    # Build
    make -j$(nproc)
    if [[ $? -ne 0 ]]; then
        print_status "${RED}" "Error: Build failed"
        exit 1
    fi
    
    # Check if binary was created
    local built_binary="${build_dir}/tle_updater"
    if [[ ! -f "${built_binary}" ]]; then
        print_status "${RED}" "Error: TLE updater binary not found after build"
        exit 1
    fi
    
    # Copy binary to expected location
    cp "${built_binary}" "${TLE_UPDATER_BIN}"
    chmod +x "${TLE_UPDATER_BIN}"
    
    print_status "${GREEN}" "TLE updater built successfully"
}

# Function to create directories
create_directories() {
    print_status "${BLUE}" "Creating directories..."
    
    mkdir -p "${TLE_DATA_DIR}"
    mkdir -p "${LOG_DIR}"
    
    # Set permissions
    chown -R haaken:haaken "${TLE_DATA_DIR}"
    chown -R haaken:haaken "${LOG_DIR}"
    
    print_status "${GREEN}" "Directories created: ${TLE_DATA_DIR}, ${LOG_DIR}"
}

# Function to install systemd service
install_systemd_service() {
    print_status "${BLUE}" "Installing systemd service..."
    
    # Copy service file
    cp "${SCRIPT_DIR}/fgcom-tle-updater.service" "${SERVICE_FILE}"
    cp "${SCRIPT_DIR}/fgcom-tle-updater.timer" "${TIMER_FILE}"
    
    # Reload systemd
    systemctl daemon-reload
    
    # Enable timer
    systemctl enable fgcom-tle-updater.timer
    
    print_status "${GREEN}" "Systemd service installed and enabled"
    print_status "${BLUE}" "Service file: ${SERVICE_FILE}"
    print_status "${BLUE}" "Timer file: ${TIMER_FILE}"
}

# Function to install cron job
install_cron_job() {
    print_status "${BLUE}" "Installing cron job..."
    
    # Copy cron file
    cp "${SCRIPT_DIR}/tle_update_cron" "${CRON_FILE}"
    
    # Set permissions
    chmod 644 "${CRON_FILE}"
    
    print_status "${GREEN}" "Cron job installed"
    print_status "${BLUE}" "Cron file: ${CRON_FILE}"
}

# Function to install user crontab
install_user_crontab() {
    print_status "${BLUE}" "Installing user crontab..."
    
    # Add to user's crontab
    (crontab -l 2>/dev/null; echo "# TLE Updates - All sources daily at 6:00 AM (24-hour cycle)"; echo "0 6 * * * ${TLE_UPDATER_BIN} --update-dir ${TLE_DATA_DIR} --log-dir ${LOG_DIR} --force >/dev/null 2>&1"; echo "# TLE Updates - ISS hourly for critical tracking"; echo "0 * * * * ${TLE_UPDATER_BIN} --update-dir ${TLE_DATA_DIR} --log-dir ${LOG_DIR} --source iss --force >/dev/null 2>&1") | crontab -
    
    print_status "${GREEN}" "User crontab installed"
}

# Function to test TLE updater
test_tle_updater() {
    print_status "${BLUE}" "Testing TLE updater..."
    
    # Test with help
    "${TLE_UPDATER_BIN}" --help
    if [[ $? -ne 0 ]]; then
        print_status "${RED}" "Error: TLE updater test failed"
        exit 1
    fi
    
    # Test with force update
    print_status "${BLUE}" "Testing TLE download..."
    "${TLE_UPDATER_BIN}" --update-dir "${TLE_DATA_DIR}" --log-dir "${LOG_DIR}" --force
    if [[ $? -ne 0 ]]; then
        print_status "${YELLOW}" "Warning: TLE download test failed (this may be normal if no internet connection)"
    else
        print_status "${GREEN}" "TLE updater test successful"
    fi
}

# Function to show status
show_status() {
    print_status "${BLUE}" "TLE Updater Setup Status:"
    echo
    
    # Check if binary exists
    if [[ -f "${TLE_UPDATER_BIN}" ]]; then
        print_status "${GREEN}" "TLE updater binary: ${TLE_UPDATER_BIN}"
    else
        print_status "${RED}" "TLE updater binary: Not found"
    fi
    
    # Check directories
    if [[ -d "${TLE_DATA_DIR}" ]]; then
        print_status "${GREEN}" "TLE data directory: ${TLE_DATA_DIR}"
    else
        print_status "${RED}" "TLE data directory: Not found"
    fi
    
    if [[ -d "${LOG_DIR}" ]]; then
        print_status "${GREEN}" "Log directory: ${LOG_DIR}"
    else
        print_status "${RED}" "Log directory: Not found"
    fi
    
    # Check systemd service
    if [[ -f "${SERVICE_FILE}" ]]; then
        print_status "${GREEN}" "Systemd service: ${SERVICE_FILE}"
        systemctl is-enabled fgcom-tle-updater.timer &>/dev/null && print_status "${GREEN}" "Timer enabled" || print_status "${YELLOW}" "Timer not enabled"
    else
        print_status "${RED}" "Systemd service: Not installed"
    fi
    
    # Check cron job
    if [[ -f "${CRON_FILE}" ]]; then
        print_status "${GREEN}" "Cron job: ${CRON_FILE}"
    else
        print_status "${RED}" "Cron job: Not installed"
    fi
    
    # Check user crontab
    if crontab -l 2>/dev/null | grep -q "TLE Updates"; then
        print_status "${GREEN}" "User crontab: Installed"
    else
        print_status "${YELLOW}" "User crontab: Not installed"
    fi
}

# Function to show help
show_help() {
    echo "TLE Updater Setup Script"
    echo
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  --user          Install for current user only (no root required)"
    echo "  --system        Install system-wide (requires root)"
    echo "  --build-only    Only build the TLE updater"
    echo "  --test          Test the TLE updater"
    echo "  --status        Show setup status"
    echo "  --help, -h      Show this help message"
    echo
    echo "Examples:"
    echo "  $0 --user       # Install for current user"
    echo "  $0 --system     # Install system-wide (requires root)"
    echo "  $0 --build-only # Only build the binary"
    echo "  $0 --test        # Test the TLE updater"
    echo "  $0 --status      # Show current status"
}

# Main script logic
case "${1:-help}" in
    --user)
        print_status "${BLUE}" "Installing TLE updater for current user..."
        check_dependencies
        build_tle_updater
        create_directories
        install_user_crontab
        test_tle_updater
        print_status "${GREEN}" "TLE updater installed for user"
        ;;
    --system)
        print_status "${BLUE}" "Installing TLE updater system-wide..."
        check_root
        check_dependencies
        build_tle_updater
        create_directories
        install_systemd_service
        install_cron_job
        test_tle_updater
        print_status "${GREEN}" "TLE updater installed system-wide"
        ;;
    --build-only)
        check_dependencies
        build_tle_updater
        print_status "${GREEN}" "TLE updater built successfully"
        ;;
    --test)
        test_tle_updater
        ;;
    --status)
        show_status
        ;;
    --help|-h|help)
        show_help
        ;;
    *)
        print_status "${RED}" "Error: Unknown option '${1}'"
        echo
        show_help
        exit 1
        ;;
esac
