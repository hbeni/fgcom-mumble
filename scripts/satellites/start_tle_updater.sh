#!/bin/bash

# TLE Automatic Updater Startup Script
# This script starts the automatic TLE (Two-Line Element) updater for satellite tracking

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TLE_CONFIG_FILE="${PROJECT_ROOT}/voice-encryption/systems/satellites/config/tle_update_config.conf"
TLE_UPDATE_DIR="${PROJECT_ROOT}/tle_data"
LOG_DIR="${PROJECT_ROOT}/logs"
PID_FILE="${PROJECT_ROOT}/tle_updater.pid"

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

# Function to check if TLE updater is already running
check_running() {
    if [[ -f "${PID_FILE}" ]]; then
        local pid=$(cat "${PID_FILE}")
        if ps -p "${pid}" > /dev/null 2>&1; then
            print_status "${YELLOW}" "TLE updater is already running (PID: ${pid})"
            return 0
        else
            print_status "${YELLOW}" "Stale PID file found, removing..."
            rm -f "${PID_FILE}"
        fi
    fi
    return 1
}

# Function to start TLE updater
start_updater() {
    print_status "${BLUE}" "Starting TLE automatic updater..."
    
    # Create necessary directories
    mkdir -p "${TLE_UPDATE_DIR}"
    mkdir -p "${LOG_DIR}"
    
    # Check if configuration file exists
    if [[ ! -f "${TLE_CONFIG_FILE}" ]]; then
        print_status "${RED}" "Error: TLE configuration file not found: ${TLE_CONFIG_FILE}"
        exit 1
    fi
    
    # Start TLE updater in background
    nohup "${PROJECT_ROOT}/voice-encryption/systems/satellites/orbital/tle_updater" \
        --config "${TLE_CONFIG_FILE}" \
        --update-dir "${TLE_UPDATE_DIR}" \
        --log-dir "${LOG_DIR}" \
        --daemon > "${LOG_DIR}/tle_updater.log" 2>&1 &
    
    local pid=$!
    echo "${pid}" > "${PID_FILE}"
    
    # Wait a moment to check if process started successfully
    sleep 2
    
    if ps -p "${pid}" > /dev/null 2>&1; then
        print_status "${GREEN}" "TLE updater started successfully (PID: ${pid})"
        print_status "${BLUE}" "Log file: ${LOG_DIR}/tle_updater.log"
        print_status "${BLUE}" "Update directory: ${TLE_UPDATE_DIR}"
        print_status "${BLUE}" "Configuration: ${TLE_CONFIG_FILE}"
    else
        print_status "${RED}" "Failed to start TLE updater"
        rm -f "${PID_FILE}"
        exit 1
    fi
}

# Function to stop TLE updater
stop_updater() {
    print_status "${BLUE}" "Stopping TLE updater..."
    
    if [[ -f "${PID_FILE}" ]]; then
        local pid=$(cat "${PID_FILE}")
        if ps -p "${pid}" > /dev/null 2>&1; then
            kill "${pid}"
            sleep 2
            
            if ps -p "${pid}" > /dev/null 2>&1; then
                print_status "${YELLOW}" "Force killing TLE updater..."
                kill -9 "${pid}"
            fi
            
            print_status "${GREEN}" "TLE updater stopped"
        else
            print_status "${YELLOW}" "TLE updater was not running"
        fi
        rm -f "${PID_FILE}"
    else
        print_status "${YELLOW}" "No PID file found, TLE updater may not be running"
    fi
}

# Function to restart TLE updater
restart_updater() {
    print_status "${BLUE}" "Restarting TLE updater..."
    stop_updater
    sleep 2
    start_updater
}

# Function to show status
show_status() {
    print_status "${BLUE}" "TLE Updater Status:"
    echo
    
    if [[ -f "${PID_FILE}" ]]; then
        local pid=$(cat "${PID_FILE}")
        if ps -p "${pid}" > /dev/null 2>&1; then
            print_status "${GREEN}" "Status: Running (PID: ${pid})"
            
            # Show process info
            echo
            print_status "${BLUE}" "Process Information:"
            ps -p "${pid}" -o pid,ppid,cmd,etime,pcpu,pmem
            
            # Show log file info
            if [[ -f "${LOG_DIR}/tle_updater.log" ]]; then
                echo
                print_status "${BLUE}" "Recent Log Entries:"
                tail -n 10 "${LOG_DIR}/tle_updater.log"
            fi
            
            # Show TLE files
            echo
            print_status "${BLUE}" "TLE Files:"
            if [[ -d "${TLE_UPDATE_DIR}" ]]; then
                ls -la "${TLE_UPDATE_DIR}/"*.tle 2>/dev/null || echo "No TLE files found"
            else
                echo "TLE directory not found"
            fi
            
        else
            print_status "${RED}" "Status: Not running (stale PID file)"
            rm -f "${PID_FILE}"
        fi
    else
        print_status "${RED}" "Status: Not running"
    fi
}

# Function to show help
show_help() {
    echo "TLE Automatic Updater Control Script"
    echo
    echo "Usage: $0 {start|stop|restart|status|help}"
    echo
    echo "Commands:"
    echo "  start   - Start the TLE automatic updater"
    echo "  stop    - Stop the TLE automatic updater"
    echo "  restart - Restart the TLE automatic updater"
    echo "  status  - Show the current status"
    echo "  help    - Show this help message"
    echo
    echo "Configuration:"
    echo "  Config file: ${TLE_CONFIG_FILE}"
    echo "  Update directory: ${TLE_UPDATE_DIR}"
    echo "  Log directory: ${LOG_DIR}"
    echo
    echo "Log files:"
    echo "  Main log: ${LOG_DIR}/tle_updater.log"
    echo "  TLE files: ${TLE_UPDATE_DIR}/"
}

# Function to check dependencies
check_dependencies() {
    print_status "${BLUE}" "Checking dependencies..."
    
    # Check if curl is available
    if ! command -v curl &> /dev/null; then
        print_status "${RED}" "Error: curl is required but not installed"
        exit 1
    fi
    
    # Check if wget is available (alternative to curl)
    if ! command -v wget &> /dev/null; then
        print_status "${YELLOW}" "Warning: wget is not available, using curl only"
    fi
    
    # Check if the TLE updater binary exists
    local tle_updater_bin="${PROJECT_ROOT}/voice-encryption/systems/satellites/orbital/tle_updater"
    if [[ ! -f "${tle_updater_bin}" ]]; then
        print_status "${RED}" "Error: TLE updater binary not found: ${tle_updater_bin}"
        print_status "${BLUE}" "Please compile the TLE updater first"
        exit 1
    fi
    
    print_status "${GREEN}" "Dependencies check passed"
}

# Main script logic
case "${1:-help}" in
    start)
        if check_running; then
            exit 0
        fi
        check_dependencies
        start_updater
        ;;
    stop)
        stop_updater
        ;;
    restart)
        check_dependencies
        restart_updater
        ;;
    status)
        show_status
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        print_status "${RED}" "Error: Unknown command '${1}'"
        echo
        show_help
        exit 1
        ;;
esac
