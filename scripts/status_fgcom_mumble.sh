#!/bin/bash
#####################################################################################
# FGcom-mumble Status Check Script
# This script checks the status of FGcom-mumble installation
#####################################################################################

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SERVICE_NAME="fgcom-mumble"
MUMBLE_SERVICE="mumble-server"

# Function to print status messages
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

# Function to check service status
check_service_status() {
    print_status "Checking FGcom-mumble service status..."
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_success "FGcom-mumble service is running"
        systemctl status "$SERVICE_NAME" --no-pager -l
    else
        print_error "FGcom-mumble service is not running"
        if systemctl is-failed --quiet "$SERVICE_NAME"; then
            print_error "FGcom-mumble service has failed"
            systemctl status "$SERVICE_NAME" --no-pager -l
        fi
    fi
    echo
}

# Function to check Mumble server status
check_mumble_status() {
    print_status "Checking Mumble server status..."
    
    if systemctl is-active --quiet "$MUMBLE_SERVICE"; then
        print_success "Mumble server is running"
        systemctl status "$MUMBLE_SERVICE" --no-pager -l
    else
        print_error "Mumble server is not running"
        if systemctl is-failed --quiet "$MUMBLE_SERVICE"; then
            print_error "Mumble server has failed"
            systemctl status "$MUMBLE_SERVICE" --no-pager -l
        fi
    fi
    echo
}

# Function to check bot processes
check_bot_processes() {
    print_status "Checking FGcom-mumble bot processes..."
    
    local bots=("fgcom-radio-recorder.bot.lua" "fgcom-radio-playback.bot.lua" "fgcom-status.bot.lua")
    local found_bots=0
    
    for bot in "${bots[@]}"; do
        if pgrep -f "$bot" > /dev/null; then
            print_success "Found running bot: $bot"
            ps aux | grep "$bot" | grep -v grep
            found_bots=$((found_bots + 1))
        else
            print_warning "No running bot found: $bot"
        fi
    done
    
    if [[ $found_bots -eq 0 ]]; then
        print_error "No FGcom-mumble bots are running"
    fi
    echo
}

# Function to check system directories
check_system_directories() {
    print_status "Checking FGcom-mumble system directories..."
    
    local dirs=(
        "/usr/share/fgcom-mumble"
        "/usr/share/fgcom-mumble/server"
        "/usr/share/fgcom-mumble/scripts"
        "/usr/share/fgcom-mumble/configs"
        "/etc/fgcom-mumble"
        "/var/log/fgcom-mumble"
        "/var/lib/fgcom-mumble"
        "/var/lib/fgcom-mumble/recordings"
    )
    
    for dir in "${dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            print_success "Directory exists: $dir"
            ls -la "$dir" | head -5
        else
            print_error "Directory missing: $dir"
        fi
    done
    echo
}

# Function to check certificates
check_certificates() {
    print_status "Checking FGcom-mumble certificates..."
    
    local certs=("recbot.pem" "recbot.key" "playbot.pem" "playbot.key" "statusbot.pem" "statusbot.key")
    
    for cert in "${certs[@]}"; do
        if [[ -f "/etc/fgcom-mumble/$cert" ]]; then
            print_success "Certificate exists: $cert"
            ls -la "/etc/fgcom-mumble/$cert"
        else
            print_error "Certificate missing: $cert"
        fi
    done
    echo
}

# Function to check Mumble channels
check_mumble_channels() {
    print_status "Checking Mumble channels..."
    
    local db_path="/var/lib/mumble-server/fgcom-mumble.sqlite"
    
    if [[ -f "$db_path" ]]; then
        print_success "Mumble database exists: $db_path"
        
        # Check if channels exist
        local channel_count=$(sqlite3 "$db_path" "SELECT COUNT(*) FROM channels WHERE name IN ('fgcom-mumble', 'fgcom-mumble-admins');" 2>/dev/null)
        
        if [[ "$channel_count" -ge 2 ]]; then
            print_success "FGcom-mumble channels exist ($channel_count channels found)"
            sqlite3 "$db_path" "SELECT id, name FROM channels WHERE name IN ('fgcom-mumble', 'fgcom-mumble-admins');" 2>/dev/null
        else
            print_error "FGcom-mumble channels not found in database"
        fi
    else
        print_error "Mumble database not found: $db_path"
    fi
    echo
}

# Function to check recent logs
check_recent_logs() {
    print_status "Checking recent FGcom-mumble logs..."
    
    if [[ -d "/var/log/fgcom-mumble" ]]; then
        print_success "Log directory exists: /var/log/fgcom-mumble"
        ls -la /var/log/fgcom-mumble/
        
        # Show recent log entries
        for log_file in /var/log/fgcom-mumble/*.log; do
            if [[ -f "$log_file" ]]; then
                print_status "Recent entries from $(basename "$log_file"):"
                tail -5 "$log_file" 2>/dev/null || print_warning "Could not read $log_file"
                echo
            fi
        done
    else
        print_error "Log directory not found: /var/log/fgcom-mumble"
    fi
    echo
}

# Function to show system information
show_system_info() {
    print_status "System Information:"
    echo "  Hostname: $(hostname)"
    echo "  OS: $(lsb_release -d | cut -f2)"
    echo "  Kernel: $(uname -r)"
    echo "  Architecture: $(uname -m)"
    echo "  Uptime: $(uptime -p)"
    echo
}

# Function to show network information
show_network_info() {
    print_status "Network Information:"
    echo "  IP Address: $(hostname -I | awk '{print $1}')"
    echo "  Mumble Server Port: 64738"
    echo "  Ice Middleware Port: 6502"
    echo
}

# Main status check function
main() {
    print_status "FGcom-mumble Status Check"
    echo "================================"
    echo
    
    show_system_info
    show_network_info
    check_service_status
    check_mumble_status
    check_bot_processes
    check_system_directories
    check_certificates
    check_mumble_channels
    check_recent_logs
    
    print_status "Status check completed!"
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "FGcom-mumble Status Check Script"
        echo "Usage: $0 [options]"
        echo
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --quick, -q    Quick status check (services only)"
        echo
        echo "This script checks the status of FGcom-mumble installation."
        exit 0
        ;;
    --quick|-q)
        print_status "Quick Status Check"
        echo "====================="
        echo
        check_service_status
        check_mumble_status
        check_bot_processes
        print_status "Quick status check completed!"
        ;;
    "")
        main
        ;;
    *)
        print_error "Unknown option: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac
