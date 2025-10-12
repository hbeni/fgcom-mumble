#!/bin/bash
#####################################################################################
# FGcom-mumble Uninstall Script
# This script removes FGcom-mumble from the system
#####################################################################################

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
FGCOM_USER="fgcom-mumble"
FGCOM_GROUP="fgcom-mumble"
SERVICE_NAME="fgcom-mumble"

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

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Function to stop and disable services
stop_services() {
    print_status "Stopping FGcom-mumble services..."
    
    # Stop FGcom-mumble service
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        systemctl stop "$SERVICE_NAME"
        print_success "Stopped $SERVICE_NAME service"
    else
        print_status "$SERVICE_NAME service is not running"
    fi
    
    # Disable FGcom-mumble service
    if systemctl is-enabled --quiet "$SERVICE_NAME"; then
        systemctl disable "$SERVICE_NAME"
    # Stop ATIS Weather service if it exists\    if systemctl is-active --quiet "fgcom-mumble-atis-weather" 2>/dev/null; then\        systemctl stop "fgcom-mumble-atis-weather"\        print_success "Stopped fgcom-mumble-atis-weather service"\    fi\    \    # Disable ATIS Weather service if it exists\    if systemctl is-enabled --quiet "fgcom-mumble-atis-weather" 2>/dev/null; then\        systemctl disable "fgcom-mumble-atis-weather"\        print_success "Disabled fgcom-mumble-atis-weather service"\    fi
        print_success "Disabled $SERVICE_NAME service"
    else
        print_status "$SERVICE_NAME service is not enabled"
    fi
}

# Function to remove systemd service
remove_systemd_service() {
    print_status "Removing systemd service..."
    
    if [[ -f "/etc/systemd/system/$SERVICE_NAME.service" ]]; then
        rm -f "/etc/systemd/system/$SERVICE_NAME.service"
        systemctl daemon-reload
        print_success "Removed systemd service file"
    else
        print_status "Systemd service file not found"
    fi
}

# Function to kill any remaining processes
kill_processes() {
    print_status "Stopping any remaining FGcom-mumble processes..."
    
    # Kill bot processes
    pkill -f "fgcom-radio-recorder.bot.lua" 2>/dev/null && print_success "Killed recorder bot processes"
    pkill -f "fgcom-radio-playback.bot.lua" 2>/dev/null && print_success "Killed playback bot processes"
    pkill -f "fgcom-status.bot.lua" 2>/dev/null && print_success "Killed status bot processes"
    pkill -f "fgcom-botmanager" 2>/dev/null && print_success "Killed bot manager processes"
    
    # Wait a moment for processes to terminate
    sleep 2
}

# Function to remove files and directories
remove_files() {
    print_status "Removing FGcom-mumble files and directories..."
    
    # Remove system directories
    local dirs_to_remove=(
        "/usr/share/fgcom-mumble"
        "/etc/fgcom-mumble"
        "/var/log/fgcom-mumble"
        "/var/lib/fgcom-mumble"
    )
    
    for dir in "${dirs_to_remove[@]}"; do
        if [[ -d "$dir" ]]; then
            rm -rf "$dir"
            print_success "Removed directory: $dir"
        else
            print_status "Directory not found: $dir"
        fi
    done
    
    # Remove wrapper script
    if [[ -f "/usr/local/bin/fgcom-botmanager" ]]; then
        rm -f "/usr/local/bin/fgcom-botmanager"
        print_success "Removed wrapper script: /usr/local/bin/fgcom-botmanager"
    fi
    
    # Remove temporary files
    rm -f "/tmp/fgcom-fnotify-fifo"
    print_success "Removed temporary files"
}

# Function to remove user and group
remove_user_group() {
    print_status "Removing FGcom-mumble user and group..."
    
    # Remove user if it exists
    if id "$FGCOM_USER" &>/dev/null; then
        userdel "$FGCOM_USER"
        print_success "Removed user: $FGCOM_USER"
    else
        print_status "User $FGCOM_USER does not exist"
    fi
    
    # Remove group if it exists
    if getent group "$FGCOM_GROUP" &>/dev/null; then
        groupdel "$FGCOM_GROUP"
        print_success "Removed group: $FGCOM_GROUP"
    else
        print_status "Group $FGCOM_GROUP does not exist"
    fi
}

# Function to restore Mumble server configuration
restore_mumble_config() {
    print_status "Restoring Mumble server configuration..."
    
    local mumble_config="/etc/mumble/mumble-server.ini"
    local backup_config="/etc/mumble/mumble-server.ini.fgcom-backup"
    
    if [[ -f "$backup_config" ]]; then
        cp "$backup_config" "$mumble_config"
        print_success "Restored Mumble server configuration from backup"
    else
        print_warning "No backup of Mumble server configuration found"
        print_status "You may need to manually restore your Mumble server configuration"
    fi
}

# Function to remove Mumble channels (optional)
remove_mumble_channels() {
    print_status "Removing FGcom-mumble channels from Mumble server..."
    
    # Check if Mumble server is running
    if systemctl is-active --quiet mumble-server; then
        print_warning "Mumble server is running. Channels will need to be removed manually."
        print_status "You can remove the 'fgcom-mumble' and 'fgcom-mumble-admins' channels through the Mumble client or server admin interface."
    else
        print_status "Mumble server is not running. Channels will remain in the database."
        print_warning "If you want to remove the channels, start the Mumble server and remove them manually."
    fi
}

# Function to show what will be removed
show_removal_summary() {
    print_status "The following will be removed:"
    echo "  - FGcom-mumble systemd service"
    echo "  - All FGcom-mumble files and directories:"
    echo "    * /usr/share/fgcom-mumble/"
    echo "    * /etc/fgcom-mumble/"
    echo "    * /var/log/fgcom-mumble/"
    echo "    * /var/lib/fgcom-mumble/"
    echo "  - FGcom-mumble user and group"
    echo "  - Wrapper script: /usr/local/bin/fgcom-botmanager"
    echo "  - Temporary files"
    echo "  - Mumble server configuration will be restored from backup"
    echo
    print_warning "Mumble channels will NOT be automatically removed."
    print_warning "You will need to remove them manually if desired."
    echo
}

# Function to confirm uninstallation
confirm_uninstall() {
    show_removal_summary
    
    read -p "Are you sure you want to uninstall FGcom-mumble? (yes/no): " -r
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        print_status "Uninstallation cancelled"
        exit 0
    fi
}

# Function to check for dependencies
check_dependencies() {
    print_status "Checking for other services that might depend on FGcom-mumble..."
    
    # Check if any other services depend on the FGcom-mumble user
    local dependent_services=$(systemctl list-dependencies --reverse "$SERVICE_NAME" 2>/dev/null | grep -v "$SERVICE_NAME" | wc -l)
    if [[ $dependent_services -gt 0 ]]; then
        print_warning "Found $dependent_services services that depend on $SERVICE_NAME"
        print_status "These services may be affected by the uninstallation"
    fi
}

# Function to show post-uninstall instructions
show_post_uninstall_instructions() {
    echo
    print_success "FGcom-mumble has been successfully uninstalled!"
    echo
    print_status "Post-uninstall instructions:"
    echo "  1. If you want to remove Mumble channels:"
    echo "     - Start Mumble server: systemctl start mumble-server"
    echo "     - Connect with Mumble client and remove 'fgcom-mumble' channels"
    echo "  2. If you want to completely remove Mumble server:"
    echo "     - systemctl stop mumble-server"
    echo "     - systemctl disable mumble-server"
    echo "     - apt remove mumble-server"
    echo "  3. If you want to remove Mumble server data:"
    echo "     - rm -rf /var/lib/mumble-server/"
    echo "     - rm -rf /etc/mumble/"
    echo
    print_status "Thank you for using FGcom-mumble!"
}

# Main uninstall function
main() {
    print_status "Starting FGcom-mumble uninstallation..."
    echo
    
    check_root
    check_dependencies
    confirm_uninstall
    
    echo
    print_status "Proceeding with uninstallation..."
    echo
    
    stop_services
    kill_processes
    remove_systemd_service
    remove_files
    remove_user_group
    restore_mumble_config
    remove_mumble_channels
    
    show_post_uninstall_instructions
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "FGcom-mumble Uninstall Script"
        echo "Usage: $0 [options]"
        echo
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --force, -f    Skip confirmation prompt"
        echo
        echo "This script will remove FGcom-mumble from your system."
        exit 0
        ;;
    --force|-f)
        # Skip confirmation for automated uninstallation
        check_root
        check_dependencies
        stop_services
        kill_processes
        remove_systemd_service
        remove_files
        remove_user_group
        restore_mumble_config
        remove_mumble_channels
        print_success "FGcom-mumble has been forcefully uninstalled!"
        exit 0
        ;;
    "")
        # Normal interactive uninstallation
        main
        ;;
    *)
        print_error "Unknown option: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac
