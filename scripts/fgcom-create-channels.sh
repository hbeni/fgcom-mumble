#!/bin/bash

# FGCom-mumble Automatic Channel Creation Script
# This script automatically creates the required Mumble channels on server start

set -e

# Configuration
MUMBLE_CONFIG="/etc/mumble/mumble-server.ini"
LOG_FILE="/var/log/fgcom-mumble/channel-creation.log"
CHANNEL_SCRIPT="/usr/local/bin/fgcom-create-channels"

# Function to log messages
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Function to create log directory
create_log_directory() {
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
}

# Function to check if channels already exist
check_existing_channels() {
    if grep -q "fgcom-mumble" "$MUMBLE_CONFIG" 2>/dev/null; then
        log_message "Channels already exist in configuration"
        return 0
    else
        log_message "Channels not found in configuration"
        return 1
    fi
}

# Function to create channels using configuration method
create_channels_config() {
    log_message "Creating channels using configuration method..."
    
    # Backup original config if it exists
    if [ -f "$MUMBLE_CONFIG" ]; then
        cp "$MUMBLE_CONFIG" "$MUMBLE_CONFIG.backup.$(date +%Y%m%d_%H%M%S)"
        log_message "Backed up original configuration"
    fi
    
    # Create config file if it doesn't exist
    if [ ! -f "$MUMBLE_CONFIG" ]; then
        log_message "Creating new Mumble server configuration"
        cat > "$MUMBLE_CONFIG" << 'EOF'
; Murmur configuration file for FGCom-mumble
; This configuration sets up a Mumble server with FGCom-mumble channels

; Database configuration
database=/var/lib/mumble-server/mumble-server.sqlite

; Welcome message
welcometext="Welcome to FGCom-mumble Server. This server provides realistic radio communication simulation."

; Server password (empty for no password)
serverpassword=

; Maximum number of users
users=100

; Default channel
defaultchannel=0

; Server port
port=64738

; Host to bind to (empty for all interfaces)
host=

; Password to join server as SuperUser
;superuser_password=

; Bandwidth limit in bits per second
bandwidth=72000

; Timeout in seconds for user inactivity
timeout=30

; Allow HTML in messages
allowhtml=true

; Send channel tree with welcome message
sendtree=true

; Log file location
logfile=/var/log/mumble-server/mumble-server.log

; Server log level (0=Info, 1=Warning, 2=Error, 3=Debug)
logLevel=1

; PID file location
pidfile=/var/run/mumble-server/mumble-server.pid

; Auto-register users
autoregister=true

; SSL Certificate settings
;sslCert=
;sslKey=

; Ice configuration (for external control)
;ice="tcp -h 127.0.0.1 -p 6502"
;icesecretread=
;icesecretwrite=
EOF
    fi
    
    # Add channel definitions to config file
    if ! grep -q "fgcom-mumble" "$MUMBLE_CONFIG"; then
        log_message "Adding FGCom-mumble channel configuration"
        cat >> "$MUMBLE_CONFIG" << 'EOF'

; FGCom-mumble Channel Configuration
[channels]
12=fgcom-mumble
13=fgcom-mumble-admins

[channel_description]
12=FGCom-mumble radio communication channel
13=FGCom-mumble administrative channel

[acl]
; fgcom-mumble channel (12) - Open to all users
12=@all:+enter,+traverse,+speak,+whisper,+textmessage

; fgcom-mumble-admins channel (13) - Restricted to admins
13=@admin:+enter,+traverse,+speak,+whisper,+textmessage
13=@all:-enter,-traverse,-speak,-whisper,-textmessage
EOF
        log_message "✓ Channel configuration added to Mumble server config"
    else
        log_message "Channel configuration already exists"
    fi
}

# Function to create channels using Ice interface (if available)
create_channels_ice() {
    log_message "Attempting to create channels using Ice interface..."
    
    # Check if Python3 and Ice are available
    if ! command -v python3 >/dev/null 2>&1; then
        log_message "Python3 not available, skipping Ice method"
        return 1
    fi
    
    # Create Python script for Ice channel creation
    cat > /tmp/create_fgcom_channels.py << 'EOF'
import sys
import os

def create_channels_ice():
    try:
        import Ice
        import Murmur
        
        # Connect to Ice interface
        ic = Ice.initialize()
        base = ic.stringToProxy("Meta:tcp -h 127.0.0.1 -p 6502")
        meta = Murmur.MetaPrx.checkedCast(base)
        
        if meta:
            # Get server
            server = meta.getServer(1)
            
            # Create fgcom-mumble channel
            channel = Murmur.Channel()
            channel.name = "fgcom-mumble"
            channel.parent = 0  # Root channel
            channel.temporary = False
            channel.position = 0
            
            try:
                channel_id = server.addChannel(channel)
                print(f"Created fgcom-mumble channel with ID: {channel_id}")
            except Exception as e:
                print(f"Error creating fgcom-mumble channel: {e}")
            
            # Create fgcom-mumble-admins channel
            admin_channel = Murmur.Channel()
            admin_channel.name = "fgcom-mumble-admins"
            admin_channel.parent = 0  # Root channel
            admin_channel.temporary = False
            admin_channel.position = 1
            
            try:
                admin_channel_id = server.addChannel(admin_channel)
                print(f"Created fgcom-mumble-admins channel with ID: {admin_channel_id}")
            except Exception as e:
                print(f"Error creating fgcom-mumble-admins channel: {e}")
            
            ic.destroy()
            return True
        else:
            print("Failed to connect to Ice interface")
            return False
            
    except ImportError:
        print("Ice Python module not available")
        return False
    except Exception as e:
        print(f"Error in Ice channel creation: {e}")
        return False

if __name__ == "__main__":
    if create_channels_ice():
        sys.exit(0)
    else:
        sys.exit(1)
EOF

    # Run the Python script
    if python3 /tmp/create_fgcom_channels.py; then
        log_message "✓ Channels created using Ice interface"
        rm -f /tmp/create_fgcom_channels.py
        return 0
    else
        log_message "Ice interface failed"
        rm -f /tmp/create_fgcom_channels.py
        return 1
    fi
}

# Function to verify channels exist
verify_channels() {
    log_message "Verifying channels exist..."
    
    # Check if channels are configured
    if grep -q "fgcom-mumble" "$MUMBLE_CONFIG"; then
        log_message "✓ Channels configured in Mumble server"
        return 0
    else
        log_message "✗ Channels not found in configuration"
        return 1
    fi
}

# Function to set proper permissions
set_permissions() {
    log_message "Setting proper permissions..."
    
    # Set ownership of config file
    if [ -f "$MUMBLE_CONFIG" ]; then
        chown mumble-server:mumble-server "$MUMBLE_CONFIG" 2>/dev/null || true
        chmod 640 "$MUMBLE_CONFIG"
        log_message "✓ Set permissions on Mumble server config"
    fi
    
    # Set ownership of log file
    if [ -f "$LOG_FILE" ]; then
        chown fgcom-mumble:fgcom-mumble "$LOG_FILE" 2>/dev/null || true
        chmod 644 "$LOG_FILE"
        log_message "✓ Set permissions on log file"
    fi
}

# Function to restart Mumble server if needed
restart_mumble_server() {
    log_message "Checking if Mumble server restart is needed..."
    
    # Check if Mumble server is running
    if systemctl is-active --quiet mumble-server; then
        log_message "Mumble server is running, restarting to apply channel changes..."
        systemctl restart mumble-server
        sleep 2
        
        if systemctl is-active --quiet mumble-server; then
            log_message "✓ Mumble server restarted successfully"
        else
            log_message "✗ Mumble server restart failed"
            return 1
        fi
    else
        log_message "Mumble server is not running, channels will be created on next start"
    fi
}

# Main execution function
main() {
    log_message "Starting FGCom-mumble automatic channel creation..."
    
    # Create log directory
    create_log_directory
    
    # Check if channels already exist
    if check_existing_channels; then
        log_message "Channels already exist, skipping creation"
        return 0
    fi
    
    # Try to create channels using Ice interface first
    if create_channels_ice; then
        log_message "✓ Channels created using Ice interface"
    else
        log_message "Ice interface failed, using configuration method..."
        create_channels_config
    fi
    
    # Verify channels were created
    if verify_channels; then
        log_message "✓ Channel creation completed successfully"
        
        # Set proper permissions
        set_permissions
        
        # Restart Mumble server if needed
        restart_mumble_server
        
        echo "Channels created:"
        echo "  - fgcom-mumble (main radio communication)"
        echo "  - fgcom-mumble-admins (administrative functions)"
        
        return 0
    else
        log_message "✗ Channel creation failed"
        return 1
    fi
}

# Run main function
main "$@"
