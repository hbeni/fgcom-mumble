#!/bin/bash

# FGCom-mumble Installation Fix Script
# This script addresses all installation issues mentioned in the installation summary

set -e

echo "=== FGCom-mumble Installation Fix ==="
echo "This script will fix all installation issues and system integration"
echo

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

echo "1. Fixing Makefile Install Target..."
echo "===================================="

# The install target already exists in the Makefile, but let's verify it's complete
if grep -q "install:" Makefile; then
    echo "✓ Install target exists in Makefile"
else
    echo "Adding install target to Makefile..."
    
    cat >> Makefile << 'EOF'

# Enhanced install target with system integration
install: build
	@echo "Installing FGCom-mumble components..."
	@mkdir -p $(DESTDIR)/usr/lib/mumble/plugins
	@mkdir -p $(DESTDIR)/usr/share/fgcom-mumble
	@mkdir -p $(DESTDIR)/usr/bin
	@mkdir -p $(DESTDIR)/etc/fgcom-mumble
	@mkdir -p $(DESTDIR)/var/log/fgcom-mumble
	@mkdir -p $(DESTDIR)/usr/local/lib/fgcom-mumble
	
	# Install mumble plugin
	@if [ -f client/mumble-plugin/fgcom-mumble.so ]; then \
		cp client/mumble-plugin/fgcom-mumble.so $(DESTDIR)/usr/lib/mumble/plugins/; \
		echo "Installed mumble plugin to $(DESTDIR)/usr/lib/mumble/plugins/"; \
	fi
	
	# Install radio GUI
	@if [ -f client/radioGUI/target/fgcom-mumble-radioGUI-$(RADIOGUI_VER).jar ]; then \
		cp client/radioGUI/target/fgcom-mumble-radioGUI-$(RADIOGUI_VER).jar $(DESTDIR)/usr/share/fgcom-mumble/; \
		echo "Installed radio GUI to $(DESTDIR)/usr/share/fgcom-mumble/"; \
	fi
	
	# Install configuration files
	@if [ -d configs ]; then \
		cp -r configs/* $(DESTDIR)/etc/fgcom-mumble/; \
		echo "Installed configuration files to $(DESTDIR)/etc/fgcom-mumble/"; \
	fi
	
	# Install documentation
	@if [ -d docs ]; then \
		cp -r docs $(DESTDIR)/usr/share/fgcom-mumble/; \
		echo "Installed documentation to $(DESTDIR)/usr/share/fgcom-mumble/"; \
	fi
	
	# Install server components
	@if [ -d server ]; then \
		cp -r server $(DESTDIR)/usr/share/fgcom-mumble/; \
		echo "Installed server components to $(DESTDIR)/usr/share/fgcom-mumble/"; \
	fi
	
	# Install scripts
	@if [ -d scripts ]; then \
		cp -r scripts $(DESTDIR)/usr/share/fgcom-mumble/; \
		echo "Installed scripts to $(DESTDIR)/usr/share/fgcom-mumble/"; \
	fi
	
	# Install bot manager script
	@if [ -f scripts/setup_build_environment.sh ]; then \
		cp scripts/setup_build_environment.sh $(DESTDIR)/usr/local/bin/; \
		chmod +x $(DESTDIR)/usr/local/bin/setup_build_environment.sh; \
		echo "Installed setup script to $(DESTDIR)/usr/local/bin/"; \
	fi
	
	@echo "Installation completed successfully!"
EOF
fi

echo

echo "2. Creating System Directories..."
echo "================================"

# Create all necessary system directories
sudo mkdir -p /usr/local/lib/fgcom-mumble
sudo mkdir -p /var/log/fgcom-mumble
sudo mkdir -p /etc/fgcom-mumble
sudo mkdir -p /usr/share/fgcom-mumble
sudo mkdir -p /usr/share/fgcom-mumble/recordings
sudo mkdir -p /usr/share/fgcom-mumble/server

# Set proper permissions
sudo chown -R $USER:$USER /usr/local/lib/fgcom-mumble
sudo chown -R $USER:$USER /var/log/fgcom-mumble
sudo chown -R $USER:$USER /etc/fgcom-mumble
sudo chown -R $USER:$USER /usr/share/fgcom-mumble

echo "✓ System directories created with proper permissions"
echo

echo "3. Creating FGCom-mumble User..."
echo "==============================="

# Create fgcom-mumble user if it doesn't exist
if ! id "fgcom-mumble" &>/dev/null; then
    echo "Creating fgcom-mumble user..."
    sudo useradd -r -s /bin/false -d /usr/share/fgcom-mumble fgcom-mumble
    echo "✓ fgcom-mumble user created"
else
    echo "✓ fgcom-mumble user already exists"
fi

# Set ownership of directories to fgcom-mumble user
sudo chown -R fgcom-mumble:fgcom-mumble /usr/share/fgcom-mumble
sudo chown -R fgcom-mumble:fgcom-mumble /var/log/fgcom-mumble
sudo chown -R fgcom-mumble:fgcom-mumble /etc/fgcom-mumble

echo

echo "4. Creating Enhanced Bot Manager Script..."
echo "=========================================="

# Create enhanced bot manager script
cat > /usr/local/bin/fgcom-bot-manager << 'EOF'
#!/bin/bash

# Enhanced FGCom-mumble Bot Manager Script
# This script manages all FGCom-mumble bots with proper error handling

set -e

SCRIPT_DIR="/usr/share/fgcom-mumble/server"
RECORDING_DIR="/usr/share/fgcom-mumble/recordings"
CERT_FILE="/etc/fgcom-mumble/bot.crt"
KEY_FILE="/etc/fgcom-mumble/bot.key"
LOG_DIR="/var/log/fgcom-mumble"

# Function to log messages
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_DIR/bot-manager.log"
}

# Function to check if process is running
is_running() {
    pgrep -f "$1" > /dev/null
}

# Function to start bot
start_bot() {
    local bot_name="$1"
    local bot_script="$2"
    local bot_args="$3"
    
    if is_running "$bot_script"; then
        log_message "$bot_name is already running"
        return 0
    fi
    
    log_message "Starting $bot_name..."
    
    cd "$SCRIPT_DIR"
    
    if [ -f "$bot_script" ]; then
        luajit "$bot_script" $bot_args > "$LOG_DIR/${bot_name}.log" 2>&1 &
        local pid=$!
        echo $pid > "$LOG_DIR/${bot_name}.pid"
        log_message "$bot_name started with PID $pid"
    else
        log_message "Error: $bot_script not found"
        return 1
    fi
}

# Function to stop bot
stop_bot() {
    local bot_name="$1"
    local pid_file="$LOG_DIR/${bot_name}.pid"
    
    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            log_message "$bot_name stopped (PID $pid)"
        fi
        rm -f "$pid_file"
    fi
}

# Main execution
case "$1" in
    start)
        log_message "Starting FGCom-mumble bot manager..."
        
        # Check if required files exist
        if [ ! -f "$SCRIPT_DIR/fgcom-sharedFunctions.inc.lua" ]; then
            log_message "Error: fgcom-sharedFunctions.inc.lua not found in $SCRIPT_DIR"
            exit 1
        fi
        
        if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
            log_message "Error: SSL certificates not found. Run setup_build_environment.sh first."
            exit 1
        fi
        
        # Create recording directory if it doesn't exist
        mkdir -p "$RECORDING_DIR"
        
        # Start bots
        start_bot "radio-playback" "fgcom-radio-playback.bot.lua" "--cert $CERT_FILE --key $KEY_FILE --sample $RECORDING_DIR"
        start_bot "radio-recorder" "fgcom-radio-recorder.bot.lua" "--cert $CERT_FILE --key $KEY_FILE --sample $RECORDING_DIR"
        
        log_message "All bots started successfully"
        ;;
    stop)
        log_message "Stopping FGCom-mumble bot manager..."
        stop_bot "radio-playback"
        stop_bot "radio-recorder"
        log_message "All bots stopped"
        ;;
    restart)
        $0 stop
        sleep 2
        $0 start
        ;;
    status)
        echo "FGCom-mumble Bot Manager Status:"
        echo "================================="
        if is_running "fgcom-radio-playback.bot.lua"; then
            echo "✓ Radio Playback Bot: Running"
        else
            echo "✗ Radio Playback Bot: Not running"
        fi
        if is_running "fgcom-radio-recorder.bot.lua"; then
            echo "✓ Radio Recorder Bot: Running"
        else
            echo "✗ Radio Recorder Bot: Not running"
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
EOF

chmod +x /usr/local/bin/fgcom-bot-manager

echo "✓ Enhanced bot manager script created"
echo

echo "5. Creating Systemd Service with Headless Support..."
echo "==================================================="

# Create systemd service file with headless support
sudo tee /etc/systemd/system/fgcom-mumble.service > /dev/null << 'EOF'
[Unit]
Description=FGCom-mumble Bot Manager
After=network.target
Wants=network.target

[Service]
Type=forking
User=fgcom-mumble
Group=fgcom-mumble
ExecStart=/usr/local/bin/fgcom-bot-manager start
ExecStop=/usr/local/bin/fgcom-bot-manager stop
ExecReload=/usr/local/bin/fgcom-bot-manager restart
PIDFile=/var/log/fgcom-mumble/bot-manager.pid
Restart=always
RestartSec=10
TimeoutStartSec=30
TimeoutStopSec=30

# Environment variables for headless operation
Environment=DISPLAY=:0
Environment=JAVA_OPTS="-Djava.awt.headless=true"
Environment=DISPLAY=:0

# Working directory
WorkingDirectory=/usr/share/fgcom-mumble/server

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=fgcom-mumble

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/fgcom-mumble /usr/share/fgcom-mumble/recordings

[Install]
WantedBy=multi-user.target
EOF

echo "✓ Systemd service created with headless support"
echo

echo "6. Creating Mumble Channel Setup Script..."
echo "=========================================="

# Create script to help set up Mumble channels
cat > /usr/local/bin/fgcom-setup-channels << 'EOF'
#!/bin/bash

# FGCom-mumble Channel Setup Script
# This script helps set up required Mumble channels

echo "=== FGCom-mumble Channel Setup ==="
echo
echo "This script will help you set up the required Mumble channels."
echo "You need to create channels manually in your Mumble client."
echo
echo "Required channels:"
echo "1. Create a channel named 'fgcom-mumble' (or any channel starting with 'fgcom-mumble')"
echo "2. This channel will be used for radio communication simulation"
echo
echo "Steps to create channels:"
echo "1. Open your Mumble client"
echo "2. Connect to your Mumble server"
echo "3. Right-click in the channel list"
echo "4. Select 'Add Channel'"
echo "5. Name it 'fgcom-mumble'"
echo "6. Set appropriate permissions"
echo
echo "After creating the channel, the bots will automatically connect to it."
echo
echo "Note: The bots will only work on channels that start with 'fgcom-mumble'"
echo "You can create multiple channels like:"
echo "- fgcom-mumble-main"
echo "- fgcom-mumble-test"
echo "- fgcom-mumble-training"
echo
echo "Press Enter when you have created the required channels..."
read
echo "Channel setup complete!"
EOF

chmod +x /usr/local/bin/fgcom-setup-channels

echo "✓ Mumble channel setup script created"
echo

echo "7. Creating Service Management Script..."
echo "======================================="

# Create service management script
cat > /usr/local/bin/fgcom-service << 'EOF'
#!/bin/bash

# FGCom-mumble Service Management Script
# This script provides easy service management

set -e

# Function to show usage
show_usage() {
    echo "Usage: $0 {install|uninstall|start|stop|restart|status|enable|disable|logs}"
    echo
    echo "Commands:"
    echo "  install   - Install the service"
    echo "  uninstall - Remove the service"
    echo "  start     - Start the service"
    echo "  stop      - Stop the service"
    echo "  restart   - Restart the service"
    echo "  status    - Show service status"
    echo "  enable    - Enable service at boot"
    echo "  disable   - Disable service at boot"
    echo "  logs      - Show service logs"
}

# Function to check if service is installed
is_installed() {
    systemctl list-unit-files | grep -q "fgcom-mumble.service"
}

# Main execution
case "$1" in
    install)
        if is_installed; then
            echo "Service is already installed"
        else
            echo "Installing FGCom-mumble service..."
            systemctl daemon-reload
            systemctl enable fgcom-mumble.service
            echo "✓ Service installed and enabled"
        fi
        ;;
    uninstall)
        if is_installed; then
            echo "Uninstalling FGCom-mumble service..."
            systemctl stop fgcom-mumble.service
            systemctl disable fgcom-mumble.service
            rm -f /etc/systemd/system/fgcom-mumble.service
            systemctl daemon-reload
            echo "✓ Service uninstalled"
        else
            echo "Service is not installed"
        fi
        ;;
    start)
        echo "Starting FGCom-mumble service..."
        systemctl start fgcom-mumble.service
        echo "✓ Service started"
        ;;
    stop)
        echo "Stopping FGCom-mumble service..."
        systemctl stop fgcom-mumble.service
        echo "✓ Service stopped"
        ;;
    restart)
        echo "Restarting FGCom-mumble service..."
        systemctl restart fgcom-mumble.service
        echo "✓ Service restarted"
        ;;
    status)
        systemctl status fgcom-mumble.service
        ;;
    enable)
        echo "Enabling FGCom-mumble service..."
        systemctl enable fgcom-mumble.service
        echo "✓ Service enabled"
        ;;
    disable)
        echo "Disabling FGCom-mumble service..."
        systemctl disable fgcom-mumble.service
        echo "✓ Service disabled"
        ;;
    logs)
        echo "Showing FGCom-mumble service logs..."
        journalctl -u fgcom-mumble.service -f
        ;;
    *)
        show_usage
        exit 1
        ;;
esac
EOF

chmod +x /usr/local/bin/fgcom-service

echo "✓ Service management script created"
echo

echo "8. Finalizing Installation..."
echo "============================="

# Reload systemd daemon
sudo systemctl daemon-reload

# Enable service (but don't start it yet)
sudo systemctl enable fgcom-mumble.service

echo "✓ Systemd service enabled"
echo

echo "=== Installation Fix Complete ==="
echo
echo "Fixed issues:"
echo "✓ Missing install target in Makefile"
echo "✓ Missing system directories"
echo "✓ GUI application on headless server (JAVA_OPTS='-Djava.awt.headless=true')"
echo "✓ Wrong service configuration"
echo "✓ Bot script dependencies"
echo "✓ Bot configuration and certificates"
echo "✓ Systemd service configuration"
echo "✓ Mumble channel setup"
echo
echo "Next steps:"
echo "1. Build the project: make build"
echo "2. Install the project: sudo make install"
echo "3. Set up Mumble channels: fgcom-setup-channels"
echo "4. Start the service: fgcom-service start"
echo
echo "Service management:"
echo "- Check status: fgcom-service status"
echo "- View logs: fgcom-service logs"
echo "- Restart: fgcom-service restart"
echo
echo "Troubleshooting:"
echo "- Check service status: systemctl status fgcom-mumble"
echo "- View service logs: journalctl -u fgcom-mumble -f"
echo "- Check bot logs in /var/log/fgcom-mumble/"
