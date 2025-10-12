#!/bin/bash
#
# FGcom-mumble Installation Script
# This script installs and configures the complete FGcom-mumble system
#

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SERVER_DIR="/usr/share/fgcom-mumble/server"
SCRIPTS_DIR="/usr/share/fgcom-mumble/scripts"
CONFIGS_DIR="/usr/share/fgcom-mumble/configs"
LOG_DIR="/var/log/fgcom-mumble"
RECORDING_DIR="/var/lib/fgcom-mumble/recordings"
CERT_DIR="/etc/fgcom-mumble"

# User and group
FGCOM_USER="fgcom-mumble"
FGCOM_GROUP="fgcom-mumble"

# Function to print colored output
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

# Function to check if Mumble server is installed
check_mumble_server() {
    if ! command -v mumble-server &> /dev/null; then
        print_error "Mumble server is not installed. Please install it first:"
        print_error "  sudo apt update && sudo apt install mumble-server"
        exit 1
    fi
    print_success "Mumble server is installed"
}

# Function to check if required packages are installed
check_dependencies() {
    print_status "Checking dependencies..."
    
    local missing_packages=()
    
    if ! command -v luajit &> /dev/null; then
        missing_packages+=("luajit")
    fi
    
    if ! command -v sqlite3 &> /dev/null; then
        missing_packages+=("sqlite3")
    fi
    
    if ! command -v openssl &> /dev/null; then
        missing_packages+=("openssl")
    fi
    
    if [[ ${#missing_packages[@]} -gt 0 ]]; then
        print_status "Installing missing packages: ${missing_packages[*]}"
        apt update
        apt install -y "${missing_packages[@]}"
    fi
    
    print_success "All dependencies are installed"
}

# Function to create system user and group
create_user_group() {
    print_status "Creating system user and group..."
    
    if ! getent group "$FGCOM_GROUP" > /dev/null 2>&1; then
        groupadd "$FGCOM_GROUP"
        print_success "Created group: $FGCOM_GROUP"
    else
        print_status "Group $FGCOM_GROUP already exists"
    fi
    
    if ! getent passwd "$FGCOM_USER" > /dev/null 2>&1; then
        useradd -r -g "$FGCOM_GROUP" -d /var/lib/fgcom-mumble -s /bin/false "$FGCOM_USER"
        print_success "Created user: $FGCOM_USER"
    else
        print_status "User $FGCOM_USER already exists"
    fi
}

# Function to create directories
create_directories() {
    print_status "Creating directories..."
    
    local dirs=(
        "$LOG_DIR"
        "$RECORDING_DIR"
        "/var/lib/fgcom-mumble"
        "/usr/share/fgcom-mumble"
        "/usr/share/fgcom-mumble/server"
        "/usr/share/fgcom-mumble/scripts"
        "/usr/share/fgcom-mumble/configs"
        "/etc/fgcom-mumble"
        "/var/lib/fgcom-mumble/atis_recordings"\        "/var/lib/fgcom-mumble/atis_cache"\        "/var/lib/fgcom-mumble/weather_data"
    )
    
    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            print_success "Created directory: $dir"
        else
            print_status "Directory already exists: $dir"
        fi
    done
    
    # Set ownership
    chown -R "$FGCOM_USER:$FGCOM_GROUP" "$LOG_DIR" "$RECORDING_DIR" "/var/lib/fgcom-mumble"
    print_success "Set ownership for directories"
}

# Function to install files to system locations
install_system_files() {
    print_status "Installing FGcom-mumble files to system locations..."
    
    # Copy server files
    cp -r "$PROJECT_ROOT/server"/* "$SERVER_DIR/"
    print_success "Copied server files to $SERVER_DIR/"
    
    # Copy scripts
    cp -r "$PROJECT_ROOT/scripts"/* "$SCRIPTS_DIR/"
    print_success "Copied scripts to $SCRIPTS_DIR/"
    
    # Copy configs
    cp -r "$PROJECT_ROOT/configs"/* "$CONFIGS_DIR/"
    print_success "Copied configs to $CONFIGS_DIR/"
    
    # Copy system bot manager
    cp "$SCRIPTS_DIR/server/fgcom-botmanager-system.sh" "$SCRIPTS_DIR/server/fgcom-botmanager.sh"
    
    # Copy uninstall and status scripts to system location
    cp "$PROJECT_ROOT/scripts/uninstall_fgcom_mumble.sh" "$SCRIPTS_DIR/"
    cp "$PROJECT_ROOT/scripts/status_fgcom_mumble.sh" "$SCRIPTS_DIR/"
    
    # Set ownership
    chown -R "$FGCOM_USER:$FGCOM_GROUP" /usr/share/fgcom-mumble/
    chmod +x "$SCRIPTS_DIR/server/fgcom-botmanager.sh"
    chmod +x "$SCRIPTS_DIR/uninstall_fgcom_mumble.sh"
    chmod +x "$SCRIPTS_DIR/status_fgcom_mumble.sh"
    
    print_success "Set ownership and permissions for system files"
}

# Function to generate bot certificates
generate_certificates() {
    print_status "Generating bot certificates..."
    
    cd "$CERT_DIR"
    
    local certs=("recbot" "playbot" "statusbot")
    
    for cert_name in "${certs[@]}"; do
        if [[ ! -f "${cert_name}.pem" ]] || [[ ! -f "${cert_name}.key" ]]; then
            print_status "Generating certificate for $cert_name..."
            
            # Generate private key
            openssl genrsa -out "${cert_name}.key" 2048
            
            # Generate certificate
            openssl req -new -x509 -key "${cert_name}.key" -out "${cert_name}.pem" -days 365 -subj "/CN=${cert_name}/O=FGcom-mumble"
            
            print_success "Generated certificate for $cert_name"
        else
            print_status "Certificate for $cert_name already exists"
        fi
    done
    
    # Set ownership
    chown "$FGCOM_USER:$FGCOM_GROUP" *.pem *.key
    chmod 600 *.key
    chmod 644 *.pem
    
    print_success "All bot certificates are ready"
}

# Function to configure Mumble server
configure_mumble_server() {
    print_status "Configuring Mumble server..."
    
    local mumble_config="/etc/mumble/mumble-server.ini"
    
    # Backup existing configuration
    if [[ -f "$mumble_config" ]]; then
        cp "$mumble_config" "${mumble_config}.backup.$(date +%Y%m%d_%H%M%S)"
        print_status "Backed up existing Mumble configuration"
    fi
    
    # Ensure Mumble database directory exists
    local mumble_db_dir="/var/lib/mumble-server"
    if [[ ! -d "$mumble_db_dir" ]]; then
        mkdir -p "$mumble_db_dir"
        chown mumble-server:mumble-server "$mumble_db_dir"
        print_success "Created Mumble database directory: $mumble_db_dir"
    fi
    
    # Create Mumble server configuration
    cat > "$mumble_config" << 'EOF'
; FGCom-mumble Mumble Server Configuration
; This configuration sets up a Mumble server for FGCom-mumble radio communication

; Database configuration
database=/var/lib/mumble-server/fgcom-mumble.sqlite

; Welcome message
welcometext="Welcome to FGCom-mumble Server. This server provides radio communication simulation for flight simulation."

; Server password (empty for no password)
serverpassword=

; Maximum number of users
users=100

; Default channel
defaultchannel=0

; Server port
port=64738

; Server name
servername=FGCom-mumble Server

; Channel configuration
; Root channel
0=Root

; FGCom-mumble channel
1=fgcom-mumble

; FGCom-mumble-admins channel
2=fgcom-mumble-admins

; Channel descriptions
[channel_description]
1=FGCom-mumble radio communication channel
2=Administrative channel for FGCom-mumble

; ACL rules
[acl]
; Root channel (0)
0=@all:+enter,+traverse,+speak,+whisper,+textmessage

; FGCom-mumble channel (1)
1=@all:+enter,+traverse,+speak,+whisper,+textmessage

; FGCom-mumble-admins channel (2)
2=@all:+enter,+traverse
2=@admin:+speak,+whisper,+textmessage

; Ice middleware configuration for channel management
ice="tcp -h 127.0.0.1 -p 6502"
EOF

    print_success "Mumble server configuration created"
}

# Function to create Mumble channels
create_mumble_channels() {
    print_status "Creating Mumble channels..."
    
    # Check if channels already exist
    local channel_count=$(sudo sqlite3 /var/lib/mumble-server/fgcom-mumble.sqlite "SELECT COUNT(*) FROM channels WHERE name IN ('fgcom-mumble', 'fgcom-mumble-admins');" 2>/dev/null || echo "0")
    
    if [[ "$channel_count" -ge 2 ]]; then
        print_status "Mumble channels already exist"
        return 0
    fi
    
    # Create channels using our database script
    if [[ -f "$SCRIPTS_DIR/create_fgcom_channels_database.py" ]]; then
        python3 "$SCRIPTS_DIR/create_fgcom_channels_database.py"
        print_success "Mumble channels created successfully"
    else
        print_error "Channel creation script not found: $SCRIPTS_DIR/create_fgcom_channels_database.py"
        exit 1
    fi
}

# Function to create systemd service
create_systemd_service() {
    print_status "Creating systemd service..."
    
    cat > /etc/systemd/system/fgcom-mumble.service << EOF
[Unit]
Description=FGcom-mumble Bot Manager
After=network.target mumble-server.service
Requires=mumble-server.service

[Service]
Type=simple
User=$FGCOM_USER
Group=$FGCOM_GROUP
WorkingDirectory=$SERVER_DIR
ExecStart=$SCRIPTS_DIR/server/fgcom-botmanager.sh
ExecStop=/bin/kill -TERM \$MAINPID
Restart=always
RestartSec=10
TimeoutStartSec=30
TimeoutStopSec=30

# Environment
Environment=HOME=/var/lib/fgcom-mumble

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$LOG_DIR $RECORDING_DIR /var/lib/fgcom-mumble

[Install]
WantedBy=multi-user.target
EOF

    print_success "Systemd service created"
}

# Function to start services
start_services() {
    print_status "Starting services..."
    
    # Start Mumble server
    systemctl enable mumble-server
    systemctl restart mumble-server
    
    # Wait for Mumble server to be ready
    sleep 5
    
    # Initialize Mumble database if it doesn't exist
    local mumble_db="/var/lib/mumble-server/fgcom-mumble.sqlite"
    if [[ ! -f "$mumble_db" ]]; then
        print_status "Initializing Mumble database..."
        # Create an empty database file to trigger Mumble to initialize it
        touch "$mumble_db"
        chown mumble-server:mumble-server "$mumble_db"
        chmod 660 "$mumble_db"
        print_success "Mumble database initialized: $mumble_db"
    fi
    
    # Create channels
    create_mumble_channels
    
    # Start FGcom-mumble service
    systemctl enable fgcom-mumble
    systemctl start fgcom-mumble
    
    print_success "All services started"
}

# Function to verify installation
verify_installation() {
    print_status "Verifying installation..."
    
    # Check if Mumble server is running
    if systemctl is-active --quiet mumble-server; then
        print_success "Mumble server is running"
    else
        print_error "Mumble server is not running"
        return 1
    fi
    
    # Check if FGcom-mumble service is running
    if systemctl is-active --quiet fgcom-mumble; then
        print_success "FGcom-mumble service is running"
    else
        print_warning "FGcom-mumble service is not running (this may be normal if bots are still starting)"
    fi
    
    # Check if channels exist
    local channel_count=$(sudo sqlite3 /var/lib/mumble-server/fgcom-mumble.sqlite "SELECT COUNT(*) FROM channels WHERE name IN ('fgcom-mumble', 'fgcom-mumble-admins');" 2>/dev/null || echo "0")
    if [[ "$channel_count" -ge 2 ]]; then
        print_success "Mumble channels are created"
    else
        print_error "Mumble channels are missing"
        return 1
    fi
    
    print_success "Installation verification completed"
}

# Function to show status
show_status() {
    print_status "FGcom-mumble System Status:"
    echo
    echo "Services:"
    systemctl status mumble-server --no-pager -l
    echo
    systemctl status fgcom-mumble --no-pager -l
    echo
    echo "Mumble Channels:"
    sudo sqlite3 /var/lib/mumble-server/fgcom-mumble.sqlite "SELECT channel_id, name FROM channels ORDER BY channel_id;"
    echo
    echo "Logs:"
    echo "  Mumble server: journalctl -u mumble-server -f"
    echo "  FGcom-mumble: journalctl -u fgcom-mumble -f"
    echo "  Bot logs: $LOG_DIR/"
}

# Main installation function
main() {
    print_status "Starting FGcom-mumble installation..."
    echo
    
    check_root
    check_mumble_server
    check_dependencies
    create_user_group
    create_directories
    install_system_files
    generate_certificates
    configure_mumble_server
    create_systemd_service
    start_services
    verify_installation
    
    echo
    print_success "FGcom-mumble installation completed successfully!"
    echo
    print_status "Next steps:"
    echo "  1. Check service status: systemctl status fgcom-mumble"
    echo "  2. View logs: journalctl -u fgcom-mumble -f"
    echo "  3. Connect to Mumble server at: $(hostname -I | awk '{print $1}'):64738"
    echo "  4. Join the 'fgcom-mumble' channel"
    echo
    print_status "For troubleshooting, run: $0 status"
    echo
    print_status "To check system status, run: ./scripts/status_fgcom_mumble.sh"
    print_status "To uninstall FGcom-mumble, run: ./scripts/uninstall_fgcom_mumble.sh"
}

# Handle command line arguments
case "${1:-install}" in
    install)
        main
        ;;
    status)
        show_status
        ;;
    *)
        echo "Usage: $0 [install|status]"
        echo "  install - Install FGcom-mumble system (default)"
        echo "  status  - Show system status"
        exit 1
        ;;
esac
