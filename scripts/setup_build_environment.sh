#!/bin/bash

# FGCom-mumble Build Environment Setup Script
# This script addresses all the build system issues mentioned in the installation summary

set -e

echo "=== FGCom-mumble Build Environment Setup ==="
echo "This script will fix all build system issues and dependencies"
echo

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install package based on system
install_package() {
    local package="$1"
    if command_exists apt-get; then
        echo "Installing $package via apt-get..."
        sudo apt-get update
        sudo apt-get install -y "$package"
    elif command_exists yum; then
        echo "Installing $package via yum..."
        sudo yum install -y "$package"
    elif command_exists pacman; then
        echo "Installing $package via pacman..."
        sudo pacman -S --noconfirm "$package"
    else
        echo "Warning: Package manager not found. Please install $package manually."
    fi
}

echo "1. Fixing Git Submodules..."
echo "=========================="

# Initialize and update submodules
echo "Initializing git submodules..."
git submodule update --init --recursive

# Verify submodules are properly initialized
if [ ! -d "client/radioGUI/lib/jsimconnect" ]; then
    echo "Error: jsimconnect submodule not found. Re-initializing..."
    git submodule deinit -f client/radioGUI/lib/jsimconnect
    git submodule update --init --recursive client/radioGUI/lib/jsimconnect
fi

if [ ! -d "client/mumble-plugin/lib/openssl" ]; then
    echo "Error: openssl submodule not found. Re-initializing..."
    git submodule deinit -f client/mumble-plugin/lib/openssl
    git submodule update --init --recursive client/mumble-plugin/lib/openssl
fi

echo "✓ Git submodules initialized successfully"
echo

echo "2. Installing Build Dependencies..."
echo "==================================="

# Check for Java/Maven
if ! command_exists java; then
    echo "Java not found. Installing OpenJDK 17..."
    install_package "openjdk-17-jdk"
fi

if ! command_exists mvn; then
    echo "Maven not found. Installing Maven..."
    install_package "maven"
fi

# Check for build tools
if ! command_exists g++; then
    echo "G++ not found. Installing build essentials..."
    install_package "build-essential"
fi

# Check for OpenSSL development libraries
if ! pkg-config --exists openssl; then
    echo "OpenSSL development libraries not found. Installing..."
    install_package "libssl-dev"
fi

# Check for curl and jsoncpp
if ! pkg-config --exists libcurl; then
    echo "libcurl not found. Installing..."
    install_package "libcurl4-openssl-dev"
fi

if ! pkg-config --exists jsoncpp; then
    echo "jsoncpp not found. Installing..."
    install_package "libjsoncpp-dev"
fi

# Check for Python and bc
if ! command_exists python3; then
    echo "Python3 not found. Installing..."
    install_package "python3"
fi

if ! command_exists bc; then
    echo "bc calculator not found. Installing..."
    install_package "bc"
fi

echo "✓ Build dependencies installed successfully"
echo

echo "3. Installing Bot Dependencies..."
echo "================================="

# Install LuaJIT and related packages for bot scripts
echo "Installing LuaJIT and bot dependencies..."
install_package "luajit"
install_package "libluajit-5.1-dev"
install_package "libprotobuf-c-dev"
install_package "libopus-dev"
install_package "libsndfile1-dev"
install_package "libsamplerate0-dev"
install_package "libuv1-dev"
install_package "protobuf-c-compiler"

echo "✓ Bot dependencies installed successfully"
echo

echo "4. Creating System Directories..."
echo "================================"

# Create necessary system directories
sudo mkdir -p /usr/local/lib/fgcom-mumble
sudo mkdir -p /var/log/fgcom-mumble
sudo mkdir -p /etc/fgcom-mumble
sudo mkdir -p /usr/share/fgcom-mumble

# Set proper permissions
sudo chown -R $USER:$USER /usr/local/lib/fgcom-mumble
sudo chown -R $USER:$USER /var/log/fgcom-mumble
sudo chown -R $USER:$USER /etc/fgcom-mumble
sudo chown -R $USER:$USER /usr/share/fgcom-mumble

echo "✓ System directories created with proper permissions"
echo

echo "5. Building lua-mumble Library..."
echo "==============================="

# Check if lua-mumble is already built
if [ ! -f "/usr/local/lib/lua/5.1/mumble.so" ]; then
    echo "Building lua-mumble library..."
    
    # Create temporary directory for lua-mumble build
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    
    # Clone and build lua-mumble
    git clone https://github.com/bkacjios/lua-mumble.git
    cd lua-mumble
    
    # Build lua-mumble
    make
    sudo make install
    
    # Clean up
    cd /
    rm -rf "$TEMP_DIR"
    
    echo "✓ lua-mumble library built and installed"
else
    echo "✓ lua-mumble library already exists"
fi

echo

echo "6. Generating SSL Certificates for Bots..."
echo "=========================================="

# Generate SSL certificates for bot authentication
if [ ! -f "/etc/fgcom-mumble/bot.crt" ] || [ ! -f "/etc/fgcom-mumble/bot.key" ]; then
    echo "Generating SSL certificates for bot authentication..."
    
    # Generate private key
    openssl genrsa -out /etc/fgcom-mumble/bot.key 2048
    
    # Generate certificate
    openssl req -new -x509 -key /etc/fgcom-mumble/bot.key -out /etc/fgcom-mumble/bot.crt -days 365 -subj "/C=US/ST=State/L=City/O=Organization/CN=fgcom-bot"
    
    # Set proper permissions
    chmod 600 /etc/fgcom-mumble/bot.key
    chmod 644 /etc/fgcom-mumble/bot.crt
    
    echo "✓ SSL certificates generated"
else
    echo "✓ SSL certificates already exist"
fi

echo

echo "7. Creating Recording Directory..."
echo "================================="

# Create recording directory for bot scripts
mkdir -p /usr/share/fgcom-mumble/recordings
chmod 755 /usr/share/fgcom-mumble/recordings

echo "✓ Recording directory created"
echo

echo "8. Creating Bot Manager Script..."
echo "================================"

# Create bot manager script
cat > /usr/local/bin/fgcom-bot-manager << 'EOF'
#!/bin/bash

# FGCom-mumble Bot Manager Script
# This script manages all FGCom-mumble bots

set -e

SCRIPT_DIR="/usr/share/fgcom-mumble/server"
RECORDING_DIR="/usr/share/fgcom-mumble/recordings"
CERT_FILE="/etc/fgcom-mumble/bot.crt"
KEY_FILE="/etc/fgcom-mumble/bot.key"

# Check if required files exist
if [ ! -f "$SCRIPT_DIR/fgcom-sharedFunctions.inc.lua" ]; then
    echo "Error: fgcom-sharedFunctions.inc.lua not found in $SCRIPT_DIR"
    exit 1
fi

if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    echo "Error: SSL certificates not found. Run setup_build_environment.sh first."
    exit 1
fi

# Create recording directory if it doesn't exist
mkdir -p "$RECORDING_DIR"

# Start radio playback bot
echo "Starting radio playback bot..."
cd "$SCRIPT_DIR"
luajit fgcom-radio-playback.bot.lua \
    --cert "$CERT_FILE" \
    --key "$KEY_FILE" \
    --sample "$RECORDING_DIR" \
    --daemon &

# Start radio recorder bot
echo "Starting radio recorder bot..."
cd "$SCRIPT_DIR"
luajit fgcom-radio-recorder.bot.lua \
    --cert "$CERT_FILE" \
    --key "$KEY_FILE" \
    --sample "$RECORDING_DIR" \
    --daemon &

echo "✓ All bots started successfully"
EOF

chmod +x /usr/local/bin/fgcom-bot-manager

echo "✓ Bot manager script created"
echo

echo "9. Creating Systemd Service..."
echo "============================="

# Create systemd service file
sudo tee /etc/systemd/system/fgcom-mumble.service > /dev/null << 'EOF'
[Unit]
Description=FGCom-mumble Bot Manager
After=network.target

[Service]
Type=forking
User=fgcom-mumble
Group=fgcom-mumble
ExecStart=/usr/local/bin/fgcom-bot-manager
ExecStop=/bin/kill -TERM $MAINPID
Restart=always
RestartSec=10

# Environment variables for headless operation
Environment=DISPLAY=:0
Environment=JAVA_OPTS="-Djava.awt.headless=true"

# Working directory
WorkingDirectory=/usr/share/fgcom-mumble/server

[Install]
WantedBy=multi-user.target
EOF

# Create fgcom-mumble user if it doesn't exist
if ! id "fgcom-mumble" &>/dev/null; then
    sudo useradd -r -s /bin/false fgcom-mumble
fi

# Set proper ownership
sudo chown -R fgcom-mumble:fgcom-mumble /usr/share/fgcom-mumble
sudo chown -R fgcom-mumble:fgcom-mumble /etc/fgcom-mumble

echo "✓ Systemd service created"
echo

echo "10. Finalizing Setup..."
echo "======================"

# Reload systemd daemon
sudo systemctl daemon-reload

# Enable service (but don't start it yet)
sudo systemctl enable fgcom-mumble.service

echo "✓ Systemd service enabled"
echo

echo "=== Build Environment Setup Complete ==="
echo
echo "Next steps:"
echo "1. Build the project: make build"
echo "2. Install the project: sudo make install"
echo "3. Create Mumble channels starting with 'fgcom-mumble'"
echo "4. Start the service: sudo systemctl start fgcom-mumble"
echo
echo "For headless server operation:"
echo "- The service is configured with JAVA_OPTS='-Djava.awt.headless=true'"
echo "- All GUI components will run in headless mode"
echo
echo "Troubleshooting:"
echo "- Check service status: sudo systemctl status fgcom-mumble"
echo "- View service logs: sudo journalctl -u fgcom-mumble -f"
echo "- Check bot logs in /var/log/fgcom-mumble/"
