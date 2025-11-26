#!/bin/bash

# Simple Piper TTS Installation Script for FGcom-Mumble
# Downloads and installs Piper TTS for automatic ATIS generation

set -e

# Configuration
PIPER_DIR="${PIPER_DIR:-/opt/piper}"
PIPER_VERSION="${PIPER_VERSION:-1.2.0}"
ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Detect system architecture
detect_architecture() {
    case "$ARCH" in
        "x86_64")
            PIPER_ARCH="amd64"
            ;;
        "aarch64"|"arm64")
            PIPER_ARCH="arm64"
            ;;
        "armv7l")
            PIPER_ARCH="armv7"
            ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    log_info "Detected architecture: $PIPER_ARCH"
}

# Install system dependencies
install_dependencies() {
    log_info "Installing system dependencies..."
    
    case "$OS" in
        "linux")
            if command -v apt-get >/dev/null 2>&1; then
                # Debian/Ubuntu
                apt-get update
                apt-get install -y wget curl
            elif command -v yum >/dev/null 2>&1; then
                # RHEL/CentOS
                yum install -y wget curl
            elif command -v dnf >/dev/null 2>&1; then
                # Fedora
                dnf install -y wget curl
            elif command -v pacman >/dev/null 2>&1; then
                # Arch Linux
                pacman -S --noconfirm wget curl
            else
                log_warning "Unknown package manager. Please install wget and curl manually."
            fi
            ;;
        "darwin")
            if command -v brew >/dev/null 2>&1; then
                brew install wget curl
            else
                log_warning "Homebrew not found. Please install wget and curl manually."
            fi
            ;;
        *)
            log_warning "Unsupported operating system: $OS"
            ;;
    esac
}

# Download and install Piper
install_piper() {
    log_info "Installing Piper TTS to $PIPER_DIR..."
    
    # Create installation directory
    mkdir -p "$PIPER_DIR"
    cd "$PIPER_DIR"
    
    # Download Piper binary
    local piper_url="https://github.com/rhasspy/piper/releases/download/v${PIPER_VERSION}/piper_${PIPER_VERSION}_${OS}_${PIPER_ARCH}.tar.gz"
    
    log_info "Downloading Piper from: $piper_url"
    
    if ! wget -q --show-progress -O piper.tar.gz "$piper_url"; then
        log_error "Failed to download Piper"
        return 1
    fi
    
    # Extract and install
    log_info "Extracting Piper..."
    tar -xzf piper.tar.gz
    rm piper.tar.gz
    
    # Make executable
    chmod +x piper
    
    # Create models directory
    mkdir -p models
    
    log_success "Piper TTS installed successfully"
}

# Install default model
install_default_model() {
    log_info "Installing default model (en_US-lessac-medium)..."
    
    local model_name="en_US-lessac-medium"
    local model_file="models/${model_name}.onnx"
    local config_file="models/${model_name}.onnx.json"
    
    # Download model files
    local model_url="https://huggingface.co/rhasspy/piper-voices/resolve/v1.0.0/${model_name}/${model_name}.onnx"
    local config_url="https://huggingface.co/rhasspy/piper-voices/resolve/v1.0.0/${model_name}/${model_name}.onnx.json"
    
    log_info "Downloading model file..."
    if ! wget -q --show-progress -O "$model_file" "$model_url"; then
        log_error "Failed to download model file"
        return 1
    fi
    
    log_info "Downloading config file..."
    if ! wget -q --show-progress -O "$config_file" "$config_url"; then
        log_error "Failed to download config file"
        return 1
    fi
    
    log_success "Default model installed successfully"
}

# Test installation
test_installation() {
    log_info "Testing Piper installation..."
    
    if [ -f "$PIPER_DIR/piper" ]; then
        if "$PIPER_DIR/piper" --help >/dev/null 2>&1; then
            log_success "Piper TTS is working correctly"
            return 0
        else
            log_error "Piper TTS test failed"
            return 1
        fi
    else
        log_error "Piper binary not found"
        return 1
    fi
}

# Main installation function
main() {
    log_info "Starting Piper TTS installation..."
    
    # Check if already installed
    if [ -f "$PIPER_DIR/piper" ]; then
        log_warning "Piper TTS already installed at $PIPER_DIR"
        read -p "Do you want to reinstall? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Installation cancelled"
            exit 0
        fi
    fi
    
    # Run installation steps
    check_root
    detect_architecture
    install_dependencies
    install_piper
    install_default_model
    test_installation
    
    log_success "Piper TTS installation completed successfully!"
    echo ""
    log_info "Usage examples:"
    echo "  $PIPER_DIR/piper --model models/en_US-lessac-medium --output_file test.wav < input.txt"
    echo ""
    log_info "For FGcom-Mumble integration, use:"
    echo "  $PIPER_DIR/../scripts/tts/piper_tts_integration.sh"
}

# Run main function
main "$@"
