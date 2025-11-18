#!/bin/bash

# FGCom-mumble WebRTC Gateway Startup Script
# This script starts the WebRTC gateway server

set -e

# Configuration
GATEWAY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$GATEWAY_DIR/logs/gateway.log"
PID_FILE="$GATEWAY_DIR/gateway.pid"
NODE_ENV="${NODE_ENV:-development}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if Node.js is installed
check_node() {
    if ! command -v node &> /dev/null; then
        error "Node.js is not installed. Please install Node.js 16 or higher."
        exit 1
    fi
    
    NODE_VERSION=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
    if [ "$NODE_VERSION" -lt 16 ]; then
        error "Node.js version 16 or higher is required. Current version: $(node --version)"
        exit 1
    fi
    
    success "Node.js $(node --version) detected"
}

# Check if npm is installed
check_npm() {
    if ! command -v npm &> /dev/null; then
        error "npm is not installed. Please install npm."
        exit 1
    fi
    
    success "npm $(npm --version) detected"
}

# Create necessary directories
create_directories() {
    log "Creating necessary directories..."
    
    mkdir -p "$GATEWAY_DIR/logs"
    mkdir -p "$GATEWAY_DIR/data"
    mkdir -p "$GATEWAY_DIR/config"
    
    success "Directories created"
}

# Install dependencies
install_dependencies() {
    log "Installing dependencies..."
    
    cd "$GATEWAY_DIR"
    
    if [ ! -f "package.json" ]; then
        error "package.json not found in $GATEWAY_DIR"
        exit 1
    fi
    
    if [ ! -d "node_modules" ] || [ "package.json" -nt "node_modules" ]; then
        log "Installing npm packages..."
        npm install
        
        if [ $? -eq 0 ]; then
            success "Dependencies installed successfully"
        else
            error "Failed to install dependencies"
            exit 1
        fi
    else
        success "Dependencies already installed"
    fi
}

# Check if gateway is already running
check_running() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p "$PID" > /dev/null 2>&1; then
            warning "Gateway is already running (PID: $PID)"
            echo "Use './start-gateway.sh stop' to stop it first"
            exit 1
        else
            log "Removing stale PID file"
            rm -f "$PID_FILE"
        fi
    fi
}

# Start the gateway
start_gateway() {
    log "Starting FGCom-mumble WebRTC Gateway..."
    
    cd "$GATEWAY_DIR"
    
    # Read configuration from gateway.json
    if [ -f "config/gateway.json" ]; then
        CONFIG_PORT=$(node -e "console.log(JSON.parse(require('fs').readFileSync('config/gateway.json', 'utf8')).server.port)" 2>/dev/null || echo "8081")
        CONFIG_MUMBLE_HOST=$(node -e "console.log(JSON.parse(require('fs').readFileSync('config/gateway.json', 'utf8')).mumble.host)" 2>/dev/null || echo "localhost")
        CONFIG_MUMBLE_PORT=$(node -e "console.log(JSON.parse(require('fs').readFileSync('config/gateway.json', 'utf8')).mumble.port)" 2>/dev/null || echo "64738")
    else
        CONFIG_PORT="8081"
        CONFIG_MUMBLE_HOST="localhost"
        CONFIG_MUMBLE_PORT="64738"
    fi
    
    # Set environment variables
    export NODE_ENV="$NODE_ENV"
    export PORT="${PORT:-$CONFIG_PORT}"
    export MUMBLE_HOST="${MUMBLE_HOST:-$CONFIG_MUMBLE_HOST}"
    export MUMBLE_PORT="${MUMBLE_PORT:-$CONFIG_MUMBLE_PORT}"
    
    log "Configuration:"
    log "  - Environment: $NODE_ENV"
    log "  - Port: $PORT"
    log "  - Mumble Host: $MUMBLE_HOST"
    log "  - Mumble Port: $MUMBLE_PORT"
    
    # Start the gateway
    nohup node server/gateway.js > "$LOG_FILE" 2>&1 &
    PID=$!
    
    # Save PID
    echo "$PID" > "$PID_FILE"
    
    # Wait a moment to check if it started successfully
    sleep 2
    
    if ps -p "$PID" > /dev/null 2>&1; then
        success "Gateway started successfully (PID: $PID)"
        log "Log file: $LOG_FILE"
        log "WebRTC client: http://localhost:$PORT/webrtc"
        log "Main page: http://localhost:$PORT/"
        log "Status: http://localhost:$PORT/health"
    else
        error "Failed to start gateway"
        log "Check log file: $LOG_FILE"
        exit 1
    fi
}

# Stop the gateway
stop_gateway() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p "$PID" > /dev/null 2>&1; then
            log "Stopping gateway (PID: $PID)..."
            kill "$PID"
            
            # Wait for graceful shutdown
            for i in {1..10}; do
                if ! ps -p "$PID" > /dev/null 2>&1; then
                    break
                fi
                sleep 1
            done
            
            if ps -p "$PID" > /dev/null 2>&1; then
                warning "Gateway did not stop gracefully, forcing kill..."
                kill -9 "$PID"
            fi
            
            rm -f "$PID_FILE"
            success "Gateway stopped"
        else
            warning "Gateway is not running"
            rm -f "$PID_FILE"
        fi
    else
        warning "No PID file found"
    fi
}

# Show status
show_status() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p "$PID" > /dev/null 2>&1; then
            success "Gateway is running (PID: $PID)"
            log "Log file: $LOG_FILE"
            log "WebRTC client: http://localhost:${PORT:-3000}/webrtc"
        else
            warning "Gateway is not running (stale PID file)"
            rm -f "$PID_FILE"
        fi
    else
        warning "Gateway is not running"
    fi
}

# Show logs
show_logs() {
    if [ -f "$LOG_FILE" ]; then
        tail -f "$LOG_FILE"
    else
        warning "Log file not found: $LOG_FILE"
    fi
}

# Main script logic
case "${1:-start}" in
    start)
        log "Starting FGCom-mumble WebRTC Gateway..."
        check_node
        check_npm
        create_directories
        install_dependencies
        check_running
        start_gateway
        ;;
    stop)
        log "Stopping FGCom-mumble WebRTC Gateway..."
        stop_gateway
        ;;
    restart)
        log "Restarting FGCom-mumble WebRTC Gateway..."
        stop_gateway
        sleep 2
        start_gateway
        ;;
    status)
        show_status
        ;;
    logs)
        show_logs
        ;;
    install)
        log "Installing dependencies only..."
        check_node
        check_npm
        create_directories
        install_dependencies
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs|install}"
        echo ""
        echo "Commands:"
        echo "  start   - Start the WebRTC gateway server"
        echo "  stop    - Stop the WebRTC gateway server"
        echo "  restart - Restart the WebRTC gateway server"
        echo "  status  - Show gateway status"
        echo "  logs    - Show gateway logs"
        echo "  install - Install dependencies only"
        echo ""
        echo "Environment variables:"
        echo "  NODE_ENV     - Node environment (default: development)"
        echo "  PORT         - Gateway port (default: 8081)"
        echo "  MUMBLE_HOST  - Mumble server host (default: localhost)"
        echo "  MUMBLE_PORT  - Mumble server port (default: 64738)"
        exit 1
        ;;
esac
