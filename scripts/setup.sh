#!/bin/bash

# FGCom-mumble Quick Setup Launcher
# This script launches the interactive configuration setup

echo "FGCom-mumble Configuration Setup"
echo "=================================="
echo ""
echo "This will guide you through setting up all FGCom-mumble configuration files."
echo "You can press Enter to skip any optional fields."
echo ""

# Check if we're in the right directory
if [[ ! -f "README.md" ]] || [[ ! -d "configs" ]]; then
    echo "Error: Please run this script from the FGCom-mumble root directory"
    echo "   Current directory: $(pwd)"
    echo "   Expected files: README.md, configs/"
    echo "   Try: ./scripts/setup.sh"
    exit 1
fi

# Launch the configuration setup
echo "Starting configuration setup..."
echo ""

exec ./scripts/setup_configuration.sh "$@"
