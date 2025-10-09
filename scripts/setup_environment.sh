#!/bin/bash

# FGCom-Mumble Environment Setup Script
# This script helps users set up environment variables securely

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Configuration
ENV_TEMPLATE="$PROJECT_ROOT/configs/env.template"
ENV_FILE="$PROJECT_ROOT/.env"
CONFIG_DIR="$PROJECT_ROOT/configs"

echo -e "${BLUE}🔧 FGCom-Mumble Environment Setup${NC}"
echo "=================================="
echo

# Check if .env already exists
if [[ -f "$ENV_FILE" ]]; then
    echo -e "${YELLOW}⚠️  .env file already exists!${NC}"
    echo "Current .env file location: $ENV_FILE"
    echo
    read -p "Do you want to overwrite it? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}ℹ️  Keeping existing .env file${NC}"
        exit 0
    fi
fi

# Check if template exists
if [[ ! -f "$ENV_TEMPLATE" ]]; then
    echo -e "${RED}❌ Error: Environment template not found!${NC}"
    echo "Expected location: $ENV_TEMPLATE"
    exit 1
fi

echo -e "${BLUE}📋 Setting up environment variables...${NC}"

# Copy template to .env
cp "$ENV_TEMPLATE" "$ENV_FILE"

# Set proper permissions
chmod 600 "$ENV_FILE"

echo -e "${GREEN}✅ Created .env file with secure permissions${NC}"
echo "Location: $ENV_FILE"
echo

# Interactive setup
echo -e "${BLUE}🔑 Let's set up your credentials interactively${NC}"
echo "You can skip any credential you don't need by pressing Enter"
echo

# Core application settings
echo -e "${YELLOW}📱 Core Application Settings${NC}"
read -p "FGCom API Key (generate a secure random key): " fgcom_api_key
if [[ -n "$fgcom_api_key" ]]; then
    sed -i "s/FGCOM_API_KEY=/FGCOM_API_KEY=\"$fgcom_api_key\"/" "$ENV_FILE"
fi

# Database settings
echo
echo -e "${YELLOW}🗄️  Database Settings (optional)${NC}"
read -p "Database Host (leave empty if using default): " db_host
if [[ -n "$db_host" ]]; then
    sed -i "s/DB_HOST=/DB_HOST=\"$db_host\"/" "$ENV_FILE"
fi

read -p "Database Port (leave empty for default): " db_port
if [[ -n "$db_port" ]]; then
    sed -i "s/DB_PORT=/DB_PORT=\"$db_port\"/" "$ENV_FILE"
fi

read -p "Database Name: " db_name
if [[ -n "$db_name" ]]; then
    sed -i "s/DB_NAME=/DB_NAME=\"$db_name\"/" "$ENV_FILE"
fi

read -p "Database Username: " db_user
if [[ -n "$db_user" ]]; then
    sed -i "s/DB_USER=/DB_USER=\"$db_user\"/" "$ENV_FILE"
fi

read -s -p "Database Password: " db_password
if [[ -n "$db_password" ]]; then
    sed -i "s/DB_PASSWORD=/DB_PASSWORD=\"$db_password\"/" "$ENV_FILE"
fi
echo

# External API settings
echo
echo -e "${YELLOW}🌐 External API Settings${NC}"
echo "You can get API keys from these services:"
echo "  - NOAA: https://www.swpc.noaa.gov/"
echo "  - NASA: https://api.nasa.gov/"
echo "  - OpenWeatherMap: https://openweathermap.org/api"
echo

read -p "NOAA SWPC API Key: " noaa_swpc_key
if [[ -n "$noaa_swpc_key" ]]; then
    sed -i "s/NOAA_SWPC_API_KEY=/NOAA_SWPC_API_KEY=\"$noaa_swpc_key\"/" "$ENV_FILE"
fi

read -p "NASA API Key: " nasa_key
if [[ -n "$nasa_key" ]]; then
    sed -i "s/NASA_API_KEY=/NASA_API_KEY=\"$nasa_key\"/" "$ENV_FILE"
fi

read -p "OpenWeatherMap API Key: " openweather_key
if [[ -n "$openweather_key" ]]; then
    sed -i "s/OPENWEATHERMAP_API_KEY=/OPENWEATHERMAP_API_KEY=\"$openweather_key\"/" "$ENV_FILE"
fi

read -p "USGS API Key: " usgs_key
if [[ -n "$usgs_key" ]]; then
    sed -i "s/USGS_API_KEY=/USGS_API_KEY=\"$usgs_key\"/" "$ENV_FILE"
fi

# Final setup
echo
echo -e "${BLUE}🔧 Finalizing setup...${NC}"

# Add to .gitignore if not already present
GITIGNORE="$PROJECT_ROOT/.gitignore"
if [[ -f "$GITIGNORE" ]] && ! grep -q "\.env" "$GITIGNORE"; then
    echo ".env" >> "$GITIGNORE"
    echo -e "${GREEN}✅ Added .env to .gitignore${NC}"
fi

# Create a simple test script
cat > "$PROJECT_ROOT/test_env.sh" << 'EOF'
#!/bin/bash
# Test script to verify environment variables are loaded

echo "Testing environment variables..."

# Load environment variables
if [[ -f ".env" ]]; then
    source .env
    echo "✅ .env file loaded"
else
    echo "❌ .env file not found"
    exit 1
fi

# Test core variables
if [[ -n "${FGCOM_API_KEY:-}" ]]; then
    echo "✅ FGCOM_API_KEY is set"
else
    echo "⚠️  FGCOM_API_KEY is not set"
fi

# Test external APIs
if [[ -n "${NOAA_SWPC_API_KEY:-}" ]]; then
    echo "✅ NOAA_SWPC_API_KEY is set"
else
    echo "⚠️  NOAA_SWPC_API_KEY is not set"
fi

if [[ -n "${NASA_API_KEY:-}" ]]; then
    echo "✅ NASA_API_KEY is set"
else
    echo "⚠️  NASA_API_KEY is not set"
fi

echo "Environment test complete!"
EOF

chmod +x "$PROJECT_ROOT/test_env.sh"

echo -e "${GREEN}✅ Environment setup complete!${NC}"
echo
echo -e "${BLUE}📋 Next steps:${NC}"
echo "1. Review your .env file: $ENV_FILE"
echo "2. Test your environment: ./test_env.sh"
echo "3. Load environment variables: source .env"
echo "4. Start FGCom-Mumble: ./start_fgcom_mumble.sh"
echo
echo -e "${YELLOW}⚠️  Security reminders:${NC}"
echo "• Never commit .env to version control"
echo "• Use strong, unique passwords and API keys"
echo "• Rotate credentials regularly"
echo "• Keep your .env file secure (permissions: 600)"
echo
echo -e "${BLUE}📚 Documentation:${NC}"
echo "• Security Setup Guide: docs/SECURITY_SETUP.md"
echo "• Best Practices: docs/SECURITY_BEST_PRACTICES.md"
echo
echo -e "${GREEN}🎉 Setup complete!${NC}"
