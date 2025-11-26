# Security Setup Guide for FGCom-Mumble

This guide explains how to securely configure FGCom-Mumble with environment variables for API keys, passwords, and other sensitive credentials.

## CRITICAL SECURITY WARNING

**NEVER store passwords, API keys, or usernames directly in configuration files!**

All sensitive credentials must be stored as environment variables. This guide shows you how to do it properly.

## Quick Start

1. **Copy the environment template:**
   ```bash
   cp configs/env.template .env
   ```

2. **Edit the .env file with your actual credentials:**
   ```bash
   nano .env  # or use your preferred editor
   ```

3. **Load the environment variables:**
   ```bash
   source .env
   ```

4. **Start FGCom-Mumble:**
   ```bash
   ./start_fgcom_mumble.sh
   ```

## Detailed Setup Instructions

### Method 1: Using .env File (Recommended for Development)

1. **Create your environment file:**
   ```bash
   cp configs/env.template .env
   ```

2. **Edit the .env file:**
   ```bash
   # Open in your preferred editor
   nano .env
   # or
   vim .env
   # or
   code .env
   ```

3. **Fill in your credentials:**
   ```bash
   # Example entries in .env file:
   FGCOM_API_KEY="your_secure_api_key_here"
   NOAA_SWPC_API_KEY="your_noaa_key_here"
   NASA_API_KEY="your_nasa_key_here"
   OPENWEATHERMAP_API_KEY="your_openweather_key_here"
   ```

4. **Load environment variables:**
   ```bash
   # Load the variables into your current session
   source .env
   
   # Verify they're loaded
   echo $FGCOM_API_KEY
   ```

### Method 2: System-wide Environment Variables

#### Linux/macOS

**Option A: Add to your shell profile**
```bash
# Add to ~/.bashrc, ~/.zshrc, or ~/.profile
echo 'export FGCOM_API_KEY="your_secure_api_key_here"' >> ~/.bashrc
echo 'export NOAA_SWPC_API_KEY="your_noaa_key_here"' >> ~/.bashrc
source ~/.bashrc
```

**Option B: Create a system-wide environment file**
```bash
# Create system-wide environment file
sudo nano /etc/environment

# Add your variables (one per line, no spaces around =)
FGCOM_API_KEY="your_secure_api_key_here"
NOAA_SWPC_API_KEY="your_noaa_key_here"
```

#### Windows

**Option A: Using PowerShell**
```powershell
# Set for current session
$env:FGCOM_API_KEY="your_secure_api_key_here"
$env:NOAA_SWPC_API_KEY="your_noaa_key_here"

# Set permanently for user
[Environment]::SetEnvironmentVariable("FGCOM_API_KEY", "your_secure_api_key_here", "User")
[Environment]::SetEnvironmentVariable("NOAA_SWPC_API_KEY", "your_noaa_key_here", "User")
```

**Option B: Using Command Prompt**
```cmd
# Set for current session
set FGCOM_API_KEY=your_secure_api_key_here
set NOAA_SWPC_API_KEY=your_noaa_key_here

# Set permanently (requires restart)
setx FGCOM_API_KEY "your_secure_api_key_here"
setx NOAA_SWPC_API_KEY "your_noaa_key_here"
```

**Option C: Using Windows Environment Variables GUI**
1. Press `Win + R`, type `sysdm.cpl`, press Enter
2. Click "Environment Variables"
3. Add your variables in "User variables" or "System variables"

### Method 3: Using a Startup Script

Create a startup script that loads your environment variables:

```bash
#!/bin/bash
# File: start_fgcom_with_env.sh

# Load environment variables
source .env

# Start FGCom-Mumble
./fgcom_mumble_server
```

Make it executable:
```bash
chmod +x start_fgcom_with_env.sh
```

## Required Environment Variables

### Core Application
- `FGCOM_API_KEY` - Main API key for FGCom-Mumble

### External Data Sources
- `NOAA_SWPC_API_KEY` - NOAA Space Weather Prediction Center
- `NOAA_SWPC_USERNAME` - NOAA SWPC username
- `NOAA_SWPC_PASSWORD` - NOAA SWPC password
- `NASA_API_KEY` - NASA API key
- `OPENWEATHERMAP_API_KEY` - OpenWeatherMap API key
- `USGS_API_KEY` - USGS API key
- `VAISALA_API_KEY` - Vaisala API key

### Database (if using external database)
- `DB_HOST` - Database host
- `DB_PORT` - Database port
- `DB_NAME` - Database name
- `DB_USER` - Database username
- `DB_PASSWORD` - Database password

## Getting API Keys

### NOAA Space Weather Prediction Center
1. Visit: https://www.swpc.noaa.gov/
2. Register for an account
3. Request API access
4. Copy your API key to `NOAA_SWPC_API_KEY`

### NASA API
1. Visit: https://api.nasa.gov/
2. Fill out the simple form
3. Copy your API key to `NASA_API_KEY`

### OpenWeatherMap
1. Visit: https://openweathermap.org/api
2. Sign up for a free account
3. Generate an API key
4. Copy your API key to `OPENWEATHERMAP_API_KEY`

### USGS
1. Visit: https://www.usgs.gov/centers/eros/science-services
2. Register for an account
3. Request API access
4. Copy your API key to `USGS_API_KEY`

## Security Best Practices

### 1. File Permissions
```bash
# Make .env file readable only by owner
chmod 600 .env

# Ensure config files are not world-readable
chmod 644 configs/*.conf
```

### 2. Git Configuration
Add to your `.gitignore` file:
```
# Environment files with sensitive data
.env
.env.local
.env.production
.env.staging
```

### 3. Production Deployment

**For Docker:**
```dockerfile
# Use Docker secrets or environment variables
ENV FGCOM_API_KEY=${FGCOM_API_KEY}
```

**For Kubernetes:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: fgcom-secrets
type: Opaque
data:
  fgcom-api-key: <base64-encoded-key>
  noaa-api-key: <base64-encoded-key>
```

**For Docker Compose:**
```yaml
version: '3.8'
services:
  fgcom-mumble:
    image: fgcom-mumble:latest
    environment:
      - FGCOM_API_KEY=${FGCOM_API_KEY}
      - NOAA_SWPC_API_KEY=${NOAA_SWPC_API_KEY}
    env_file:
      - .env
```

### 4. Credential Rotation
- Rotate API keys regularly (every 90 days recommended)
- Use different credentials for development, staging, and production
- Monitor API key usage and revoke unused keys

### 5. Monitoring and Alerting
- Set up monitoring for failed authentication attempts
- Alert on unusual API usage patterns
- Log all credential access (without logging the actual credentials)

## Troubleshooting

### Environment Variables Not Loading
```bash
# Check if variables are set
env | grep FGCOM

# Check if .env file exists and is readable
ls -la .env

# Test loading the file
source .env && echo $FGCOM_API_KEY
```

### Configuration Not Reading Environment Variables
1. Ensure your configuration parser supports `${VARIABLE_NAME}` syntax
2. Check that the configuration file references environment variables correctly
3. Verify the environment variables are loaded before starting the application

### Permission Denied Errors
```bash
# Fix file permissions
chmod 600 .env
chown $USER:$USER .env
```

## Example Complete Setup

```bash
# 1. Copy template
cp configs/env.template .env

# 2. Edit with your credentials
nano .env

# 3. Set proper permissions
chmod 600 .env

# 4. Load variables
source .env

# 5. Verify they're loaded
echo "API Key: $FGCOM_API_KEY"

# 6. Start the application
./start_fgcom_mumble.sh
```

## Support

If you encounter issues with environment variable setup:

1. Check the [Installation Guide](INSTALLATION_GUIDE.md)
2. Review the [Configuration Guide](CONFIGURATION_GUIDE.md)
3. Open an issue on GitHub with:
   - Your operating system
   - The error messages you're seeing
   - Your configuration (with sensitive data redacted)

## Additional Resources

- [Environment Variables Best Practices](https://12factor.net/config)
- [Docker Secrets Management](https://docs.docker.com/engine/swarm/secrets/)
- [Kubernetes Secrets](https://kubernetes.io/docs/concepts/configuration/secret/)
- [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/)
- [HashiCorp Vault](https://www.vaultproject.io/)
