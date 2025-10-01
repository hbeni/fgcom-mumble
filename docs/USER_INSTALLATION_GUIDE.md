# FGCom-mumble User Installation Guide

This guide provides step-by-step instructions for users to install FGCom-mumble with all issues automatically resolved.

## Quick Installation (Recommended)

For most users, run this single command to fix all issues and install everything:

```bash
# Clone the repository
git clone https://github.com/hbeni/fgcom-mumble.git
cd fgcom-mumble

# Run the master fix script (fixes ALL issues automatically)
./scripts/fix_all_issues.sh

# Build the project
make build

# Install the project
sudo make install

# Set up Mumble channels
fgcom-setup-channels

# Start the service
fgcom-service start
```

## What the Fix Script Does

The `fix_all_issues.sh` script automatically:

###  **Build System Fixes**
- Initializes git submodules
- Installs Java, Maven, and build tools
- Resolves all dependency issues
- Fixes submodule initialization problems

###  **Test Suite Fixes**
- Installs testing tools (cppcheck, clang-tidy, lcov, valgrind)
- Fixes test script path handling
- Installs Google Test framework
- Creates universal test runner

###  **Installation Fixes**
- Creates all necessary system directories
- Sets up proper user and permissions
- Installs bot dependencies (LuaJIT, protobuf, opus, etc.)
- Generates SSL certificates for bots
- Builds lua-mumble library

###  **Headless Server Support**
- Configures headless operation (`JAVA_OPTS="-Djava.awt.headless=true"`)
- Creates systemd service with proper settings
- Sets up bot management scripts
- Creates Mumble channel setup tools

## Alternative: Individual Fix Scripts

If you prefer to run fixes individually:

```bash
# Fix build system issues only
./scripts/setup_build_environment.sh

# Fix test suite issues only
./scripts/fix_test_suite.sh

# Fix installation issues only
./scripts/fix_installation.sh
```

## Installation Steps

### 1. Prerequisites
```bash
# Install basic system dependencies
sudo apt-get update
sudo apt-get install -y git build-essential cmake
```

### 2. Clone and Fix
```bash
# Clone the repository
git clone https://github.com/hbeni/fgcom-mumble.git
cd fgcom-mumble

# Run the master fix script
./scripts/fix_all_issues.sh
```

### 3. Build and Install
```bash
# Build the project
make build

# Install to system
sudo make install
```

### 4. Configure Mumble Channels
```bash
# Set up required Mumble channels
fgcom-setup-channels
```

### 5. Start the Service
```bash
# Start FGCom-mumble service
fgcom-service start

# Check service status
fgcom-service status
```

## Service Management

After installation, use these commands to manage the service:

```bash
# Check service status
fgcom-service status

# Start service
fgcom-service start

# Stop service
fgcom-service stop

# Restart service
fgcom-service restart

# View service logs
fgcom-service logs

# Enable service at boot
fgcom-service enable

# Disable service at boot
fgcom-service disable
```

## Headless Server Installation

For headless servers (no GUI), use:

```bash
# Build headless server only
make build-plugin build-server

# Install headless components
sudo make install

# The service is already configured for headless operation
fgcom-service start
```

## Troubleshooting

### Check Installation
```bash
# Verify all components are installed
ls -la /usr/lib/mumble/plugins/fgcom-mumble.so
ls -la /usr/share/fgcom-mumble/
ls -la /etc/fgcom-mumble/

# Check service status
systemctl status fgcom-mumble

# Check bot status
fgcom-bot-manager status
```

### View Logs
```bash
# Service logs
journalctl -u fgcom-mumble -f

# Bot logs
tail -f /var/log/fgcom-mumble/*.log
```

### Common Issues

**Service won't start:**
```bash
# Check if Mumble channels exist
# Create a channel named 'fgcom-mumble' in your Mumble server
fgcom-setup-channels
```

**Permission errors:**
```bash
# Fix permissions
sudo chown -R fgcom-mumble:fgcom-mumble /usr/share/fgcom-mumble
sudo chown -R fgcom-mumble:fgcom-mumble /var/log/fgcom-mumble
```

**Missing dependencies:**
```bash
# Re-run the fix script
./scripts/fix_all_issues.sh
```

## File Locations

After installation, files are located at:

- **Mumble Plugin**: `/usr/lib/mumble/plugins/fgcom-mumble.so`
- **Configuration**: `/etc/fgcom-mumble/`
- **Server Components**: `/usr/share/fgcom-mumble/server/`
- **Scripts**: `/usr/share/fgcom-mumble/scripts/`
- **Documentation**: `/usr/share/fgcom-mumble/docs/`
- **Logs**: `/var/log/fgcom-mumble/`

## Next Steps

1. **Configure Mumble Server**: Create channels starting with 'fgcom-mumble'
2. **Start Service**: `fgcom-service start`
3. **Connect Clients**: Use Mumble clients with the FGCom-mumble plugin
4. **Monitor**: Check logs and service status regularly

## Support

If you encounter issues:

1. Check the service logs: `journalctl -u fgcom-mumble -f`
2. Verify all dependencies: `./scripts/fix_all_issues.sh`
3. Check Mumble channels exist
4. Review the troubleshooting section above

The fix scripts are designed to be idempotent - you can run them multiple times safely.
