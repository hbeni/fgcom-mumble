# FGCom-mumble Installation Issues and Fixes

This document addresses all the installation issues encountered during FGCom-mumble setup and provides comprehensive solutions. **Note: Most issues are now automatically resolved by the new installation system.**

## Summary of Issues Fixed

### 1. Build System Issues - FIXED

**Issues:**
- Missing dependencies and submodules
- jsimconnect submodule not initialized
- Maven build failures
- Missing Java/Maven dependencies

**Solutions:**
- **NEW**: Use `sudo ./scripts/install_fgcom_mumble.sh` for automated installation
- Created `scripts/setup_build_environment.sh` to initialize all submodules
- Added automatic dependency installation for Java, Maven, and build tools
- Fixed submodule initialization with `git submodule update --init --recursive`
- Added dependency checking and installation for all required packages

### 2. Test Suite Issues - FIXED

**Issues:**
- Missing testing tools (gtest, cppcheck, clang-tidy)
- Incorrect path handling in test scripts
- Test scripts using relative paths from wrong working directory
- Failing unit tests

**Solutions:**
- Created `scripts/fix_test_suite.sh` to install all testing tools
- Fixed test scripts to use absolute paths
- Added graceful handling of missing source files
- Created universal test runner with proper path handling
- Fixed Google Test detection to check for headers instead of commands

### 3. Installation Issues - FIXED

**Issues:**
- Missing install target in Makefile
- Missing system directories
- No rule to make target 'install'

**Solutions:**
- Verified and enhanced the existing install target in Makefile
- Created all necessary system directories with proper permissions
- Added comprehensive install target that handles all components
- Created fgcom-mumble user with proper ownership

### 4. Service Configuration Issues - FIXED

**Issues:**
- GUI application on headless server
- Wrong service configuration
- Service failing with GUI-related errors

**Solutions:**
- Added `JAVA_OPTS="-Djava.awt.headless=true"` to systemd service
- Created proper bot manager script for server functionality
- Fixed service configuration to run bots instead of GUI
- Added headless operation support throughout

### 5. Bot Script Dependencies - FIXED

**Issues:**
- Missing shared functions file
- Missing mumble.so library
- Missing compilation dependencies

**Solutions:**
- Created `scripts/setup_build_environment.sh` to install all bot dependencies
- Added automatic installation of LuaJIT, protobuf, opus, and other required packages
- Built lua-mumble library from source with all dependencies
- Copied shared functions file to proper location

### 6. Bot Configuration Issues - FIXED

**Issues:**
- Missing bot certificates
- Missing bot parameters
- Missing recording directory

**Solutions:**
- Added automatic SSL certificate generation
- Created enhanced bot manager script with proper parameter handling
- Created recording directory with proper permissions
- Added comprehensive error handling and logging

### 7. System Integration Issues - FIXED

**Issues:**
- Systemd service configuration problems
- Missing Mumble channels
- Service pointing to wrong executable

**Solutions:**
- Created proper systemd service file with headless support
- Added service management script (`fgcom-service`)
- Created Mumble channel setup script (`fgcom-setup-channels`)
- Fixed all service configuration issues

## Fix Scripts Created

### 1. `scripts/setup_build_environment.sh`
**Purpose:** Fixes all build system issues
**Features:**
- Initializes git submodules
- Installs all build dependencies
- Creates system directories
- Generates SSL certificates
- Builds lua-mumble library
- Creates bot manager script
- Sets up systemd service

### 2. `scripts/fix_test_suite.sh`
**Purpose:** Fixes all test suite issues
**Features:**
- Installs testing tools
- Fixes test script paths
- Creates universal test runner
- Adds graceful error handling
- Creates test dependencies checker
- Creates test results aggregator

### 3. `scripts/fix_installation.sh`
**Purpose:** Fixes all installation issues
**Features:**
- Creates system directories
- Sets up user and permissions
- Creates enhanced bot manager
- Sets up systemd service
- Creates service management tools
- Creates Mumble channel setup script

### 4. `scripts/fix_all_issues.sh`
**Purpose:** Master script that fixes ALL issues
**Features:**
- Combines all fixes into one script
- Addresses every issue mentioned in the summary
- Provides comprehensive solution
- Includes troubleshooting information

## Usage Instructions

### Quick Fix (Recommended)
```bash
# Run the master fix script to address all issues
./scripts/fix_all_issues.sh
```

### Individual Fixes
```bash
# Fix build system issues only
./scripts/setup_build_environment.sh

# Fix test suite issues only
./scripts/fix_test_suite.sh

# Fix installation issues only
./scripts/fix_installation.sh
```

### After Running Fixes
```bash
# Build the project
make build

# Install the project
sudo make install

# Set up Mumble channels
fgcom-setup-channels

# Start the service
fgcom-service start
```

## Service Management

### Service Commands
```bash
# Check service status
fgcom-service status

# Start service
fgcom-service start

# Stop service
fgcom-service stop

# Restart service
fgcom-service restart

# View logs
fgcom-service logs

# Enable at boot
fgcom-service enable

# Disable at boot
fgcom-service disable
```

### Troubleshooting
```bash
# Check service status
systemctl status fgcom-mumble

# View service logs
journalctl -u fgcom-mumble -f

# Check bot logs
tail -f /var/log/fgcom-mumble/*.log

# Check bot status
fgcom-bot-manager status
```

## Headless Server Operation

The fixes include comprehensive headless server support:

### Headless Configuration
- `JAVA_OPTS="-Djava.awt.headless=true"` in systemd service
- All GUI components run in headless mode
- Service configured for server operation only
- Bot scripts handle all server functionality

### Headless Build Options
```bash
# Build headless server only
make build-plugin build-server

# Build without GUI components
make build-plugin build-server build-fgcom-addon

# Build without MSFS2020 integration
make build ENABLE_JSIMCONNECT=false
```

## File Locations

### System Directories
- `/usr/local/lib/fgcom-mumble/` - Main library directory
- `/var/log/fgcom-mumble/` - Log files
- `/etc/fgcom-mumble/` - Configuration files
- `/usr/share/fgcom-mumble/` - Server components
- `/usr/share/fgcom-mumble/recordings/` - Bot recordings

### Executables
- `/usr/local/bin/fgcom-bot-manager` - Bot management script
- `/usr/local/bin/fgcom-service` - Service management script
- `/usr/local/bin/fgcom-setup-channels` - Channel setup script

### Service Files
- `/etc/systemd/system/fgcom-mumble.service` - Systemd service
- `/var/log/fgcom-mumble/` - Service logs

## Verification

After running the fixes, verify everything is working:

```bash
# Check if all components are installed
ls -la /usr/lib/mumble/plugins/fgcom-mumble.so
ls -la /usr/share/fgcom-mumble/
ls -la /etc/fgcom-mumble/

# Check if service is configured
systemctl status fgcom-mumble

# Check if bots can start
fgcom-bot-manager status

# Check if certificates exist
ls -la /etc/fgcom-mumble/bot.*

# Check if lua-mumble is built
ls -la /usr/local/lib/lua/5.1/mumble.so
```

## Support

If you encounter any issues after running the fixes:

1. Check the service logs: `journalctl -u fgcom-mumble -f`
2. Check bot logs: `tail -f /var/log/fgcom-mumble/*.log`
3. Verify all dependencies are installed
4. Ensure Mumble channels are created
5. Check SSL certificates are valid

All fixes are designed to be idempotent - you can run them multiple times safely.
