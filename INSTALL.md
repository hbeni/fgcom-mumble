# FGCom-mumble Installation

## Quick Start (Recommended)

```bash
# Clone the repository
git clone https://github.com/Supermagnum/fgcom-mumble.git
cd fgcom-mumble

# Fix all issues and install dependencies
./scripts/fix_all_issues.sh

# Build and install
make build
sudo make install

# Set up Mumble channels and start service
fgcom-setup-channels
fgcom-service start
```

## What This Does

The `fix_all_issues.sh` script automatically resolves all known installation issues:

- ✅ **Build System**: Initializes submodules, installs dependencies
- ✅ **Test Suite**: Installs testing tools, fixes path handling  
- ✅ **Installation**: Creates directories, sets permissions
- ✅ **Service Config**: Configures headless operation, creates systemd service
- ✅ **Bot Dependencies**: Installs LuaJIT, protobuf, builds lua-mumble library
- ✅ **SSL Certificates**: Generates bot authentication certificates
- ✅ **System Integration**: Creates service management scripts

## Service Management

```bash
fgcom-service start     # Start the service
fgcom-service stop      # Stop the service  
fgcom-service restart   # Restart the service
fgcom-service status    # Check service status
fgcom-service logs      # View service logs
```

## Headless Server

For headless servers (no GUI):

```bash
# Build headless components only
make build-plugin build-server
sudo make install
fgcom-service start
```

## Troubleshooting

```bash
# Check service status
systemctl status fgcom-mumble

# View logs
journalctl -u fgcom-mumble -f

# Re-run fixes if needed
./scripts/fix_all_issues.sh
```

## Documentation

- [User Installation Guide](docs/USER_INSTALLATION_GUIDE.md) - Detailed installation instructions
- [Installation Issues Fixes](docs/INSTALLATION_ISSUES_FIXES.md) - Complete list of fixes
- [Compilation Guide](docs/COMPILATION_GUIDE.md) - Build system documentation

## Support

If you encounter issues, the fix scripts address all known installation problems. Run `./scripts/fix_all_issues.sh` to resolve any issues automatically.
