# FGCom-mumble Installation Guide

**Complete installation and setup guide for FGCom-mumble client and server components**

## Client Installation

### Setup Requirements

- Have a standard mumble client with recent plugin support (>= v1.4.0)
- A recent OpenSSL installation
- **v2.0+ Additional Requirements**:
  - `python3` (required): For antenna pattern generation and coordinate transformations
  - `bc` (required): For high-precision trigonometric calculations
  - `libcurl4-openssl-dev` (required): HTTP client library for OpenInfraMap integration
  - `libjsoncpp-dev` (required): JSON parsing library for OpenInfraMap data processing
  - `nec2c` (optional): NEC2 antenna simulation for pattern generation
  - GPU libraries (optional): CUDA/OpenCL for GPU acceleration features
  - `httplib.h` (included): HTTP client for solar data, lightning data, and weather data
  - `json.hpp` (included): JSON parsing for API responses and configuration

### Installation Methods

The release ZIP contains all binary plugins for all supported operating systems in the `mumble_plugin` bundle.

#### v2.0+ Installation Notes
For full functionality with v2.0+ features, ensure you have the additional dependencies installed:

**Linux/Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install python3 bc libssl-dev libcurl4-openssl-dev libjsoncpp-dev
# Optional: For GPU acceleration
sudo apt-get install nvidia-cuda-toolkit  # For CUDA support
sudo apt-get install opencl-headers     # For OpenCL support
```

**Windows:**
- Install Python 3.x from python.org
- Install bc calculator (available via Chocolatey: `choco install bc`)
- Install Visual Studio Build Tools for C++ compilation
- Install CUDA Toolkit (optional, for GPU acceleration)

**macOS:**
```bash
brew install python3 bc openssl curl jsoncpp
# Optional: For GPU acceleration
brew install cuda  # For CUDA support
```

### GUI Method (Recommended)
After installing Mumble, you can usually install the plugin by just double-clicking the `.mumble_plugin`-bundle.

Otherwise you can also use Mumbles integrated plugin installer:
- Start Mumble.
- In Mumbles *Configure/Settings/Plugins* dialog, hit *Install plugin*.
- Select the `.mumble_plugin` plugin bundle. Mumble will install the plugin file and report success.
- Browse the plugin list and activate *FGCom-mumble*.
- You are now ready to go!

### Manual Install Through Terminal
The installation can also be started by calling mumble from the commandline with the plugin binary release, like: `mumble fgcom-mumble-1.4.1.mumble_plugin`

### Manual Install by File Copying
- Rename the `.mumble_plugin` bundle to `.zip` and extract it.
- Choose the appropriate library for your operating system and copy it to mumbles `plugins`-folder.
  - `fgcom-mumble.so` for Linux (64 bit)
  - `fgcom-mumble.dll` for Windows (64 bit)
  - `fgcom-mumble-x86_32.dll` for Windows (32 bit)
  - `fgcom-mumble-macOS.bundle` for MacOs
- Mumble will pick it up automatically and show it in the plugins dialog. Activate the plugin.

## Updating

When Mumble starts, it will check the most recent version of the plugin against the github release page.
This can be disabled in mumbles settings.

When a more recent version is found, Mumble will ask you if you want to upgrade. When you allow it, Mumble downloads and replaces the plugin library automatically for you.  
You can also download and upgrade manually by the normal installation procedure described above.

## Plugin Configuration

Usually the default values are fine. Some features however can be configured differently, like disabling radio audio effects (white noise etc), changing the plugins UDP listen port or the name match of the special `fgcom-mumble` channel.

You can do this by copying the [`fgcom-mumble.ini`](configs/fgcom-mumble.ini) example file to your users home folder and adjusting as needed. The file is loaded once at plugin initialization from the following locations (in order):

- Linux:
  - `/etc/mumble/fgcom-mumble.ini`
  - `<home>/.fgcom-mumble.ini`
  - `<home>/fgcom-mumble.ini`
- Windows:
  - `<home>\fgcom-mumble.ini`
  - `<home>\Documents\fgcom-mumble.ini`

### Advanced Configuration (v2.0+)
FGCom-mumble v2.0+ includes comprehensive configuration options for all advanced features:

- **[configs/fgcom-mumble.conf.example](configs/fgcom-mumble.conf.example)**: Complete configuration template with all available options
- **[configs/fgcom-mumble.conf.minimal](configs/fgcom-mumble.conf.minimal)**: Minimal configuration for basic operation
- **Feature Toggles**: Runtime enable/disable of 107 features across 17 categories
- **Threading**: Customize thread intervals and resource allocation
- **API Server**: Configure RESTful API endpoints and WebSocket settings
- **Debugging**: Set logging levels, output handlers, and performance monitoring
- **Power Management**: Configure transmit power limits.
- **Solar Data**: Set NOAA/SWPC data update intervals and fallback options
- **Lightning Data**: Configure atmospheric noise simulation parameters
- **Weather Data**: Set weather data sources and update frequencies

All configuration files support INI format with comprehensive documentation and validation.

## Troubleshooting Installation Issues

### Installation Issues

**Plugin not loading:**
- Ensure Mumble version is >= 1.4.0
- Check that OpenSSL is properly installed
- Verify the plugin file is not corrupted
- Check Mumble's plugin directory permissions

**v2.0+ Features not working:**
- Verify Python 3 is installed and accessible: `python3 --version`
- Check bc calculator is available: `bc --version`
- For GPU acceleration, verify CUDA/OpenCL drivers are installed
- Check configuration files are in correct locations

**Configuration issues:**
- Ensure configuration files are in the correct directory (`configs/` not `config/`)
- Check file permissions allow reading configuration files
- Verify INI file syntax is correct (no missing brackets, proper key=value format)

## Server Installation

For server installation and configuration, see:
- [Server Documentation](server/Readme.server.md) - Server setup and configuration
- [Status Page Documentation](server/statuspage/Readme.statuspage.md) - Status page implementation
- [Technical Setup Guide](docs/TECHNICAL_SETUP_GUIDE.md) - Comprehensive setup guide

## Next Steps

After successful installation:
1. See [Client Usage Guide](docs/CLIENT_USAGE_GUIDE.md) for using the client
2. See [Special Frequencies Guide](docs/SPECIAL_FREQUENCIES_GUIDE.md) for special features
3. See [Troubleshooting Guide](docs/TROUBLESHOOTING_GUIDE.md) if you encounter issues
4. See [Compilation Guide](docs/COMPILATION_GUIDE.md) if you need to compile from source
