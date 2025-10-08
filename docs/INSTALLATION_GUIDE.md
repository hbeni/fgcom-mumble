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

# GPU Acceleration Dependencies (Optional but Recommended)
# For NVIDIA GPUs (CUDA support)
sudo apt-get install nvidia-cuda-toolkit nvidia-driver-470
# For AMD/Intel GPUs (OpenCL support)
sudo apt-get install opencl-headers ocl-icd-opencl-dev
# For Intel GPUs specifically
sudo apt-get install intel-opencl-icd
# For AMD GPUs specifically
sudo apt-get install rocm-opencl-runtime
```

**Windows:**
- Install Python 3.x from python.org
- Install bc calculator (available via Chocolatey: `choco install bc`)
- Install Visual Studio Build Tools for C++ compilation

**GPU Acceleration Dependencies (Optional but Recommended):**
- **NVIDIA GPUs**: Install CUDA Toolkit 11.0+ from NVIDIA Developer
- **AMD GPUs**: Install AMD Radeon Software with OpenCL support
- **Intel GPUs**: Install Intel Graphics Driver with OpenCL support
- **All GPUs**: Install OpenCL runtime for cross-platform support

**macOS:**
```bash
brew install python3 bc openssl curl jsoncpp

# GPU Acceleration Dependencies (Optional but Recommended)
# For NVIDIA GPUs (CUDA support)
brew install cuda
# For Apple Silicon/Intel GPUs (Metal support - built-in)
# Metal is automatically available on macOS 10.14+
# For OpenCL support (if needed)
brew install opencl-headers
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

You can do this by copying the example 
file found here https://github.com/Supermagnum/fgcom-mumble/blob/master/docs/fgcom-mumble-INI.md
to your users home folder and adjusting as needed. The file is loaded once at plugin initialization from the following locations (in order):

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

## GPU Acceleration Setup

### GPU Acceleration Modes

FGCom-mumble supports four GPU acceleration modes:

#### 1. DISABLED Mode
- **Description**: No GPU acceleration, all processing on CPU
- **Use Case**: Systems without GPU or when GPU resources are needed for other applications
- **Configuration**: `enable_gpu_acceleration = false`

#### 2. SERVER_ONLY Mode
- **Description**: GPU acceleration only on the server
- **Use Case**: Centralized processing with powerful server GPU
- **Configuration**: `gpu_mode = server`

#### 3. CLIENT_ONLY Mode
- **Description**: GPU acceleration only on client machines
- **Use Case**: Distributed processing with client GPUs
- **Configuration**: `gpu_mode = client`

#### 4. HYBRID Mode (Recommended)
- **Description**: Intelligent distribution between server and client GPUs
- **Use Case**: Optimal performance with load balancing
- **Configuration**: `gpu_mode = hybrid`

### GPU Framework Selection

#### NVIDIA GPUs (CUDA)
```ini
[gpu_acceleration]
enable_gpu_acceleration = true
gpu_mode = hybrid
enable_cuda = true
cuda_device_id = 0
cuda_memory_fraction = 0.8
```

#### AMD/Intel GPUs (OpenCL)
```ini
[gpu_acceleration]
enable_gpu_acceleration = true
gpu_mode = hybrid
enable_opencl = true
opencl_platform_id = 0
opencl_device_id = 0
```

#### Apple GPUs (Metal)
```ini
[gpu_acceleration]
enable_gpu_acceleration = true
gpu_mode = hybrid
enable_metal = true
metal_device_id = 0
```

### GPU Resource Management

#### Basic GPU Resource Limiting
```ini
[gpu_resource_limiting]
enable_gpu_resource_limiting = true
gpu_usage_percentage_limit = 30
gpu_memory_limit_mb = 256
gpu_priority_level = 3
```

#### Adaptive GPU Usage (Recommended for Gaming)
```ini
[gpu_resource_limiting]
enable_gpu_resource_limiting = true
gpu_usage_percentage_limit = 30
enable_adaptive_gpu_usage = true
min_gpu_usage_percentage = 10
max_gpu_usage_percentage = 50
game_detection_reduction = 50
high_load_reduction = 30
low_battery_reduction = 40
```

### GPU Performance Optimization

#### High-Performance Configuration
```ini
[gpu_acceleration]
enable_gpu_acceleration = true
gpu_mode = hybrid
gpu_memory_limit = 4096
gpu_max_concurrent_operations = 8
temperature_threshold = 85.0
utilization_threshold = 90.0
enable_memory_optimization = true
enable_thermal_management = true
```

#### Gaming-Optimized Configuration
```ini
[gpu_resource_limiting]
enable_gpu_resource_limiting = true
gpu_usage_percentage_limit = 25
gpu_memory_limit_mb = 128
gpu_priority_level = 2
enable_adaptive_gpu_usage = true
game_detection_reduction = 60
```

### GPU Monitoring and Debugging

#### Enable GPU Monitoring
```ini
[gpu_resource_limiting]
enable_gpu_monitoring = true
enable_gpu_usage_logging = true
gpu_usage_log_file = gpu_usage.log
enable_gpu_statistics = true
```

#### Debug GPU Issues
```bash
# Check GPU status
nvidia-smi  # For NVIDIA GPUs
clinfo      # For OpenCL GPUs

# Monitor GPU usage
watch -n 1 nvidia-smi

# Check FGCom GPU status via API
curl "http://localhost:8080/api/v1/gpu-resource/status"
```

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

**GPU acceleration issues:**
- **GPU not detected**: Check GPU drivers are installed and up-to-date
- **CUDA not working**: Verify CUDA Toolkit installation and NVIDIA drivers
- **OpenCL not working**: Install OpenCL runtime and drivers for your GPU
- **Performance issues**: Check GPU temperature and memory usage
- **Game conflicts**: Enable GPU resource limiting for gaming systems

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
