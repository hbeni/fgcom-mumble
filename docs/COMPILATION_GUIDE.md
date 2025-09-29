# FGCom-mumble Compilation Guide

**Complete guide for compiling FGCom-mumble from source code**

## Prerequisites

### Basic Requirements
- `git`, `make`, `g++`, `mingw32` (for windows build)
- OpenSSL: Linux builds dynamically against the installed `libssl-dev`. MingW/Windows links statically against a build from the git submodule `lib/openssl` by invoking `make openssl-win`.

### v2.0+ Additional Dependencies
- `httplib.h` (included): HTTP client for solar data, lightning data, and weather data
- `json.hpp` (included): JSON parsing for API responses and configuration
- `libcurl4-openssl-dev` (required): HTTP client library for OpenInfraMap integration
- `libjsoncpp-dev` (required): JSON parsing library for OpenInfraMap data processing
- `nec2c` (optional): NEC2 antenna simulation for pattern generation
- `python3` (required): For antenna pattern generation and coordinate transformations
- `bc` (required): For high-precision trigonometric calculations

## Linux Native Build

The makefile is optimized for Linux systems and provides the most comprehensive build options.

### Prerequisites Installation

**Ubuntu/Debian:**
```bash
# Install basic build tools
sudo apt-get update
sudo apt-get install build-essential git make g++

# Install OpenSSL development libraries
sudo apt-get install libssl-dev

# Install v2.0+ dependencies
sudo apt-get install python3 bc

# Install OpenInfraMap integration dependencies
sudo apt-get install libcurl4-openssl-dev libjsoncpp-dev

# Optional: Install NEC2 for antenna pattern generation
sudo apt-get install nec2c

# Optional: Install GPU acceleration libraries
sudo apt-get install nvidia-cuda-toolkit  # For CUDA support
sudo apt-get install opencl-headers      # For OpenCL support
```

**CentOS/RHEL/Fedora:**
```bash
# Install basic build tools
sudo yum groupinstall "Development Tools"
sudo yum install git

# Install OpenSSL development libraries
sudo yum install openssl-devel

# Install v2.0+ dependencies
sudo yum install python3 bc

# Install OpenInfraMap integration dependencies
sudo yum install libcurl-devel jsoncpp-devel

# Optional: Install NEC2 for antenna pattern generation
sudo yum install nec2c

# Optional: Install GPU acceleration libraries
sudo yum install cuda-toolkit  # For CUDA support
sudo yum install opencl-headers  # For OpenCL support
```

**Arch Linux:**
```bash
# Install basic build tools
sudo pacman -S base-devel git

# Install OpenSSL development libraries
sudo pacman -S openssl

# Install v2.0+ dependencies
sudo pacman -S python bc

# Install OpenInfraMap integration dependencies
sudo pacman -S curl jsoncpp

# Optional: Install NEC2 for antenna pattern generation
sudo pacman -S nec2c

# Optional: Install GPU acceleration libraries
sudo pacman -S cuda opencl-headers
```

### Building the Plugin

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Supermagnum/fgcom-mumble.git
   cd fgcom-mumble
   ```

2. **Build the plugin:**
   ```bash
   # Standard release build
   make plugin
   
   # Debug build (with verbose output)
   make debug
   
   # Release build with all optimizations
   make release
   ```

3. **Install the plugin:**
   ```bash
   # Copy plugin to Mumble plugins directory
   sudo cp client/mumble-plugin/fgcom-mumble.so /usr/lib/mumble/plugins/
   
   # Or for user installation
   mkdir -p ~/.local/share/mumble/plugins/
   cp client/mumble-plugin/fgcom-mumble.so ~/.local/share/mumble/plugins/
   ```

### Advanced Build Options

**Build with specific compiler:**
```bash
make plugin CC=gcc-11 CXX=g++-11
```

**Build with debug symbols:**
```bash
make debug CFLAGS="-g -O0 -DDEBUG"
```

**Build with specific OpenSSL version:**
```bash
make plugin CFLAGS="-I/usr/local/ssl/include" LDFLAGS="-L/usr/local/ssl/lib"
```

**Build with GPU acceleration:**
```bash
# Enable CUDA support
make plugin ENABLE_CUDA=1

# Enable OpenCL support  
make plugin ENABLE_OPENCL=1

# Enable both
make plugin ENABLE_CUDA=1 ENABLE_OPENCL=1
```

### Testing the Build

**Run unit tests:**
```bash
make test
```

**Run comprehensive test suite:**
```bash
make test-all
```

**Generate documentation:**
```bash
make api-docs
make user-guide
```

**Generate antenna patterns:**
```bash
make patterns
```

### Troubleshooting Linux Build Issues

**OpenSSL not found:**
```bash
# Install OpenSSL development package
sudo apt-get install libssl-dev  # Ubuntu/Debian
sudo yum install openssl-devel   # CentOS/RHEL
```

**Python3 not found:**
```bash
# Install Python 3
sudo apt-get install python3 python3-dev  # Ubuntu/Debian
sudo yum install python3 python3-devel    # CentOS/RHEL
```

**bc calculator not found:**
```bash
# Install bc calculator
sudo apt-get install bc  # Ubuntu/Debian
sudo yum install bc      # CentOS/RHEL
```

**libcurl not found:**
```bash
# Install libcurl development package
sudo apt-get install libcurl4-openssl-dev  # Ubuntu/Debian
sudo yum install libcurl-devel             # CentOS/RHEL
sudo pacman -S curl                        # Arch Linux
```

**jsoncpp not found:**
```bash
# Install jsoncpp development package
sudo apt-get install libjsoncpp-dev  # Ubuntu/Debian
sudo yum install jsoncpp-devel       # CentOS/RHEL
sudo pacman -S jsoncpp               # Arch Linux
```

**Permission denied errors:**
```bash
# Fix permissions
sudo chown -R $USER:$USER /usr/share/fgcom-mumble/
chmod +x scripts/pattern_generation/*.sh
```

**GPU acceleration not working:**
```bash
# Check CUDA installation
nvcc --version

# Check OpenCL installation
clinfo

# Install missing GPU libraries
sudo apt-get install nvidia-cuda-toolkit opencl-headers
```

## Windows Native Build

The makefile works well on Windows with cygwin64 with mingw32.  
You just need to use `x86_64-w64-mingw32-g++` instead of `x86_64-w64-mingw32-g++-posix`:

- 64bit: `make CC=x86_64-w64-mingw32-g++ plugin-win64`
- 32bit: `make CC=i686-w64-mingw32-g++ plugin-win32`

## macOS Native Build

There is an makefile alias `make plugin-macOS` that will do the following:

- You need to explicitly use the _g++-11_ compiler, as the default _g++_ is linked to _clang_. Also you need to adjust the path to the openssl distribution:  
`make -C client/mumble-plugin/ outname=fgcom-mumble-macOS.bundle CC=g++-11 CFLAGS="-I/usr/local/opt/openssl/include/ -L/usr/local/opt/openssl/lib/" plugin`

- After compilation, rename the plugin binary to `fgcom-mumble-macOS.bundle` to stay compatible with the official releases.

## ASTER GDEM Terrain Data (Optional)

For realistic terrain obstruction detection, you can download ASTER GDEM elevation data:

### Download ASTER GDEM Data

1. **Create data directory**:
   ```bash
   sudo mkdir -p /usr/share/fgcom-mumble/aster_gdem
   sudo chown $USER:$USER /usr/share/fgcom-mumble/aster_gdem
   ```

2. **Download ASTER GDEM tiles** (example for Europe):
   ```bash
   cd /usr/share/fgcom-mumble/aster_gdem
   
   # Download specific tiles (example: N50E010 for 50°N, 10°E)
   wget https://e4ftl01.cr.usgs.gov/ASTT/ASTGTM.003/2000.03.01/ASTGTM_N50E010_dem.tif
   wget https://e4ftl01.cr.usgs.gov/ASTT/ASTGTM.003/2000.03.01/ASTGTM_N50E011_dem.tif
   # ... download more tiles as needed
   ```

3. **Enable ASTER GDEM in configuration**:
   ```ini
   [terrain_elevation]
   enabled = true
   elevation_source = aster_gdem
   
   [aster_gdem]
   enabled = true
   data_path = /usr/share/fgcom-mumble/aster_gdem
   auto_download = false
   enable_obstruction_detection = true
   terrain_resolution_m = 30
   enable_fresnel_zone = true
   fresnel_clearance_percent = 0.6
   enable_diffraction = true
   ```

### ASTER GDEM Coverage

- **Global Coverage**: Available for entire Earth surface
- **Resolution**: 30 meters (1 arc-second)
- **Format**: GeoTIFF (.tif files)
- **Tile Size**: 1° x 1° (approximately 111km x 111km at equator)
- **Total Size**: ~30GB for global coverage
- **Download Source**: [NASA Earthdata](https://e4ftl01.cr.usgs.gov/ASTT/ASTGTM.003/2000.03.01/)

### Tile Naming Convention

ASTER GDEM tiles follow the pattern: `ASTGTM_N{lat}E{lon}_dem.tif`

- **N{lat}**: North latitude (e.g., N50 for 50°N)
- **E{lon}**: East longitude (e.g., E010 for 10°E)
- **Example**: `ASTGTM_N50E010_dem.tif` for 50°N, 10°E

### Regional Download Examples

**Europe (50°N-60°N, 0°E-20°E)**:
```bash
# Download tiles for Central Europe
for lat in {50..59}; do
  for lon in {0..19}; do
    wget "https://e4ftl01.cr.usgs.gov/ASTT/ASTGTM.003/2000.03.01/ASTGTM_N${lat}E$(printf "%03d" $lon)_dem.tif"
  done
done
```

**North America (30°N-50°N, 70°W-130°W)**:
```bash
# Download tiles for North America
for lat in {30..49}; do
  for lon in {70..129}; do
    wget "https://e4ftl01.cr.usgs.gov/ASTT/ASTGTM.003/2000.03.01/ASTGTM_N${lat}W$(printf "%03d" $lon)_dem.tif"
  done
done
```

### Alternative: SRTM Data

If ASTER GDEM is not available, you can use SRTM data:

1. **Download SRTM tiles** from [USGS Earth Explorer](https://earthexplorer.usgs.gov/)
2. **Convert to GeoTIFF** format
3. **Update configuration**:
   ```ini
   [terrain_elevation]
   elevation_source = srtm
   ```

## Build Targets

### Standard Targets
- `make` is an alias for `make release`
- `make release` creates release ZIP files
- `make debug` will build the plugin and add debug code that will print lots of stuff to the terminal window when running the plugin
- `make test` builds and runs catch2-unittests
- `make tools` builds some utilities and test tools

### v2.0+ New Targets
- `make patterns` generates antenna patterns using EZNEC/NEC2
- `make api-docs` generates API documentation
- `make config-examples` creates configuration file examples
- `make user-guide` generates user-friendly documentation
- `make radio-classification` generates radio era classification documentation
- `make agc-squelch` builds AGC and Squelch components
- `make test-all` runs comprehensive test suite including AGC/Squelch tests

## Cross-Compilation

### Windows Cross-Compilation
```bash
# 64-bit Windows
make CC=x86_64-w64-mingw32-g++ plugin-win64

# 32-bit Windows
make CC=i686-w64-mingw32-g++ plugin-win32
```

### macOS Cross-Compilation
```bash
make plugin-macOS
```

## Development Builds

### Debug Build
```bash
make debug
```

### Release Build
```bash
make release
```

### Custom Build
```bash
make plugin CFLAGS="-DDEBUG -g" LDFLAGS="-static"
```

## Testing

### Unit Tests
```bash
make test
```

### Integration Tests
```bash
make test-all
```

### Performance Tests
```bash
make test-performance
```

## Documentation Generation

### API Documentation
```bash
make api-docs
```

### User Guide
```bash
make user-guide
```

### Technical Documentation
```bash
make tech-docs
```

## Packaging

### Create Release Package
```bash
make release
```

### Create Debug Package
```bash
make debug-package
```

### Create Source Package
```bash
make source-package
```

## Troubleshooting

### Common Build Issues

**OpenSSL Issues:**
- Ensure OpenSSL development libraries are installed
- Check OpenSSL version compatibility
- Verify library paths

**Python Issues:**
- Ensure Python 3 is installed
- Check Python version compatibility
- Verify Python development headers

**GPU Acceleration Issues:**
- Check CUDA/OpenCL installation
- Verify driver compatibility
- Check library paths

**Permission Issues:**
- Check file permissions
- Ensure proper ownership
- Verify directory access

### Build Environment Issues

**Compiler Issues:**
- Check compiler version
- Verify compiler compatibility
- Check compiler flags

**Library Issues:**
- Check library versions
- Verify library compatibility
- Check library paths

**System Issues:**
- Check system requirements
- Verify system compatibility
- Check system resources

## Advanced Configuration

### Custom Makefile Options
```bash
# Custom compiler
make plugin CC=gcc-11 CXX=g++-11

# Custom flags
make plugin CFLAGS="-O3 -march=native" LDFLAGS="-static"

# Custom paths
make plugin CFLAGS="-I/usr/local/include" LDFLAGS="-L/usr/local/lib"
```

### Environment Variables
```bash
# Set custom paths
export OPENSSL_ROOT_DIR=/usr/local/ssl
export CUDA_ROOT_DIR=/usr/local/cuda

# Set custom flags
export CFLAGS="-O3 -march=native"
export LDFLAGS="-static"
```

## Next Steps

After successful compilation:
1. See [Installation Guide](docs/INSTALLATION_GUIDE.md) for installation
2. See [Client Usage Guide](docs/CLIENT_USAGE_GUIDE.md) for usage
3. See [Troubleshooting Guide](docs/TROUBLESHOOTING_GUIDE.md) if you encounter issues
