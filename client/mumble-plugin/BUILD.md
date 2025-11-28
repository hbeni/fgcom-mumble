# Cross-Platform Build Guide

This document describes how to build FGCom-mumble for Windows, macOS, and Linux.

## Prerequisites

### Linux
- `g++` (GNU C++ compiler)
- `make`
- `libcurl-dev` or `libcurl-devel`
- `pthread` (usually included with g++)
- Optional: `mingw-w64` for cross-compiling Windows builds

### macOS
- Xcode Command Line Tools (`xcode-select --install`)
- `g++` or `clang++`
- `make`
- `curl` (usually pre-installed)
- Universal binary support requires macOS 10.13+

### Windows (Native)
- MinGW-w64 or MSVC
- `make` (from MinGW or MSYS2)
- `curl` development libraries

### Windows (Cross-compile from Linux)
- `mingw-w64` package:
  ```bash
  sudo apt-get install mingw-w64  # Debian/Ubuntu
  sudo yum install mingw64-gcc-c++  # RHEL/CentOS
  ```

## Build Targets

### Linux (Native)

Build the plugin:
```bash
cd client/mumble-plugin
make plugin
```

Build everything (plugin + tools):
```bash
make all
```

Build in debug mode:
```bash
make debug
```

### Building Individual Modules

The codebase is organized into independent modules that can be built and tested separately:

```bash
# Build individual modules
make module-propagation    # Propagation physics, terrain, weather
make module-noise          # Atmospheric noise and noise floor
make module-audio         # Audio processing
make module-maps          # OpenInfraMap data source
make module-security      # Security and encryption (core + work unit)

# Test module integration
make plugin  # Builds everything together
```

For detailed information on the modular structure and incremental development workflow, see [MODULE_DEVELOPMENT.md](MODULE_DEVELOPMENT.md).

### macOS (Native)

Build universal binary (x86_64 + arm64):
```bash
cd client/mumble-plugin
make plugin-macOS
```

This will:
1. Build OpenSSL as universal binaries (if SSLFLAGS is set)
2. Compile the plugin with both architectures
3. Create `fgcom-mumble-macOS.bundle`

**Note**: Universal binaries require macOS 10.13 or later as minimum deployment target.

### Windows (Cross-compile from Linux)

Build 64-bit Windows plugin:
```bash
cd client/mumble-plugin
make plugin-win64
```

Build 32-bit Windows plugin:
```bash
make plugin-win32
```

Build Windows tools:
```bash
make tools-win64
```

Build everything for Windows:
```bash
make all-win
```

**Requirements**:
- `mingw-w64` must be installed
- OpenSSL will be cross-compiled automatically (if SSLFLAGS is set)
- Output: `fgcom-mumble.dll` (64-bit) or `fgcom-mumble-x86_32.dll` (32-bit)

### Windows (Native on Windows)

If building natively on Windows with MinGW:

```bash
cd client/mumble-plugin
# Set compiler
export CC=x86_64-w64-mingw32-g++-posix
# Build libraries
make libs-win64
# Build plugin
make plugin-win64-only
```

## Build Configuration

### Disable OpenSSL/Updater

To skip OpenSSL dependency and updater code:
```bash
make CFLAGS+="-DNO_UPDATER" SSLFLAGS= plugin
```

### Debug Builds

Enable debug symbols and debug code:
```bash
make DEBUG+="-g3 -DDEBUG -Og" plugin
```

Or use the convenience target:
```bash
make debug
```

### Feature Flags

Disable specific features:
- `-DNO_UDPCLIENT` - No RDF data sending thread
- `-DNO_UDPSERVER` - No UDP server thread
- `-DNO_NOTIFY` - No pluginIO notification thread
- `-DNO_GC` - No garbage collector thread
- `-DNO_CFG` - No config file parsing
- `-DNO_COMMENT` - No mumble GUI comment adjustments

Example:
```bash
make CFLAGS+="-DNO_UDPCLIENT -DNO_UDPSERVER" plugin
```

## Build Output

### Linux
- Plugin: `fgcom-mumble.so`
- Tools: `test/geotest`, `test/frqtest`

### macOS
- Plugin: `fgcom-mumble-macOS.bundle`
- Tools: `test/geotest`, `test/frqtest`

### Windows
- Plugin (64-bit): `fgcom-mumble.dll`
- Plugin (32-bit): `fgcom-mumble-x86_32.dll`
- Tools: `test/geotest.exe`, `test/frqtest.exe`

## Testing

Run unit tests:
```bash
make test
```

Run specific test suites:
```bash
make test-band-segments
make test-preset-channels
make test-terrain-compliance
```

## Cleaning

Clean object files:
```bash
make clean
```

Clean everything including binaries:
```bash
make clean-all
```

## Troubleshooting

### Windows Cross-Compilation Issues

**Problem**: `mingw-w64` not found
**Solution**: Install the package:
```bash
sudo apt-get install mingw-w64
```

**Problem**: Missing OpenSSL libraries
**Solution**: The Makefile will build OpenSSL automatically if `SSLFLAGS` is set. If you want to skip SSL:
```bash
make SSLFLAGS= plugin-win64-only
```

### macOS Universal Binary Issues

**Problem**: `lipo` command not found
**Solution**: Install Xcode Command Line Tools:
```bash
xcode-select --install
```

**Problem**: Architecture mismatch errors
**Solution**: Ensure you're using a recent enough macOS SDK. The minimum is macOS 10.13.

### Linux Build Issues

**Problem**: Missing `libcurl`
**Solution**: Install development package:
```bash
sudo apt-get install libcurl4-openssl-dev  # Debian/Ubuntu
sudo yum install libcurl-devel  # RHEL/CentOS
```

**Problem**: `pthread` errors
**Solution**: Usually included with g++, but if missing:
```bash
sudo apt-get install libpthread-stubs0-dev
```

## Architecture Support

- **Linux**: x86_64, arm64 (if cross-compiler available)
- **macOS**: x86_64, arm64 (universal binaries)
- **Windows**: x86_64, i686 (32-bit)

## Notes

- The Makefile automatically detects the compiler and uses appropriate flags
- Windows builds require `-posix` variant of mingw-w64 for proper threading support
- All builds use position-independent code (`-fPIC`) for plugin compatibility
- OpenSSL is built as a git submodule and must be initialized before building with SSL support

