# TLE Automatic Updater Documentation

## Overview

The TLE (Two-Line Element) Automatic Updater is a comprehensive system for automatically downloading and updating satellite tracking data every 24 hours. This system ensures that satellite position calculations remain accurate by keeping TLE data current.

## Features

- **24-Hour Automatic Updates**: Downloads TLE data daily at 6:00 AM
- **Multiple Data Sources**: Supports CelesTrak, AMSAT, Space-Track, and custom URLs
- **Background Processing**: Non-blocking updates with daemon mode
- **Error Handling**: Retry logic and fallback mechanisms
- **System Integration**: Systemd service and cron job support
- **Status Monitoring**: Real-time update status tracking
- **Backup System**: Automatic TLE file backups

## Architecture

### Components

1. **TLE Updater Binary** (`tle_updater`)
   - C++ implementation with libcurl for HTTP downloads
   - Command-line interface with multiple options
   - Background daemon mode support

2. **Systemd Service** (`fgcom-tle-updater.service`)
   - System-wide service for automatic updates
   - Timer-based execution every 24 hours
   - Proper logging and error handling

3. **Cron Jobs** (`tle_update_cron`)
   - Alternative scheduling mechanism
   - User and system-wide installation options

4. **Setup Script** (`setup_tle_updater.sh`)
   - Automated installation and configuration
   - Dependency checking and build process
   - Testing and status monitoring

## Installation

### Prerequisites

- **libcurl**: For HTTP downloads
- **cmake**: For building
- **gcc/g++**: C++ compiler
- **pkg-config**: For library detection

### Quick Installation

```bash
# Build and install for current user
./scripts/satellites/setup_tle_updater.sh --user

# Build and install system-wide (requires root)
sudo ./scripts/satellites/setup_tle_updater.sh --system
```

### Manual Installation

1. **Build the TLE updater**:
   ```bash
   cd voice-encryption/systems/satellites/orbital
   mkdir build && cd build
   cmake ..
   make -j$(nproc)
   ```

2. **Install systemd service**:
   ```bash
   sudo cp ../../../../scripts/satellites/fgcom-tle-updater.service /etc/systemd/system/
   sudo cp ../../../../scripts/satellites/fgcom-tle-updater.timer /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable fgcom-tle-updater.timer
   ```

3. **Install cron job**:
   ```bash
   sudo cp ../../../../scripts/satellites/tle_update_cron /etc/cron.d/fgcom-tle-updater
   ```

## Configuration

### Default TLE Sources

The system comes pre-configured with these sources:

1. **Amateur Satellites** (Daily)
   - URL: `https://celestrak.org/NORAD/elements/amateur.txt`
   - Frequency: Daily at 6:00 AM
   - File: `amateur.tle`

2. **ISS** (Hourly)
   - URL: `https://celestrak.org/NORAD/elements/gp.php?CATNR=25544&FORMAT=tle`
   - Frequency: Hourly for critical tracking
   - File: `iss.tle`

3. **Weather Satellites** (Daily)
   - URL: `https://celestrak.org/NORAD/elements/weather.txt`
   - Frequency: Daily at 6:00 AM
   - File: `weather.tle`

4. **Military Satellites** (Weekly)
   - URL: `https://celestrak.org/NORAD/elements/military.txt`
   - Frequency: Weekly on Sunday at 2:00 AM
   - File: `military.tle`

5. **Starlink Satellites** (Daily)
   - URL: `https://celestrak.org/NORAD/elements/starlink.txt`
   - Frequency: Daily at 6:00 AM
   - File: `starlink.tle`

### Configuration File

The system uses `/home/haaken/fgcom-mumble/voice-encryption/systems/satellites/config/tle_update_config.conf` for advanced configuration.

## Usage

### Command Line Interface

```bash
# Show help
./tle_updater --help

# Force update all sources
./tle_updater --update-dir ./tle_data --log-dir ./logs --force

# Update specific source
./tle_updater --update-dir ./tle_data --log-dir ./logs --source iss --force

# Run in daemon mode
./tle_updater --update-dir ./tle_data --log-dir ./logs --daemon
```

### Systemd Service

```bash
# Start the service
sudo systemctl start fgcom-tle-updater.service

# Check status
sudo systemctl status fgcom-tle-updater.service

# View logs
sudo journalctl -u fgcom-tle-updater.service

# Enable timer (24-hour updates)
sudo systemctl enable fgcom-tle-updater.timer
sudo systemctl start fgcom-tle-updater.timer
```

### Cron Jobs

```bash
# Check cron job status
sudo systemctl status cron

# View cron logs
sudo journalctl -u cron

# Manual execution
sudo run-parts /etc/cron.d/fgcom-tle-updater
```

## Monitoring

### Status Checking

```bash
# Check TLE updater status
./scripts/satellites/setup_tle_updater.sh --status

# View downloaded TLE files
ls -la /home/haaken/fgcom-mumble/tle_data/

# Check update logs
tail -f /home/haaken/fgcom-mumble/logs/tle_updater.log
```

### Performance Metrics

The TLE updater provides performance metrics including:
- Download times
- File sizes
- Success/failure rates
- Satellite counts
- Error messages

## File Structure

```
fgcom-mumble/
├── voice-encryption/systems/satellites/orbital/
│   ├── tle_updater.h              # Header file
│   ├── tle_updater.cpp            # Implementation
│   ├── CMakeLists.txt             # Build configuration
│   └── build/                     # Build directory
├── scripts/satellites/
│   ├── setup_tle_updater.sh       # Setup script
│   ├── start_tle_updater.sh       # Control script
│   ├── backup_tle_files.sh         # Backup script
│   ├── fgcom-tle-updater.service  # Systemd service
│   ├── fgcom-tle-updater.timer    # Systemd timer
│   └── tle_update_cron            # Cron configuration
├── tle_data/                      # TLE files directory
│   ├── amateur.tle
│   ├── iss.tle
│   ├── weather.tle
│   └── ...
├── logs/                          # Log files directory
│   └── tle_updater.log
└── tle_backup/                    # Backup directory
    └── tle_backup_YYYYMMDD_HHMMSS.tar.gz
```

## Troubleshooting

### Common Issues

1. **Build Failures**
   - Ensure all dependencies are installed
   - Check that libcurl development headers are available
   - Verify cmake and compiler versions

2. **Download Failures**
   - Check internet connectivity
   - Verify TLE source URLs are accessible
   - Check firewall settings

3. **Permission Issues**
   - Ensure proper file permissions on directories
   - Check user/group ownership
   - Verify systemd service user configuration

4. **Service Not Starting**
   - Check systemd service status
   - Verify configuration file paths
   - Check log files for errors

### Debug Mode

```bash
# Enable verbose logging
./tle_updater --update-dir ./tle_data --log-dir ./logs --force --verbose

# Check systemd service logs
sudo journalctl -u fgcom-tle-updater.service -f

# Test individual sources
./tle_updater --update-dir ./tle_data --log-dir ./logs --source amateur --force
```

## Advanced Configuration

### Custom TLE Sources

To add custom TLE sources, modify the configuration file or use the API:

```cpp
// Add custom source
updater.addSource("custom", TLESource::CUSTOM_URL, 
                 UpdateFrequency::DAILY, "https://example.com/tle.txt");
```

### Update Frequencies

- `HOURLY`: Update every hour
- `DAILY`: Update every 24 hours
- `WEEKLY`: Update every 7 days
- `MANUAL`: Update only when forced

### SSL Configuration

```cpp
// Disable SSL verification (not recommended)
updater.setSSLVerification(false);

// Set custom SSL certificates
updater.setSSLVerification(true);
```

## Security Considerations

1. **SSL Verification**: Enabled by default for secure downloads
2. **File Permissions**: Proper ownership and permissions on TLE files
3. **Network Security**: HTTPS-only downloads from trusted sources
4. **Systemd Security**: Restricted permissions and sandboxing

## Performance Optimization

1. **Concurrent Downloads**: Limited to prevent system overload
2. **Caching**: TLE data cached in memory for fast access
3. **Compression**: Backup files compressed to save space
4. **Retry Logic**: Intelligent retry with exponential backoff

## Integration

The TLE updater integrates with:

- **Satellite Tracking Systems**: Provides current TLE data
- **Orbital Calculations**: SGP4/SDP4 algorithms
- **Ground Station Software**: Real-time satellite positions
- **Mission Planning**: Satellite pass predictions

## Support

For issues and questions:

1. Check the log files for error messages
2. Verify system dependencies are installed
3. Test individual TLE sources manually
4. Review systemd service configuration
5. Check network connectivity to TLE sources

## License

This TLE updater is part of the FGcom-Mumble project and follows the same licensing terms.
