# Configuration Files Directory

This directory contains all configuration files for the FGcom-Mumble project, organized by functionality and purpose.

## Configuration Files Overview

### Core Configuration Files

#### `fgcom-mumble.conf.example`
**Purpose**: Main configuration file template with all available options and examples.

**Features**:
- Complete configuration template
- All available options documented
- Example values provided
- Comments explaining each option
- Best practices included

**Usage**:
```bash
# Copy template to create your configuration
cp configs/fgcom-mumble.conf.example ~/.fgcom-mumble.ini

# Edit with your settings
nano ~/.fgcom-mumble.ini
```

#### `fgcom-mumble.conf.minimal`
**Purpose**: Minimal configuration file with only essential settings.

**Features**:
- Essential settings only
- Minimal setup required
- Quick start configuration
- Basic functionality enabled
- Simplified options

**Usage**:
```bash
# Use minimal configuration for quick setup
cp configs/fgcom-mumble.conf.minimal ~/.fgcom-mumble.ini
```

#### `fgcom-mumble.ini`
**Purpose**: Standard INI format configuration file.

**Features**:
- INI format configuration
- Section-based organization
- Easy to read and edit
- Standard format support
- Cross-platform compatibility

### Specialized Configuration Files

#### `band_plan_custom.json`
**Purpose**: Custom frequency band plan configuration for specific regions or use cases.

**Features**:
- Custom frequency allocations
- Regional band plans
- Specialized frequency ranges
- Regulatory compliance
- Custom channel definitions

**Usage**:
```json
{
  "band_plan": "custom",
  "regions": ["US", "EU", "UK"],
  "frequencies": {
    "aviation": {
      "vhf_civil": "118.000-137.000",
      "vhf_military": "225.000-400.000"
    },
    "amateur": {
      "2m": "144.000-148.000",
      "70cm": "420.000-450.000"
    }
  }
}
```

#### `debugging.conf`
**Purpose**: Debugging and diagnostic configuration settings.

**Features**:
- Debug level settings
- Logging configuration
- Diagnostic options
- Performance monitoring
- Error reporting

**Usage**:
```ini
[debug]
debug_level = 2
log_file = logs/debug.log
verbose_output = true
performance_monitoring = true
```

#### `env.template`
**Purpose**: Environment variables template for secure credential management.

**Features**:
- Environment variable templates
- Security best practices
- Credential management
- API key configuration
- Database settings

**Usage**:
```bash
# Copy template
cp configs/env.template .env

# Edit with your credentials
nano .env

# Load environment variables
source .env
```

#### `feature_toggles.conf`
**Purpose**: Comprehensive feature toggle configuration for enabling/disabling specific features across 17 categories. Controls 107+ configurable features including API endpoints, external data sources, noise analysis, ATIS integration, and GPU scaling.

**Documentation**: See [Feature Toggle System](../docs/FEATURE_TOGGLE_SYSTEM.md) and [Feature Toggle API Control](../docs/FEATURE_TOGGLE_API_CONTROL.md) for detailed information.

**Configuration Sections**:

##### `[feature_toggles]` - Core System Features
- **Core Features**: Radio communication, terrain analysis, antenna patterns, propagation modeling
- **Advanced Features**: GPU acceleration, distributed computing, EME calculations, solar data integration
- **Audio Features**: Audio effects, noise reduction, AGC squelch, frequency offset
- **Network Features**: UDP communication, WebSocket API, REST API, secure communication
- **API Endpoint Control**: Read/write controls for solar, weather, propagation, and antenna APIs
- **Debugging Features**: Debug logging, performance monitoring, memory tracking, thread monitoring (default: `false`)
- **Experimental Features**: Experimental propagation, audio, networking, GPU features (default: `false`)

##### `[radio_features]` - Radio Communication Types
Controls which radio frequency bands and communication types are enabled:
- VHF, UHF, HF communication
- Amateur, military, aviation, maritime radio
- **Default**: All enabled (`true`)

##### `[antenna_features]` - Antenna Types
Controls which antenna pattern types are supported:
- Yagi, dipole, vertical, beam, parabolic antennas
- **Default**: All enabled (`true`)

##### `[propagation_features]` - Propagation Models
Controls which radio propagation models are active:
- Line of sight, tropospheric ducting, ionospheric propagation, ground wave, sky wave
- **Default**: All enabled (`true`)

##### `[audio_features]` - Audio Processing
Controls audio processing capabilities:
- Doppler shift, audio compression, enhancement, filtering
- **Default**: All enabled (`true`)

##### `[network_features]` - Network Protocols
Controls network communication protocols:
- UDP/TCP server/client, WebSocket server/client
- **Default**: All enabled (`true`)

##### `[security_features]` - Security Controls
Controls security features:
- Authentication, encryption, certificate validation, threat detection
- **Default**: All enabled (`true`)

##### `[monitoring_features]` - System Monitoring
Controls monitoring and statistics collection:
- Signal monitoring, performance monitoring, error monitoring, statistics collection
- **Default**: All enabled (`true`)

##### `[api_endpoint_features]` - API Endpoint Controls
**IMPORTANT**: Most API endpoints are **disabled by default** (`false`) for security.

**Solar Data API Controls** (default: `false`):
- `enable_solar_data_get_current` - GET current solar data
- `enable_solar_data_get_history` - GET solar data history
- `enable_solar_data_get_forecast` - GET solar data forecast
- `enable_solar_data_post_submit` - POST submit solar data
- `enable_solar_data_post_batch_submit` - POST batch submit solar data
- `enable_solar_data_put_update` - PUT update solar data

**Weather Data API Controls** (default: `false`):
- `enable_weather_data_get_current` - GET current weather data
- `enable_weather_data_get_history` - GET weather data history
- `enable_weather_data_get_forecast` - GET weather forecast
- `enable_weather_data_post_submit` - POST submit weather data
- `enable_weather_data_post_batch_submit` - POST batch submit weather data
- `enable_weather_data_put_update` - PUT update weather data

**Lightning Data API Controls** (default: `false`):
- `enable_lightning_data_get_current` - GET current lightning data
- `enable_lightning_data_get_strikes` - GET lightning strikes
- `enable_lightning_data_post_submit` - POST submit lightning data
- `enable_lightning_data_post_batch_submit` - POST batch submit lightning data

**External Data Source Controls** (default: `false`):
- `enable_external_solar_data_sources` - Master toggle for external solar data
- `enable_external_weather_data_sources` - Master toggle for external weather data
- `enable_noaa_solar_data` - NOAA solar data fetching
- `enable_noaa_weather_data` - NOAA weather data fetching
- `enable_openweather_api` - OpenWeather API integration
- `enable_weather_gov_api` - Weather.gov API integration
- `enable_noaa_swpc` - NOAA Space Weather Prediction Center
- `enable_nasa_space_weather` - NASA space weather data
- `enable_openweathermap_api` - OpenWeatherMap API
- `enable_aster_gdem` - ASTER GDEM elevation data
- `enable_usgs_ned` - USGS National Elevation Dataset
- `enable_ionospheric_data` - Real-time ionospheric data
- `enable_wwlln_lightning` - World Wide Lightning Location Network
- `enable_vaisala_lightning` - Vaisala Global Lightning Dataset

**Note**: External data sources require API keys configured via environment variables (see `[external_data_credentials]` section).

##### `[data_source_features]` - Data Source Behavior
Controls how data is fetched and submitted:
- `enable_solar_data_external_fetch` - Fetch solar data from external sources (default: `true`)
- `enable_weather_data_external_fetch` - Fetch weather data from external sources (default: `true`)
- `enable_solar_data_game_submission` - Allow game clients to submit solar data (default: `true`)
- `enable_weather_data_game_submission` - Allow game clients to submit weather data (default: `true`)

**Note**: When game submission is enabled, external fetching should typically be disabled to avoid conflicts.

##### `[noise_analysis_features]` - Noise Floor Analysis
Controls noise floor calculation features:
- **Basic Noise** (default: `true`): Atmospheric noise, lightning noise, solar noise, environmental noise
- **Advanced Noise** (default: `false`): Power line analysis, traffic analysis, industrial analysis, EV charging analysis, substation analysis, power station analysis, OpenInfraMap integration

**Note**: Advanced noise features require external data sources and may need API keys.

##### `[external_data_credentials]` - API Credentials
**Security Note**: Credentials should be set via environment variables, not in config files.

All credentials use environment variable substitution:
- NOAA SWPC: `NOAA_SWPC_API_KEY`, `NOAA_SWPC_USERNAME`, `NOAA_SWPC_PASSWORD`
- NASA: `NASA_API_KEY`, `NASA_USERNAME`, `NASA_PASSWORD`
- OpenWeatherMap: `OPENWEATHERMAP_API_KEY`, `OPENWEATHERMAP_USERNAME`, `OPENWEATHERMAP_PASSWORD`
- NOAA Weather: `NOAA_WEATHER_API_KEY`, `NOAA_WEATHER_USERNAME`, `NOAA_WEATHER_PASSWORD`
- ASTER GDEM: `ASTER_USERNAME`, `ASTER_PASSWORD`
- USGS NED: `USGS_API_KEY`, `USGS_USERNAME`, `USGS_PASSWORD`
- Ionospheric Data: `IONOSPHERIC_API_KEY`, `IONOSPHERIC_USERNAME`, `IONOSPHERIC_PASSWORD`
- WWLLN: `WWLLN_USERNAME`, `WWLLN_PASSWORD`
- Vaisala: `VAISALA_API_KEY`, `VAISALA_USERNAME`, `VAISALA_PASSWORD`

##### `[atis_weather_integration_features]` - ATIS Weather Integration
Controls ATIS (Automatic Terminal Information Service) weather monitoring and generation:
- **Core Features** (default: `true`): Weather monitoring, automatic ATIS generation, letter system, pressure correction, runway detection, gust detection, visibility/cloud/temperature/wind/dew point monitoring, QNH/QFE monitoring
- **Notifications** (default: `false`): ATIS notifications, webhook notifications, email notifications
- **Debugging** (default: `false`): Debug logging, verbose logging
- **System Features** (default: `true`): Performance monitoring, error recovery, fallback APIs, caching, persistence

##### `[atis_weather_api_features]` - ATIS Weather API Integration
Controls which weather APIs are used for ATIS:
- **Core APIs** (default: `true`): Aviation weather API, OpenWeatherMap API, Weather.gov API, METAR data fetching
- **Extended Features** (default: `false`): TAF data fetching, weather forecast, historical weather, weather alerts

##### `[atis_weather_threshold_features]` - ATIS Weather Thresholds
Controls which weather parameters trigger ATIS updates:
- All monitoring features enabled by default (`true`): Wind direction/speed, gusts, temperature, pressure, visibility, cloud cover, dew point, runway change detection, active runway detection

##### `[atis_weather_tts_features]` - ATIS Text-to-Speech
Controls ATIS voice synthesis:
- **Core TTS** (default: `true`): Piper TTS integration, voice selection, speed control, pitch control, audio quality control
- **Advanced TTS** (default: `false`): Multilingual support, voice customization

##### `[dynamic_gpu_scaling_features]` - Dynamic GPU Scaling
Controls GPU resource management for high user loads (up to 200 users):
- All features enabled by default (`true`): Dynamic GPU scaling, auto GPU allocation, network GPU sharing, load balancing, fallback, performance monitoring, utilization tracking, health checking, scaling thresholds, high load management, bandwidth monitoring, latency monitoring, reliability tracking, adaptive scaling, GPU pool management

**Usage Examples**:

**Minimal Configuration** (disable all external APIs):
```ini
[api_endpoint_features]
# All API endpoints disabled by default
enable_solar_data_get_current = false
enable_weather_data_get_current = false
enable_external_solar_data_sources = false
enable_external_weather_data_sources = false
```

**Enable Read-Only APIs**:
```ini
[api_endpoint_features]
# Enable read operations only
enable_solar_data_get_current = true
enable_solar_data_get_history = true
enable_weather_data_get_current = true
enable_weather_data_get_history = true
# Keep write operations disabled
enable_solar_data_post_submit = false
enable_weather_data_post_submit = false
```

**Enable External Data Sources**:
```ini
[api_endpoint_features]
enable_external_solar_data_sources = true
enable_external_weather_data_sources = true
enable_noaa_solar_data = true
enable_noaa_weather_data = true
enable_openweather_api = true

[external_data_credentials]
# Set these via environment variables:
# export NOAA_API_KEY="your_key"
# export OPENWEATHER_API_KEY="your_key"
```

**Enable Advanced Noise Analysis**:
```ini
[noise_analysis_features]
enable_ev_charging_analysis = true
enable_substation_analysis = true
enable_power_station_analysis = true
enable_openinframap_integration = true
```

**Related Documentation**:
- [Feature Toggle System Documentation](../docs/FEATURE_TOGGLE_SYSTEM.md) - Complete system overview
- [Feature Toggle API Control](../docs/FEATURE_TOGGLE_API_CONTROL.md) - API endpoint control details
- [Installation Guide](../docs/INSTALLATION_GUIDE.md) - Setup instructions

#### `frequency_offset.conf`
**Purpose**: Frequency offset configuration for calibration and adjustment.

**Features**:
- Frequency offset settings
- Calibration parameters
- Adjustment factors
- Regional variations
- Equipment-specific settings

**Usage**:
```ini
[frequency_offsets]
default_offset = 0.0
regional_offsets = {
  "US": 0.0,
  "EU": 0.0,
  "UK": 0.0
}
equipment_offsets = {
  "radio_1": 0.1,
  "radio_2": -0.1
}
```

#### `gpu_acceleration.conf`
**Purpose**: GPU acceleration configuration for high-performance computing.

**Features**:
- GPU acceleration settings
- CUDA configuration
- OpenCL settings
- Performance optimization
- Resource management

**Usage**:
```ini
[gpu_acceleration]
enabled = true
cuda_enabled = true
opencl_enabled = true
max_gpu_memory = 8GB
parallel_jobs = 8
```

#### `power_management.conf`
**Purpose**: Power management configuration for energy efficiency.

**Features**:
- Power management settings
- Energy efficiency options
- Thermal management
- Performance scaling
- Resource optimization

**Usage**:
```ini
[power_management]
enabled = true
thermal_throttling = true
performance_scaling = true
energy_efficiency = true
max_cpu_usage = 80
```

#### `radio_amateur_band_segments.csv`
**Purpose**: CSV file containing amateur radio band segment definitions.

**Features**:
- Amateur radio band segments
- Frequency allocations
- Mode definitions
- Power limits
- Regulatory information

**Usage**:
```csv
Band,Start_Freq,End_Freq,Mode,Power_Limit,Notes
2m,144.000,148.000,FM,50W,Primary 2m band
70cm,420.000,450.000,FM,50W,Primary 70cm band
```

#### `satellite_config.conf`
**Purpose**: Satellite communication configuration settings.

**Features**:
- Satellite tracking settings
- TLE data configuration
- Communication parameters
- Orbital mechanics
- Ground station settings

**Usage**:
```ini
[satellites]
tle_update_interval = 3600
max_satellites = 100
tracking_enabled = true
ground_stations = {
  "station_1": "40.7128,-74.0060",
  "station_2": "34.0522,-118.2437"
}
```

#### `server_statuspage_config.dist.ini`
**Purpose**: Server status page configuration template.

**Features**:
- Status page settings
- Monitoring configuration
- Alert settings
- Display options
- Update intervals

**Usage**:
```ini
[status_page]
enabled = true
update_interval = 30
show_uptime = true
show_users = true
show_performance = true
```

#### `statuspage_config.dist.ini`
**Purpose**: Status page configuration for system monitoring.

**Features**:
- System monitoring settings
- Status indicators
- Performance metrics
- Health checks
- Alert configuration

**Usage**:
```ini
[monitoring]
enabled = true
check_interval = 60
alert_threshold = 80
notification_email = admin@example.com
```

#### `threading_config.conf`
**Purpose**: Threading and concurrency configuration.

**Features**:
- Thread pool settings
- Concurrency limits
- Performance tuning
- Resource management
- Scalability options

**Usage**:
```ini
[threading]
max_threads = 20
thread_pool_size = 10
concurrency_limit = 100
performance_mode = true
```

## Configuration Management

### Environment Variables
```bash
# Load environment variables
source .env

# Check configuration
./scripts/setup_configuration.sh --check

# Validate configuration
./scripts/setup_configuration.sh --validate
```

### Configuration Validation
```bash
# Validate all configurations
./scripts/validation/validate_configs.sh

# Check specific configuration
./scripts/validation/validate_configs.sh --config fgcom-mumble.conf
```

### Configuration Updates
```bash
# Update configuration
./scripts/setup_configuration.sh --update

# Backup configuration
./scripts/setup_configuration.sh --backup

# Restore configuration
./scripts/setup_configuration.sh --restore
```

## Best Practices

### Configuration Security
1. **Never commit credentials**: Use environment variables
2. **Secure file permissions**: Restrict access to config files
3. **Regular backups**: Backup configuration files
4. **Version control**: Track configuration changes
5. **Documentation**: Document configuration changes

### Configuration Management
1. **Template usage**: Use templates for new configurations
2. **Validation**: Validate configurations before deployment
3. **Testing**: Test configurations in development
4. **Monitoring**: Monitor configuration changes
5. **Rollback**: Maintain rollback capabilities

## Troubleshooting

### Common Issues

1. **Configuration not found**
   ```bash
   # Check configuration file location
   ls -la ~/.fgcom-mumble.ini
   # Copy template if missing
   cp configs/fgcom-mumble.conf.example ~/.fgcom-mumble.ini
   ```

2. **Invalid configuration**
   ```bash
   # Validate configuration
   ./scripts/validation/validate_configs.sh
   # Check syntax
   ./scripts/validation/validate_configs.sh --syntax-check
   ```

3. **Environment variables not loaded**
   ```bash
   # Check environment variables
   env | grep FGCOM
   # Load environment file
   source .env
   ```

### Debugging

1. **Verbose output**
   ```bash
   # Enable verbose configuration loading
   export FGCOM_DEBUG=1
   ./scripts/setup_configuration.sh
   ```

2. **Configuration logging**
   ```bash
   # Check configuration logs
   tail -f logs/configuration.log
   ```

3. **Validation reports**
   ```bash
   # Generate validation report
   ./scripts/validation/validate_configs.sh --report
   ```

## Integration

### With Development Workflow
```bash
# Pre-commit configuration validation
./scripts/validation/validate_configs.sh --pre-commit

# Post-build configuration check
./scripts/setup_configuration.sh --post-build
```

### With CI/CD
```bash
# CI configuration validation
./scripts/validation/validate_configs.sh --ci-mode

# Automated configuration setup
./scripts/setup_configuration.sh --automated
```

## Future Enhancements

- Configuration management UI
- Dynamic configuration updates
- Configuration versioning
- Advanced validation rules
- Configuration templates

## Support

For configuration issues:
1. Check configuration files in `configs/`
2. Review environment variables
3. Validate configuration syntax
4. Check log files
5. Review documentation
