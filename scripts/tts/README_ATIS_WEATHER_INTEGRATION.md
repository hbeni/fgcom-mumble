# ATIS Weather Integration System

## Overview

The ATIS Weather Integration System automatically updates ATIS (Automatic Terminal Information Service) recordings when weather conditions change significantly. This system integrates with real-time weather data APIs to monitor weather conditions and automatically regenerate ATIS recordings using the existing Piper TTS system.

## Features

### Core Functionality
- **Real-time Weather Monitoring**: Continuously monitors weather conditions for configured airports
- **Intelligent Change Detection**: Uses configurable thresholds to detect significant weather changes
- **Automatic ATIS Generation**: Generates new ATIS recordings when weather changes are detected
- **Letter Designation System**: Implements ICAO spelling alphabet (alpha, bravo, charlie, etc.) for ATIS identification
- **Weather Data Caching**: Efficiently caches and compares weather data to detect changes

### Weather Data Integration
- **Wind Speed and Direction**: Monitors wind changes with configurable thresholds
- **Visibility**: Tracks visibility changes (e.g., "10 kilometres or more (maximum)")
- **Cloud Cover**: Monitors cloud coverage percentage changes
- **Temperature**: Tracks temperature changes in Celsius
- **Dew Point**: Monitors dew point temperature changes
- **QNH (Pressure at Mean Sea Level)**: Tracks barometric pressure changes
- **QFE (Pressure at Airfield Elevation)**: Calculates airfield-specific pressure

### Change Detection Thresholds
The system triggers ATIS updates when:

#### Wind Changes
- Wind direction changes by 10 degrees or more (configurable)
- Wind speed changes by 5 knots or more (configurable)
- Gusts develop, increase, or disappear (especially if gusts exceed 10-15 knots)
- Wind shifts from calm to measurable or vice versa

#### Temperature Changes
- Temperature changes by 2-3°C (configurable)
- Significant temperature variations that affect operations

#### Pressure Changes
- Barometric pressure changes by 0.02 inches of mercury (0.68 hPa) or more
- Significant pressure variations affecting altimeter settings

#### Other Parameters
- Visibility changes by 1 km or more
- Cloud cover changes by 10% or more
- Scheduled updates at fixed intervals (default: 60 minutes)

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager
- Internet connection for weather data APIs
- Existing Piper TTS system

### Dependencies
```bash
pip install requests python-dateutil
```

### Configuration
1. Copy the configuration template:
```bash
cp atis_weather_config.json.example atis_weather_config.json
```

2. Edit the configuration file:
```json
{
  "weather_api_key": "YOUR_AVIATION_WEATHER_API_KEY_HERE",
  "airports": ["KJFK", "KLAX", "ENGM", "EGLL"],
  "thresholds": {
    "wind_direction_change_deg": 10,
    "wind_speed_change_kts": 5,
    "gust_threshold_kts": 10,
    "temperature_change_celsius": 2.0,
    "pressure_change_hpa": 0.68,
    "visibility_change_km": 1.0,
    "cloud_cover_change_percent": 10
  },
  "update_interval_minutes": 60,
  "max_age_hours": 12,
  "output_directory": "atis_recordings",
  "tts_config": {
    "voice": "en_US-lessac-medium",
    "speed": 1.0,
    "pitch": 1.0
  }
}
```

## Usage

### Manual Operation
```bash
# Test the system with a specific airport
python3 atis_weather_integration.py --test --airport KJFK

# Start monitoring all configured airports
python3 atis_weather_integration.py

# Start monitoring with custom config
python3 atis_weather_integration.py --config custom_config.json
```

### Service Operation
```bash
# Start the service
python3 atis_weather_service.py --start

# Stop the service
python3 atis_weather_service.py --stop

# Check service status
python3 atis_weather_service.py --status

# Run as daemon
python3 atis_weather_service.py --daemon
```

### Systemd Service
1. Copy the systemd service file:
```bash
sudo cp atis_weather_systemd.service /etc/systemd/system/
```

2. Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable atis-weather
sudo systemctl start atis-weather
```

3. Check service status:
```bash
sudo systemctl status atis-weather
```

## Configuration Options

### Weather API Settings
- `weather_api_key`: API key for aviation weather data
- `airports`: List of ICAO airport codes to monitor
- `weather_sources`: Primary and fallback weather data sources

### Threshold Settings
- `wind_direction_change_deg`: Wind direction change threshold (default: 10°)
- `wind_speed_change_kts`: Wind speed change threshold (default: 5 kts)
- `gust_threshold_kts`: Gust threshold for triggering updates (default: 10 kts)
- `temperature_change_celsius`: Temperature change threshold (default: 2°C)
- `pressure_change_hpa`: Pressure change threshold (default: 0.68 hPa)
- `visibility_change_km`: Visibility change threshold (default: 1 km)
- `cloud_cover_change_percent`: Cloud cover change threshold (default: 10%)

### Update Settings
- `update_interval_minutes`: Fixed update interval (default: 60 minutes)
- `max_age_hours`: Maximum age before forced update (default: 12 hours)
- `output_directory`: Directory for ATIS recordings

### TTS Settings
- `voice`: TTS voice to use
- `speed`: Speech speed multiplier
- `pitch`: Speech pitch multiplier

## ATIS Letter System

The system implements the ICAO spelling alphabet for ATIS identification:
- Letters progress through the alphabet (A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U, V, W, X, Y, Z)
- After Z, the sequence starts over at A
- Letters reset to A after a break in service of 12 hours or more
- Letter state is persisted across service restarts

## Weather Data Sources

### Primary Source: Aviation Weather API
- **URL**: https://api.aviationweather.gov
- **Data Format**: METAR (Meteorological Aerodrome Report)
- **Update Frequency**: Real-time
- **Coverage**: Global aviation weather data

### Fallback Sources
- OpenWeatherMap API
- National Weather Service API
- Local weather stations (if available)

## ATIS Text Format

The system generates ATIS text in the following format:

```
ATIS Information [LETTER] for [AIRPORT].
Wind [DIRECTION] degrees at [SPEED] knots[, gusts to [GUSTS] knots].
Visibility [VISIBILITY] kilometres[ or more].
[CLOUD COVER description].
Temperature [TEMP], dew point [DEW_POINT].
QNH [QNH], QFE [QFE].
Advise you have information [LETTER].
```

### Example ATIS Text
```
ATIS Information Alpha for KJFK.
Wind 270 degrees at 15 knots, gusts to 25 knots.
Visibility 10 kilometres or more.
Scattered clouds.
Temperature 20, dew point 15.
QNH 1013, QFE 1012.
Advise you have information Alpha.
```

## Monitoring and Logging

### Log Files
- Service logs: `logs/atis_weather_service_YYYYMMDD.log`
- Weather data logs: `logs/weather_data_YYYYMMDD.log`
- ATIS generation logs: `logs/atis_generation_YYYYMMDD.log`

### Status Monitoring
```bash
# Check service status
python3 atis_weather_service.py --status

# View recent logs
tail -f logs/atis_weather_service_$(date +%Y%m%d).log

# Check systemd service
sudo systemctl status atis-weather
```

## Testing

### Unit Tests
```bash
# Run all tests
python3 test_atis_weather_integration.py

# Run specific test class
python3 -m unittest test_atis_weather_integration.TestWeatherAPI

# Run with verbose output
python3 -m unittest -v test_atis_weather_integration
```

### Integration Tests
```bash
# Test weather data parsing
python3 atis_weather_integration.py --test --airport KJFK

# Test ATIS generation
python3 atis_weather_integration.py --test --airport ENGM
```

## Troubleshooting

### Common Issues

#### Weather Data Not Available
- Check API key configuration
- Verify internet connectivity
- Check weather service status
- Review error logs

#### ATIS Not Generating
- Verify TTS system is working
- Check output directory permissions
- Review TTS configuration
- Check disk space

#### Service Not Starting
- Check systemd service configuration
- Verify Python path and dependencies
- Check file permissions
- Review service logs

### Debug Mode
```bash
# Enable debug logging
export ATIS_DEBUG=1
python3 atis_weather_integration.py --test --airport KJFK
```

## Security Considerations

### API Key Security
- Store API keys in secure configuration files
- Use environment variables for sensitive data
- Restrict file permissions on configuration files
- Regularly rotate API keys

### Service Security
- Run service with minimal privileges
- Use systemd security settings
- Restrict network access if possible
- Monitor service logs for anomalies

## Performance Optimization

### Resource Usage
- Memory limit: 512MB (configurable)
- CPU quota: 50% (configurable)
- File descriptor limit: 65536
- Network timeout: 10 seconds

### Caching
- Weather data is cached for comparison
- Letter state is persisted across restarts
- Configuration is loaded once at startup

## Future Enhancements

### Planned Features
- Multi-language ATIS support
- Custom voice selection per airport
- Weather forecast integration
- Advanced runway selection logic
- Integration with flight planning systems

### API Improvements
- Support for additional weather sources
- Historical weather data analysis
- Weather trend prediction
- Custom weather thresholds per airport

## Support

### Documentation
- API documentation: [Weather API Docs](https://aviationweather.gov/api)
- TTS documentation: [Piper TTS Docs](https://github.com/rhasspy/piper)
- Systemd documentation: [Systemd Service Docs](https://systemd.io/)

### Community
- GitHub Issues: [FGCom-Mumble Issues](https://github.com/Supermagnum/fgcom-mumble/issues)
- Discussion Forum: [FGCom-Mumble Discussions](https://github.com/Supermagnum/fgcom-mumble/discussions)

## License

This software is part of the FGCom-Mumble project and is licensed under the same terms as the main project.

## Contributing

Contributions are welcome! Please see the main project's contributing guidelines for details on how to submit patches, report bugs, or suggest new features.
