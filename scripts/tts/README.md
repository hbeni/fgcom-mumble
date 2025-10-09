# FGcom-Mumble Piper TTS Integration

This directory contains scripts for integrating Piper TTS (Text-to-Speech) with FGcom-Mumble for automatic ATIS (Automatic Terminal Information Service) generation.

## Overview

The Piper TTS integration provides:
- Automatic ATIS recording generation using high-quality neural TTS
- Integration with existing FGcom-Mumble server infrastructure
- Support for multiple languages and voice models
- FGCS format compatibility for seamless playback

## Files

- `piper_tts_integration.sh` - Main shell script for TTS integration
- `install_piper.sh` - Installation script for Piper TTS
- `atis_tts_generator.py` - Python script for advanced ATIS generation
- `tts_config.conf` - Configuration file for TTS settings
- `atis_templates/` - ATIS text templates for different scenarios

## Installation

### 1. Install Piper TTS

```bash
# Run the installation script (requires sudo)
sudo ./install_piper.sh

# Or install manually:
wget https://github.com/rhasspy/piper/releases/latest/download/piper_amd64.tar.gz
tar -xzf piper_amd64.tar.gz
sudo mv piper /opt/piper/
sudo mkdir -p /opt/piper/models
```

### 2. Download Voice Models

```bash
# Download default English model
./piper_tts_integration.sh setup-model en_US-lessac-medium

# Or download other models
./piper_tts_integration.sh setup-model en_US-lessac-high
./piper_tts_integration.sh setup-model en_GB-lessac-medium
```

## Usage

### Basic ATIS Generation

```bash
# Generate ATIS for KJFK airport
./piper_tts_integration.sh airport KJFK 121.650

# Generate ATIS with specific model
./piper_tts_integration.sh airport KJFK 121.650 en_US-lessac-high
```

### Custom ATIS Text

```bash
# Generate ATIS from custom text
./piper_tts_integration.sh generate "This is KJFK information Alpha" /tmp/atis.wav

# Generate with specific voice speed
./piper_tts_integration.sh generate "This is KJFK information Alpha" /tmp/atis.wav en_US-lessac-medium 0.8
```

### Batch Generation

```bash
# Create airports configuration
./piper_tts_integration.sh create-config

# Edit the configuration file
nano /home/haaken/github-projects/fgcom-mumble-dev/server/atis_airports.csv

# Generate ATIS for all airports
./piper_tts_integration.sh batch /home/haaken/github-projects/fgcom-mumble-dev/server/atis_airports.csv
```

### Python Integration

```bash
# Generate ATIS using Python script
python3 atis_tts_generator.py KJFK --frequency 121.650 --model en_US-lessac-medium

# Generate with custom template
python3 atis_tts_generator.py KJFK --template detailed_atis.txt
```

## Configuration

Edit `tts_config.conf` to customize:

```ini
[piper]
piper_dir = /opt/piper
default_model = en_US-lessac-medium
voice_speed = 1.0

[output]
output_dir = /tmp/fgcom-atis
recordings_dir = /home/haaken/github-projects/fgcom-mumble-dev/server/recordings
audio_format = wav
sample_rate = 48000

[atis]
default_template = standard_atis.txt
update_interval = 30
weather_source = simulated
```

## ATIS Templates

The system supports multiple ATIS templates:

- `standard_atis.txt` - Standard ATIS format
- `detailed_atis.txt` - Detailed ATIS with runway information
- `emergency_atis.txt` - Emergency conditions ATIS

### Template Variables

Templates support the following variables:
- `{{AIRPORT_CODE}}` - Airport ICAO code
- `{{ATIS_LETTER}}` - Current ATIS letter (A-Z)
- `{{WIND_DIRECTION}}` - Wind direction in degrees
- `{{WIND_SPEED}}` - Wind speed in knots
- `{{VISIBILITY}}` - Visibility in miles
- `{{WEATHER_CONDITIONS}}` - Weather conditions
- `{{TEMPERATURE}}` - Temperature in Celsius
- `{{DEW_POINT}}` - Dew point in Celsius
- `{{ALTIMETER}}` - Altimeter setting
- `{{RUNWAY}}` - Active runway

## Available Voice Models

### English Models
- `en_US-lessac-medium` - US English, medium quality (default)
- `en_US-lessac-high` - US English, high quality
- `en_GB-lessac-medium` - UK English, medium quality

### Other Languages
- `de_DE-thorsten-medium` - German
- `fr_FR-siwis-medium` - French
- `es_ES-sharvard-medium` - Spanish
- `it_IT-riccardo-medium` - Italian
- `pt_BR-faber-medium` - Portuguese (Brazil)
- `nl_NL-mls-medium` - Dutch
- `pl_PL-darkman-medium` - Polish
- `ru_RU-dmitri-medium` - Russian
- `ja_JP-nanami-medium` - Japanese
- `ko_KR-kss-medium` - Korean
- `zh_CN-huihui-medium` - Chinese

## Integration with FGcom-Mumble Server

The generated ATIS files are compatible with the FGcom-Mumble server:

1. **FGCS Format**: Generated files include proper FGCS headers
2. **Directory Structure**: Files are placed in the correct server directories
3. **Playback Integration**: Compatible with existing playback bots

### Server Integration

```bash
# Generate ATIS for server
./piper_tts_integration.sh airport KJFK 121.650

# The generated files will be in:
# /home/haaken/github-projects/fgcom-mumble-dev/server/recordings/atis/KJFK/
```

## Troubleshooting

### Common Issues

1. **Piper not found**
   ```bash
   # Check installation
   ./piper_tts_integration.sh check
   
   # Reinstall if needed
   sudo ./install_piper.sh
   ```

2. **Model download fails**
   ```bash
   # Check internet connection
   wget --spider https://huggingface.co/rhasspy/piper-voices
   
   # Try manual download
   wget https://huggingface.co/rhasspy/piper-voices/resolve/v1.0.0/en_US-lessac-medium/en_US-lessac-medium.onnx
   ```

3. **Audio generation fails**
   ```bash
   # Check permissions
   ls -la /opt/piper/piper
   
   # Test manually
   echo "Test" | /opt/piper/piper --model /opt/piper/models/en_US-lessac-medium --output_file test.wav
   ```

### Performance Optimization

- Use `en_US-lessac-medium` for faster generation
- Use `en_US-lessac-high` for better quality
- Adjust `voice_speed` in configuration for different speaking rates

## Examples

### Generate ATIS for Major Airports

```bash
# Generate ATIS for multiple airports
for airport in KJFK KLAX KORD KDFW KATL; do
    ./piper_tts_integration.sh airport $airport 121.650
done
```

### Custom ATIS with Weather Data

```bash
# Generate ATIS with specific weather
./piper_tts_integration.sh standard KJFK 270 15 10 "Clear" 22 29.92 /tmp/kjfk_atis.wav
```

### Batch Processing

```bash
# Create batch configuration
cat > airports.csv << EOF
KJFK,121.650
KLAX,121.650
KORD,121.650
EOF

# Generate all ATIS
./piper_tts_integration.sh batch airports.csv
```

## Support

For issues and questions:
1. Check the troubleshooting section above
2. Review the configuration files
3. Test with simple examples first
4. Check server logs for integration issues

## License

This TTS integration is part of the FGcom-Mumble project and follows the same GPL-3.0 license.
