# ATIS Weather Integration Documentation

**Automatic ATIS recording updates based on weather conditions for airports**

## Overview

FGCom-Mumble's ATIS Weather Integration system automatically updates ATIS recordings when weather conditions change for monitored airports. This system integrates with real-time weather data APIs to detect significant weather changes and automatically regenerate ATIS recordings with updated information.

## Features

- **Real-time weather data integration** with multiple weather APIs
- **Automatic weather change detection** based on configurable thresholds
- **ATIS letter designation system** (Alpha, Bravo, Charlie, etc.)
- **Automatic ATIS recording generation** using Piper TTS
- **Multi-airport monitoring** with individual configurations
- **Weather threshold customization** for different airports
- **API fallback mechanisms** for reliability

## Configuration Examples

```json
{
  "weather_api_key": "YOUR_AVIATION_WEATHER_API_KEY_HERE",
  "airports": [
    "KJFK",
    "KLAX", 
    "ENGM",
    "EGLL"
  ],
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
  "tts_config": {
    "voice": "en_US-lessac-medium",
    "speed": 1.0,
    "pitch": 1.0
  }
}
```

## ATIS Letter System

The system implements the ICAO spelling alphabet for ATIS identification:
- **Alpha** - First update of the day
- **Bravo** - Second update  
- **Charlie** - Third update
- **Delta** - Fourth update
- **Echo** - Fifth update

The letter progresses through the alphabet with every update and resets to Alpha after 12 hours of service interruption.

## Weather Change Detection

### Wind Change Thresholds
A new ATIS is issued when:
- **Wind direction changes by 10 degrees or more**
- **Wind speed changes by 5 knots or more**
- **Gusts develop, increase, or disappear** (especially if gusts exceed 10-15 knots)

### Temperature Change Thresholds
- **Temperature change of 2-3°C** may trigger an update
- **Significant temperature trends** over time

### Pressure Change Thresholds
- **Barometric pressure changes by 0.68 hPa or more**
- **QNH changes** affecting altimeter settings

For detailed implementation and troubleshooting, see the main FGCom-Mumble documentation.
