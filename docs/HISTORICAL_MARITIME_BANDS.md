# Historical Maritime HF Bands Configuration

This document explains the configuration and usage of historical maritime HF frequency bands in FGCom-mumble.

## Overview

Before the Global Maritime Distress and Safety System (GMDSS) was implemented in the 1990s-2000s, ships and coastal stations used specific HF frequency bands for maritime communications. These bands are now available to amateur radio operators as secondary allocations.

## Supported Historical Bands

### 1. 500 kHz Band (International Distress)
- **Frequency**: 500 kHz
- **Historical Use**: International distress and calling frequency
- **Primary Use**: CW (Morse code) communications
- **Emergency Status**: Primary emergency frequency until GMDSS implementation
- **Power Limit**: 500W maximum (historical maritime)
- **Mode**: CW only
- **Wavelength**: 600 meters
- **Propagation**: Ground wave dominant

### 2. 2 MHz Band (1.6-4 MHz)
- **Frequency Range**: 1.6-4.0 MHz
- **Historical Use**: Marine MF/HF-SSB radios
- **Power Limit**: 1000W maximum (historical maritime)
- **Mode**: SSB (Single Sideband)
- **Wavelength**: 150-187 meters
- **Propagation**: Ground wave and sky wave

### 3. 630 Meter Band (472-479 kHz)
- **Frequency Range**: 472-479 kHz
- **Historical Use**: Maritime distress and calling frequency
- **Amateur Allocation**: Secondary (2017 in USA)
- **Power Limit**: 100W maximum
- **Mode**: CW only
- **Wavelength**: 630 meters
- **Propagation**: Ground wave, limited sky wave

### 4. 2200 Meter Band (135.7-137.8 kHz)
- **Frequency Range**: 135.7-137.8 kHz
- **Historical Use**: Maritime navigation and communication
- **Amateur Allocation**: Secondary (2017 in USA, 1998 in UK)
- **Power Limit**: 200W maximum
- **Mode**: CW only
- **Wavelength**: 2200 meters
- **Propagation**: Ground wave dominant

## Configuration

### Enable/Disable Historical Bands

```ini
[historical_maritime_bands]
# Master switch for all historical maritime bands
enable_historical_maritime_bands = true

# Individual band controls
enable_500khz_band = true
enable_2mhz_band = true
enable_630m_band = true
enable_2200m_band = true
```

### Power Limits and Modes

```ini
# 500 kHz band settings
500khz_power_limit_watts = 500
500khz_mode = CW
500khz_historical_use = "International distress and calling frequency"
500khz_primary_until_gmdss = true

# 2 MHz band settings
2mhz_power_limit_watts = 1000
2mhz_mode = SSB
2mhz_frequency_range = "1.6-4.0 MHz"
2mhz_historical_use = "Marine MF/HF-SSB radios"

# 630m band settings
630m_power_limit_watts = 100
630m_mode = CW
630m_secondary_allocation = true

# 2200m band settings
2200m_power_limit_watts = 200
2200m_mode = CW
2200m_secondary_allocation = true
```

### Interference Protection

```ini
# Interference protection settings
protect_primary_services = true
automatic_power_reduction = true
interference_monitoring = true
```

## Antenna Types

### Maritime Vessels (Ships)
- **T-Type Antenna**: 500 kHz distress frequency
- **Long Wire Antenna**: 2 MHz SSB communications
- **Inverted-L Antenna**: 630m maritime distress
- **Long Wire Antenna**: 2200m navigation
- **Height**: 10m above ground
- **Power**: 100-1000W
- **ATU Required**: Yes (electrical length tuning)

### Coastal Stations
- **T-Type Antenna**: 500 kHz distress frequency
- **Long Wire Antenna**: 2 MHz SSB communications
- **Inverted-L Antenna**: 630m maritime distress
- **Long Wire Antenna**: 2200m navigation
- **Height**: 30m above ground
- **Power**: 1000-5000W
- **Ground System**: Copper plates in sea water
- **ATU Required**: No (properly tuned)

## Usage Examples

### Maritime Vessel Configuration

```json
{
  "vehicle_id": "SS_MARITIME_HISTORIC",
  "antennas": [
    {
      "antenna_id": "distress_500khz",
      "antenna_type": "t_type_wire",
      "frequency_range": "500 kHz",
      "power": "500W",
      "mode": "CW",
      "historical_use": "International distress and calling frequency"
    },
    {
      "antenna_id": "marine_2mhz_ssb",
      "antenna_type": "long_wire",
      "frequency_range": "1.6-4.0 MHz",
      "power": "1000W",
      "mode": "SSB",
      "historical_use": "Marine MF/HF-SSB radios"
    }
  ]
}
```

### Coastal Station Configuration

```json
{
  "vehicle_id": "COASTAL_STATION_HISTORIC",
  "antennas": [
    {
      "antenna_id": "distress_500khz_coastal",
      "antenna_type": "t_type_wire",
      "frequency_range": "500 kHz",
      "power": "2000W",
      "mode": "CW",
      "ground_system": "copper_plates_sea_water"
    }
  ]
}
```

## Why You Might Want to Disable These Bands

### Reasons to Disable Historical Maritime Bands:

1. **Interference Concerns**:
   - These bands are secondary allocations
   - Primary services have priority
   - Risk of interfering with maritime services

2. **Regulatory Compliance**:
   - Some regions may restrict these bands
   - Power limits may be lower than configured
   - Mode restrictions may apply

3. **Technical Limitations**:
   - Very long wavelengths require large antennas
   - Ground wave propagation limits range
   - High noise levels at low frequencies

4. **Operational Considerations**:
   - Limited practical use for most amateur operations
   - Specialized equipment requirements
   - Higher power consumption

### Reasons to Enable Historical Maritime Bands:

1. **Historical Education**:
   - Understanding pre-GMDSS maritime communications
   - Learning about historical radio operations
   - Educational simulations

2. **Specialized Operations**:
   - Maritime emergency communications
   - Historical reenactments
   - Educational demonstrations

3. **Technical Challenge**:
   - Working with very low frequencies
   - Understanding ground wave propagation
   - Learning about maritime antenna systems

## Implementation Notes

- All historical maritime bands are **secondary allocations**
- **Primary services** have priority and must be protected
- **Power limits** are strictly enforced
- **Mode restrictions** apply (CW only for most bands)
- **Interference monitoring** is recommended
- **Automatic power reduction** may be triggered

## File Locations

- **EZNEC Models**: `/client/mumble-plugin/lib/antenna_patterns/Ground-based/maritime_hf/`
- **Coastal Station Models**: `/client/mumble-plugin/lib/antenna_patterns/Ground-based/coastal_stations/`
- **Generation Scripts**: `/client/mumble-plugin/lib/generate_maritime_hf_patterns.sh`
- **Configuration**: `config/fgcom-mumble.conf.example`

## References

- ITU Radio Regulations
- Amateur Radio Service Rules
- Historical Maritime Communications
- GMDSS Implementation History
- International Distress Frequencies

