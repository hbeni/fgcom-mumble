# Coastal Station HF Antennas

This directory contains EZNEC models for historical coastal station HF antennas used for maritime communications before the GMDSS era.

## Antenna Types

### 1. T-Type Antenna (500 kHz)
- **File**: `t_type_500khz_coastal.ez`
- **Frequency**: 500 kHz (International distress and calling frequency)
- **Configuration**: Vertical wire with horizontal top section
- **Height**: 30m above ground
- **Length**: 150m total (vertical + horizontal)
- **Power**: 2000W maximum
- **Mode**: CW only
- **Use**: International distress and calling frequency

### 2. Long Wire Antenna (2 MHz)
- **File**: `long_wire_2mhz_coastal.ez`
- **Frequency**: 1.6-4.0 MHz (Marine MF/HF-SSB radios)
- **Configuration**: Single wire stretched between masts
- **Height**: 30m above ground
- **Length**: 150m (optimized for 2 MHz)
- **Power**: 5000W maximum
- **Mode**: SSB
- **Use**: Marine MF/HF-SSB communications

### 3. Inverted-L Antenna (630m)
- **File**: `inverted_l_630m_coastal.ez`
- **Frequency**: 472-479 kHz (Maritime distress frequency)
- **Configuration**: Vertical section with horizontal top
- **Height**: 30m above ground
- **Length**: 100m total
- **Power**: 1000W maximum
- **Mode**: CW only
- **Use**: Maritime distress frequency

### 4. Long Wire Antenna (2200m)
- **File**: `long_wire_2200m_coastal.ez`
- **Frequency**: 135.7-137.8 kHz (Maritime navigation)
- **Configuration**: Very long wire between masts
- **Height**: 30m above ground
- **Length**: 400m (multiple wavelengths)
- **Power**: 2000W maximum
- **Mode**: CW only
- **Use**: Maritime navigation

## Ground System: Copper Plates in Sea Water

### North-South Orientation
- **Purpose**: Provides ground reference in North-South direction
- **Size**: 300-800m length × 50-100m width
- **Material**: Copper plates in sea water
- **Conductivity**: Enhanced by sea water

### East-West Orientation
- **Purpose**: Provides ground reference in East-West direction
- **Size**: 300-800m length × 50-100m width
- **Material**: Copper plates in sea water
- **Conductivity**: Enhanced by sea water

## Coastal Station vs Ship Antennas

### Key Differences
- **Height**: 30m above ground (vs 10m on ships)
- **Power**: Higher power handling (2000-5000W vs 100-1000W)
- **Ground System**: Copper plates in sea water (vs simple radials)
- **Tuning**: No ATU required (vs ATU required on ships)
- **Coverage**: Better coverage due to height and ground system

### Advantages of Coastal Stations
- **Better Ground**: Sea water provides excellent ground reference
- **Higher Power**: Can handle much higher power levels
- **Better Coverage**: Higher mounting height improves range
- **No ATU**: Properly tuned antennas don't need ATUs
- **Copper Plates**: Enhanced ground conductivity

## Technical Specifications

### Common Features
- **Height**: All antennas modeled at 30m above ground
- **Construction**: Heavy-duty copper wire
- **Weather Protection**: Marine-grade connections
- **Lightning Protection**: Required for all installations
- **Ground System**: Copper plates in sea water

### Performance Characteristics
- **Gain**: 4-7 dBi depending on antenna type
- **Elevation Pattern**: Very low angle radiation (2-5°)
- **Azimuth Pattern**: Omnidirectional or directional
- **SWR**: <1.5:1 (properly tuned)
- **Impedance**: 50Ω (no ATU needed)

## Historical Context

These antennas were used at coastal stations that provided:
- **International Distress**: 500 kHz was the primary emergency frequency
- **Marine Communications**: 2 MHz SSB for ship-to-shore communications
- **Navigation**: 136 kHz for maritime navigation
- **Emergency**: 472 kHz for distress communications

## Usage in FGCom-mumble

These antennas are integrated into the FGCom-mumble plugin for:
- **Historical Maritime Simulations**: Pre-GMDSS era operations
- **Amateur Radio Operations**: 630m and 2200m bands
- **Emergency Communications**: Distress and calling frequencies
- **Educational Purposes**: Understanding historical maritime communications

## File Structure

```
coastal_stations/
├── README.md                           # This file
├── t_type_500khz_coastal.ez           # T-Type antenna for 500 kHz
├── long_wire_2mhz_coastal.ez          # Long wire for 2 MHz SSB
├── inverted_l_630m_coastal.ez         # Inverted-L for 630m band
└── long_wire_2200m_coastal.ez        # Long wire for 2200m band
```

## Generation Scripts

Each antenna type has corresponding generation scripts:
- `generate_t_type_500khz_coastal_patterns.sh`
- `generate_long_wire_2mhz_coastal_patterns.sh`
- `generate_inverted_l_630m_coastal_patterns.sh`
- `generate_long_wire_2200m_coastal_patterns.sh`

These scripts automate the generation of radiation patterns for each antenna type.

## Notes

- All antennas are modeled at 30m height above ground
- Ground systems use copper plates in sea water
- No ATU requirements (properly tuned)
- Historical context is provided for educational purposes
- These antennas represent pre-GMDSS coastal station communications

