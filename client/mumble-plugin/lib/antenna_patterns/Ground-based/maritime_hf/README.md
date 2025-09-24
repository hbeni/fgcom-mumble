# Maritime HF Antennas

This directory contains EZNEC models for historical maritime HF antennas used on ships before the GMDSS era.

## Antenna Types

### 1. T-Type Antenna (500 kHz)
- **File**: `t_type_500khz.ez`
- **Frequency**: 500 kHz (International distress and calling frequency)
- **Configuration**: Vertical wire with horizontal top section
- **Height**: 10m above ground
- **Length**: 150m total (vertical + horizontal)
- **Power**: 500W maximum
- **Mode**: CW only
- **Use**: International distress and calling frequency

### 2. Long Wire Antenna (2 MHz)
- **File**: `long_wire_2mhz.ez`
- **Frequency**: 1.6-4.0 MHz (Marine MF/HF-SSB radios)
- **Configuration**: Single wire stretched between masts
- **Height**: 10m above ground
- **Length**: 75m (optimized for 2 MHz)
- **Power**: 1000W maximum
- **Mode**: SSB
- **Use**: Marine MF/HF-SSB communications

### 3. Inverted-L Antenna (630m)
- **File**: `inverted_l_630m.ez`
- **Frequency**: 472-479 kHz (Maritime distress frequency)
- **Configuration**: Vertical section with horizontal top
- **Height**: 10m above ground
- **Length**: 60m total
- **Power**: 100W maximum
- **Mode**: CW only
- **Use**: Maritime distress frequency

### 4. Long Wire Antenna (2200m)
- **File**: `long_wire_2200m.ez`
- **Frequency**: 135.7-137.8 kHz (Maritime navigation)
- **Configuration**: Very long wire between masts
- **Height**: 10m above ground
- **Length**: 200m (multiple wavelengths)
- **Power**: 200W maximum
- **Mode**: CW only
- **Use**: Maritime navigation

## Antenna Tuning Unit (ATU) Requirements

All maritime HF antennas require ATUs because:
- **Electrical Length**: Ship antennas are rarely exactly resonant
- **Impedance Matching**: 50Ω radio to various antenna impedances
- **Frequency Coverage**: Single antenna for multiple frequencies
- **Tuning Components**: Inductors and capacitors for resonance
- **Automatic Tuning**: Modern ATUs tune automatically
- **Power Handling**: Must handle full transmitter power

## Historical Context

These antennas were used on ships before the Global Maritime Distress and Safety System (GMDSS) was implemented in the 1990s-2000s. They represent the traditional maritime HF communication systems that were essential for:

- **International Distress**: 500 kHz was the primary emergency frequency
- **Marine Communications**: 2 MHz SSB for ship-to-shore communications
- **Navigation**: 136 kHz for maritime navigation
- **Emergency**: 472 kHz for distress communications

## Technical Specifications

### Common Features
- **Height**: All antennas modeled at 10m above ground
- **Construction**: Heavy-duty copper wire
- **Weather Protection**: Marine-grade connections
- **Lightning Protection**: Required for all installations
- **Ground System**: Radial systems for proper operation

### Performance Characteristics
- **Gain**: 2-5 dBi depending on antenna type
- **Elevation Pattern**: Low angle radiation (3-10°)
- **Azimuth Pattern**: Omnidirectional or directional
- **SWR**: <2:1 with proper ATU tuning
- **Impedance**: 50Ω (after ATU transformation)

## Usage in FGCom-mumble

These antennas are integrated into the FGCom-mumble plugin for:
- **Historical Maritime Simulations**: Pre-GMDSS era operations
- **Amateur Radio Operations**: 630m and 2200m bands
- **Emergency Communications**: Distress and calling frequencies
- **Educational Purposes**: Understanding historical maritime communications

## File Structure

```
maritime_hf/
├── README.md                    # This file
├── t_type_500khz.ez            # T-Type antenna for 500 kHz
├── long_wire_2mhz.ez           # Long wire for 2 MHz SSB
├── inverted_l_630m.ez          # Inverted-L for 630m band
└── long_wire_2200m.ez          # Long wire for 2200m band
```

## Generation Scripts

Each antenna type has corresponding generation scripts:
- `generate_t_type_500khz_patterns.sh`
- `generate_long_wire_2mhz_patterns.sh`
- `generate_inverted_l_630m_patterns.sh`
- `generate_long_wire_2200m_patterns.sh`

These scripts automate the generation of radiation patterns for each antenna type.

## Notes

- All antennas are modeled at 10m height above ground
- Ground systems are included for proper operation
- ATU requirements are documented for each antenna
- Historical context is provided for educational purposes
- These antennas represent pre-GMDSS maritime communications

