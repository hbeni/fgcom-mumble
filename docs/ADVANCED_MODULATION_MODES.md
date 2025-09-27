# Advanced Modulation Modes Documentation

**FGCom-mumble v2.3+ Advanced Modulation Support**

This document describes the implementation of advanced modulation modes in FGCom-mumble, including DSB, ISB, and VSB support.

## Overview

FGCom-mumble now supports four additional modulation modes beyond the standard SSB, CW, AM, and FM:

- **DSB** (Double Sideband)
- **ISB** (Independent Sideband) 
- **VSB** (Vestigial Sideband)
- **NFM** (Narrow FM)

## Modulation Mode Details

### 1. DSB (Double Sideband)

**Technical Characteristics:**
- **Bandwidth**: 6 kHz
- **Carrier**: Suppressed (no carrier transmitted)
- **Sidebands**: Both upper and lower sidebands transmitted
- **Efficiency**: 75% power efficiency
- **Channel Spacing**: 6 kHz

**Applications:**
- Amateur radio communications
- Maritime communications
- Point-to-point links
- Educational purposes

**Frequency Ranges:**
- HF: 1.6-30 MHz
- VHF: 30-150 MHz (limited use)

**Advantages:**
- More efficient than AM
- No carrier power waste
- Simpler than SSB for some applications

**Disadvantages:**
- Less efficient than SSB
- Wider bandwidth than SSB
- Limited modern usage

### 2. ISB (Independent Sideband)

**Technical Characteristics:**
- **Bandwidth**: 6 kHz total (3 kHz upper + 3 kHz lower)
- **Carrier**: Suppressed
- **Sidebands**: Independent control of upper and lower
- **Efficiency**: 85% power efficiency
- **Channel Spacing**: 6 kHz

**Applications:**
- Amateur radio (voice + data)
- Military communications
- Telemetry systems
- Dual-purpose communications

**Frequency Ranges:**
- HF: 3-30 MHz
- VHF: 30-100 MHz (limited)

**Advantages:**
- Dual-purpose communication
- Independent sideband control
- Higher efficiency than DSB
- Flexible applications

**Disadvantages:**
- Complex implementation
- Requires careful frequency planning
- Limited modern usage

### 3. VSB (Vestigial Sideband)

**Technical Characteristics:**
- **Bandwidth**: 4 kHz
- **Carrier**: Present
- **Sidebands**: One full sideband + vestigial portion of other
- **Efficiency**: 70% power efficiency
- **Channel Spacing**: 4 kHz

**Applications:**
- Broadcast communications
- Amateur radio
- Television audio
- Specialized applications

**Frequency Ranges:**
- HF: 3-30 MHz
- VHF: 30-300 MHz

**Advantages:**
- Compromise between AM and SSB
- Carrier present for easy tuning
- Moderate bandwidth requirements

**Disadvantages:**
- Less efficient than SSB
- Carrier power waste
- Limited modern usage

### 4. NFM (Narrow FM)

**Technical Characteristics:**
- **Bandwidth**: 12.5 kHz
- **Deviation**: 2.5 kHz
- **Carrier**: Present
- **Efficiency**: 60% power efficiency
- **Channel Spacing**: 12.5 kHz

**Applications:**
- Maritime communications
- Aviation communications
- Amateur radio
- Emergency services

**Frequency Ranges:**
- VHF: 30-300 MHz
- UHF: 300-1000 MHz

**Advantages:**
- Better noise immunity than AM
- Squelch capability
- Good for voice communications
- Preemphasis available

**Disadvantages:**
- Wider bandwidth than SSB
- Less efficient than SSB
- Requires squelch for operation

## Implementation Details

### Channel Spacing

| Mode | Channel Spacing | Bandwidth | Efficiency |
|------|----------------|-----------|------------|
| **CW** | 500 Hz | 500 Hz | 100% |
| **SSB** | 3 kHz | 3 kHz | 100% |
| **AM** | 6 kHz | 6 kHz | 50% |
| **DSB** | 6 kHz | 6 kHz | 75% |
| **ISB** | 6 kHz | 6 kHz | 85% |
| **VSB** | 4 kHz | 4 kHz | 70% |
| **NFM** | 12.5 kHz | 12.5 kHz | 60% |
| **FM** | 25 kHz | 25 kHz | 50% |

### Power Efficiency Comparison

```
SSB:  ████████████████████████████████ 100%
CW:   ████████████████████████████████ 100%
ISB:  ███████████████████████████████  85%
DSB:  ███████████████████████████     75%
VSB:  █████████████████████████       70%
NFM:  ███████████████████████         60%
AM:   ███████████████████             50%
FM:   ███████████████████             50%
```

### Bandwidth Efficiency Comparison

```
SSB:  ████████████████████████████████ 100%
CW:   ████████████████████████████████ 100%
VSB:  ███████████████████████████     67%
DSB:  ███████████████████             50%
ISB:  ███████████████████             50%
AM:   ███████████████████             50%
FM:   ███████████████████             50%
```

## Configuration

### Enable Advanced Modulation Modes

```ini
[advanced_modulation]
# Enable advanced modulation modes
enable_dsb = true
enable_isb = true
enable_vsb = true

# DSB Configuration
dsb_bandwidth_hz = 6000.0
dsb_carrier_suppressed = true
dsb_power_efficiency = 0.75

# ISB Configuration
isb_upper_bandwidth_hz = 3000.0
isb_lower_bandwidth_hz = 3000.0
isb_independent_control = true

# VSB Configuration
vsb_bandwidth_hz = 4000.0
vsb_vestigial_bandwidth_hz = 1000.0
vsb_carrier_present = true
```

### Frequency Band Support

```ini
[frequency_bands]
# HF Bands supporting advanced modulation
160m_dsb = true
80m_dsb = true
40m_dsb = true
20m_dsb = true
15m_dsb = true
10m_dsb = true

# ISB support
160m_isb = true
80m_isb = true
40m_isb = true
20m_isb = true

# VSB support
160m_vsb = true
80m_vsb = true
40m_vsb = true
20m_vsb = true
15m_vsb = true
10m_vsb = true
```

## Usage Examples

### DSB Usage

```cpp
// Set up DSB radio
fgcom_amateur_radio radio;
radio.frequency = "14.200";
radio.mode = "DSB";
radio.band = "20m";
radio.power_watts = 100.0;

// DSB characteristics
double bandwidth = 6000.0; // 6 kHz
double efficiency = 0.75;   // 75% efficiency
bool carrier_suppressed = true;
```

### ISB Usage

```cpp
// Set up ISB radio
fgcom_amateur_radio radio;
radio.frequency = "7.200";
radio.mode = "ISB";
radio.band = "40m";
radio.power_watts = 100.0;

// ISB characteristics
double upper_bandwidth = 3000.0; // 3 kHz upper
double lower_bandwidth = 3000.0; // 3 kHz lower
double total_bandwidth = 6000.0;  // 6 kHz total
```

### VSB Usage

```cpp
// Set up VSB radio
fgcom_amateur_radio radio;
radio.frequency = "3.800";
radio.mode = "VSB";
radio.band = "80m";
radio.power_watts = 100.0;

// VSB characteristics
double bandwidth = 4000.0;        // 4 kHz total
double vestigial_width = 1000.0;  // 1 kHz vestigial
bool carrier_present = true;
```

## API Reference

### Advanced Modulation Functions

```cpp
// Initialize advanced modulation system
bool FGCom_AdvancedModulation::initialize();

// Check if frequency supports advanced modulation
bool FGCom_AdvancedModulation::isDSBFrequency(double frequency_khz);
bool FGCom_AdvancedModulation::isISBFrequency(double frequency_khz);
bool FGCom_AdvancedModulation::isVSBFrequency(double frequency_khz);

// Get configuration for specific mode
DSBConfig FGCom_AdvancedModulation::getDSBConfig(const std::string& application);
ISBConfig FGCom_AdvancedModulation::getISBConfig(const std::string& application);
VSBConfig FGCom_AdvancedModulation::getVSBConfig(const std::string& application);

// Calculate bandwidth and efficiency
double FGCom_AdvancedModulation::calculateDSBBandwidth(double frequency_khz);
double FGCom_AdvancedModulation::calculateISBBandwidth(double frequency_khz);
double FGCom_AdvancedModulation::calculateVSBBandwidth(double frequency_khz);

// Signal processing
double FGCom_DSBProcessor::processDSBSignal(double input_signal, const DSBConfig& config);
double FGCom_ISBProcessor::processISBUpperSignal(double input_signal, const ISBConfig& config);
double FGCom_ISBProcessor::processISBLowerSignal(double input_signal, const ISBConfig& config);
double FGCom_VSBProcessor::processVSBSignal(double input_signal, const VSBConfig& config);
```

## Testing

### Test Frequencies

**DSB Test Frequencies:**
- 14.200 MHz (20m band)
- 7.200 MHz (40m band)
- 3.800 MHz (80m band)

**ISB Test Frequencies:**
- 14.200 MHz (20m band)
- 7.200 MHz (40m band)
- 3.800 MHz (80m band)

**VSB Test Frequencies:**
- 14.200 MHz (20m band)
- 7.200 MHz (40m band)
- 3.800 MHz (80m band)

### Validation

```cpp
// Validate modulation mode
bool validateMode(const std::string& mode) {
    std::vector<std::string> valid_modes = {
        "SSB", "CW", "AM", "FM", "USB", "LSB", 
        "DSB", "ISB", "VSB", "DIGITAL", "FT8", "FT4", "PSK31", "RTTY"
    };
    // ... validation logic
}
```

## Troubleshooting

### Common Issues

1. **Mode Not Recognized**
   - Ensure mode is in uppercase
   - Check that advanced modulation is enabled
   - Verify frequency band supports the mode

2. **Channel Spacing Issues**
   - DSB/ISB: 6 kHz spacing required
   - VSB: 4 kHz spacing required
   - Check frequency alignment

3. **Power Efficiency Problems**
   - DSB: 75% efficiency expected
   - ISB: 85% efficiency expected
   - VSB: 70% efficiency expected

### Debug Information

```cpp
// Enable debug logging
pluginDbg("[Advanced Modulation] DSB mode selected");
pluginDbg("[Advanced Modulation] ISB mode selected");
pluginDbg("[Advanced Modulation] VSB mode selected");

// Check mode validation
if (validateMode(mode)) {
    pluginDbg("[Advanced Modulation] Mode " + mode + " is valid");
} else {
    pluginDbg("[Advanced Modulation] Mode " + mode + " is invalid");
}
```

## Future Enhancements

### Planned Features

1. **Digital Mode Integration**
   - FT8/FT4 support with advanced modulation
   - PSK31/PSK63 integration
   - RTTY support

2. **Advanced Signal Processing**
   - Noise reduction algorithms
   - Adaptive filtering
   - Signal enhancement

3. **Performance Optimization**
   - GPU acceleration for signal processing
   - Multi-threaded processing
   - Memory optimization

### Compatibility

- **Backward Compatible**: Existing SSB/CW/AM/FM modes unchanged
- **Forward Compatible**: New modes can be added without breaking existing functionality
- **Cross-Platform**: Works on Linux, Windows, macOS
- **Standards Compliant**: Follows ITU regulations and amateur radio standards

## License

This implementation is part of FGCom-mumble and is licensed under the GNU General Public License v3.0.

## Band Segments Reference

For detailed band segment information and frequency allocations, refer to the comprehensive band segments database:

- **Band Segments CSV**: [https://github.com/Supermagnum/Supermorse-server/blob/main/Bandplans_and_antennas/band_segments.csv](https://github.com/Supermagnum/Supermorse-server/blob/main/Bandplans_and_antennas/band_segments.csv)

This CSV file contains detailed information about:
- Frequency allocations for different regions
- Band segments for various modulation modes
- ITU region specifications
- Channel spacing requirements
- Power limits and restrictions

## Support

For technical support and questions about advanced modulation modes:

- **Documentation**: See `docs/` directory
- **API Reference**: See `docs/API_DOCUMENTATION.md`
- **Examples**: See `examples/` directory
- **Issues**: Report on GitHub repository

---

**Last Updated**: September 27, 2024  
**Version**: FGCom-mumble v2.3+  
**Author**: FGCom-mumble Development Team
