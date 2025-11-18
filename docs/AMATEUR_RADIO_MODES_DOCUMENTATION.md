# Amateur Radio Modes Documentation

**FGCom-mumble v2.4+ Amateur Radio Mode Support**

This document describes the implementation of standard amateur radio modes in FGCom-mumble, including CW, LSB, USB, NFM, and AM support.

## Overview

FGCom-mumble now properly supports the five standard amateur radio modes used by radio amateurs worldwide:

- **CW** (Continuous Wave - Morse Code)
- **LSB** (Lower Sideband)
- **USB** (Upper Sideband)
- **NFM** (Narrow Frequency Modulation)
- **AM** (Amplitude Modulation)

## Standard Amateur Radio Modes

### CW (Continuous Wave - Morse Code)

**Technical Characteristics:**
- **Bandwidth**: 150 Hz (typical)
- **Carrier**: Present (on/off keying)
- **Efficiency**: 100% power efficiency
- **Channel Spacing**: 500 Hz
- **Modulation Index**: 1.0 (full modulation)
- **Sideband Suppression**: 0 dB (no suppression)
- **Carrier Suppression**: 0 dB (no suppression)

**Applications:**
- Amateur radio telegraphy
- Emergency communications
- Long-distance contacts
- Contest operations
- DX (long-distance) communications

**Frequency Ranges:**
- HF: 1.8-30 MHz (all bands)
- VHF: 50-54 MHz, 144-148 MHz
- UHF: 430-450 MHz

**Advantages:**
- Maximum range capability
- Excellent signal-to-noise ratio
- Simple equipment requirements
- Works in poor conditions
- 100% power efficiency
- Works with any antenna

**Disadvantages:**
- Requires Morse code knowledge
- Slower than voice communication
- Limited to text messages
- Requires CW keyer or manual keying

**Typical Usage:**
- 160m, 80m, 40m, 20m, 15m, 10m, 6m bands
- Emergency communications
- Contest operations
- DX operations

### LSB (Lower Sideband)

**Technical Characteristics:**
- **Bandwidth**: 3 kHz
- **Carrier**: Suppressed (40 dB)
- **Sideband**: Lower sideband only
- **Efficiency**: 75% power efficiency
- **Channel Spacing**: 3 kHz
- **Modulation Index**: 1.0 (full modulation)
- **Sideband Suppression**: 40 dB (upper sideband suppressed)
- **Carrier Suppression**: 40 dB (carrier suppressed)

**Applications:**
- HF amateur radio voice
- 160m, 80m, 40m bands
- Long-distance voice communication
- Emergency communications

**Frequency Ranges:**
- HF: 1.8-7.3 MHz (160m, 80m, 40m bands)

**Advantages:**
- Standard for HF voice on lower bands
- Good range capability
- Efficient power usage
- Clear audio quality
- Better than AM for voice

**Disadvantages:**
- Limited to HF bands
- Requires SSB equipment
- More complex than AM
- Requires proper frequency alignment

**Typical Usage:**
- 160m band (1.8-2.0 MHz)
- 80m band (3.5-4.0 MHz)
- 40m band (7.0-7.3 MHz)
- Emergency communications
- Long-distance voice contacts

### USB (Upper Sideband)

**Technical Characteristics:**
- **Bandwidth**: 3 kHz
- **Carrier**: Suppressed (40 dB)
- **Sideband**: Upper sideband only
- **Efficiency**: 75% power efficiency
- **Channel Spacing**: 3 kHz
- **Modulation Index**: 1.0 (full modulation)
- **Sideband Suppression**: 40 dB (lower sideband suppressed)
- **Carrier Suppression**: 40 dB (carrier suppressed)

**Applications:**
- HF amateur radio voice
- 20m, 15m, 10m, 6m bands
- VHF amateur radio
- Long-distance voice communication
- Emergency communications

**Frequency Ranges:**
- HF: 14-54 MHz (20m, 15m, 10m, 6m bands)
- VHF: 144-148 MHz (2m band)

**Advantages:**
- Standard for higher HF bands
- Good range capability
- Efficient power usage
- Clear audio quality
- Better than AM for voice

**Disadvantages:**
- Limited to specific bands
- Requires SSB equipment
- More complex than AM
- Requires proper frequency alignment

**Typical Usage:**
- 20m band (14.0-14.35 MHz)
- 15m band (21.0-21.45 MHz)
- 10m band (28.0-29.7 MHz)
- 6m band (50-54 MHz)
- 2m band (144-148 MHz)
- Emergency communications
- Long-distance voice contacts

### NFM (Narrow Frequency Modulation)

**Technical Characteristics:**
- **Bandwidth**: 12.5 kHz
- **Carrier**: Present
- **Modulation**: Frequency modulation
- **Efficiency**: 90% power efficiency
- **Channel Spacing**: 12.5 kHz
- **Modulation Index**: 0.9 (FM modulation index)
- **Sideband Suppression**: 0 dB (no suppression)
- **Carrier Suppression**: 0 dB (no suppression)

**Applications:**
- VHF/UHF amateur radio
- Repeater operations
- Local communications
- Emergency communications
- Simplex operations

**Frequency Ranges:**
- VHF: 144-148 MHz (2m band)
- UHF: 430-450 MHz (70cm band)

**Advantages:**
- Excellent audio quality
- Good for local communications
- Simple to use
- Works well with repeaters
- Good for mobile operations

**Disadvantages:**
- Limited range (line of sight)
- Requires VHF/UHF equipment
- Higher power consumption
- Not suitable for long-distance

**Typical Usage:**
- 2m band (144-148 MHz)
- 70cm band (430-450 MHz)
- Repeater operations
- Local emergency communications
- Mobile operations

### AM (Amplitude Modulation)

**Technical Characteristics:**
- **Bandwidth**: 6 kHz
- **Carrier**: Present
- **Modulation**: Amplitude modulation
- **Efficiency**: 50% power efficiency
- **Channel Spacing**: 6 kHz
- **Modulation Index**: 0.8 (AM modulation index)
- **Sideband Suppression**: 0 dB (no suppression)
- **Carrier Suppression**: 0 dB (no suppression)

**Applications:**
- HF amateur radio
- Emergency communications
- Historical compatibility
- Educational purposes
- Emergency backup

**Frequency Ranges:**
- HF: 1.8-30 MHz (all bands)

**Advantages:**
- Simple equipment
- Compatible with old radios
- Good for emergency use
- Easy to understand
- Works with any receiver

**Disadvantages:**
- Lower power efficiency
- Wider bandwidth
- Limited modern usage
- More susceptible to noise
- Less efficient than SSB

**Typical Usage:**
- Emergency communications
- Historical demonstrations
- Educational purposes
- Backup communication method
- Compatible with old equipment

## Mode Selection Guidelines

### By Frequency Band

**160m Band (1.8-2.0 MHz):**
- **LSB**: Primary voice mode
- **CW**: Telegraphy
- **AM**: Emergency backup

**80m Band (3.5-4.0 MHz):**
- **LSB**: Primary voice mode
- **CW**: Telegraphy
- **AM**: Emergency backup

**40m Band (7.0-7.3 MHz):**
- **LSB**: Primary voice mode
- **CW**: Telegraphy
- **AM**: Emergency backup

**20m Band (14.0-14.35 MHz):**
- **USB**: Primary voice mode
- **CW**: Telegraphy
- **AM**: Emergency backup

**15m Band (21.0-21.45 MHz):**
- **USB**: Primary voice mode
- **CW**: Telegraphy
- **AM**: Emergency backup

**10m Band (28.0-29.7 MHz):**
- **USB**: Primary voice mode
- **CW**: Telegraphy
- **AM**: Emergency backup

**6m Band (50-54 MHz):**
- **USB**: Primary voice mode
- **CW**: Telegraphy
- **NFM**: Local communications

**2m Band (144-148 MHz):**
- **NFM**: Primary voice mode
- **USB**: Long-distance voice
- **CW**: Telegraphy

**70cm Band (430-450 MHz):**
- **NFM**: Primary voice mode
- **CW**: Telegraphy

### By Application

**Emergency Communications:**
- **CW**: Maximum range, works in poor conditions
- **LSB/USB**: Voice communications
- **NFM**: Local emergency communications
- **AM**: Backup method

**Contest Operations:**
- **CW**: Fast, efficient
- **LSB/USB**: Voice contacts
- **NFM**: Local contacts

**DX Operations:**
- **CW**: Maximum range
- **LSB/USB**: Voice DX
- **AM**: Backup method

**Local Communications:**
- **NFM**: VHF/UHF local
- **USB**: VHF long-distance
- **CW**: Telegraphy

## Technical Implementation

### Signal Processing

Each mode has specific signal processing characteristics:

**CW Processing:**
- On/off keying detection
- Morse code decoding
- Noise filtering
- Signal strength measurement

**LSB/USB Processing:**
- Sideband filtering
- Carrier suppression
- Audio processing
- Frequency alignment

**NFM Processing:**
- Frequency demodulation
- Audio processing
- Squelch control
- Noise filtering

**AM Processing:**
- Amplitude demodulation
- Audio processing
- Carrier detection
- Noise filtering

### Power Management

**CW**: 100% efficiency - full power to antenna
**LSB/USB**: 75% efficiency - carrier suppressed
**NFM**: 90% efficiency - FM modulation
**AM**: 50% efficiency - carrier present

### Bandwidth Requirements

**CW**: 150 Hz
**LSB/USB**: 3 kHz
**NFM**: 12.5 kHz
**AM**: 6 kHz

## Configuration

### Mode Selection

The amateur radio mode can be configured in the radio model:

```cpp
fgcom_amateur_radio radio;
radio.mode = "USB";  // Set to USB for 20m band
radio.band = "20m";  // Set band
radio.power_watts = 100.0;  // Set power
```

### Supported Modes

The system validates amateur radio modes:

```cpp
std::vector<std::string> amateur_modes = {"CW", "LSB", "USB", "NFM", "AM"};
```

### Mode Validation

The system validates mode selection based on frequency band:

- **160m, 80m, 40m**: LSB, CW, AM
- **20m, 15m, 10m, 6m**: USB, CW, AM
- **2m, 70cm**: NFM, USB, CW

## Best Practices

### Mode Selection

1. **Use LSB for 160m, 80m, 40m bands**
2. **Use USB for 20m, 15m, 10m, 6m bands**
3. **Use NFM for 2m, 70cm bands**
4. **Use CW for maximum range**
5. **Use AM for emergency backup**

### Power Settings

- **CW**: Full power (100% efficiency)
- **LSB/USB**: 75% of full power
- **NFM**: 90% of full power
- **AM**: 50% of full power

### Frequency Planning

- **CW**: 500 Hz spacing
- **LSB/USB**: 3 kHz spacing
- **NFM**: 12.5 kHz spacing
- **AM**: 6 kHz spacing

## Conclusion

FGCom-mumble now properly supports all five standard amateur radio modes used by radio amateurs worldwide. The implementation includes proper signal processing, power management, and mode validation to ensure realistic amateur radio operation.

The system automatically selects the appropriate mode based on frequency band and provides proper signal characteristics for each mode, ensuring authentic amateur radio communication simulation.
