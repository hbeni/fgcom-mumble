# Satellite Communication Systems

## Overview

This module provides comprehensive satellite communication simulation for both military and amateur radio scenarios. It includes support for various satellite types, orbital mechanics, and communication protocols.

## Satellite Categories

### 1. Military Satellites

#### **Strela-3 Series (LEO Store-and-Forward)**
- **Satellites**: Strela-3 (multiple launches 1980s-2000s)
- **Orbit**: ~1400-1500 km circular LEO
- **Frequencies**: 150-174 MHz military VHF band
- **Use Case**: Tactical military messaging
- **TLE Available**: Yes, search "Strela-3" or "Rodnik"

#### **Tsiklon/Tsikada Navigation**
- **Satellites**: Soviet navigation satellite predecessors to GLONASS
- **Orbit**: ~1000 km circular LEO
- **Frequencies**: 150 MHz, 400 MHz beacons
- **TLE Available**: Yes

#### **FLTSATCOM Series (1970s-1980s)**
- **Satellites**: FLTSATCOM 1-8 (US Navy communications)
- **Orbit**: GEO (Geostationary)
- **Frequencies**: 240-320 MHz UHF military band
- **TLE Available**: Yes for most

### 2. Amateur Radio Satellites

#### **Linear Transponder Satellites (SSB/CW)**

**AO-7 (AMSAT-OSCAR 7) - 1974:**
- **Mode A**: 145.850-145.950 MHz up → 29.400-29.500 MHz down
- **Mode B**: 432.125-432.175 MHz up → 145.975-145.925 MHz down
- **Status**: Still operational (intermittently)
- **Orbit**: 1450 km circular LEO
- **NORAD**: 07530

**FO-29 (Fuji-OSCAR 29) - 1996:**
- **Mode JA**: 145.900-146.000 MHz up → 435.800-435.900 MHz down
- **Mode JD**: 145.900-146.000 MHz up → 435.800-435.900 MHz down (digital)
- **Orbit**: 800 km circular LEO
- **NORAD**: 24278

**AO-73 (FUNcube-1) - 2013:**
- **Linear transponder**: 145.935-145.965 MHz up → 435.150-435.180 MHz down
- **Orbit**: Sun-synchronous LEO
- **NORAD**: 39444

**XW-2 Series (Chinese CAS Satellites) - 2015:**
- **XW-2A**: 145.660-145.690 MHz up → 435.030-435.060 MHz down
- **XW-2B**: 145.725-145.775 MHz up → 435.180-435.230 MHz down
- **XW-2C**: 145.790-145.820 MHz up → 435.210-435.240 MHz down
- **XW-2D**: 145.870-145.890 MHz up → 435.345-435.365 MHz down
- **XW-2F**: 145.875-145.905 MHz up → 435.350-435.380 MHz down
- **NORAD**: 40903, 40906, 40907, 40908, 40910

**AO-92 (Fox-1D) - 2017:**
- **Linear transponder**: 435.350 MHz (145.880 MHz FM also available)
- **Orbit**: Sun-synchronous LEO
- **NORAD**: 43017

#### **FM Voice Repeater Satellites**

**SO-50 (SaudiOSCAR-50) - 2002:**
- **Uplink**: 145.850 MHz (67.0 Hz CTCSS)
- **Downlink**: 436.795 MHz
- **Mode**: FM voice repeater
- **Orbit**: 670 km circular LEO
- **NORAD**: 27607

**AO-91 (RadFxSat/Fox-1B) - 2017:**
- **Uplink**: 145.960 MHz (67.0 Hz CTCSS)
- **Downlink**: 435.250 MHz
- **Mode**: FM voice repeater
- **Orbit**: Sun-synchronous LEO
- **NORAD**: 43017

**AO-85 (Fox-1A) - 2015:**
- **Uplink**: 145.880 MHz (67.0 Hz CTCSS)
- **Downlink**: 436.800 MHz
- **Mode**: FM voice repeater
- **NORAD**: 40967

**ISS (International Space Station):**
- **Uplink**: 145.990 MHz
- **Downlink**: 145.800 MHz
- **Mode**: FM voice (when crew active) + APRS digipeater
- **Packet**: 145.825 MHz (APRS)
- **Orbit**: ~400 km LEO
- **NORAD**: 25544

**PO-101 (Diwata-2B) - 2018:**
- **Uplink**: 145.900 MHz (141.3 Hz CTCSS)
- **Downlink**: 437.500 MHz
- **NORAD**: 43678

#### **Digital/Data Mode Satellites**

**NO-84 (PSAT/BricSat-P) - 2015:**
- **Frequencies**: 435.350 MHz, 28.120 MHz
- **Modes**: PSK31, BPSK telemetry
- **NORAD**: 40654

**LilacSat-2 - 2015:**
- **Downlink**: 437.200 MHz, 437.225 MHz
- **Modes**: BPSK, GMSK, GFSK
- **NORAD**: 40908

**AO-95 (Fox-1C/RadFxSat-2) - 2018:**
- **Downlink**: 435.300 MHz (telemetry)
- **NORAD**: 43770

## Technical Features

### Orbital Mechanics
- **TLE Support**: Two-Line Element set parsing and orbital calculations
- **Visibility Calculations**: Satellite pass predictions and visibility
- **Doppler Shift**: Frequency compensation for satellite motion
- **Elevation/Azimuth**: Ground station pointing calculations

### Communication Protocols
- **Linear Transponders**: SSB/CW operation with frequency translation
- **FM Repeaters**: Voice repeaters with CTCSS access
- **Digital Modes**: PSK31, BPSK, GMSK, GFSK
- **Store-and-Forward**: Message storage and forwarding

### Frequency Management
- **Uplink/Downlink**: Separate frequency pairs for satellite communication
- **Band Plans**: 2m (144-146 MHz) and 70cm (430-440 MHz) amateur bands
- **Military Bands**: VHF (150-174 MHz) and UHF (240-320 MHz) military bands
- **Doppler Compensation**: Automatic frequency tracking

## TLE Data Sources

### Amateur Satellites
- **CelesTrak**: https://celestrak.org/NORAD/elements/amateur.txt
- **AMSAT**: https://amsat.org/tle/current/nasabare.txt
- **Space-Track**: Free registration required

### Military Satellites
- **Space-Track.org**: Register (free), search by satellite name or NORAD number
- **Search Terms**: "Molniya", "DSCS", "Strela", "FLTSATCOM", "Transit"

### Example TLE URLs
- **Amateur sats**: https://celestrak.org/NORAD/elements/gp.php?GROUP=amateur&FORMAT=tle
- **By NORAD ID**: https://celestrak.org/NORAD/elements/gp.php?CATNR=25544&FORMAT=tle (ISS example)

## Usage Examples

### Basic Satellite Communication
```cpp
#include "satellite_communication.h"

// Create satellite communication instance
SatelliteCommunication satcom;

// Initialize with ground station location
satcom.initialize(40.7128, -74.0060); // New York City

// Load TLE data
satcom.loadTLE("iss.tle");

// Get satellite pass predictions
auto passes = satcom.getPasses("ISS", 24); // Next 24 hours

// Calculate current satellite position
auto position = satcom.getSatellitePosition("ISS");

// Set up communication
satcom.setFrequency(145.990, 145.800); // Uplink, Downlink
satcom.setMode(SatelliteMode::FM_VOICE);
```

### Advanced Satellite Tracking
```cpp
// Set up satellite tracking
satcom.enableTracking(true);
satcom.setTrackingInterval(1.0); // Update every second

// Get real-time satellite data
auto elevation = satcom.getElevation("ISS");
auto azimuth = satcom.getAzimuth("ISS");
auto doppler_shift = satcom.getDopplerShift("ISS", 145.990);

// Compensate for Doppler shift
satcom.setDopplerCompensation(true);
satcom.setFrequency(145.990 + doppler_shift, 145.800);
```

## Integration with Voice Encryption

### Satellite + Voice Encryption
- **Voice Processing**: Apply voice encryption to satellite communications
- **Frequency Translation**: Handle uplink/downlink frequency pairs
- **Doppler Compensation**: Automatic frequency tracking
- **Orbital Mechanics**: Real-time satellite position calculations

### Use Cases
- **Military Communications**: Secure satellite links
- **Amateur Radio**: Satellite communication simulation
- **Emergency Communications**: Satellite-based emergency systems
- **Educational**: Satellite communication training

## Technical Advantages

### Realistic Simulation
- **Orbital Mechanics**: Accurate satellite position calculations
- **Doppler Shift**: Realistic frequency variations
- **Visibility**: Satellite pass predictions
- **Communication**: Authentic satellite communication protocols

### Educational Value
- **Satellite Tracking**: Learn orbital mechanics
- **Radio Propagation**: Understand satellite communication
- **Emergency Preparedness**: Satellite communication skills
- **Amateur Radio**: Satellite operation training

### Military Applications
- **Secure Communications**: Encrypted satellite links
- **Tactical Messaging**: Store-and-forward systems
- **Navigation**: Satellite navigation systems
- **Intelligence**: Satellite communication intelligence

## Conclusion

The satellite communication module provides comprehensive support for both military and amateur radio satellite operations. It includes realistic orbital mechanics, frequency management, and communication protocols, making it ideal for satellite communication simulation and training.

The system supports a wide range of satellite types, from Cold War military systems to modern amateur radio satellites, providing authentic simulation of satellite communication scenarios for flight simulation and educational purposes.
