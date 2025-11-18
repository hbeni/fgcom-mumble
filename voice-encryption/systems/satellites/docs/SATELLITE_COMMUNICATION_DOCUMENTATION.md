# Satellite Communication Systems Documentation

## Overview

This document provides comprehensive documentation for the satellite communication systems implemented in the FGcom-Mumble voice encryption module. The system supports both military and amateur radio satellites with realistic orbital mechanics, frequency management, and communication protocols.

## System Architecture

### Core Components

#### 1. Satellite Communication Manager
- **Purpose**: Unified interface for all satellite operations
- **Features**: Ground station management, satellite selection, communication setup
- **Integration**: Works with all satellite types and communication modes

#### 2. TLE Support System
- **Purpose**: Two-Line Element set parsing and orbital calculations
- **Features**: SGP4/SDP4 algorithms, position calculations, visibility predictions
- **Integration**: Used by all satellite systems for orbital mechanics

#### 3. Military Satellite Systems
- **Strela-3**: LEO store-and-forward messaging
- **FLTSATCOM**: GEO military communications
- **Tsiklon**: Navigation satellite support

#### 4. Amateur Radio Satellite Systems
- **Linear Transponders**: AO-7, FO-29, AO-73, XW-2 series
- **FM Repeaters**: SO-50, AO-91, AO-85, ISS
- **Digital Modes**: NO-84, LilacSat-2, AO-95

#### 5. IoT/Data Satellite Systems
- **Orbcomm**: LEO data/IoT communications
- **Gonets**: Russian store-and-forward messaging

## Satellite Categories

### Military Satellites

#### **Strela-3 Series (LEO Store-and-Forward)**
- **Satellites**: Multiple launches 1980s-2000s
- **Orbit**: ~1400-1500 km circular LEO
- **Frequencies**: 150-174 MHz military VHF band
- **Use Case**: Tactical military messaging
- **TLE Available**: Yes, search "Strela-3" or "Rodnik"

**Features:**
- Store-and-forward messaging
- Message encryption support
- Priority-based message handling
- Tactical military communications

#### **FLTSATCOM Series (1970s-1980s)**
- **Satellites**: FLTSATCOM 1-8 (US Navy communications)
- **Orbit**: GEO (Geostationary)
- **Frequencies**: 240-320 MHz UHF military band
- **Use Case**: US Navy communications, tactical operations
- **TLE Available**: Yes for most

**Features:**
- GEO communications
- Multiple communication channels
- Voice and data transmission
- Command and control operations

#### **Tsiklon/Tsikada Navigation**
- **Satellites**: Soviet navigation satellite predecessors to GLONASS
- **Orbit**: ~1000 km circular LEO
- **Frequencies**: 150 MHz, 400 MHz beacons
- **Use Case**: Navigation and positioning
- **TLE Available**: Yes

**Features:**
- Navigation beacon transmission
- Positioning services
- Telemetry data
- Soviet navigation system

### Amateur Radio Satellites

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

### IoT/Data Satellite Systems

#### **Orbcomm (LEO Data/IoT)**
- **Frequencies**: 137-138 MHz downlink, 148-150.05 MHz uplink
- **Status**: Multiple satellites active
- **Orbit**: ~700-800 km LEO
- **Use**: Machine-to-machine communications, asset tracking, maritime
- **TLE Available**: Yes - search "Orbcomm" on Space-Track
- **NORAD Examples**: 23545, 25112, 25113, 25114, etc.

**Features:**
- M2M communications
- Asset tracking and monitoring
- Maritime communications
- IoT data transmission
- Store-and-forward messaging

#### **Gonets (Russian equivalent to Orbcomm)**
- **Frequencies**: 387-390 MHz
- **Orbit**: ~1400 km LEO
- **Use**: Store-and-forward messaging, IoT
- **TLE Available**: Yes

**Features:**
- Russian store-and-forward system
- IoT data transmission
- Telemetry services
- Emergency communications

## Technical Features

### Orbital Mechanics
- **TLE Support**: Two-Line Element set parsing and orbital calculations
- **Visibility Calculations**: Satellite pass predictions and visibility
- **Doppler Shift**: Frequency compensation for satellite motion
- **Elevation/Azimuth**: Ground station pointing calculations
- **SGP4/SDP4**: Advanced orbital calculation algorithms

### Communication Protocols
- **Linear Transponders**: SSB/CW operation with frequency translation
- **FM Repeaters**: Voice repeaters with CTCSS access
- **Digital Modes**: PSK31, BPSK, GMSK, GFSK
- **Store-and-Forward**: Message storage and forwarding
- **M2M Communications**: Machine-to-machine data exchange

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

### Military Satellite Operations
```cpp
#include "strela_3.h"

// Create Strela-3 instance
Strela3 strela;

// Initialize with ground station location
strela.initialize(40.7128, -74.0060);

// Load TLE data
strela.loadTLE("strela_3.tle");

// Send tactical message
Strela3Message message;
message.type = Strela3MessageType::TACTICAL_MESSAGE;
message.content = "Tactical message content";
strela.sendMessage(message);
```

### Amateur Radio Satellite Operations
```cpp
#include "ao_7.h"

// Create AO-7 instance
AO7 ao7;

// Initialize with ground station location
ao7.initialize(40.7128, -74.0060);

// Load TLE data
ao7.loadTLE("ao_7.tle");

// Configure for Mode A
AO7Config config;
config.mode = AO7Mode::MODE_A;
config.transponder = AO7Transponder::LINEAR_A;
ao7.configure(config);
```

### IoT/Data Satellite Operations
```cpp
#include "orbcomm.h"

// Create Orbcomm instance
Orbcomm orbcomm;

// Initialize with ground station location
orbcomm.initialize(40.7128, -74.0060);

// Load TLE data
orbcomm.loadTLE("orbcomm.tle");

// Configure for asset tracking
OrbcommConfig config;
config.service = OrbcommService::TRACKING_SERVICE;
config.tracking_enabled = true;
orbcomm.configure(config);

// Send asset tracking data
orbcomm.sendAssetTracking("ASSET001", 40.7128, -74.0060, 100.0, 
                         std::chrono::system_clock::now());
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

## Performance Characteristics

### Satellite Communication Performance

#### **LEO Satellites (AO-7, ISS, SO-50, etc.)**
- **Pass Duration**: 5-15 minutes
- **Elevation Range**: 0-90 degrees
- **Doppler Shift**: ±3-5 kHz at 145 MHz
- **Visibility**: Multiple passes per day
- **Communication**: Real-time voice/data

#### **GEO Satellites (FLTSATCOM)**
- **Pass Duration**: Continuous (24/7)
- **Elevation Range**: 0-90 degrees
- **Doppler Shift**: Minimal
- **Visibility**: Always visible (if in range)
- **Communication**: Continuous voice/data

#### **IoT Satellites (Orbcomm, Gonets)**
- **Pass Duration**: 10-20 minutes
- **Elevation Range**: 0-90 degrees
- **Doppler Shift**: ±2-4 kHz at 150 MHz
- **Visibility**: Multiple passes per day
- **Communication**: Store-and-forward data

### Frequency Management

#### **Amateur Radio Bands**
- **2m Band**: 144-146 MHz (uplink for most satellites)
- **70cm Band**: 430-440 MHz (downlink for most satellites)
- **10m Band**: 28-29 MHz (downlink for AO-7 Mode A)

#### **Military Bands**
- **VHF Military**: 150-174 MHz (Strela-3, Tsiklon)
- **UHF Military**: 240-320 MHz (FLTSATCOM)

#### **IoT Bands**
- **Orbcomm**: 137-138 MHz downlink, 148-150.05 MHz uplink
- **Gonets**: 387-390 MHz

## Conclusion

The satellite communication module provides comprehensive support for both military and amateur radio satellite operations. It includes realistic orbital mechanics, frequency management, and communication protocols, making it ideal for satellite communication simulation and training.

The system supports a wide range of satellite types, from Cold War military systems to modern amateur radio satellites, providing authentic simulation of satellite communication scenarios for flight simulation and educational purposes.

### Key Features Summary
- **Military Satellites**: Strela-3, FLTSATCOM, Tsiklon
- **Amateur Satellites**: AO-7, FO-29, AO-73, XW-2 series, SO-50, AO-91, AO-85, ISS
- **IoT Satellites**: Orbcomm, Gonets
- **Orbital Mechanics**: TLE support, SGP4/SDP4 algorithms
- **Frequency Management**: Doppler compensation, uplink/downlink pairs
- **Communication Protocols**: Linear transponders, FM repeaters, digital modes
- **Realistic Simulation**: Authentic satellite communication characteristics
