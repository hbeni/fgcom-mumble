# Dual-Band VHF/UHF Omnidirectional Antenna (2m/70cm)

## Overview

This directory contains the EZNEC model and radiation patterns for a high-performance dual-band omnidirectional antenna designed for both the 2m (144-146 MHz) and 70cm (430-440 MHz) amateur radio bands. This antenna is suitable for professional base station and repeater applications requiring omnidirectional coverage with good gain on both bands.

## Antenna Specifications

### **Physical Characteristics**
- **Type**: Dual-band collinear omnidirectional antenna
- **VHF Range**: 144.0 - 146.0 MHz (2m amateur band)
- **UHF Range**: 430.0 - 440.0 MHz (70cm amateur band)
- **Total Length**: 5.2m
- **Height**: 10m above ground
- **Polarization**: Vertical
- **Pattern**: Omnidirectional (360°)
- **Max Power**: 200W
- **Weight**: 2.5 kg

### **Performance Specifications**
- **VHF Gain**: 8.3 dBi @ 144 MHz
- **UHF Gain**: 11.7 dBi @ 432 MHz
- **SWR**: <1.5:1 across both bands
- **Impedance**: 50Ω
- **Elevation Angle**: ~10-15° (VHF), ~5-8° (UHF)

## Antenna Design

### **Collinear Array Configuration**
The antenna uses a collinear array design with separate radiating sections for each band:

#### **2m Band Section (144-146 MHz)**
- **Elements**: Two λ/2 collinear elements
- **Phasing**: Quarter-wave phasing stub between elements
- **Gain**: 8.3 dBi omnidirectional
- **Elevation Pattern**: ~10-15° (good for local/regional coverage)
- **Effective Aperture**: ~2λ collinear

#### **70cm Band Section (430-440 MHz)**
- **Elements**: Four λ/2 collinear elements
- **Phasing**: Quarter-wave phasing stubs between elements
- **Gain**: 11.7 dBi omnidirectional
- **Elevation Pattern**: ~5-8° (excellent for long distance)
- **Effective Aperture**: ~6λ collinear

### **Ground Plane System**
- **Radials**: Four λ/4 radials at 145 MHz (51cm length)
- **Purpose**: Provides proper ground reference
- **Pattern**: Ensures omnidirectional coverage
- **Optimization**: Works for both bands

### **Matching System**
- **Impedance**: Internal 50Ω impedance matching
- **Design**: Broadband design covers both amateur bands
- **SWR**: Low SWR across entire frequency ranges
- **Power Handling**: 200W capability

## EZNEC Model Features

### **Model Components**
- **Mounting Mast**: Steel mounting structure (non-radiating)
- **2m Band Elements**: Two λ/2 collinear elements with phasing stub
- **70cm Band Elements**: Four λ/2 collinear elements with phasing stubs
- **Ground Plane**: Four λ/4 radials for omnidirectional pattern
- **Matching Network**: Internal 50Ω impedance matching

### **Source Configuration**
- **Feed Point**: Base through matching network
- **Impedance**: 50Ω (internal matching)
- **Power Handling**: 200W maximum

### **Load Conditions**
- **Mounting Mast**: Steel construction (1E+06 S/m)
- **Antenna Elements**: Aluminum construction (3.7E+07 S/m)
- **Matching Network**: 50Ω impedance transformer

## Radiation Patterns

### **Pattern Generation**
The antenna patterns are generated for:
- **VHF Frequencies**: 144.0, 144.1, 144.2, ..., 146.0 MHz (21 frequencies)
- **UHF Frequencies**: 430.0, 430.5, 431.0, ..., 440.0 MHz (21 frequencies)
- **Altitudes**: 0, 100, 500, 1000, 2000m above ground
- **Total Patterns**: 210 pattern files (42 frequencies × 5 altitudes)

### **Pattern Characteristics**
- **Azimuth Pattern**: True omnidirectional (±1 dB)
- **Elevation Pattern**: Low angle for both bands
- **Ground Effects**: Minimal at 10m height
- **Consistency**: Consistent performance across frequency ranges

## Applications

### **Primary Uses**
- **VHF/UHF Repeater Sites**: Professional repeater installations
- **Base Station Operations**: High-performance base station antennas
- **Emergency Communications**: Reliable omnidirectional coverage
- **Dual-Band Packet Radio**: APRS and digital mode communication
- **APRS Gateway Stations**: Wide-area packet radio coverage
- **Contest Stations**: Omnidirectional coverage for contests

### **Specialized Applications**
- **Public Safety**: Emergency communication systems
- **Amateur Radio Clubs**: Club station antennas
- **Field Day Operations**: Portable omnidirectional coverage
- **Satellite Communication**: Ground station antennas
- **Weak Signal Modes**: CW, SSB, digital modes

## Construction Notes

### **Mechanical Design**
- **Construction**: Fiberglass/aluminum composite
- **Weather Sealing**: Internal matching network sealed
- **Hardware**: Stainless steel hardware
- **Radome**: UV-resistant protective covering
- **Wind Load**: Suitable for 160+ km/h winds

### **Mounting Specifications**
- **Mast Diameter**: 30-62mm (adjustable clamps)
- **Mounting Height**: Recommended 8-15m AGL
- **Guy Wires**: Not required (rigid construction)
- **Grounding**: DC ground through radial system

### **Electrical Design**
- **Impedance Matching**: Internal 50Ω matching
- **Power Handling**: 200W maximum continuous
- **SWR Performance**: <1.5:1 across both bands
- **Broadband Design**: Covers entire amateur bands

## Performance Optimization

### **Design Features**
- **Collinear Array**: Maximizes gain while maintaining omnidirectional pattern
- **Dual-Band Design**: Separate optimized sections for each band
- **Ground Plane**: Proper radial system for omnidirectional coverage
- **Matching Network**: Broadband impedance matching

### **Pattern Characteristics**
- **Omnidirectional Coverage**: True 360° coverage (±1 dB)
- **Low Elevation Angles**: Optimized for ground wave propagation
- **Minimal Distortion**: Clean patterns with minimal mounting effects
- **Consistent Performance**: Reliable across frequency ranges

## Files in This Directory

### **EZNEC Model**
- **`dual_band_omni_2m_70cm.ez`**: Main EZNEC model file
- **Complete geometry**: All elements with ground plane system
- **Source configuration**: Base feed with matching network
- **Load conditions**: Aluminum elements and matching network

### **Pattern Files**
- **`patterns/vhf/`**: Directory containing VHF radiation patterns
- **`patterns/uhf/`**: Directory containing UHF radiation patterns
- **Frequency subdirectories**: `144.0mhz/`, `144.1mhz/`, etc.
- **Altitude variations**: 0m, 100m, 500m, 1000m, 2000m
- **Pattern format**: Standard 4NEC2 output format

### **Documentation**
- **`README.md`**: This comprehensive documentation
- **`dual_band_omni_specifications.txt`**: Technical specifications
- **`dual_band_omni_patterns_index.txt`**: Pattern file index

### **Generation Scripts**
- **`generate_dual_band_omni_patterns.sh`**: Pattern generation script
- **Multi-core processing**: Utilizes all available CPU cores
- **Dual-band generation**: Creates patterns for both VHF and UHF bands

## Usage in FGCom-mumble

### **Integration**
This antenna model integrates with FGCom-mumble's propagation system:

1. **Pattern Loading**: Antenna patterns loaded automatically
2. **Frequency Matching**: Patterns matched to operating frequency
3. **Altitude Interpolation**: Patterns interpolated for aircraft altitude
4. **Gain Calculation**: Real-time gain calculation for signal quality

### **Performance Benefits**
- **Omnidirectional Coverage**: 360° coverage for all directions
- **Dual-Band Operation**: Single antenna for both VHF and UHF
- **High Gain**: Good gain on both bands
- **Professional Quality**: Suitable for repeater and base station use

## Technical Notes

### **Model Accuracy**
- **Element Modeling**: Accurate wire representation
- **Ground Plane**: Realistic radial system modeling
- **Ground Effects**: Real ground modeling
- **Matching Effects**: Internal impedance matching included

### **Limitations**
- **Single Frequency**: Patterns generated for specific frequencies
- **Ground Assumptions**: Assumes flat ground
- **Weather Effects**: No weather-dependent modeling
- **Mechanical Effects**: No wind or ice loading effects

## Installation Guidelines

### **Mounting Requirements**
- **Height**: Mount as high as practical for best performance
- **Radials**: Ensure radials are horizontal and unobstructed
- **Cable**: Use quality 50Ω coaxial cable
- **Lightning Protection**: Lightning protection recommended
- **Inspection**: Regular inspection of radial system

### **Performance Optimization**
- **Clearance**: Maintain clear area around antenna
- **Grounding**: Proper grounding system
- **Cable Quality**: Use low-loss coaxial cable
- **Height**: Higher mounting improves performance

## Comparison to Other Antennas

### **Advantages**
- **Higher Gain**: More gain than simple λ/4 verticals
- **Omnidirectional**: Better coverage than Yagi arrays
- **Dual-Band**: More compact than separate single-band antennas
- **Professional**: Superior to mobile whips for base station use

### **Trade-offs**
- **Size**: Larger than simple verticals
- **Complexity**: More complex than single-band antennas
- **Cost**: Higher cost than basic antennas
- **Installation**: Requires proper mounting and grounding

## Conclusion

This dual-band omnidirectional antenna represents a high-performance solution for professional VHF/UHF base station applications. The EZNEC model provides accurate radiation patterns for integration with FGCom-mumble's propagation system, enabling realistic simulation of omnidirectional antenna performance in flight simulation environments.

The antenna is particularly well-suited for:
- **Repeater installations** requiring omnidirectional coverage
- **Base station operations** with dual-band capability
- **Emergency communications** requiring reliable coverage
- **Professional applications** requiring consistent performance

The comprehensive pattern generation ensures accurate modeling across both amateur bands with various altitude conditions, making it suitable for both ground-based and airborne communication scenarios.
