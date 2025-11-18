# 11-Element 2m Yagi Antenna (144-145 MHz)

## Overview

This directory contains the EZNEC model and radiation patterns for a high-performance 11-element Yagi beam antenna designed for the 2m amateur radio band (144-145 MHz). This antenna is suitable for serious VHF operations requiring maximum gain and excellent pattern control.

## Antenna Specifications

### **Physical Characteristics**
- **Type**: 11-element Yagi beam antenna
- **Frequency Range**: 144.0 - 145.0 MHz (2m amateur band)
- **Boom Length**: 5.72m (572 cm)
- **Elements**: 11 total (1 reflector, 1 driven, 9 directors)
- **Height**: 10m above ground
- **Polarization**: Horizontal
- **Weight**: 6.95 kg
- **Max Power**: 500W

### **Performance Specifications**
- **Gain**: 14.8 dBi (typical)
- **Front/Back Ratio**: 27 dB
- **Beamwidth**: ~30° horizontal, ~35° vertical
- **SWR**: <1.5:1 across band
- **Impedance**: 50Ω (with 4:1 balun)
- **Elevation Angle**: ~7-10° optimum

## Element Details

### **Element Specifications**
| Element | Length | Position | Diameter | Material |
|---------|--------|----------|----------|----------|
| Reflector | 105cm | -2.50m | 6mm | Aluminum rod |
| Driven | 97cm | -1.80m | 6mm | Aluminum rod |
| Director 1 | 93cm | -1.20m | 6mm | Aluminum rod |
| Director 2 | 91cm | -0.70m | 6mm | Aluminum rod |
| Director 3 | 89cm | -0.25m | 6mm | Aluminum rod |
| Director 4 | 88cm | 0.15m | 6mm | Aluminum rod |
| Director 5 | 87cm | 0.50m | 6mm | Aluminum rod |
| Director 6 | 86cm | 0.85m | 6mm | Aluminum rod |
| Director 7 | 85cm | 1.25m | 6mm | Aluminum rod |
| Director 8 | 84cm | 1.75m | 6mm | Aluminum rod |
| Director 9 | 83cm | 2.35m | 6mm | Aluminum rod |

### **Boom Specifications**
- **Length**: 5.72m (572 cm)
- **Diameter**: 25mm
- **Material**: Aluminum tube
- **Mounting**: Center balance point

## EZNEC Model Features

### **Model Components**
- **Boom Structure**: 5.72m aluminum tube with 57 segments
- **Yagi Elements**: 11 elements with optimized spacing and lengths
- **Element Connections**: Short connecting segments from boom to elements
- **Balun**: 4:1 balun for impedance transformation (200Ω to 50Ω)
- **Ground**: Real ground at 0m height, antenna at 10m

### **Source Configuration**
- **Feed Point**: Driven element center via balun
- **Impedance**: 50Ω (after balun transformation)
- **Balun Type**: 4:1 balun for common-mode rejection

### **Load Conditions**
- **Aluminum Elements**: 3.7E+07 S/m conductivity
- **Balun Impedance**: 200Ω to 50Ω transformation
- **Ground Effects**: Real ground modeling at 10m height

## Radiation Patterns

### **Pattern Generation**
The antenna patterns are generated for:
- **Frequencies**: 144.0, 144.1, 144.2, 144.3, 144.4, 144.5, 144.6, 144.7, 144.8, 144.9, 145.0 MHz
- **Altitudes**: 0, 100, 500, 1000, 2000m above ground
- **Total Patterns**: 55 pattern files (11 frequencies × 5 altitudes)

### **Pattern Characteristics**
- **Azimuth Pattern**: Highly directional with ~30° beamwidth
- **Elevation Pattern**: ~35° vertical beamwidth
- **Front/Back Ratio**: 25-30 dB typical
- **Side Lobe Suppression**: Excellent pattern control
- **Ground Effects**: Minimal at 10m height

## Applications

### **Primary Uses**
- **VHF Weak Signal Communication**: EME (Earth-Moon-Earth), MS (Meteor Scatter)
- **Contest Operation**: High-gain beam for competitive operating
- **DXpeditions**: Long-distance VHF communication
- **Repeater Access**: High-gain access to distant repeaters
- **Digipeater Access**: APRS and digital mode communication

### **Specialized Applications**
- **Satellite Communication**: Linear transponder access
- **EME Operations**: Moon bounce communication
- **Meteor Scatter**: High-gain for MS contacts
- **Weak Signal Modes**: CW, SSB, digital modes
- **Contest Operations**: Multipliers and rare grid squares

## Construction Notes

### **Mechanical Design**
- **Element Mounting**: Insulated clamps on boom
- **Boom-to-Mast**: Bracket at balance point
- **Weather Protection**: Balun connections protected
- **Guy Wires**: May be needed for mechanical stability
- **Wind Loading**: Designed for typical wind conditions

### **Electrical Design**
- **Impedance Matching**: 4:1 balun for 50Ω feed
- **Common-Mode Rejection**: Balun provides isolation
- **SWR Performance**: <1.5:1 across 2m band
- **Power Handling**: 500W maximum continuous

## Performance Optimization

### **Design Features**
- **Element Lengths**: Tuned for maximum gain
- **Spacing Optimization**: Optimized for F/B ratio
- **Progressive Tapering**: Directors progressively shorter
- **Clean Impedance**: 50Ω match with balun
- **Pattern Control**: Excellent front/back ratio

### **Ground Effects**
- **Height Advantage**: 10m height minimizes ground interaction
- **Clean Patterns**: Minimal ground reflection effects
- **Elevation Angle**: Optimum at 7-10° elevation
- **Azimuth Patterns**: Clean directional patterns

## Files in This Directory

### **EZNEC Model**
- **`yagi_144mhz_11element.ez`**: Main EZNEC model file
- **Complete geometry**: All 11 elements with boom and connections
- **Source configuration**: Driven element with balun
- **Load conditions**: Aluminum elements and balun impedance

### **Pattern Files**
- **`patterns/`**: Directory containing all radiation patterns
- **Frequency subdirectories**: `144.0mhz/`, `144.1mhz/`, etc.
- **Altitude variations**: 0m, 100m, 500m, 1000m, 2000m
- **Pattern format**: Standard 4NEC2 output format

### **Documentation**
- **`README.md`**: This comprehensive documentation
- **`yagi_144mhz_specifications.txt`**: Technical specifications
- **`yagi_144mhz_patterns_index.txt`**: Pattern file index

### **Generation Scripts**
- **`generate_yagi_144mhz_patterns.sh`**: Pattern generation script
- **Multi-core processing**: Utilizes all available CPU cores
- **Automated generation**: Creates all frequency/altitude combinations

## Usage in FGCom-mumble

### **Integration**
This antenna model integrates with FGCom-mumble's propagation system:

1. **Pattern Loading**: Antenna patterns loaded automatically
2. **Frequency Matching**: Patterns matched to operating frequency
3. **Altitude Interpolation**: Patterns interpolated for aircraft altitude
4. **Gain Calculation**: Real-time gain calculation for signal quality

### **Performance Benefits**
- **Realistic Modeling**: Accurate VHF beam antenna performance
- **Directional Effects**: Proper front/back ratio modeling
- **Frequency Response**: Band-specific performance characteristics
- **Altitude Effects**: Ground-based antenna with height variations

## Technical Notes

### **Model Accuracy**
- **Element Modeling**: Accurate wire representation
- **Boom Effects**: Boom included in model
- **Ground Effects**: Real ground modeling
- **Balun Effects**: Impedance transformation included

### **Limitations**
- **Single Frequency**: Patterns generated for specific frequencies
- **Ground Assumptions**: Assumes flat ground
- **Weather Effects**: No weather-dependent modeling
- **Mechanical Effects**: No wind or ice loading effects

## Conclusion

This 11-element 2m Yagi antenna represents a high-performance VHF beam antenna suitable for serious amateur radio operations. The EZNEC model provides accurate radiation patterns for integration with FGCom-mumble's propagation system, enabling realistic simulation of VHF beam antenna performance in flight simulation environments.

The antenna is particularly well-suited for:
- **Contest operations** requiring maximum gain
- **Weak signal communication** (EME, MS)
- **DX operations** on 2m band
- **Professional applications** requiring reliable VHF communication

The comprehensive pattern generation ensures accurate modeling across the entire 2m band with various altitude conditions, making it suitable for both ground-based and airborne communication scenarios.
