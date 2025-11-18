# 16-Element 70cm Yagi Antenna (430-440 MHz)

## Overview

This directory contains the EZNEC model and radiation patterns for a high-performance 16-element Yagi beam antenna designed for the 70cm amateur radio band (430-440 MHz). This antenna is suitable for serious UHF operations requiring maximum gain and excellent pattern control.

## Antenna Specifications

### **Physical Characteristics**
- **Type**: 16-element Yagi beam antenna
- **Frequency Range**: 430.0 - 440.0 MHz (70cm amateur band)
- **Boom Length**: 3.10m (310 cm)
- **Elements**: 16 total (1 reflector, 1 driven, 14 directors)
- **Height**: 10m above ground
- **Polarization**: Horizontal
- **Max Power**: 1000W
- **Tapered Boom**: 25-30-25mm aluminum design

### **Performance Specifications**
- **Gain**: 16.56 dBi (free space)
- **Front/Back Ratio**: 32 dB
- **Beamwidth**: ~24° horizontal, ~26° vertical
- **SWR**: <1.3:1 across band
- **Impedance**: 50Ω (with 4:1 balun)
- **Elevation Angle**: ~7-10° optimum

## Element Details

### **Element Specifications**
| Element | Length | Position | Diameter | Material |
|---------|--------|----------|----------|----------|
| Reflector | 35cm | -1.40m | 3mm | Aluminum rod |
| Driven | 32.4cm | -1.10m | 3mm | Aluminum rod |
| Director 1 | 31.6cm | -0.85m | 3mm | Aluminum rod |
| Director 2 | 31.0cm | -0.62m | 3mm | Aluminum rod |
| Director 3 | 30.4cm | -0.42m | 3mm | Aluminum rod |
| Director 4 | 30.0cm | -0.24m | 3mm | Aluminum rod |
| Director 5 | 29.6cm | -0.08m | 3mm | Aluminum rod |
| Director 6 | 29.2cm | 0.06m | 3mm | Aluminum rod |
| Director 7 | 28.8cm | 0.19m | 3mm | Aluminum rod |
| Director 8 | 28.4cm | 0.31m | 3mm | Aluminum rod |
| Director 9 | 28.0cm | 0.42m | 3mm | Aluminum rod |
| Director 10 | 27.6cm | 0.53m | 3mm | Aluminum rod |
| Director 11 | 27.2cm | 0.63m | 3mm | Aluminum rod |
| Director 12 | 26.8cm | 0.73m | 3mm | Aluminum rod |
| Director 13 | 26.4cm | 0.83m | 3mm | Aluminum rod |
| Director 14 | 26.0cm | 0.93m | 3mm | Aluminum rod |

### **Tapered Boom Specifications**
- **Total Length**: 3.10m (310 cm)
- **Center Section**: 30mm diameter, 1.0m length (maximum strength)
- **End Sections**: 25mm diameter, 2.1m total (weight optimization)
- **Mounting**: Center mount capability (60mm max mast diameter)
- **Material**: Aluminum tube with tapered design

## EZNEC Model Features

### **Model Components**
- **Tapered Boom Structure**: 3.10m aluminum tube with optimized segments
- **Yagi Elements**: 16 elements with optimized spacing and lengths
- **Element Connections**: Short connecting segments from boom to elements
- **High-Power Balun**: 1000W rated balun for impedance transformation
- **Ground**: Real ground at 0m height, antenna at 10m

### **Source Configuration**
- **Feed Point**: Driven element center via high-power balun
- **Impedance**: 50Ω (after 4:1 balun transformation)
- **Balun Type**: High-power 4:1 balun for common-mode rejection

### **Load Conditions**
- **Aluminum Elements**: 3.7E+07 S/m conductivity
- **High-Power Balun**: 200Ω to 50Ω transformation (1000W rated)
- **Ground Effects**: Real ground modeling at 10m height

## Radiation Patterns

### **Pattern Generation**
The antenna patterns are generated for:
- **Frequencies**: 430.0, 430.5, 431.0, 431.5, 432.0, 432.5, 433.0, 433.5, 434.0, 434.5, 435.0, 435.5, 436.0, 436.5, 437.0, 437.5, 438.0, 438.5, 439.0, 439.5, 440.0 MHz
- **Altitudes**: 0, 100, 500, 1000, 2000m above ground
- **Total Patterns**: 105 pattern files (21 frequencies × 5 altitudes)

### **Pattern Characteristics**
- **Azimuth Pattern**: Highly directional with ~24° beamwidth
- **Elevation Pattern**: ~26° vertical beamwidth
- **Front/Back Ratio**: 30-35 dB typical
- **Side Lobe Suppression**: Excellent pattern control
- **Ground Effects**: Minimal at 10m height

## Applications

### **Primary Uses**
- **UHF Weak Signal Communication**: EME (Earth-Moon-Earth), MS (Meteor Scatter)
- **Contest Operation**: High-gain beam for competitive operating
- **DXpeditions**: Long-distance UHF communication
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
- **Tapered Boom**: Optimized for mechanical/electrical balance
- **Element Mounting**: Insulated clamps on boom
- **Center Mounting**: Balance point optimization
- **No Guying Required**: Rigid design for wind survival
- **Wind Loading**: 160 km/h survival rating

### **Electrical Design**
- **Impedance Matching**: 4:1 balun for 50Ω feed
- **High-Power Capability**: 1000W power handling
- **Common-Mode Rejection**: Balun provides isolation
- **SWR Performance**: <1.3:1 across 70cm band
- **Low-Loss Design**: Ferrite core balun

## Performance Optimization

### **Design Features**
- **Element Lengths**: Tuned for maximum gain at 432 MHz
- **Spacing Optimization**: Optimized for F/B ratio
- **Progressive Tapering**: Directors progressively shorter
- **Clean Impedance**: 50Ω match with balun
- **Pattern Control**: Excellent front/back ratio

### **Tapered Boom Benefits**
- **Weight Optimization**: Lighter ends, stronger center
- **Mechanical Balance**: Center mounting capability
- **Wind Resistance**: Optimized for high wind survival
- **Stacking Capability**: 132cm H / 139cm V spacing

## Files in This Directory

### **EZNEC Model**
- **`yagi_70cm_16element.ez`**: Main EZNEC model file
- **Complete geometry**: All 16 elements with tapered boom
- **Source configuration**: Driven element with high-power balun
- **Load conditions**: Aluminum elements and balun impedance

### **Pattern Files**
- **`patterns/`**: Directory containing all radiation patterns
- **Frequency subdirectories**: `430.0mhz/`, `430.5mhz/`, etc.
- **Altitude variations**: 0m, 100m, 500m, 1000m, 2000m
- **Pattern format**: Standard 4NEC2 output format

### **Documentation**
- **`README.md`**: This comprehensive documentation
- **`yagi_70cm_specifications.txt`**: Technical specifications
- **`yagi_70cm_patterns_index.txt`**: Pattern file index

### **Generation Scripts**
- **`generate_yagi_70cm_patterns.sh`**: Pattern generation script
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
- **Realistic Modeling**: Accurate UHF beam antenna performance
- **Directional Effects**: Proper front/back ratio modeling
- **Frequency Response**: Band-specific performance characteristics
- **Altitude Effects**: Ground-based antenna with height variations

## Technical Notes

### **Model Accuracy**
- **Element Modeling**: Accurate wire representation
- **Tapered Boom**: Realistic boom structure modeling
- **Ground Effects**: Real ground modeling
- **Balun Effects**: High-power impedance transformation included

### **Limitations**
- **Single Frequency**: Patterns generated for specific frequencies
- **Ground Assumptions**: Assumes flat ground
- **Weather Effects**: No weather-dependent modeling
- **Mechanical Effects**: No wind or ice loading effects

## Conclusion

This 16-element 70cm Yagi antenna represents a high-performance UHF beam antenna suitable for serious amateur radio operations. The EZNEC model provides accurate radiation patterns for integration with FGCom-mumble's propagation system, enabling realistic simulation of UHF beam antenna performance in flight simulation environments.

The antenna is particularly well-suited for:
- **Contest operations** requiring maximum gain
- **Weak signal communication** (EME, MS)
- **DX operations** on 70cm band
- **Professional applications** requiring reliable UHF communication

The comprehensive pattern generation ensures accurate modeling across the entire 70cm band with various altitude conditions, making it suitable for both ground-based and airborne communication scenarios.
