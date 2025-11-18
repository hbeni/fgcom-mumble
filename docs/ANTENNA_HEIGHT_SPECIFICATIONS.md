# Antenna Height Specifications - 10m Above Ground

## Overview

All new ground-based antennas in the FGCom-mumble system are positioned **10 meters above ground level**. This height specification has significant implications for propagation modeling, signal quality, and realistic radio communication simulation.

## New Antennas with 10m Height

### **1. 11-Element 2m Yagi Antenna (144-145 MHz)**
- **File**: `antenna_patterns/Ground-based/yagi_144mhz/yagi_144mhz_11element.ez`
- **Height**: 10m above ground
- **Gain**: 14.8 dBi
- **Pattern**: Directional beam antenna
- **Applications**: VHF weak signal, contest operations, DXpeditions

### **2. 16-Element 70cm Yagi Antenna (430-440 MHz)**
- **File**: `antenna_patterns/Ground-based/yagi_70cm/yagi_70cm_16element.ez`
- **Height**: 10m above ground
- **Gain**: 16.56 dBi (free space)
- **Pattern**: Directional beam antenna
- **Applications**: UHF weak signal, satellite communication, EME operations

### **3. Dual-Band Omnidirectional Antenna (2m/70cm)**
- **File**: `antenna_patterns/Ground-based/dual_band_omni/dual_band_omni_2m_70cm.ez`
- **Height**: 10m above ground
- **Gain**: 8.3 dBi @ 144 MHz, 11.7 dBi @ 432 MHz
- **Pattern**: Omnidirectional (360°)
- **Applications**: Repeater sites, base stations, emergency communications

## Height Specifications in EZNEC Models

### **Ground Reference**
All models use:
```
GD 1 0 0 0 0.005 0.013
```
- **Real ground** at 0m height
- **Antenna elements** at 10m height
- **Ground plane radials** at 10m height

### **Element Positioning**
All antenna elements are positioned with Z-coordinates starting at 10.0m:
- **Yagi elements**: All at 10.0m height
- **Omnidirectional elements**: All at 10.0m height
- **Ground plane radials**: At 10.0m height
- **Mounting structures**: Below 10.0m (non-radiating)

## Propagation Physics Implications

### **Antenna Height Gain**
The 10m height provides significant advantages:

#### **VHF (144 MHz)**
- **Height Gain**: ~20 dB at 10m height
- **Range Extension**: 2-3x compared to ground level
- **Elevation Pattern**: Optimized for low-angle radiation
- **Ground Effects**: Minimal interaction at 10m

#### **UHF (432 MHz)**
- **Height Gain**: ~20 dB at 10m height
- **Range Extension**: 2-3x compared to ground level
- **Elevation Pattern**: Lower angles for extended range
- **Ground Effects**: Minimal interaction at 10m

### **Free Space Path Loss**
The 10m height affects path loss calculations:

```cpp
// Antenna height gain calculation
double height_gain = FGCom_PropagationPhysics::calculateAntennaHeightGain(
    antenna_height_m, frequency_mhz, distance_km
);
```

**Formula**: `20*log10(height)` where height is in meters
- **10m height**: ~20 dB gain
- **Frequency dependency**: More significant at higher frequencies
- **Distance effects**: Height gain decreases with distance

### **Ground Effects**
At 10m height, ground effects are minimized:

#### **Reflection Effects**
- **Minimal ground reflection**: Clean radiation patterns
- **Reduced multipath**: Better signal quality
- **Consistent patterns**: Less distortion from ground

#### **Elevation Patterns**
- **VHF**: ~10-15° elevation angle optimum
- **UHF**: ~5-8° elevation angle optimum
- **Low-angle radiation**: Extended range capability

## Signal Quality Calculations

### **Height-Adjusted Propagation**
All propagation calculations include antenna height:

```cpp
double total_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
    distance_km, frequency_mhz, altitude_m, antenna_height_m,
    temperature_c, humidity_percent, rain_rate_mmh, obstruction_height_m
);
```

### **Realistic Range Predictions**
The 10m height enables realistic range predictions:

#### **VHF Range (144 MHz)**
- **Ground level**: ~25-50 km typical
- **10m height**: ~50-100 km typical
- **Extended range**: 150+ km with tropospheric ducting

#### **UHF Range (432 MHz)**
- **Ground level**: ~15-30 km typical
- **10m height**: ~30-60 km typical
- **Extended range**: 100+ km in good conditions

## Pattern Generation Considerations

### **Altitude Variations**
Pattern files are generated for multiple altitudes:
- **0m**: Ground level reference
- **100m**: Low altitude aircraft
- **500m**: Medium altitude aircraft
- **1000m**: High altitude aircraft
- **2000m**: Very high altitude aircraft

### **Height Interpolation**
The 10m ground antenna height provides:
- **Baseline reference**: For altitude interpolation
- **Realistic modeling**: Ground-based communication
- **Pattern consistency**: Across frequency ranges

## Installation Requirements

### **Mounting Specifications**
All antennas require:
- **Mast height**: 10m minimum above ground
- **Clearance**: Unobstructed area around antenna
- **Grounding**: Proper grounding system
- **Lightning protection**: Recommended for 10m height

### **Mechanical Considerations**
- **Wind loading**: Higher wind loads at 10m height
- **Guy wires**: May be required for stability
- **Maintenance**: Access requirements for 10m height
- **Safety**: Fall protection for installation/maintenance

## Performance Benefits

### **Range Extension**
The 10m height provides:
- **2-3x range increase** compared to ground level
- **Better line-of-sight** coverage
- **Reduced ground losses**
- **Improved signal quality**

### **Pattern Quality**
- **Clean radiation patterns**: Minimal ground distortion
- **Consistent omnidirectional coverage**: For omni antennas
- **Sharp directional patterns**: For Yagi antennas
- **Low elevation angles**: Extended range capability

### **Realistic Modeling**
- **Professional installations**: Typical base station height
- **Repeater sites**: Standard mounting height
- **Emergency communications**: Reliable coverage
- **Contest operations**: Competitive advantage

## Comparison with Other Heights

### **Ground Level (0m)**
- **Range**: Limited by ground effects
- **Pattern**: Distorted by ground reflection
- **Quality**: Poor signal quality
- **Use**: Mobile applications only

### **5m Height**
- **Range**: Moderate improvement
- **Pattern**: Some ground effects
- **Quality**: Acceptable for local use
- **Use**: Residential installations

### **10m Height (Current)**
- **Range**: Significant improvement
- **Pattern**: Clean, consistent patterns
- **Quality**: Professional-grade performance
- **Use**: Base stations, repeaters, contest operations

### **15m+ Height**
- **Range**: Maximum range capability
- **Pattern**: Excellent patterns
- **Quality**: Best possible performance
- **Use**: Professional installations, major repeaters

## Technical Implementation

### **EZNEC Model Height**
All models specify:
```
; Height: 10m above ground
```
- **Consistent height**: All elements at 10.0m
- **Ground reference**: Real ground at 0.0m
- **Pattern generation**: Based on 10m height

### **Propagation Calculations**
Height is included in all calculations:
- **Free space path loss**: Distance-based
- **Antenna height gain**: 10m height advantage
- **Ground effects**: Minimal at 10m
- **Signal quality**: Height-adjusted results

### **Pattern Interpolation**
The 10m height enables:
- **Altitude interpolation**: For aircraft at various altitudes
- **Realistic modeling**: Ground-to-air communication
- **Consistent results**: Across frequency ranges
- **Professional quality**: Base station performance

## Conclusion

The **10m above ground** specification for all new antennas provides:

**Realistic Base Station Modeling**:
- Professional installation height
- Significant range extension
- Clean radiation patterns
- Minimal ground effects

**Enhanced Propagation Performance**:
- 2-3x range improvement over ground level
- Better signal quality
- Lower elevation angles
- Extended coverage area

**Professional-Grade Simulation**:
- Repeater site performance
- Contest operation capability
- Emergency communication reliability
- Realistic radio communication modeling

This height specification ensures that FGCom-mumble provides realistic modeling of professional VHF/UHF base station installations, enabling accurate simulation of ground-based radio communication systems in flight simulation environments.
