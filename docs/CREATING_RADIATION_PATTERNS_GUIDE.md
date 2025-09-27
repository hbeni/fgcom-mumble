# Complete Guide: Creating Radiation Pattern Files for FGCom-mumble

## Overview

This comprehensive guide explains how to create radiation pattern files for vehicles, aircraft, boats, and ships in FGCom-mumble. It covers the complete workflow from initial modeling to final pattern integration.

**✅ CURRENT STATUS**: The automated pattern generation system has been updated and is now working correctly. The script `scripts/pattern_generation/antenna-radiation-pattern-generator.sh` now uses Python-based coordinate transformations for reliable 3D attitude pattern generation with full yaw rotation support via the Vehicle Dynamics API.

## Table of Contents

1. [Understanding Radiation Patterns](#understanding-radiation-patterns)
2. [Required Tools and Software](#required-tools-and-software)
3. [Vehicle Categories and Requirements](#vehicle-categories-and-requirements)
4. [Step-by-Step Workflow](#step-by-step-workflow)
5. [Practical Examples](#practical-examples)
6. [Pattern File Format](#pattern-file-format)
7. [Integration with FGCom-mumble](#integration-with-fgcom-mumble)
8. [Troubleshooting and Quality Control](#troubleshooting-and-quality-control)

## Understanding Radiation Patterns

### What Are Radiation Patterns?

Radiation patterns describe how an antenna radiates electromagnetic energy in 3D space. They show:
- **Directional gain** (where the antenna is strongest/weakest)
- **Polarization** (horizontal/vertical components)
- **Frequency response** (how patterns change with frequency)
- **Ground effects** (how terrain affects radiation)

### Why Patterns Matter in FGCom-mumble

- **Realistic Communication**: Different vehicles have different antenna characteristics
- **Range Modeling**: Accurate patterns affect communication range and quality
- **Environmental Effects**: Ground, water, and altitude affect radiation patterns
- **Vehicle-Specific Behavior**: Aircraft, boats, and ground vehicles behave differently

### 3D Attitude and Coordinate Systems

The new pattern generation system supports full 3D attitude modeling:

- **Pitch Rotation**: Around Y-axis (nose up/down) - affects antenna pointing direction
- **Roll Rotation**: Around X-axis (wing up/down) - affects antenna polarization
- **Yaw Rotation**: Around Z-axis (heading change) - handled via Vehicle Dynamics API
- **Aviation Coordinate System**: Standard X-forward, Y-right, Z-up coordinate system
- **Python-Based Transformations**: Reliable trigonometry for accurate 3D coordinate transformations

## Required Tools and Software

### Essential Tools

#### 1. EZNEC (Recommended)
- **Platform**: Windows (primary), Linux/macOS via Wine
- **Type**: Commercial antenna modeling software
- **Features**: 
  - Native EZNEC file format support
  - Built-in antenna design tools
  - 3D visualization
  - Pattern analysis and optimization
- **Website**: http://www.eznec.com/
- **Cost**: Commercial license required (~$89)

#### 2. 4NEC2 (Free Alternative)
- **Platform**: Windows
- **Type**: Free NEC2-based antenna modeling
- **Features**:
  - NEC2 engine with GUI
  - EZNEC file import/export
  - 3D visualization
  - Pattern analysis
- **Website**: http://www.qsl.net/4nec2/
- **Cost**: Free

#### 3. NEC2C (Command Line)
- **Platform**: Linux, macOS, Windows
- **Type**: Command-line NEC2 engine
- **Features**:
  - Fast batch processing
  - Scriptable automation
  - High accuracy
- **Installation**: `sudo apt-get install nec2c` (Ubuntu/Debian)
- **Cost**: Free

### Optional Tools

#### 3D Modeling Software
- **Blender** (Free): For complex vehicle geometry
- **FreeCAD** (Free): For technical drawings
- **SketchUp** (Free/Paid): For simple geometry

#### Pattern Analysis Tools
- **Python with matplotlib**: For pattern visualization
- **MATLAB**: For advanced analysis
- **GNU Octave**: Free MATLAB alternative

## Vehicle Categories and Requirements

### Aircraft
- **Altitude Dependencies**: Patterns change with altitude (0m to 10,000m+)
- **Frequency Bands**: VHF (118-137 MHz), HF (3-30 MHz)
- **Antenna Types**: Whip, blade, stub, trailing wire
- **Special Considerations**: Ground effects, multipath, atmospheric conditions

### Boats and Ships
- **Maritime Environment**: Saltwater ground effects
- **Antenna Types**: Whip, backstay, HF loops, verticals
- **Frequency Bands**: HF (3-30 MHz), VHF (156-162 MHz)
- **Special Considerations**: Heeling effects, saltwater conductivity

### Historical Coastal Radio Stations
- **Massive Scale**: T-shaped antennas with 150m+ height, 195m+ top wire
- **Power Levels**: 10 kW+ for intercontinental communication
- **Ground Systems**: Extensive buried radial systems (120+ radials, 200m+ each)
- **Antenna Types**: T-shaped, L-shaped, and other large wire antennas
- **Frequency Bands**: HF (3-30 MHz) for long-range maritime communication
- **Special Considerations**: Optimized for maximum range and reliability

**Important Note**: The examples provided are simplified models of historical coastal radio stations. In reality, these stations were much more complex, featuring:
- **Multiple Antenna Systems**: Various antennas for different frequency bands and purposes
- **Sophisticated Switching**: Complex switching systems to route signals to different antennas
- **Multiple Operators**: Teams of radio operators working around the clock
- **Advanced Ground Systems**: Elaborate buried radial networks and counterpoise systems
- **Backup Systems**: Redundant antennas and equipment for reliability
- **Directional Arrays**: Phased arrays and directional antennas for specific routes
- **Power Distribution**: Complex power distribution systems for multiple transmitters

### Ground Vehicles
- **Terrain Effects**: Different ground conductivities
- **Antenna Types**: Whip, vertical, mobile antennas
- **Frequency Bands**: VHF (30-300 MHz), UHF (300-3000 MHz)
- **Special Considerations**: Ground plane effects, vehicle body coupling

### Military Vehicles
- **Tactical Frequencies**: HF (3-30 MHz) for long-range
- **Antenna Types**: Tied-down whips, vehicle-mounted
- **Special Considerations**: Camouflage, rapid deployment

## Step-by-Step Workflow

### Phase 1: Planning and Research

#### 1. Define Vehicle Specifications
```
Vehicle Type: [Aircraft/Boat/Ship/Ground Vehicle/Military]
Dimensions: [Length x Width x Height]
Antenna Type: [Whip/Blade/Vertical/Loop/etc.]
Frequency Range: [e.g., 3-30 MHz for HF]
Operating Environment: [Land/Sea/Air]
```

#### 2. Research Real-World Antennas
- **Aircraft**: Study actual aircraft antenna installations
- **Maritime**: Research ship antenna systems
- **Ground**: Look at mobile radio installations
- **Military**: Study tactical communication systems

#### 3. Determine Ground Characteristics
- **Saltwater**: σ = 5 S/m, εᵣ = 81 (ships, coastal)
- **Average Soil**: σ = 0.005 S/m, εᵣ = 13 (typical land)
- **Poor Ground**: σ = 0.001 S/m, εᵣ = 5 (dry, rocky)
- **Free Space**: No ground effects (high altitude)

### Phase 2: EZNEC Model Creation

#### 1. Create Vehicle Structure

**Basic Vehicle Wireframe Example (NATO Jeep):**
```eznec
CM NATO Jeep with 10ft whip antenna at 45 degrees
CM Vehicle dimensions: 4.2m x 1.8m x 1.5m
CM Antenna: 3m whip at 45 degree angle
CE

GW  1  1   -2.1  -0.9   0.0   2.1  -0.9   0.0  0.01
GW  2  1    2.1  -0.9   0.0   2.1   0.9   0.0  0.01
GW  3  1    2.1   0.9   0.0  -2.1   0.9   0.0  0.01
GW  4  1   -2.1   0.9   0.0  -2.1  -0.9   0.0  0.01

GW  5  1   -2.1  -0.9   0.0  -2.1  -0.9   1.5  0.01
GW  6  1    2.1  -0.9   0.0   2.1  -0.9   1.5  0.01
GW  7  1    2.1   0.9   0.0   2.1   0.9   1.5  0.01
GW  8  1   -2.1   0.9   0.0  -2.1   0.9   1.5  0.01

GW  9  1   -2.1  -0.9   1.5   2.1  -0.9   1.5  0.01
GW 10  1    2.1  -0.9   1.5   2.1   0.9   1.5  0.01
GW 11  1    2.1   0.9   1.5  -2.1   0.9   1.5  0.01
GW 12  1   -2.1   0.9   1.5  -2.1  -0.9   1.5  0.01

GE  0
```

#### 2. Add Antenna Geometry

**Whip Antenna Example:**
```eznec
CM 10ft whip antenna at 45 degree angle
GW 13  5    0.0   0.0   1.5   2.12  2.12  3.62  0.005

GE  0
```

#### 3. Set Ground Parameters

**Ground Definition:**
```eznec
GD  0  0  0  0  0.005  13
```

Where:
- `0.005` = Ground conductivity (S/m)
- `13` = Relative permittivity

#### 4. Define Excitation

**Voltage Source:**
```eznec
EX  0  13  3  0  1.0  0.0
```

Where:
- `13` = Wire number (antenna)
- `3` = Segment number (middle of antenna)
- `1.0` = Voltage magnitude
- `0.0` = Phase

#### 5. Set Frequency

**Frequency Definition:**
```eznec
FR  0  1  0  0  3000.0  0
```

Where:
- `3000.0` = Frequency in kHz
- `0` = No frequency sweep

#### 6. Calculate Radiation Pattern

**Pattern Calculation:**
```eznec
RP  0  37  73  1000  0.0  0.0  5.0  5.0  0.0  0.0
```

Where:
- `37` = Theta angles (0-180° in 5° steps)
- `73` = Phi angles (0-360° in 5° steps)
- `1000` = Distance for far-field calculation
- `5.0  5.0` = Theta and Phi step sizes

### Phase 3: Pattern Generation

#### 1. Create Frequency-Specific Models

**Script for Multiple Frequencies:**
```bash
#!/bin/bash
# Generate patterns for multiple frequencies

frequencies=(3000 5000 7000 9000 14000 18000 21000 28000)

for freq in "${frequencies[@]}"; do
    # Copy base model
    cp vehicle.ez vehicle_${freq}kHz.ez
    
    # Update frequency
    sed -i "s/^FR.*/FR 0 1 0 0 ${freq}.0 0/" vehicle_${freq}kHz.ez
    
    # Convert to NEC2
    ./eznec2nec.sh vehicle_${freq}kHz.ez
    
    # Run simulation
    nec2c -i vehicle_${freq}kHz.nec -o vehicle_${freq}kHz.out
    
    # Extract pattern
    ./extract_pattern.sh vehicle_${freq}kHz.out vehicle_${freq}kHz_pattern.txt
done
```

#### 2. Run NEC2 Simulation

**Command Line:**
```bash
# Run simulation
nec2c -i vehicle_3000kHz.nec -o vehicle_3000kHz.out

# Check for errors
if [ $? -ne 0 ]; then
    echo "Simulation failed for frequency 3000 kHz"
    exit 1
fi
```

#### 3. Extract Radiation Pattern

**Pattern Extraction Script:**
```bash
#!/bin/bash
# Extract radiation pattern from NEC2 output

input_file="$1"
output_file="$2"
frequency="$3"
altitude="$4"

echo "# FGCom-mumble Far-Field Radiation Pattern" > "$output_file"
echo "# Frequency: ${frequency} MHz" >> "$output_file"
echo "# Altitude: ${altitude} m" >> "$output_file"
echo "# Format: Theta Phi Gain_dBi H_Polarization V_Polarization" >> "$output_file"
echo "# Theta: Elevation angle (0-180 degrees)" >> "$output_file"
echo "# Phi: Azimuth angle (0-360 degrees)" >> "$output_file"
echo "# Gain: Antenna gain in dBi" >> "$output_file"
echo "# H_Polarization: Horizontal polarization component" >> "$output_file"
echo "# V_Polarization: Vertical polarization component" >> "$output_file"

# Extract pattern data (simplified)
grep "RADIATION PATTERN" -A 1000 "$input_file" | \
grep -E "^[[:space:]]*[0-9]" | \
awk '{print $1, $2, $3, $4, $5}' >> "$output_file"
```

### Phase 4: Aircraft Altitude Variations

#### 1. Altitude-Specific Patterns

**For Aircraft Only:**
```bash
#!/bin/bash
# Generate altitude-dependent patterns for aircraft

altitudes=(0 100 500 1000 2000 3000 5000 8000 10000)

for alt in "${altitudes[@]}"; do
    # Create altitude-specific model
    cp aircraft.ez aircraft_${alt}m.ez
    
    # Update ground parameters for altitude
    if [ $alt -gt 1000 ]; then
        # High altitude - free space
        sed -i "s/^GD.*/GD  0  0  0  0  0.0  1.0/" aircraft_${alt}m.ez
    else
        # Low altitude - ground effects
        sed -i "s/^GD.*/GD  0  0  0  0  0.005  13/" aircraft_${alt}m.ez
    fi
    
    # Generate pattern for this altitude
    ./generate_pattern.sh aircraft_${alt}m.ez aircraft_${alt}m_pattern.txt
done
```

## Practical Examples

### Example 1: Cessna 172 Aircraft

#### Vehicle Specifications
- **Type**: General aviation aircraft
- **Dimensions**: 8.2m x 10.9m x 2.7m
- **Antenna**: VHF whip on fuselage
- **Frequency**: 118-137 MHz (VHF)
- **Altitude Range**: 0-10,000m

#### EZNEC Model
```eznec
CM Cessna 172 VHF Antenna Model
CM Aircraft dimensions: 8.2m x 10.9m x 2.7m
CM VHF whip antenna on fuselage
CE

GW  1  1   -4.1  -5.45  0.0   4.1  -5.45  0.0  0.01
GW  2  1    4.1  -5.45  0.0   4.1   5.45  0.0  0.01
GW  3  1    4.1   5.45  0.0  -4.1   5.45  0.0  0.01
GW  4  1   -4.1   5.45  0.0  -4.1  -5.45  0.0  0.01

GW  5  1   -4.1  -5.45  0.0  -4.1  -5.45  2.7  0.01
GW  6  1    4.1  -5.45  0.0   4.1  -5.45  2.7  0.01
GW  7  1    4.1   5.45  0.0   4.1   5.45  2.7  0.01
GW  8  1   -4.1   5.45  0.0  -4.1   5.45  2.7  0.01

GW  9  1   -4.1  -5.45  2.7   4.1  -5.45  2.7  0.01
GW 10  1    4.1  -5.45  2.7   4.1   5.45  2.7  0.01
GW 11  1    4.1   5.45  2.7  -4.1   5.45  2.7  0.01
GW 12  1   -4.1   5.45  2.7  -4.1  -5.45  2.7  0.01

CM VHF whip antenna (1.05m at 130 MHz)
GW 13  5    0.0   0.0   2.7   0.0   0.0   3.75  0.005

GE  0
GD  0  0  0  0  0.005  13
EX  0  13  3  0  1.0  0.0
FR  0  1  0  0  130000.0  0
RP  0  37  73  1000  0.0  0.0  5.0  5.0  0.0  0.0
EN
```

### Example 2: Sailboat with Backstay Antenna

#### Vehicle Specifications
- **Type**: Sailboat
- **Dimensions**: 12m x 3.5m x 1.5m
- **Antenna**: Backstay antenna (insulated)
- **Frequency**: 3-30 MHz (HF)
- **Environment**: Saltwater

#### EZNEC Model
```eznec
CM Sailboat with Backstay Antenna
CM Boat dimensions: 12m x 3.5m x 1.5m
CM Backstay antenna (insulated)
CE

GW  1  1   -6.0  -1.75  0.0   6.0  -1.75  0.0  0.01
GW  2  1    6.0  -1.75  0.0   6.0   1.75  0.0  0.01
GW  3  1    6.0   1.75  0.0  -6.0   1.75  0.0  0.01
GW  4  1   -6.0   1.75  0.0  -6.0  -1.75  0.0  0.01

GW  5  1   -6.0  -1.75  0.0  -6.0  -1.75  1.5  0.01
GW  6  1    6.0  -1.75  0.0   6.0  -1.75  1.5  0.01
GW  7  1    6.0   1.75  0.0   6.0   1.75  1.5  0.01
GW  8  1   -6.0   1.75  0.0  -6.0   1.75  1.5  0.01

GW  9  1   -6.0  -1.75  1.5   6.0  -1.75  1.5  0.01
GW 10  1    6.0  -1.75  1.5   6.0   1.75  1.5  0.01
GW 11  1    6.0   1.75  1.5  -6.0   1.75  1.5  0.01
GW 12  1   -6.0   1.75  1.5  -6.0  -1.75  1.5  0.01

CM Backstay antenna (12m vertical)
GW 13  5    0.0   0.0   1.5   0.0   0.0   13.5  0.005

GE  0
GD  0  0  0  0  5.0  81
EX  0  13  3  0  1.0  0.0
FR  0  1  0  0  3000.0  0
RP  0  37  73  1000  0.0  0.0  5.0  5.0  0.0  0.0
EN
```

### Example 3: Container Ship HF System

#### Vehicle Specifications
- **Type**: Container ship
- **Dimensions**: 200m x 32m x 15m
- **Antenna**: 80m loop antenna
- **Frequency**: 3-30 MHz (HF)
- **Environment**: Saltwater

#### EZNEC Model
```eznec
CM Container Ship with 80m Loop Antenna
CM Ship dimensions: 200m x 32m x 15m
CM 80m loop antenna on deck
CE

GW  1  1   -100.0  -16.0  0.0   100.0  -16.0  0.0  0.01
GW  2  1    100.0  -16.0  0.0   100.0   16.0  0.0  0.01
GW  3  1    100.0   16.0  0.0  -100.0   16.0  0.0  0.01
GW  4  1   -100.0   16.0  0.0  -100.0  -16.0  0.0  0.01

GW  5  1   -100.0  -16.0  0.0  -100.0  -16.0  15.0  0.01
GW  6  1    100.0  -16.0  0.0   100.0  -16.0  15.0  0.01
GW  7  1    100.0   16.0  0.0   100.0   16.0  15.0  0.01
GW  8  1   -100.0   16.0  0.0  -100.0   16.0  15.0  0.01

GW  9  1   -100.0  -16.0  15.0   100.0  -16.0  15.0  0.01
GW 10  1    100.0  -16.0  15.0   100.0   16.0  15.0  0.01
GW 11  1    100.0   16.0  15.0  -100.0   16.0  15.0  0.01
GW 12  1   -100.0   16.0  15.0  -100.0  -16.0  15.0  0.01

CM 80m loop antenna (40m x 40m square)
GW 13  5   -20.0  -20.0  15.0   20.0  -20.0  15.0  0.01
GW 14  5    20.0  -20.0  15.0   20.0   20.0  15.0  0.01
GW 15  5    20.0   20.0  15.0  -20.0   20.0  15.0  0.01
GW 16  5   -20.0   20.0  15.0  -20.0  -20.0  15.0  0.01

GE  0
GD  0  0  0  0  5.0  81
EX  0  13  1  0  1.0  0.0
FR  0  1  0  0  3000.0  0
RP  0  37  73  1000  0.0  0.0  5.0  5.0  0.0  0.0
EN
```

## Pattern File Format

### Standard Pattern File Structure

```
# FGCom-mumble Far-Field Radiation Pattern
# Frequency: 3.0 MHz
# Altitude: 0 m
# Format: Theta Phi Gain_dBi H_Polarization V_Polarization
# Theta: Elevation angle (0-180 degrees)
# Phi: Azimuth angle (0-360 degrees)
# Gain: Antenna gain in dBi
# H_Polarization: Horizontal polarization component
# V_Polarization: Vertical polarization component
0.0 0.0 -15.2 0.8 0.6
0.0 5.0 -14.8 0.7 0.7
0.0 10.0 -14.1 0.6 0.8
...
```

### Data Points Requirements

- **Theta Range**: 0° to 180° (elevation)
- **Phi Range**: 0° to 360° (azimuth)
- **Step Size**: 5° (recommended)
- **Total Points**: 1,296 (37 × 35)
- **File Size**: 20-40 KB

### Quality Standards

- **Gain Range**: -20 to +10 dBi (typical)
- **Data Completeness**: All angles covered
- **Format Consistency**: Standard header and data format
- **Numerical Accuracy**: 3 decimal places minimum

## Integration with FGCom-mumble

### Directory Structure

```
antenna_patterns/
├── aircraft/
│   ├── cessna_172/
│   │   ├── cessna_172.ez
│   │   └── patterns/
│   │       ├── 0m/
│   │       │   ├── cessna_172_130.0MHz_0m_pattern.txt
│   │       │   └── cessna_172_118.0MHz_0m_pattern.txt
│   │       ├── 1000m/
│   │       └── 5000m/
├── boat/
│   ├── sailboat/
│   │   ├── sailboat.ez
│   │   └── patterns/
│   │       ├── 3.0mhz/
│   │       └── 7.0mhz/
└── ship/
    ├── containership/
    │   ├── containership.ez
    │   └── patterns/
    │       ├── 3.0mhz/
    │       └── 14.0mhz/
```

### Pattern Loading Code

```cpp
// Load pattern for specific vehicle and frequency
std::string pattern_file = "antenna_patterns/aircraft/cessna_172/patterns/0m/cessna_172_130.0MHz_0m_pattern.txt";

FGCom_RadiationPattern pattern;
if (pattern.loadPattern(pattern_file)) {
    // Get gain for specific direction
    float gain = pattern.getGain(theta, phi);
    
    // Apply to radio propagation calculation
    float signal_strength = calculateSignalStrength(gain, distance, frequency);
}
```

### Vehicle Type Detection

```cpp
std::string detectVehicleType(const std::string& vehicle_name) {
    if (vehicle_name.find("cessna") != std::string::npos ||
        vehicle_name.find("boeing") != std::string::npos ||
        vehicle_name.find("airbus") != std::string::npos) {
        return "aircraft";
    }
    else if (vehicle_name.find("sailboat") != std::string::npos ||
             vehicle_name.find("yacht") != std::string::npos) {
        return "boat";
    }
    else if (vehicle_name.find("ship") != std::string::npos ||
             vehicle_name.find("vessel") != std::string::npos) {
        return "ship";
    }
    else if (vehicle_name.find("jeep") != std::string::npos ||
             vehicle_name.find("tank") != std::string::npos) {
        return "military_land";
    }
    else {
        return "ground_vehicle";
    }
}
```

## Troubleshooting and Quality Control

### Common Issues

#### 1. Simulation Failures
- **Problem**: NEC2 simulation fails
- **Causes**: Invalid geometry, frequency issues, ground parameters
- **Solutions**: 
  - Check wire geometry for overlaps
  - Verify frequency is in valid range
  - Ensure proper ground parameters

#### 2. Unrealistic Patterns
- **Problem**: Patterns show impossible gains or nulls
- **Causes**: Poor geometry, incorrect excitation, ground issues
- **Solutions**:
  - Simplify geometry
  - Check excitation location
  - Verify ground parameters

#### 3. File Format Errors
- **Problem**: Pattern files not loading
- **Causes**: Incorrect format, missing headers, data errors
- **Solutions**:
  - Verify file format matches specification
  - Check header information
  - Validate data ranges

### Quality Control Checklist

#### Before Simulation
- [ ] Vehicle dimensions realistic
- [ ] Antenna geometry correct
- [ ] Ground parameters appropriate
- [ ] Frequency in valid range
- [ ] Excitation properly placed

#### After Simulation
- [ ] Pattern file created successfully
- [ ] File size reasonable (20-40 KB)
- [ ] Gain values realistic (-20 to +10 dBi)
- [ ] All angles covered (0-180°, 0-360°)
- [ ] No missing data points

#### Integration Testing
- [ ] Pattern loads without errors
- [ ] Gain values reasonable for direction
- [ ] Frequency matching works
- [ ] Vehicle type detection correct

### Performance Optimization

#### Model Simplification
- **Wire Count**: Keep under 50 wires for speed
- **Segmentation**: Use minimum required segments
- **Geometry**: Simplify complex shapes
- **Frequency**: Use single frequency per model

#### Batch Processing
- **Parallel Processing**: Use multiple CPU cores
- **Script Automation**: Automate repetitive tasks
- **Error Handling**: Implement robust error checking
- **Progress Tracking**: Monitor generation progress

## Advanced Topics

### Multi-Frequency Patterns
- Generate patterns for multiple frequencies
- Interpolate between frequencies
- Handle frequency-dependent behavior

### Altitude-Dependent Patterns (Aircraft)
- Generate patterns at multiple altitudes
- Interpolate between altitudes
- Handle ground effects at low altitude

### Environmental Effects
- Different ground types
- Weather effects
- Atmospheric conditions
- Terrain effects

### Pattern Optimization
- Antenna placement optimization
- Gain pattern optimization
- SWR optimization
- Bandwidth optimization

## Conclusion

Creating radiation pattern files for FGCom-mumble requires understanding of:
- **Antenna theory and electromagnetic modeling**
- **EZNEC/NEC2 software and syntax**
- **Vehicle-specific requirements**
- **Pattern file formats and integration**

This guide provides the foundation for creating accurate, realistic radiation patterns that enhance the FGCom-mumble simulation experience.

For additional help and examples, refer to the existing documentation in the `docs/` directory and the pattern generation scripts in the `client/mumble-plugin/lib/` directory.
