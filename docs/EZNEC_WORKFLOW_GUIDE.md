# Complete EZNEC Workflow Guide for FGCom-mumble

## Overview

This document provides a comprehensive, step-by-step guide for using EZNEC to create radiation pattern files for FGCom-mumble. It covers the complete workflow from initial model creation to final pattern integration.

**✅ CURRENT STATUS**: The automated pattern generation system has been updated and is now working correctly. The script `scripts/pattern_generation/simplified_nec_generator.sh` now uses `.nec` files exclusively and properly generates patterns at multiple altitudes for aircraft with parallel processing support.

## Table of Contents

1. [EZNEC Basics](#eznec-basics)
2. [Model Creation Workflow](#model-creation-workflow)
3. [Pattern Generation Workflow](#pattern-generation-workflow)
4. [Quality Control](#quality-control)
5. [Integration with FGCom-mumble](#integration-with-fgcom-mumble)
6. [Troubleshooting](#troubleshooting)
7. [Advanced Techniques](#advanced-techniques)

## EZNEC Basics

### What is EZNEC?

EZNEC (Easy NEC) is a commercial antenna modeling software that uses the NEC (Numerical Electromagnetics Code) engine to calculate antenna radiation patterns. It's widely used in the amateur radio community for antenna design and analysis.

### Key Concepts

#### Wire Geometry
- **Wires**: Basic building blocks of antenna models
- **Segments**: Wires are divided into segments for calculation
- **Coordinates**: 3D coordinates define wire positions
- **Radius**: Wire radius affects calculations

#### Ground Systems
- **Perfect Ground**: Ideal conductor (σ = ∞)
- **Real Ground**: Finite conductivity and permittivity
- **Free Space**: No ground effects

#### Excitation
- **Voltage Source**: Applied voltage to antenna
- **Current Source**: Applied current to antenna
- **Impedance**: Antenna input impedance

### EZNEC File Format

#### Basic Structure
```
CM Comments (optional)
CE
GW  Wire_Number  Segments  X1  Y1  Z1  X2  Y2  Z2  Radius
GE  Ground_Type
EX  Source_Type  Wire  Segment  Voltage_Real  Voltage_Imag
FR  Frequency_Type  Frequency_Count  Start_Frequency  End_Frequency  Step_Frequency
RP  Calculation_Type  Theta_Count  Phi_Count  Distance  Theta_Start  Theta_End  Phi_Start  Phi_End
EN
```

#### Example EZNEC File
```
CM Simple VHF Antenna Model
CM Frequency: 144 MHz
CE

GW  1  5    0.0   0.0   0.0   0.0   0.0   0.52  0.005

GE  0
EX  0  1  3  0  1.0  0.0
FR  0  1  0  0  144000.0  0
RP  0  37  73  1000  0.0  0.0  5.0  5.0  0.0  0.0
EN
```

## Model Creation Workflow

### Step 1: Planning and Research

#### Define Vehicle Specifications
```
Vehicle Type: [Aircraft/Boat/Ship/Ground Vehicle/Military]
Dimensions: [Length x Width x Height]
Antenna Type: [Whip/Blade/Vertical/Loop/etc.]
Frequency Range: [e.g., 3-30 MHz for HF]
Operating Environment: [Land/Sea/Air]
```

#### Research Real-World Antennas
- **Aircraft**: Study actual aircraft antenna installations
- **Maritime**: Research ship antenna systems
- **Ground**: Look at mobile radio installations
- **Military**: Study tactical communication systems

#### Determine Ground Characteristics
- **Saltwater**: σ = 5 S/m, εᵣ = 81 (ships, coastal)
- **Average Soil**: σ = 0.005 S/m, εᵣ = 13 (typical land)
- **Poor Ground**: σ = 0.001 S/m, εᵣ = 5 (dry, rocky)
- **Free Space**: No ground effects (high altitude)

### Step 2: Create Vehicle Structure

#### Basic Vehicle Wireframe

**Example: NATO Jeep Structure**
```eznec
CM NATO Jeep Vehicle Structure
CM Vehicle dimensions: 4.2m x 1.8m x 1.5m
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

#### Wire Parameters
- **Wire Number**: Sequential numbering (1, 2, 3, ...)
- **Segments**: Number of segments per wire
- **Coordinates**: Start (X1,Y1,Z1) and end (X2,Y2,Z2) points
- **Radius**: Wire radius in meters

#### Segmentation Guidelines
- **Minimum**: 10 segments per wavelength
- **Typical**: 20-50 segments per wavelength
- **Maximum**: 1000 segments total
- **Balance**: Accuracy vs. computation time

### Step 3: Add Antenna Geometry

#### Vertical Whip Antenna
```eznec
CM Vertical whip antenna (0.25m at 300 MHz)
GW 13  5    0.0   0.0   1.5   0.0   0.0   1.75  0.005
```

#### Tied-Down Antenna (45°)
```eznec
CM 10ft whip antenna at 45 degree angle
GW 13  5    0.0   0.0   1.5   2.12  2.12  3.62  0.005
```

#### Loop Antenna
```eznec
CM 80m loop antenna (40m x 40m square)
GW 13  5   -20.0  -20.0  15.0   20.0  -20.0  15.0  0.01
GW 14  5    20.0  -20.0  15.0   20.0   20.0  15.0  0.01
GW 15  5    20.0   20.0  15.0  -20.0   20.0  15.0  0.01
GW 16  5   -20.0   20.0  15.0  -20.0  -20.0  15.0  0.01
```

### Step 4: Set Ground Parameters

#### Ground Definition
```eznec
GD  0  0  0  0  Conductivity  Permittivity
```

#### Ground Types
- **Perfect Ground**: `GD 0 0 0 0 0.0 1.0`
- **Saltwater**: `GD 0 0 0 0 5.0 81`
- **Average Soil**: `GD 0 0 0 0 0.005 13`
- **Poor Ground**: `GD 0 0 0 0 0.001 5`
- **Free Space**: `GD 0 0 0 0 0.0 1.0`

#### Historical Coastal Radio Stations
- **Massive Scale**: T-shaped antennas with 150m+ height, 195m+ top wire
- **Power Levels**: 10 kW+ for intercontinental communication
- **Ground Systems**: Extensive buried radial systems (120+ radials, 200m+ each)
- **Modeling Challenges**: Large scale requires careful segmentation and ground modeling
- **Examples**: Bergen Radio (LGN), Norddeich Radio (DAN), Portishead Radio (GKB)

**Important Note**: The examples provided are simplified models of historical coastal radio stations. In reality, these stations were much more complex, featuring:
- **Multiple Antenna Systems**: Various antennas for different frequency bands and purposes
- **Sophisticated Switching**: Complex switching systems to route signals to different antennas
- **Multiple Operators**: Teams of radio operators working around the clock
- **Advanced Ground Systems**: Elaborate buried radial networks and counterpoise systems
- **Backup Systems**: Redundant antennas and equipment for reliability
- **Directional Arrays**: Phased arrays and directional antennas for specific routes
- **Power Distribution**: Complex power distribution systems for multiple transmitters

### Step 5: Define Excitation

#### Voltage Source
```eznec
EX  0  Wire_Number  Segment_Number  0  Voltage_Real  Voltage_Imag
```

#### Current Source
```eznec
EX  1  Wire_Number  Segment_Number  0  Current_Real  Current_Imag
```

#### Excitation Guidelines
- **Wire Number**: Antenna wire number
- **Segment**: Middle segment of antenna
- **Voltage**: 1.0 V (typical)
- **Phase**: 0.0 (typical)

### Step 6: Set Frequency

#### Single Frequency
```eznec
FR  0  1  0  0  Frequency_kHz  0
```

#### Frequency Sweep
```eznec
FR  0  1  0  0  Start_Frequency  End_Frequency
```

#### Frequency Guidelines
- **Units**: Frequency in kHz
- **Range**: 3-300,000 kHz (3 Hz - 300 GHz)
- **Step**: Use single frequency for pattern generation

### Step 7: Calculate Radiation Pattern

#### Pattern Calculation
```eznec
RP  0  Theta_Count  Phi_Count  Distance  Theta_Start  Theta_End  Phi_Start  Phi_End
```

#### Pattern Parameters
- **Theta Count**: 37 (0-180° in 5° steps)
- **Phi Count**: 73 (0-360° in 5° steps)
- **Distance**: 1000 (far-field distance)
- **Theta Range**: 0-180° (elevation)
- **Phi Range**: 0-360° (azimuth)

## Pattern Generation Workflow

### Step 1: Create Frequency-Specific Models

#### Manual Creation
```bash
# Copy base model
cp vehicle.ez vehicle_3000kHz.ez

# Update frequency
sed -i "s/^FR.*/FR 0 1 0 0 3000.0 0/" vehicle_3000kHz.ez
```

#### Automated Creation
```bash
#!/bin/bash
# Generate frequency-specific models

frequencies=(3000 5000 7000 10000 14000 18000 21000 28000)

for freq in "${frequencies[@]}"; do
    echo "Creating model for ${freq} kHz"
    
    # Copy base model
    cp vehicle.ez vehicle_${freq}kHz.ez
    
    # Update frequency
    sed -i "s/^FR.*/FR 0 1 0 0 ${freq}.0 0/" vehicle_${freq}kHz.ez
    
    # Update ground parameters if needed
    if [ $freq -lt 10000 ]; then
        # HF frequencies - use real ground
        sed -i "s/^GD.*/GD  0  0  0  0  0.005  13/" vehicle_${freq}kHz.ez
    else
        # VHF frequencies - use perfect ground
        sed -i "s/^GD.*/GD  0  0  0  0  0.0  1.0/" vehicle_${freq}kHz.ez
    fi
done
```

### Step 2: Convert to NEC2 Format

#### EZNEC2NEC Conversion
```bash
# Convert single file
./eznec2nec.sh vehicle_3000kHz.ez

# Convert multiple files
for file in *.ez; do
    ./eznec2nec.sh "$file"
done
```

#### Conversion Script
```bash
#!/bin/bash
# EZNEC to NEC2 conversion script

input_file="$1"
output_file="${input_file%.ez}.nec"

if [ -z "$input_file" ]; then
    echo "Usage: $0 <input.ez>"
    exit 1
fi

# Convert EZNEC format to NEC2 format
# This is a simplified conversion - actual implementation would be more complex

echo "Converting $input_file to $output_file"

# Copy file and modify format
cp "$input_file" "$output_file"

# Convert EZNEC format to NEC2 format
# (Implementation details would go here)

echo "Conversion complete: $output_file"
```

### Step 3: Run NEC2 Simulation

#### Single Simulation
```bash
# Run simulation
nec2c -i vehicle_3000kHz.nec -o vehicle_3000kHz.out

# Check for errors
if [ $? -ne 0 ]; then
    echo "Simulation failed for frequency 3000 kHz"
    exit 1
fi
```

#### Batch Simulation
```bash
#!/bin/bash
# Batch NEC2 simulation

for file in *.nec; do
    echo "Running simulation for $file"
    
    # Run simulation
    nec2c -i "$file" -o "${file%.nec}.out"
    
    # Check for errors
    if [ $? -ne 0 ]; then
        echo "ERROR: Simulation failed for $file"
        continue
    fi
    
    echo "Simulation complete: ${file%.nec}.out"
done
```

### Step 4: Extract Radiation Pattern

#### Pattern Extraction Script
```bash
#!/bin/bash
# Extract radiation pattern from NEC2 output

input_file="$1"
output_file="$2"
frequency="$3"
altitude="$4"

if [ -z "$input_file" ] || [ -z "$output_file" ]; then
    echo "Usage: $0 <input.out> <output.txt> <frequency> <altitude>"
    exit 1
fi

echo "Extracting pattern from $input_file"

# Create header
cat > "$output_file" << EOF
# FGCom-mumble Far-Field Radiation Pattern
# Frequency: ${frequency} MHz
# Altitude: ${altitude} m
# Format: Theta Phi Gain_dBi H_Polarization V_Polarization
# Theta: Elevation angle (0-180 degrees)
# Phi: Azimuth angle (0-360 degrees)
# Gain: Antenna gain in dBi
# H_Polarization: Horizontal polarization component
# V_Polarization: Vertical polarization component
EOF

# Extract pattern data
grep "RADIATION PATTERN" -A 1000 "$input_file" | \
grep -E "^[[:space:]]*[0-9]" | \
awk '{print $1, $2, $3, $4, $5}' >> "$output_file"

echo "Pattern extraction complete: $output_file"
```

#### Usage
```bash
# Extract single pattern
./extract_pattern.sh vehicle_3000kHz.out vehicle_3000kHz_pattern.txt 3.0 0

# Extract multiple patterns
for file in *.out; do
    ./extract_pattern.sh "$file" "${file%.out}_pattern.txt" 3.0 0
done
```

### Step 5: Aircraft Altitude Variations

#### Altitude-Specific Patterns
```bash
#!/bin/bash
# Generate altitude-dependent patterns for aircraft

altitudes=(0 100 500 1000 2000 3000 5000 8000 10000)

for alt in "${altitudes[@]}"; do
    echo "Generating patterns for altitude ${alt}m"
    
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

## Quality Control

### Pattern File Validation

#### File Size Check
```bash
# Check file size (should be 20-40 KB)
size=$(stat -c%s "$file")
if [ $size -lt 20000 ] || [ $size -gt 40000 ]; then
    echo "WARNING: File size unusual ($size bytes)"
fi
```

#### Data Point Count
```bash
# Check data point count (should be 1000+)
data_lines=$(grep -v "^#" "$file" | wc -l)
if [ $data_lines -lt 1000 ]; then
    echo "ERROR: Insufficient data points ($data_lines)"
fi
```

#### Gain Range Check
```bash
# Check gain range (should be -20 to +10 dBi)
min_gain=$(grep -v "^#" "$file" | awk '{print $3}' | sort -n | head -1)
max_gain=$(grep -v "^#" "$file" | awk '{print $3}' | sort -n | tail -1)

if (( $(echo "$min_gain < -30" | bc -l) )) || (( $(echo "$max_gain > 20" | bc -l) )); then
    echo "WARNING: Gain range unusual ($min_gain to $max_gain dBi)"
fi
```

### Pattern Quality Standards

#### Required Elements
- **Header**: Complete header with frequency and altitude
- **Data Format**: Correct format with 5 columns
- **Data Completeness**: All angles covered (0-180°, 0-360°)
- **Numerical Accuracy**: 3 decimal places minimum

#### Quality Metrics
- **File Size**: 20-40 KB
- **Data Points**: 1,000+ radiation points
- **Gain Range**: -20 to +10 dBi
- **Format Consistency**: Standard header and data format

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

## Troubleshooting

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

### Debugging Steps

#### 1. Check EZNEC Model
```bash
# Validate EZNEC file format
grep -E "^(GW|GE|EX|FR|RP)" model.ez

# Check for common errors
grep -i "error" model.ez
grep -i "warning" model.ez
```

#### 2. Check NEC2 Output
```bash
# Check for simulation errors
grep -i "error" model.out
grep -i "warning" model.out

# Check for convergence issues
grep -i "convergence" model.out
```

#### 3. Validate Pattern File
```bash
# Check file format
head -10 pattern.txt

# Check data completeness
wc -l pattern.txt

# Check gain range
awk '{print $3}' pattern.txt | sort -n | head -1
awk '{print $3}' pattern.txt | sort -n | tail -1
```

## Advanced Techniques

### Multi-Frequency Patterns

#### Frequency Interpolation
```cpp
// Interpolate between frequencies
double interpolateFrequency(double freq1, double freq2, double gain1, double gain2, double target_freq) {
    double ratio = (target_freq - freq1) / (freq2 - freq1);
    return gain1 + ratio * (gain2 - gain1);
}
```

#### Frequency Selection
```cpp
// Select appropriate frequency pattern
std::string selectFrequencyPattern(double frequency_mhz) {
    if (frequency_mhz < 10.0) {
        return "3.0mhz";
    } else if (frequency_mhz < 20.0) {
        return "14.0mhz";
    } else if (frequency_mhz < 50.0) {
        return "28.0mhz";
    } else {
        return "144.0mhz";
    }
}
```

### Altitude Interpolation

#### Altitude Selection
```cpp
// Select appropriate altitude pattern
std::string selectAltitudePattern(double altitude_m) {
    if (altitude_m < 100.0) {
        return "0m";
    } else if (altitude_m < 500.0) {
        return "100m";
    } else if (altitude_m < 1000.0) {
        return "500m";
    } else if (altitude_m < 2000.0) {
        return "1000m";
    } else if (altitude_m < 5000.0) {
        return "2000m";
    } else {
        return "5000m";
    }
}
```

#### Altitude Interpolation
```cpp
// Interpolate between altitudes
double interpolateAltitude(double alt1, double alt2, double gain1, double gain2, double target_alt) {
    double ratio = (target_alt - alt1) / (alt2 - alt1);
    return gain1 + ratio * (gain2 - gain1);
}
```

### Pattern Optimization

#### Antenna Placement
```cpp
// Optimize antenna placement
struct AntennaPosition {
    double x, y, z;
    double gain;
};

std::vector<AntennaPosition> optimizeAntennaPlacement(const std::string& vehicle_type) {
    // Implementation would test different antenna positions
    // and select the one with best overall gain
}
```

#### Gain Optimization
```cpp
// Optimize antenna gain
double optimizeGain(const std::string& vehicle_type, double frequency_mhz) {
    // Implementation would test different antenna configurations
    // and select the one with best gain
}
```

## Conclusion

This guide provides a complete workflow for using EZNEC to create radiation pattern files for FGCom-mumble:

1. **Model Creation**: Design accurate electromagnetic models
2. **Pattern Generation**: Generate patterns for multiple frequencies and altitudes
3. **Quality Control**: Validate patterns for accuracy and completeness
4. **Integration**: Load patterns into FGCom-mumble system

The workflow can be adapted for different vehicle types and requirements, providing a solid foundation for creating realistic antenna patterns that enhance the FGCom-mumble simulation experience.

For additional help and examples, refer to the existing documentation in the `docs/` directory and the pattern generation scripts in the `client/mumble-plugin/lib/` directory.
