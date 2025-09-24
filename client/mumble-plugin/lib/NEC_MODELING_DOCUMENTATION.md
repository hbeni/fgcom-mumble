# NEC Modeling and Antenna Calculations Documentation

## Overview

This document provides comprehensive guidance for creating NEC (Numerical Electromagnetics Code) models for antenna simulation, including wavelength calculations, minimum spacing requirements, and practical examples for various vehicle types.

## VHF/UHF Professional Antennas

### New Professional Antenna Models

The system now includes professional-grade VHF/UHF antennas with 10m height modeling:

#### **2m Yagi Antenna (144-145 MHz)**
- **11-Element Design**: 1 reflector, 1 driven, 9 directors
- **Gain**: 14.8 dBi
- **Height**: 10m above ground
- **Applications**: VHF weak signal, contest operations, DXpeditions
- **File**: `antenna_patterns/Ground-based/yagi_144mhz/yagi_144mhz_11element.ez`

#### **70cm Yagi Antenna (430-440 MHz)**
- **16-Element Design**: 1 reflector, 1 driven, 14 directors
- **Gain**: 16.56 dBi (free space)
- **Height**: 10m above ground
- **Applications**: UHF weak signal, satellite communication, EME operations
- **File**: `antenna_patterns/Ground-based/yagi_70cm/yagi_70cm_16element.ez`

#### **Dual-Band Omnidirectional (2m/70cm)**
- **Collinear Design**: Omnidirectional coverage
- **VHF Gain**: 8.3 dBi @ 144 MHz
- **UHF Gain**: 11.7 dBi @ 432 MHz
- **Height**: 10m above ground
- **Applications**: Repeater sites, base stations, emergency communications
- **File**: `antenna_patterns/Ground-based/dual_band_omni/dual_band_omni_2m_70cm.ez`

### Professional Height Modeling

All new antennas are positioned **10 meters above ground level**, providing:
- **2-3x range extension** compared to ground level
- **Professional base station performance**
- **Clean radiation patterns** with minimal ground distortion
- **Realistic propagation modeling** for flight simulation

## Wavelength Calculations

### Basic Formula

The wavelength (λ) calculation is straightforward using the fundamental wave equation:

**λ = c / f**

Where:
- **λ** = wavelength (meters)
- **c** = speed of light = 299,792,458 m/s (≈ 3 × 10⁸ m/s)
- **f** = frequency (Hz)

### Practical Examples

**300 MHz:**
- λ = 299,792,458 / 300,000,000 = 1.0 meter

**1 GHz (1,000 MHz):**
- λ = 299,792,458 / 1,000,000,000 = 0.3 meter (30 cm)

**2.4 GHz (WiFi):**
- λ = 299,792,458 / 2,400,000,000 = 0.125 meter (12.5 cm)

### Quick Approximation

For engineering work, you can use:
**λ ≈ 300 / f(MHz)**

This gives wavelength in meters when frequency is in MHz.

**Examples:**
- 300 MHz: λ ≈ 300/300 = 1.0 m
- 900 MHz: λ ≈ 300/900 = 0.33 m
- 2400 MHz: λ ≈ 300/2400 = 0.125 m

## Minimum Spacing Requirements

### NEC Simulation Guidelines

For NEC simulations, the recommended minimum spacing between wire segments is:
**λ/10 to λ/20** (wavelength/10 to wavelength/20)

**At the highest used frequency:**

**Example: 300 MHz: λ = 1m → minimum spacing = 5-10 cm**

### Frequency-Specific Examples

| Frequency | Wavelength | Minimum Spacing (λ/20) | Minimum Spacing (λ/10) |
|-----------|------------|------------------------|------------------------|
| 30 MHz    | 10.0 m     | 50 cm                  | 100 cm                 |
| 100 MHz   | 3.0 m      | 15 cm                  | 30 cm                  |
| 300 MHz   | 1.0 m      | 5 cm                   | 10 cm                  |
| 1 GHz     | 0.3 m      | 1.5 cm                 | 3 cm                   |
| 2.4 GHz   | 0.125 m    | 0.625 cm               | 1.25 cm                |

## Common Antenna Lengths

### Standard Antenna Types

- **Quarter-wave (λ/4)**: Most common for vehicle antennas
- **Half-wave (λ/2)**: Good for dipoles
- **Full-wave (λ)**: Loop antennas

### Practical Examples for 300 MHz

- **λ = 1m**
- **λ/4 = 0.25m** (quarter-wave antenna length)
- **Minimum wire spacing = λ/10 to λ/20 = 5-10 cm**

## Basic Tank Model for NEC Simulation

Here's a comprehensive guide for creating a basic tank model for NEC simulation:

### Model Components

1. **Tank body**: A simple rectangular box (4m × 2m × 1.5m) made of 12 wire segments forming the edges
2. **Antenna**: A quarter-wave vertical antenna (0.25m at 300 MHz) mounted on top center

### Key NEC Commands

- **GW (Geometry Wire)**: Defines wire segments for the tank structure and antenna
- **GE (Geometry End)**: Marks end of geometry definition
- **EX (Excitation)**: Applies voltage source to antenna segment 13, segment 3 (middle)
- **FR (Frequency)**: Sets frequency to 300 MHz
- **RP (Radiation Pattern)**: Calculates radiation pattern

### Wire Parameters

- **Tank edges**: Use 0.01m radius wires
- **Antenna**: Use 0.005m radius (thinner)
- **Antenna segmentation**: Segment into 5 parts for better accuracy

### Complete NEC Model Example

```nec
CM Basic Tank Model for NEC Simulation
CM Simple rectangular box with 1/4 wave antenna
CM Frequency: 300 MHz (1 meter wavelength)
CM Tank dimensions: 4m x 2m x 1.5m
CM Quarter-wave antenna: 0.25m vertical
CE

GW  1  1   -2.0  -1.0   0.0   2.0  -1.0   0.0  0.01
GW  2  1    2.0  -1.0   0.0   2.0   1.0   0.0  0.01
GW  3  1    2.0   1.0   0.0  -2.0   1.0   0.0  0.01
GW  4  1   -2.0   1.0   0.0  -2.0  -1.0   0.0  0.01

GW  5  1   -2.0  -1.0   0.0  -2.0  -1.0   1.5  0.01
GW  6  1    2.0  -1.0   0.0   2.0  -1.0   1.5  0.01
GW  7  1    2.0   1.0   0.0   2.0   1.0   1.5  0.01
GW  8  1   -2.0   1.0   0.0  -2.0   1.0   1.5  0.01

GW  9  1   -2.0  -1.0   1.5   2.0  -1.0   1.5  0.01
GW 10  1    2.0  -1.0   1.5   2.0   1.0   1.5  0.01
GW 11  1    2.0   1.0   1.5  -2.0   1.0   1.5  0.01
GW 12  1   -2.0   1.0   1.5  -2.0  -1.0   1.5  0.01

GW 13  1   -2.0  -1.0   0.0   2.0  -1.0   0.0  0.01
GW 14  1    2.0  -1.0   0.0   2.0   1.0   0.0  0.01
GW 15  1    2.0   1.0   0.0  -2.0   1.0   0.0  0.01
GW 16  1   -2.0   1.0   0.0  -2.0  -1.0   0.0  0.01

GW 17  5    0.0   0.0   1.5   0.0   0.0   1.75  0.005

GE  0

EX  0  17  3  0  1.0  0.0

FR  0  1  0  0  300.0  0

RP  0  37  73  1000  0.0  0.0  5.0  5.0  0.0  0.0

EN
```

### Model Explanation

#### Tank Structure (Wires 1-16)
- **Bottom face** (wires 1-4): Forms the rectangular base
- **Vertical edges** (wires 5-8): Connect bottom to top
- **Top face** (wires 9-12): Forms the rectangular top
- **Additional bottom wires** (wires 13-16): Provide ground plane effect

#### Antenna (Wire 17)
- **Length**: 0.25m (quarter-wave at 300 MHz)
- **Position**: Center of tank top (0.0, 0.0, 1.5m to 1.75m)
- **Segments**: 5 segments for accurate modeling
- **Radius**: 0.005m (thinner than tank structure)

#### Excitation and Analysis
- **EX command**: Excites wire 17, segment 3 (middle of antenna)
- **FR command**: Sets frequency to 300 MHz
- **RP command**: Calculates radiation pattern with 37 theta angles, 73 phi angles

### Usage Notes

1. **Save as .nec file**: Use this format for NEC-2/NEC-4 compatibility
2. **Tank as ground plane**: The tank acts as a ground plane/reflector
3. **Adjustable dimensions**: Modify coordinate values to change tank size
4. **Frequency scaling**: For different frequencies, scale the antenna length (λ/4)
5. **Enhanced modeling**: Add more segments for curved surfaces and surface features

### Advanced Modeling Considerations

#### Realistic Tank Features
- **Bottom plate**: Essential for realistic modeling
- **Current path completion**: Provides return path for antenna currents
- **Shielding effects**: Bottom affects radiation patterns significantly
- **Ground interaction**: Changes how the tank couples to ground

#### Multi-Frequency Analysis
For broadband analysis, create multiple models:
- **Low frequency**: Use longer segments, larger spacing
- **High frequency**: Use shorter segments, smaller spacing
- **Compromise**: Use frequency-dependent segmentation

#### Antenna Tuner Integration
- **Non-resonant antennas**: Model antennas that require tuning
- **SWR simulation**: Include matching networks
- **Multi-band operation**: Model antennas for multiple frequencies

### Performance Optimization

#### Segmentation Guidelines
- **Minimum segments**: At least 10 segments per wavelength
- **Maximum segments**: Balance accuracy vs. computation time
- **Segment length**: Keep segments shorter than λ/10

#### Memory and Computation
- **Wire count**: Limit total wires for reasonable computation time
- **Frequency range**: Analyze only necessary frequency range
- **Pattern resolution**: Balance accuracy vs. computation time

### Common Issues and Solutions

#### Convergence Problems
- **Segment length**: Ensure segments are not too long
- **Wire radius**: Use appropriate wire radius for frequency
- **Ground modeling**: Include proper ground plane

#### Unrealistic Results
- **Missing bottom**: Always include vehicle bottom
- **Insufficient segmentation**: Use adequate segment density
- **Wrong excitation**: Place source at appropriate location

#### Performance Issues
- **Too many segments**: Reduce segment count for faster computation
- **High frequency**: Use appropriate frequency range
- **Complex geometry**: Simplify model if possible

### Integration with FGCom-mumble

#### Pattern File Generation
1. **Run NEC simulation**: Generate .out file
2. **Extract patterns**: Use pattern extraction tools
3. **Format for FGCom**: Convert to FGCom pattern format
4. **Store in database**: Place in appropriate antenna pattern directory

#### Altitude-Dependent Patterns
1. **Ground parameters**: Vary ground conductivity with altitude
2. **Multiple models**: Create models for different altitudes
3. **Interpolation**: Use altitude interpolation for smooth transitions

#### Real-Time Updates
1. **Pattern caching**: Cache frequently used patterns
2. **Lazy loading**: Load patterns on demand
3. **Memory management**: Manage pattern memory efficiently

This basic model will give you antenna patterns and impedance characteristics for a vehicle-mounted antenna scenario, providing a foundation for more complex modeling in the FGCom-mumble system.

## Pattern Generation Workflow

### Overview

Creating antenna patterns for vehicles involves several steps:
1. **EZNEC Model Creation** - Define antenna geometry and vehicle structure
2. **Frequency-Specific Generation** - Create models for each operational frequency
3. **NEC2 Conversion** - Convert EZNEC format to NEC2 format
4. **Simulation** - Run `nec2c` to calculate radiation patterns
5. **Pattern Extraction** - Extract and format radiation pattern data

### Step-by-Step Pattern Generation

#### 1. EZNEC Model Requirements

**File Structure:**
```
antenna_patterns/
├── military-land/
│   ├── vehicle_name/
│   │   ├── vehicle_name.ez          # Main EZNEC model
│   │   └── vehicle_name_patterns/   # Generated patterns
│   │       ├── 3.0mhz/
│   │       ├── 5.0mhz/
│   │       ├── 7.0mhz/
│   │       └── 9.0mhz/
```

**EZNEC File Components:**
- **Wire Geometry (GW):** Define vehicle structure and antenna
- **Ground (GD):** Specify ground characteristics
- **Excitation (EX):** Define voltage source location
- **Frequency (FR):** Set operating frequency
- **Radiation Pattern (RP):** Calculate far-field pattern

#### 2. Military Vehicle Frequencies

**NATO Military Vehicles:**
- 3.0 MHz (3000 kHz) - Tactical communications
- 5.0 MHz (5000 kHz) - Medium-range tactical
- 7.0 MHz (7000 kHz) - Long-range tactical
- 9.0 MHz (9000 kHz) - Strategic communications

**Soviet/Eastern Bloc Vehicles:**
- 3.0 MHz (3000 kHz) - Tactical communications
- 5.0 MHz (5000 kHz) - Medium-range tactical
- 7.0 MHz (7000 kHz) - Long-range tactical
- 9.0 MHz (9000 kHz) - Strategic communications

#### 3. Pattern Generation Script

**Using `generate_military_vehicle_patterns.sh`:**

```bash
#!/bin/bash
# Generate patterns for military vehicles

# Process NATO Jeep
./generate_military_vehicle_patterns.sh

# Or process individual vehicles:
process_military_vehicle "antenna_patterns/military-land/nato_jeep_10ft_whip_45deg.ez" "NATO Jeep"
process_military_vehicle "antenna_patterns/military-land/soviet_uaz_4m_whip_45deg.ez" "Soviet UAZ"
```

**Script Functions:**
1. **Frequency Processing:** Creates frequency-specific EZNEC files
2. **NEC2 Conversion:** Uses `eznec2nec.sh` to convert format
3. **Simulation:** Runs `nec2c` for each frequency
4. **Pattern Extraction:** Uses `extract_pattern_advanced.sh` to extract radiation data

#### 4. Manual Pattern Generation

**Step 1: Create Frequency-Specific EZNEC**
```bash
# Copy base EZNEC file
cp vehicle.ez vehicle_3.0MHz.ez

# Update frequency in EZNEC file
sed -i "s/^FR.*/FR 0 1 0 0 3000.0 0/" vehicle_3.0MHz.ez
```

**Step 2: Convert to NEC2 Format**
```bash
./eznec2nec.sh vehicle_3.0MHz.ez
# Creates: vehicle_3.0MHz.nec
```

**Step 3: Run NEC2 Simulation**
```bash
# Run from within the directory (to avoid filename length issues)
cd frequency_directory/
nec2c -i vehicle_3.0MHz.nec -o vehicle_3.0MHz.out
```

**Step 4: Extract Radiation Pattern**
```bash
source extract_pattern_advanced.sh
extract_radiation_pattern_advanced vehicle_3.0MHz.out vehicle_3.0MHz_pattern.txt 3.0 0
```

#### 5. Pattern File Format

**Generated Pattern Files:**
- **Format:** ASCII text with header and data
- **Content:** Theta, Phi, Gain (dBi), H_Polarization, V_Polarization
- **Resolution:** Typically 5° increments in theta and phi
- **Size:** ~1,000-1,500 data points per pattern

**Example Pattern File Header:**
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
```

#### 6. Quality Control

**Verification Steps:**
1. **File Sizes:** Pattern files should be 20-40 KB
2. **Data Points:** Should contain 1,000+ radiation points
3. **Gain Range:** Typical gains -20 to +10 dBi
4. **Format Check:** Verify header and data format

**Common Issues:**
- **Filename Length:** `nec2c` has path length limitations
- **Frequency Format:** Ensure kHz values in EZNEC files
- **Ground Parameters:** Verify ground characteristics match vehicle type
- **Antenna Geometry:** Check wire segmentation and radius values

#### 7. Integration with FGCom-mumble

**Pattern Loading:**
```cpp
// Load pattern for specific frequency
FGCom_AntennaPattern pattern;
pattern.loadPattern("antenna_patterns/military-land/vehicle_patterns/3.0mhz/vehicle_3.0MHz_pattern.txt");

// Get gain for specific direction
float gain = pattern.getGain(theta, phi);
```

**Frequency Selection:**
```cpp
// Select appropriate pattern based on operating frequency
std::string pattern_file = selectPatternFile(vehicle_type, frequency_mhz);
```

### Automated Pattern Generation

#### Using Existing Scripts

**For Military Vehicles:**
```bash
# Generate all military vehicle patterns
./generate_military_vehicle_patterns.sh

# Generate specific vehicle patterns
./generate_leopard1_patterns.sh
./generate_t55_patterns.sh
```

**For Civilian Vehicles:**
```bash
# Generate all civilian patterns
./generate_all_patterns.sh

# Generate specific vehicle patterns
./generate_amateur_bands.sh
```

#### Script Features

**Multi-Core Processing:**
- Uses `xargs -P` for parallel processing
- Configurable CPU core usage
- Faster pattern generation

**Error Handling:**
- Comprehensive error checking and logging
- Automatic retry mechanisms for failed simulations
- Detailed error reporting for troubleshooting

## 3D Model Import and Conversion

### STL File Limitations

**Important Note**: Presently no known tool exists that can convert STL files to the required EZNEC file formats. STL files are designed for 3D printing and contain only surface mesh data, which is not suitable for electromagnetic modeling that requires wire-based geometry.

### Model Refinement Requirements

Note that many of the included EZNEC files may need refinement. If you have some experience with 3D modeling, that will make the process easier. The following skills are helpful:

- **Wire-based modeling**: Understanding how to represent 3D objects as wire frames
- **Electromagnetic concepts**: Basic understanding of antenna theory and RF principles
- **NEC/EZNEC syntax**: Familiarity with the command structure and parameters
- **Geometry optimization**: Knowing how to balance model accuracy with computational efficiency

### Recommended Tools for EZNEC File Creation

#### Cross-Platform Tools

**EZNEC (Roy Lewallen, W7EL)**
- **Platform**: Windows (primary), Linux (via Wine), macOS (via Wine/Parallels)
- **Type**: Commercial antenna modeling software
- **Features**: 
  - Native EZNEC file format support
  - Built-in antenna design tools
  - 3D visualization
  - Pattern analysis and optimization
- **Website**: http://www.eznec.com/
- **Cost**: Commercial license required

**4NEC2 (Arie Voors)**
- **Platform**: Windows
- **Type**: Free NEC2-based antenna modeling
- **Features**:
  - NEC2 engine with GUI
  - EZNEC file import/export
  - Advanced visualization
  - Scripting capabilities
- **Website**: https://www.qsl.net/4nec2/
- **Cost**: Free

#### Linux Tools

**NEC2C (NEC2 Engine)**
- **Platform**: Linux, Unix
- **Type**: Command-line NEC2 simulator
- **Features**:
  - Fast computation
  - Batch processing
  - Integration with shell scripts
- **Installation**: `sudo apt-get install nec2c` (Ubuntu/Debian)
- **Cost**: Free

**Python NEC2 Tools**
- **Platform**: Linux, cross-platform
- **Type**: Python libraries for NEC2
- **Features**:
  - `nec2python`: Python wrapper for NEC2
  - `pynec`: Python NEC2 interface
  - Custom script development
- **Installation**: `pip install nec2python pynec`
- **Cost**: Free

**GNURadio Companion**
- **Platform**: Linux
- **Type**: RF simulation framework
- **Features**:
  - Antenna pattern visualization
  - RF system modeling
  - Integration with NEC2
- **Installation**: `sudo apt-get install gnuradio`
- **Cost**: Free

#### Windows Tools

**EZNEC Pro**
- **Platform**: Windows
- **Type**: Professional antenna modeling
- **Features**:
  - Advanced antenna design
  - 3D pattern visualization
  - Optimization tools
  - Professional support
- **Website**: http://www.eznec.com/
- **Cost**: Commercial

**MMANA-GAL**
- **Platform**: Windows
- **Type**: Free antenna modeling
- **Features**:
  - NEC2-based engine
  - Japanese/English interface
  - Pattern analysis
  - EZNEC compatibility
- **Website**: https://mmhamsoft.amateur-radio.ca/
- **Cost**: Free

**Antenna Model**
- **Platform**: Windows
- **Type**: Educational antenna modeling
- **Features**:
  - Basic NEC2 functionality
  - Learning-oriented interface
  - Pattern visualization
- **Cost**: Free

#### macOS Tools

**EZNEC via Wine/Parallels**
- **Platform**: macOS
- **Type**: Windows EZNEC running in compatibility layer
- **Features**: Same as Windows EZNEC
- **Requirements**: Wine or Parallels Desktop
- **Cost**: Commercial (EZNEC) + compatibility software

**NEC2C via Homebrew**
- **Platform**: macOS
- **Type**: Command-line NEC2
- **Installation**: `brew install nec2c`
- **Features**: Same as Linux version
- **Cost**: Free

**Python Tools (Cross-platform)**
- **Platform**: macOS
- **Type**: Python-based NEC2 tools
- **Installation**: `pip install nec2python pynec`
- **Features**: Same as Linux Python tools
- **Cost**: Free

#### Web-Based Tools

**Online NEC2 Calculators**
- **Platform**: Web browser (any platform)
- **Type**: Online antenna modeling
- **Features**:
  - Basic NEC2 calculations
  - Simple antenna designs
  - Pattern visualization
- **Limitations**: Limited complexity, requires internet
- **Cost**: Usually free with limitations

### File Format Conversion

#### EZNEC to NEC2
- **Tool**: `eznec2nec.sh` (included in this project)
- **Usage**: `./eznec2nec.sh input.ez output.nec`
- **Features**: Automated conversion with error checking

#### NEC2 to EZNEC
- **Tool**: Manual conversion or custom scripts
- **Process**: Requires understanding of both formats
- **Complexity**: High - not recommended for beginners

### Model Creation Workflow

1. **Design Phase**:
   - Use 3D modeling software for initial geometry
   - Export to wire-based format
   - Plan antenna placement and feed points

2. **Conversion Phase**:
   - Convert geometry to EZNEC format
   - Define wire segments and connections
   - Set material properties and ground conditions

3. **Simulation Phase**:
   - Run NEC2 simulation
   - Analyze results and patterns
   - Optimize geometry if needed

4. **Integration Phase**:
   - Convert to FGCom-mumble format
   - Test with propagation engine
   - Validate against real-world measurements

### Best Practices

- **Start Simple**: Begin with basic geometries before complex models
- **Validate Results**: Compare with known antenna patterns
- **Optimize Segments**: Balance accuracy with computation time
- **Document Changes**: Keep track of model modifications
- **Test Thoroughly**: Verify patterns at multiple frequencies
- Automatic directory creation
- Consistent file naming
- Pattern file organization

### Troubleshooting Pattern Generation

#### Common Errors

**"Input file name too long"**
- **Cause:** `nec2c` has path length limitations
- **Solution:** Run `nec2c` from within the target directory
- **Fix:** Use `(cd "$freq_dir" && nec2c -i "$filename" -o "$output")`

**"NON-NUMERICAL CHARACTER"**
- **Cause:** Comments in EZNEC file not stripped
- **Solution:** Use `sed 's/;.*$//'` to remove comments
- **Fix:** Clean EZNEC files before conversion

**"Pattern extraction failed"**
- **Cause:** Incorrect function parameters
- **Solution:** Use correct parameter count for extraction function
- **Fix:** `extract_radiation_pattern_advanced input output frequency altitude`

#### Performance Optimization

**File Size Management:**
- Use shorter filenames to avoid path length issues
- Compress pattern files for storage
- Cache frequently used patterns

**Processing Speed:**
- Use multi-core processing for batch operations
- Parallel execution of independent simulations
- Optimize EZNEC models for faster computation

**Memory Usage:**
- Process patterns in batches
- Clean up temporary files
- Use streaming processing for large datasets

This comprehensive workflow ensures consistent, high-quality antenna patterns for all vehicles in the FGCom-mumble system, with proper documentation and troubleshooting guidance for pattern generation.
