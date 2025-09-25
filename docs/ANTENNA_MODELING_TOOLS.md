# Antenna Modeling Tools and Software for FGCom-mumble

## Overview

This document provides comprehensive information about tools and software available for creating radiation pattern files for FGCom-mumble. It covers commercial and free options, installation instructions, and usage examples.

**⚠️ CURRENT STATUS**: The automated pattern generation system is not working correctly. The script `scripts/pattern_generation/generate_all_patterns.sh` is not properly generating patterns at multiple altitudes for aircraft. Manual pattern creation is recommended until this issue is resolved.

## Table of Contents

1. [Commercial Software](#commercial-software)
2. [Free and Open Source Software](#free-and-open-source-software)
3. [Command Line Tools](#command-line-tools)
4. [Installation Instructions](#installation-instructions)
5. [Usage Examples](#usage-examples)
6. [Tool Comparison](#tool-comparison)
7. [Recommended Workflows](#recommended-workflows)

## Commercial Software

### EZNEC (Roy Lewallen, W7EL)

#### Overview
- **Platform**: Windows (primary), Linux/macOS via Wine
- **Type**: Commercial antenna modeling software
- **Cost**: ~$89 USD
- **Website**: http://www.eznec.com/

#### Features
- **Native EZNEC Format**: Direct support for .ez files
- **3D Visualization**: Interactive 3D antenna pattern display
- **Pattern Analysis**: Comprehensive radiation pattern analysis
- **Optimization Tools**: Built-in antenna optimization
- **Ground Modeling**: Advanced ground system modeling
- **Frequency Sweep**: Multi-frequency analysis
- **Export Options**: Multiple output formats

#### Advantages
- **User-Friendly**: Intuitive graphical interface
- **Comprehensive**: Complete antenna modeling suite
- **Accurate**: High-precision electromagnetic calculations
- **Well-Documented**: Extensive help system and examples
- **Industry Standard**: Widely used in amateur radio community

#### Disadvantages
- **Cost**: Commercial license required
- **Platform**: Windows-only (requires Wine on Linux/macOS)
- **Learning Curve**: Complex features require time to master

#### Installation (Windows)
1. Download from http://www.eznec.com/
2. Run installer as administrator
3. Enter license key when prompted
4. Verify installation with sample models

#### Installation (Linux/macOS via Wine)
```bash
# Install Wine
sudo apt-get install wine  # Ubuntu/Debian
brew install wine-stable   # macOS

# Download EZNEC installer
wget http://www.eznec.com/eznec.exe

# Install EZNEC
wine eznec.exe

# Run EZNEC
wine ~/.wine/drive_c/Program\ Files/EZNEC/eznec.exe
```

### 4NEC2 (Arie Voors)

#### Overview
- **Platform**: Windows
- **Type**: Free NEC2-based antenna modeling
- **Cost**: Free
- **Website**: http://www.qsl.net/4nec2/

#### Features
- **NEC2 Engine**: Free NEC2 electromagnetic engine
- **GUI Interface**: User-friendly graphical interface
- **EZNEC Import**: Can import EZNEC files
- **3D Visualization**: 3D antenna pattern display
- **Pattern Analysis**: Radiation pattern analysis tools
- **Ground Modeling**: Various ground system models
- **Export Options**: Multiple output formats

#### Advantages
- **Free**: No cost for full functionality
- **Powerful**: Full NEC2 engine capabilities
- **Compatible**: Works with EZNEC files
- **Well-Supported**: Active development and support
- **Educational**: Great for learning antenna theory

#### Disadvantages
- **Platform**: Windows-only
- **Interface**: Less polished than commercial software
- **Learning Curve**: Requires understanding of NEC2 syntax

#### Installation
1. Download from http://www.qsl.net/4nec2/
2. Run installer
3. Install required Visual C++ redistributables
4. Launch 4NEC2

### FEKO (Altair Engineering)

#### Overview
- **Platform**: Windows, Linux
- **Type**: Commercial electromagnetic simulation
- **Cost**: Very expensive (enterprise pricing)
- **Website**: https://www.altair.com/feko/

#### Features
- **Advanced Modeling**: Full 3D electromagnetic simulation
- **Multiple Solvers**: MoM, FDTD, FEM, MLFMM
- **Complex Geometry**: CAD import and complex structures
- **High Performance**: Parallel processing and GPU acceleration
- **Professional**: Industry-standard electromagnetic software

#### Advantages
- **Professional**: Industry-standard software
- **Powerful**: Handles complex geometries
- **Accurate**: High-precision calculations
- **Scalable**: Parallel processing support

#### Disadvantages
- **Cost**: Very expensive
- **Complexity**: Steep learning curve
- **Overkill**: Too powerful for simple antenna modeling

## Free and Open Source Software

### NEC2C (Command Line)

#### Overview
- **Platform**: Linux, macOS, Windows
- **Type**: Command-line NEC2 engine
- **Cost**: Free
- **Website**: Various sources

#### Features
- **Fast**: Optimized C implementation
- **Scriptable**: Perfect for batch processing
- **Lightweight**: Minimal resource requirements
- **Accurate**: High-precision calculations
- **Portable**: Runs on multiple platforms

#### Installation (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install nec2c
```

#### Installation (macOS)
```bash
brew install nec2c
```

#### Installation (Windows)
```bash
# Download from https://github.com/tmolteno/necpp
# Or use Windows Subsystem for Linux
```

#### Usage Example
```bash
# Run NEC2 simulation
nec2c -i antenna.nec -o antenna.out

# Check for errors
if [ $? -eq 0 ]; then
    echo "Simulation successful"
else
    echo "Simulation failed"
fi
```

### Python with NumPy/SciPy

#### Overview
- **Platform**: Cross-platform
- **Type**: Programming language with scientific libraries
- **Cost**: Free
- **Website**: https://www.python.org/

#### Features
- **Flexible**: Custom analysis and visualization
- **Powerful**: Scientific computing libraries
- **Extensible**: Easy to add custom functionality
- **Visualization**: matplotlib for pattern display
- **Integration**: Easy integration with other tools

#### Installation
```bash
# Install Python
sudo apt-get install python3 python3-pip

# Install scientific libraries
pip3 install numpy scipy matplotlib

# Install additional tools
pip3 install pandas jupyter
```

#### Usage Example
```python
import numpy as np
import matplotlib.pyplot as plt

# Load pattern data
data = np.loadtxt('antenna_pattern.txt', skiprows=7)

# Extract angles and gain
theta = data[:, 0]
phi = data[:, 1]
gain = data[:, 2]

# Create 3D plot
fig = plt.figure()
ax = fig.add_subplot(111, projection='3d')

# Convert to Cartesian coordinates
x = gain * np.sin(np.radians(theta)) * np.cos(np.radians(phi))
y = gain * np.sin(np.radians(theta)) * np.sin(np.radians(phi))
z = gain * np.cos(np.radians(theta))

ax.scatter(x, y, z, c=gain, cmap='viridis')
plt.show()
```

### GNU Octave

#### Overview
- **Platform**: Cross-platform
- **Type**: Free MATLAB alternative
- **Cost**: Free
- **Website**: https://www.gnu.org/software/octave/

#### Features
- **MATLAB Compatible**: Similar syntax to MATLAB
- **Scientific Computing**: Built-in scientific functions
- **Plotting**: Advanced plotting capabilities
- **Free**: No license costs
- **Educational**: Great for learning

#### Installation (Ubuntu/Debian)
```bash
sudo apt-get install octave octave-signal octave-control
```

#### Installation (macOS)
```bash
brew install octave
```

#### Usage Example
```octave
% Load pattern data
data = dlmread('antenna_pattern.txt', ' ', 7, 0);

% Extract data
theta = data(:, 1);
phi = data(:, 2);
gain = data(:, 3);

% Create 3D plot
figure;
[X, Y, Z] = sph2cart(deg2rad(phi), deg2rad(theta), gain);
scatter3(X, Y, Z, 20, gain, 'filled');
colorbar;
title('Antenna Radiation Pattern');
```

## Command Line Tools

### EZNEC2NEC Converter

#### Overview
- **Purpose**: Convert EZNEC files to NEC2 format
- **Platform**: Cross-platform
- **Cost**: Free
- **Source**: Included with FGCom-mumble

#### Features
- **Format Conversion**: EZNEC to NEC2
- **Batch Processing**: Convert multiple files
- **Error Checking**: Validate file format
- **Scriptable**: Easy automation

#### Usage
```bash
# Convert single file
./eznec2nec.sh antenna.ez

# Convert multiple files
for file in *.ez; do
    ./eznec2nec.sh "$file"
done
```

### Pattern Extraction Scripts

#### Overview
- **Purpose**: Extract radiation patterns from NEC2 output
- **Platform**: Cross-platform
- **Cost**: Free
- **Source**: Included with FGCom-mumble

#### Features
- **Pattern Extraction**: Extract gain data from NEC2 output
- **Format Conversion**: Convert to FGCom-mumble format
- **Validation**: Check pattern quality
- **Batch Processing**: Process multiple files

#### Usage
```bash
# Extract single pattern
./extract_pattern.sh antenna.out antenna_pattern.txt 14.0 0

# Extract multiple patterns
for file in *.out; do
    ./extract_pattern.sh "$file" "${file%.out}_pattern.txt" 14.0 0
done
```

### Batch Processing Scripts

#### Overview
- **Purpose**: Automate pattern generation for multiple vehicles
- **Platform**: Cross-platform
- **Cost**: Free
- **Source**: Included with FGCom-mumble

#### Features
- **Automation**: Generate patterns for multiple vehicles
- **Parallel Processing**: Use multiple CPU cores
- **Error Handling**: Robust error checking
- **Progress Tracking**: Monitor generation progress

#### Usage
```bash
# Generate all patterns
./generate_all_patterns.sh

# Generate specific vehicle type
./generate_aircraft_patterns.sh

# Generate with parallel processing
./generate_all_patterns.sh --parallel 8
```

## Installation Instructions

### Complete Development Environment

#### Ubuntu/Debian
```bash
# Update system
sudo apt-get update

# Install basic tools
sudo apt-get install git make gcc g++

# Install NEC2C
sudo apt-get install nec2c

# Install Python and scientific libraries
sudo apt-get install python3 python3-pip python3-numpy python3-scipy python3-matplotlib

# Install additional tools
sudo apt-get install gnuplot octave

# Install Wine for EZNEC (optional)
sudo apt-get install wine

# Clone FGCom-mumble repository
git clone https://github.com/Supermagnum/fgcom-mumble.git
cd fgcom-mumble

# Make scripts executable
chmod +x client/mumble-plugin/lib/*.sh
```

#### macOS
```bash
# Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install basic tools
brew install git make gcc

# Install NEC2C
brew install nec2c

# Install Python and scientific libraries
brew install python3
pip3 install numpy scipy matplotlib

# Install additional tools
brew install gnuplot octave

# Install Wine for EZNEC (optional)
brew install wine-stable

# Clone FGCom-mumble repository
git clone https://github.com/Supermagnum/fgcom-mumble.git
cd fgcom-mumble

# Make scripts executable
chmod +x client/mumble-plugin/lib/*.sh
```

#### Windows
```bash
# Install Windows Subsystem for Linux (WSL)
# Or use Git Bash

# Install basic tools
sudo apt-get update
sudo apt-get install git make gcc g++

# Install NEC2C
sudo apt-get install nec2c

# Install Python
sudo apt-get install python3 python3-pip
pip3 install numpy scipy matplotlib

# Clone FGCom-mumble repository
git clone https://github.com/Supermagnum/fgcom-mumble.git
cd fgcom-mumble

# Make scripts executable
chmod +x client/mumble-plugin/lib/*.sh
```

## Usage Examples

### Basic Pattern Generation

#### Step 1: Create EZNEC Model
```eznec
CM Simple VHF Antenna Model
CM Frequency: 144 MHz
CE

GW  1  5    0.0   0.0   0.0   0.0   0.0   0.52  0.005

GE  0
GD  0  0  0  0  0.005  13
EX  0  1  3  0  1.0  0.0
FR  0  1  0  0  144000.0  0
RP  0  37  73  1000  0.0  0.0  5.0  5.0  0.0  0.0
EN
```

#### Step 2: Convert to NEC2
```bash
./eznec2nec.sh antenna.ez
```

#### Step 3: Run Simulation
```bash
nec2c -i antenna.nec -o antenna.out
```

#### Step 4: Extract Pattern
```bash
./extract_pattern.sh antenna.out antenna_pattern.txt 144.0 0
```

### Batch Processing Example

#### Generate Patterns for Multiple Frequencies
```bash
#!/bin/bash
# Generate patterns for multiple frequencies

frequencies=(3000 5000 7000 10000 14000 18000 21000 28000)

for freq in "${frequencies[@]}"; do
    echo "Generating pattern for ${freq} kHz"
    
    # Create frequency-specific model
    cp antenna.ez antenna_${freq}kHz.ez
    
    # Update frequency
    sed -i "s/^FR.*/FR 0 1 0 0 ${freq}.0 0/" antenna_${freq}kHz.ez
    
    # Convert to NEC2
    ./eznec2nec.sh antenna_${freq}kHz.ez
    
    # Run simulation
    nec2c -i antenna_${freq}kHz.nec -o antenna_${freq}kHz.out
    
    # Extract pattern
    ./extract_pattern.sh antenna_${freq}kHz.out antenna_${freq}kHz_pattern.txt "$freq" "0"
done
```

### Parallel Processing Example

#### Use Multiple CPU Cores
```bash
#!/bin/bash
# Parallel pattern generation

# Function to process single frequency
process_frequency() {
    local freq="$1"
    echo "Processing ${freq} kHz"
    
    # Create frequency-specific model
    cp antenna.ez antenna_${freq}kHz.ez
    
    # Update frequency
    sed -i "s/^FR.*/FR 0 1 0 0 ${freq}.0 0/" antenna_${freq}kHz.ez
    
    # Convert to NEC2
    ./eznec2nec.sh antenna_${freq}kHz.ez
    
    # Run simulation
    nec2c -i antenna_${freq}kHz.nec -o antenna_${freq}kHz.out
    
    # Extract pattern
    ./extract_pattern.sh antenna_${freq}kHz.out antenna_${freq}kHz_pattern.txt "$freq" "0"
}

# Export function for parallel processing
export -f process_frequency

# Process frequencies in parallel
frequencies=(3000 5000 7000 10000 14000 18000 21000 28000)
printf '%s\n' "${frequencies[@]}" | xargs -n 1 -P 4 -I {} bash -c 'process_frequency "$@"' _ {}
```

## Tool Comparison

| Tool | Cost | Platform | Ease of Use | Accuracy | Features |
|------|------|----------|--------------|----------|----------|
| EZNEC | $89 | Windows | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| 4NEC2 | Free | Windows | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| NEC2C | Free | Cross-platform | ⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |
| Python | Free | Cross-platform | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| GNU Octave | Free | Cross-platform | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |

### Feature Comparison

#### EZNEC
- ✅ **Best Overall**: Most comprehensive and user-friendly
- ✅ **Professional**: Industry-standard for amateur radio
- ✅ **Accurate**: High-precision calculations
- ❌ **Cost**: Commercial license required
- ❌ **Platform**: Windows-only

#### 4NEC2
- ✅ **Free**: No cost for full functionality
- ✅ **Powerful**: Full NEC2 engine
- ✅ **Compatible**: Works with EZNEC files
- ❌ **Platform**: Windows-only
- ❌ **Interface**: Less polished than EZNEC

#### NEC2C
- ✅ **Free**: No cost
- ✅ **Fast**: Optimized C implementation
- ✅ **Scriptable**: Perfect for automation
- ❌ **Command Line**: No graphical interface
- ❌ **Learning Curve**: Requires understanding of NEC2

#### Python
- ✅ **Free**: No cost
- ✅ **Flexible**: Custom analysis and visualization
- ✅ **Powerful**: Scientific computing libraries
- ❌ **Learning Curve**: Requires programming knowledge
- ❌ **Setup**: Requires additional libraries

## Recommended Workflows

### For Beginners

#### Recommended Tools
1. **4NEC2** (Free, Windows)
2. **EZNEC** (Commercial, Windows)

#### Workflow
1. **Learn Basics**: Start with 4NEC2 tutorials
2. **Create Models**: Build simple antenna models
3. **Generate Patterns**: Create radiation patterns
4. **Validate Results**: Check pattern quality
5. **Integrate**: Load patterns into FGCom-mumble

### For Advanced Users

#### Recommended Tools
1. **EZNEC** (Commercial, Windows)
2. **NEC2C** (Free, Command Line)
3. **Python** (Free, Analysis)

#### Workflow
1. **Design Models**: Use EZNEC for complex models
2. **Batch Processing**: Use NEC2C for automation
3. **Analysis**: Use Python for custom analysis
4. **Validation**: Implement quality control
5. **Integration**: Automated pattern loading

### For Developers

#### Recommended Tools
1. **NEC2C** (Free, Command Line)
2. **Python** (Free, Analysis)
3. **Bash Scripts** (Free, Automation)

#### Workflow
1. **Automation**: Create batch processing scripts
2. **Validation**: Implement quality control
3. **Integration**: Automated pattern loading
4. **Testing**: Comprehensive test suite
5. **Documentation**: Complete documentation

## Conclusion

The choice of antenna modeling tools depends on your needs:

- **Beginners**: Start with 4NEC2 (free) or EZNEC (commercial)
- **Advanced Users**: Use EZNEC for design, NEC2C for automation
- **Developers**: Use NEC2C and Python for automation and analysis

All tools can generate the radiation pattern files needed for FGCom-mumble, with the main differences being ease of use, cost, and platform support.

For the most comprehensive experience, consider using multiple tools:
- **EZNEC** for model design and visualization
- **NEC2C** for batch processing and automation
- **Python** for analysis and visualization
- **Bash Scripts** for automation and integration
