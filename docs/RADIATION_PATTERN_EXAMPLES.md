# Practical Examples: Creating Radiation Patterns for FGCom-mumble

## Overview

This document provides step-by-step examples for creating radiation pattern files for different vehicle types in FGCom-mumble. Each example includes complete EZNEC models, pattern generation scripts, and integration instructions.

**✅ CURRENT STATUS**: The automated pattern generation system has been updated and is now working correctly. The script `scripts/pattern_generation/simplified_nec_generator.sh` now uses `.nec` files exclusively and properly generates patterns at multiple altitudes for aircraft with parallel processing support.

## Table of Contents

1. [Aircraft Examples](#aircraft-examples)
2. [Maritime Examples](#maritime-examples)
3. [Ground Vehicle Examples](#ground-vehicle-examples)
4. [Military Vehicle Examples](#military-vehicle-examples)
5. [Pattern Generation Scripts](#pattern-generation-scripts)
6. [Integration Examples](#integration-examples)

## Aircraft Examples

### Example 1: Cessna 172 VHF Antenna

#### Step 1: Research and Planning

**Vehicle Specifications:**
- **Type**: General aviation aircraft
- **Dimensions**: 8.2m × 10.9m × 2.7m
- **Antenna**: VHF whip on fuselage
- **Frequency**: 130 MHz (VHF)
- **Altitude**: 0-10,000m

**Research Notes:**
- VHF antennas are typically 1/4 wavelength (0.55m at 130 MHz)
- Mounted on fuselage top center
- Ground plane provided by aircraft structure
- Patterns change significantly with altitude

#### Step 2: Create EZNEC Model

**File: `antenna_patterns/aircraft/cessna_172/cessna_172.ez`**

```eznec
CM Cessna 172 VHF Antenna Model
CM Aircraft dimensions: 8.2m x 10.9m x 2.7m
CM VHF whip antenna on fuselage
CM Frequency: 130 MHz (VHF)
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

CM VHF whip antenna (0.55m at 130 MHz)
GW 13  5    0.0   0.0   2.7   0.0   0.0   3.25  0.005

GE  0
GD  0  0  0  0  0.005  13
EX  0  13  3  0  1.0  0.0
FR  0  1  0  0  130000.0  0
RP  0  37  73  1000  0.0  0.0  5.0  5.0  0.0  0.0
EN
```

#### Step 3: Generate Altitude-Dependent Patterns

**Script: `generate_cessna_patterns.sh`**

```bash
#!/bin/bash
# Generate altitude-dependent patterns for Cessna 172

BASE_DIR="antenna_patterns/aircraft/cessna_172"
PATTERNS_DIR="$BASE_DIR/patterns"
FREQUENCIES=(118 121 125 130 135 137)
ALTITUDES=(0 100 500 1000 2000 3000 5000 8000 10000)

# Create directory structure
mkdir -p "$PATTERNS_DIR"

for alt in "${ALTITUDES[@]}"; do
    mkdir -p "$PATTERNS_DIR/${alt}m"
    
    for freq in "${FREQUENCIES[@]}"; do
        echo "Generating pattern for ${freq} MHz at ${alt}m altitude"
        
        # Create altitude-specific model
        cp "$BASE_DIR/cessna_172.ez" "$PATTERNS_DIR/${alt}m/cessna_172_${freq}.0MHz.ez"
        
        # Update frequency
        sed -i "s/^FR.*/FR 0 1 0 0 ${freq}000.0 0/" "$PATTERNS_DIR/${alt}m/cessna_172_${freq}.0MHz.ez"
        
        # Update ground parameters for altitude
        if [ $alt -gt 1000 ]; then
            # High altitude - free space
            sed -i "s/^GD.*/GD  0  0  0  0  0.0  1.0/" "$PATTERNS_DIR/${alt}m/cessna_172_${freq}.0MHz.ez"
        else
            # Low altitude - ground effects
            sed -i "s/^GD.*/GD  0  0  0  0  0.005  13/" "$PATTERNS_DIR/${alt}m/cessna_172_${freq}.0MHz.ez"
        fi
        
        # Convert to NEC2
        ./eznec2nec.sh "$PATTERNS_DIR/${alt}m/cessna_172_${freq}.0MHz.ez"
        
        # Run simulation
        cd "$PATTERNS_DIR/${alt}m/"
        nec2c -i "cessna_172_${freq}.0MHz.nec" -o "cessna_172_${freq}.0MHz.out"
        
        # Extract pattern
        ./extract_pattern.sh "cessna_172_${freq}.0MHz.out" "cessna_172_${freq}.0MHz_${alt}m_pattern.txt" "$freq" "$alt"
        
        cd - > /dev/null
    done
done

echo "Cessna 172 pattern generation complete!"
```

#### Step 4: Pattern File Example

**File: `cessna_172_130.0MHz_0m_pattern.txt`**

```
# FGCom-mumble Far-Field Radiation Pattern
# Frequency: 130.0 MHz
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
0.0 15.0 -13.5 0.5 0.9
0.0 20.0 -13.2 0.4 0.9
...
```

### Example 2: Boeing 737 HF Antenna

#### Step 1: Research and Planning

**Vehicle Specifications:**
- **Type**: Commercial airliner
- **Dimensions**: 39.5m × 35.8m × 12.5m
- **Antenna**: HF trailing wire
- **Frequency**: 3-30 MHz (HF)
- **Altitude**: 0-12,000m

**Research Notes:**
- HF antennas are typically long wires (10-50m)
- Trailing wire antennas are common on airliners
- Ground effects significant at low altitude
- Patterns vary greatly with frequency

#### Step 2: Create EZNEC Model

**File: `antenna_patterns/aircraft/b737/b737.ez`**

```eznec
CM Boeing 737 HF Trailing Wire Antenna
CM Aircraft dimensions: 39.5m x 35.8m x 12.5m
CM HF trailing wire antenna
CM Frequency: 14 MHz (20m band)
CE

GW  1  1   -19.75  -17.9  0.0   19.75  -17.9  0.0  0.01
GW  2  1    19.75  -17.9  0.0   19.75   17.9  0.0  0.01
GW  3  1    19.75   17.9  0.0  -19.75   17.9  0.0  0.01
GW  4  1   -19.75   17.9  0.0  -19.75  -17.9  0.0  0.01

GW  5  1   -19.75  -17.9  0.0  -19.75  -17.9  12.5  0.01
GW  6  1    19.75  -17.9  0.0   19.75  -17.9  12.5  0.01
GW  7  1    19.75   17.9  0.0   19.75   17.9  12.5  0.01
GW  8  1   -19.75   17.9  0.0  -19.75   17.9  12.5  0.01

GW  9  1   -19.75  -17.9  12.5   19.75  -17.9  12.5  0.01
GW 10  1    19.75  -17.9  12.5   19.75   17.9  12.5  0.01
GW 11  1    19.75   17.9  12.5  -19.75   17.9  12.5  0.01
GW 12  1   -19.75   17.9  12.5  -19.75  -17.9  12.5  0.01

CM HF trailing wire antenna (20m wire)
GW 13  5    0.0   0.0   12.5   0.0   0.0   32.5  0.005

GE  0
GD  0  0  0  0  0.005  13
EX  0  13  3  0  1.0  0.0
FR  0  1  0  0  14000.0  0
RP  0  37  73  1000  0.0  0.0  5.0  5.0  0.0  0.0
EN
```

## Maritime Examples

### Example 3: Sailboat with Backstay Antenna

#### Step 1: Research and Planning

**Vehicle Specifications:**
- **Type**: Sailboat
- **Dimensions**: 12m × 3.5m × 1.5m
- **Antenna**: Backstay antenna (insulated)
- **Frequency**: 3-30 MHz (HF)
- **Environment**: Saltwater

**Research Notes:**
- Backstay antennas are common on sailboats
- Insulated from rigging
- Saltwater provides excellent ground
- Patterns affected by boat heeling

#### Step 2: Create EZNEC Model

**File: `antenna_patterns/boat/sailboat/sailboat.ez`**

```eznec
CM Sailboat with Backstay Antenna
CM Boat dimensions: 12m x 3.5m x 1.5m
CM Backstay antenna (insulated)
CM Frequency: 14 MHz (20m band)
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
FR  0  1  0  0  14000.0  0
RP  0  37  73  1000  0.0  0.0  5.0  5.0  0.0  0.0
EN
```

#### Step 3: Generate Maritime Patterns

**Script: `generate_sailboat_patterns.sh`**

```bash
#!/bin/bash
# Generate patterns for sailboat with backstay antenna

BASE_DIR="antenna_patterns/boat/sailboat"
PATTERNS_DIR="$BASE_DIR/patterns"
FREQUENCIES=(3000 5000 7000 10000 14000 18000 21000 28000)

# Create directory structure
mkdir -p "$PATTERNS_DIR"

for freq in "${FREQUENCIES[@]}"; do
    echo "Generating pattern for ${freq} kHz"
    
    # Create frequency-specific model
    cp "$BASE_DIR/sailboat.ez" "$PATTERNS_DIR/sailboat_${freq}kHz.ez"
    
    # Update frequency
    sed -i "s/^FR.*/FR 0 1 0 0 ${freq}.0 0/" "$PATTERNS_DIR/sailboat_${freq}kHz.ez"
    
    # Convert to NEC2
    ./eznec2nec.sh "$PATTERNS_DIR/sailboat_${freq}kHz.ez"
    
    # Run simulation
    cd "$PATTERNS_DIR/"
    nec2c -i "sailboat_${freq}kHz.nec" -o "sailboat_${freq}kHz.out"
    
    # Extract pattern
    ./extract_pattern.sh "sailboat_${freq}kHz.out" "sailboat_${freq}kHz_pattern.txt" "$freq" "0"
    
    cd - > /dev/null
done

echo "Sailboat pattern generation complete!"
```

### Example 4: Historical Coastal Radio Station (Bergen Radio)

#### Step 1: Research and Planning

**Station Specifications:**
- **Type**: Coastal radio station
- **Antenna**: T-shaped antenna system
- **Height**: 150m vertical mast
- **Top Cross**: 195m horizontal wire
- **Ground System**: Buried radials
- **Power**: 10 kW
- **Frequency**: 3-30 MHz (HF)
- **Environment**: Coastal saltwater

**Research Notes:**
- Historical coastal stations used massive T-shaped antennas
- Vertical mast provided height for long-range communication
- Horizontal top wire increased radiation efficiency
- Buried radial ground system for optimal ground plane
- High power (10 kW) for intercontinental communication
- Patterns optimized for maritime communication

**Historical Context:**
- Bergen Radio (LGN) was one of Norway's major coastal radio stations
- T-shaped antennas were common for long-range maritime communication
- These stations provided communication with ships worldwide
- Antennas were designed for maximum range and reliability
- Ground systems were extensive to ensure good radiation efficiency
- Power levels were much higher than modern amateur radio (10 kW vs 1.5 kW)

**Important Note**: This is a very simplified example of a coastal radio station. In reality, the antenna system was much more complex, featuring:
- **Multiple Antenna Systems**: Various antennas for different frequency bands and purposes
- **Sophisticated Switching**: Complex switching systems to route signals to different antennas
- **Multiple Operators**: Teams of radio operators working around the clock
- **Advanced Ground Systems**: Elaborate buried radial networks and counterpoise systems
- **Backup Systems**: Redundant antennas and equipment for reliability
- **Directional Arrays**: Phased arrays and directional antennas for specific routes
- **Power Distribution**: Complex power distribution systems for multiple transmitters

#### Step 2: Create EZNEC Model

**File: `antenna_patterns/coastal/bergen_radio/bergen_radio.ez`**

```eznec
CM Bergen Radio T-Shaped Antenna System
CM Vertical mast: 150m height
CM Horizontal top: 195m length
CM Ground system: Buried radials
CM Power: 10 kW
CM Frequency: 14 MHz (20m band)
CE

CM Vertical mast (150m height)
GW  1  5    0.0   0.0   0.0   0.0   0.0   150.0  0.01

CM Horizontal top wire (195m length)
GW  2  5   -97.5   0.0   150.0   97.5   0.0   150.0  0.01

CM Buried radial ground system (120 radials, 200m each)
GW  3  1   -200.0   0.0   0.0   200.0   0.0   0.0  0.01
GW  4  1    0.0  -200.0   0.0   0.0   200.0   0.0  0.01
GW  5  1   -141.4  -141.4  0.0   141.4   141.4  0.0  0.01
GW  6  1    141.4  -141.4  0.0  -141.4   141.4  0.0  0.01

GE  0
GD  0  0  0  0  5.0  81
EX  0  1  3  0  1.0  0.0
FR  0  1  0  0  14000.0  0
RP  0  37  73  1000  0.0  0.0  5.0  5.0  0.0  0.0
EN
```

## Ground Vehicle Examples

### Example 5: Ford Transit Camper Van

#### Step 1: Research and Planning

**Vehicle Specifications:**
- **Type**: Camper van
- **Dimensions**: 5.3m × 2.0m × 2.5m
- **Antenna**: VHF/UHF mobile antenna
- **Frequency**: 144 MHz (2m band)
- **Environment**: Land

**Research Notes:**
- Mobile antennas typically 1/4 wavelength
- Ground plane provided by vehicle roof
- Patterns affected by vehicle body
- Good for amateur radio operations

#### Step 2: Create EZNEC Model

**File: `antenna_patterns/vehicle/ford_transit/ford_transit.ez`**

```eznec
CM Ford Transit Camper Van VHF Antenna
CM Vehicle dimensions: 5.3m x 2.0m x 2.5m
CM VHF mobile antenna on roof
CM Frequency: 144 MHz (2m band)
CE

GW  1  1   -2.65  -1.0  0.0   2.65  -1.0  0.0  0.01
GW  2  1    2.65  -1.0  0.0   2.65   1.0  0.0  0.01
GW  3  1    2.65   1.0  0.0  -2.65   1.0  0.0  0.01
GW  4  1   -2.65   1.0  0.0  -2.65  -1.0  0.0  0.01

GW  5  1   -2.65  -1.0  0.0  -2.65  -1.0  2.5  0.01
GW  6  1    2.65  -1.0  0.0   2.65  -1.0  2.5  0.01
GW  7  1    2.65   1.0  0.0   2.65   1.0  2.5  0.01
GW  8  1   -2.65   1.0  0.0  -2.65   1.0  2.5  0.01

GW  9  1   -2.65  -1.0  2.5   2.65  -1.0  2.5  0.01
GW 10  1    2.65  -1.0  2.5   2.65   1.0  2.5  0.01
GW 11  1    2.65   1.0  2.5  -2.65   1.0  2.5  0.01
GW 12  1   -2.65   1.0  2.5  -2.65  -1.0  2.5  0.01

CM VHF mobile antenna (0.52m at 144 MHz)
GW 13  5    0.0   0.0  2.5   0.0   0.0   3.02  0.005

GE  0
GD  0  0  0  0  0.005  13
EX  0  13  3  0  1.0  0.0
FR  0  1  0  0  144000.0  0
RP  0  37  73  1000  0.0  0.0  5.0  5.0  0.0  0.0
EN
```

## Military Vehicle Examples

### Example 6: NATO Jeep with Tied-Down Antenna

#### Step 1: Research and Planning

**Vehicle Specifications:**
- **Type**: Military utility vehicle
- **Dimensions**: 4.2m × 1.8m × 1.5m
- **Antenna**: 10ft whip tied down at 45°
- **Frequency**: 3-30 MHz (HF)
- **Environment**: Land

**Research Notes:**
- Tied-down antennas common in military
- 45° angle provides good radiation
- Ground effects significant
- Tactical communication frequencies

#### Step 2: Create EZNEC Model

**File: `antenna_patterns/military_land/nato_jeep/nato_jeep.ez`**

```eznec
CM NATO Jeep with 10ft Whip Antenna at 45 degrees
CM Vehicle dimensions: 4.2m x 1.8m x 1.5m
CM 10ft whip antenna tied down at 45 degrees
CM Frequency: 14 MHz (20m band)
CE

GW  1  1   -2.1  -0.9  0.0   2.1  -0.9  0.0  0.01
GW  2  1    2.1  -0.9  0.0   2.1   0.9  0.0  0.01
GW  3  1    2.1   0.9  0.0  -2.1   0.9  0.0  0.01
GW  4  1   -2.1   0.9  0.0  -2.1  -0.9  0.0  0.01

GW  5  1   -2.1  -0.9  0.0  -2.1  -0.9  1.5  0.01
GW  6  1    2.1  -0.9  0.0   2.1  -0.9  1.5  0.01
GW  7  1    2.1   0.9  0.0   2.1   0.9  1.5  0.01
GW  8  1   -2.1   0.9  0.0  -2.1   0.9  1.5  0.01

GW  9  1   -2.1  -0.9  1.5   2.1  -0.9  1.5  0.01
GW 10  1    2.1  -0.9  1.5   2.1   0.9  1.5  0.01
GW 11  1    2.1   0.9  1.5  -2.1   0.9  1.5  0.01
GW 12  1   -2.1   0.9  1.5  -2.1  -0.9  1.5  0.01

CM 10ft whip antenna at 45 degree angle (3m at 45°)
GW 13  5    0.0   0.0  1.5   2.12  2.12  3.62  0.005

GE  0
GD  0  0  0  0  0.005  13
EX  0  13  3  0  1.0  0.0
FR  0  1  0  0  14000.0  0
RP  0  37  73  1000  0.0  0.0  5.0  5.0  0.0  0.0
EN
```

## Pattern Generation Scripts

### Master Pattern Generation Script

**File: `generate_all_patterns.sh`**

```bash
#!/bin/bash
# Master script to generate all radiation patterns

set -e

# Configuration
BASE_DIR="antenna_patterns"
PARALLEL_JOBS=4

# Function to generate patterns for a vehicle
generate_vehicle_patterns() {
    local vehicle_type="$1"
    local vehicle_name="$2"
    local base_file="$3"
    
    echo "Generating patterns for $vehicle_name ($vehicle_type)"
    
    # Create patterns directory
    mkdir -p "$BASE_DIR/$vehicle_type/$vehicle_name/patterns"
    
    # Generate patterns based on vehicle type
    case "$vehicle_type" in
        "aircraft")
            ./generate_aircraft_patterns.sh "$base_file" "$vehicle_name"
            ;;
        "boat")
            ./generate_boat_patterns.sh "$base_file" "$vehicle_name"
            ;;
        "ship")
            ./generate_ship_patterns.sh "$base_file" "$vehicle_name"
            ;;
        "vehicle")
            ./generate_vehicle_patterns.sh "$base_file" "$vehicle_name"
            ;;
        "military_land")
            ./generate_military_patterns.sh "$base_file" "$vehicle_name"
            ;;
        *)
            echo "Unknown vehicle type: $vehicle_type"
            exit 1
            ;;
    esac
}

# Generate patterns for all vehicles
generate_vehicle_patterns "aircraft" "cessna_172" "antenna_patterns/aircraft/cessna_172/cessna_172.ez"
generate_vehicle_patterns "aircraft" "b737" "antenna_patterns/aircraft/b737/b737.ez"
generate_vehicle_patterns "boat" "sailboat" "antenna_patterns/boat/sailboat/sailboat.ez"
generate_vehicle_patterns "ship" "containership" "antenna_patterns/ship/containership/containership.ez"
generate_vehicle_patterns "vehicle" "ford_transit" "antenna_patterns/vehicle/ford_transit/ford_transit.ez"
generate_vehicle_patterns "military_land" "nato_jeep" "antenna_patterns/military_land/nato_jeep/nato_jeep.ez"

echo "All pattern generation complete!"
```

### Aircraft Pattern Generation Script

**File: `generate_aircraft_patterns.sh`**

```bash
#!/bin/bash
# Generate altitude-dependent patterns for aircraft

set -e

BASE_FILE="$1"
VEHICLE_NAME="$2"

if [ -z "$BASE_FILE" ] || [ -z "$VEHICLE_NAME" ]; then
    echo "Usage: $0 <base_file> <vehicle_name>"
    exit 1
fi

FREQUENCIES=(118 121 125 130 135 137)
ALTITUDES=(0 100 500 1000 2000 3000 5000 8000 10000)

for alt in "${ALTITUDES[@]}"; do
    echo "Generating patterns for altitude ${alt}m"
    
    mkdir -p "antenna_patterns/aircraft/$VEHICLE_NAME/patterns/${alt}m"
    
    for freq in "${FREQUENCIES[@]}"; do
        echo "  Frequency: ${freq} MHz"
        
        # Create altitude-specific model
        cp "$BASE_FILE" "antenna_patterns/aircraft/$VEHICLE_NAME/patterns/${alt}m/${VEHICLE_NAME}_${freq}.0MHz.ez"
        
        # Update frequency
        sed -i "s/^FR.*/FR 0 1 0 0 ${freq}000.0 0/" "antenna_patterns/aircraft/$VEHICLE_NAME/patterns/${alt}m/${VEHICLE_NAME}_${freq}.0MHz.ez"
        
        # Update ground parameters for altitude
        if [ $alt -gt 1000 ]; then
            # High altitude - free space
            sed -i "s/^GD.*/GD  0  0  0  0  0.0  1.0/" "antenna_patterns/aircraft/$VEHICLE_NAME/patterns/${alt}m/${VEHICLE_NAME}_${freq}.0MHz.ez"
        else
            # Low altitude - ground effects
            sed -i "s/^GD.*/GD  0  0  0  0  0.005  13/" "antenna_patterns/aircraft/$VEHICLE_NAME/patterns/${alt}m/${VEHICLE_NAME}_${freq}.0MHz.ez"
        fi
        
        # Convert to NEC2
        ./eznec2nec.sh "antenna_patterns/aircraft/$VEHICLE_NAME/patterns/${alt}m/${VEHICLE_NAME}_${freq}.0MHz.ez"
        
        # Run simulation
        cd "antenna_patterns/aircraft/$VEHICLE_NAME/patterns/${alt}m/"
        nec2c -i "${VEHICLE_NAME}_${freq}.0MHz.nec" -o "${VEHICLE_NAME}_${freq}.0MHz.out"
        
        # Extract pattern
        ./extract_pattern.sh "${VEHICLE_NAME}_${freq}.0MHz.out" "${VEHICLE_NAME}_${freq}.0MHz_${alt}m_pattern.txt" "$freq" "$alt"
        
        cd - > /dev/null
    done
done

echo "Aircraft pattern generation complete for $VEHICLE_NAME"
```

## Integration Examples

### Pattern Loading in C++

**File: `pattern_loading_example.cpp`**

```cpp
#include "pattern_interpolation.h"
#include "antenna_pattern_mapping.h"

// Load pattern for specific vehicle and frequency
bool loadVehiclePattern(const std::string& vehicle_name, 
                       double frequency_mhz, 
                       double altitude_m) {
    
    // Detect vehicle type
    std::string vehicle_type = detectVehicleType(vehicle_name);
    
    // Get pattern file path
    std::string pattern_file = getPatternFilePath(vehicle_type, vehicle_name, frequency_mhz, altitude_m);
    
    // Load pattern
    FGCom_RadiationPattern pattern;
    if (!pattern.loadPattern(pattern_file)) {
        std::cerr << "Failed to load pattern: " << pattern_file << std::endl;
        return false;
    }
    
    // Store in pattern mapping
    g_antenna_pattern_mapping->addPattern(vehicle_type, frequency_mhz, pattern);
    
    return true;
}

// Get antenna gain for specific direction
double getAntennaGain(const std::string& vehicle_name,
                     double frequency_mhz,
                     double altitude_m,
                     double theta_deg,
                     double phi_deg) {
    
    // Get pattern
    FGCom_RadiationPattern* pattern = g_antenna_pattern_mapping->getPattern(vehicle_name, frequency_mhz);
    
    if (!pattern) {
        // Fallback to default pattern
        return 0.0; // 0 dBi gain
    }
    
    // Get interpolated gain
    return pattern->getGain(theta_deg, phi_deg);
}
```

### Pattern File Validation

**File: `validate_patterns.sh`**

```bash
#!/bin/bash
# Validate generated pattern files

validate_pattern_file() {
    local file="$1"
    
    echo "Validating: $file"
    
    # Check file exists
    if [ ! -f "$file" ]; then
        echo "  ERROR: File not found"
        return 1
    fi
    
    # Check file size (should be 20-40 KB)
    local size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null)
    if [ $size -lt 20000 ] || [ $size -gt 40000 ]; then
        echo "  WARNING: File size unusual ($size bytes)"
    fi
    
    # Check header format
    if ! grep -q "FGCom-mumble Far-Field Radiation Pattern" "$file"; then
        echo "  ERROR: Missing header"
        return 1
    fi
    
    # Check data format
    local data_lines=$(grep -v "^#" "$file" | wc -l)
    if [ $data_lines -lt 1000 ]; then
        echo "  ERROR: Insufficient data points ($data_lines)"
        return 1
    fi
    
    # Check gain range
    local min_gain=$(grep -v "^#" "$file" | awk '{print $3}' | sort -n | head -1)
    local max_gain=$(grep -v "^#" "$file" | awk '{print $3}' | sort -n | tail -1)
    
    if (( $(echo "$min_gain < -30" | bc -l) )) || (( $(echo "$max_gain > 20" | bc -l) )); then
        echo "  WARNING: Gain range unusual ($min_gain to $max_gain dBi)"
    fi
    
    echo "  OK: Pattern file valid"
    return 0
}

# Validate all pattern files
find antenna_patterns -name "*_pattern.txt" | while read file; do
    validate_pattern_file "$file"
done

echo "Pattern validation complete!"
```

## Conclusion

These examples provide a complete workflow for creating radiation pattern files for FGCom-mumble:

1. **Research and Planning**: Understand vehicle specifications and antenna requirements
2. **EZNEC Model Creation**: Create accurate electromagnetic models
3. **Pattern Generation**: Use scripts to generate patterns for multiple frequencies and altitudes
4. **Quality Control**: Validate generated patterns for accuracy and completeness
5. **Integration**: Load patterns into FGCom-mumble system

Each example includes complete code, scripts, and step-by-step instructions that can be adapted for different vehicle types and requirements.
