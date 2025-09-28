# FGCom-mumble Pattern File Standards

## Overview

This document defines the standards and requirements for antenna radiation pattern files in the FGCom-mumble system.

## What Are Antenna Patterns?

### Definition
Antenna patterns (also called radiation patterns) are 3D mathematical models that describe how an antenna radiates electromagnetic energy in different directions. They show the antenna's gain (signal strength) at every possible angle around it - both horizontally (azimuth) and vertically (elevation).

### Why Are They Needed?

**1. Realistic Radio Communication Simulation**
- **Without patterns**: All antennas radiate equally in all directions (isotropic)
- **With patterns**: Antennas have realistic directional characteristics
- **Result**: More authentic radio communication experience

**2. Physics-Based Signal Quality**
- **Directional antennas** (like Yagi beams) have high gain in one direction, low gain in others
- **Omnidirectional antennas** (like whip antennas) radiate equally in all horizontal directions
- **Aircraft antennas** change pattern based on aircraft attitude (roll, pitch, altitude)

**3. Real-World Antenna Behavior**
- **Ground vehicles**: Antenna patterns affected by vehicle body, ground plane, and mounting height
- **Aircraft**: Patterns change with aircraft attitude, altitude, and speed
- **Maritime**: Ship antennas affected by vessel structure and sea conditions

### How They Work in FGCom-Mumble

**1. Signal Quality Calculation**
```
Final Signal Quality = Base Signal × Antenna Gain × Propagation Effects
```

**2. Directional Effects**
- **Yagi antenna**: High gain in forward direction, low gain behind
- **Dipole antenna**: Figure-8 pattern with nulls at ends
- **Vertical antenna**: Omnidirectional in horizontal plane

**3. Vehicle-Specific Patterns**
- **Aircraft**: Patterns change with roll/pitch angles
- **Ground vehicles**: Patterns affected by vehicle body
- **Maritime**: Patterns affected by ship structure

### Real-World Examples

**Ground Station with Yagi Antenna:**
- **Forward direction**: 14.8 dBi gain (strong signal)
- **Side directions**: 5-8 dBi gain (moderate signal)  
- **Behind antenna**: -10 dBi gain (very weak signal)

**Aircraft with VHF Antenna:**
- **Level flight**: Normal omnidirectional pattern
- **Banking left**: Signal stronger to left, weaker to right
- **Climbing**: Signal pattern tilts upward

**Military Vehicle with Whip Antenna:**
- **Omnidirectional**: Equal signal in all horizontal directions
- **Vertical nulls**: Weak signal directly above and below
- **Ground effects**: Signal enhanced by ground plane

### Technical Benefits

**1. Accurate Propagation Modeling**
- Realistic signal strength calculations
- Directional communication effects
- Vehicle attitude impacts on communication

**2. Educational Value**
- Learn how real antennas work
- Understand radio propagation physics
- Experience authentic radio procedures

**3. Realistic Gameplay**
- Strategic antenna positioning matters
- Vehicle orientation affects communication
- Different vehicles have different radio capabilities

### Pattern File Contents

Each pattern file contains:
- **Gain values** for every direction (elevation/azimuth)
- **Polarization information** (horizontal/vertical components)
- **Frequency-specific data** for different radio bands
- **Altitude variations** for aircraft patterns
- **Attitude data** for aircraft roll/pitch effects

### Why This Matters

**For Pilots:**
- Learn proper antenna positioning
- Understand radio communication limitations
- Experience realistic signal propagation

**For ATC:**
- Understand coverage patterns
- Plan communication strategies
- Learn antenna placement principles

**For Developers:**
- Integrate realistic radio physics
- Create authentic communication systems
- Provide educational value

## File Format Standards

## File Format Standards

### Required Header Format

All pattern files must begin with the following header:

```
# FGCom-mumble Far-Field Radiation Pattern
# Frequency: XXX.X MHz
# Altitude: XXX m
# Format: Theta Phi Gain_dBi H_Polarization V_Polarization
# Theta: Elevation angle (0-180 degrees)
# Phi: Azimuth angle (0-360 degrees)
# Gain: Antenna gain in dBi
# H_Polarization: Horizontal polarization component
# V_Polarization: Vertical polarization component
```

### Data Format

Each data line must contain exactly 5 numeric values:
```
Theta Phi Gain_dBi H_Polarization V_Polarization
```

Where:
- **Theta**: Elevation angle (0-180 degrees)
- **Phi**: Azimuth angle (0-360 degrees)  
- **Gain_dBi**: Antenna gain in decibels relative to isotropic
- **H_Polarization**: Horizontal polarization component (0.0-1.0)
- **V_Polarization**: Vertical polarization component (0.0-1.0)

## File Size Requirements

### Minimum Standards
- **File Size**: Minimum 500 bytes
- **Data Lines**: Minimum 1,200 lines
- **Coverage**: Full elevation/azimuth grid

### Typical Ranges
- **Aircraft Patterns**: 28-56 KB
- **Ground-based Patterns**: 30-32 KB
- **Marine Patterns**: 29-56 KB
- **Military Patterns**: 29-30 KB

## Directory Structure Standards

### Aircraft Patterns
```
aircraft/
├── Civil/
│   ├── cessna_172/
│   │   └── patterns/
│   │       ├── 14.0mhz/
│   │       └── 121.5mhz/
│   └── b737_800/
│       └── patterns/
│           └── 130.0mhz/
└── Military/
    ├── mi4_hound/
    └── bell_uh1_huey/
```

### Ground-based Patterns
```
Ground-based/
├── Yagi-antennas/
│   ├── yagi_6m/
│   ├── yagi_144mhz/
│   └── Yagi_2x-stack_144mhz/
```

### Marine Patterns
```
Marine/
└── ship/
    └── containership/
        └── patterns/
            ├── 3.5mhz/
            ├── 7mhz/
            └── 156.8mhz/
```

### Military Land Patterns
```
military-land/
├── soviet_uaz/
├── t55_soviet_mbt/
└── nato_jeep/
```

## Naming Conventions

### Pattern File Names
- **Base Pattern**: `{vehicle}_{frequency}MHz_pattern.txt`
- **Attitude Pattern**: `{altitude}m_roll_{roll}_pitch_{pitch}.txt`
- **Yagi Pattern**: `yagi2x11_{altitude}m_roll_{roll}_pitch_{pitch}_{frequency}MHz.txt`

### Examples
```
cessna-VHF_121.5MHz_pattern.txt
yagi2x11_0m_roll_0_pitch_45_144MHz.txt
10000m_roll_0_pitch_0.txt
```

## Quality Validation

### Automated Checks
1. **File Size**: Must be >500 bytes
2. **Header Validation**: Must contain required header
3. **Data Validation**: Must have 1,200+ data lines
4. **Numeric Validation**: All gain values must be numeric
5. **Coverage Validation**: Full elevation/azimuth coverage

### Manual Checks
1. **Gain Realism**: Gain values should be realistic for antenna type
2. **Pattern Shape**: Should match expected antenna characteristics
3. **Frequency Accuracy**: Must match specified frequency
4. **Attitude Accuracy**: Must match specified roll/pitch angles

## Generation Standards

### Coordinate Systems
- **Elevation (Theta)**: 0° (horizontal) to 180° (vertical)
- **Azimuth (Phi)**: 0° to 360° (full rotation)
- **Resolution**: 5° increments (37×73 = 2,701 points)

### Attitude Transformations
- **Roll**: -90° to +90° (aircraft banking)
- **Pitch**: -90° to +90° (aircraft nose up/down)
- **Altitude**: 0m to 20,000m (ground to high altitude)

### Frequency Coverage
- **HF**: 1.8-30 MHz
- **VHF**: 30-300 MHz
- **UHF**: 300-3000 MHz

## Validation Tools

### Quick Validation Script
```bash
./quick_pattern_check.sh
```

### Comprehensive Validation
```bash
./validate_patterns_efficient.sh
```

### Manual Validation
```bash
# Check file size
wc -c pattern_file.txt

# Check data lines
grep -v "^#" pattern_file.txt | wc -l

# Check header
head -10 pattern_file.txt
```

## Error Handling

### Common Issues
1. **Incomplete Files**: <500 bytes (placeholder files)
2. **Missing Headers**: No FGCom-mumble header
3. **Invalid Data**: Non-numeric gain values
4. **Insufficient Coverage**: <1,200 data lines

### Resolution
1. **Remove incomplete files**
2. **Regenerate missing patterns**
3. **Validate data format**
4. **Check generation parameters**

## Maintenance

### Regular Tasks
1. **Monthly validation** of all pattern files
2. **Cleanup** of incomplete/placeholder files
3. **Regeneration** of missing patterns
4. **Documentation** updates for new patterns

### Quality Assurance
1. **Automated validation** in CI/CD pipeline
2. **Manual review** of new pattern types
3. **Performance testing** of pattern loading
4. **User feedback** integration

## Compliance

All pattern files must comply with these standards to be included in the FGCom-mumble system. Non-compliant files will be automatically detected and flagged for correction or removal.

## Support

For questions about pattern file standards or validation issues, refer to:
- Pattern generation documentation
- Validation script documentation  
- FGCom-mumble technical documentation
