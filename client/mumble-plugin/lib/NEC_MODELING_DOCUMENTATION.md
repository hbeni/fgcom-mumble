# NEC Modeling and Antenna Calculations Documentation

## Overview

This document provides comprehensive guidance for creating NEC (Numerical Electromagnetics Code) models for antenna simulation, including wavelength calculations, minimum spacing requirements, and practical examples for various vehicle types.

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
