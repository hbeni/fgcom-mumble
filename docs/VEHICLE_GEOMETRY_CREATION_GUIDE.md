# Vehicle Geometry Creation Guide

## Overview

This guide explains how to create the basic vehicle geometry (hull, sides, top, front, rear) that serves as the ground plane for antenna modeling in the FGCom-mumble system.

## Table of Contents

1. [Vehicle Geometry Requirements](#vehicle-geometry-requirements)
2. [Creating Vehicle Hull Geometry](#creating-vehicle-hull-geometry)
3. [NEC File Structure for Vehicles](#nec-file-structure-for-vehicles)
4. [Ground Plane Implementation](#ground-plane-implementation)
5. [Antenna Mounting Points](#antenna-mounting-points)
6. [Material Properties](#material-properties)
7. [Example: Abrams Tank Geometry](#example-abrams-tank-geometry)
8. [Validation and Testing](#validation-and-testing)

## Vehicle Geometry Requirements

### **Essential Components**

Every vehicle requires these basic geometric components:

1. **Hull/Body**: Main vehicle structure
2. **Sides**: Left and right side panels
3. **Top**: Upper surface/roof
4. **Front**: Front panel/grille
5. **Rear**: Rear panel/tailgate
6. **Treads/Tracks**: **CRITICAL** - Track system affects ground plane
7. **Ground Plane**: Complete conductive surface including treads

### **Abrams Tank Specifications**

- **Length**: 7.93 meters (26 feet)
- **Width**: 3.66 meters (12 feet)
- **Height**: 2.44 meters (8 feet)
- **Ground Clearance**: 0.43 meters (1.4 feet) - **CRITICAL PARAMETER**
- **Track Width**: 0.64 meters (2.1 feet) - **CRITICAL FOR ANTENNA MODELING**
- **Track Length**: 7.93 meters (26 feet) - **CRITICAL FOR ANTENNA MODELING**
- **Weight**: 62,000 kg (136,000 lbs)
- **Material**: Steel armor
- **Ground Plane Area**: ~29 m² (including treads)

## Creating Vehicle Hull Geometry

### **Step 1: Define Vehicle Dimensions**

```cpp
struct VehicleDimensions {
    float length_m;        // Vehicle length in meters
    float width_m;         // Vehicle width in meters
    float height_m;        // Vehicle height in meters
    float ground_clearance_m; // Ground clearance - CRITICAL for antenna modeling
    float track_width_m;   // Track width - CRITICAL for antenna modeling
    float track_length_m;  // Track length - CRITICAL for antenna modeling
    std::string material;  // Hull material (steel, aluminum, etc.)
};
```

### **Step 2: Create Hull Wire Structure**

The vehicle hull must be modeled as a wire structure in NEC format:

```
! Abrams Tank Hull Geometry
! Length: 7.93m, Width: 3.66m, Height: 2.44m
! Ground Clearance: 0.43m - CRITICAL for antenna modeling
! Material: Steel armor
! Ground plane: Complete hull surface
```

### **Step 3: Define Wire Segments**

Each surface of the vehicle must be defined as wire segments:

#### **Bottom Surface (Hull Floor)**
```
! Bottom surface - hull floor at ground clearance height
! Ground clearance: 0.43m above ground
GW 1 21 0 0 0.43 7.93 0 0.43 0.001    ! Front to rear
GW 2 21 0 0 0.43 0 3.66 0.43 0.001     ! Left to right
GW 3 21 7.93 0 0.43 7.93 3.66 0.43 0.001 ! Rear edge
GW 4 21 0 3.66 0.43 7.93 3.66 0.43 0.001 ! Right edge
```

#### **Left Side Surface**
```
! Left side surface - from ground clearance to top
GW 5 21 0 0 0.43 0 0 2.44 0.001      ! Front left corner
GW 6 21 0 0 2.44 7.93 0 2.44 0.001 ! Top edge
GW 7 21 7.93 0 0.43 7.93 0 2.44 0.001 ! Rear edge
GW 8 21 0 0 0.43 0 0 2.44 0.001      ! Front edge
```

#### **Right Side Surface**
```
! Right side surface - from ground clearance to top
GW 9 21 0 3.66 0.43 0 3.66 2.44 0.001 ! Front right corner
GW 10 21 0 3.66 2.44 7.93 3.66 2.44 0.001 ! Top edge
GW 11 21 7.93 3.66 0.43 7.93 3.66 2.44 0.001 ! Rear edge
GW 12 21 0 3.66 0.43 0 3.66 2.44 0.001 ! Front edge
```

#### **Top Surface (Roof)**
```
! Top surface - roof
GW 13 21 0 0 2.44 7.93 0 2.44 0.001 ! Front to rear
GW 14 21 0 0 2.44 0 3.66 2.44 0.001 ! Left to right
GW 15 21 7.93 0 2.44 7.93 3.66 2.44 0.001 ! Rear edge
GW 16 21 0 3.66 2.44 7.93 3.66 2.44 0.001 ! Right edge
```

#### **Front Surface**
```
! Front surface - from ground clearance to top
GW 17 21 0 0 0.43 0 0 2.44 0.001      ! Bottom to top
GW 18 21 0 0 2.44 0 3.66 2.44 0.001 ! Top edge
GW 19 21 0 3.66 0.43 0 3.66 2.44 0.001 ! Right edge
GW 20 21 0 0 0.43 0 3.66 0.43 0.001      ! Bottom edge
```

#### **Rear Surface**
```
! Rear surface - from ground clearance to top
GW 21 21 7.93 0 0.43 7.93 0 2.44 0.001 ! Bottom to top
GW 22 21 7.93 0 2.44 7.93 3.66 2.44 0.001 ! Top edge
GW 23 21 7.93 3.66 0.43 7.93 3.66 2.44 0.001 ! Right edge
GW 24 21 7.93 0 0.43 7.93 3.66 0.43 0.001 ! Bottom edge
```

#### **Track/Tread System - IN CONTACT WITH GROUND**
```
! Left track - CRITICAL for antenna modeling
! Tracks are IN DIRECT CONTACT with ground (Z=0)
GW 25 21 0 0 0 7.93 0 0 0.001              ! Left track bottom - ON GROUND
GW 26 21 0 0 0 0 0.64 0 0.001             ! Left track front - ON GROUND
GW 27 21 7.93 0 0 7.93 0.64 0 0.001       ! Left track rear - ON GROUND
GW 28 21 0 0.64 0 7.93 0.64 0 0.001       ! Left track top - ON GROUND

! Right track - CRITICAL for antenna modeling
! Tracks are IN DIRECT CONTACT with ground (Z=0)
GW 29 21 0 3.02 0 7.93 3.02 0 0.001       ! Right track bottom - ON GROUND
GW 30 21 0 3.02 0 0 3.66 0 0.001          ! Right track front - ON GROUND
GW 31 21 7.93 3.02 0 7.93 3.66 0 0.001    ! Right track rear - ON GROUND
GW 32 21 0 3.66 0 7.93 3.66 0 0.001       ! Right track top - ON GROUND
```

## Wheeled Vehicle Ground Plane - Different from Tracked Vehicles

### **Wheeled Vehicle Ground Plane Structure**

Wheeled vehicles have a **completely different** ground plane structure than tracked vehicles:

1. **Metal Rims**: Steel/aluminum rims provide conductive ground plane
2. **Tire Insulation**: Rubber tires **INSULATE** the metal inside from ground contact
3. **Ground Clearance**: Vehicle body is elevated above ground by tire height
4. **Limited Ground Contact**: Only rim edges may contact ground
5. **Insulated Ground Plane**: Metal inside tires is **NOT** in direct contact with ground

### **Wheeled Vehicle vs. Tracked Vehicle Ground Planes**

| Vehicle Type | Ground Contact | Ground Plane | Ground Clearance |
|--------------|---------------|--------------|------------------|
| **Tracked (Abrams)** | **Direct contact** (Z=0) | Tracks on ground | Hull at 0.43m |
| **Wheeled (HMMWV)** | **Insulated contact** | Rims only | Body at 0.3-0.5m |

### **Wheeled Vehicle Ground Plane Effects**

1. **Reduced Ground Contact**: Only rim edges contact ground
2. **Insulated Metal**: Metal inside tires is insulated by rubber
3. **Higher Ground Clearance**: Vehicle body elevated by tire height
4. **Limited Ground Plane**: Smaller effective ground plane area
5. **Different Antenna Patterns**: Significantly different from tracked vehicles

### **Example: HMMWV Wheeled Vehicle**

#### **HMMWV Specifications**
- **Length**: 4.57 meters (15 feet)
- **Width**: 2.16 meters (7.1 feet)
- **Height**: 1.83 meters (6 feet)
- **Ground Clearance**: 0.41 meters (1.35 feet) - **CRITICAL PARAMETER**
- **Tire Diameter**: 0.81 meters (2.65 feet)
- **Rim Material**: Steel/aluminum
- **Tire Insulation**: Rubber - **INSULATES** metal inside

#### **HMMWV Ground Plane Structure**
```
! HMMWV Wheeled Vehicle - VHF Antenna (30 MHz)
! Vehicle dimensions: 4.57m x 2.16m x 1.83m
! Ground clearance: 0.41m - CRITICAL for antenna modeling
! Tire system: 0.81m diameter - INSULATED from ground
! Material: Steel/aluminum rims, rubber tires
! Ground plane: Rims only, NOT tires

! Vehicle Hull Geometry
! Bottom surface - at ground clearance height
GW 1 21 0 0 0.41 4.57 0 0.41 0.001
GW 2 21 0 0 0.41 0 2.16 0.41 0.001
GW 3 21 4.57 0 0.41 4.57 2.16 0.41 0.001
GW 4 21 0 2.16 0.41 4.57 2.16 0.41 0.001

! Wheel System - INSULATED from ground
! Front left wheel - rim only, tire insulated
GW 25 21 0.5 0.3 0.41 0.5 0.3 0.41 0.001    ! Front left rim
GW 26 21 0.5 0.3 0.41 0.5 0.3 0.41 0.001    ! Front left rim edge

! Front right wheel - rim only, tire insulated
GW 27 21 0.5 1.86 0.41 0.5 1.86 0.41 0.001  ! Front right rim
GW 28 21 0.5 1.86 0.41 0.5 1.86 0.41 0.001  ! Front right rim edge

! Rear left wheel - rim only, tire insulated
GW 29 21 4.07 0.3 0.41 4.07 0.3 0.41 0.001  ! Rear left rim
GW 30 21 4.07 0.3 0.41 4.07 0.3 0.41 0.001  ! Rear left rim edge

! Rear right wheel - rim only, tire insulated
GW 31 21 4.07 1.86 0.41 4.07 1.86 0.41 0.001 ! Rear right rim
GW 32 21 4.07 1.86 0.41 4.07 1.86 0.41 0.001 ! Rear right rim edge
```

#### **Wheeled Vehicle Ground Plane Effects**

1. **Limited Ground Contact**: Only rim edges contact ground
2. **Insulated Metal**: Metal inside tires is insulated by rubber
3. **Reduced Ground Plane**: Smaller effective ground plane area
4. **Higher Ground Clearance**: Vehicle body elevated by tire height
5. **Different Antenna Patterns**: Significantly different from tracked vehicles

## Track/Tread System - Critical for Antenna Modeling

### **Why Tracks Matter for Antennas**

The **track system** is **CRITICAL** for antenna modeling because:

1. **Extended Ground Plane**: Tracks extend the ground plane significantly
2. **Conductive Path**: Steel tracks provide excellent electrical conductivity
3. **Ground Effect**: Tracks create a large, conductive ground plane
4. **Pattern Distortion**: Track geometry affects antenna radiation patterns
5. **Frequency Response**: Track length affects different frequencies differently

### **Abrams Track Specifications**

- **Track Width**: 0.64 meters (2.1 feet)
- **Track Length**: 7.93 meters (26 feet)
- **Track Material**: Steel
- **Ground Contact**: **IN DIRECT CONTACT WITH GROUND** (Z=0)
- **Conductivity**: 1.0e7 S/m (steel)
- **Ground Plane**: Tracks form part of the ground plane at ground level

### **Track Impact on Antenna Performance**

| Frequency | Track Length vs Wavelength | Effect on Antenna |
|-----------|---------------------------|-------------------|
| 3 MHz (HF) | 7.93m vs 100m (λ/12.6) | Minor effect |
| 30 MHz (VHF) | 7.93m vs 10m (λ/1.26) | **Major effect** |
| 300 MHz (UHF) | 7.93m vs 1m (λ/7.93) | **Significant effect** |

### **Track Ground Plane Effects**

1. **Extended Ground Plane**: Tracks extend ground plane by 0.64m on each side **AT GROUND LEVEL**
2. **Direct Ground Contact**: Tracks are **IN DIRECT CONTACT** with ground (Z=0)
3. **Improved Ground Contact**: Better electrical connection to earth through direct contact
4. **Reduced Ground Losses**: Lower resistance path to ground through steel tracks
5. **Pattern Enhancement**: Improved antenna patterns due to better ground plane
6. **Ground Reflection**: Tracks create additional ground reflection effects

### **Why Ground Contact is CRITICAL**

The fact that tracks are **IN DIRECT CONTACT** with the ground is **CRITICAL** for antenna modeling because:

1. **Electrical Connection**: Direct contact provides excellent electrical connection to earth
2. **Ground Plane Extension**: Tracks extend the ground plane **AT GROUND LEVEL** (Z=0)
3. **Reduced Resistance**: Direct contact minimizes ground resistance
4. **Improved Efficiency**: Better ground contact improves antenna efficiency
5. **Pattern Accuracy**: Ground contact affects radiation patterns significantly
6. **Frequency Response**: Ground contact affects different frequencies differently

### **Ground Contact vs. Ground Clearance**

- **Ground Clearance (0.43m)**: Space between hull bottom and ground
- **Track Contact (0m)**: Tracks are **IN DIRECT CONTACT** with ground
- **Combined Effect**: Both parameters affect antenna performance
- **Ground Plane**: Hull at 0.43m + Tracks at 0m = Complex ground plane

## NEC File Structure for Vehicles

### **Complete NEC File Template**

```
! Abrams Tank - VHF Antenna (30 MHz)
! Vehicle dimensions: 7.93m x 3.66m x 2.44m
! Ground clearance: 0.43m - CRITICAL for antenna modeling
! Track system: 0.64m wide x 7.93m long - CRITICAL for antenna modeling
! Material: Steel armor
! Ground plane: Complete hull surface including tracks

! Vehicle Hull Geometry
! Bottom surface - at ground clearance height
GW 1 21 0 0 0.43 7.93 0 0.43 0.001
GW 2 21 0 0 0.43 0 3.66 0.43 0.001
GW 3 21 7.93 0 0.43 7.93 3.66 0.43 0.001
GW 4 21 0 3.66 0.43 7.93 3.66 0.43 0.001

! Track/Tread System - CRITICAL for antenna modeling
! Tracks are IN DIRECT CONTACT with ground (Z=0)
! Left track - ON GROUND
GW 25 21 0 0 0 7.93 0 0 0.001              ! Left track bottom - ON GROUND
GW 26 21 0 0 0 0 0.64 0 0.001             ! Left track front - ON GROUND
GW 27 21 7.93 0 0 7.93 0.64 0 0.001       ! Left track rear - ON GROUND
GW 28 21 0 0.64 0 7.93 0.64 0 0.001       ! Left track top - ON GROUND

! Right track - ON GROUND
GW 29 21 0 3.02 0 7.93 3.02 0 0.001       ! Right track bottom - ON GROUND
GW 30 21 0 3.02 0 0 3.66 0 0.001          ! Right track front - ON GROUND
GW 31 21 7.93 3.02 0 7.93 3.66 0 0.001    ! Right track rear - ON GROUND
GW 32 21 0 3.66 0 7.93 3.66 0 0.001       ! Right track top - ON GROUND

! Left side surface
GW 5 21 0 0 0 0 0 2.44 0.001
GW 6 21 0 0 2.44 7.93 0 2.44 0.001
GW 7 21 7.93 0 0 7.93 0 2.44 0.001
GW 8 21 0 0 0 0 0 2.44 0.001

! Right side surface
GW 9 21 0 3.66 0 0 3.66 2.44 0.001
GW 10 21 0 3.66 2.44 7.93 3.66 2.44 0.001
GW 11 21 7.93 3.66 0 7.93 3.66 2.44 0.001
GW 12 21 0 3.66 0 0 3.66 2.44 0.001

! Top surface
GW 13 21 0 0 2.44 7.93 0 2.44 0.001
GW 14 21 0 0 2.44 0 3.66 2.44 0.001
GW 15 21 7.93 0 2.44 7.93 3.66 2.44 0.001
GW 16 21 0 3.66 2.44 7.93 3.66 2.44 0.001

! Front surface
GW 17 21 0 0 0 0 0 2.44 0.001
GW 18 21 0 0 2.44 0 3.66 2.44 0.001
GW 19 21 0 3.66 0 0 3.66 2.44 0.001
GW 20 21 0 0 0 0 3.66 0 0.001

! Rear surface
GW 21 21 7.93 0 0 7.93 0 2.44 0.001
GW 22 21 7.93 0 2.44 7.93 3.66 2.44 0.001
GW 23 21 7.93 3.66 0 7.93 3.66 2.44 0.001
GW 24 21 7.93 0 0 7.93 3.66 0 0.001

! Antenna Mounting Points
! VHF Antenna on turret (center of vehicle)
GW 25 21 3.965 1.83 2.44 3.965 1.83 4.44 0.001

! Ground plane definition
GD 1 0 0 0 0.005 0.013

! Frequency and power
FR 0 1 0 0 30 0

! Excitation
EX 0 25 1 0 1 0

! Radiation pattern
RP 0 91 360 1000 0 0 0 0

! End of file
EN
```

## Ground Clearance - Critical Parameter

### **Why Ground Clearance Matters**

The **ground clearance** (height between ground and vehicle bottom) is **CRITICAL** for antenna modeling because:

1. **Ground Effect**: The space between vehicle and ground affects antenna patterns
2. **Reflection**: Radio waves reflect off both the vehicle hull AND the ground
3. **Interference**: Ground clearance affects signal propagation and interference patterns
4. **Pattern Distortion**: Different clearances create different radiation patterns
5. **Frequency Dependency**: Ground effects vary significantly with frequency

### **Abrams Tank Ground Clearance**

- **Ground Clearance**: 0.43 meters (1.4 feet)
- **Effect on VHF (30 MHz)**: Significant ground reflection and pattern distortion
- **Effect on UHF (300 MHz)**: Moderate ground effects
- **Effect on HF (3 MHz)**: Major ground effects, pattern completely different

### **Ground Clearance Impact on Antenna Performance**

| Frequency | Ground Clearance Effect | Pattern Change |
|-----------|------------------------|----------------|
| 3 MHz (HF) | Major - λ/4 = 25m, clearance << λ/4 | Severe distortion |
| 30 MHz (VHF) | Significant - λ/4 = 2.5m, clearance < λ/4 | Moderate distortion |
| 300 MHz (UHF) | Moderate - λ/4 = 0.25m, clearance > λ/4 | Minor distortion |

## Ground Plane Implementation

### **Ground Plane Characteristics**

The vehicle hull serves as the ground plane with these properties:

- **Material**: Steel armor
- **Conductivity**: 1.0e7 S/m (steel)
- **Thickness**: 0.001m (1mm)
- **Area**: 29 m² (7.93m × 3.66m)
- **Ground Clearance**: 0.43m - **CRITICAL PARAMETER**
- **Resistance**: ~0.003 Ω

### **Ground Plane Effects**

The vehicle hull ground plane provides:

1. **Reflection**: Radio waves reflect off the hull surface
2. **Shielding**: Hull provides electromagnetic shielding
3. **Ground Effect**: Hull acts as a ground plane for antennas
4. **Pattern Distortion**: Hull shape affects antenna patterns

## Antenna Mounting Points

### **Abrams Tank Antenna Locations**

1. **Turret Mount**: Center of vehicle, 2.44m height
2. **Hull Mount**: Front of vehicle, 1.5m height
3. **Rear Mount**: Rear of vehicle, 1.5m height
4. **Side Mount**: Left/right sides, 1.5m height

### **Mounting Point Coordinates**

```cpp
struct AntennaMountingPoint {
    std::string name;           // "turret", "hull_front", etc.
    float x_m;                  // X coordinate in meters
    float y_m;                  // Y coordinate in meters
    float z_m;                  // Z coordinate in meters
    std::string antenna_type;   // "vhf", "uhf", "hf"
    float max_power_watts;      // Maximum power
    bool is_rotating;           // Can antenna rotate?
};
```

## Material Properties

### **Steel Armor Properties**

- **Conductivity**: 1.0e7 S/m
- **Permeability**: 1000 (ferromagnetic)
- **Thickness**: 0.001m (1mm)
- **Resistance**: 0.003 Ω
- **Shielding**: 40 dB at 30 MHz

### **Material Definition in NEC**

```
! Material properties for steel armor
! Conductivity: 1.0e7 S/m
! Thickness: 0.001m
! Shielding: 40 dB at 30 MHz
```

## Example: Abrams Tank Geometry

### **Complete Vehicle Model**

```cpp
class AbramsTankGeometry {
private:
    VehicleDimensions dimensions;
    std::vector<WireSegment> hull_segments;
    std::vector<AntennaMountingPoint> antenna_points;
    
public:
    AbramsTankGeometry() {
        dimensions.length_m = 7.93;
        dimensions.width_m = 3.66;
        dimensions.height_m = 2.44;
        dimensions.ground_clearance_m = 0.43;  // CRITICAL PARAMETER
        dimensions.track_width_m = 0.64;      // CRITICAL PARAMETER
        dimensions.track_length_m = 7.93;     // CRITICAL PARAMETER
        dimensions.material = "steel";
    }
    
    void createHullGeometry() {
        // Create bottom surface
        createBottomSurface();
        
        // Create side surfaces
        createLeftSide();
        createRightSide();
        
        // Create top surface
        createTopSurface();
        
        // Create front surface
        createFrontSurface();
        
        // Create rear surface
        createRearSurface();
        
        // Create track system - CRITICAL for antenna modeling
        createTrackSystem();
    }
    
    void createTrackSystem() {
        // Create left track
        createLeftTrack();
        
        // Create right track
        createRightTrack();
    }
    
    void createAntennaMountingPoints() {
        // Turret mount (center)
        antenna_points.push_back({
            "turret", 3.965, 1.83, 2.44, "vhf", 25.0, true
        });
        
        // Hull front mount
        antenna_points.push_back({
            "hull_front", 1.0, 1.83, 1.5, "vhf", 25.0, false
        });
        
        // Hull rear mount
        antenna_points.push_back({
            "hull_rear", 6.93, 1.83, 1.5, "vhf", 25.0, false
        });
    }
};
```

## Validation and Testing

### **Geometry Validation**

1. **Wire Connectivity**: Ensure all wires are properly connected
2. **Surface Completeness**: Verify all surfaces are defined
3. **Antenna Placement**: Check antenna mounting points
4. **Material Properties**: Validate material characteristics

### **Simulation Testing**

1. **Pattern Generation**: Generate radiation patterns
2. **Performance Analysis**: Analyze antenna performance
3. **Ground Effect**: Verify ground plane effects
4. **Integration Testing**: Test with vehicle system

### **Quality Assurance**

1. **NEC File Validation**: Check NEC file syntax
2. **Geometry Accuracy**: Verify dimensions and coordinates
3. **Material Properties**: Validate material characteristics
4. **Performance Testing**: Test antenna performance

## Conclusion

Creating vehicle geometry for antenna modeling requires:

1. **Complete Hull Geometry**: All surfaces must be defined
2. **Ground Clearance**: **CRITICAL** - Height between ground and vehicle bottom
3. **Track System**: **CRITICAL** - Track geometry significantly affects antenna performance
4. **Proper Ground Plane**: Hull AND tracks serve as ground plane
5. **Antenna Mounting**: Define antenna mounting points
6. **Material Properties**: Specify material characteristics
7. **Validation**: Test and validate the model

### **Key Takeaways for Abrams Tank (Tracked Vehicle):**

- **Ground Clearance (0.43m)**: Critical for HF/VHF antenna modeling
- **Track System (0.64m × 7.93m)**: Major impact on antenna patterns
- **Track Ground Contact (Z=0)**: **CRITICAL** - Tracks are IN DIRECT CONTACT with ground
- **Extended Ground Plane**: Tracks extend ground plane by 0.64m on each side **AT GROUND LEVEL**
- **Frequency Effects**: Track length affects different frequencies differently
- **Pattern Distortion**: Both ground clearance and tracks affect radiation patterns
- **Complex Ground Plane**: Hull at 0.43m + Tracks at 0m = Multi-level ground plane

### **Key Takeaways for HMMWV (Wheeled Vehicle):**

- **Ground Clearance (0.41m)**: Critical for HF/VHF antenna modeling
- **Wheel System (0.81m diameter)**: **INSULATED** from ground by rubber tires
- **Rim Ground Contact**: Only rim edges contact ground, **NOT** the metal inside tires
- **Limited Ground Plane**: Smaller effective ground plane area than tracked vehicles
- **Insulated Metal**: Metal inside tires is **INSULATED** by rubber from ground contact
- **Different Patterns**: Significantly different antenna patterns from tracked vehicles
- **Reduced Ground Effect**: Less ground plane effect than tracked vehicles

### **Tracked vs. Wheeled Vehicle Comparison:**

| Parameter | Tracked (Abrams) | Wheeled (HMMWV) |
|-----------|------------------|------------------|
| **Ground Contact** | **Direct** (Z=0) | **Insulated** (rims only) |
| **Ground Plane** | **Extended** (tracks) | **Limited** (rims) |
| **Ground Clearance** | 0.43m | 0.41m |
| **Ground Effect** | **Major** | **Minor** |
| **Antenna Patterns** | **Distorted** by tracks | **Less distorted** |
| **Frequency Response** | **Track length dependent** | **Rim size dependent** |

The Abrams tank example demonstrates how to create a complete vehicle geometry with proper ground plane implementation **including the critical track system** for antenna modeling.

The HMMWV example demonstrates how wheeled vehicles have **completely different** ground plane characteristics due to **insulated tires** and **limited ground contact** compared to tracked vehicles.

**Both vehicle types require different approaches to antenna modeling due to their fundamentally different ground plane structures.**
