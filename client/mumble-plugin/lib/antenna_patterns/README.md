# FGCom-Mumble Antenna Pattern Collection

This directory contains EZNEC antenna pattern files organized by vehicle/platform type and antenna configuration.

## Directory Structure

### Ground-based/
- **yagi_40m/**: 40-meter Yagi antennas (Hy-Gain TH-3DXX, Mosley TA-40)
- **yagi_30m/**: 30-meter Yagi antennas (multiband designs)
- **yagi_20m/**: 20-meter Yagi antennas (Cushcraft A3WS, Force 12 C-3)
- **yagi_15m/**: 15-meter Yagi antennas (Cushcraft A3S tribander)
- **yagi_10m/**: 10-meter Yagi antennas (Hy-Gain TH-4DXX)
- **yagi_6m/**: 6-meter Yagi antennas (Hy-Gain VB-64FM)
- **dipole/**: Dipole antennas (horizontal, vertical, inverted-V)
- **vertical/**: Vertical antennas (ground plane, quarter-wave, loaded)
- **loop/**: Loop antennas (magnetic loop, delta loop, quad)
- **other/**: Other ground-based antennas

### Aircraft/
- **b737/**: Boeing 737 commercial airliner patterns
- **uh1_huey/**: Bell UH-1 Huey helicopter patterns
- **tu95_bear/**: Tu-95 Bear strategic bomber patterns
- **c130_hercules/**: C-130 Hercules transport patterns
- **cessna_172/**: Cessna 172 general aviation patterns
- **mi4_hound/**: Mil Mi-4 Hound helicopter patterns
- **other/**: Other aircraft patterns

### Boat/
- **sailboat_whip/**: Sailboat whip antennas
- **sailboat_backstay/**: Sailboat backstay antennas
- **other/**: Other boat antennas

### Ship/
- **containership/**: Container ship antennas (80m loop, HF systems)
- **other/**: Other ship antennas

### Vehicle/
- **ford_transit/**: Ford Transit camper van patterns
- **vw_passat/**: VW Passat sedan patterns
- **other/**: Other vehicle patterns

### Military-land/
- **nato_jeep/**: NATO military vehicle patterns (45° tied-down)
- **soviet_uaz/**: Soviet military vehicle patterns (45° tied-down)
- **other/**: Other military land vehicle patterns

## File Naming Convention

EZNEC files follow this naming pattern:
```
[antenna_model]_[frequency]_[configuration].ez
```

Examples:
- `hy_gain_th3dxx_40m.ez` - Hy-Gain TH-3DXX 40-meter Yagi
- `tu95_bear_hf_sigint.ez` - Tu-95 Bear HF SIGINT system
- `sailboat_23ft_whip_20m.ez` - Sailboat 23ft whip for 20m band

## Altitude-Dependent Patterns

For aircraft antennas, altitude-dependent patterns are generated using the `altitude_sweep.sh` script:

```bash
./altitude_sweep.sh antenna_file.ez frequency_mhz [output_directory]
```

This creates patterns at multiple altitudes:
- **Ground Effect Zone (0-1000m)**: Dense sampling (50-100m intervals)
- **Low Altitude (1000-3000m)**: Moderate sampling (200-300m intervals)
- **Medium Altitude (3000-8000m)**: Wide intervals (500-1000m)
- **High Altitude (8000-15000m)**: Very wide intervals (1000-2000m)

## Popular Yagi Antennas by Band

### 40 Meters (7.0-7.3 MHz)
- **Hy-Gain TH-3DXX**: 3 elements, 6-7 dBi, 30-36 ft boom
- **Mosley TA-40**: 3 elements, 6-7 dBi, 30-36 ft boom

### 30 Meters (10.1-10.15 MHz)
- **Multiband designs**: 2-3 elements, 4-6 dBi, often tribander

### 20 Meters (14.0-14.35 MHz)
- **Cushcraft A3WS**: 3 elements, 6-7 dBi, 18-24 ft boom
- **Force 12 C-3**: 3 elements, 6-7 dBi, 18-24 ft boom

### 15 Meters (21.0-21.45 MHz)
- **Cushcraft A3S**: 3 elements, 6-7 dBi, 18-24 ft boom (tribander)

### 10 Meters (28.0-29.7 MHz)
- **Hy-Gain TH-4DXX**: 4 elements, 8-9 dBi, 20-24 ft boom

### 6 Meters (50-54 MHz)
- **Hy-Gain VB-64FM**: 4 elements, 8-9 dBi, 8-10 ft boom

## Usage in FGCom-Mumble

The antenna patterns are used by the propagation engine to:

1. **Calculate antenna gain** at specific angles and frequencies
2. **Account for ground effects** at different altitudes
3. **Model vehicle-specific** antenna performance
4. **Interpolate patterns** for intermediate frequencies/angles
5. **Apply altitude-dependent** pattern variations

## Pattern Processing

1. **Generate altitude patterns**: Use `altitude_sweep.sh` for aircraft
2. **Run 4NEC2**: Process .ez files to generate .out pattern files
3. **Parse patterns**: Use `pattern_interpolation.cpp` to create lookup tables
4. **Integrate**: Load patterns into FGCom-Mumble propagation engine

## Adding New Antennas

To add new antenna patterns:

1. Create EZNEC model file (.ez format)
2. Place in appropriate directory based on platform type
3. Follow naming convention
4. For aircraft: run altitude sweep to generate multi-altitude patterns
5. Process with 4NEC2 to generate radiation patterns
6. Update pattern interpolation system

## Ground System Modeling

Antenna patterns account for different ground systems:

- **Saltwater**: σ = 5 S/m, εᵣ = 81 (ships, coastal stations)
- **Average soil**: σ = 0.005 S/m, εᵣ = 13 (typical land stations)
- **Poor ground**: σ = 0.001 S/m, εᵣ = 5 (dry, rocky terrain)
- **Free space**: No ground effects (high altitude aircraft)

## Performance Characteristics

Each antenna model includes:

- **Gain patterns** (elevation and azimuth)
- **Impedance characteristics**
- **SWR performance**
- **Front-to-back ratio**
- **Beamwidth specifications**
- **Ground effect modeling**
- **Altitude-dependent variations** (aircraft only)

## Visualization Examples

### NATO Jeep Radiation Pattern Visualization

This is an example of how the radiation pattern looks on a NATO Jeep with an antenna tied down in a 45-degree fashion. The visualization shows:

- **Spherical/egg-shaped mesh** showing how the HF antenna radiates
- **Based on actual NEC2 simulation data** with realistic gain values
- **3D electromagnetic field pattern** visualization

#### What the wireframe shows:

- **Basic rectangular chassis outline** (footprint)
- **Simple cab structure** (rectangular box shape)
- **Minimal vertical lines** connecting ground to cab level

#### What's missing from the simplified model:

- **Side panels/doors** of the jeep
- **Wheels** (as noted in the visualization)
- **Hood/engine compartment** details
- **More realistic vehicle proportions**

The wireframe is quite simplified - it's more like a "schematic jeep" than a detailed vehicle model, but it effectively demonstrates the antenna radiation pattern characteristics.

**Screenshot location**: `/Screenshots/gain pattern.png`

This comprehensive collection provides realistic antenna modeling for all major vehicle types and antenna configurations used in amateur radio and commercial/military communications.
