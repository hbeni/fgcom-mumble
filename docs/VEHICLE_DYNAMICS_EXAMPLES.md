# Vehicle Dynamics Integration Examples

## Overview

This document provides comprehensive examples of how vehicle dynamics (heading, speed, attitude, altitude) affect radio propagation calculations and antenna performance in FGCom-mumble.

## Key Concepts

### Vehicle Dynamics Impact on Antennas

1. **Yagi Antennas**: Vehicle attitude directly affects pointing direction
2. **Dipole Antennas**: Vehicle orientation affects polarization
3. **Vertical Antennas**: Least affected by vehicle attitude
4. **Loop Antennas**: Cannot be rotated, but vehicle attitude affects orientation
5. **Whip Antennas**: Similar to vertical antennas

### Propagation Model Integration

Vehicle dynamics are automatically integrated into propagation calculations to provide accurate signal quality predictions.

## Example 1: General Aviation Aircraft with Realistic Antennas

### Scenario
- **Aircraft**: Cessna 172 (General Aviation)
- **Antenna**: Loaded whip antenna (realistic for small GA)
- **Frequency**: 14.230 MHz (20m SSB)
- **Target**: Ground station 100km away

### Vehicle Dynamics
```json
{
  "vehicle_id": "N12345",
  "position": {
    "latitude": 40.7128,
    "longitude": -74.0060,
    "altitude_ft_msl": 3500.0,
    "altitude_ft_agl": 3000.0
  },
  "attitude": {
    "pitch_deg": 2.5,      // Nose up
    "roll_deg": -1.2,      // Left wing down
    "yaw_deg": 045.0,      // Heading 045°
    "magnetic_heading_deg": 043.5
  },
  "velocity": {
    "speed_knots": 120.0,
    "course_deg": 045.0,
    "vertical_speed_fpm": 500.0
  },
  "antennas": [
    {
      "antenna_id": "vhf_com_blade",
      "antenna_type": "blade",
      "frequency_range": "118-137 MHz",
      "mounting": "wing_strut",
      "length": "0.5m",
      "power": "25W",
      "azimuth_deg": 0.0,      // Omnidirectional
      "elevation_deg": 0.0
    },
    {
      "antenna_id": "hf_loaded_whip",
      "antenna_type": "loaded_whip",
      "frequency_range": "3-30 MHz",
      "mounting": "fuselage_top",
      "length": "2.6m",
      "power": "100W",
      "loading_coil": true,
      "azimuth_deg": 0.0,      // Omnidirectional
      "elevation_deg": 0.0
    }
  ]
}
```

### Antenna Orientation Calculation

**Realistic Small Aircraft Constraints:**
- **VHF COM Blade**: Omnidirectional, minimal attitude effects
- **HF Loaded Whip**: Omnidirectional, some attitude effects on loading coil
- **No steerable antennas**: Small GA aircraft don't have directional antennas
- **Simple mounting**: Fixed positions, no rotation systems

**Vehicle Dynamics Effects:**
- **VHF Blade**: Minimal effect from aircraft attitude
- **HF Whip**: Loading coil efficiency affected by aircraft attitude
- **Ground plane**: Aircraft fuselage provides ground plane reference
- **Altitude effects**: Higher altitude improves HF propagation

### Propagation Calculation

```json
{
  "lat1": 40.7128,
  "lon1": -74.0060,
  "lat2": 39.7128,
  "lon2": -75.0060,
  "alt1": 3000.0,
  "alt2": 100.0,
  "frequency_mhz": 14.230,
  "power_watts": 100.0,
  "antenna_type": "loaded_whip",
  "include_vehicle_dynamics": true,
  "vehicle_id": "N12345",
  "antenna_id": "hf_loaded_whip"
}
```

**Result:**
```json
{
  "signal_quality": 0.72,
  "signal_strength_db": -3.8,
  "antenna_gain_db": -2.1,
  "vehicle_attitude_effect_db": -1.2,
  "loading_coil_efficiency": 0.65,
  "ground_plane_effect_db": 2.3,
  "propagation_mode": "skywave"
}
```

## Example 2: Sailboat with Backstay Antenna

### Scenario
- **Vessel**: 40-foot sailboat
- **Antenna**: Backstay antenna (inverted-L configuration)
- **Frequency**: 14.230 MHz (20m SSB)
- **Target**: Ground station with Yagi antenna 200km away

### Vehicle Dynamics
```json
{
  "vehicle_id": "SV_SEAHAWK",
  "position": {
    "latitude": 41.8781,
    "longitude": -87.6298,
    "altitude_ft_msl": 0.0,
    "altitude_ft_agl": 0.0
  },
  "attitude": {
    "pitch_deg": 5.0,      // Bow up (sailing upwind)
    "roll_deg": 15.0,      // Port side down (heeling)
    "yaw_deg": 030.0,      // Heading 030°
    "magnetic_heading_deg": 028.5
  },
  "velocity": {
    "speed_knots": 8.0,
    "course_deg": 030.0,
    "vertical_speed_fpm": 0.0
  },
  "antennas": [
    {
      "antenna_id": "backstay_20m",
      "antenna_type": "inverted_l",
      "azimuth_deg": 0.0,      // Omnidirectional
      "elevation_deg": 0.0
    }
  ]
}
```

### Antenna Orientation Calculation

**Backstay Antenna Effects:**
- Vehicle roll: 15° (Port side down)
- Antenna polarization: Affected by roll
- Effective gain: Reduced by 1.5dB due to roll
- Signal quality: Good (omnidirectional antenna)

### Propagation Calculation

```json
{
  "lat1": 41.8781,
  "lon1": -87.6298,
  "lat2": 41.4281,
  "lon2": -87.1298,
  "alt1": 0.0,
  "alt2": 0.0,
  "frequency_mhz": 14.230,
  "power_watts": 100.0,
  "antenna_type": "inverted_l",
  "include_vehicle_dynamics": true,
  "vehicle_id": "SV_SEAHAWK",
  "antenna_id": "backstay_20m"
}
```

**Result:**
```json
{
  "signal_quality": 0.78,
  "signal_strength_db": -3.2,
  "antenna_gain_db": 2.1,
  "vehicle_attitude_effect_db": -1.5,
  "propagation_mode": "groundwave",
  "saltwater_ground_effect": 2.3
}
```

## Example 3: Ground Station with Rotatable Yagi (Future Moonbounce/Satellite)

### Scenario
- **Station**: Amateur radio station
- **Antenna**: Cushcraft A3WS 20m Yagi with rotator (3-element)
- **Frequency**: 14.230 MHz (20m SSB)
- **Target**: Sailboat 200km away
- **Note**: Auto-tracking reserved for future moonbounce/satellite work with Doppler shift

### Vehicle Dynamics
```json
{
  "vehicle_id": "W1ABC",
  "position": {
    "latitude": 42.3601,
    "longitude": -71.0589,
    "altitude_ft_msl": 100.0,
    "altitude_ft_agl": 100.0
  },
  "attitude": {
    "pitch_deg": 0.0,      // Ground station
    "roll_deg": 0.0,       // Ground station
    "yaw_deg": 0.0,        // Ground station
    "magnetic_heading_deg": 0.0
  },
  "velocity": {
    "speed_knots": 0.0,
    "course_deg": 0.0,
    "vertical_speed_fpm": 0.0
  },
  "antennas": [
    {
      "antenna_id": "cushcraft_a3ws_20m",
      "antenna_type": "yagi",
      "azimuth_deg": 045.0,    // Pointing northeast
      "elevation_deg": 20.0,   // 20° elevation
      "is_auto_tracking": true,
      "rotation_speed_deg_per_sec": 5.0
    }
  ]
}
```

### Auto-tracking Calculation (Future Moonbounce/Satellite Work)

**Current Target (Sailboat):**
- Latitude: 43.3601
- Longitude: -70.0589
- Altitude: 0ft (sea level)

**Optimal Antenna Orientation:**
- Bearing to target: 045°
- Elevation angle: 5° (low angle for ground wave)
- Auto-tracking: Manual rotation only (future: automatic with Doppler shift for moonbounce/satellite)

**Antenna Rotation:**
```json
{
  "target_azimuth_deg": 045.0,
  "target_elevation_deg": 5.0,
  "current_azimuth_deg": 045.0,
  "current_elevation_deg": 20.0,
  "rotation_time_sec": 1.0,
  "auto_tracking": true
}
```

### Propagation Calculation

```json
{
  "lat1": 42.3601,
  "lon1": -71.0589,
  "lat2": 43.3601,
  "lon2": -70.0589,
  "alt1": 100.0,
  "alt2": 0.0,
  "frequency_mhz": 14.230,
  "power_watts": 100.0,
  "antenna_type": "yagi",
  "include_vehicle_dynamics": true,
  "vehicle_id": "W1ABC",
  "antenna_id": "cushcraft_a3ws_20m"
}
```

**Result:**
```json
{
  "signal_quality": 0.92,
  "signal_strength_db": 1.8,
  "antenna_gain_db": 7.0,
  "vehicle_attitude_effect_db": 0.0,
  "effective_antenna_azimuth_deg": 045.0,
  "effective_antenna_elevation_deg": 15.0,
  "propagation_mode": "skywave",
  "auto_tracking_active": false,
  "note": "Auto-tracking reserved for future moonbounce/satellite work with Doppler shift"
}
```

## Future Enhancements: Moonbounce and Satellite Work

### Planned Auto-tracking Features
- **Moonbounce (EME)**: Automatic tracking of moon position with Doppler shift compensation
- **Satellite Communication**: Automatic tracking of satellite orbits with Doppler shift
- **Doppler Shift Calculation**: Real-time frequency adjustment based on relative velocity
- **Orbital Mechanics**: Integration with satellite ephemeris data

### Doppler Shift Implementation (Future)
```json
{
  "doppler_shift": {
    "enabled": true,
    "target_type": "moon",
    "relative_velocity_ms": 0.0,
    "frequency_shift_hz": 0.0,
    "compensation_applied": true
  }
}
```

## Example 4: Large Commercial Aircraft with Realistic Antennas

### Scenario
- **Aircraft**: Boeing 737-800 (Commercial Airliner)
- **Antennas**: HF probe, VHF COM, SATCOM systems
- **Frequency**: 8.900 MHz (Aeronautical HF)
- **Target**: Ground station 2000km away

### Vehicle Dynamics
```json
{
  "vehicle_id": "N737AB",
  "position": {
    "latitude": 40.7128,
    "longitude": -74.0060,
    "altitude_ft_msl": 35000.0,
    "altitude_ft_agl": 35000.0
  },
  "attitude": {
    "pitch_deg": 1.5,      // Slight nose up
    "roll_deg": 0.0,       // Level flight
    "yaw_deg": 270.0,      // Heading 270°
    "magnetic_heading_deg": 268.5
  },
  "velocity": {
    "speed_knots": 450.0,
    "course_deg": 270.0,
    "vertical_speed_fpm": 0.0
  },
  "antennas": [
    {
      "antenna_id": "hf_probe_belly",
      "antenna_type": "probe",
      "frequency_range": "2-30 MHz",
      "mounting": "belly_mounted",
      "length": "3.0m",
      "power": "400W",
      "azimuth_deg": 0.0,      // Omnidirectional
      "elevation_deg": 0.0
    },
    {
      "antenna_id": "vhf_com_blade",
      "antenna_type": "blade",
      "frequency_range": "118-137 MHz",
      "mounting": "fuselage_top",
      "length": "0.3m",
      "power": "25W",
      "azimuth_deg": 0.0,      // Omnidirectional
      "elevation_deg": 0.0
    },
    {
      "antenna_id": "satcom_dome",
      "antenna_type": "satcom",
      "frequency_range": "1.5-1.6 GHz",
      "mounting": "fuselage_top",
      "dome_diameter": "0.8m",
      "power": "50W",
      "azimuth_deg": 0.0,      // Omnidirectional
      "elevation_deg": 0.0
    }
  ]
}
```

### Antenna Orientation Calculation

**Realistic Commercial Aircraft Constraints:**
- **HF Probe**: Short antenna (3m) for aerodynamic reasons, low efficiency
- **VHF COM**: Small blade antenna, omnidirectional
- **SATCOM**: Primary oceanic communication, omnidirectional dome
- **No steerable antennas**: Commercial aircraft use fixed omnidirectional antennas
- **Aerodynamic constraints**: All antennas designed for minimal drag

**Vehicle Dynamics Effects:**
- **HF Probe**: Minimal attitude effects due to short length
- **VHF COM**: No attitude effects, omnidirectional
- **SATCOM**: No attitude effects, tracks satellites automatically
- **Altitude effects**: High altitude (35,000ft) provides excellent propagation
## Example 5: Military Vehicle with Realistic Antennas

### Scenario
- **Vehicle**: NATO Military Jeep (M151)
- **Antennas**: VHF-FM tactical, HF whip (tied down)
- **Frequency**: 30.000 MHz (VHF-FM tactical)
- **Target**: Command post 10km away

### Vehicle Dynamics
```json
{
  "vehicle_id": "JEEP_001",
  "position": {
    "latitude": 52.5200,
    "longitude": 13.4050,
    "altitude_ft_msl": 100.0,
    "altitude_ft_agl": 0.0
  },
  "attitude": {
    "pitch_deg": 0.0,      // Level ground
    "roll_deg": 0.0,       // Level ground
    "yaw_deg": 090.0,      // Facing east
    "magnetic_heading_deg": 088.5
  },
  "velocity": {
    "speed_knots": 25.0,
    "course_deg": 090.0,
    "vertical_speed_fpm": 0.0
  },
  "antennas": [
    {
      "antenna_id": "vhf_fm_whip",
      "antenna_type": "whip",
      "frequency_range": "30-88 MHz",
      "mounting": "rear_corner",
      "length": "2.4m",
      "power": "50W",
      "azimuth_deg": 0.0,      // Omnidirectional
      "elevation_deg": 0.0
    },
    {
      "antenna_id": "hf_whip_tied_down",
      "antenna_type": "whip_tied_down",
      "frequency_range": "2-30 MHz",
      "mounting": "rear_corner_tied_to_front",
      "length": "3.05m",
      "tie_down_angle": "45_degrees",
      "power": "100W",
      "azimuth_deg": 0.0,      // Omnidirectional
      "elevation_deg": 0.0
    }
  ]
}
```

### Antenna Orientation Calculation

**Realistic Military Vehicle Constraints:**
- **VHF Whip**: Standard military whip antenna, omnidirectional
- **HF Whip**: Tied down at 45° for clearance, omnidirectional
- **No steerable antennas**: Military vehicles use fixed omnidirectional antennas
- **Tactical considerations**: Antennas must not interfere with vehicle operation

**Vehicle Dynamics Effects:**
- **VHF Whip**: Minimal attitude effects, omnidirectional
- **HF Whip**: Tied-down configuration reduces attitude effects
- **Ground system**: Vehicle hull provides good ground plane
- **Effective gain**: 0dB (omnidirectional)
- **Signal quality**: Good

## Example 6: Professional Ground Station with Yagi Antennas

### Scenario
- **Station**: Professional VHF/UHF Base Station
- **Antennas**: 2m Yagi, 70cm Yagi, Dual-band omni
- **Frequency**: 144.500 MHz (2m amateur band)
- **Target**: Aircraft 150km away

### Station Configuration
```json
{
  "station_id": "W1ABC",
  "position": {
    "latitude": 42.3601,
    "longitude": -71.0589,
    "altitude_ft_msl": 100.0,
    "altitude_ft_agl": 100.0
  },
  "station_type": "professional_base",
  "antennas": [
    {
      "antenna_id": "yagi_2m_11element",
      "antenna_type": "yagi",
      "frequency_range": "144-145 MHz",
      "mounting": "10m_tower",
      "elements": 11,
      "boom_length": "5.72m",
      "gain": "14.8 dBi",
      "height": "10m",
      "power": "500W",
      "azimuth_deg": 045.0,      // Pointing northeast
      "elevation_deg": 5.0
    },
    {
      "antenna_id": "yagi_70cm_16element",
      "antenna_type": "yagi",
      "frequency_range": "430-440 MHz",
      "mounting": "10m_tower",
      "elements": 16,
      "boom_length": "3.10m",
      "gain": "16.56 dBi",
      "height": "10m",
      "power": "1000W",
      "azimuth_deg": 045.0,      // Pointing northeast
      "elevation_deg": 5.0
    },
    {
      "antenna_id": "dual_band_omni",
      "antenna_type": "collinear",
      "frequency_range": "144-146 MHz, 430-440 MHz",
      "mounting": "10m_tower",
      "length": "5.2m",
      "gain": "8.3 dBi @ 144 MHz, 11.7 dBi @ 432 MHz",
      "height": "10m",
      "power": "200W",
      "azimuth_deg": 0.0,        // Omnidirectional
      "elevation_deg": 0.0
    }
  ]
}
```

### Antenna Orientation Calculation

**Professional Ground Station Capabilities:**
- **2m Yagi**: High-gain directional antenna, steerable
- **70cm Yagi**: High-gain directional antenna, steerable
- **Dual-band Omni**: Omnidirectional coverage for both bands
- **10m Height**: Professional base station performance
- **Steerable antennas**: Can track moving targets

**Station Dynamics Effects:**
- **Yagi antennas**: Directional gain, must be pointed at target
- **Omnidirectional**: No pointing required, 360° coverage
- **Height advantage**: 10m height provides significant range extension
- **Professional performance**: 2-3x range compared to ground level

### Propagation Calculation

```json
{
  "lat1": 42.3601,
  "lon1": -71.0589,
  "lat2": 52.5200,
  "lon2": 13.5050,
  "alt1": 100.0,
  "alt2": 100.0,
  "frequency_mhz": 30.000,
  "power_watts": 25.0,
  "antenna_type": "whip",
  "include_vehicle_dynamics": true,
  "vehicle_id": "TANK_001",
  "antenna_id": "vhf_fm_whip"
}
```

**Result:**
```json
{
  "signal_quality": 0.88,
  "signal_strength_db": -2.1,
  "antenna_gain_db": 0.0,
  "vehicle_attitude_effect_db": 0.0,
  "propagation_mode": "line_of_sight",
  "ground_system_effect": 1.5
}
```

## Example 5: Container Ship with Historical Maritime HF Antennas

### Scenario
- **Vessel**: Container ship (1,000-4,000 TEUs)
- **Antennas**: Multiple wire antennas between masts and superstructure
- **Frequencies**: 500 kHz (distress), 2 MHz (SSB), 472 kHz (630m), 136 kHz (2200m)
- **Target**: Coast stations and other vessels worldwide

### Vehicle Dynamics
```json
{
  "vehicle_id": "MSC_OCEAN",
  "position": {
    "latitude": 40.6892,
    "longitude": -74.0445,
    "altitude_ft_msl": 0.0,
    "altitude_ft_agl": 0.0
  },
  "attitude": {
    "pitch_deg": 1.0,      // Slight bow up
    "roll_deg": 3.0,       // Slight port roll
    "yaw_deg": 180.0,      // Heading south
    "magnetic_heading_deg": 178.5
  },
  "velocity": {
    "speed_knots": 20.0,
    "course_deg": 180.0,
    "vertical_speed_fpm": 0.0
  },
  "antennas": [
    {
      "antenna_id": "t_type_500khz",
      "antenna_type": "t_type_wire",
      "frequency_range": "500 kHz",
      "mounting": "mast_to_superstructure",
      "wire_length": "150.0m",
      "wire_type": "insulated_copper",
      "power": "500W",
      "mode": "CW",
      "azimuth_deg": 0.0,
      "elevation_deg": 0.0,
      "atu_required": true,
      "historical_use": "International distress and calling frequency"
    },
    {
      "antenna_id": "long_wire_2mhz",
      "antenna_type": "long_wire",
      "frequency_range": "1.6-4.0 MHz",
      "mounting": "mast_to_mast",
      "wire_length": "75.0m",
      "wire_type": "insulated_copper",
      "power": "1000W",
      "mode": "SSB",
      "azimuth_deg": 0.0,
      "elevation_deg": 0.0,
      "atu_required": true,
      "historical_use": "Marine MF/HF-SSB radios"
    },
    {
      "antenna_id": "inverted_l_630m",
      "antenna_type": "inverted_l_wire",
      "frequency_range": "472-479 kHz",
      "mounting": "mast_to_superstructure",
      "wire_length": "60.0m",
      "wire_type": "insulated_copper",
      "power": "100W",
      "mode": "CW",
      "azimuth_deg": 0.0,
      "elevation_deg": 0.0,
      "atu_required": true,
      "historical_use": "Maritime distress frequency"
    },
    {
      "antenna_id": "long_wire_2200m",
      "antenna_type": "long_wire",
      "frequency_range": "135.7-137.8 kHz",
      "mounting": "mast_to_mast",
      "wire_length": "200.0m",
      "wire_type": "insulated_copper",
      "power": "200W",
      "mode": "CW",
      "azimuth_deg": 0.0,
      "elevation_deg": 0.0,
      "atu_required": true,
      "historical_use": "Maritime navigation"
    }
  ]
}
```

### Maritime HF Antenna Types

**T-Type Antenna (500 kHz):**
- **Configuration**: Vertical wire with horizontal top section
- **Mounting**: Mast to superstructure
- **Length**: 150m total (vertical + horizontal)
- **ATU Required**: Yes (electrical length tuning)
- **Use**: International distress and calling frequency

**Long Wire Antenna (2 MHz SSB):**
- **Configuration**: Single wire stretched between masts
- **Mounting**: Mast to mast
- **Length**: 75m (optimized for 2 MHz)
- **ATU Required**: Yes (impedance matching)
- **Use**: Marine MF/HF-SSB communications

**Inverted-L Antenna (630m):**
- **Configuration**: Vertical section with horizontal top
- **Mounting**: Mast to superstructure
- **Length**: 60m total
- **ATU Required**: Yes (resonance tuning)
- **Use**: Maritime distress frequency

**Long Wire Antenna (2200m):**
- **Configuration**: Very long wire between masts
- **Mounting**: Mast to mast
- **Length**: 200m (multiple wavelengths)
- **ATU Required**: Yes (electrical length adjustment)
- **Use**: Maritime navigation

### Antenna Tuning Unit (ATU) Requirements

**All maritime HF antennas require ATUs because:**
- **Electrical Length**: Ship antennas are rarely exactly resonant
- **Impedance Matching**: 50Ω radio to various antenna impedances
- **Frequency Coverage**: Single antenna for multiple frequencies
- **Tuning Components**: Inductors and capacitors for resonance
- **Automatic Tuning**: Modern ATUs tune automatically
- **Power Handling**: Must handle full transmitter power

## Example 6: Historical Maritime Vessel with Multiple HF Bands

### Scenario
- **Vessel**: Historical maritime vessel (pre-GMDSS era)
- **Antennas**: Multiple wire antennas for different maritime frequency bands
- **Frequencies**: 500 kHz (distress), 2 MHz (SSB), 472 kHz (630m), 136 kHz (2200m)
- **Target**: Coast stations and other vessels

### Vehicle Dynamics
```json
{
  "vehicle_id": "SS_MARITIME_HISTORIC",
  "position": {
    "latitude": 40.6892,
    "longitude": -74.0445,
    "altitude_ft_msl": 0.0,
    "altitude_ft_agl": 0.0
  },
  "attitude": {
    "pitch_deg": 1.0,      // Slight bow up
    "roll_deg": 3.0,       // Slight port roll
    "yaw_deg": 180.0,      // Heading south
    "magnetic_heading_deg": 178.5
  },
  "velocity": {
    "speed_knots": 15.0,
    "course_deg": 180.0,
    "vertical_speed_fpm": 0.0
  },
  "antennas": [
    {
      "antenna_id": "distress_500khz",
      "antenna_type": "vertical_wire",
      "frequency_range": "500 kHz",
      "mounting": "mast_mounted",
      "wire_length": "150.0m",
      "wire_type": "insulated_copper",
      "power": "500W",
      "mode": "CW",
      "azimuth_deg": 0.0,
      "elevation_deg": 0.0,
      "historical_use": "International distress and calling frequency"
    },
    {
      "antenna_id": "marine_2mhz_ssb",
      "antenna_type": "wire_antenna",
      "frequency_range": "1.6-4.0 MHz",
      "mounting": "mast_to_mast",
      "wire_length": "75.0m",
      "wire_type": "insulated_copper",
      "power": "1000W",
      "mode": "SSB",
      "azimuth_deg": 0.0,
      "elevation_deg": 0.0,
      "historical_use": "Marine MF/HF-SSB radios"
    },
    {
      "antenna_id": "distress_630m",
      "antenna_type": "wire_antenna",
      "frequency_range": "472-479 kHz",
      "mounting": "mast_to_mast",
      "wire_length": "60.0m",
      "wire_type": "insulated_copper",
      "power": "100W",
      "mode": "CW",
      "azimuth_deg": 0.0,
      "elevation_deg": 0.0,
      "historical_use": "Maritime distress frequency"
    },
    {
      "antenna_id": "nav_2200m",
      "antenna_type": "wire_antenna",
      "frequency_range": "135.7-137.8 kHz",
      "mounting": "mast_to_mast",
      "wire_length": "200.0m",
      "wire_type": "insulated_copper",
      "power": "200W",
      "mode": "CW",
      "azimuth_deg": 0.0,
      "elevation_deg": 0.0,
      "historical_use": "Maritime navigation"
    }
  ]
}
```
- **Frequency**: 3.5 MHz (80m band) - optimal for loop antenna
- **Power**: 400W typical for small-medium commercial vessels
- **Size**: Up to 1,000 TEUs (first generation containerships)
- **Mounting**: Deck level, clear of cargo operations

**Technical Advantages of 80m Loop at 3.75 MHz:**
- **Electrical Length**: 1.05 wavelengths (slightly longer than full wavelength)
- **Current Distribution**: Maximum current at multiple points around loop
- **In-Phase Currents**: Reinforce signal capture and radiation
- **Broadband Response**: Wider frequency response than resonant antennas
- **Large Capture Area**: ~530 square meters physical aperture
- **Low Noise Design**: Closed-loop topology rejects common-mode interference
- **Height Advantage**: 10m above deck reduces local noise sources

**Vehicle Dynamics Effects:**
- **Ship roll**: 3° (Port side down)
- **Loop antenna orientation**: Affected by ship roll, directional pattern
- **Loop efficiency**: Some reduction due to roll, but still effective
- **Ground plane**: Large ship hull provides excellent ground plane
- **Signal quality**: Good (directional but fixed orientation)

### Propagation Calculation

```json
{
  "lat1": 40.6892,
  "lon1": -74.0445,
  "lat2": 35.6892,
  "lon2": -74.0445,
  "alt1": 0.0,
  "alt2": 0.0,
  "frequency_mhz": 3.500,
  "power_watts": 400.0,
  "antenna_type": "horizontal_loop",
  "include_vehicle_dynamics": true,
  "vehicle_id": "MSC_OCEAN",
  "antenna_id": "hf_loop_80m"
}
```

**Result:**
```json
{
  "signal_quality": 0.92,
  "signal_strength_db": 3.8,
  "antenna_gain_db": 4.2,
  "vehicle_attitude_effect_db": -0.6,
  "loop_efficiency": 0.85,
  "electrical_length_wavelengths": 1.05,
  "capture_area_sqm": 530,
  "noise_rejection_db": 8.5,
  "propagation_mode": "groundwave",
  "ground_plane_effect": 3.8
}
```

### Why This 80m Loop Configuration Is Highly Effective

**Electrical Resonance Characteristics:**
- **1.05 Wavelengths**: Slightly longer than full wavelength creates multiple current maxima
- **In-Phase Currents**: Currents at different points around loop reinforce each other
- **Broadband Response**: Works well across entire 80m band (3.5-4.0 MHz)
- **Lower Radiation Resistance**: Reduces thermal noise compared to resonant antennas

**Large Capture Area Benefits:**
- **Physical Aperture**: 530 square meters (assuming square configuration)
- **Effective Aperture**: Much larger than dipole's linear capture
- **Signal Gathering**: Intercepts more electromagnetic energy from weak signals
- **Spatial Diversity**: Multiple current maxima provide reception diversity

**Low Noise Mechanisms:**
- **Closed Loop Topology**: Balanced system rejects common-mode interference
- **Differential Mode Enhancement**: Radio waves enhanced, local noise rejected
- **Height Advantage**: 10m above deck reduces coupling to ship electrical systems
- **Noise Source Separation**: Clear of LED lights, switching supplies, and utilities

**Why Contesters Value This Configuration:**
- **Weak Signal Reception**: Large physical size captures more signal power
- **Low Noise Floor**: Reveals weak stations that other antennas miss
- **Interference Rejection**: Balanced feed system rejects common-mode interference
- **Consistent Performance**: Works well across entire 80m band
- **Directional Nulling**: Loop geometry provides some directional characteristics

## Historical Maritime HF Bands Configuration

### Configuration Options

```ini
# Historical Maritime HF Bands (Optional)
[historical_maritime_bands]
# Enable historical maritime HF bands (472 kHz, 136 kHz, 500 kHz, 2 MHz)
# These bands were historically used for maritime distress and communication
# before being allocated to amateur radio operators
enable_historical_maritime_bands = true

# 500 kHz band - International distress and calling frequency
enable_500khz_band = true
500khz_power_limit_watts = 500
500khz_mode = CW
500khz_historical_use = "International distress and calling frequency"
500khz_primary_until_gmdss = true

# 2 MHz band (1.6-4 MHz) - Marine MF/HF-SSB radios
enable_2mhz_band = true
2mhz_power_limit_watts = 1000
2mhz_mode = "SSB"
2mhz_frequency_range = "1.6-4.0 MHz"
2mhz_historical_use = "Marine MF/HF-SSB radios"

# 630 meter band (472-479 kHz) - Historical maritime distress frequency
enable_630m_band = true
630m_power_limit_watts = 100
630m_mode = CW
630m_secondary_allocation = true

# 2200 meter band (135.7-137.8 kHz) - Historical maritime navigation
enable_2200m_band = true
2200m_power_limit_watts = 200
2200m_mode = CW
2200m_secondary_allocation = true

# Interference protection settings
protect_primary_services = true
automatic_power_reduction = true
interference_monitoring = true
```

### Why You Might Want to Disable These Bands

**Reasons to Disable Historical Maritime Bands:**

1. **Interference Concerns:**
   - These are secondary allocations - amateurs must not interfere with primary services
   - Power lines and electrical equipment can cause significant interference
   - Local noise sources (LED lights, switching supplies) are problematic

2. **Antenna Requirements:**
   - Extremely large antennas required (630m = 630 meters wavelength)
   - Very long wire antennas needed for effective operation
   - Ground system requirements are extensive

3. **Propagation Limitations:**
   - Limited propagation during daylight hours
   - Very slow CW operation required
   - Limited communication range compared to higher frequencies

4. **Regulatory Compliance:**
   - Must accept interference from primary services
   - Automatic power reduction required if interference detected
   - Complex licensing requirements in some countries

5. **Practical Considerations:**
   - Very slow data rates (CW only)
   - Limited number of active operators
   - Requires specialized equipment and antennas

**When to Enable These Bands:**

1. **Historical Simulation:**
   - Simulating pre-GMDSS maritime communications
   - Educational purposes for maritime radio history
   - Realistic period-accurate radio operations

2. **Specialized Operations:**
   - Long-distance ground wave propagation simulation
   - Emergency communication scenarios
   - Research into low-frequency propagation

3. **Contest Operations:**
   - Amateur radio contests on these bands
   - Special event stations
   - Experimental communications

### Band Characteristics

**500 kHz Band (International Distress):**
- **Historical Use**: International distress and calling frequency
- **Primary Use**: CW (Morse code) communications
- **Emergency Status**: Primary emergency frequency until GMDSS implementation
- **Power Limit**: 500W maximum (historical maritime)
- **Mode**: CW only
- **Wavelength**: 600 meters
- **Propagation**: Ground wave dominant

**2 MHz Band (1.6-4 MHz):**
- **Historical Use**: Marine MF/HF-SSB radios
- **Frequency Range**: 1.6-4.0 MHz
- **Power Limit**: 1000W maximum (historical maritime)
- **Mode**: SSB (Single Sideband)
- **Wavelength**: 150-187 meters
- **Propagation**: Ground wave and sky wave

**630 Meter Band (472-479 kHz):**
- **Historical Use**: Maritime distress and calling frequency
- **Amateur Allocation**: Secondary (2017 in USA)
- **Power Limit**: 100W maximum
- **Mode**: CW only
- **Wavelength**: 630 meters
- **Propagation**: Ground wave, limited sky wave

**2200 Meter Band (135.7-137.8 kHz):**
- **Historical Use**: Maritime navigation and communication
- **Amateur Allocation**: Secondary (2017 in USA, 1998 in UK)
- **Power Limit**: 200W maximum
- **Mode**: CW only
- **Wavelength**: 2200 meters
- **Propagation**: Ground wave dominant

## API Usage Examples

### Python Client for Vehicle Dynamics

```python
import requests
import json
import time

class VehicleDynamicsClient:
    def __init__(self, base_url="http://localhost:8080/api/v1"):
        self.base_url = base_url
    
    def register_vehicle(self, vehicle_id, vehicle_type, position):
        """Register a new vehicle"""
        data = {
            "vehicle_id": vehicle_id,
            "vehicle_type": vehicle_type,
            "initial_position": position
        }
        response = requests.post(f"{self.base_url}/vehicles/register", json=data)
        return response.json()
    
    def update_vehicle_dynamics(self, vehicle_id, attitude, velocity, position):
        """Update vehicle dynamics"""
        # Update attitude
        requests.put(f"{self.base_url}/vehicles/{vehicle_id}/attitude", json=attitude)
        
        # Update velocity
        requests.put(f"{self.base_url}/vehicles/{vehicle_id}/velocity", json=velocity)
        
        # Update position
        requests.put(f"{self.base_url}/vehicles/{vehicle_id}/position", json=position)
    
    def rotate_antenna(self, vehicle_id, antenna_id, azimuth, elevation):
        """Rotate antenna to target position"""
        data = {
            "target_azimuth_deg": azimuth,
            "target_elevation_deg": elevation,
            "immediate": False
        }
        response = requests.post(f"{self.base_url}/vehicles/{vehicle_id}/antennas/{antenna_id}/rotate", json=data)
        return response.json()
    
    def calculate_propagation(self, vehicle_id, antenna_id, target_lat, target_lon, frequency):
        """Calculate propagation with vehicle dynamics"""
        data = {
            "vehicle_id": vehicle_id,
            "antenna_id": antenna_id,
            "target_latitude": target_lat,
            "target_longitude": target_lon,
            "frequency_mhz": frequency,
            "include_vehicle_dynamics": True
        }
        response = requests.post(f"{self.base_url}/propagation", json=data)
        return response.json()

# Example usage
client = VehicleDynamicsClient()

# Register aircraft
aircraft_data = {
    "vehicle_id": "N12345",
    "vehicle_type": "aircraft",
    "initial_position": {
        "latitude": 40.7128,
        "longitude": -74.0060,
        "altitude_ft_msl": 3500.0
    }
}
client.register_vehicle(**aircraft_data)

# Simulate flight dynamics
for i in range(10):
    attitude = {
        "pitch_deg": 2.0 + i * 0.1,
        "roll_deg": -1.0 + i * 0.2,
        "yaw_deg": 045.0 + i * 2.0
    }
    
    velocity = {
        "speed_knots": 120.0,
        "course_deg": 045.0 + i * 2.0,
        "vertical_speed_fpm": 500.0
    }
    
    position = {
        "latitude": 40.7128 + i * 0.01,
        "longitude": -74.0060 + i * 0.01,
        "altitude_ft_msl": 3500.0 + i * 100.0
    }
    
    client.update_vehicle_dynamics("N12345", attitude, velocity, position)
    
    # Calculate propagation to ground station
    result = client.calculate_propagation("N12345", "yagi_20m", 40.7128, -74.0060, 14.230)
    print(f"Signal quality: {result['data']['signal_quality']:.2f}")
    
    time.sleep(1)
```

### JavaScript Client for Real-time Updates

```javascript
class VehicleDynamicsClient {
    constructor(baseUrl = 'http://localhost:8080/api/v1') {
        this.baseUrl = baseUrl;
        this.ws = null;
    }
    
    connectWebSocket() {
        this.ws = new WebSocket('ws://localhost:8080/ws/vehicles');
        
        this.ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            this.handleWebSocketMessage(data);
        };
        
        this.ws.onopen = () => {
            console.log('WebSocket connected');
        };
        
        this.ws.onclose = () => {
            console.log('WebSocket disconnected');
        };
    }
    
    handleWebSocketMessage(data) {
        switch(data.type) {
            case 'vehicle_position_update':
                this.updateVehiclePosition(data.vehicle_id, data.position);
                break;
            case 'vehicle_attitude_update':
                this.updateVehicleAttitude(data.vehicle_id, data.attitude);
                break;
            case 'antenna_rotation_update':
                this.updateAntennaRotation(data.vehicle_id, data.antenna_id, data.orientation);
                break;
        }
    }
    
    async updateVehicleDynamics(vehicleId, dynamics) {
        const response = await fetch(`${this.baseUrl}/vehicles/${vehicleId}/dynamics`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(dynamics)
        });
        
        return response.json();
    }
    
    async rotateAntenna(vehicleId, antennaId, azimuth, elevation) {
        const response = await fetch(`${this.baseUrl}/vehicles/${vehicleId}/antennas/${antennaId}/rotate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                target_azimuth_deg: azimuth,
                target_elevation_deg: elevation,
                immediate: false
            })
        });
        
        return response.json();
    }
}

// Example usage
const client = new VehicleDynamicsClient();
client.connectWebSocket();

// Simulate vehicle dynamics updates
setInterval(async () => {
    const dynamics = {
        attitude: {
            pitch_deg: Math.random() * 10 - 5,
            roll_deg: Math.random() * 20 - 10,
            yaw_deg: Math.random() * 360
        },
        velocity: {
            speed_knots: 100 + Math.random() * 50,
            course_deg: Math.random() * 360,
            vertical_speed_fpm: Math.random() * 1000 - 500
        }
    };
    
    await client.updateVehicleDynamics('N12345', dynamics);
}, 1000);
```

## Performance Considerations

### Real-time Updates
- Vehicle dynamics updates: 10Hz maximum
- Antenna rotation updates: 1Hz maximum
- WebSocket connections: Limited to prevent resource exhaustion

### Calculation Optimization
- Antenna orientation calculations: Cached for 1 second
- Propagation calculations: Include vehicle dynamics by default
- Auto-tracking: Throttled to prevent excessive CPU usage

### Memory Management
- Vehicle cleanup: Automatic removal of inactive vehicles
- Antenna state: Cached for performance
- WebSocket clients: Automatic cleanup of inactive connections

## Security Considerations

### Access Control
- Vehicle registration: Requires appropriate permissions
- Antenna rotation: Validated for safety limits
- Auto-tracking: Can be disabled for security-sensitive applications

### Rate Limiting
- Vehicle updates: 100 requests per minute per IP
- Antenna rotation: 10 requests per minute per vehicle
- WebSocket connections: 5 connections per IP

### Data Validation
- Vehicle dynamics: Validated for realistic ranges
- Antenna orientation: Safety limits enforced
- Position data: Geographic bounds checking

## EZNEC Multi-Antenna Modeling Guidelines

### Critical Limitation: Single Active Antenna Per Model

**Important**: Due to EZNEC's computational nature, it is not possible to model multiple active antennas (VHF and HF) simultaneously in the same model. This will produce incorrect radiation data and other modeling issues.

### Proper Multi-Antenna Modeling Approach

To get correct radiation patterns for vehicles with multiple antennas:

1. **Active Antenna**: Only one antenna should have a source/feed point
2. **Passive Elements**: Other antennas must be modeled as wires without feed points
3. **Mutual Coupling**: Passive elements will still affect the active antenna through mutual coupling

### Example: Tu-95 "Bear" with VHF Antenna

```eznec
EZNEC ver. 7.0

DESCRIPTION
Tu-95 "Bear" Strategic Bomber with Primary VHF Communications Antenna
Aircraft Structure: 49.5m fuselage, 51.1m wingspan, realistic wire grid
VHF Antenna: 3m monopole on fuselage centerline for 118-174 MHz operation
Model includes fuselage, wings, stabilizers, and existing HF antennas
Grid spacing optimized for VHF frequency analysis

FREQUENCY
150.0  MHz

ENVIRONMENT
0  (Free Space)

GROUND
0  (No Ground)

WIRES
99

WIRE DATA
W001  99  -24.750  0.000  0.000  24.750  0.000  0.000  0.003
W002  10  -24.750  0.000  1.450  -19.750  0.000  1.450  0.003
W003  10  -19.750  0.000  1.450  -14.750  0.000  1.450  0.003
W004  10  -14.750  0.000  1.450  -9.750  0.000  1.450  0.003
W005  10  -9.750  0.000  1.450  -4.750  0.000  1.450  0.003
W006  10  -4.750  0.000  1.450  0.250  0.000  1.450  0.003
W007  10  0.250  0.000  1.450  5.250  0.000  1.450  0.003
W008  10  5.250  0.000  1.450  10.250  0.000  1.450  0.003
W009  10  10.250  0.000  1.450  15.250  0.000  1.450  0.003
W010  10  15.250  0.000  1.450  20.250  0.000  1.450  0.003
W011  10  20.250  0.000  1.450  24.750  0.000  1.450  0.003

REM Fuselage Cross-Sections (Circular approximation)
W012  8  -20.000  -1.450  0.000  -20.000  1.450  0.000  0.003
W013  8  -20.000  1.450  0.000  -20.000  -1.450  0.000  0.003
W014  8  -15.000  -1.450  0.000  -15.000  1.450  0.000  0.003
W015  8  -15.000  1.450  0.000  -15.000  -1.450  0.000  0.003
W016  8  -10.000  -1.450  0.000  -10.000  1.450  0.000  0.003
W017  8  -10.000  1.450  0.000  -10.000  -1.450  0.000  0.003
W018  8  -5.000  -1.450  0.000  -5.000  1.450  0.000  0.003
W019  8  -5.000  1.450  0.000  -5.000  -1.450  0.000  0.003
W020  8  0.000  -1.450  0.000  0.000  1.450  0.000  0.003
W021  8  0.000  1.450  0.000  0.000  -1.450  0.000  0.003
W022  8  5.000  -1.450  0.000  5.000  1.450  0.000  0.003
W023  8  5.000  1.450  0.000  5.000  -1.450  0.000  0.003
W024  8  10.000  -1.450  0.000  10.000  1.450  0.000  0.003
W025  8  10.000  1.450  0.000  10.000  -1.450  0.000  0.003
W026  8  15.000  -1.450  0.000  15.000  1.450  0.000  0.003
W027  8  15.000  1.450  0.000  15.000  -1.450  0.000  0.003
W028  8  20.000  -1.450  0.000  20.000  1.450  0.000  0.003
W029  8  20.000  1.450  0.000  20.000  -1.450  0.000  0.003

REM Main Wings (Swept back design)
W030  48  -8.000  -25.550  -0.500  -12.000  -1.550  0.500  0.003
W031  48  -8.000  25.550  -0.500  -12.000  1.550  0.500  0.003
W032  10  -8.000  -25.550  -0.500  -8.000  -1.550  -0.500  0.003
W033  10  -8.000  25.550  -0.500  -8.000  1.550  -0.500  0.003
W034  10  -12.000  -25.550  0.500  -12.000  -1.550  0.500  0.003
W035  10  -12.000  25.550  0.500  -12.000  1.550  0.500  0.003

REM Vertical Stabilizer
W036  22  15.000  0.000  1.450  15.000  0.000  12.550  0.003
W037  10  15.000  -2.000  1.450  15.000  2.000  1.450  0.003
W038  10  15.000  -2.000  12.550  15.000  2.000  12.550  0.003

REM Horizontal Stabilizers
W039  24  10.000  -6.000  2.000  10.000  6.000  2.000  0.003
W040  12  10.000  -6.000  2.000  20.000  -6.000  2.500  0.003
W041  12  10.000  6.000  2.000  20.000  6.000  2.500  0.003
W042  10  20.000  -6.000  2.500  20.000  6.000  2.500  0.003

REM Existing HF Antennas (PASSIVE - No Source)
W043  26  8.000  0.000  -0.500  34.000  0.000  -3.500  0.003
W044  12  5.000  0.000  2.000  5.000  0.000  5.000  0.005

REM Direction Finding Loops (PASSIVE - No Source)
W045  4  -10.000  -20.000  1.800  -10.000  -19.500  2.200  0.004
W046  4  -10.000  20.000  1.800  -10.000  19.500  2.200  0.004

REM VHF Communications Antenna (ACTIVE - With Source)
W047  12  0.000  0.000  1.450  0.000  0.000  4.450  0.008

SOURCES
1
SRC  W047  6  0  1.000  0.000

LOADS
0

TRANSMISSION LINES
0

NETWORKS
0

END
```

### Key Modeling Principles

1. **Single Source**: Only one antenna (W047) has a source point
2. **Passive Elements**: HF antennas (W043, W044) and DF loops (W045, W046) are present but unpowered
3. **Mutual Coupling**: Passive elements affect the active antenna's radiation pattern
4. **Realistic Effects**: Shows actual operational scenario with multiple antennas present

### Expected Mutual Coupling Effects

- **26m HF trailing wire**: Acts as parasitic element at VHF frequencies
- **Pattern distortion**: Especially in aft sectors due to long trailing wire
- **Near-field coupling**: HF dorsal whip affects VHF antenna performance
- **Minor ripples**: DF loops create small pattern variations
- **Electrically long elements**: All HF elements are long at VHF frequencies

### Analysis Benefits

- **Realistic operational scenario**: VHF active, HF antennas present but inactive
- **Actual mutual coupling**: Shows real-world multi-antenna installation effects
- **Pattern distortion**: Passive elements clearly visible in radiation pattern
- **Accurate predictions**: More realistic gain and impedance calculations

### Frequency Analysis Recommendations

- **Primary frequency**: 150 MHz (center of VHF aviation band)
- **Frequency sweep**: 118-174 MHz for full band analysis
- **Comparison studies**: Remove passive elements (W043-W046) for baseline comparison
- **Pattern analysis**: Focus on 150 MHz for realistic aircraft effects

### Expected Performance Characteristics

- **Omnidirectional horizontal pattern**: With aircraft structure effects
- **Pattern distortion**: From 26m trailing wire parasitic coupling
- **Vertical polarization**: With some cross-pol from passive elements
- **Ground plane effect**: From fuselage structure
- **Typical gain**: -2 to +3 dBi depending on frequency and direction
- **Pattern nulls/lobes**: From parasitic coupling effects

This comprehensive vehicle dynamics system ensures accurate radio propagation calculations by accounting for real-world vehicle orientation, speed, attitude, and antenna rotation effects.
