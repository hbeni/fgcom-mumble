# Vehicle Frequency Analysis for Antenna Pattern Generation

This document provides a comprehensive analysis of frequency assignments and antenna pattern requirements for each vehicle type in FGCom-mumble.

## Aircraft Analysis

### Boeing 737 (Civilian Commercial Aircraft)
- **Pattern Folder**: `aircraft/b737/b737_patterns/`
- **Frequencies**: Civilian aircraft HF frequencies
  - **MWARA**: 2.85, 3.4, 5.5, 6.5, 8.9, 11.3, 13.3, 17.9 MHz
  - **VOLMET**: 3.4, 5.5, 6.5, 8.9, 11.3, 13.3, 17.9 MHz
  - **Primary**: 8.9 MHz (typical commercial HF)
- **Altitudes**: 0-15000m (dense sampling 0-1000m, sparse 1000-15000m)
- **Ground Effects**: Free space at high altitude, ground effects at low altitude
- **Antenna Type**: Short probe antennas on fuselage
- **Power**: 400W typical

### C-130 Hercules (Military Transport Aircraft)
- **Pattern Folder**: `aircraft/c130_hercules/c130_patterns/`
- **Frequencies**: Military HF frequencies
  - **NATO Tactical**: 6000, 8000, 10000, 12000 kHz
  - **Primary**: 8000 kHz (NATO tactical)
- **Altitudes**: 0-15000m
- **Ground Effects**: Free space at high altitude, ground effects at low altitude
- **Antenna Type**: Trailing wire antenna (120m)
- **Power**: 400W tactical

### Cessna 172 (General Aviation Aircraft)
- **Pattern Folder**: `aircraft/cessna_172/cessna_patterns/`
- **Frequencies**: Amateur radio bands (if equipped)
  - **20m**: 14.230 MHz (SSB)
  - **40m**: 7.150 MHz (SSB)
  - **Primary**: 14.230 MHz (20m SSB)
- **Altitudes**: 0-5000m (typical GA range)
- **Ground Effects**: Ground effects at low altitude
- **Antenna Type**: Loaded whip antenna
- **Power**: 100W amateur

### Tu-95 Bear (Soviet Strategic Bomber)
- **Pattern Folder**: `aircraft/tu95_bear/tu95_patterns/`
- **Frequencies**: Soviet military HF frequencies
  - **Soviet Strategic**: 5000, 7000, 9000, 11000, 13000 kHz
  - **Primary**: 9000 kHz (Soviet strategic)
- **Altitudes**: 0-15000m
- **Ground Effects**: Free space at high altitude, ground effects at low altitude
- **Antenna Type**: Trailing wire antenna (200m) + SIGINT systems
- **Power**: 800W strategic

### Mi-4 Hound (Soviet Military Helicopter)
- **Pattern Folder**: `aircraft/mi4_hound/mi4_patterns/`
- **Frequencies**: Soviet military HF frequencies
  - **Soviet Tactical**: 3000, 5000, 7000, 9000 kHz
  - **Primary**: 7000 kHz (Soviet tactical)
- **Altitudes**: 0-5000m (helicopter range)
- **Ground Effects**: Ground effects at low altitude, rotor interference
- **Antenna Type**: HF/VHF antenna configuration
- **Power**: 300W tactical

### Bell UH-1 Huey (NATO Military Helicopter)
- **Pattern Folder**: `aircraft/uh1_huey/uh1_patterns/`
- **Frequencies**: NATO military HF frequencies
  - **NATO Tactical**: 3000, 5000, 7000, 9000 kHz
  - **Primary**: 7000 kHz (NATO tactical)
- **Altitudes**: 0-5000m (helicopter range)
- **Ground Effects**: Ground effects at low altitude, rotor interference
- **Antenna Type**: HF/VHF/UHF antenna configuration
- **Power**: 400W tactical

## Marine Vessel Analysis

### Sailboat 23ft Whip (Private Recreational Vessel)
- **Pattern Folder**: `boat/sailboat_whip/sailboat_whip_patterns/`
- **Frequencies**: Maritime HF + Amateur radio bands
  - **Maritime**: 2-4 MHz (ship-to-shore)
  - **Amateur 20m**: 14.230 MHz (SSB)
  - **Amateur 40m**: 7.150 MHz (SSB)
  - **Primary**: 14.230 MHz (20m SSB)
- **Ground**: Saltwater (excellent ground, σ = 5 S/m)
- **Antenna Type**: 23ft whip antenna
- **Power**: 100W amateur

### Sailboat Backstay (Private Recreational Vessel)
- **Pattern Folder**: `boat/sailboat_backstay/sailboat_backstay_patterns/`
- **Frequencies**: Maritime HF + Amateur radio bands
  - **Maritime**: 2-4 MHz (ship-to-shore)
  - **Amateur 40m**: 7.150 MHz (SSB)
  - **Amateur 80m**: 3.800 MHz (SSB)
  - **Primary**: 7.150 MHz (40m SSB)
- **Ground**: Saltwater (excellent ground, σ = 5 S/m)
- **Antenna Type**: Backstay wire antenna (inverted-L)
- **Power**: 100W amateur

### Container Ship (Large Commercial Vessel)
- **Pattern Folder**: `ship/containership/containership_patterns/`
- **Frequencies**: Maritime HF + Amateur radio bands
  - **Maritime**: 2-18 MHz (ship-to-shore)
  - **Amateur 80m**: 3.800 MHz (SSB)
  - **Amateur 40m**: 7.150 MHz (SSB)
  - **Primary**: 3.800 MHz (80m SSB)
- **Ground**: Saltwater (excellent ground, σ = 5 S/m)
- **Antenna Type**: 80m square loop antenna
- **Power**: 100W amateur

## Ground Vehicle Analysis

### Ford Transit Camper (Civilian Recreational Vehicle)
- **Pattern Folder**: `vehicle/ford_transit/ford_transit_patterns/`
- **Frequencies**: Amateur radio bands
  - **Amateur 20m**: 14.230 MHz (SSB)
  - **Amateur 40m**: 7.150 MHz (SSB)
  - **Amateur 10m**: 28.400 MHz (SSB)
  - **Primary**: 14.230 MHz (20m SSB)
- **Ground**: Average soil (σ = 0.005 S/m)
- **Antenna Type**: Multi-band whip antenna
- **Power**: 100W amateur

### VW Passat (Civilian Passenger Vehicle)
- **Pattern Folder**: `vehicle/vw_passat/vw_passat_patterns/`
- **Frequencies**: Amateur radio bands
  - **Amateur 20m**: 14.230 MHz (SSB)
  - **Amateur 40m**: 7.150 MHz (SSB)
  - **Amateur 10m**: 28.400 MHz (SSB)
  - **Primary**: 14.230 MHz (20m SSB)
- **Ground**: Average soil (σ = 0.005 S/m)
- **Antenna Type**: Hi-Q style loaded HF antenna
- **Power**: 100W amateur

### NATO Jeep (Military Ground Vehicle)
- **Pattern Folder**: `military-land/nato_jeep/nato_jeep_patterns/`
- **Frequencies**: NATO military HF frequencies
  - **NATO Tactical**: 3000, 5000, 7000, 9000 kHz
  - **Primary**: 7000 kHz (NATO tactical)
- **Ground**: Average soil (σ = 0.005 S/m)
- **Antenna Type**: 10ft whip antenna (45° tied-down)
- **Power**: 400W tactical

### Soviet UAZ (Military Ground Vehicle)
- **Pattern Folder**: `military-land/soviet_uaz/soviet_uaz_patterns/`
- **Frequencies**: Soviet military HF frequencies
  - **Soviet Tactical**: 3000, 5000, 7000, 9000 kHz
  - **Primary**: 7000 kHz (Soviet tactical)
- **Ground**: Average soil (σ = 0.005 S/m)
- **Antenna Type**: 4m whip antenna (45° tied-down)
- **Power**: 300W tactical

## Ground-Based Antenna Analysis

### Yagi 40m (Fixed Amateur Radio Station)
- **Pattern Folder**: `Ground-based/yagi_40m/yagi_40m_patterns/`
- **Frequencies**: Amateur 40m band
  - **40m SSB**: 7.150 MHz
  - **40m CW**: 7.060 MHz
  - **Primary**: 7.150 MHz (SSB)
- **Height**: 10m above ground
- **Ground**: Average soil (σ = 0.005 S/m)
- **Antenna Type**: Hy-Gain TH-3DXX 3-element Yagi
- **Power**: 100W amateur

### Yagi 20m (Fixed Amateur Radio Station)
- **Pattern Folder**: `Ground-based/yagi_20m/yagi_20m_patterns/`
- **Frequencies**: Amateur 20m band
  - **20m SSB**: 14.230 MHz
  - **20m CW**: 14.060 MHz
  - **Primary**: 14.230 MHz (SSB)
- **Height**: 10m above ground
- **Ground**: Average soil (σ = 0.005 S/m)
- **Antenna Type**: Cushcraft A3WS 3-element Yagi
- **Power**: 100W amateur

### Yagi 10m (Fixed Amateur Radio Station)
- **Pattern Folder**: `Ground-based/yagi_10m/yagi_10m_patterns/`
- **Frequencies**: Amateur 10m band
  - **10m SSB**: 28.400 MHz
  - **10m CW**: 28.060 MHz
  - **Primary**: 28.400 MHz (SSB)
- **Height**: 10m above ground
- **Ground**: Average soil (σ = 0.005 S/m)
- **Antenna Type**: Hy-Gain TH-4DXX 4-element Yagi
- **Power**: 100W amateur

### Yagi 6m (Fixed Amateur Radio Station)
- **Pattern Folder**: `Ground-based/yagi_6m/yagi_6m_patterns/`
- **Frequencies**: Amateur 6m band
  - **6m FM**: 52.000 MHz
  - **6m SSB**: 50.125 MHz
  - **Primary**: 52.000 MHz (FM)
- **Height**: 10m above ground
- **Ground**: Average soil (σ = 0.005 S/m)
- **Antenna Type**: Hy-Gain VB-64FM 4-element Yagi
- **Power**: 100W amateur

### Loop Antenna (Fixed Amateur Radio Station)
- **Pattern Folder**: `Ground-based/loop/loop_patterns/`
- **Frequencies**: Amateur radio bands
  - **40m**: 7.150 MHz (SSB)
  - **20m**: 14.230 MHz (SSB)
  - **Primary**: 7.150 MHz (40m SSB)
- **Height**: 10m above ground
- **Ground**: Average soil (σ = 0.005 S/m)
- **Antenna Type**: Magnetic loop or delta loop
- **Power**: 100W amateur

## Pattern Generation Strategy

### Aircraft Patterns
1. **Generate altitude sweep** using `altitude_sweep.sh`
2. **Process with xnec2c** to create radiation patterns
3. **Store in vehicle-specific pattern folders**
4. **Use realistic operating frequencies** for each aircraft type

### Marine Patterns
1. **Use saltwater ground** (σ = 5 S/m, εᵣ = 81)
2. **Process with xnec2c** for saltwater environment
3. **Store in vessel-specific pattern folders**
4. **Use maritime + amateur frequencies**

### Ground Vehicle Patterns
1. **Use average soil ground** (σ = 0.005 S/m, εᵣ = 13)
2. **Process with xnec2c** for soil environment
3. **Store in vehicle-specific pattern folders**
4. **Use appropriate military or amateur frequencies**

### Ground-Based Patterns
1. **Use 10m height** above average soil
2. **Process with xnec2c** for ground-based environment
3. **Store in antenna-specific pattern folders**
4. **Use amateur radio frequencies**

## Frequency Selection Notes

- **20m Band**: Use 14.230 MHz (SSB) for pattern analysis
- **40m Band**: Use 7.150 MHz (SSB) for pattern analysis
- **10m Band**: Use 28.400 MHz (SSB) for pattern analysis
- **6m Band**: Use 52.000 MHz (FM) for pattern analysis
- **Military HF**: Use primary tactical frequencies (7000-8000 kHz)
- **Maritime HF**: Use 2-4 MHz for ship-to-shore communications

This analysis provides the foundation for generating accurate antenna patterns for all vehicle types in FGCom-mumble.
