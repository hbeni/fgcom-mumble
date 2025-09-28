# 4m Band International Allocations

This document provides comprehensive information about 4m band (around 70 MHz) amateur radio allocations worldwide.

## Overview

The 4m amateur radio band is allocated in several countries, primarily in Europe, with varying frequency ranges and power limits. It is not universally available and is often shared with other services.

## European Allocations

### United Kingdom
- **Frequency Range**: 70.0-70.5 MHz
- **License Classes**: Full, Intermediate, Foundation
- **Power Limits**: 
  - Foundation: 10W
  - Intermediate: 50W
  - Full: 400W
- **Modes**: All amateur modes
- **Special Notes**: Popular for VHF weak signal, EME, local repeaters

### Ireland
- **Frequency Range**: 70.0-70.5 MHz
- **License Classes**: Full, Intermediate, Foundation
- **Power Limits**: Similar to UK
- **Modes**: All amateur modes

### Netherlands
- **Frequency Range**: 70.0-70.5 MHz
- **License Classes**: Full, Intermediate, Foundation
- **Power Limits**: 
  - Foundation: 25W
  - Intermediate: 100W
  - Full: 400W
- **Modes**: All amateur modes

### Belgium
- **Frequency Range**: 70.0-70.5 MHz
- **License Classes**: Full, Intermediate, Foundation
- **Power Limits**: Similar to Netherlands
- **Modes**: All amateur modes

### Luxembourg
- **Frequency Range**: 70.0-70.5 MHz
- **License Classes**: Full, Intermediate, Foundation
- **Power Limits**: Similar to Netherlands
- **Modes**: All amateur modes

### Denmark
- **Frequency Range**: 70.0-70.5 MHz
- **License Classes**: Full, Intermediate, Foundation
- **Power Limits**: Similar to Netherlands
- **Modes**: All amateur modes

### Norway
- **Frequency Range**: 69.9-70.5 MHz
- **License Classes**: Special
- **Power Limits**: 
  - Normal usage: 100W
  - EME operations: 1000W
  - Meteor scatter: 1000W
- **Modes**: All amateur modes
- **Special Notes**: Extended frequency range, higher power for EME/MS

### Sweden
- **Frequency Range**: 70.0-70.5 MHz
- **License Classes**: Full, Intermediate, Foundation
- **Power Limits**: Similar to Netherlands
- **Modes**: All amateur modes

### Finland
- **Frequency Range**: 70.0-70.5 MHz
- **License Classes**: Full, Intermediate, Foundation
- **Power Limits**: Similar to Netherlands
- **Modes**: All amateur modes

### Estonia
- **Frequency Range**: 70.0-70.5 MHz
- **License Classes**: Full, Intermediate, Foundation
- **Power Limits**: Similar to Netherlands
- **Modes**: All amateur modes

### Latvia
- **Frequency Range**: 70.0-70.5 MHz
- **License Classes**: Full, Intermediate, Foundation
- **Power Limits**: Similar to Netherlands
- **Modes**: All amateur modes

### Lithuania
- **Frequency Range**: 70.0-70.5 MHz
- **License Classes**: Full, Intermediate, Foundation
- **Power Limits**: Similar to Netherlands
- **Modes**: All amateur modes

### Poland
- **Frequency Range**: 70.0-70.5 MHz
- **License Classes**: Full, Intermediate, Foundation
- **Power Limits**: Similar to Netherlands
- **Modes**: All amateur modes

### Czech Republic
- **Frequency Range**: 70.0-70.5 MHz
- **License Classes**: Full, Intermediate, Foundation
- **Power Limits**: Similar to Netherlands
- **Modes**: All amateur modes

### Slovakia
- **Frequency Range**: 70.0-70.5 MHz
- **License Classes**: Full, Intermediate, Foundation
- **Power Limits**: Similar to Netherlands
- **Modes**: All amateur modes

### Slovenia
- **Frequency Range**: 70.0-70.5 MHz
- **License Classes**: Full, Intermediate, Foundation
- **Power Limits**: Similar to Netherlands
- **Modes**: All amateur modes

### Croatia
- **Frequency Range**: 70.0-70.5 MHz
- **License Classes**: Full, Intermediate, Foundation
- **Power Limits**: Similar to Netherlands
- **Modes**: All amateur modes

## Non-European Allocations

### South Africa
- **Frequency Range**: 70.0-70.5 MHz
- **License Classes**: Full, Intermediate, Foundation
- **Power Limits**: Similar to European standards
- **Modes**: All amateur modes

### Australia
- **Frequency Range**: Limited regional access
- **License Classes**: Advanced, Standard, Foundation
- **Power Limits**: Varies by region
- **Modes**: All amateur modes
- **Special Notes**: Limited regional access only

### New Zealand
- **Frequency Range**: Limited regional access
- **License Classes**: Advanced, Standard, Foundation
- **Power Limits**: Varies by region
- **Modes**: All amateur modes
- **Special Notes**: Limited regional access only

### Caribbean Islands
- **Frequency Range**: Varies by island
- **License Classes**: Varies by island
- **Power Limits**: Varies by island
- **Modes**: All amateur modes
- **Special Notes**: Limited access, varies by jurisdiction

## Countries WITHOUT 4m Allocations

### North America
- **United States**: No 4m allocation
- **Canada**: No 4m allocation
- **Mexico**: No 4m allocation

### Asia
- **Japan**: No 4m allocation
- **China**: No 4m allocation
- **India**: No 4m allocation
- **South Korea**: No 4m allocation
- **Most Asian countries**: No 4m allocation

### Other Regions
- **Most of Africa**: No 4m allocation
- **Most of South America**: No 4m allocation
- **Most of Central America**: No 4m allocation

## Technical Characteristics

### Propagation
- **Type**: Line of sight (LOS)
- **Range**: 50-200 km typical
- **Atmospheric Effects**: Minimal tropospheric ducting
- **Ground Wave**: Limited ground wave propagation
- **Ionospheric Effects**: No ionospheric reflection

### Antenna Types
- **Vertical**: Common for local communication
- **Yagi**: Popular for weak signal work
- **Beam**: Used for EME and weak signal
- **Dipole**: Basic antenna for local use

### Popular Applications
- **VHF Weak Signal**: Long-distance communication
- **EME (Moonbounce)**: Earth-Moon-Earth communication
- **Local Repeaters**: Repeater networks
- **Contests**: VHF contests and competitions
- **DX**: Long-distance communication

## Implementation in FGCom-mumble

### Band Configuration
```cpp
// 4m band configuration for different countries
struct Band4mConfig {
    std::string country;
    float frequency_start;
    float frequency_end;
    std::vector<std::string> license_classes;
    std::map<std::string, float> power_limits;
    bool eme_ms_allowed;
    float eme_ms_power_limit;
};

// European 4m band configurations
std::vector<Band4mConfig> european_4m_configs = {
    {"UK", 70.0, 70.5, {"Full", "Intermediate", "Foundation"}, 
     {{"Foundation", 10.0}, {"Intermediate", 50.0}, {"Full", 400.0}}, false, 0.0},
    {"Norway", 69.9, 70.5, {"Special"}, 
     {{"Special", 100.0}}, true, 1000.0},
    {"Netherlands", 70.0, 70.5, {"Full", "Intermediate", "Foundation"}, 
     {{"Foundation", 25.0}, {"Intermediate", 100.0}, {"Full", 400.0}}, false, 0.0}
};
```

### Frequency Validation
```cpp
// 4m band frequency validation
bool validate4mFrequency(float frequency_mhz, const std::string& country) {
    if (country == "Norway") {
        return (frequency_mhz >= 69.9 && frequency_mhz <= 70.5);
    } else if (country == "UK" || country == "Netherlands" || 
               country == "Belgium" || country == "Luxembourg" ||
               country == "Denmark" || country == "Sweden" ||
               country == "Finland" || country == "Estonia" ||
               country == "Latvia" || country == "Lithuania" ||
               country == "Poland" || country == "Czech Republic" ||
               country == "Slovakia" || country == "Slovenia" ||
               country == "Croatia") {
        return (frequency_mhz >= 70.0 && frequency_mhz <= 70.5);
    }
    return false; // No 4m allocation in this country
}
```

### Power Limit Validation
```cpp
// 4m band power limit validation
float get4mPowerLimit(const std::string& country, const std::string& license_class, 
                     bool eme_ms_operation = false) {
    if (country == "Norway" && license_class == "Special") {
        if (eme_ms_operation) {
            return 1000.0; // EME/MS operations
        }
        return 100.0; // Normal usage
    } else if (country == "UK" && license_class == "Full") {
        return 400.0;
    } else if (country == "UK" && license_class == "Intermediate") {
        return 50.0;
    } else if (country == "UK" && license_class == "Foundation") {
        return 10.0;
    }
    // Add other countries as needed
    return 0.0; // No 4m allocation or invalid combination
}
```

## Regional Considerations

### ITU Region 1 (Europe, Africa, Middle East)
- **Primary Region**: Most 4m allocations are in Region 1
- **Frequency Coordination**: CEPT coordination
- **Power Limits**: Generally 400W maximum
- **Special Operations**: EME/MS operations allowed in some countries

### ITU Region 2 (Americas)
- **No Allocations**: No 4m amateur allocations
- **Alternative Bands**: 6m (50-54 MHz) and 2m (144-148 MHz)
- **Special Notes**: 4m band used for other services

### ITU Region 3 (Asia-Pacific)
- **Limited Allocations**: Very limited 4m allocations
- **Alternative Bands**: 6m (50-54 MHz) and 2m (144-148 MHz)
- **Special Notes**: Most countries use 6m band instead

## Best Practices

### Operating Guidelines
- **Check Local Regulations**: Always check local regulations
- **Respect Power Limits**: Stay within allocated power limits
- **Use Appropriate Antennas**: Use appropriate antennas for the application
- **Follow Band Plans**: Follow local band plans and etiquette
- **Respect Other Services**: Respect shared frequency allocations

### Technical Considerations
- **Antenna Height**: Significant impact on range
- **Terrain Effects**: Major impact on propagation
- **Weather Effects**: Minimal atmospheric effects
- **Interference**: Potential interference with other services

## References

- ITU Radio Regulations
- CEPT Recommendations
- National amateur radio regulations
- Regional frequency coordination
- International amateur radio databases
