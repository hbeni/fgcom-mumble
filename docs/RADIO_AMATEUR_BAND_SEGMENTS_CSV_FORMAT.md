# Radio Amateur Band Segments CSV Format Documentation

## Overview

The `radio_amateur_band_segments.csv` file contains comprehensive amateur radio frequency allocations, power limits, and licensing requirements for different countries and ITU regions. This file is used by the FGCom-Mumble system to validate amateur radio frequencies, enforce power limits, and ensure compliance with regional regulations.

**CRITICAL: This file format is position-sensitive and must match exactly or parsing will fail!**

## File Location

```
configs/radio_amateur_band_segments.csv
```

## CSV Format

### Header Row
```csv
Band,Mode,StartFreq,EndFreq,Region,Country,LicenseClass,PowerLimit,Notes
```

**CRITICAL: Header row must be exactly this format or CSV parsing will fail!**
**Any deviation will cause the parser to assign wrong values to fields!**

### Field Descriptions

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| **Band** | String | Amateur radio band designation | `160m`, `80m`, `40m`, `20m`, `15m`, `10m`, `6m`, `2m`, `70cm` |
| **Mode** | String | Operating mode | `CW`, `SSB`, `Digital`, `EME`, `MS`, `Omni` |
| **StartFreq** | Float | Start frequency in kHz | `1810.0`, `7000.0`, `14000.0` |
| **EndFreq** | Float | End frequency in kHz | `1838.0`, `7200.0`, `14350.0` |
| **Region** | Integer | ITU Region (1=Europe/Africa, 2=Americas, 3=Asia-Pacific) | `1`, `2`, `3` |
| **Country** | String | Country or jurisdiction | `UK`, `USA`, `Germany`, `Canada`, `Australia` |
| **LicenseClass** | String | Required license class | `Full`, `Intermediate`, `Foundation`, `Extra`, `Advanced`, `General` |
| **PowerLimit** | Float | Maximum power in Watts | `1000.0`, `400.0`, `1500.0` |
| **Notes** | String | Additional restrictions or notes | `"CW only below 1840 kHz"`, `"Limited to 5 channels"` |

**CRITICAL FIELD VALIDATION RULES:**
- **StartFreq** must be < **EndFreq** or parsing will fail
- **Region** must be 1, 2, or 3 or validation will fail
- **PowerLimit** must be positive or power validation will fail
- **Notes** field supports quoted strings with commas inside

## What Happens If Format Is Wrong

### CSV Parsing Failures
- **Missing fields**: Parser will assign wrong values to fields, causing frequency validation to fail
- **Wrong field order**: Band data will be assigned to wrong variables, breaking amateur radio validation
- **Invalid numeric values**: std::stof() and std::stoi() will throw exceptions, crashing the application
- **Missing header**: First data row will be parsed as header, causing all data to be shifted

### Frequency Validation Failures
- **Wrong frequency ranges**: Amateur radio frequencies will be rejected as invalid
- **Wrong license classes**: Users will be denied access to frequencies they should have
- **Wrong power limits**: Power validation will fail, preventing legitimate operations
- **Wrong ITU regions**: Regional frequency allocations will be incorrect

### System Impact
- **Amateur radio validation disabled**: No frequency checking will work
- **Regulatory compliance failure**: Users may operate out-of-band
- **Application crashes**: Invalid data causes exceptions in parsing functions
- **Data corruption**: Wrong field assignments corrupt the band segment database

## Data Examples

### 160m Band (Region 1 - Europe)
```csv
160m,CW,1810,1838,1,UK,Full,1000,"CW only below 1838 kHz"
160m,CW,1810,1838,1,UK,Intermediate,50,"CW only below 1838 kHz"
160m,SSB,1838,2000,1,UK,Full,1000,"SSB and digital modes"
160m,SSB,1838,2000,1,UK,Intermediate,50,"SSB and digital modes"
```

### 20m Band (Region 2 - Americas)
```csv
20m,CW,14000,14150,2,USA,Extra,1500,"CW only below 14150 kHz"
20m,CW,14000,14150,2,USA,Advanced,1500,"CW only below 14150 kHz"
20m,CW,14000,14150,2,USA,General,1500,"CW only below 14150 kHz"
20m,SSB,14150,14350,2,USA,Extra,1500,"SSB and digital modes"
```

### 2m Band (VHF)
```csv
2m,CW,144000,144200,2,USA,Extra,1500,"VHF band, CW only below 144200 kHz"
2m,CW,144000,144200,2,USA,Technician,1500,"VHF band, CW only below 144200 kHz"
```

### Norway-Specific Allocations
```csv
2m,EME,144000,146000,1,Norway,Special,1000,"EME operations, directional antenna required, logging mandatory"
2m,MS,144000,146000,1,Norway,Special,1000,"Meteor scatter operations, directional antenna required, logging mandatory"
2m,Omni,144000,146000,1,Norway,Special,300,"Omnidirectional antenna operations, 300W max"
70cm,EME,430000,440000,1,Norway,Special,1000,"EME operations, directional antenna required, logging mandatory"
70cm,MS,430000,440000,1,Norway,Special,1000,"Meteor scatter operations, directional antenna required, logging mandatory"
70cm,Omni,430000,440000,1,Norway,Special,300,"Omnidirectional antenna operations, 300W max"
4m,Omni,70000000,70000000,1,Norway,Special,100,"Omnidirectional antenna operations, 100W max"
2m,SSB,144200,148000,2,USA,Extra,1500,"VHF band, SSB and digital modes"
```

## Norway-Specific Regulations

### Power Limits
Norway has specific power limits for different operating modes and antenna types:

#### EME and Meteor Scatter Operations
- **Maximum Power**: 1000W
- **Antenna Requirements**: Directional antenna required
- **Logging**: Mandatory logging of operations
- **Bands**: 2m (144-146 MHz), 70cm (430-440 MHz)

#### Omnidirectional Antenna Operations
- **2m Band**: 300W maximum power
- **70cm Band**: 300W maximum power  
- **4m Band**: 100W maximum power

### License Class
- **Single Radiateur Class**: All Norway entries use "Special" license class
- **No Multiple Classes**: Unlike other countries, Norway has only one radiateur class

### Mode-Specific Entries
- **EME**: Earth-Moon-Earth operations
- **MS**: Meteor Scatter operations
- **Omni**: Omnidirectional antenna operations

## Operating Modes

### Standard Modes
- **CW** - Continuous Wave (Morse code)
- **SSB** - Single Sideband (USB/LSB)
- **Digital** - Digital modes (FT8, PSK31, etc.)

### Special Modes
- **EME** - Earth-Moon-Earth (moonbounce)
- **MS** - Meteor Scatter
- **AM** - Amplitude Modulation
- **FM** - Frequency Modulation

## License Classes by Country

### United Kingdom (UK)
- **Full** - Full license privileges
- **Intermediate** - Intermediate license
- **Foundation** - Foundation license (limited power)

### United States (USA)
- **Extra** - Extra class license
- **Advanced** - Advanced class license
- **General** - General class license
- **Technician** - Technician class license

### Germany
- **Class A** - Full privileges
- **Class E** - Limited privileges

### Canada
- **Advanced** - Advanced license
- **Basic** - Basic license

### Australia
- **Advanced** - Advanced license
- **Standard** - Standard license
- **Foundation** - Foundation license

## ITU Regions

### Region 1: Europe, Africa, Middle East, former USSR
- **Countries**: UK, Germany, France, Italy, Spain, Norway, etc.
- **Frequency allocations**: Generally more restrictive
- **Power limits**: Often lower than other regions

### Region 2: Americas
- **Countries**: USA, Canada, Mexico, Brazil, Argentina, etc.
- **Frequency allocations**: Generally more permissive
- **Power limits**: Often higher (up to 1500W)

### Region 3: Asia-Pacific
- **Countries**: Australia, Japan, New Zealand, India, China, etc.
- **Frequency allocations**: Varies by country
- **Power limits**: Moderate to high

## Power Limit Notes

### Common Power Limits
- **Foundation/Technician**: 10-200W
- **Intermediate/General**: 400-1000W
- **Full/Extra/Advanced**: 1000-1500W
- **Special operations**: Up to 2250W (Canada)

### Power Limit Types
- **TX to antenna**: Power delivered to antenna
- **EIRP**: Effective Isotropically Radiated Power
- **ERP**: Effective Radiated Power

## Special Restrictions

### 60m Band (5 MHz)
- **Limited channels**: Usually 5 specific channels
- **Power limits**: Often 100W ERP maximum
- **Mode restrictions**: CW and SSB only

### 30m Band (10 MHz)
- **WARC band**: No contest activity
- **Power limits**: 200W maximum
- **Mode restrictions**: CW and digital only

### 2m Band (144 MHz)
- **VHF band**: Line-of-sight propagation
- **Power limits**: Often 1500W maximum
- **Special operations**: EME, meteor scatter

## Usage in FGCom-Mumble

### Frequency Validation
```cpp
// Check if frequency is valid for amateur radio
bool is_valid = FGCom_AmateurRadio::validateAmateurFrequency("14200.0", "SSB", 2);
```

### License Class Requirements
```cpp
// Get required license class for a frequency
std::string license_class = FGCom_AmateurRadio::getRequiredLicenseClass(14200.0, 2, "SSB");
// Returns: "Extra", "Advanced", or "General"
```

### Power Limit Validation
```cpp
// Check if power level is within limits
bool power_ok = FGCom_AmateurRadio::validatePowerLevel(14200.0, 2, "SSB", 1000.0);
```

### Country-Specific Allocations
```cpp
// Get all allocations for a specific country
std::vector<fgcom_band_segment> uk_allocations = 
    FGCom_AmateurRadio::getCountryAllocations("UK", 1);
```

### Available Bands for License Class
```cpp
// Get bands available to a license class
std::vector<std::string> bands = 
    FGCom_AmateurRadio::getAvailableBands("General", 2);
// Returns: ["160m", "80m", "40m", "20m", "15m", "10m", "6m", "2m", "70cm"]
```

## File Maintenance

### Adding New Countries
1. Add new rows with appropriate ITU region
2. Include all license classes for the country
3. Specify power limits according to national regulations
4. Add notes for any special restrictions

### Updating Power Limits
1. Verify current regulations with national authorities
2. Update power limits for affected license classes
3. Update notes field if restrictions change

### Adding New Bands
1. Add new band designations (e.g., "1.25m", "33cm")
2. Include frequency ranges and mode allocations
3. Specify regional differences
4. Add propagation characteristics

## Data Sources

### Primary Sources
- **ITU Radio Regulations**: International frequency allocations
- **National Regulatory Authorities**: Country-specific rules
- **Amateur Radio Organizations**: IARU, national societies

### Validation
- **Cross-reference**: Multiple sources for accuracy
- **Regular updates**: Annual review of regulations
- **Community feedback**: Amateur radio operator input

## Error Handling

### Common Issues
- **Missing fields**: Ensure all 9 fields are present
- **Invalid frequencies**: Check frequency ranges
- **Inconsistent power limits**: Verify against regulations
- **Missing license classes**: Include all relevant classes

### Validation Rules
- **Frequency ranges**: StartFreq < EndFreq
- **Power limits**: Positive values, reasonable ranges
- **ITU regions**: Valid values (1, 2, 3)
- **License classes**: Valid for country/region

## Integration with FGCom-Mumble

### Configuration
```cpp
// Initialize amateur radio data
FGCom_AmateurRadio::initialize();

// Load from CSV file
FGCom_AmateurRadio::loadBandSegments("configs/radio_amateur_band_segments.csv");
```

### Real-time Validation
- **Frequency checking**: Before transmission
- **Power validation**: During setup
- **License verification**: User authentication
- **Regional compliance**: Location-based rules

### API Integration
- **REST endpoints**: Query band information
- **WebSocket updates**: Real-time validation
- **Configuration management**: Dynamic updates


### Data Expansion
- **More countries**: Global coverage
- **Historical data**: Regulation changes over time
- **Propagation models**: Enhanced propagation prediction
- **Equipment databases**: Transceiver capabilities

## Support and Maintenance

### Contact Information
- **Technical support**: GitHub issues
- **Data updates**: Pull requests welcome
- **Documentation**: Wiki and README files
- **Community**: Amateur radio forums

### Contributing
1. **Fork repository**: Create your own copy
2. **Make changes**: Update CSV file
3. **Test thoroughly**: Validate all entries
4. **Submit pull request**: Share improvements
5. **Document changes**: Update this documentation

---

*This documentation is maintained as part of the FGCom-Mumble project. For the most current information, please refer to the project repository and official amateur radio regulatory sources.*
