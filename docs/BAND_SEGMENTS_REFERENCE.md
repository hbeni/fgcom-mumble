# Band Segments Reference

**Complete reference for amateur radio frequency allocations and band segments**

## Band Segments Database

For detailed band segment information and frequency allocations, refer to the comprehensive band segments database:

- **Band Segments CSV**: [https://github.com/Supermagnum/Supermorse-server/blob/main/Bandplans_and_antennas/band_segments.csv](https://github.com/Supermagnum/Supermorse-server/blob/main/Bandplans_and_antennas/band_segments.csv)

**Local CSV File**: `/home/haaken/github-projects/fgcom-mumble/configs/band_segments.csv`

## Database Contents

This CSV file contains detailed information about:

- **Frequency Allocations**: Frequency ranges for different regions
- **Band Segments**: Specific segments for various modulation modes
- **ITU Region Specifications**: International Telecommunication Union region requirements
- **Channel Spacing Requirements**: Required spacing between channels
- **Power Limits**: Maximum power allowed per band and region
- **Country-Specific Restrictions**: National regulations and limitations
- **Special Norwegian Allocations**: 1000W for EME/MS operations on 2m, 70cm, 23cm bands

## Frequency Bands Covered

### HF Bands
- **160m**: 1.8-2.0 MHz
- **80m**: 3.5-4.0 MHz
- **40m**: 7.0-7.3 MHz
- **30m**: 10.1-10.15 MHz
- **20m**: 14.0-14.35 MHz
- **17m**: 18.068-18.168 MHz
- **15m**: 21.0-21.45 MHz
- **12m**: 24.89-24.99 MHz
- **10m**: 28.0-29.7 MHz

### VHF Bands
- **6m**: 50.0-54.0 MHz
- **2m**: 144.0-148.0 MHz
- **1.25m**: 222.0-225.0 MHz

### UHF Bands
- **70cm**: 420.0-450.0 MHz
- **33cm**: 902.0-928.0 MHz
- **23cm**: 1240.0-1300.0 MHz
- **13cm**: 2300.0-2450.0 MHz

### Microwave Bands
- **9cm**: 3300.0-3500.0 MHz
- **6cm**: 5650.0-5850.0 MHz
- **3cm**: 10000.0-10500.0 MHz
- **1.2cm**: 24000.0-24250.0 MHz

## Modulation Modes

### Supported Modes
- **CW**: Continuous Wave (Morse code)
- **LSB**: Lower Sideband
- **USB**: Upper Sideband
- **NFM**: Narrow Frequency Modulation
- **AM**: Amplitude Modulation
- **DSB**: Double Sideband
- **ISB**: Independent Sideband
- **VSB**: Vestigial Sideband

### Mode-Specific Allocations
- **CW**: All bands, typically at band edges
- **SSB**: HF bands and some VHF/UHF
- **FM**: VHF/UHF bands primarily
- **AM**: HF bands and some VHF
- **Digital**: Various bands with specific allocations

## Regional Variations

### ITU Region 1 (Europe, Africa, Middle East)
- **160m**: 1.810-1.850 MHz
- **80m**: 3.500-3.800 MHz
- **40m**: 7.000-7.200 MHz
- **20m**: 14.000-14.350 MHz
- **2m**: 144.000-146.000 MHz

### ITU Region 2 (Americas)
- **160m**: 1.800-2.000 MHz
- **80m**: 3.500-4.000 MHz
- **40m**: 7.000-7.300 MHz
- **20m**: 14.000-14.350 MHz
- **2m**: 144.000-148.000 MHz

### ITU Region 3 (Asia-Pacific)
- **160m**: 1.800-2.000 MHz
- **80m**: 3.500-4.000 MHz
- **40m**: 7.000-7.300 MHz
- **20m**: 14.000-14.350 MHz
- **2m**: 144.000-148.000 MHz

## Power Limits

### General Power Limits
- **HF Bands**: 100W PEP (Peak Envelope Power)
- **VHF Bands**: 50W PEP
- **UHF Bands**: 25W PEP
- **Microwave Bands**: 10W PEP

### Special Allocations
- **EME Operations**: Up to 1000W on 2m, 70cm, 23cm (Norway)
- **MS Operations**: Up to 1000W on 2m, 70cm, 23cm (Norway)
- **Emergency Communications**: Higher power limits during emergencies
- **Contest Operations**: Special power limits during contests

## Channel Spacing

### Standard Spacing
- **HF Bands**: 3.8 kHz (CW), 2.8 kHz (SSB)
- **VHF Bands**: 12.5 kHz (FM), 2.8 kHz (SSB)
- **UHF Bands**: 12.5 kHz (FM), 2.8 kHz (SSB)
- **Microwave Bands**: 25 kHz (FM), 2.8 kHz (SSB)

### Digital Modes
- **PSK31**: 31.25 Hz spacing
- **RTTY**: 170 Hz spacing
- **FT8**: 6.25 Hz spacing
- **JT65**: 2.7 Hz spacing

## Country-Specific Restrictions

### United States
- **FCC Part 97**: Amateur radio regulations
- **Power Limits**: 1500W PEP maximum
- **Band Plans**: ARRL band plans
- **Special Allocations**: Emergency communications

### European Union
- **CEPT Recommendations**: European Conference of Postal and Telecommunications Administrations
- **Power Limits**: 400W PEP maximum
- **Band Plans**: IARU Region 1 band plans
- **Special Allocations**: Emergency communications

### Japan
- **Ministry of Internal Affairs and Communications**: Japanese regulations
- **Power Limits**: 200W PEP maximum
- **Band Plans**: JARL band plans
- **Special Allocations**: Emergency communications

## Special Allocations

### Emergency Communications
- **Emergency Frequencies**: Designated emergency frequencies
- **Higher Power**: Increased power limits during emergencies
- **Priority Access**: Priority access to frequencies
- **Coordination**: Emergency communication coordination

### Contest Operations
- **Contest Frequencies**: Designated contest frequencies
- **Power Limits**: Contest-specific power limits
- **Time Limits**: Contest time restrictions
- **Coordination**: Contest coordination

### EME (Earth-Moon-Earth) Operations
- **EME Frequencies**: Designated EME frequencies
- **High Power**: Up to 1000W for EME operations
- **Special Antennas**: High-gain antenna requirements
- **Coordination**: EME operation coordination

## Database Structure

### CSV Format
The band segments database is stored in CSV format with the following columns:

- **Band**: Frequency band designation
- **Frequency_Start**: Start frequency in MHz
- **Frequency_End**: End frequency in MHz
- **Mode**: Modulation mode
- **Region**: ITU region
- **Country**: Country code
- **Power_Limit**: Maximum power in watts
- **Channel_Spacing**: Channel spacing in kHz
- **Special_Notes**: Special restrictions or notes

### Data Validation
- **Frequency Ranges**: Validated against ITU allocations
- **Power Limits**: Checked against national regulations
- **Channel Spacing**: Verified against technical requirements
- **Regional Compliance**: Ensured compliance with regional regulations

## Modifying Band Segments

### Editing the Database
1. **Open the CSV file**: `/home/haaken/github-projects/fgcom-mumble/configs/band_segments.csv`
2. **Edit the data**: Modify frequency allocations, power limits, or restrictions
3. **Validate changes**: Ensure compliance with regulations
4. **Save the file**: Changes take effect after plugin restart

### Adding New Allocations
1. **Research regulations**: Check national and international regulations
2. **Add new entries**: Add new frequency allocations
3. **Validate compliance**: Ensure compliance with regulations
4. **Test changes**: Verify changes work correctly

### Removing Allocations
1. **Check dependencies**: Ensure no other systems depend on the allocation
2. **Remove entries**: Delete the allocation from the database
3. **Update documentation**: Update relevant documentation
4. **Test changes**: Verify removal doesn't break functionality

## Integration with FGCom-mumble

### Automatic Loading
The band segments database is automatically loaded when the plugin starts:

1. **Database Loading**: CSV file is parsed and loaded into memory
2. **Validation**: Data is validated against regulations
3. **Indexing**: Data is indexed for fast lookup
4. **Caching**: Data is cached for performance

### Real-time Updates
The database can be updated without recompilation:

1. **File Monitoring**: Plugin monitors the CSV file for changes
2. **Automatic Reload**: Changes are automatically detected and loaded
3. **Validation**: New data is validated before loading
4. **Error Handling**: Invalid data is rejected with error messages

### API Integration
The band segments database is accessible through the API:

- **RESTful API**: HTTP endpoints for band segment data
- **WebSocket Updates**: Real-time updates for band segment changes
- **Query Interface**: Search and filter band segment data
- **Export Functions**: Export band segment data in various formats

## Troubleshooting

### Common Issues
- **Invalid CSV Format**: Check CSV syntax and formatting
- **Missing Data**: Ensure all required fields are present
- **Invalid Frequencies**: Check frequency ranges and formats
- **Power Limit Errors**: Verify power limits against regulations

### Validation Errors
- **Frequency Range Errors**: Check frequency ranges against ITU allocations
- **Power Limit Errors**: Verify power limits against national regulations
- **Channel Spacing Errors**: Check channel spacing requirements
- **Regional Compliance Errors**: Ensure compliance with regional regulations

### Performance Issues
- **Large Database**: Optimize database size and structure
- **Slow Loading**: Improve loading performance
- **Memory Usage**: Monitor memory usage and optimize
- **Cache Issues**: Check caching configuration and performance

## Best Practices

### Database Maintenance
- **Regular Updates**: Keep database current with regulations
- **Validation**: Regularly validate data against regulations
- **Backup**: Maintain backups of the database
- **Documentation**: Keep documentation current

### Performance Optimization
- **Indexing**: Use proper indexing for fast lookups
- **Caching**: Implement effective caching strategies
- **Compression**: Use compression for large databases
- **Optimization**: Regularly optimize database performance

### Compliance
- **Regulatory Updates**: Stay current with regulatory changes
- **Validation**: Regularly validate against regulations
- **Documentation**: Maintain compliance documentation
- **Testing**: Regular testing for compliance

## Related Documentation

- [API Documentation](docs/API_DOCUMENTATION.md) - API reference for band segments
- [Technical Documentation](docs/TECHNICAL_DOCUMENTATION.md) - Technical details
- [Installation Guide](docs/INSTALLATION_GUIDE.md) - Installation and setup
- [Client Usage Guide](docs/CLIENT_USAGE_GUIDE.md) - Client usage and compatibility
