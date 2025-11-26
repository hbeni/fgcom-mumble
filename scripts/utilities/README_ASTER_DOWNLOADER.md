# ASTER GDEM Terrain Data Downloader

This utility provides easy downloading of ASTER Global Digital Elevation Model (GDEM) terrain data for specific countries/regions. ASTER GDEM provides high-resolution elevation data (30m resolution) that is essential for realistic radio propagation modeling in FGCom-mumble.

## Features

- **Country/Region Selection**: Download terrain data for specific countries or regions
- **NASA Earthdata Integration**: Direct integration with NASA's data services
- **Automated Download**: Batch download of multiple terrain tiles
- **Progress Tracking**: Real-time download progress and logging
- **Data Organization**: Automatic organization of downloaded data by region
- **Metadata Management**: Track download history and file information

## Prerequisites

### 1. NASA Earthdata Account
- Create a free account at: https://urs.earthdata.nasa.gov/
- Note your username and password

### 2. System Dependencies
```bash
# Install required tools
sudo apt-get update
sudo apt-get install wget unzip

# Install GDAL for terrain data processing (optional but recommended)
sudo apt-get install gdal-bin

# Install Python dependencies
pip install -r requirements_aster.txt
```

## Usage

### Quick Start (Bash Script)
```bash
# Make executable
chmod +x aster_gdem_downloader.sh

# Run with interactive prompts
./aster_gdem_downloader.sh
```

### Advanced Usage (Python Script)
```bash
# List available regions
python3 aster_gdem_advanced.py --list-regions

# Download data for United States
python3 aster_gdem_advanced.py --region USA --username your_username --password your_password

# Download with limits
python3 aster_gdem_advanced.py --region CAN --max-tiles 10

# Get region information
python3 aster_gdem_advanced.py --info USA
```

### Environment Variables (REQUIRED)
**SECURITY REQUIREMENT**: All credentials must be provided via environment variables. Interactive password input is disabled for security reasons.

Set credentials as environment variables:
```bash
export NASA_USERNAME="your_username"
export NASA_PASSWORD="your_password"
```

**Security Best Practices:**
- Never hardcode credentials in scripts
- Use environment variables or secure credential managers
- Consider using `.env` files with proper permissions (600)
- Use credential managers like `keyring` for production environments
```

## Available Regions

| Code | Country/Region | Coverage |
|------|----------------|----------|
| USA  | United States  | Continental US, Alaska, Hawaii |
| CAN  | Canada         | All provinces and territories |
| GBR  | United Kingdom | England, Scotland, Wales, Northern Ireland |
| DEU  | Germany        | All federal states |
| FRA  | France         | Metropolitan France |
| JPN  | Japan          | All prefectures |
| AUS  | Australia      | All states and territories |

## Data Structure

Downloaded data is organized as follows:
```
terrain_data/
├── raw/                    # Raw ASTER GDEM tiles
│   ├── USA/               # United States tiles
│   ├── CAN/               # Canada tiles
│   └── ...
├── processed/             # Processed terrain data
│   ├── USA/               # Processed US data
│   └── ...
├── metadata/              # Download metadata and logs
└── aster_download.log     # Download log file
```

## File Formats

- **Input**: ASTER GDEM GeoTIFF files (.tif)
- **Resolution**: 30m x 30m pixels
- **Coordinate System**: WGS84 (EPSG:4326)
- **Elevation Units**: Meters above sea level
- **Data Type**: 16-bit signed integer

## Integration with FGCom-mumble

The downloaded terrain data can be used with FGCom-mumble's terrain and environmental API:

1. **Terrain Altitude Data**: Provides elevation information for line-of-sight calculations
2. **Environmental Conditions**: Can be correlated with weather data for propagation modeling
3. **Noise Floor Calculations**: Terrain affects radio noise levels

### Example Integration
```cpp
// Use downloaded terrain data in FGCom-mumble
TerrainDataProvider terrain_provider;
terrain_provider.loadTerrainData("/path/to/terrain_data/processed/USA/");

// Get elevation at specific coordinates
double elevation = terrain_provider.getTerrainHeight(latitude, longitude);
```

## Performance Considerations

- **Download Size**: Each tile is typically 10-50 MB
- **Total Data**: A country like the USA may have 1000+ tiles
- **Download Time**: Depends on internet speed (hours for large regions)
- **Storage**: Plan for 10-100 GB for complete country coverage

## Troubleshooting

### Common Issues

1. **Authentication Errors**
   - Verify NASA Earthdata credentials
   - Check account activation status

2. **Download Failures**
   - Check internet connection
   - Verify NASA Earthdata service status
   - Review log files for specific errors

3. **Missing Tiles**
   - Some regions may have limited ASTER coverage
   - Check available tiles with `--info` option

### Log Files
- **Main Log**: `terrain_data/aster_download.log`
- **Download Progress**: Real-time console output
- **Error Details**: Check log files for specific error messages

## Advanced Configuration

### Custom Regions
To add support for additional regions, modify the `region_bounds` dictionary in the Python script:

```python
self.region_bounds = {
    'NEW_REGION': {
        'north': 50.0, 'south': 40.0, 
        'east': 10.0, 'west': 0.0
    }
}
```

### Batch Processing
For multiple regions:
```bash
# Download multiple regions
for region in USA CAN GBR; do
    python3 aster_gdem_advanced.py --region $region
done
```

## Data Quality Notes

- **ASTER GDEM v3**: Latest version with improved accuracy
- **Coverage Gaps**: Some areas may have missing data
- **Water Bodies**: Ocean areas are set to 0 elevation
- **Urban Areas**: May have artifacts from buildings
- **Validation**: Cross-reference with other elevation datasets

## Legal and Usage

- **Data Source**: NASA/METI ASTER GDEM
- **License**: Public domain
- **Attribution**: Required for derived products
- **Commercial Use**: Allowed with proper attribution

## Support

For issues with the downloader:
1. Check the log files for error messages
2. Verify NASA Earthdata account status
3. Test with a small region first
4. Review the troubleshooting section above

For FGCom-mumble integration questions, refer to the main documentation.
