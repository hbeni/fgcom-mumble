# Utilities Scripts Directory

This directory contains utility scripts for various tasks including data processing, file conversion, terrain data management, and system maintenance in the FGcom-Mumble project.

## Scripts Overview

### `aster_gdem_advanced.py`
**Purpose**: Advanced ASTER GDEM (Global Digital Elevation Model) data processing for terrain analysis and elevation data management.

**Features**:
- ASTER GDEM data processing
- Terrain elevation analysis
- Geographic data conversion
- Elevation profile generation
- Terrain feature extraction

**Usage**:
```bash
# Process ASTER GDEM data
python3 aster_gdem_advanced.py --input data/aster_gdem.tif --output processed/

# Generate elevation profiles
python3 aster_gdem_advanced.py --profile --coordinates 40.7128,-74.0060

# Extract terrain features
python3 aster_gdem_advanced.py --features --input data/terrain.tif
```

**Dependencies**:
- Python 3.8+
- GDAL library
- NumPy
- SciPy
- Matplotlib (for visualization)

### `aster_gdem_downloader.sh`
**Purpose**: Automated downloading of ASTER GDEM elevation data for specific geographic regions.

**Features**:
- Automated ASTER GDEM downloading
- Geographic region selection
- Batch download capabilities
- Data validation and verification
- Progress tracking

**Usage**:
```bash
# Download ASTER GDEM data
./aster_gdem_downloader.sh --region "40.7128,-74.0060,40.7589,-73.9851"

# Batch download multiple regions
./aster_gdem_downloader.sh --batch regions.txt

# Download with validation
./aster_gdem_downloader.sh --validate --region "40.7128,-74.0060,40.7589,-73.9851"
```

### `extract_pattern_advanced.sh`
**Purpose**: Advanced extraction of radiation patterns from NEC2 simulation output files.

**Features**:
- NEC2 output parsing
- Pattern data extraction
- Format conversion
- Data validation
- Quality assurance

**Usage**:
```bash
# Extract patterns from NEC2 output
./extract_pattern_advanced.sh --input nec2_output.out --output patterns/

# Extract with specific format
./extract_pattern_advanced.sh --format csv --input nec2_output.out

# Extract with validation
./extract_pattern_advanced.sh --validate --input nec2_output.out
```

### `ez2nec_converter.py`
**Purpose**: Converts EZNEC antenna files to NEC2 format for electromagnetic simulation.

**Features**:
- EZNEC to NEC2 conversion
- Format validation
- Data integrity checks
- Conversion optimization
- Error handling

**Usage**:
```bash
# Convert EZNEC file to NEC2
python3 ez2nec_converter.py --input antenna.ez --output antenna.nec

# Batch conversion
python3 ez2nec_converter.py --batch ez_files.txt --output nec_files/

# Convert with validation
python3 ez2nec_converter.py --validate --input antenna.ez
```

### `eznec2nec.sh`
**Purpose**: Shell script wrapper for EZNEC to NEC2 conversion with additional features.

**Features**:
- EZNEC to NEC2 conversion
- Batch processing
- Error handling
- Progress tracking
- Output validation

**Usage**:
```bash
# Convert EZNEC file
./eznec2nec.sh antenna.ez antenna.nec

# Batch conversion
./eznec2nec.sh --batch ez_files.txt

# Convert with options
./eznec2nec.sh --options "--validate --optimize" antenna.ez
```

### `fix_gmock_issues.sh`
**Purpose**: Fixes common Google Mock (GMock) issues in C++ test code.

**Features**:
- GMock issue detection
- Automatic fix application
- Test code validation
- Mock object optimization
- Compatibility fixes

**Usage**:
```bash
# Fix GMock issues
./fix_gmock_issues.sh

# Fix specific files
./fix_gmock_issues.sh --files test_voice_encryption.cpp

# Fix with validation
./fix_gmock_issues.sh --validate
```

## Utility Categories

### Data Processing Utilities
- **ASTER GDEM Processing**: Terrain elevation data processing
- **Pattern Extraction**: Radiation pattern data extraction
- **Format Conversion**: File format conversion utilities
- **Data Validation**: Data integrity and quality checks

### File Conversion Utilities
- **EZNEC to NEC2**: Antenna file format conversion
- **Pattern Format Conversion**: Radiation pattern format conversion
- **Data Format Standardization**: Data format standardization
- **Batch Processing**: Batch file conversion

### System Maintenance Utilities
- **GMock Fixes**: Test framework issue resolution
- **Dependency Management**: System dependency management
- **Configuration Updates**: System configuration updates
- **Performance Optimization**: System performance optimization

## Usage Examples

### Terrain Data Processing
```bash
# Download ASTER GDEM data
./aster_gdem_downloader.sh --region "40.7128,-74.0060,40.7589,-73.9851"

# Process elevation data
python3 aster_gdem_advanced.py --input data/aster_gdem.tif --output processed/

# Generate elevation profiles
python3 aster_gdem_advanced.py --profile --coordinates 40.7128,-74.0060
```

### Antenna Pattern Processing
```bash
# Convert EZNEC to NEC2
./eznec2nec.sh antenna.ez antenna.nec

# Extract patterns from NEC2 output
./extract_pattern_advanced.sh --input nec2_output.out --output patterns/

# Batch process multiple files
./eznec2nec.sh --batch ez_files.txt
```

### System Maintenance
```bash
# Fix GMock issues
./fix_gmock_issues.sh

# Validate system dependencies
./fix_gmock_issues.sh --check-deps

# Update system configuration
./fix_gmock_issues.sh --update-config
```

## Configuration

### Utility Settings
- `utility_config.json` - Utility script configuration
- `data_processing.conf` - Data processing settings
- `conversion_rules.conf` - File conversion rules

### Dependencies
- `requirements_aster.txt` - Python dependencies for ASTER processing
- `system_deps.conf` - System dependencies
- `python_deps.txt` - Python package dependencies

## Integration

### With Development Workflow
```bash
# Pre-commit data processing
python3 aster_gdem_advanced.py --pre-commit

# Post-build pattern extraction
./extract_pattern_advanced.sh --post-build
```

### With CI/CD
```bash
# CI data processing
python3 aster_gdem_advanced.py --ci-mode

# Automated conversion
./eznec2nec.sh --automated
```

## Data Management

### Input Data
- **ASTER GDEM Files**: Terrain elevation data
- **EZNEC Files**: Antenna design files
- **NEC2 Output**: Electromagnetic simulation results
- **Pattern Files**: Radiation pattern data

### Output Data
- **Processed Terrain**: Processed elevation data
- **NEC2 Files**: Converted antenna files
- **Pattern Data**: Extracted radiation patterns
- **Analysis Reports**: Data analysis results

## Performance Optimization

### Processing Optimization
- Parallel processing support
- Memory optimization
- CPU utilization optimization
- I/O optimization
- Cache management

### Batch Processing
- Batch file processing
- Progress tracking
- Error handling
- Resource management
- Queue management

## Troubleshooting

### Common Issues

1. **Python Dependencies**
   ```bash
   # Install Python dependencies
   pip install -r requirements_aster.txt
   # Check Python version
   python3 --version
   ```

2. **GDAL Issues**
   ```bash
   # Install GDAL
   sudo apt-get install gdal-bin python3-gdal
   # Check GDAL installation
   gdalinfo --version
   ```

3. **File Conversion Issues**
   ```bash
   # Check file formats
   file input_file.ez
   # Validate conversion
   ./eznec2nec.sh --validate input_file.ez
   ```

### Debugging

1. **Verbose Output**
   ```bash
   # Enable verbose output
   python3 aster_gdem_advanced.py --verbose
   ./extract_pattern_advanced.sh --verbose
   ```

2. **Debug Mode**
   ```bash
   # Enable debug mode
   python3 ez2nec_converter.py --debug
   ./eznec2nec.sh --debug
   ```

3. **Log Analysis**
   ```bash
   # Check utility logs
   tail -f logs/utilities.log
   # Analyze error logs
   grep ERROR logs/utilities.log
   ```

## Best Practices

### Data Processing
1. **Backup Data**: Always backup input data
2. **Validate Input**: Validate input data before processing
3. **Monitor Resources**: Monitor system resources during processing
4. **Quality Checks**: Perform quality checks on output data
5. **Documentation**: Document processing steps and results

### File Conversion
1. **Format Validation**: Validate file formats before conversion
2. **Data Integrity**: Ensure data integrity during conversion
3. **Error Handling**: Implement proper error handling
4. **Progress Tracking**: Track conversion progress
5. **Output Validation**: Validate converted files

## Future Enhancements

- Machine learning-based data processing
- Advanced terrain analysis
- Real-time data processing
- Cloud-based processing
- Advanced visualization

## Support

For utility script issues:
1. Check utility logs in `logs/utilities/`
2. Verify dependencies
3. Review configuration files
4. Check input data formats
5. Validate system resources
