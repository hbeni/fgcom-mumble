# Utilities and Tools

## API Testing Tool
Comprehensive testing framework for all FGCom-mumble APIs:

- **[Comprehensive API Tester](scripts/api_testing/comprehensive_api_tester.py)** - Complete API testing tool for all endpoints
  - **Requirements**: Must be run against a compiled and running FGCom-mumble server
  - **Coverage**: Tests all API endpoints including authentication, solar data, weather, band segments, radio models, AGC/Squelch, antenna patterns, and vehicle dynamics
  - **Usage**: `python3 scripts/api_testing/comprehensive_api_tester.py --base-url http://localhost:8080`
  - **Features**: Automated testing, detailed reporting, error detection, and performance metrics

## Advanced Utilities
Essential tools for terrain data processing, antenna pattern conversion, and advanced configuration:

- **[ASTER GDEM Advanced Processing](scripts/utilities/aster_gdem_advanced.py)** - Advanced terrain data processing with Python
- **[ASTER GDEM Downloader](scripts/utilities/aster_gdem_downloader.sh)** - Automated ASTER terrain data download
- **[ASTER Downloader Documentation](scripts/utilities/README_ASTER_DOWNLOADER.md)** - Complete guide for ASTER data acquisition
- **[Pattern Extraction Advanced](scripts/utilities/extract_pattern_advanced.sh)** - Advanced antenna pattern extraction tools
- **[EZ to NEC Converter](scripts/utilities/ez2nec_converter.py)** - Convert EZ format files to NEC format
- **[EZNEC to NEC Converter](scripts/utilities/eznec2nec.sh)** - EZNEC format conversion script
- **[ASTER Requirements](scripts/utilities/requirements_aster.txt)** - Python dependencies for ASTER tools

## Utility Categories

### Terrain Data Processing:
- ASTER GDEM download and processing
- Advanced terrain elevation calculations
- Geographic data format conversion

### Antenna Pattern Tools:
- EZ/NEC format conversion
- Pattern extraction and analysis
- Electromagnetic simulation preparation

### Data Processing:
- Advanced pattern extraction
- Format conversion utilities
- Automated processing workflows

### Noise Analysis:
- EV charging station noise modeling
- Substation and power station noise analysis
- Open Infrastructure Map integration
- Atmospheric noise calculation
- Environmental noise analysis
