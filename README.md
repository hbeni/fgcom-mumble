

 FGCom-mumble - a flightsim radio simulation framework based on mumble
 
=====================================================================

<img src="server/statuspage/inc/fgcom_logo.png" width="100px" align="left" />
This project aims to provide a mumble-based modular radio simulation for flight simulators. The project started mainly as a successor for the asterisk-based FGCom implementation.

([-> deutsche Version](server/Readme.server-de_DE.md)) | [![donate](https://img.shields.io/badge/Help_keep_this_running-PaypalMe/BeniH-blue)](https://www.paypal.com/paypalme/BeniH/5)

### The main goals are:
- Provide communication with geographic and channel separation
- Provide a realistic radio simulation (incl. propagation)
- Ease of use for the end user / pilot
- Arbitary frequency support
- ATIS recording and playback
- Radio station broadcast support
- Landline/Intercom support
- RDF detection for clients
- Ease of server side installation and operation
- Standalone nature (no dependency on flightgear)
- Capability to be integrated into flightgear, with the option to support third party applications (ATC, but also other flightsims)
- Modularity, so individual components can be easily updated and extended with new features
- Good and complete documentation

### **Realistic Radio Communication Simulator**
- **Technical Setup Required**: Server administration and technical configuration needed
- **Primary Support**: FlightGear (native) and Microsoft Flight Simulator 2020 (via RadioGUI)
- **Realistic Communication**: Experience authentic radio procedures used by real pilots and operators
- **Educational Value**: Learn real radio communication skills and propagation physics
- **Community Support**: Join a community of aviation and radio simulation enthusiasts
- **Free to Use**: Open source with comprehensive documentation

**[Technical Setup Guide](docs/TECHNICAL_SETUP_GUIDE.md)** - Comprehensive setup guide for administrators and technical users

##  **Important: Technical Complexity Assessment**

**FGCom-mumble is NOT a simple "plug and play" system.** It requires:

- **Server Administration**: Linux/Windows server management experience
- **Technical Configuration**: 625+ configuration options across 17 categories
- **Network Setup**: UDP port configuration, firewall rules, channel management
- **Radio Knowledge**: Understanding of radio frequencies and propagation
- **Complex Installation**: Multi-step process with dependencies and manual configuration

**Supported Platforms:**
- **FlightGear**: Native integration (requires technical knowledge)
- **Microsoft Flight Simulator 2020**: Via RadioGUI with SimConnect (requires technical setup)
- **Other Games**: Manual integration through Mumble voice chat (no automatic detection)

**Realistic Setup Time:**
- **Basic Setup**: 2-4 hours for experienced administrators
- **Advanced Configuration**: 1-2 days for full feature setup
- **Troubleshooting**: Additional time for configuration issues

### **Advanced Features**
See [Advanced Features Documentation](docs/ADVANCED_FEATURES.md) for a comprehensive overview of all advanced features and capabilities organized by version and update cycle.

**Detailed Documentation**: See [Technical Documentation](docs/TECHNICAL_DOCUMENTATION.md) for comprehensive technical details.

**Noise Analysis**: See [EV Charging Station Noise Analysis](docs/EV_CHARGING_STATION_NOISE_ANALYSIS.md) for comprehensive noise modeling including electric vehicle charging station noise analysis.

**Electrical Infrastructure**: See [Substation and Power Station Noise Analysis](docs/SUBSTATION_POWER_STATION_NOISE_ANALYSIS.md) for comprehensive noise modeling including electrical substations and power stations with 2MW+ capacity threshold, fencing effects, and multipolygon geometry support.

**Real-time Infrastructure Data**: See [Open Infrastructure Map Integration](docs/OPEN_INFRASTRUCTURE_MAP_INTEGRATION.md) for comprehensive integration with Open Infrastructure Map data source, providing real-time electrical infrastructure data from OpenStreetMap via Overpass API for enhanced noise floor calculations.

**Amateur Radio Band Segments**: See [Radio Amateur Band Segments CSV Format](docs/RADIO_AMATEUR_BAND_SEGMENTS_CSV_FORMAT.md) for comprehensive documentation of the amateur radio frequency allocation system, including country-specific regulations, license class requirements, and power limits.

## Amateur Radio Integration

FGCom-Mumble includes comprehensive amateur radio band segment support with:

- **Global Frequency Allocations**: Support for all ITU regions (1, 2, 3)
- **Country-Specific Regulations**: Detailed allocations for UK, USA, Germany, Canada, Australia, and more
- **License Class Validation**: Automatic checking of license class requirements
- **Power Limit Enforcement**: Real-time power limit validation
- **Mode-Specific Allocations**: CW, SSB, Digital, EME, and Meteor Scatter support
- **Regional Compliance**: Automatic ITU region detection and validation

The system reads from `configs/radio_amateur_band_segments.csv` which contains over 280 frequency allocations covering all major amateur radio bands from 2200m to 70cm, with detailed power limits and licensing requirements for different countries and license classes.

## Quick Start Guide

### For Users
1. **[Installation Guide](docs/INSTALLATION_GUIDE.md)** - Get started with installation and setup
2. **[Client Usage Guide](docs/CLIENT_USAGE_GUIDE.md)** - Learn how to use the client with your flight simulator
3. **[Special Frequencies Guide](docs/SPECIAL_FREQUENCIES_GUIDE.md)** - Understand special features like ATIS and test frequencies
4. **[Troubleshooting Guide](docs/TROUBLESHOOTING_GUIDE.md)** - Solve common issues

### For Developers
1. **[Compilation Guide](docs/COMPILATION_GUIDE.md)** - Build from source code
2. **[Game Developer Integration Guide](docs/GAME_DEVELOPER_INTEGRATION_GUIDE.md)** - Integrate with your game or simulator
3. **[API Documentation](docs/API_REFERENCE_COMPLETE.md)** - Use the RESTful API and WebSocket interfaces
4. **[Technical Documentation](docs/TECHNICAL_DOCUMENTATION.md)** - Deep technical details

### For Administrators
1. **[Technical Setup Guide](docs/TECHNICAL_SETUP_GUIDE.md)** - Server setup and configuration
2. **[Security Documentation](docs/SECURITY_API_DOCUMENTATION.md)** - Security implementation and best practices
3. **[Server Documentation](server/Readme.server.md)** - Server-side components and operation

## **Improvements and Enhancements**

See [Improvements](improvements.md) for detailed information about:
- Security enhancement recommendations
- ATIS recording generation improvements
- Cold war era voice encryption systems
- Technical improvements and feature additions

Documentation
=============
The documentation is split up into relevant parts:

- Readme.md (*this file*): General overview and client documentation ([deutsche Version](server/Readme.server-de_DE.md))
- [client/mumble-plugin/plugin.spec.md](client/mumble-plugin/plugin.spec.md) Technical details on plugin design and its input/output data formats
- [client/radioGUI/Readme.RadioGUI.md](client/radioGUI/Readme.RadioGUI.md) Documentation for the Radio GUI client
- [client/fgfs-addon/Readme.md](client/fgfs-addon/Readme.md) Documentation for the Flightgear integration addon
- [server/Readme.server.md](server/Readme.server.md) Details on the server side components and how to run them
- [server/statuspage/Readme.statuspage.md](server/statuspage/Readme.statuspage.md) Technical details about the status page implementation
- [Security Documentation](docs/SECURITY_API_DOCUMENTATION.md) Comprehensive security guide for TLS/SSL, authentication, and secure client connections
- [GOOD_CODING_PRACTICES.md](docs/GOOD_CODING_PRACTICES.md) **STRICT coding standards and quality requirements** - Mandatory rules for all development work

### User Documentation:
- **[Technical Setup Guide](docs/TECHNICAL_SETUP_GUIDE.md)** **Comprehensive setup guide for administrators and technical users** - Honest assessment of complexity and detailed setup instructions
- **[Technical User Guide](docs/TECHNICAL_USER_GUIDE.md)** **Technical overview** - Understanding what FGCom-mumble is and its actual capabilities
- **[Game Developer Integration Guide](docs/GAME_DEVELOPER_INTEGRATION_GUIDE.md)** **Comprehensive guide for game developers and modders** - Technical integration requirements, data exchange protocols, and implementation examples
- **[Terrain and Environmental Data API](docs/TERRAIN_ENVIRONMENTAL_DATA_API.md)** **Critical terrain and environmental data requirements** - Line of sight, altitude, weather, and noise floor data that games must provide
- **[Game Terrain Integration Guide](docs/GAME_TERRAIN_INTEGRATION_GUIDE.md)** **Detailed terrain integration instructions** - Step-by-step guide for implementing terrain and environmental data in games

### Advanced Features Documentation:
- [API Reference Complete](docs/API_REFERENCE_COMPLETE.md) Complete RESTful API and WebSocket documentation
- [Work Unit Distribution API](docs/WORK_UNIT_DISTRIBUTION_API.md) Distributed computing and work unit management
- [Security API Documentation](docs/SECURITY_API_DOCUMENTATION.md) Comprehensive security implementation
- [Technical Setup Guide](docs/TECHNICAL_SETUP_GUIDE.md) Comprehensive setup instructions for administrators
- [Technical Documentation](docs/TECHNICAL_DOCUMENTATION.md) Consolidated technical documentation
- [Vehicle Geometry Creation Guide](docs/VEHICLE_GEOMETRY_CREATION_GUIDE.md) Complete guide for creating vehicle geometry
- [Amateur Radio Modes](docs/AMATEUR_RADIO_MODES_DOCUMENTATION.md) Complete guide to CW, LSB, USB, NFM, and AM modes
- [Amateur Radio Terminology](docs/AMATEUR_RADIO_TERMINOLOGY.md) Comprehensive amateur radio terminology and Q-codes reference
- [Coding Standards](docs/CODING_STANDARDS.md) Strict architectural and design standards
- [Radio Era Classification](docs/RADIO_ERA_CLASSIFICATION.md) Comprehensive radio technology classification system
- [BFO/SDR Compatibility](docs/BFO_SDR_COMPATIBILITY_ASSESSMENT.md) Beat Frequency Oscillator and Software Defined Radio compatibility
- [Threading Architecture](docs/TECHNICAL_DOCUMENTATION.md#threading-architecture) Multi-threaded system documentation
- [NEC Modeling Guide](docs/TECHNICAL_DOCUMENTATION.md#antenna-patterns) Antenna modeling and calculation guide
- [VHF/UHF Antenna Specifications](docs/ANTENNA_HEIGHT_SPECIFICATIONS.md) Professional antenna height and performance
- [New Antennas Summary](docs/2M_YAGI_ANTENNA_SUMMARY.md) Complete overview of all new VHF/UHF antennas
- [Propagation Physics](docs/TECHNICAL_DOCUMENTATION.md#propagation-physics) Physics-based radio wave propagation modeling
- [Vehicle Dynamics API](docs/TECHNICAL_DOCUMENTATION.md#vehicle-dynamics) Vehicle tracking and antenna orientation API
- [Vehicle Dynamics Examples](docs/TECHNICAL_DOCUMENTATION.md#vehicle-dynamics) Practical examples for vehicle dynamics integration
- [Historical Maritime Bands](docs/HISTORICAL_MARITIME_BANDS.md) Configuration and usage of historical maritime HF frequency bands
- [Realistic Antenna Examples](docs/2M_YAGI_ANTENNA_SUMMARY.md) Realistic antenna configurations for various vehicle types
- [Frequency Offset Documentation](docs/FREQUENCY_OFFSET_DOCUMENTATION.md) Audio processing and frequency offset simulation
- [VHF/UHF Pattern Integration](docs/VHF_UHF_PATTERN_INTEGRATION.md) VHF/UHF antenna pattern integration documentation

### Antenna Pattern Creation Documentation:
- [Creating Radiation Patterns Guide](docs/TECHNICAL_DOCUMENTATION.md#antenna-patterns) Complete guide for creating radiation pattern files
- [EZNEC Workflow Guide](docs/TECHNICAL_DOCUMENTATION.md#antenna-patterns) Step-by-step EZNEC workflow for pattern creation
- [Antenna Modeling Tools](docs/TECHNICAL_DOCUMENTATION.md#antenna-patterns) Tools and software for antenna modeling
- [Radiation Pattern Examples](docs/2M_YAGI_ANTENNA_SUMMARY.md) Practical examples for different vehicle types
- [2M Yagi Antenna Summary](docs/2M_YAGI_ANTENNA_SUMMARY.md) Professional 2m Yagi antenna specifications

**Important Note: Pattern Generation Requirements**
- **Aircraft radiation patterns are NOT included** in the repository due to storage constraints
- **Ground-based installation patterns are complete** and ready to use (216 patterns)
- **Marine patterns are NOT AVAILABLE** - cannot be generated due to safety limits (50,000+ combinations exceed limit, and storage constraints
- **Military-land and civilian-vehicle patterns are complete** and ready to use
- **Aircraft patterns must be generated by the user** using the provided pattern generation scripts
- **Marine patterns cannot be generated** - script safety limits prevent generation (exceeds 50,000 combination limit), use the --force option to fix the issue!
- **Generation time**: Aircraft patterns can take several hours to generate (10,000+ combinations per aircraft)
- **Storage requirements**: Each aircraft requires significant disk space for all attitude combinations
- **Generation script**: Use `scripts/pattern_generation/antenna-radiation-pattern-generator.sh` to generate missing patterns
- **Progress reporting**: The script includes progress reporting showing altitude bands and completion percentage

**[Available Radiation Patterns](available_patterns.md)** - Complete list of radiation patterns currently available in the repository

### Frequency and Band Documentation:
- [Aviation VHF Civil](docs/aviation-VHF-civil.md) Civil aviation VHF frequency bands and usage
- [Military VHF/UHF](docs/military-vhf-uhf.md) Military VHF/UHF frequency bands and protocols
- [Civil HF Frequencies](docs/CIVIL_HF_freqs.md) Civil HF frequency allocations and usage
- [Known Military Bands](docs/KNOWN_MILITARY_BANDS_AND_FREQS.md) Military frequency bands and protocols
- [Vehicle Frequency Analysis](docs/TECHNICAL_DOCUMENTATION.md#vehicle-dynamics) Frequency analysis for different vehicle types



### Antenna Pattern Visualization:
The system includes comprehensive antenna pattern visualization showing realistic radiation patterns for various vehicle types. The purple lines represent a basic, crude representation of a JEEP vehicle (sides and wheels not shown for clarity). The "8" figure demonstrates how a typical antenna tied down at a 45° angle radiates, providing realistic propagation modeling for ground-based vehicles.

![Gain Pattern Visualization](https://raw.githubusercontent.com/Supermagnum/fgcom-mumble/refs/heads/master/Screenshots/gain%20pattern.png)

### Bugs/Feature requests/coding help
The project lives on github: https://github.com/Supermagnum/fgcom-mumble

If you want to request a feature or report a bug, you can do so on the issuetracker there. I appreciate help with coding, so feel free to clone the repository and hand in pull-requests!


## Installation and Setup

**See [Installation Guide](docs/INSTALLATION_GUIDE.md) for complete installation and setup instructions.**



## Client Usage

**See [Client Usage Guide](docs/CLIENT_USAGE_GUIDE.md) for complete client usage instructions and compatibility information.**


## Special Frequencies and Features

**See [Special Frequencies Guide](docs/SPECIAL_FREQUENCIES_GUIDE.md) for complete information about special frequencies, ATIS, landlines, and test features.**


## Troubleshooting

**See [Troubleshooting Guide](docs/TROUBLESHOOTING_GUIDE.md) for comprehensive troubleshooting information and solutions.**


## Compilation and Build

**See [Compilation Guide](docs/COMPILATION_GUIDE.md) for complete compilation and build instructions.**

### **Testing Framework Compilation**
The comprehensive testing framework can be compiled and executed as follows:

```bash
# AGC/Squelch Module Tests
cd test/agc_squelch_tests
g++ -std=c++17 -I../../client/mumble-plugin/lib -I. -lgtest -lgmock -pthread test_agc_squelch_main.cpp test_agc_config.cpp test_thread_safety.cpp -o agc_squelch_tests

# Integration Tests
cd test/integration_tests
g++ -std=c++17 -I../../client/mumble-plugin/lib -I. -lgtest -lgmock -pthread test_integration_main.cpp -o integration_tests

# Status Page Module Tests
cd test/status_page_module_tests
g++ -std=c++17 -I../../client/mumble-plugin/lib -I. -lgtest -lgmock -pthread test_status_page_main.cpp -o status_page_tests

# Error Handling Tests
cd test/error_handling_tests
g++ -std=c++17 -I../../client/mumble-plugin/lib -I. -lgtest -lgmock -pthread test_error_handling_main.cpp -o error_handling_tests

# Performance Tests
cd test/performance_tests
g++ -std=c++17 -I../../client/mumble-plugin/lib -I. -lgtest -lgmock -pthread test_performance_main.cpp -o performance_tests
```

**All test files compile successfully and adhere to strict quality standards including thread safety, error handling, memory management, and input validation.**

## Band Segments Reference

**See [Band Segments Reference](docs/BAND_SEGMENTS_REFERENCE.md) for complete information about frequency allocations, band segments, and regulatory compliance.**

## Utilities and Tools

### **API Testing Tool**
Comprehensive testing framework for all FGCom-mumble APIs:

- **[Comprehensive API Tester](scripts/api_testing/comprehensive_api_tester.py)** - Complete API testing tool for all endpoints
  - **Requirements**: Must be run against a compiled and running FGCom-mumble server
  - **Coverage**: Tests all API endpoints including authentication, solar data, weather, band segments, radio models, AGC/Squelch, antenna patterns, and vehicle dynamics
  - **Usage**: `python3 scripts/api_testing/comprehensive_api_tester.py --base-url http://localhost:8080`
  - **Features**: Automated testing, detailed reporting, error detection, and performance metrics

### **Advanced Utilities**
Essential tools for terrain data processing, antenna pattern conversion, and advanced configuration:

- **[ASTER GDEM Advanced Processing](scripts/utilities/aster_gdem_advanced.py)** - Advanced terrain data processing with Python
- **[ASTER GDEM Downloader](scripts/utilities/aster_gdem_downloader.sh)** - Automated ASTER terrain data download
- **[ASTER Downloader Documentation](scripts/utilities/README_ASTER_DOWNLOADER.md)** - Complete guide for ASTER data acquisition
- **[Pattern Extraction Advanced](scripts/utilities/extract_pattern_advanced.sh)** - Advanced antenna pattern extraction tools
- **[EZ to NEC Converter](scripts/utilities/ez2nec_converter.py)** - Convert EZ format files to NEC format
- **[EZNEC to NEC Converter](scripts/utilities/eznec2nec.sh)** - EZNEC format conversion script
- **[ASTER Requirements](scripts/utilities/requirements_aster.txt)** - Python dependencies for ASTER tools

### **Utility Categories**

**Terrain Data Processing:**
- ASTER GDEM download and processing
- Advanced terrain elevation calculations
- Geographic data format conversion

**Antenna Pattern Tools:**
- EZ/NEC format conversion
- Pattern extraction and analysis
- Electromagnetic simulation preparation

**Data Processing:**
- Advanced pattern extraction
- Format conversion utilities
- Automated processing workflows

**Noise Analysis:**
- EV charging station noise modeling
- Substation and power station noise analysis
- Open Infrastructure Map integration
- Atmospheric noise calculation
- Environmental noise analysis

## Testing Framework

FGCom-mumble includes a comprehensive testing framework with strict quality standards and comprehensive test coverage:

### **Test Suite Overview**
The project includes multiple test suites covering all critical components:

#### **AGC/Squelch Module Tests** (`test/agc_squelch_tests/`)
- **`test_agc_squelch_main.cpp`** - Main test framework with thread-safe fixtures and comprehensive validation
- **`test_agc_config.cpp`** - AGC configuration testing with proper bounds checking and error handling
- **`test_thread_safety.cpp`** - Thread safety testing with concurrent operations and race condition detection
- **`test_singleton.cpp`** - Singleton pattern testing with thread-safe access validation
- **Features**: Thread-safe access methods, comprehensive input validation, proper error handling, atomic operations

#### **Integration Tests** (`test/integration_tests/`)
- **`test_integration_main.cpp`** - End-to-end integration testing with mock components
- **Features**: Mock client/server testing, audio processing validation, connection testing

#### **Status Page Module Tests** (`test/status_page_module_tests/`)
- **`test_status_page_main.cpp`** - Status page rendering and data processing tests
- **Features**: HTML rendering validation, data processing tests, WebSocket testing

#### **Error Handling Tests** (`test/error_handling_tests/`)
- **`test_error_handling_main.cpp`** - Comprehensive error handling and recovery testing
- **Features**: Exception handling, resource management, error propagation testing

#### **Performance Tests** (`test/performance_tests/`)
- **`test_performance_main.cpp`** - Performance and latency testing
- **Features**: Audio encoding/decoding performance, network transmission testing, propagation calculation testing

### **Test Quality Standards**
All tests adhere to strict quality standards:
- **Thread Safety**: All operations are properly synchronized with mutex protection
- **Error Handling**: Comprehensive try-catch blocks with proper exception propagation
- **Memory Management**: RAII principles with proper resource cleanup
- **Input Validation**: All inputs validated with bounds checking and sanitization
- **Race Condition Prevention**: Atomic operations and proper synchronization
- **Resource Management**: Exception-safe destructors and cleanup
- **Code Quality**: Clean separation of concerns and maintainable structure

### **Test Execution**
```bash
# Compile individual test suites
cd test/agc_squelch_tests
g++ -std=c++17 -I../../client/mumble-plugin/lib -I. -lgtest -lgmock -pthread test_agc_squelch_main.cpp test_agc_config.cpp test_thread_safety.cpp -o agc_squelch_tests

# Run tests with sanitizers
cd test/agc_squelch_tests
make test_with_sanitizers

# Run tests with coverage
cd test/agc_squelch_tests
make test_with_coverage
```

### **Test Coverage**
- **Unit Tests**: Individual component testing with mock objects
- **Integration Tests**: End-to-end system testing
- **Thread Safety Tests**: Concurrent operation validation
- **Performance Tests**: Latency and throughput measurement
- **Error Handling Tests**: Exception and error recovery testing
- **Memory Safety Tests**: Memory leak detection and resource management

## Project Reports

For comprehensive project status, testing results, and quality assurance documentation, see the following reports:

### Status Reports
- [Current Status Report](docs/reports/CURRENT_STATUS_REPORT.md) - Latest project status and recent improvements
- [Final Status Report](docs/reports/FINAL_STATUS_REPORT.md) - Final project status summary

### Quality Assurance Reports
- [Critical Code Inspection Report](docs/reports/CRITICAL_CODE_INSPECTION_REPORT.md) - Critical issues found and resolved
- [Code Review Report](docs/reports/CODE_REVIEW_REPORT.md) - Comprehensive code review for quality and architecture
- [Static Analysis Report](docs/reports/STATIC_ANALYSIS_REPORT.md) - Static code analysis results

### Testing Reports
- [Comprehensive Test Report](docs/reports/TEST_REPORT_COMPREHENSIVE.md) - Complete testing results and validation

### Documentation Reports
- [Code Documentation Audit Report](docs/reports/CODE_DOCUMENTATION_AUDIT_REPORT.md) - Documentation audit for self-documenting code standards

### Reports Index
- [Reports Index](docs/reports/REPORTS_INDEX.md) - Complete index of all project reports

All reports are dated September 29, 2024, and reflect the current production-ready status of the FGCom-mumble project.
