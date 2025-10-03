

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
- **WebRTC browser client support** (implemented) - Enable web browser access while preserving all existing connection methods
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
See [Advanced Features](advanced_features.md) for a comprehensive overview of all advanced features and capabilities.

## Quick Start Guide

### For Users
1. **[Installation Guide](docs/INSTALLATION_GUIDE.md)** - Get started with installation and setup
2. **[Client Usage Guide](docs/CLIENT_USAGE_GUIDE.md)** - Learn how to use the client with your flight simulator
3. **[WebRTC Gateway](webrtc-gateway/README.md)** - Web browser client for FGCom-mumble (no installation required)
4. **[Special Frequencies Guide](docs/SPECIAL_FREQUENCIES_GUIDE.md)** - Understand special features like ATIS and test frequencies
5. **[Troubleshooting Guide](docs/TROUBLESHOOTING_GUIDE.md)** - Solve common issues

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

See [Improvements](docs/roadmap/improvements.md) for detailed information about:
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

### WebRTC Browser Client Support (Implemented):
See [WebRTC Browser Client Support](web_rtc.md) for comprehensive WebRTC implementation documentation and related features.

### Antenna Pattern Creation Documentation:
See [Antenna Pattern Creation Documentation](antenna_patterns.md) for comprehensive antenna pattern creation guides and requirements.

### Frequency and Band Documentation:
- [Aviation VHF Civil](docs/aviation-VHF-civil.md) Civil aviation VHF frequency bands and usage
- [Military VHF/UHF](docs/military-vhf-uhf.md) Military VHF/UHF frequency bands and protocols
- [Civil HF Frequencies](docs/CIVIL_HF_freqs.md) Civil HF frequency allocations and usage
- [Known Military Bands](docs/KNOWN_MILITARY_BANDS_AND_FREQS.md) Military frequency bands and protocols
- [Vehicle Frequency Analysis](docs/TECHNICAL_DOCUMENTATION.md#vehicle-dynamics) Frequency analysis for different vehicle types



### Antenna Pattern Visualization:
The system includes comprehensive antenna pattern visualization showing realistic radiation patterns for various vehicle types. The purple lines represent a basic, crude representation of a JEEP vehicle (sides and wheels not shown for clarity). The "8" figure demonstrates how a typical antenna tied down at a 45° angle radiates, providing realistic propagation modeling for ground-based vehicles.

![Gain Pattern Visualization](https://raw.githubusercontent.com/Supermagnum/fgcom-mumble/refs/heads/master/assets/screenshots/gain%20pattern.png)

### Bugs/Feature requests/coding help
The project lives on github: https://github.com/Supermagnum/fgcom-mumble

If you want to request a feature or report a bug, you can do so on the issuetracker there. I appreciate help with coding, so feel free to clone the repository and hand in pull-requests!


## Installation and Setup

**See [Installation Guide](docs/INSTALLATION_GUIDE.md) for complete installation and setup instructions.**

### Quick Fix for Installation Issues

If you encounter installation problems, use the automated fix script:
- **[Fix Installation Script](scripts/fix_installation.sh)** - Automatically resolves common installation issues



## Client Usage

**See [Client Usage Guide](docs/CLIENT_USAGE_GUIDE.md) for complete client usage instructions and compatibility information.**


## Special Frequencies and Features

**See [Special Frequencies Guide](docs/SPECIAL_FREQUENCIES_GUIDE.md) for complete information about special frequencies, ATIS, landlines, and test features.**


## Troubleshooting

**See [Troubleshooting Guide](docs/TROUBLESHOOTING_GUIDE.md) for comprehensive troubleshooting information and solutions.**


## Compilation and Build

**See [Compilation Guide](docs/COMPILATION_GUIDE.md) for complete compilation and build instructions.**


## Band Segments Reference

**See [Band Segments Reference](docs/BAND_SEGMENTS_REFERENCE.md) for complete information about frequency allocations, band segments, and regulatory compliance.**

## Utilities and Tools

See [Utilities and Tools](utilities_and_tools.md) for comprehensive utilities, API testing tools, and advanced processing capabilities.

## Testing Framework

See [Testing Framework](testing_framework.md) for comprehensive testing framework documentation, test suites, quality standards, and execution instructions.

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
