

# FGCom-mumble
## Realistic Radio Communication Simulator for Flight Simulators

<img src="server/statuspage/inc/fgcom_logo.png" width="100px" align="left" />

A mumble-based modular radio simulation framework that provides realistic radio communication for flight simulators and games with geographic separation, propagation modeling, and authentic radio effects.

[![donate](https://img.shields.io/badge/Help_keep_this_running-PaypalMe/BeniH-blue)](https://www.paypal.com/paypalme/BeniH/5) | [Deutsche Version](server/Readme.server-de_DE.md)

---

## What This Is

**FGCom-mumble** is a sophisticated radio communication simulator that brings realistic radio procedures to flight simulation and games. It's designed for enthusiasts who want authentic radio communication experiences with proper propagation modeling, geographic separation, and realistic audio effects.

### Key Features
- **Realistic Radio Simulation**: Geographic separation, propagation modeling, and authentic audio effects
- **Multi-Platform Support**: FlightGear (native), Microsoft Flight Simulator 2020 (experimental), and web browsers
- **Advanced Features**: ATIS recording, radio station broadcasts, landline/intercom support, and RDF detection
- **WebRTC Support**: Browser-based access without installation requirements
- **GPU Acceleration with Dynamic Scaling**: Intelligent GPU resource management for up to 200 concurrent users for high-performance propagation
- **Advanced GPU acceleration with shared computing capabilities**: Distribute calculations across multiple clients
- **Real-Time Data Integration**: Solar data, lightning data, and weather data for accurate propagation modeling
- **Antenna Pattern Library**: EZNEC-based 3D radiation patterns for all vehicle types
- **Physics-Based Propagation**: Atmospheric effects, tropospheric ducting, and terrain obstruction modeling
- **Feature Toggle System**: 50+ configurable features for custom deployments
- **API Integration**: RESTful APIs and WebSocket support for game developer integration
- **Voice Encryption Systems**: Military-grade voice encryption simulated
- **Satellite Communication**: Real-time satellite tracking and communication simulation
- **Advanced Fuzzing**: Comprehensive testing framework with AFL++ and MULL integration
- **ATIS Weather Integration**: Automatic weather data integration for realistic ATIS generation
- **Modular Design**: Extensible architecture for custom integrations

---

---

## Beta Testers Wanted!

**FGCom-mumble is actively seeking beta testers to help improve the system!**

We need experienced users to test new features, provide feedback, and help identify issues before public release. Beta testing is particularly valuable for:

- **GPU Acceleration Features**: Test CUDA, OpenCL, and Metal GPU acceleration
- **Advanced Configuration Options**: Validate multiple configuration settings across 17 categories
- **Multi-Platform Integration**: Test FlightGear, MSFS 2020, and WebRTC compatibility
- **Performance Optimization**: Help optimize GPU resource management and thermal control
- **New API Endpoints**: Test RESTful API and WebSocket interfaces
- **Security Features**: Validate authentication and authorization systems

### How to Participate

1. **Join the Beta Program**: Contact the development team through GitHub Issues
2. **Report Issues**: Use the issue tracker to report bugs and suggest improvements
3. **Provide Feedback**: Share your experience with different configurations and use cases
4. **Test New Features**: Help validate new functionality before public release

### Beta Tester Requirements

- **Technical Expertise**: Server administration and configuration experience
- **Testing Environment**: Dedicated test system for beta features
- **Feedback Commitment**: Regular feedback and issue reporting
- **Documentation**: Help improve documentation and user guides
- **Preferred optional skills**: C++/C experience and log reading ability

**Interested?** Open an issue on GitHub with "Beta Tester Application" in the title and describe your technical background and testing environment.

---


##  Security Setup

**IMPORTANT: Never store passwords, API keys, or usernames in configuration files!**

FGCom-mumble requires secure credential management. All sensitive data must be stored as environment variables.

### Quick Configuration Setup

```bash
# 1. Run the interactive configuration setup (RECOMMENDED)
./scripts/setup.sh

# 2. Or run the environment setup only
./scripts/setup_environment.sh

# 3. Or manually copy the template
cp configs/env.template .env
chmod 600 .env

# 4. Edit with your credentials
nano .env

# 4. Load environment variables
source .env
```

**The interactive setup script (`./scripts/setup.sh`) will guide you through:**
- Core application settings (API keys, database)
- External data sources (NOAA, NASA, weather APIs)
- GPU acceleration configuration
- Feature toggles and network settings
- Monitoring and logging options

### Security Documentation

- **[Security Setup Guide](docs/SECURITY_SETUP.md)** - Complete guide for setting up environment variables
- **[Security Best Practices](docs/SECURITY_BEST_PRACTICES.md)** - Production security guidelines
- **[Environment Template](configs/env.template)** - Template for all required environment variables

### Required Environment Variables

- `FGCOM_API_KEY` - Main application API key
- `NOAA_SWPC_API_KEY` - NOAA Space Weather API
- `NASA_API_KEY` - NASA API access
- `OPENWEATHERMAP_API_KEY` - Weather data API
- Database credentials (if using external database)

---

## Recent Updates (v1.3.1)

### New Features Added
- **Voice Encryption Systems**: Complete implementation of military-grade voice encryption including FreeDV, MELPe, and NATO standards
- **Satellite Communication**: Real-time satellite tracking with TLE support for military and amateur radio satellites
- **Advanced Fuzzing Framework**: Comprehensive testing with AFL++ and MULL integration for improved code quality
- **ATIS Weather Integration**: Automatic weather data integration with Piper TTS for realistic ATIS generation
- **Enhanced Security**: Multi-core optimization and comprehensive security fixes
- **Interactive Configuration**: New setup scripts for easier installation and configuration

### Component Versions
- **Plugin**: 1.1.1
- **Server**: 1.3.0  
- **RadioGUI**: 1.2.0
- **FlightGear Addon**: 1.3.1


## Important: Technical Requirements

**FGCom-mumble is NOT a simple "plug and play" system.** It requires technical expertise:

### Prerequisites
- **Server Administration**: Linux/Windows server management experience
- **Technical Configuration**: Multiple configuration options across 17 categories  
- **Network Setup**: UDP port configuration, firewall rules, channel management
- **Radio Knowledge**: Understanding of radio frequencies and propagation
- **Installation Time**: 2-4 hours for basic setup, 1-2 days for advanced configuration

### Supported Platforms
- **FlightGear**: Native integration (requires technical knowledge)
- **Microsoft Flight Simulator 2020**: Via RadioGUI with SimConnect (requires technical setup)
- **Web Browsers**: WebRTC gateway (no installation required)



---

## Getting Started

### For Pilots and Users
| Guide | Purpose |
|-------|---------|
| **[Installation Guide](docs/INSTALLATION.md)** | Complete setup and installation instructions |
| **[Client Usage Guide](docs/CLIENT_USAGE_GUIDE.md)** | How to use FGCom-mumble with your flight simulator |
| **[WebRTC Gateway](webrtc-gateway/README.md)** | Browser-based access (no installation required) |
| **[Special Frequencies Guide](docs/SPECIAL_FREQUENCIES_GUIDE.md)** | ATIS, test frequencies, and special features |
| **[Troubleshooting Guide](docs/TROUBLESHOOTING_GUIDE.md)** | Common issues and solutions |

### For Administrators
| Guide | Purpose |
|-------|---------|
| **[Technical Setup Guide](docs/TECHNICAL_SETUP_GUIDE.md)** | Server setup and configuration |
| **[Bot Management Guide](docs/BOT_MANAGEMENT_GUIDE.md)** | Bot configuration and management |
| **[Security Documentation](docs/SECURITY_API_DOCUMENTATION.md)** | Security implementation and best practices |
| **[Server Documentation](server/Readme.server.md)** | Server-side components and operation |
| **[Server Components](server/README.md)** | Complete server components and API documentation |
| **[Configuration Files](configs/README.md)** | All configuration files documentation |

### For Developers
| Guide | Purpose |
|-------|---------|
| **[Compilation Guide](docs/COMPILATION_GUIDE.md)** | Build from source code |
| **[Game Developer Integration Guide](docs/GAME_DEVELOPER_INTEGRATION_GUIDE.md)** | Integrate with your game or simulator |
| **[API Documentation](docs/API_REFERENCE_COMPLETE.md)** | RESTful API and WebSocket interfaces |
| **[Technical Documentation](docs/TECHNICAL_DOCUMENTATION.md)** | Deep technical details |
| **[Voice Encryption Documentation](voice-encryption/docs/VOICE_ENCRYPTION_MODULE.md)** | Military-grade voice encryption systems |
| **[Satellite Communication](voice-encryption/systems/satellites/docs/SATELLITE_COMMUNICATION_DOCUMENTATION.md)** | Satellite tracking and communication |
| **[Fuzzing Guide](docs/AFL_MULL_FUZZING_GUIDE.md)** | Advanced testing and quality assurance |
| **[Test Infrastructure](test/README.md)** | Comprehensive test infrastructure overview |
| **[Scripts Documentation](scripts/README.md)** | All scripts and utilities documentation |
| **[Analysis Scripts](scripts/analysis/README.md)** | Code analysis and static analysis tools |
| **[Debug Scripts](scripts/debug/README.md)** | Debugging and diagnostic scripts |
| **[Fix Scripts](scripts/fixes/README.md)** | Automated fix scripts |
| **[Validation Scripts](scripts/validation/README.md)** | Validation and testing scripts |
| **[Utility Scripts](scripts/utilities/README.md)** | Utility scripts for data processing |
| **[Pattern Generation](scripts/pattern_generation/README.md)** | Antenna pattern generation scripts with STL-to-NEC converter tool for 3D model conversion |
| **[WebRTC API Documentation](webrtc-gateway/API_DOCUMENTATION.md)** | Complete WebRTC Gateway API reference |
| **[WebRTC Integration Examples](webrtc-gateway/INTEGRATION_EXAMPLES.md)** | WebRTC Gateway integration examples |

---

## Quick Configuration

### Basic Setup
```bash
# Copy the example configuration
cp configs/fgcom-mumble.ini ~/.fgcom-mumble.ini
nano ~/.fgcom-mumble.ini
```

### Essential Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `radioAudioEffects` | `1` | Enable realistic radio static, noise, and propagation effects |
| `allowHearingNonPluginUsers` | `0` | Allow WebRTC browser clients to be heard by plugin users |
| `udpServerHost` | `127.0.0.1` | UDP server listening interface (`*` for all interfaces) |
| `udpServerPort` | `16661` | UDP server port for client communication |

### Configuration Examples

**For Pilots:**
```ini
radioAudioEffects=1
allowHearingNonPluginUsers=0
udpServerHost=127.0.0.1
```

**For ATC Controllers:**
```ini
radioAudioEffects=1
allowHearingNonPluginUsers=1
autoJoinChannel=1
```

**For WebRTC Gateway:**
```ini
radioAudioEffects=1
allowHearingNonPluginUsers=1
udpServerHost=*
```

---

## Complete Documentation

### Core Documentation
- **[How This Works for Dummies](docs/HOW_THIS_WORKS_FOR_DUMMIES.md)** - Simple explanation of radio propagation with practical examples
- **[Radio Propagation Mathematics](docs/RADIO_PROPAGATION_MATHEMATICS.md)** - Mathematical models and calculations
- **[Technical User Guide](docs/TECHNICAL_USER_GUIDE.md)** - Technical overview and capabilities

### Advanced Features
- **[Advanced Features](docs/advanced_features.md)** - Comprehensive overview of all advanced features
- **[WebRTC Browser Client Support](docs/web_rtc.md)** - WebRTC implementation documentation
- **[Antenna Pattern Creation](docs/antenna_patterns.md)** - Antenna pattern creation guides
- **[Dynamic GPU Scaling](docs/DYNAMIC_GPU_SCALING.md)** - Intelligent GPU resource management
- **[Utilities and Tools](docs/utilities_and_tools.md)** - Available utilities and tools

### Game Integration
- **[Game Developer Integration Guide](docs/GAME_DEVELOPER_INTEGRATION_GUIDE.md)** - Integration requirements and protocols
- **[Terrain and Environmental Data API](docs/TERRAIN_ENVIRONMENTAL_DATA_API.md)** - Critical terrain and environmental data requirements
- **[Game Terrain Integration Guide](docs/GAME_TERRAIN_INTEGRATION_GUIDE.md)** - Terrain integration instructions

### Frequency Documentation
- **[Aviation VHF Civil](docs/aviation-VHF-civil.md)** - Civil aviation VHF frequency bands
- **[Military VHF/UHF](docs/military-vhf-uhf.md)** - Military VHF/UHF frequency bands
- **[Civil HF Frequencies](docs/CIVIL_HF_freqs.md)** - Civil HF frequency allocations
- **[Known Military Bands](docs/KNOWN_MILITARY_BANDS_AND_FREQS.md)** - Military frequency bands and protocols
- **[Band Segments Reference](docs/BAND_SEGMENTS_REFERENCE.md)** - Frequency allocations and regulatory compliance

### Development Resources
- **[Good Coding Practices](docs/GOOD_CODING_PRACTICES.md)** - Strict coding standards and quality requirements

---

## Technical Components

### Client Components
- **[Mumble Plugin](client/mumble-plugin/plugin.spec.md)** - Technical details on plugin design and data formats
- **[RadioGUI](client/radioGUI/Readme.RadioGUI.md)** - Radio GUI client documentation
- **[FlightGear Addon](client/fgfs-addon/Readme.md)** - FlightGear integration addon

### Server Components
- **[Server Documentation](server/Readme.server.md)** - Server-side components and operation
- **[Status Page](server/statuspage/Readme.statuspage.md)** - Status page implementation details

### Advanced APIs
- **[Work Unit Distribution API](docs/WORK_UNIT_DISTRIBUTION_API.md)** - Distributed computing and work unit management
- **[Security API Documentation](docs/SECURITY_API_DOCUMENTATION.md)** - Comprehensive security implementation


### Satellite Communication
- **[Satellite Communication Documentation](voice-encryption/systems/satellites/docs/SATELLITE_COMMUNICATION_DOCUMENTATION.md)** - Complete satellite communication system
- **[TLE Support](voice-encryption/systems/satellites/orbital/tle_support.h)** - Two-Line Element orbital calculations
- **[Military Satellites](voice-encryption/systems/satellites/military/)** - Military satellite systems (Strela-3, FLTSATCOM, Tsiklon)
- **[Amateur Radio Satellites](voice-encryption/systems/satellites/amateur/)** - Amateur radio satellite systems (AO-7, FO-29, ISS, etc.)
- **[IoT Satellites](voice-encryption/systems/satellites/iot/)** - IoT and data satellite systems (Orbcomm, Gonets)

### Text-to-Speech Integration
- **[Piper TTS Integration](scripts/tts/README.md)** - Automatic ATIS generation with Piper TTS
- **[ATIS Weather Integration](scripts/tts/README_ATIS_WEATHER_INTEGRATION.md)** - Real-time weather data integration for ATIS

### Voice Encryption Systems Simulated
- **Yachta T-219 (Soviet/East Bloc)** 
- **VINSON KY-57 (NATO)**
- **Granit (Soviet/East Bloc)**
- **STANAG 4197 (NATO)**
- **MELPe with NATO Type 1 Encryption (NATO)**
- **FreeDV with ChaCha20-Poly1305 + X25519 Key Exchange (Modern)** 

> **IMPORTANT DISCLAIMER**: All voice encryption systems in this project are implemented for **educational and simulation purposes only**. These systems are designed to provide authentic Cold War-era and modern military communication simulation for flight simulators and games. **If used for any illegal activities, the responsibility lies solely with the user.** The developers and maintainers of this project are not responsible for any misuse of these systems.

### Voice Encryption Systems
- **[Voice Encryption Analysis](voice-encryption/docs/DEGRADATION_AND_INTERCEPTION_ANALYSIS.md)** - Comprehensive analysis of voice encryption systems
- **[FreeDV Implementation](voice-encryption/systems/freedv/README.md)** - FreeDV digital voice system with X25519 key exchange
- **[MELPe Implementation](voice-encryption/systems/melpe/README.md)** - MELPe NATO standard vocoder with NATO Type 1 encryption
- **[Military Encryption Systems](voice-encryption/systems/)** - Various military-grade encryption systems

#### Security Classifications
- **128-bit (Standard)**: Squadron communications, routine operations
- **192-bit (Tactical)**: Command channels, tactical operations  
- **256-bit (Top Secret)**: Special operations, classified missions

### Satellite Communication
- **[Satellite Communication Documentation](voice-encryption/systems/satellites/docs/SATELLITE_COMMUNICATION_DOCUMENTATION.md)** - Complete satellite communication system
- **[TLE Support](voice-encryption/systems/satellites/orbital/tle_support.h)** - Two-Line Element orbital calculations
- **[Military Satellites](voice-encryption/systems/satellites/military/)** - Military satellite systems (Strela-3, FLTSATCOM, Tsiklon)
- **[Amateur Radio Satellites](voice-encryption/systems/satellites/amateur/)** - Amateur radio satellite systems (AO-7, FO-29, ISS, etc.)
- **[IoT Satellites](voice-encryption/systems/satellites/iot/)** - IoT and data satellite systems (Orbcomm, Gonets)




---

## Installation

### Automated Installation
```bash
# Clone the repository
git clone https://github.com/Supermagnum/fgcom-mumble.git
cd fgcom-mumble

# Run the interactive configuration setup (RECOMMENDED)
./scripts/setup.sh

# Or run the automated installation script
sudo ./scripts/install_fgcom_mumble.sh
```

### Service Management
```bash
# Check system status
sudo ./scripts/status_fgcom_mumble.sh

# Uninstall (if needed)
sudo ./scripts/uninstall_fgcom_mumble.sh
```

### Environment Setup
```bash
# Set up environment variables securely
./scripts/setup_environment.sh

# Or manually copy and edit the template
cp configs/env.template .env
nano .env
source .env
```



### Build Commands
```bash
# Build all components
make all

# Build without MSFS 2020 support (recommended)
make build-radioGUI-without-jsimconnect

# Build with MSFS 2020 support (experimental)
make build-radioGUI-with-jsimconnect

# Build headless server (no GUI components)
make build-headless

# Create release packages
make release
```

## GPU Acceleration & Shared Computing

**Advanced GPU acceleration with shared computing capabilities:**

- **Multi-GPU Support**: Distribute calculations across multiple graphics cards
- **Network GPU Sharing**: Use GPUs from multiple computers in your network
- **Cloud GPU Integration**: Combine local and cloud GPU resources
- **Automatic Load Balancing**: Distribute work optimally across available GPUs
- **Cross-Platform**: CUDA (NVIDIA), OpenCL (AMD/Intel), Metal (Apple)

**Performance Benefits:**
- **10-100x faster** than CPU-only calculations
- **Handles 200+ pilots with intelligent dynamic scaling** simultaneously
- **Real-time weather** effects with no lag
- **Scalable performance** as you add more GPUs

## Dynamic GPU Scaling

**For detailed configuration and implementation guide, see [Dynamic GPU Scaling Documentation](docs/DYNAMIC_GPU_SCALING.md)**

**Intelligent GPU resource management for high user loads (up to 200 concurrent users):**

### **Key Features**
- **Automatic Scaling**: Adjusts GPU allocation based on user count (1-200+ users)
- **Network GPU Support**: Distribute calculations across multiple computers
- **Health Monitoring**: Automatic failover and load balancing
- **Performance Optimization**: Intelligent resource allocation with minimal waste

### **Quick Setup**
```bash
# Enable dynamic GPU scaling
enable_dynamic_gpu_scaling = true
max_local_gpus = 4
max_network_gpus = 8
scaling_thresholds = [20, 50, 100, 150, 200]
```

**For complete configuration options, troubleshooting, and advanced setup, see the [Dynamic GPU Scaling Documentation](docs/DYNAMIC_GPU_SCALING.md).**

---

## Antenna Pattern Visualization

**For detailed antenna pattern guide, see [Antenna Pattern Creation Documentation](docs/antenna_patterns.md)**

The system includes comprehensive antenna pattern visualization showing realistic radiation patterns for various vehicle types. The purple lines represent a basic, crude representation of a JEEP vehicle (sides and wheels not shown for clarity). The "8" figure demonstrates how a typical antenna tied down at a 45° angle radiates, providing realistic propagation modeling for ground-based vehicles.

![Gain Pattern Visualization](https://raw.githubusercontent.com/Supermagnum/fgcom-mumble/refs/heads/master/assets/screenshots/gain%20pattern.png)

### Included Antenna Patterns

**Note: Not all patterns are included to conserve repository space. Some patterns must be generated by users. Some of these needs improvements**

#### Ground-based Antennas (155 patterns)
- **Yagi Antennas**: 116 patterns covering HF (7-28MHz), VHF (50-144MHz), and UHF (432MHz) bands
- **Vertical Antennas**: 22 patterns for VHF/UHF fixed installations
- **Loop Antennas**: 10 patterns for HF (80m) operations
- **Coastal Stations**: 7 patterns for HF maritime communications

#### Military Land Vehicles (596 patterns)
- **Soviet UAZ**: 588 patterns with attitude variations
- **Leopard 1 MBT**: 3 patterns
- **T-55 Soviet MBT**: 3 patterns  
- **NATO Jeep**: 2 patterns

#### Civilian Vehicles (4 patterns)
- **Ford Transit**: 2 patterns
- **VW Passat**: 2 patterns

#### Patterns Not Included (Must be Generated)
- **Aircraft Patterns**: Not included due to storage constraints - must be generated using the pattern generation script
- **Marine Patterns**: Not available - cannot be generated due to safety limits (exceeds 50,000+ combination limit)
- **Ground Type Variations**: Ideally, patterns should be generated for each ground type (conductivity, permittivity), but this would create an extremely large database

**Generation**: Use `scripts/pattern_generation/antenna-radiation-pattern-generator.sh` to generate missing aircraft patterns. See [Antenna Pattern Creation Documentation](docs/antenna_patterns.md) for complete details.

**Note on Ground Types**: While ideal antenna patterns would account for different ground types (soil conductivity, moisture, urban vs rural environments), the database would become prohibitively large. Current patterns use standard ground assumptions for practical implementation.

---

## Contributing

The project lives on GitHub: https://github.com/Supermagnum/fgcom-mumble

- **Issues**: Report bugs or request features on the issue tracker
- **Pull Requests**: Contributions are welcome! Clone the repository and submit pull requests

---

## Testing and Quality

- **[Testing Guide](docs/TESTING_GUIDE.md)** - Simple explanation of what all tests do (non-programmer friendly)
- **[Test Results](docs/TEST_COVERAGE_DOCUMENTATION.md)** - Test suite execution results and coverage analysis
- **[Fuzzing Framework](docs/AFL_MULL_FUZZING_GUIDE.md)** - Advanced testing with AFL++ and MULL integration
- **[Fuzzing Results Report](docs/FUZZING_RESULTS_REPORT_2025-10-12.md)** - Comprehensive 12-hour fuzzing session results with zero crashes found
- **[Fuzzing Harnesses](fuzzing-tests/)** - libFuzzer-based fuzzing targets for comprehensive testing
- **[Test Modules](test-modules/)** - Comprehensive test suite with 20+ specialized testing modules
- **[RapidCheck Integration](docs/RAPIDCHECK_INTEGRATION_SUMMARY.md)** - Property-based testing framework
- **[Test Coverage Documentation](docs/TEST_COVERAGE_DOCUMENTATION.md)** - Comprehensive test coverage analysis

This code was built with AI assistance. I cannot program at all, but I can understand some compiler warnings and understand some log files. The code has proper formulas and calculations throughout. "Is these claims bullshit?" has one definitive answer: Run the tests. Examine what they do. Examine the mathematics. Read the documentation.
