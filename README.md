

# FGCom-mumble
## Realistic Radio Communication Simulator for Flight Simulators

<img src="server/statuspage/inc/fgcom_logo.png" width="100px" align="left" />

A mumble-based modular radio simulation framework that provides realistic radio communication for flight simulators with geographic separation, propagation modeling, and authentic radio procedures.

[![donate](https://img.shields.io/badge/Help_keep_this_running-PaypalMe/BeniH-blue)](https://www.paypal.com/paypalme/BeniH/5) | [Deutsche Version](server/Readme.server-de_DE.md)

---

## What This Is

**FGCom-mumble** is a sophisticated radio communication simulator that brings realistic radio procedures to flight simulation. It's designed for aviation enthusiasts who want authentic radio communication experiences with proper propagation modeling, geographic separation, and realistic audio effects.

### Key Features
- **Realistic Radio Simulation**: Geographic separation, propagation modeling, and authentic audio effects
- **Multi-Platform Support**: FlightGear (native), Microsoft Flight Simulator 2020 (via RadioGUI), and web browsers
- **Advanced Features**: ATIS recording, radio station broadcasts, landline/intercom support, and RDF detection
- **WebRTC Support**: Browser-based access without installation requirements
- **Modular Design**: Extensible architecture for custom integrations

---

## Beta Testers Wanted!

**FGCom-mumble is actively seeking beta testers to help improve the system!**

We need experienced users to test new features, provide feedback, and help identify issues before public release. Beta testing is particularly valuable for:

- **GPU Acceleration Features**: Test CUDA, OpenCL, and Metal GPU acceleration
- **Advanced Configuration Options**: Validate 625+ configuration settings across 17 categories
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

**Interested?** Open an issue on GitHub with "Beta Tester Application" in the title and describe your technical background and testing environment.

---

## Important: Technical Requirements

**FGCom-mumble is NOT a simple "plug and play" system.** It requires technical expertise:

### Prerequisites
- **Server Administration**: Linux/Windows server management experience
- **Technical Configuration**: 625+ configuration options across 17 categories  
- **Network Setup**: UDP port configuration, firewall rules, channel management
- **Radio Knowledge**: Understanding of radio frequencies and propagation
- **Installation Time**: 2-4 hours for basic setup, 1-2 days for advanced configuration

### Supported Platforms
- **FlightGear**: Native integration (requires technical knowledge)
- **Microsoft Flight Simulator 2020**: Via RadioGUI with SimConnect (requires technical setup)
- **Web Browsers**: WebRTC gateway (no installation required)
- **Other Games**: Manual integration through Mumble voice chat

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

### For Developers
| Guide | Purpose |
|-------|---------|
| **[Compilation Guide](docs/COMPILATION_GUIDE.md)** | Build from source code |
| **[Game Developer Integration Guide](docs/GAME_DEVELOPER_INTEGRATION_GUIDE.md)** | Integrate with your game or simulator |
| **[API Documentation](docs/API_REFERENCE_COMPLETE.md)** | RESTful API and WebSocket interfaces |
| **[Technical Documentation](docs/TECHNICAL_DOCUMENTATION.md)** | Deep technical details |

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


---

## Installation

### Automated Installation
```bash
# Clone the repository
git clone https://github.com/Supermagnum/fgcom-mumble.git
cd fgcom-mumble

# Run the automated installation script
sudo ./scripts/install_fgcom_mumble.sh
```

### Service Management
```bash
# Check system status
sudo ./scripts/status_fgcom_mumble.sh

# Uninstall (if needed)
sudo ./scripts/uninstall_fgcom_mumble.sh
```

---

## Antenna Pattern Visualization

The system includes comprehensive antenna pattern visualization showing realistic radiation patterns for various vehicle types. The purple lines represent a basic, crude representation of a JEEP vehicle (sides and wheels not shown for clarity). The "8" figure demonstrates how a typical antenna tied down at a 45° angle radiates, providing realistic propagation modeling for ground-based vehicles.

![Gain Pattern Visualization](https://raw.githubusercontent.com/Supermagnum/fgcom-mumble/refs/heads/master/assets/screenshots/gain%20pattern.png)

### Included Antenna Patterns

**Note: Not all patterns are included to conserve repository space. Some patterns must be generated by users.**

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

- **[Test Results](test/tests-passed.md)** - Test suite execution results and coverage analysis

s 