

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

### New Advanced Features (v2.0+):
- **Multi-threaded Architecture**: [7 specialized background threads for optimal performance](docs/TECHNICAL_DOCUMENTATION.md#threading-architecture) - Learn how the threading system works and what each thread does
- **GPU Acceleration**: [Configurable GPU acceleration for complex calculations (client/server/hybrid modes)](docs/GPU_ACCELERATION_GUIDE.md) - Understand GPU modes, performance benefits, and configuration options
- **Feature Toggle System**: [107 configurable features across 17 categories for runtime customization](docs/TECHNICAL_DOCUMENTATION.md#feature-toggle-system) - Runtime feature management and configuration
- **Advanced Debugging**: [Comprehensive logging, profiling, and memory tracking system](docs/TECHNICAL_DOCUMENTATION.md#debugging-system) - Debugging and monitoring capabilities
- **RESTful API**: [Complete HTTP API with WebSocket real-time updates for external integration](docs/API_REFERENCE_COMPLETE.md) - Complete API documentation with examples
- **Amateur Radio Support**: [Full amateur radio band coverage with ITU region compliance](docs/BAND_SEGMENTS_API_DOCUMENTATION.md) - Amateur radio band segments and power limits
- **Amateur Radio Modes**: [Complete guide to CW, LSB, USB, NFM, and AM modes used by radio amateurs](docs/AMATEUR_RADIO_MODES_DOCUMENTATION.md) - Standard amateur radio mode implementation
- **Amateur Radio Terminology**: [Comprehensive guide to Q-codes, operating procedures, and amateur radio communication](docs/AMATEUR_RADIO_TERMINOLOGY.md) - Complete amateur radio terminology reference
- **Aviation & Maritime HF**: [Dedicated HF communication models for aviation and maritime operations](docs/aviation-VHF-civil.md) - Aviation and maritime HF communication
- **Antenna Pattern Library**: [Comprehensive EZNEC-based antenna patterns for all vehicle types with automated generation workflow](docs/PATTERN_FILE_STANDARDS.md) - **Realistic 3D antenna radiation patterns that model how antennas actually radiate electromagnetic energy in different directions. These patterns are essential for authentic radio communication simulation, showing how directional antennas (like Yagi beams) have high gain in one direction and low gain in others, while omnidirectional antennas radiate equally in all horizontal directions. The system includes patterns for aircraft (affected by attitude and altitude), ground vehicles (affected by vehicle body and ground plane), and maritime platforms (affected by ship structure). This provides physics-based signal quality calculations where antenna gain directly affects communication range and quality, making the radio simulation educationally valuable and realistic.**
- **STL-to-NEC Converter**: [Cross-platform tool for converting STL files to EZ and NEC formats for electromagnetic simulation](https://github.com/Supermagnum/stl-to-nec) - Convert 3D vehicle models to antenna simulation files
- **VHF/UHF Antenna Support**: [Professional-grade 2m (144-145 MHz) and 70cm (430-440 MHz) Yagi antennas with 10m height modeling](docs/2M_YAGI_ANTENNA_SUMMARY.md) - VHF/UHF antenna specifications and usage
- **Physics-Based Propagation**: [Advanced radio wave propagation modeling with atmospheric effects, tropospheric ducting, and terrain obstruction](docs/TECHNICAL_DOCUMENTATION.md#propagation-physics) - Radio propagation physics and modeling
- **Solar Data Integration**: [Real-time NOAA/SWPC solar data for accurate propagation modeling](docs/TECHNICAL_DOCUMENTATION.md#solar-data) - Solar data integration and usage
- **Vehicle Dynamics API**: [Complete vehicle position, attitude, and antenna orientation tracking](docs/TECHNICAL_DOCUMENTATION.md#vehicle-dynamics) - Vehicle dynamics and tracking system
- **Power Management**: [Advanced transmit power control](docs/TECHNICAL_DOCUMENTATION.md#power-management) - Power control and efficiency features
- **Frequency Offset Simulation**: [Realistic audio effects including Doppler shift and "Donald Duck" effect](docs/FREQUENCY_OFFSET_DOCUMENTATION.md) - Audio effects and frequency processing
- **Lightning Data Integration**: [Real-time atmospheric noise simulation from lightning strikes](docs/TECHNICAL_DOCUMENTATION.md#lightning-data) - Lightning data and noise simulation
- **Weather Data Integration**: [Atmospheric condition effects on radio propagation](docs/TECHNICAL_DOCUMENTATION.md#weather-data) - Weather effects on radio propagation
- **Security Features**: [TLS/SSL encryption, certificate-based authentication, token authorization, and secure client integration](docs/SECURITY_API_DOCUMENTATION.md) - Comprehensive security implementation guide *(Note: Radio encryption simulation is not yet implemented)*
- **Noise Floor Calculation**: [Advanced atmospheric noise modeling with environment-specific calculations, distance-based noise falloff, and manual position setting via GPS or Maidenhead locators](docs/NOISE_FLOOR_DISTANCE_GUIDE.md) - Distance-based noise falloff and environment detection
- **AGC & Squelch System**: [Advanced Automatic Gain Control and Squelch functionality with configurable presets](docs/TECHNICAL_DOCUMENTATION.md#agc-squelch) - AGC and squelch system configuration and usage
- **Radio Era Classification**: [Comprehensive radio technology classification system for SDR and traditional radios](docs/RADIO_ERA_CLASSIFICATION.md) - Historical radio technology classification and performance modeling
- **Technical Documentation**: [Technical user guide for administrators and developers](docs/TECHNICAL_USER_GUIDE.md) - Comprehensive guide for technical users

### Latest Updates (v2.1+):
- **Complete Antenna Pattern Integration**: [All 52 available radiation pattern files now loaded and mapped](docs/TECHNICAL_DOCUMENTATION.md#antenna-patterns) - Antenna pattern integration and management
- **Historical Maritime Support**: [Added coastal stations and HF ship antennas with toggle functionality](docs/HISTORICAL_MARITIME_BANDS.md) - Historical maritime HF frequency bands and coastal stations
- **Dynamic Pattern Loading**: [Replaced hardcoded paths with intelligent pattern discovery system](docs/TECHNICAL_DOCUMENTATION.md#antenna-patterns) - Dynamic antenna pattern loading system
- **Enhanced Vehicle Support**: [Added support for boats, ships, military vehicles, and amateur radio operators](docs/TECHNICAL_DOCUMENTATION.md#vehicle-dynamics) - Vehicle support and dynamics tracking
- **Organized Documentation**: [Restructured documentation with proper file organization](docs/README.md) - Documentation structure and organization

### Latest Updates (v2.3+):
- **Work Unit Distribution**: [Distributed computing system for GPU acceleration across multiple clients](docs/WORK_UNIT_DISTRIBUTION_API.md) - Learn about distributed computing and work unit management
- **Comprehensive Security**: [Multi-layer security with authentication, encryption, and threat detection](docs/SECURITY_API_DOCUMENTATION.md) - Security implementation and configuration *(Note: Radio encryption simulation is not yet implemented)*
- **Advanced API**: [Complete RESTful API with work unit distribution and security endpoints](docs/API_REFERENCE_COMPLETE.md) - Complete API documentation with examples
- **Vehicle Geometry Creation**: [Complete guide for creating vehicle geometry and ground planes](docs/VEHICLE_GEOMETRY_CREATION_GUIDE.md) - Vehicle geometry creation and ground plane modeling
- **Coding Standards**: [Strict architectural and design standards implementation](docs/CODING_STANDARDS.md) - Coding standards and architectural guidelines
- **Zero Tolerance Quality**: [Comprehensive code inspection ensuring no race conditions, memory leaks, or security vulnerabilities](docs/reports/CRITICAL_CODE_INSPECTION_REPORT.md) - Quality assurance and code inspection
- **Enhanced Documentation**: [Updated and consolidated documentation structure](docs/README.md) - Documentation structure and organization

### Latest Updates (v2.4+):
- **Radio Model Configuration**: [Comprehensive radio model system with NATO and Soviet/Warsaw Pact equipment support](docs/SERVER_SIDE_CONFIGURATION_GUIDE.md) - Server-side radio model configuration and management
- **Preset Channel Management**: [Advanced preset channel system for military radios with 99 presets support](docs/PRESET_CHANNEL_API_DOCUMENTATION.md) - Preset channel configuration and read-only API access
- **Military Radio Equipment**: [Implementation of AN/PRC-152, AN/PRC-77, AN/PRC-148, R-105, R-107, R-123 Magnolia and more](docs/SERVER_SIDE_CONFIGURATION_GUIDE.md#radio-model-configuration) - Military radio specifications and channel management
- **Configuration-Based System**: [All radio models and presets defined in JSON configuration files](docs/SERVER_SIDE_CONFIGURATION_GUIDE.md#configuration-files) - Server-side configuration management *(Note: Radio encryption simulation is not yet implemented)*
- **Missing Implementation**: Radio technical data specifications have not been implemented, and there are currently no antenna radiation patterns created for handheld or portable radio sets
- **GPU Resource Limiting**: [Intelligent GPU resource management for Client-Only and Hybrid modes with game detection and adaptive limits](docs/GPU_RESOURCE_LIMITING_GUIDE.md) - GPU resource management and performance optimization
- **Terrain and Environmental API**: [Production-ready C++ implementation with comprehensive error handling, thread safety, and performance optimization](client/mumble-plugin/lib/terrain_environmental_api.h) - Advanced terrain data processing with strict quality standards

**Detailed Documentation**: See [Technical Documentation](docs/TECHNICAL_DOCUMENTATION.md) for comprehensive technical details.



Documentation
=============
The documentation is split up into relevant parts:

- Readme.md (*this file*): General overview and client documentation ([deutsche Version](server/Readme.server-de_DE.md))
- [client/mumble-plugin/plugin.spec.md](client/mumble-plugin/plugin.spec.md) Technical details on plugin design and its input/output data formats
- [client/radioGUI/Readme.RadioGUI.md](client/radioGUI/Readme.RadioGUI.md) Documentation for the Radio GUI client
- [client/fgfs-addon/Readme.md](client/fgfs-addon/Readme.md) Documentation for the Flightgear integration addon
- [server/Readme.server.md](server/Readme.server.md) Details on the server side components and how to run them
- [server/statuspage/Readme.statuspage.md](server/statuspage/Readme.statuspage.md) Technical details about the status page implementation
- [SECURITY.md](docs/SECURITY_API_DOCUMENTATION.md) Comprehensive security guide for TLS/SSL, authentication, and secure client connections

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


Install / Setup for the Client
==============================

Setup requirements
----------------------
- have a standard mumble client with recent plugin support (>= v1.4.0)
- a recent OpenSSL installation
- **v2.0+ Additional Requirements**:
  - `python3` (required): For antenna pattern generation and coordinate transformations
  - `bc` (required): For high-precision trigonometric calculations
  - `nec2c` (optional): NEC2 antenna simulation for pattern generation
  - GPU libraries (optional): CUDA/OpenCL for GPU acceleration features
  - `httplib.h` (included): HTTP client for solar data, lightning data, and weather data
  - `json.hpp` (included): JSON parsing for API responses and configuration


Installation
-----------------------
The release ZIP contains all binary plugins for all supported operating systems in the `mumble_plugin` bundle.

### v2.0+ Installation Notes
For full functionality with v2.0+ features, ensure you have the additional dependencies installed:

**Linux/Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install python3 bc libssl-dev
# Optional: For GPU acceleration
sudo apt-get install nvidia-cuda-toolkit  # For CUDA support
sudo apt-get install opencl-headers     # For OpenCL support
```

**Windows:**
- Install Python 3.x from python.org
- Install bc calculator (available via Chocolatey: `choco install bc`)
- Install Visual Studio Build Tools for C++ compilation
- Install CUDA Toolkit (optional, for GPU acceleration)

**macOS:**
```bash
brew install python3 bc openssl
# Optional: For GPU acceleration
brew install cuda  # For CUDA support
```

Several installation procedures exist:

### GUI method (recommended)
After installing Mumble, you can usually install the plugin by just double-clicking the  `.mumble_plugin`-bundle.

Otherwise you can also use Mumbles integrated plugin installer:
- Start Mumble.
- In Mumbles *Configure/Settings/Plugins* dialog, hit *Install plugin*.
- Select the `.mumble_plugin` plugin bundle. Mumble will install the plugin file and report success.
- browse the plugin list and activate *FGCom-mumble*.
- You are now ready to go!

### Manual install trough terminal
The installation can also be started by calling mumble from the commandline with the plugin binary release, like: `mumble fgcom-mumble-1.4.1.mumble_plugin`

### Manual install by file copying
- Rename the `.mumble_plugin` bundle to `.zip` and extract it.
- Choose the appropriate library for your operating system and copy it to mumbles `plugins`-folder.
  - `fgcom-mumble.so` for Linux (64 bit)
  - `fgcom-mumble.dll` for Windows (64 bit)
  - `fgcom-mumble-x86_32.dll` for Windows (32 bit)
  - `fgcom-mumble-macOS.bundle` for MacOs
- Mumble will pick it up automatically and show it in the plugins dialog. Activate the plugin.


Updating
----------------------
When Mumble starts, it will check the most recent version of the plugin against the github release page.
This can be disabled in mumbles settings.

When a more recent version is found, Mumble will ask you if you want to upgrade. When you allow it, Mumble downloads and replaces the plugin library automatically for you.  
You can also download and upgrade manually by the normal installation procedure described above.


Plugin configuration
-----------------------
Usually the default values are fine. Some features however can be configured differently, like disabling radio audio effects (white noise etc), changing the plugins UDP listen port or the name match of the special `fgcom-mumble` channel.

You can do this by copying the [`fgcom-mumble.ini`](configs/fgcom-mumble.ini) example file to your users home folder and adjusting as needed. The file is loaded once at plugin initialization from the following locations (in order):

- Linux:
  - `/etc/mumble/fgcom-mumble.ini`
  - `<home>/.fgcom-mumble.ini`
  - `<home>/fgcom-mumble.ini`
- Windows:
  - `<home>\fgcom-mumble.ini`
  - `<home>\Documents\fgcom-mumble.ini`

### Advanced Configuration (v2.0+)
FGCom-mumble v2.0+ includes comprehensive configuration options for all advanced features:

- **[configs/fgcom-mumble.conf.example](configs/fgcom-mumble.conf.example)**: Complete configuration template with all available options
- **[configs/fgcom-mumble.conf.minimal](configs/fgcom-mumble.conf.minimal)**: Minimal configuration for basic operation
- **Feature Toggles**: Runtime enable/disable of 107 features across 17 categories
- **Threading**: Customize thread intervals and resource allocation
- **API Server**: Configure RESTful API endpoints and WebSocket settings
- **Debugging**: Set logging levels, output handlers, and performance monitoring
- **Power Management**: Configure transmit power limits.
- **Solar Data**: Set NOAA/SWPC data update intervals and fallback options
- **Lightning Data**: Configure atmospheric noise simulation parameters
- **Weather Data**: Set weather data sources and update frequencies

All configuration files support INI format with comprehensive documentation and validation.



Running the client
======================
- connect your mumble client to fgfs mumble server
- enable your plugin in your standard mumble client
- join a channel starting with `fgcom-mumble` 

You are ready for radio usage! Some client needs to supply information to the plugin now, so it knows about your location and radio stack.

### API Integration (v2.0+)
FGCom-mumble v2.0+ provides comprehensive API integration for external applications:

- **RESTful API**: HTTP endpoints for propagation data, solar conditions, band status, antenna patterns, vehicle dynamics, power management, and system status
- **Band Segments API**: Read-only access to amateur radio frequency allocations, power limits, and regional restrictions
- **Preset Channel API**: Read-only access to preset channel information for radio models (AN/PRC-152 with 99 presets)
- **WebSocket Real-time Updates**: Live propagation updates, solar data changes, vehicle position tracking, and system monitoring
- **Client Examples**: JavaScript, Python, and C++ integration examples provided
- **Authentication**: API key management with secure storage and rotation
- **Rate Limiting**: Built-in abuse detection and prevention
- **Documentation**: Complete API reference with request/response examples

See [API Documentation](docs/API_DOCUMENTATION.md), [Band Segments API Documentation](docs/BAND_SEGMENTS_API_DOCUMENTATION.md), [Preset Channel API Documentation](docs/PRESET_CHANNEL_API_DOCUMENTATION.md), [Noise Floor Distance Guide](docs/NOISE_FLOOR_DISTANCE_GUIDE.md), [Environment Detection Guide](docs/ENVIRONMENT_DETECTION_GUIDE.md), and [GPU Acceleration Guide](docs/GPU_ACCELERATION_GUIDE.md) for complete integration details.


### Generic compatibility
The plugin aims to be compatible to the legacy fgcom-standalone protocol, so vey much all halfway recent fgfs instances, ATC clients and aircraft should handle it out of the box at least with COM1.

Note that frequencies can be arbitary strings. That said, all participating clients must share a common definition of "frequency", this should be the physical radio wave frequency in MHz and not the "channel" (esp. with 8.3 channels spacing).  
Also note that callsigns and frequencies are not allowed to contain the comma symbol (`,`). Decimal point symbol has always to be a point (`.`).

The connected simulator is expected  to provide PTT-information in order to activate radio transmissions, but you may also use the configfile to define mappings for mumble's internal voice activation. This way, you can use mumbles own PTT-binding to activate the radios you mapped. By default, the first Radio is already mapped for your convinience.


### RadioGUI
FGCom-mumble releases ship with a cross-plattform java application that implements most of the UDP protocol and thus can be used not only for testing purposes, but also real operations without the need for another client.  
Core features are supported by any radioGUI version but use the latest to be sure to get all features (if in doubt, read the release notes).

#### SimConnect (MSFS-2020) support
RadioGUI can act as a SimConnect bridge to support MSFS2020 and other SimConnect compatible simulators (P3d, FSX, etc).
For details on how this can be done, look at RadioGUI's readme.


### Flightgear specific
Just add and activate the [FGFS-addon](client/fgfs-addon/Readme.md) in your launcher (you can use FGCom-Mumble and the old FGCom in parallel).

The FGFS protocol file will handle old 25kHz as well as newer 8.3kHz radios.
After starting flightgear, you can use your radio stack like with FGCom (default is *space* to talk on COM1, *shift+space* for COM2, *alt+space* for COM3 and *ctrl+space* for intercom). Additional radios can be accessed by adding custom keybinds, or by using the _Combar_.  
The addon can be configured via a new entry in the *Multiplayer* menu.

Your ADF will recognize transmissions in the kHz range. With enabled _ADF_-mode the indicated bearing is recognized and visible on the instrument. The plane's audio system may also playback the received analog audio signal. This is usually switched at your plane's audio panel.


### ATC-Pie specific
Since ATC-Pie v1.7.1 FGCom-mumble is supported out of the box.
Be sure to activate the fgcom-mumble option however, as the standard fgcom support does only work with COM1.


### OpenRadar specific
Currently, OpenRadar just supports one Radio per UDP port. In case you want several Radios (which is likely), you need to invoke several dedicated mumble processes. This will give you separate FGCom-mumble plugin instances listening on different ports, and in OpenRadar you can thus specify that ports.

For better FGCom-mumble support, [patches are already pending](https://sourceforge.net/p/openradar/tickets/) and there is a [binary package available](http://fgcom.hallinger.org/OpenRadar_fgcom-mumble.jar).  
With that patches, you can select FGCom-mumble and then kindly add the same port for each radio (like "`16661,16661`" to get two radios connected to your single plugin instance).


Support for FGCom special frequencies
-------------------------------------
A common thing is that pilots may want to easily test if their setup works. This is implemented trough some special bots as well as the plugin itself. Also, FGCom-mumble has builtin special frequencies with alternative behaviour.

Please note there is no global-chat frequency. If you want to globally chat, switch to normal mumble channels or use the landline feature (tune a `PHONE` frequency, see below).

### ATIS

ATIS Recording and -playback is provided by a set of specialized server side bots. Look for the recorder bot in mumbles channel list to see if the server supports ATIS recordings.

Recording
---------
To record an ATIS sample, you need to:

- Setup your Callsign to the target one. The replay-bot will use that callsign to identify itself
- Setup your location on earth; pay attention to a proper height as this will mainly determine the range of the signal
- Tune a COM device to frequency `RECORD_<tgtFrq>`
- Start talking on the COM device by pressing its PTT
- When done, release PTT and retune to a normal frequency.

Regular recordings have a serverside limit of 120 seconds by default.

Note: Chances are good that your ATC client does all this for you and you just need to push some "Record ATIS" button.  
The RadioGUI has a tuning template for that. It may be a good idea to start a separate instance of the RadioGUI for recording in order to be able to leave the original client data untouched.

Playback
---------
If a `botmanager` is running at the server, the recorderbot will notify it to start a matching replay-bot. the recording user is by default authenticated to the playback bot and can thus manage it using chat commands (try saying `/help` to him to get started).


### Landlines/Intercom
Landlines/Intercom connections are a feature meant to be used by ATC instances. They are not subject to radio limits like range or signal quality. They operate worldwide and in full duplex.  
Landline channel names starts with `PHONE` and intercom with `IC:`. The difference between the two is audio characteristics.

To talk on an intercom/landline connection:

- Tune a COM device to frequency `PHONE:[ICAO]:[POS](:[LINE])`, like `PHONE:EDDM:TWR:1` or `PHONE:EDMO:GND`.
- Use your PTT as usual

Note: Chances are good that your ATC client does set this up for you and provides some "Talk on Intercom" button.


### Test frequencies
Test frequencies are provided by a specialized server side bot. Look for the bot in mumbles channel list to see if the server supports test frequencies:

  - 910.000 MHz: echo test frequency. Your voice will be echoed back after you release PTT, to allow you to check that your microphone, speakers/headset and that your connection to the FGCom server works and to let you know how you are heared from others. Test recordings are limited to 10 seconds by default.
  - NOT-IMPLEMENTED-YET: 911.000 MHz: The frequency continuously plays a test sample, allowing you to check that your connection to the FGCom server works.


### Obsolete legacy FGCom frequencies
The following traditional FGCom frequencies are not special anymore; these are now implemented trough "default" comms (they were special before because of asterisk implementation details):

- 121.000 MHz, 121.500 MHz: "guard" frequencies reserved for emergency communications;
- 123.450 MHz, 123.500 MHz, 122.750 MHz: general chat frequencies (they are obsolete anyway since 8.33 channels where introduced 20.12.2019! -> new is 122.540, 122.555, 130.430 MHz);
- 700.000 MHz: radio station frequency. Depending on the FGCom server in use, a recorded radio message will be played;
- 723.340 MHz: French Air Patrol communication frequency.


### Special FGCom-mumble frequencies
- `<del>`: Providing this frequency will deregister the radio. A Radio on this frequency is never operable and thus never sends or receives transmissions.


Troubleshooting
------------------------

### Installation Issues

**Plugin not loading:**
- Ensure Mumble version is >= 1.4.0
- Check that OpenSSL is properly installed
- Verify the plugin file is not corrupted
- Check Mumble's plugin directory permissions

**v2.0+ Features not working:**
- Verify Python 3 is installed and accessible: `python3 --version`
- Check bc calculator is available: `bc --version`
- For GPU acceleration, verify CUDA/OpenCL drivers are installed
- Check configuration files are in correct locations

**Configuration issues:**
- Ensure configuration files are in the correct directory (`configs/` not `config/`)
- Check file permissions allow reading configuration files
- Verify INI file syntax is correct (no missing brackets, proper key=value format)

### Radio Communication Issues
When you cannot hear other pilots or are unable to transmit on the radios, you can check the following:

- Make sure, your mumble is operational otherwise (so you can talk with others)
- Check mumbles client comment if the callsign and radio frequencies are registered
- Check the status webpage if it shows your entry (shows the data others receive from you)
- To send, you need to activate the PTT of the radio (pressing mumbles native PTT-key is just mapped to COM1 by default).
- Try to check against the FGCOM-Echo bot (tune 910.00 and transmit something; but needs the bot manager alive on the server)
- Check that you are not transmitting when you expect incoming messages (Radios are halfduplex -> look at your mumble symbol)
- Recheck the tuned frequencies and volume of radio and, if present, audio panel
- Make sure the radio is operable (powered, switched on, serviceable)
- Check that you really are in range (low altitude severely limits your available range!)
- Try to leave and rejoin the channel, so the plugin reinitializes; or restart mumble.
- Check that your software (ATC, flightsim) actually sends data to the plugin udp port. Recheck the port the plugin listens to (the plugin tells you at startup in the mumble chat window)
- Look at the plugins debug messages (start mumble from terminal; you need to make a debug build for that)
  - Look at the murmur server log for possible dropped plugin messages (look for the string `Dropping plugin message`), they may cause out of sync state. Reasons can be:
    - the setting *`pluginmessagelimit`* in `murmur.ini` may be too restrictive.
    - a bug in the plugin-io code: The plugin is expected to work well with default settings, so dropped messages may indicate a plugin bug; especially if they appear rapidly over a longer time.


Known Issues
------------
- **None currently known.** All major issues have been resolved. The system is production-ready with comprehensive testing and quality assurance.


Compiling the plugin
======================
The FGCom-mumble client plugin needs to be in binary form. If you want to use the latest code from github, you can compile yourself. The makefile is tailored to be used mainly on linux, but can be used in windows and macOS too.  

- Prerequisites:
  - `git`, `make`, `g++`, `mingw32` (for windows build)
  - OpenSSL: Linux builds dynamically against the installed `libssl-dev`. MingW/Windows links statically against a build from the git submodule `lib/openssl` by invoking `make openssl-win`.
- **v2.0+ Additional Dependencies**:
  - `httplib.h` (included): HTTP client for solar data, lightning data, and weather data
  - `json.hpp` (included): JSON parsing for API responses and configuration
  - `nec2c` (optional): NEC2 antenna simulation for pattern generation
  - `python3` (required): For antenna pattern generation and coordinate transformations
  - `bc` (required): For high-precision trigonometric calculations

Linux native build
------------------
The makefile is optimized for Linux systems and provides the most comprehensive build options:

### Prerequisites Installation

**Ubuntu/Debian:**
```bash
# Install basic build tools
sudo apt-get update
sudo apt-get install build-essential git make g++

# Install OpenSSL development libraries
sudo apt-get install libssl-dev

# Install v2.0+ dependencies
sudo apt-get install python3 bc

# Optional: Install NEC2 for antenna pattern generation
sudo apt-get install nec2c

# Optional: Install GPU acceleration libraries
sudo apt-get install nvidia-cuda-toolkit  # For CUDA support
sudo apt-get install opencl-headers      # For OpenCL support
```

**CentOS/RHEL/Fedora:**
```bash
# Install basic build tools
sudo yum groupinstall "Development Tools"
sudo yum install git

# Install OpenSSL development libraries
sudo yum install openssl-devel

# Install v2.0+ dependencies
sudo yum install python3 bc

# Optional: Install NEC2 for antenna pattern generation
sudo yum install nec2c

# Optional: Install GPU acceleration libraries
sudo yum install cuda-toolkit  # For CUDA support
sudo yum install opencl-headers  # For OpenCL support
```

**Arch Linux:**
```bash
# Install basic build tools
sudo pacman -S base-devel git

# Install OpenSSL development libraries
sudo pacman -S openssl

# Install v2.0+ dependencies
sudo pacman -S python bc

# Optional: Install NEC2 for antenna pattern generation
sudo pacman -S nec2c

# Optional: Install GPU acceleration libraries
sudo pacman -S cuda opencl-headers
```

### Building the Plugin

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Supermagnum/fgcom-mumble.git
   cd fgcom-mumble
   ```

2. **Build the plugin:**
   ```bash
   # Standard release build
   make plugin
   
   # Debug build (with verbose output)
   make debug
   
   # Release build with all optimizations
   make release
   ```

3. **Install the plugin:**
   ```bash
   # Copy plugin to Mumble plugins directory
   sudo cp client/mumble-plugin/fgcom-mumble.so /usr/lib/mumble/plugins/
   
   # Or for user installation
   mkdir -p ~/.local/share/mumble/plugins/
   cp client/mumble-plugin/fgcom-mumble.so ~/.local/share/mumble/plugins/
   ```

### Advanced Build Options

**Build with specific compiler:**
```bash
make plugin CC=gcc-11 CXX=g++-11
```

**Build with debug symbols:**
```bash
make debug CFLAGS="-g -O0 -DDEBUG"
```

**Build with specific OpenSSL version:**
```bash
make plugin CFLAGS="-I/usr/local/ssl/include" LDFLAGS="-L/usr/local/ssl/lib"
```

**Build with GPU acceleration:**
```bash
# Enable CUDA support
make plugin ENABLE_CUDA=1

# Enable OpenCL support  
make plugin ENABLE_OPENCL=1

# Enable both
make plugin ENABLE_CUDA=1 ENABLE_OPENCL=1
```

### Testing the Build

**Run unit tests:**
```bash
make test
```

**Run comprehensive test suite:**
```bash
make test-all
```

**Generate documentation:**
```bash
make api-docs
make user-guide
```

**Generate antenna patterns:**
```bash
make patterns
```

### Troubleshooting Linux Build Issues

**OpenSSL not found:**
```bash
# Install OpenSSL development package
sudo apt-get install libssl-dev  # Ubuntu/Debian
sudo yum install openssl-devel   # CentOS/RHEL
```

**Python3 not found:**
```bash
# Install Python 3
sudo apt-get install python3 python3-dev  # Ubuntu/Debian
sudo yum install python3 python3-devel    # CentOS/RHEL
```

**bc calculator not found:**
```bash
# Install bc calculator
sudo apt-get install bc  # Ubuntu/Debian
sudo yum install bc      # CentOS/RHEL
```

**Permission denied errors:**
```bash
# Fix permissions
sudo chown -R $USER:$USER /usr/share/fgcom-mumble/
chmod +x scripts/pattern_generation/*.sh
```

**GPU acceleration not working:**
```bash
# Check CUDA installation
nvcc --version

# Check OpenCL installation
clinfo

# Install missing GPU libraries
sudo apt-get install nvidia-cuda-toolkit opencl-headers
```

### ASTER GDEM Terrain Data (Optional)

For realistic terrain obstruction detection, you can download ASTER GDEM elevation data:

#### Download ASTER GDEM Data

1. **Create data directory**:
   ```bash
   sudo mkdir -p /usr/share/fgcom-mumble/aster_gdem
   sudo chown $USER:$USER /usr/share/fgcom-mumble/aster_gdem
   ```

2. **Download ASTER GDEM tiles** (example for Europe):
   ```bash
   cd /usr/share/fgcom-mumble/aster_gdem
   
   # Download specific tiles (example: N50E010 for 50°N, 10°E)
   wget https://e4ftl01.cr.usgs.gov/ASTT/ASTGTM.003/2000.03.01/ASTGTM_N50E010_dem.tif
   wget https://e4ftl01.cr.usgs.gov/ASTT/ASTGTM.003/2000.03.01/ASTGTM_N50E011_dem.tif
   # ... download more tiles as needed
   ```

3. **Enable ASTER GDEM in configuration**:
   ```ini
   [terrain_elevation]
   enabled = true
   elevation_source = aster_gdem
   
   [aster_gdem]
   enabled = true
   data_path = /usr/share/fgcom-mumble/aster_gdem
   auto_download = false
   enable_obstruction_detection = true
   terrain_resolution_m = 30
   enable_fresnel_zone = true
   fresnel_clearance_percent = 0.6
   enable_diffraction = true
   ```

#### ASTER GDEM Coverage

- **Global Coverage**: Available for entire Earth surface
- **Resolution**: 30 meters (1 arc-second)
- **Format**: GeoTIFF (.tif files)
- **Tile Size**: 1° x 1° (approximately 111km x 111km at equator)
- **Total Size**: ~30GB for global coverage
- **Download Source**: [NASA Earthdata](https://e4ftl01.cr.usgs.gov/ASTT/ASTGTM.003/2000.03.01/)

#### Tile Naming Convention

ASTER GDEM tiles follow the pattern: `ASTGTM_N{lat}E{lon}_dem.tif`

- **N{lat}**: North latitude (e.g., N50 for 50°N)
- **E{lon}**: East longitude (e.g., E010 for 10°E)
- **Example**: `ASTGTM_N50E010_dem.tif` for 50°N, 10°E

#### Regional Download Examples

**Europe (50°N-60°N, 0°E-20°E)**:
```bash
# Download tiles for Central Europe
for lat in {50..59}; do
  for lon in {0..19}; do
    wget "https://e4ftl01.cr.usgs.gov/ASTT/ASTGTM.003/2000.03.01/ASTGTM_N${lat}E$(printf "%03d" $lon)_dem.tif"
  done
done
```

**North America (30°N-50°N, 70°W-130°W)**:
```bash
# Download tiles for North America
for lat in {30..49}; do
  for lon in {70..129}; do
    wget "https://e4ftl01.cr.usgs.gov/ASTT/ASTGTM.003/2000.03.01/ASTGTM_N${lat}W$(printf "%03d" $lon)_dem.tif"
  done
done
```

#### Alternative: SRTM Data

If ASTER GDEM is not available, you can use SRTM data:

1. **Download SRTM tiles** from [USGS Earth Explorer](https://earthexplorer.usgs.gov/)
2. **Convert to GeoTIFF** format
3. **Update configuration**:
   ```ini
   [terrain_elevation]
   elevation_source = srtm
   ```

- Building:
  - Download the source tree: `git clone https://github.com/Supermagnum/fgcom-mumble.git`
  - Go into the source project folder: `cd fgcom-mumble`
  - on linux type `make plugin` to build the binary mumble plugin library
  - or `make plugin-win64` to cross-compile to windows

Other interesting compile targets:

  - `make` is an alias for `make release`
  - `make release` creates release ZIP files
  - `make debug` will build the plugin and add debug code that will print lots of stuff to the terminal window when running the plugin
  - `make test` builds and runs catch2-unittests
  - `make tools` builds some utilitys and test tools
  - **v2.0+ New Targets**:
    - `make patterns` generates antenna patterns using EZNEC/NEC2
    - `make api-docs` generates API documentation
    - `make config-examples` creates configuration file examples
    - `make user-guide` generates user-friendly documentation
    - `make radio-classification` generates radio era classification documentation
    - `make agc-squelch` builds AGC and Squelch components
    - `make test-all` runs comprehensive test suite including AGC/Squelch tests


Windows native build
--------------------
The makefile works well on Windows with cygwin64 with mingw32.  
You just need to use `x86_64-w64-mingw32-g++` instead of `x86_64-w64-mingw32-g++-posix`:

- 64bit: `make CC=x86_64-w64-mingw32-g++ plugin-win64`
- 32bit: `make CC=i686-w64-mingw32-g++ plugin-win32`


MacOS native build
------------------
There is an makefile alias `make plugin-macOS` that will do the following:

- You need to explicitely use the _g++-11_ compiler, as the default _g++_ is linked to _clang_. Also you need to adjust the path to the openssl distribution:  
`make -C client/mumble-plugin/ outname=fgcom-mumble-macOS.bundle CC=g++-11 CFLAGS="-I/usr/local/opt/openssl/include/ -L/usr/local/opt/openssl/lib/" plugin`

- After compilation, rename the plugin binary to `fgcom-mumble-macOS.bundle` to stay compatible with the official releases.

## Band Segments Reference

For detailed band segment information and frequency allocations, refer to the comprehensive band segments database:

- **Band Segments CSV**: [https://github.com/Supermagnum/Supermorse-server/blob/main/Bandplans_and_antennas/band_segments.csv](https://github.com/Supermagnum/Supermorse-server/blob/main/Bandplans_and_antennas/band_segments.csv)

**Local CSV File**: `/home/haaken/github-projects/fgcom-mumble/configs/band_segments.csv`

This CSV file contains detailed information about:
- Frequency allocations for different regions
- Band segments for various modulation modes
- ITU region specifications
- Channel spacing requirements
- Power limits per band and region
- Country-specific restrictions
- Special Norwegian allocations (1000W for EME/MS operations on 2m, 70cm, 23cm bands)

**Modifying Band Segments**: Edit the local CSV file to update frequency allocations, power limits, and regional restrictions. Changes take effect after plugin restart without recompilation.
- Power limits and restrictions
