FGCom-mumble - a flightsim radio simulation framework based on mumble
=====================================================================

<img src="server/statuspage/inc/fgcom_logo.png" width="100px" align="left" />
This project aims to provide a mumble-based modular radio simulation for flight simulators. The project started mainly as a successor for the asterisk-based FGCom implementation.

([-> deutsche Version](config/README-de_DE.md)) | [![donate](https://img.shields.io/badge/Help_keep_this_running-PaypalMe/BeniH-blue)](https://www.paypal.com/paypalme/BeniH/5)

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

### **Perfect for Gamers and Non-Technical Users!**
- **Easy Setup**: No technical knowledge required - just install and play!
- **Game Compatibility**: Works with popular games like Microsoft Flight Simulator, X-Plane, DCS World, Arma 3, Squad, and many more
- **Realistic Communication**: Experience authentic radio procedures used by real pilots, soldiers, and emergency responders
- **Educational Value**: Learn real radio communication skills while having fun
- **Community Support**: Join a friendly community of aviation and military simulation enthusiasts
- **Free to Use**: No cost, no subscriptions, just download and start communicating!

**[Simple User Guide](docs/USER_GUIDE_SIMPLE.md)** - Perfect for beginners and non-technical users!

### New Advanced Features (v2.0+):
- **Multi-threaded Architecture**: 7 specialized background threads for optimal performance
- **GPU Acceleration**: Configurable GPU acceleration for complex calculations (client/server/hybrid modes)
- **Feature Toggle System**: 107 configurable features across 17 categories for runtime customization
- **Advanced Debugging**: Comprehensive logging, profiling, and memory tracking system
- **RESTful API**: Complete HTTP API with WebSocket real-time updates for external integration
- **Amateur Radio Support**: Full amateur radio band coverage with ITU region compliance
- **Aviation & Maritime HF**: Dedicated HF communication models for aviation and maritime operations
- **Antenna Pattern Library**: Comprehensive EZNEC-based antenna patterns for all vehicle types with automated generation workflow
- **VHF/UHF Antenna Support**: Professional-grade 2m (144-145 MHz) and 70cm (430-440 MHz) Yagi antennas with 10m height modeling
- **Physics-Based Propagation**: Advanced radio wave propagation modeling with atmospheric effects, tropospheric ducting, and terrain obstruction
- **Solar Data Integration**: Real-time NOAA/SWPC solar data for accurate propagation modeling
- **Vehicle Dynamics API**: Complete vehicle position, attitude, and antenna orientation tracking
- **Power Management**: Advanced transmit power control with efficiency and safety features
- **Frequency Offset Simulation**: Realistic audio effects including Doppler shift and "Donald Duck" effect
- **Lightning Data Integration**: Real-time atmospheric noise simulation from lightning strikes
- **Weather Data Integration**: Atmospheric condition effects on radio propagation
- **Security Features**: TLS/SSL encryption, certificate-based authentication, token authorization, and secure client integration
- **Noise Floor Calculation**: Advanced atmospheric noise modeling with environment-specific calculations and manual position setting via GPS or Maidenhead locators
- **AGC & Squelch System**: Advanced Automatic Gain Control and Squelch functionality with configurable presets
- **Radio Era Classification**: Comprehensive radio technology classification system for SDR and traditional radios
- **User-Friendly Documentation**: Simple user guide for non-technical users and gamers

### Latest Updates (v2.1+):
- **Complete Antenna Pattern Integration**: All 52 available radiation pattern files now loaded and mapped
- **Historical Maritime Support**: Added coastal stations and HF ship antennas with toggle functionality
- **Dynamic Pattern Loading**: Replaced hardcoded paths with intelligent pattern discovery system
- **Enhanced Vehicle Support**: Added support for boats, ships, military vehicles, and amateur radio operators
- **Organized Documentation**: Restructured documentation with proper file organization

### Latest Updates (v2.2+):
- **Advanced Pattern Generation**: New `antenna-radiation-pattern-generator.sh` with Python-based coordinate transformations
- **Reliable Trigonometry**: Replaced AWK with Python for accurate 3D coordinate transformations (pitch/roll/yaw)
- **3D Attitude Support**: Full support for aircraft attitude-based radiation patterns with real-time yaw rotation via API
- **Enhanced Coordinate System**: Proper aviation coordinate system implementation (pitch around Y-axis, roll around X-axis)
- **Improved Pattern Quality**: More accurate antenna radiation patterns with proper ground effects modeling
- **API Integration**: Seamless integration with Vehicle Dynamics API for real-time antenna orientation control
- **AGC & Squelch System**: Advanced Automatic Gain Control and Squelch functionality with configurable presets
- **Radio Era Classification**: Comprehensive radio technology classification system for SDR and traditional radios
- **User-Friendly Documentation**: Simple user guide for non-technical users and gamers

**📖 Detailed Documentation**: See [Antenna Pattern Generation Improvements](docs/ANTENNA_PATTERN_GENERATION_IMPROVEMENTS.md) for comprehensive technical details.

**PATTERN GENERATION FIXED**: The antenna radiation pattern generation system has been updated and is now working correctly. The scripts now use `.nec` files exclusively and include working aircraft patterns with proper altitude handling.

**IMPORTANT NOTICE**: The changes made to this branch compile successfully, but **all functions related to radio propagation simulation have not been tested**. Users should exercise caution when using radio propagation features in production environments until comprehensive testing is completed.

Documentation
=============
The documentation is split up into relevant parts:

- Readme.md (*this file*): General overview and client documentation ([deutsche Version](config/README-de_DE.md))
- [Readme.architecture.md](config/Readme.architecture.md) Details about the components that make up the system
- [client/plugin.spec.md](client/plugin.spec.md) Technical details on plugin design and its input/output data formats
- [client/radioGUI/Readme.RadioGUI.md](client/radioGUI/Readme.RadioGUI.md) Documentation for the Radio GUI client
- [client/fgfs-addon/Readme.md](client/fgfs-addon/Readme.md) Documentation for the Flightgear integration addon
- [server/Readme.server.md](server/Readme.server.md) Details on the server side components and how to run them
- [server/statuspage/Readme.statuspage.md](server/statuspage/Readme.statuspage.md) Technical details about the status page implementation
- [SECURITY.md](config/SECURITY.md) Comprehensive security guide for TLS/SSL, authentication, and secure client connections

### User Documentation:
- **[Simple User Guide](docs/USER_GUIDE_SIMPLE.md)** **Perfect for non-technical users and gamers!** Easy-to-understand guide explaining what FGCom-mumble is, what it can do, and how to use it with popular games and flight simulators.

### Advanced Features Documentation:
- [API Documentation](docs/API_DOCUMENTATION.md) Complete RESTful API and WebSocket documentation
- [AGC & Squelch API](docs/AGC_SQUELCH_API_DOCUMENTATION.md) Advanced Automatic Gain Control and Squelch API documentation
- [Radio Era Classification](docs/RADIO_ERA_CLASSIFICATION.md) Comprehensive radio technology classification system for SDR and traditional radios
- [BFO/SDR Compatibility](docs/BFO_SDR_COMPATIBILITY_ASSESSMENT.md) Beat Frequency Oscillator and Software Defined Radio compatibility assessment
- [Threading Architecture](docs/THREADING_ARCHITECTURE_DOCUMENTATION.md) Multi-threaded system documentation
- [NEC Modeling Guide](docs/NEC_MODELING_DOCUMENTATION.md) Antenna modeling and calculation guide
- [VHF/UHF Antenna Specifications](docs/ANTENNA_HEIGHT_SPECIFICATIONS.md) Professional antenna height and performance specifications
- [New Antennas Summary](docs/NEW_ANTENNAS_SUMMARY.md) Complete overview of all new VHF/UHF antennas
- [Propagation Physics](docs/PROPAGATION_PHYSICS_DOCUMENTATION.md) Physics-based radio wave propagation modeling
- [Vehicle Dynamics API](docs/VEHICLE_DYNAMICS_API.md) Vehicle tracking and antenna orientation API
- [Vehicle Dynamics Examples](docs/VEHICLE_DYNAMICS_EXAMPLES.md) Practical examples for vehicle dynamics integration
- [Historical Maritime Bands](docs/HISTORICAL_MARITIME_BANDS.md) Configuration and usage of historical maritime HF frequency bands
- [Realistic Antenna Examples](docs/REALISTIC_ANTENNA_EXAMPLES.md) Realistic antenna configurations for various vehicle types
- [Frequency Offset Documentation](docs/FREQUENCY_OFFSET_DOCUMENTATION.md) Audio processing and frequency offset simulation
- [VHF/UHF Pattern Integration](docs/VHF_UHF_PATTERN_INTEGRATION.md) VHF/UHF antenna pattern integration documentation
- [Encrypted Radio Module](docs/ENCRYPTED_RADIO_TRANSMISSION_MODULE.md) Encrypted radio transmission module documentation
- [Changes Log](docs/changes.md) Detailed development history and feature implementation log

### Antenna Pattern Creation Documentation:
- [Creating Radiation Patterns Guide](docs/CREATING_RADIATION_PATTERNS_GUIDE.md) Complete guide for creating radiation pattern files
- [EZNEC Workflow Guide](docs/EZNEC_WORKFLOW_GUIDE.md) Step-by-step EZNEC workflow for pattern creation
- [Antenna Modeling Tools](docs/ANTENNA_MODELING_TOOLS.md) Tools and software for antenna modeling
- [Radiation Pattern Examples](docs/RADIATION_PATTERN_EXAMPLES.md) Practical examples for different vehicle types
- [2M Yagi Antenna Summary](docs/2M_YAGI_ANTENNA_SUMMARY.md) Professional 2m Yagi antenna specifications

### Frequency and Band Documentation:
- [Aviation VHF Civil](docs/aviation-VHF-civil.md) Civil aviation VHF frequency bands and usage
- [Military VHF/UHF](docs/military-vhf-uhf.md) Military VHF/UHF frequency bands and protocols
- [Civil HF Frequencies](docs/CIVIL_HF_freqs.md) Civil HF frequency allocations and usage
- [Known Military Bands](docs/KNOWN_MILITARY_BANDS_AND_FREQS.md) Military frequency bands and protocols
- [Vehicle Frequency Analysis](docs/VEHICLE_FREQUENCY_ANALYSIS.md) Frequency analysis for different vehicle types

### Technical Documentation:
- [Architectural Fixes Summary](docs/ARCHITECTURAL_FIXES_SUMMARY.md) Summary of architectural improvements and fixes
- [Compilation Status](docs/COMPILATION_STATUS.md) Current compilation status and build information
- [Standardized Structure Summary](docs/STANDARDIZED_STRUCTURE_SUMMARY.md) Project structure standardization and organization

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


Installation
-----------------------
The release ZIP contains all binary plugins for all supported operating systems in the `mumble_plugin` bundle.

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
The installation can also be started by calling mumble from the commandline with the plugin binary release, like: `mumble fgcom-mumble-0.14.1.mumble_plugin`

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
- **GPU Acceleration**: Configure client/server/hybrid GPU acceleration modes
- **Threading**: Customize thread intervals and resource allocation
- **API Server**: Configure RESTful API endpoints and WebSocket settings
- **Debugging**: Set logging levels, output handlers, and performance monitoring
- **Power Management**: Configure transmit power limits and efficiency settings
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
- **WebSocket Real-time Updates**: Live propagation updates, solar data changes, vehicle position tracking, and system monitoring
- **Client Examples**: JavaScript, Python, and C++ integration examples provided
- **Authentication**: API key management with secure storage and rotation
- **Rate Limiting**: Built-in abuse detection and prevention
- **Documentation**: Complete API reference with request/response examples

See [API Documentation](docs/API_DOCUMENTATION.md) for complete integration details.


### Generic compatibility
The plugin aims to be compatible to the legacy fgcom-standalone protocol, so vey much all halfway recent fgfs instances, ATC clients and aircraft should handle it out of the box at least with COM1.

Note that frequencies can be arbitary strings. That said, all participating clients must share a common definition of "frequency", this should be the physical radio wave frequency in MHz and not the "channel" (esp. with 8.3 channels spacing).  
Also note that callsigns and frequencies are not allowed to contain the comma symbol (`,`). Decimal point symbol has always to be a point (`.`).

Despite we expect the connected simulator to provide PTT-information in order to activate radio transmissions, you may also use the configfile to define mappings for mumble's internal voice activation. This way, you can use mumbles own PTT-binding to activate the radios you mapped. By default, the first Radio is already mapped for your convinience.


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
- **Antenna radiation pattern generation currently does not work.** The pattern generation system is under development and may not produce correct results. Use with caution for production environments.


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
    - GPU libraries (optional): CUDA/OpenCL for GPU acceleration features
    - `python3` (required): For antenna pattern generation and coordinate transformations
    - `bc` (required): For high-precision trigonometric calculations

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
