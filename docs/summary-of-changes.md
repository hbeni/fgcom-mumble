# Summary of Changes - Local Repository vs Original

This document summarizes all changes made to the codebase compared to the original repository at https://github.com/hbeni/fgcom-mumble/tree/master.

## Overview

- **Total Modified Files**: 29
- **Total Deleted Files**: 9
- **Total Structural Changes**: Multiple reorganizations

## Deleted Files (9)

### Root Level
1. `README-de_DE.md` - German README removed from root
2. `Readme.architecture.md` - Architecture documentation removed from root
3. `SECURITY.md` - Security policy removed from root

### Client Plugin Library
4. `client/mumble-plugin/lib/debug.cpp` - Debug implementation removed
5. `client/mumble-plugin/lib/radio_model_hf.cpp` - HF radio model removed
6. `client/mumble-plugin/lib/radio_model_string.cpp` - String radio model removed

### Test Infrastructure
7. `client/mumble-plugin/test/25_833-test.sh` - Test script removed
8. `client/mumble-plugin/test/genAllFrq.sh` - Frequency generation script removed
9. `client/mumble-plugin/test/test_setup.sh` - Test setup script removed

## Modified Files (29)

### Root Level Files
- `.gitignore` - Updated ignore patterns
- `Makefile` - Build system changes (+115 lines)
- `README.md` - Major documentation updates (+600 lines)

### GitHub Workflows
- `.github/ISSUE_TEMPLATE/bug_report.md` - Bug report template updated
- `.github/workflows/codeql-analysis.yml` - CodeQL workflow updated (actions v3, checkout v4, setup-java v4)

### Client Plugin Core
- `client/mumble-plugin/Makefile` - Build configuration updated
- `client/mumble-plugin/fgcom-mumble.cpp` - Main plugin code modified (+353 lines)
- `client/mumble-plugin/fgcom-mumble.h` - Header file updated (+28 lines)

### Client Plugin Library
- `client/mumble-plugin/lib/audio.cpp` - Audio processing modified
- `client/mumble-plugin/lib/audio.h` - Audio header updated
- `client/mumble-plugin/lib/DspFilters/RootFinder.h` - Filter root finder updated (+263 lines)
- `client/mumble-plugin/lib/garbage_collector.cpp` - Garbage collection modified
- `client/mumble-plugin/lib/globalVars.h` - Global variables updated
- `client/mumble-plugin/lib/http/httplib.h` - HTTP library updated
- `client/mumble-plugin/lib/io_UDPServer.cpp` - UDP server modified
- `client/mumble-plugin/lib/io_plugin.cpp` - Plugin I/O modified
- `client/mumble-plugin/lib/io_plugin.h` - Plugin I/O header updated
- `client/mumble-plugin/lib/radio_model.cpp` - Radio model base modified
- `client/mumble-plugin/lib/radio_model.h` - Radio model header updated
- `client/mumble-plugin/lib/radio_model_uhf.cpp` - UHF model modified
- `client/mumble-plugin/lib/radio_model_vhf.cpp` - VHF model modified

### Client Documentation
- `client/plugin.spec.md` - Plugin specification updated

### RadioGUI
- `client/radioGUI/lib/jsimconnect` - jsimconnect submodule updated
- `client/radioGUI/pom.xml` - Maven configuration updated
- `client/radioGUI/src/main/java/hbeni/fgcom_mumble/radioGUI.java` - Main GUI code modified

### Server
- `server/fgcom-botmanager.sh` - Bot manager script modified
- `server/fgcom-radio-playback.bot.lua` - Playback bot modified
- `server/fgcom-radio-recorder.bot.lua` - Recorder bot modified
- `server/statuspage/fgcom-status.bot.lua` - Status page bot modified

## Structural Changes

### 1. Configuration Files Reorganization

**Moved to `configs/` directory:**
- `client/mumble-plugin/fgcom-mumble.ini` → `configs/fgcom-mumble.ini` (95% similarity)
- `server/statuspage/config.dist.ini` → `configs/server_statuspage_config.dist.ini` (100% similarity)

**Result:** All configuration files centralized in `configs/` directory for better organization.

### 2. Test Modules Reorganization

**Major Move:**
- `test-modules/` → `client/mumble-plugin/test/test-modules/`

**Examples of moved test modules:**
- `test-modules/agc_squelch_tests/` → `client/mumble-plugin/test/test-modules/agc_squelch_tests/`
- `test-modules/antenna_pattern_module_tests/` → `client/mumble-plugin/test/test-modules/antenna_pattern_module_tests/`
- All client-related test modules moved under the client plugin structure

**Server-Specific Tests Moved:**
- `test-modules/atis_module_tests/run_atis_module_tests.sh` → `server/test/atis_module_tests/run_atis_module_tests.sh`
- `test-modules/status_page_module_tests/run_status_page_module_tests.sh` → `server/test/status_page_module_tests/run_status_page_module_tests.sh`

**Result:** Tests organized by component (client vs server) for better maintainability.

### 3. Server Scripts Reorganization

**Moved from `scripts/server/` to `server/`:**
- `scripts/server/fgcom-botmanager.sh` → `server/fgcom-botmanager.sh`
- `scripts/server/fgcom-botmanager-system.sh` → `server/fgcom-botmanager-system.sh`
- `scripts/server/loadTest.sh` → `server/test/loadTest.sh`

**New Server Test Structure:**
- Created `server/test/` directory
- Added `server/test/run_all_server_tests.sh` for unified server test execution

**Result:** Server scripts consolidated under `server/` directory, aligning with component-based architecture.

### 4. Fuzzing Infrastructure Move

**Moved:**
- `test/build-fuzz/` → `fuzzing-tests/`

**Result:** Fuzzing infrastructure separated from regular test infrastructure for clarity.

### 5. Component-Based Organization

**Principle:** Clear separation between client and server components

**Client Structure:**
- `client/mumble-plugin/test/test-modules/` - All client tests
- `client/mumble-plugin/` - Plugin code

**Server Structure:**
- `server/test/` - Server-specific tests
- `server/` - Server scripts and bots

## New Directory Structure

The following directories were added to the root (not present in original repository):

- `assets/` - Screenshots and visual assets
- `config/` - Configuration documentation
- `configs/` - Configuration files (centralized)
- `docs/` - Comprehensive documentation
- `fuzzing-tests/` - Fuzzing infrastructure
- `releases/` - Release packages
- `scripts/` - Utility scripts
- `tle_data/` - Satellite TLE data
- `voice-encryption/` - Voice encryption systems
- `webrtc-gateway/` - WebRTC gateway implementation

## Key Improvements

### 1. Configuration Centralization
All configuration files moved to `configs/` directory for easier management and discovery.

### 2. Test Reorganization
Tests organized by component (client/server) with clear separation:
- Client tests: `client/mumble-plugin/test/test-modules/`
- Server tests: `server/test/`

### 3. Server Consolidation
All server-related scripts and tests moved to `server/` directory for better organization.

### 4. Fuzzing Separation
Fuzzing infrastructure moved to dedicated `fuzzing-tests/` directory, separate from regular tests.

### 5. Documentation Cleanup
Root-level documentation files removed (moved to appropriate locations or deleted if redundant).

### 6. Component Separation
Clear boundaries between client and server components, making the codebase more maintainable.

## Build System Changes

### Makefile Updates
- Added 115+ lines of new build targets
- Enhanced cross-platform support
- Improved build configuration options

### GitHub Actions Updates
- Updated CodeQL actions to v3
- Updated checkout action to v4 with recursive submodules
- Updated Java setup to v4 with temurin distribution
- Added libcurl-dev dependency for C++ builds

## Code Changes Summary

### Major Code Modifications
- **fgcom-mumble.cpp**: +353 lines (core plugin functionality)
- **README.md**: +600 lines (comprehensive documentation)
- **Makefile**: +115 lines (build system enhancements)
- **RootFinder.h**: +263 lines (filter improvements)

### Radio Model Changes
- HF radio model removed
- String radio model removed
- UHF and VHF models updated
- Radio model base classes refactored

### Audio Processing
- Audio processing functions updated
- Audio header files modified
- Improved audio handling

## Testing Infrastructure Changes

### Removed Test Scripts
- `25_833-test.sh` - Removed
- `genAllFrq.sh` - Removed
- `test_setup.sh` - Removed

### Test Module Reorganization
- All test modules moved to component-specific locations
- Server tests moved to `server/test/`
- Client tests moved to `client/mumble-plugin/test/test-modules/`

## Documentation Changes

### Removed Documentation
- `README-de_DE.md` - Removed from root
- `Readme.architecture.md` - Removed from root
- `SECURITY.md` - Removed from root

### Enhanced Documentation
- `README.md` - Significantly expanded with comprehensive information
- New `docs/` directory with extensive documentation
- Added `docs/propagation-maths.md` - Complete formula reference
- Added `docs/TESTING_GUIDE.md` - Testing documentation
- Added `docs/TEST_COVERAGE_DOCUMENTATION.md` - Test coverage analysis

## Current Codebase Structure

### Root Level Structure

```
fgcom-mumble/
├── assets/                    # Screenshots and visual assets
├── client/                    # Client-side components
├── config/                    # Configuration documentation
├── configs/                   # Configuration files (centralized)
├── docs/                      # Comprehensive documentation
├── fuzzing-tests/             # Fuzzing infrastructure
├── releases/                  # Release packages
├── scripts/                   # Utility scripts
├── server/                    # Server-side components
├── test-modules/              # Legacy test location (being phased out)
├── tle_data/                  # Satellite TLE data
├── voice-encryption/          # Voice encryption systems
├── webrtc-gateway/            # WebRTC gateway implementation
├── .gitignore                 # Git ignore patterns
├── .gitmodules                # Git submodules configuration
├── LICENSE                    # GPL-3.0 license
├── Makefile                   # Build system
└── README.md                  # Main documentation
```

### Client Structure

```
client/
├── fgfs-addon/                # FlightGear addon
│   ├── FGData/                # FlightGear data
│   └── gui/                   # GUI components
├── mumble-plugin/             # Mumble plugin (main client)
│   ├── lib/                   # Plugin libraries
│   │   ├── DspFilters/        # Digital signal processing filters
│   │   ├── antenna_patterns/  # Antenna pattern data
│   │   ├── architecture/      # Architecture documentation
│   │   ├── http/             # HTTP client library
│   │   ├── json/             # JSON parsing library
│   │   ├── mumble/           # Mumble integration
│   │   ├── noise/            # Noise generation
│   │   └── openssl/          # OpenSSL submodule
│   └── test/                 # Test infrastructure
│       └── test-modules/     # Client test modules (25+ modules)
│           ├── agc_squelch_tests/
│           ├── antenna_pattern_module_tests/
│           ├── audio_processing_tests/
│           ├── client_plugin_module_tests/
│           ├── database_configuration_module_tests/
│           ├── frequency_management_tests/
│           ├── geographic_module_tests/
│           ├── integration_tests/
│           ├── network_module_tests/
│           ├── performance_tests/
│           ├── radio_propagation_tests/
│           ├── rapidcheck_tests/
│           ├── satellite_communication_tests/
│           ├── security_module_tests/
│           ├── tts_integration_tests/
│           ├── voice_encryption_tests/
│           ├── webrtc_api_tests/
│           └── work_unit_distribution_module_tests/
├── plugin.spec.md            # Plugin specification
└── radioGUI/                 # Radio GUI (Java application)
    ├── lib/                  # Java libraries
    │   ├── jmapviewer-2.9/   # Map viewer library
    │   └── jsimconnect/      # SimConnect library (submodule)
    └── src/                  # Java source code
```

### Server Structure

```
server/
├── api/                      # API implementations
├── recordings/               # ATIS recordings storage
├── statuspage/               # Status page web interface
│   └── inc/                  # Status page includes
├── test/                     # Server test modules
│   ├── atis_module_tests/    # ATIS module tests
│   └── status_page_module_tests/  # Status page tests
├── fgcom-botmanager.sh       # Bot manager script
├── fgcom-botmanager-system.sh # System bot manager
├── fgcom-radio-playback.bot.lua  # Playback bot
├── fgcom-radio-recorder.bot.lua  # Recorder bot
└── fgcom-sharedFunctions.inc.lua # Shared Lua functions
```

### Documentation Structure

```
docs/
├── development/              # Development documentation
├── roadmap/                  # Project roadmap
├── technical/                # Technical documentation
├── AFL_MULL_FUZZING_GUIDE.md
├── API_REFERENCE_COMPLETE.md
├── COMPILATION_GUIDE.md
├── INSTALLATION.md
├── propagation-maths.md      # Complete propagation formulas
├── TESTING_GUIDE.md
├── TEST_COVERAGE_DOCUMENTATION.md
└── summary-of-changes.md    # This document
```

### Scripts Structure

```
scripts/
├── analysis/                 # Code analysis scripts
├── api_examples/             # API usage examples
├── api_testing/              # API testing scripts
├── debug/                    # Debugging scripts
├── fixes/                    # Automated fix scripts
├── pattern_generation/       # Antenna pattern generation
│   └── stl-to-nec/          # STL to NEC converter
├── satellites/               # Satellite-related scripts
├── testing/                  # Testing utilities
├── tts/                      # Text-to-speech scripts
│   └── atis_templates/      # ATIS templates
├── utilities/                # General utilities
└── validation/               # Validation scripts
```

### Voice Encryption Structure

```
voice-encryption/
├── docs/                     # Encryption documentation
├── include/                  # Header files
├── src/                      # Source files
└── systems/                  # Encryption systems
    ├── freedv/              # FreeDV system
    ├── granit/              # Granit system
    ├── melpe/               # MELPe system
    ├── satellites/          # Satellite communication
    ├── stanag-4197/         # STANAG 4197
    ├── vinson-ky57/         # VINSON KY-57
    └── yachta-t219/         # Yachta T-219
```

### Fuzzing Tests Structure

```
fuzzing-tests/
├── harnesses/                # Fuzzing harnesses
│   ├── fuzz_audio_processing.cpp
│   ├── fuzz_data_parsing.cpp
│   ├── fuzz_file_io.cpp
│   ├── fuzz_mathematical_calculations.cpp
│   ├── fuzz_network_protocol.cpp
│   ├── fuzz_radio_propagation.cpp
│   └── fuzz_security_functions.cpp
└── scripts/                  # Fuzzing scripts
    ├── compile_fuzzers.sh
    ├── generate_corpus.py
    └── run_individual_fuzzer.sh
```

### Configuration Structure

```
configs/
├── band_plan_custom.json
├── debugging.conf
├── env.template              # Environment variables template
├── feature_toggles.conf
├── fgcom-mumble.conf.example
├── fgcom-mumble.conf.minimal
├── fgcom-mumble.ini          # Main configuration (moved from client/)
├── frequency_offset.conf
├── gpu_acceleration.conf
├── power_management.conf
├── radio_amateur_band_segments.csv
├── satellite_config.conf
├── server_statuspage_config.dist.ini  # Status page config (moved from server/)
├── statuspage_config.dist.ini
├── threading_config.conf
└── README.md
```

### Test Organization

**Client Tests** (25+ test modules):
- Located in: `client/mumble-plugin/test/test-modules/`
- Covers: Audio processing, radio propagation, antenna patterns, security, encryption, etc.

**Server Tests**:
- Located in: `server/test/`
- Includes: ATIS module tests, status page tests

**Fuzzing Tests**:
- Located in: `fuzzing-tests/harnesses/`
- Separate from regular tests for clarity

### Key Structural Principles

1. **Component Separation**: Clear boundaries between client and server
2. **Configuration Centralization**: All configs in `configs/`
3. **Test Organization**: Tests organized by component
4. **Documentation Centralization**: All docs in `docs/`
5. **Script Organization**: Scripts categorized by purpose in `scripts/`
6. **Modular Design**: Each major feature in its own directory

## Conclusion

The codebase has undergone significant structural reorganization to improve maintainability, clarity, and component separation. The changes follow a component-based architecture with clear boundaries between client and server components. Configuration files have been centralized, tests have been organized by component, and the overall structure has been improved for better developer experience.

All changes maintain backward compatibility where possible, and the reorganization makes the codebase easier to navigate and maintain.

