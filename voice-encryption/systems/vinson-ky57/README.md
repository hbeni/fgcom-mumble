# VINSON KY-57/KY-58 NATO Secure Voice System

## Overview

The VINSON KY-57/KY-58 is a NATO standard secure voice system that provides Type 1 encryption for tactical military communications. This implementation provides authentic simulation of the original system with all distinctive audio characteristics.

## Features

- **CVSD Vocoder**: 16 kbps voice compression with robotic sound quality
- **FSK Modulation**: 1200 baud data transmission with buzzy characteristics
- **Type 1 Encryption**: NSA approved encryption for classified communications
- **Key Management**: Electronic key loading and validation
- **Audio Effects**: Authentic NATO robotic and buzzy sound characteristics
- **Real-time Processing**: Low latency audio processing for tactical use

## Technical Specifications

- **Digital Vocoder**: CVSD (Continuously Variable Slope Delta) at 16 kbps
- **Modulation**: FSK (Frequency Shift Keying)
- **Frequency Range**: VHF/UHF tactical bands
- **Security**: Type 1 encryption (NSA approved)
- **Key Management**: Electronic key loading system
- **Audio Quality**: Characteristic robotic, buzzy sound due to CVSD compression
- **Usage**: Tactical radios, field communications
- **Interoperability**: NATO standard for secure voice communications

## Quick Start

```cpp
#include "vinson_ky57.h"

// Create VINSON KY-57 instance
VinsonKY57 vinson;

// Initialize with audio parameters
vinson.initialize(44100.0f, 1); // 44.1 kHz, mono

// Set encryption key
vinson.setKey(12345, "encryption_key_data");

// Encrypt audio
std::vector<float> input_audio = loadAudioData();
std::vector<float> encrypted_audio = vinson.encrypt(input_audio);
```

## Documentation

- [Complete Documentation](docs/VINSON_KY57_DOCUMENTATION.md)
- [API Reference](include/vinson_ky57.h)
- [Test Suite](tests/test_vinson_ky57.cpp)

## Building

```bash
mkdir build
cd build
cmake ..
make
```

## Testing

```bash
make test
```

## License

This implementation is part of the FGcom-mumble project and is licensed under the same terms as the main project.

## Support

For technical support and questions, please refer to the main FGcom-mumble project documentation and support channels.
