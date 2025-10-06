# Granit Soviet Time-Scrambling Voice Encryption System

## Overview

The Granit is a Soviet-era secure voice system that employs unique time-domain scrambling techniques to provide secure voice communications. This implementation provides authentic simulation of the original system with all distinctive temporal distortion characteristics.

## Features

- **Time-Domain Scrambling**: Segment reordering for secure communications
- **Pilot Signal Synchronization**: Continuous synchronization signal
- **Temporal Distortion**: Authentic Soviet audio characteristics
- **Segment Processing**: Time-domain audio segmentation
- **Key Management**: Secure key handling and validation
- **Audio Effects**: Distinctive segmented, time-jumped sound
- **Real-time Processing**: Low latency audio processing for tactical use

## Technical Specifications

- **Scrambling Method**: Time-domain segment reordering
- **Segment Size**: 10-50 ms time segments
- **Synchronization**: Pilot signal at 1-2 kHz
- **Processing Delay**: 300-600 ms
- **Audio Response**: 300-3400 Hz voice band
- **Scrambling Depth**: Multiple segment reordering
- **Key Management**: Pseudo-random sequence generation
- **Distinctive Sound**: Unique temporal distortion effects
- **Recognition**: Highly recognizable when encountered
- **Usage**: Soviet military tactical communications

## Quick Start

```cpp
#include "granit.h"

// Create Granit instance
Granit granit;

// Initialize with audio parameters
granit.initialize(44100.0f, 1); // 44.1 kHz, mono

// Set scrambling key
granit.setKey(12345, "scrambling_key_data");

// Encrypt audio
std::vector<float> input_audio = loadAudioData();
std::vector<float> encrypted_audio = granit.encrypt(input_audio);
```

## Documentation

- [Complete Documentation](docs/GRANIT_DOCUMENTATION.md)
- [API Reference](include/granit.h)
- [Test Suite](tests/test_granit.cpp)

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
