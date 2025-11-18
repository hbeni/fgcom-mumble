# Voice Encryption Module

## Overview

The Voice Encryption Module provides a comprehensive suite of Cold War era voice encryption systems for authentic radio simulation. This module includes four distinct encryption systems representing both Soviet/East Bloc and NATO technologies.

## Available Systems

### 1. Yachta T-219 (Soviet/East Bloc)
- **Type**: Frequency-domain voice scrambling
- **Characteristics**: Warbled, "Donald Duck" sound
- **Technology**: FSK sync signal, M-sequence generation, key card system
- **Usage**: Soviet military tactical communications

### 2. VINSON KY-57 (NATO)
- **Type**: Digital CVSD secure voice system
- **Characteristics**: Robotic, buzzy digital voice
- **Technology**: CVSD vocoder, FSK modulation, Type 1 encryption
- **Usage**: NATO tactical radios, field communications

### 3. Granit (Soviet/East Bloc)
- **Type**: Time-domain scrambling system
- **Characteristics**: Segmented, time-jumped sound
- **Technology**: Time segment reordering, pilot signal synchronization
- **Usage**: Soviet military tactical communications

### 4. STANAG 4197 (NATO)
- **Type**: QPSK OFDM digital voice system
- **Characteristics**: Digital voice with OFDM modulation
- **Technology**: QPSK OFDM, LPC voice encoding, preamble sequences
- **Usage**: NATO HF digital voice communications

## Quick Start

```cpp
#include "voice_encryption.h"

// Create voice encryption manager
VoiceEncryptionManager manager;

// Initialize with audio parameters
manager.initialize(44100.0f, 1); // 44.1 kHz, mono

// Set encryption system
manager.setEncryptionSystem(EncryptionSystem::YACHTA_T219);

// Set encryption key
manager.setKey(12345, "encryption_key_data");

// Encrypt audio
std::vector<float> input_audio = loadAudioData();
std::vector<float> encrypted_audio = manager.encrypt(input_audio);
```

## Documentation

- [Complete Module Documentation](docs/VOICE_ENCRYPTION_MODULE.md)
- [API Reference](include/voice_encryption.h)
- [Yachta T-219 Documentation](systems/yachta-t219/docs/YACHTA_T219_DOCUMENTATION.md)
- [VINSON KY-57 Documentation](systems/vinson-ky57/docs/VINSON_KY57_DOCUMENTATION.md)
- [Granit Documentation](systems/granit/docs/GRANIT_DOCUMENTATION.md)
- [STANAG 4197 Documentation](systems/stanag-4197/docs/STANAG_4197_DOCUMENTATION.md)

## Building

```bash
mkdir build
cd build
cmake ..
make
```

## Testing

```bash
# Run voice encryption tests
cd test/voice_encryption_tests
mkdir build
cd build
cmake ..
make
./voice_encryption_tests
```

## Features

- **Unified API**: Single interface for all encryption systems
- **Real-time Processing**: Low latency audio processing
- **Authentic Effects**: Accurate audio characteristics
- **Key Management**: Secure key handling and validation
- **System Switching**: Dynamic system changes
- **Comprehensive Testing**: Full test coverage
- **Self-Documentation**: Extensive inline documentation

## Audio Characteristics

### Yachta T-219
- Warbled, "Donald Duck" sound
- FSK sync signal at 100 baud, 150 Hz shift
- Frequency range: 3-30 MHz (HF band)
- Upper Sideband (USB) modulation

### VINSON KY-57
- Robotic, buzzy digital voice
- CVSD vocoder at 16 kbps
- FSK modulation
- Type 1 encryption

### Granit
- Segmented, time-jumped audio
- Time-domain segment reordering
- Pilot signal synchronization
- Temporal distortion effects

### STANAG 4197
- Digital voice with OFDM characteristics
- QPSK OFDM modulation
- 2400 bps LPC encoded speech
- Preamble-based synchronization

## System Requirements

- **C++17**: Required for modern C++ features
- **CMake 3.10+**: Build system
- **GTest/GMock**: Testing framework
- **Audio Processing**: Real-time audio capabilities

## License

This implementation is part of the FGcom-mumble project and is licensed under the same terms as the main project.

## Support

For technical support and questions, please refer to the main FGcom-mumble project documentation and support channels.