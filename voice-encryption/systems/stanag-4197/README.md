# STANAG 4197 NATO QPSK OFDM Voice Encryption System

## Overview

The STANAG 4197 is a NATO standard for digital voice encryption using QPSK OFDM modulation. This implementation provides authentic simulation of the original system with all distinctive digital voice characteristics and encryption methods.

## Features

- **QPSK OFDM Modulation**: Quadrature phase shift keying with orthogonal frequency division multiplexing
- **Digital Voice Encoding**: Linear predictive coding (LPC) voice encoding
- **Preamble Generation**: 16-tone header + 39-tone data payload
- **NATO Standard**: Full compliance with STANAG 4197 specifications
- **Key Management**: Secure key handling and validation
- **Audio Effects**: Distinctive NATO digital voice characteristics
- **Real-time Processing**: Low latency audio processing for tactical use

## Technical Specifications

- **Modulation**: QPSK OFDM (Quadrature Phase Shift Keying Orthogonal Frequency Division Multiplexing)
- **Data Rate**: 2400 bps linear predictive encoded digital speech
- **Frequency Range**: HF radio facilities
- **Preamble**: Unique 16-tone data header + 39-tone data payload
- **Waveform**: Similar to MIL-STD-188-110A/B Appendix B (without 393.75 Hz pilot)
- **Encryption**: Digital voice encryption over HF
- **Interoperability**: NATO standard for digital voice communications
- **Modem**: ANDVT MINTERM KY-99A modem support
- **Terminal**: Advanced Narrowband Digital Voice Terminal (ANDVT/AN/DVT)

## Quick Start

```cpp
#include "stanag_4197.h"

// Create STANAG 4197 instance
Stanag4197 stanag;

// Initialize with audio parameters
stanag.initialize(44100.0f, 1); // 44.1 kHz, mono

// Set encryption key
stanag.setKey(12345, "encryption_key_data");

// Encrypt audio
std::vector<float> input_audio = loadAudioData();
std::vector<float> encrypted_audio = stanag.encrypt(input_audio);
```

## Documentation

- [Complete Documentation](docs/STANAG_4197_DOCUMENTATION.md)
- [API Reference](include/stanag_4197.h)
- [Test Suite](tests/test_stanag_4197.cpp)

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
