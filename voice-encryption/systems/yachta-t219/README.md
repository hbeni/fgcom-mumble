# Yachta T-219 Soviet Analog Voice Scrambler

A comprehensive implementation of the Soviet Yachta T-219 analog voice scrambler system for realistic Cold War era radio communication simulation.

## Overview

The Yachta T-219 was a Soviet analog voice scrambler used for tactical military communications during the Cold War. This implementation provides authentic simulation of the system's distinctive audio characteristics and encryption methods.

## Features

### Core Functionality
- **Authentic Soviet Audio Characteristics**: Classic "warbled" and "Donald Duck" sounds
- **FSK Synchronization**: 100 baud rate with 150 Hz frequency shift
- **Voice Scrambling**: Time segment processing with channel operations
- **M-Sequence Generation**: Based on polynomial x^52 + x^49 + 1
- **Key Card System**: Hexadecimal key card data parsing and processing
- **Real-time Audio Processing**: Optimized for real-time performance

### Technical Specifications
- **Frequency Range**: 3 MHz to 30 MHz (HF band)
- **Modulation**: Upper Sideband (USB)
- **Bandwidth**: 2.7 kHz
- **Audio Response**: 300 to 2700 Hz
- **FSK Sync Signal**: 100 baud, 150 Hz shift
- **Scrambling Method**: Voice divided into unequal time segments
- **Key Card System**: Uses coding key cards for encryption

## Directory Structure

```
yachta-t219/
├── CMakeLists.txt                    # Build configuration
├── README.md                         # This file
├── include/
│   └── yachta_t219.h                # Header file
├── src/
│   └── yachta_t219.cpp              # Implementation
├── tests/
│   ├── CMakeLists.txt               # Test build configuration
│   └── test_yachta_t219.cpp         # Test suite
└── docs/
    └── YACHTA_T219_DOCUMENTATION.md # Detailed documentation
```

## Building

### Prerequisites

- CMake 3.10+
- C++17 compatible compiler
- Google Test and Google Mock
- pthread library

### Build Instructions

```bash
# Create build directory
mkdir build && cd build

# Configure
cmake ..

# Build
make

# Run tests
make test
```

### Build Options

- `CMAKE_BUILD_TYPE`: Debug, Release, RelWithDebInfo, MinSizeRel
- `CMAKE_CXX_FLAGS`: Additional compiler flags
- `CMAKE_INSTALL_PREFIX`: Installation directory

## Usage

### Basic Usage

```cpp
#include "yachta_t219.h"

// Create Yachta T-219 instance
YachtaT219 yachta;

// Initialize with audio parameters
yachta.initialize(44100.0f, 1); // 44.1 kHz, mono

// Set encryption key
yachta.setKey(12345, "encryption_key_data");

// Encrypt audio
std::vector<float> input_audio = loadAudioData();
std::vector<float> encrypted_audio = yachta.encrypt(input_audio);

// Decrypt audio
std::vector<float> decrypted_audio = yachta.decrypt(encrypted_audio);
```

### Advanced Configuration

```cpp
// Configure FSK parameters
yachta.setFSKParameters(100, 150.0f); // 100 baud, 150 Hz shift

// Configure scrambling parameters
std::vector<uint32_t> segments = {25, 75, 50, 100, 30, 60, 40, 80}; // ms
yachta.setScramblingParameters(segments, 0.8f); // 80% scrambling factor

// Configure audio response
yachta.setAudioResponse(300.0f, 2700.0f); // 300-2700 Hz
yachta.setBandwidth(2700.0f); // 2.7 kHz bandwidth

// Load key card
std::string key_card = "01 23 45 67 89 AB CD EF 12 34 56 78";
yachta.loadKeyCard(key_card);
```

### Utility Functions

```cpp
// Generate M-sequence
auto sequence = YachtaUtils::generateMSequence(0x2000000000001ULL, 52);

// Generate FSK signal
std::vector<bool> data = {true, false, true, false, true};
auto fsk_signal = YachtaUtils::generateFSKSignal(data, 44100.0f, 100, 150.0f);

// Apply audio scrambling
std::vector<uint32_t> segments = {25, 75, 50, 100};
YachtaUtils::applyAudioScrambling(audio, segments, 0.8f);

// Generate Soviet characteristics
YachtaUtils::generateWarbledEffect(audio, 0.5f);
YachtaUtils::generateDonaldDuckSound(audio, 0.3f);

// Parse key card data
std::string key_card = "01 23 45 67 89 AB CD EF";
auto key_bytes = YachtaUtils::parseKeyCardData(key_card);
```

## Testing

### Running Tests

```bash
# Build tests
cd tests
mkdir build && cd build
cmake ..
make

# Run tests
./yachta_t219_tests

# Run with verbose output
./yachta_t219_tests --gtest_verbose
```

### Test Coverage

- Initialization and configuration tests
- Encryption/decryption functionality
- Audio characteristics validation
- M-sequence generation
- FSK signal processing
- Voice scrambling
- Utility functions
- Performance testing
- Edge case handling

## API Reference

### Core Classes

- `YachtaT219`: Main encryption class
- `YachtaUtils`: Utility functions namespace

### Key Methods

- `initialize()`: Initialize the system
- `setKey()`: Set encryption key
- `loadKeyCard()`: Load key card data
- `encrypt()`: Encrypt audio data
- `decrypt()`: Decrypt audio data
- `setFSKParameters()`: Configure FSK parameters
- `setScramblingParameters()`: Configure scrambling
- `setAudioResponse()`: Configure audio response

## Configuration

### Audio Parameters

- `sample_rate`: Audio sample rate (Hz)
- `channels`: Number of audio channels
- `bandwidth`: Audio bandwidth (Hz)
- `audio_response_min`: Minimum audio frequency (Hz)
- `audio_response_max`: Maximum audio frequency (Hz)

### FSK Parameters

- `baud_rate`: FSK baud rate
- `shift_frequency`: FSK frequency shift (Hz)
- `center_frequency`: FSK center frequency (Hz)

### Scrambling Parameters

- `time_segments`: Time segment durations (ms)
- `scrambling_factor`: Scrambling intensity (0.0-1.0)
- `channel_swap_pattern`: Channel swapping pattern
- `channel_inversion_pattern`: Channel inversion pattern

## Performance

### Requirements

- **CPU**: Moderate (real-time capable)
- **Memory**: ~1-2 MB per instance
- **Latency**: <50ms typical
- **Throughput**: Real-time at 44.1 kHz

### Optimization

- Efficient FFT processing
- Vectorized operations
- Buffer management
- Coefficient caching

## Security

### Key Management

- Secure key storage
- Key rotation support
- Key validation
- Cryptographic quality

### Features

- M-sequence generation
- Secure scrambling
- Key-dependent parameters
- Synchronization security

## Troubleshooting

### Common Issues

1. **Build Issues**
   - Check CMake version
   - Verify dependencies
   - Check compiler flags

2. **Runtime Issues**
   - Verify audio parameters
   - Check key data format
   - Monitor memory usage

3. **Debugging**
   - Enable debug output
   - Run self-tests
   - Check status information

### Debug Commands

```cpp
// Enable debugging
yachta.runSelfTest();
yachta.calibrateFSK();
yachta.alignAudioResponse();

// Check status
std::string status = yachta.getEncryptionStatus();
```

## Historical Context

### Soviet Military Communications
The Yachta T-219 was used by Soviet military forces for tactical communications during the Cold War. It provided secure voice communication over HF radio links with distinctive audio characteristics.

### Technical Significance
- **Analog Scrambling**: One of the most sophisticated analog voice scrambling systems
- **FSK Synchronization**: Advanced synchronization using M-sequence generation
- **Key Card System**: Secure key management using physical key cards
- **Audio Characteristics**: Distinctive "warbled" and "Donald Duck" sounds

### Current Status
The system is still in use as recently as 2025, being gradually replaced by more modern digital encryption systems.

## References

### Technical Documentation
- **ITU-R Recommendations**: Radio communication standards
- **Military Standards**: Soviet encryption specifications
- **Cryptographic Standards**: M-sequence and FSK specifications
- **Audio Processing**: Digital signal processing techniques

### Historical References
- **Cold War Communications**: Soviet radio systems
- **Military Radio History**: Tactical communication evolution
- **Encryption History**: Voice scrambling development
- **Radio Technology**: HF/VHF/UHF communication systems

## Contributing

### Development Setup

1. Clone the repository
2. Install dependencies
3. Build the system
4. Run tests
5. Make changes
6. Test thoroughly
7. Submit pull request

### Code Standards

- C++17 standard
- Google C++ style guide
- Comprehensive testing
- Documentation requirements

## License

This system is part of the FGcom-mumble project and follows the same licensing terms.

## Support

For issues and questions:

1. Check the documentation
2. Review test cases
3. Check troubleshooting guide
4. Submit issue report
