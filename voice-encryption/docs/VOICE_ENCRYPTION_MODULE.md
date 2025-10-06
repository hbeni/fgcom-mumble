# Voice Encryption Module Documentation

## Overview

The Voice Encryption Module provides a comprehensive suite of Cold War era voice encryption systems for authentic radio simulation. This module includes four distinct encryption systems representing both Soviet/East Bloc and NATO technologies.

## Available Systems

### 1. Yachta T-219 (Soviet/East Bloc)
- **Type**: Frequency-domain voice scrambling
- **Characteristics**: Warbled, "Donald Duck" sound
- **Technology**: FSK sync signal, M-sequence generation, key card system
- **Usage**: Soviet military tactical communications
- **Audio Effects**: Distinctive warbled sound with FSK synchronization

### 2. VINSON KY-57 (NATO)
- **Type**: Digital CVSD secure voice system
- **Characteristics**: Robotic, buzzy digital voice
- **Technology**: CVSD vocoder, FSK modulation, Type 1 encryption
- **Usage**: NATO tactical radios, field communications
- **Audio Effects**: Digital voice with robotic/buzzy characteristics

### 3. Granit (Soviet/East Bloc)
- **Type**: Time-domain scrambling system
- **Characteristics**: Segmented, time-jumped sound
- **Technology**: Time segment reordering, pilot signal synchronization
- **Usage**: Soviet military tactical communications
- **Audio Effects**: Temporal distortion with segmented audio

### 4. STANAG 4197 (NATO)
- **Type**: QPSK OFDM digital voice system
- **Characteristics**: Digital voice with OFDM modulation
- **Technology**: QPSK OFDM, LPC voice encoding, preamble sequences
- **Usage**: NATO HF digital voice communications
- **Audio Effects**: Digital voice with QPSK OFDM characteristics

## API Usage

### Basic Usage

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

### System-Specific Configuration

```cpp
// Configure Yachta T-219
manager.setYachtaT219Parameters(882, 8, 0.8f); // 20ms segments, 8 depth, 80% intensity

// Configure VINSON KY-57
manager.setVinsonKY57Parameters(16000.0f, 0.8f); // 16 kbps CVSD, 80% quality

// Configure Granit
manager.setGranitParameters(882, 8, 1500.0f); // 20ms segments, 8 depth, 1.5kHz pilot

// Configure STANAG 4197
manager.setStanag4197Parameters(2400, 39, 16); // 2400 bps, 39 tones, 16 header tones
```

### Key Management

```cpp
// Set encryption key
manager.setKey(12345, "01 23 45 67 89 AB CD EF");

// Load key from file
manager.loadKeyFromFile("key.bin");

// Save key to file
manager.saveKeyToFile("key.bin");

// Validate key
bool valid = manager.validateKey("01 23 45 67 89 AB CD EF");
```

### System Information

```cpp
// Get available systems
std::vector<EncryptionSystem> systems = manager.getAvailableSystems();

// Get system information
std::string info = manager.getSystemInfo(EncryptionSystem::YACHTA_T219);

// Get system status
std::string status = manager.getStatus();

// Get key information
std::string key_info = manager.getKeyInfo();
```

## Audio Characteristics

### Yachta T-219
- **Sound**: Warbled, "Donald Duck" quality
- **Sync Signal**: FSK at 100 baud, 150 Hz shift
- **Frequency Range**: 3-30 MHz (HF band)
- **Modulation**: Upper Sideband (USB)
- **Bandwidth**: 2.7 kHz
- **Audio Response**: 300-2700 Hz

### VINSON KY-57
- **Sound**: Robotic, buzzy digital voice
- **Vocoder**: CVSD at 16 kbps
- **Modulation**: FSK
- **Frequency Range**: VHF/UHF tactical bands
- **Security**: Type 1 encryption
- **Key Management**: Electronic key loading

### Granit
- **Sound**: Segmented, time-jumped audio
- **Scrambling**: Time-domain segment reordering
- **Synchronization**: Pilot signal at 1-2 kHz
- **Processing Delay**: 300-600 ms
- **Audio Response**: 300-3400 Hz
- **Characteristics**: Temporal distortion effects

### STANAG 4197
- **Sound**: Digital voice with OFDM characteristics
- **Modulation**: QPSK OFDM
- **Data Rate**: 2400 bps LPC encoded speech
- **Frequency Range**: HF radio facilities
- **Preamble**: 16-tone header + 39-tone data payload
- **Characteristics**: NATO digital voice quality

## Technical Specifications

### Common Parameters
- **Sample Rate**: 44.1 kHz (standard), 48 kHz (professional)
- **Channels**: 1 (mono), 2 (stereo)
- **Bit Depth**: 32-bit float
- **Processing**: Real-time capable
- **Latency**: < 100 ms (typical)

### System-Specific Parameters

#### Yachta T-219
- **Segment Size**: 10-50 ms (configurable)
- **Scrambling Depth**: 4-16 segments
- **FSK Rate**: 100 baud
- **FSK Shift**: 150 Hz
- **Key Length**: 64 bits

#### VINSON KY-57
- **CVSD Rate**: 16 kbps
- **FSK Frequencies**: 1200/1800 Hz
- **Encryption**: Type 1 (AES-256)
- **Key Length**: 128 bits
- **Quality**: 0.0-1.0 (configurable)

#### Granit
- **Segment Size**: 10-50 ms (configurable)
- **Scrambling Depth**: 4-16 segments
- **Pilot Frequency**: 1-2 kHz
- **Processing Delay**: 300-600 ms
- **Key Length**: 64 bits

#### STANAG 4197
- **Data Rate**: 2400 bps
- **OFDM Tones**: 39 (data payload)
- **Header Tones**: 16 (data header)
- **FFT Size**: 64 points
- **Key Length**: 128 bits

## Performance Characteristics

### Processing Speed
- **Real-time**: All systems support real-time processing
- **Latency**: < 100 ms (typical)
- **Throughput**: Audio sample rate
- **CPU Usage**: < 10% (typical)

### Memory Usage
- **Buffers**: Configurable buffer sizes
- **State**: Minimal state storage
- **FFT**: Optional FFT processing
- **Memory**: < 100 MB (typical)

### Audio Quality
- **Fidelity**: High-quality audio processing
- **Effects**: Authentic system characteristics
- **Filtering**: Clean frequency response
- **Noise**: Minimal processing noise

## Error Handling

### Initialization Errors
- **Invalid Parameters**: Sample rate, channels
- **Resource Allocation**: Memory, buffers
- **System State**: Already initialized
- **Recovery**: Automatic cleanup

### Encryption Errors
- **Key Management**: Invalid keys, missing keys
- **System State**: Not initialized
- **Processing**: Audio processing failures
- **Recovery**: Error reporting, state reset

### Audio Processing Errors
- **Input Validation**: Empty buffers, invalid samples
- **Processing**: System-specific failures
- **Effects**: Audio effect failures
- **Recovery**: Graceful degradation

## Testing

### Unit Tests
- **Initialization**: System setup and configuration
- **Encryption**: Audio encryption and decryption
- **Key Management**: Key loading and validation
- **Effects**: Audio effect processing
- **Status**: System status reporting

### Integration Tests
- **Audio Pipeline**: Complete processing chain
- **System Switching**: Dynamic system changes
- **Key Management**: Cross-system key handling
- **Performance**: Speed and memory usage

### Performance Tests
- **Real-time Processing**: Latency and throughput
- **Memory Usage**: Buffer sizes and allocation
- **CPU Usage**: Processing efficiency
- **Audio Quality**: Signal quality metrics

## Security Considerations

### Key Management
- **Storage**: Secure key storage
- **Transmission**: Secure key exchange
- **Validation**: Key integrity checking
- **Rotation**: Key rotation support

### System Security
- **Initialization**: Secure system setup
- **State**: Secure state management
- **Processing**: Secure audio processing
- **Cleanup**: Secure resource cleanup

### Encryption Security
- **Algorithms**: Industry-standard encryption
- **Key Length**: Appropriate key lengths
- **Randomness**: Cryptographically secure random generation
- **Validation**: Key validation and verification

## Troubleshooting

### Common Issues
- **Initialization**: Check parameters and system state
- **Key Loading**: Validate key format and length
- **Audio Processing**: Check buffer sizes and sample rates
- **Effects**: Verify effect parameters and intensity

### Debug Information
- **Status**: System status reporting
- **Key Info**: Key information and validation
- **Performance**: Processing speed and memory usage
- **Errors**: Error reporting and diagnostics

### Performance Optimization
- **Buffer Sizes**: Optimize for real-time processing
- **System Selection**: Choose appropriate system for use case
- **Key Management**: Optimize key operations
- **Memory Usage**: Minimize memory allocation

## Future Enhancements

### Planned Features
- **Additional Systems**: More encryption systems
- **Key Management**: Enhanced key management
- **Audio Effects**: More audio effects
- **Performance**: Performance optimizations

### Compatibility
- **Standards**: Industry standard compliance
- **Interoperability**: Cross-platform compatibility
- **Integration**: FGcom-mumble integration
- **Testing**: Comprehensive test coverage

## References

- [Yachta T-219 Documentation](systems/yachta-t219/docs/YACHTA_T219_DOCUMENTATION.md)
- [VINSON KY-57 Documentation](systems/vinson-ky57/docs/VINSON_KY57_DOCUMENTATION.md)
- [Granit Documentation](systems/granit/docs/GRANIT_DOCUMENTATION.md)
- [STANAG 4197 Documentation](systems/stanag-4197/docs/STANAG_4197_DOCUMENTATION.md)
- [Voice Encryption Tests](../test/voice_encryption_tests/)

## License

This implementation is part of the FGcom-mumble project and is licensed under the same terms as the main project.

## Support

For technical support and questions about the voice encryption module, please refer to the main FGcom-mumble project documentation and support channels.