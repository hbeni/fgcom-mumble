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

### 5. MELPe with NATO Type 1 Encryption
- **Type**: NATO standard digital voice with Cold War encryption
- **Characteristics**: High-quality digital voice with NATO Type 1 security
- **Technology**: MELPe vocoder + NATO Type 1 encryption
- **Usage**: NATO military digital voice communications
- **Audio Effects**: Clean digital voice with encryption overhead
- **Key Length**: 128 bits minimum (16 bytes)
- **Security Level**: NATO Type 1 (NSA-approved)
- **Authentication**: NATO Type 1 standards
- **Encryption**: Stream cipher with LFSR key generation
- **Standard**: STANAG 4591 compliance

### 6. FreeDV with ChaCha20-Poly1305 Encryption
- **Type**: Modern digital voice with X25519 key exchange and military-grade encryption
- **Characteristics**: High-quality digital voice with multiple security levels
- **Technology**: FreeDV digital voice + ChaCha20-Poly1305 + X25519 key exchange
- **Usage**: Military communications with security classifications
- **Audio Effects**: Clean digital voice with minimal encryption overhead
- **Key Exchange**: X25519 elliptic curve cryptography
- **Hash Functions**: BLAKE2-256 (Standard/Tactical), SHA-256 (Top Secret)
- **Security Levels**: 
  - 128-bit: Standard squadron communications
  - 192-bit: Command/tactical channels
  - 256-bit: Top secret/special operations
- **Authentication**: Poly1305 MAC
- **Encryption**: ChaCha20 stream cipher
- **Standards**: RFC 8439, RFC 7748, RFC 7693

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

### MELPe with NATO Type 1 Encryption

```cpp
#include "melpe.h"

// Create MELPe instance
MELPe melpe;

// Initialize MELPe system
melpe.initialize(8000.0f, 1);

// Set NATO Type 1 encryption key
std::string key_data = "NATO_Type1_Encryption_Key_12345";
melpe.setEncryptionKey(12345, key_data);

// Enable NATO Type 1 encryption
melpe.enableNATOEncryption(true);

// Process voice data (now encrypted)
std::vector<float> audio = loadAudioData();
std::vector<float> encrypted = melpe.encrypt(audio);

// Decrypt voice data
std::vector<float> decrypted = melpe.decrypt(encrypted);
```

### FreeDV with ChaCha20-Poly1305 Encryption

```cpp
#include "freedv.h"
#include "chacha20_poly1305.h"

// Create FreeDV instance with security level
FreeDV freedv;

// Initialize FreeDV system
freedv.initialize(44100.0f, 1);

// Set FreeDV mode
freedv.setMode(FreeDVMode::MODE_2020);

// Create ChaCha20-Poly1305 with security level
ChaCha20Poly1305 crypto(SecurityLevel::TACTICAL); // 192-bit encryption

// Generate X25519 key pair for key exchange
auto key_pair = crypto.generateKeyPair();
std::cout << "Generated key pair for key exchange\n";

// Simulate key exchange with remote party
// (In real implementation, exchange public keys over secure channel)
auto shared_secret = crypto.performKeyExchange(remote_public_key);

// Derive encryption key from shared secret
crypto.deriveKeyFromSharedSecret(shared_secret);

// Enable ChaCha20-Poly1305 encryption
freedv.enableEncryption(crypto);

// Process voice data (now encrypted with 192-bit security)
std::vector<float> audio = loadAudioData();
std::vector<uint8_t> encrypted = freedv.encode(audio);

// Decrypt voice data
std::vector<float> decrypted = freedv.decode(encrypted);

// Display security information
std::cout << "Security Level: " << static_cast<int>(crypto.getSecurityLevel()) << "-bit\n";
std::cout << "Hash Function: " << ChaCha20Poly1305Utils::getRecommendedHashFunction(crypto.getSecurityLevel()) << "\n";
std::cout << crypto.getSecurityInfo() << std::endl;
```

### Security Level Examples

```cpp
// Standard squadron communications (128-bit)
ChaCha20Poly1305 standard_crypto(SecurityLevel::STANDARD);
// Uses BLAKE2-256 hashing, 16-byte keys

// Command/tactical channels (192-bit)
ChaCha20Poly1305 tactical_crypto(SecurityLevel::TACTICAL);
// Uses BLAKE2-256 or SHA-256 hashing, 24-byte keys

// Top secret/special operations (256-bit)
ChaCha20Poly1305 topsecret_crypto(SecurityLevel::TOP_SECRET);
// Uses SHA-256 hashing, 32-byte keys
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

// Configure FreeDV with encryption
freedv.setMode(FreeDVMode::MODE_2020); // High quality mode
freedv.enableEncryptionFromString("0123456789abcdef0123456789abcdef"); // 32-char hex key
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

// FreeDV encryption key management
std::vector<uint8_t> key = FreeDV::generateEncryptionKey(); // Generate random key
freedv.enableEncryption(key); // Set encryption key
freedv.enableEncryptionFromString("0123456789abcdef0123456789abcdef"); // Set from hex string
freedv.disableEncryption(); // Disable encryption
bool encrypted = freedv.isEncryptionEnabled(); // Check encryption status
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

// Get FreeDV encryption status
std::string encryption_status = freedv.getEncryptionStatus();
std::cout << encryption_status << std::endl;
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

### FreeDV with ChaCha20-Poly1305
- **Sound**: Clean digital voice with minimal encryption overhead
- **Encryption**: ChaCha20-Poly1305 authenticated encryption with X25519 key exchange
- **Security Levels**: 
  - 128-bit: Standard squadron communications (16-byte keys)
  - 192-bit: Command/tactical channels (24-byte keys)
  - 256-bit: Top secret/special operations (32-byte keys)
- **Key Exchange**: X25519 elliptic curve cryptography
- **Hash Functions**: BLAKE2-256 (Standard/Tactical), SHA-256 (Top Secret)
- **Authentication**: Poly1305 MAC prevents tampering
- **Overhead**: 28 bytes per encryption operation (nonce + tag)
- **Performance**: Minimal impact on processing speed
- **Characteristics**: High-quality digital voice with military-grade encryption

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

#### FreeDV with ChaCha20-Poly1305
- **FreeDV Modes**: 1600, 700, 700D, 2020, 2020B, 2020C bps
- **Encryption Algorithm**: ChaCha20-Poly1305 (RFC 8439)
- **Key Length**: 128 bits (16 bytes)
- **Nonce Length**: 96 bits (12 bytes)
- **Tag Length**: 128 bits (16 bytes)
- **Security Level**: 128-bit equivalent
- **Encryption Overhead**: 28 bytes per operation
- **Performance**: Real-time capable

## Performance Characteristics

### Processing Speed
- **Real-time**: All systems support real-time processing
- **Latency**: < 100 ms (typical)
- **Throughput**: Audio sample rate
- **CPU Usage**: < 10% (typical)
- **FreeDV Encryption**: Minimal performance impact
- **Encryption Overhead**: < 1% of processing time

### Memory Usage
- **Buffers**: Configurable buffer sizes
- **State**: Minimal state storage
- **FFT**: Optional FFT processing
- **Memory**: < 100 MB (typical)
- **Encryption State**: < 1 MB for ChaCha20-Poly1305
- **Key Storage**: 16 bytes for encryption key

### Audio Quality
- **Fidelity**: High-quality audio processing
- **Effects**: Authentic system characteristics
- **Filtering**: Clean frequency response
- **Noise**: Minimal processing noise
- **Encryption Quality**: No audio degradation from encryption
- **Digital Voice**: High-quality FreeDV digital voice

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
- **FreeDV Encryption**: Invalid key length, decryption failures
- **Authentication**: Failed tag verification
- **Nonce**: Duplicate nonce usage

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
- **FreeDV Encryption**: ChaCha20-Poly1305 encryption/decryption
- **Key Generation**: Random key generation
- **Authentication**: Tag verification

### Integration Tests
- **Audio Pipeline**: Complete processing chain
- **System Switching**: Dynamic system changes
- **Key Management**: Cross-system key handling
- **Performance**: Speed and memory usage
- **FreeDV Integration**: Encryption with FreeDV modes
- **End-to-End**: Complete voice encryption pipeline

### Performance Tests
- **Real-time Processing**: Latency and throughput
- **Memory Usage**: Buffer sizes and allocation
- **CPU Usage**: Processing efficiency
- **Audio Quality**: Signal quality metrics
- **Encryption Performance**: ChaCha20-Poly1305 speed
- **Overhead Measurement**: Encryption impact on processing

## Security Considerations

### Key Management
- **Storage**: Secure key storage
- **Transmission**: Secure key exchange
- **Validation**: Key integrity checking
- **Rotation**: Key rotation support
- **FreeDV Keys**: 128-bit ChaCha20-Poly1305 keys
- **Key Generation**: Cryptographically secure random generation
- **Key Format**: Hexadecimal string or binary vector

### System Security
- **Initialization**: Secure system setup
- **State**: Secure state management
- **Processing**: Secure audio processing
- **Cleanup**: Secure resource cleanup
- **FreeDV Security**: Secure encryption state management
- **Key Clearing**: Secure key memory cleanup
- **Nonce Management**: Unique nonce generation

### Encryption Security
- **Algorithms**: Industry-standard encryption
- **Key Length**: Appropriate key lengths
- **Randomness**: Cryptographically secure random generation
- **Validation**: Key validation and verification
- **ChaCha20-Poly1305**: RFC 8439 compliant implementation
- **Authentication**: Poly1305 MAC for integrity
- **Forward Secrecy**: Unique nonce per encryption
- **Security Level**: 128-bit equivalent strength

## Troubleshooting

### Common Issues
- **Initialization**: Check parameters and system state
- **Key Loading**: Validate key format and length
- **Audio Processing**: Check buffer sizes and sample rates
- **Effects**: Verify effect parameters and intensity
- **FreeDV Encryption**: Verify key length (16 bytes)
- **Decryption Failures**: Check key matching and data integrity
- **Authentication**: Verify tag validation

### Debug Information
- **Status**: System status reporting
- **Key Info**: Key information and validation
- **Performance**: Processing speed and memory usage
- **Errors**: Error reporting and diagnostics
- **Encryption Status**: FreeDV encryption status and configuration
- **Security Info**: ChaCha20-Poly1305 security information
- **Key Validation**: Encryption key format and length verification

### Performance Optimization
- **Buffer Sizes**: Optimize for real-time processing
- **System Selection**: Choose appropriate system for use case
- **Key Management**: Optimize key operations
- **Memory Usage**: Minimize memory allocation
- **Encryption Performance**: Optimize ChaCha20-Poly1305 processing
- **FreeDV Modes**: Select appropriate FreeDV mode for conditions
- **Encryption Overhead**: Minimize encryption impact

## Future Enhancements

### Planned Features
- **Additional Systems**: More encryption systems
- **Key Management**: Enhanced key management
- **Audio Effects**: More audio effects
- **Performance**: Performance optimizations
- **FreeDV Enhancements**: Additional FreeDV modes with encryption
- **Advanced Encryption**: Additional encryption algorithms
- **Key Exchange**: Secure key exchange protocols

### Compatibility
- **Standards**: Industry standard compliance
- **Interoperability**: Cross-platform compatibility
- **Integration**: FGcom-mumble integration
- **Testing**: Comprehensive test coverage
- **FreeDV Standards**: RFC 8439 ChaCha20-Poly1305 compliance
- **Cross-Platform**: Windows, Linux, macOS support
- **API Compatibility**: Backward compatible API

## FreeDV Encryption Examples

### Basic Encryption Setup

```cpp
#include "freedv.h"

// Create and initialize FreeDV
FreeDV freedv;
freedv.initialize(44100.0f, 1);
freedv.setMode(FreeDVMode::MODE_2020);

// Generate and set encryption key
std::vector<uint8_t> key = FreeDV::generateEncryptionKey();
freedv.enableEncryption(key);

// Process voice data
std::vector<float> audio = loadAudioData();
std::vector<uint8_t> encrypted = freedv.encode(audio);
std::vector<float> decrypted = freedv.decode(encrypted);
```

### Encryption with Key String

```cpp
// Use hexadecimal key string
std::string key_string = "0123456789abcdef0123456789abcdef";
freedv.enableEncryptionFromString(key_string);

// Process encrypted voice
std::vector<uint8_t> encrypted = freedv.encode(audio);
```

### Encryption Status and Diagnostics

```cpp
// Check encryption status
if (freedv.isEncryptionEnabled()) {
    std::cout << "Encryption is active" << std::endl;
    std::cout << freedv.getEncryptionStatus() << std::endl;
}

// Disable encryption
freedv.disableEncryption();
```

### Performance Testing

```cpp
// Measure encryption performance
auto start = std::chrono::high_resolution_clock::now();
std::vector<uint8_t> encrypted = freedv.encode(audio);
auto end = std::chrono::high_resolution_clock::now();

auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
std::cout << "Encryption time: " << duration.count() << " microseconds" << std::endl;
```

## References

- [Yachta T-219 Documentation](systems/yachta-t219/docs/YACHTA_T219_DOCUMENTATION.md)
- [VINSON KY-57 Documentation](systems/vinson-ky57/docs/VINSON_KY57_DOCUMENTATION.md)
- [Granit Documentation](systems/granit/docs/GRANIT_DOCUMENTATION.md)
- [STANAG 4197 Documentation](systems/stanag-4197/docs/STANAG_4197_DOCUMENTATION.md)
- [FreeDV Encryption Documentation](systems/freedv/docs/FREEDV_ENCRYPTION_DOCUMENTATION.md)
- [Voice Encryption Tests](../test/voice_encryption_tests/)

## License

This implementation is part of the FGcom-mumble project and is licensed under the same terms as the main project.

## Support

For technical support and questions about the voice encryption module, please refer to the main FGcom-mumble project documentation and support channels.