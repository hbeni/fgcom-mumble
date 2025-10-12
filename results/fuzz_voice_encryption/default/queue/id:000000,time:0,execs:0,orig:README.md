# Voon Fuzzing Corpuins test data for fuzzing voice encryption and secure communication in FGCom-mumble.

## Test Data Files

### encryption_key.txt
- **Purpose**: Cryptographic key data
- **Format**: Binary key material
- **Size**: 72 bytes
- **Usage**: Tests encryption key handling and validation

### encryption_mode.txt
- **Purpose**: Encryption algorithm modes
- **Format**: Mode identifiers
- **Size**: 12 bytes
- **Usage**: Tests different encryption algorithm selections

### voice_sample.txt
- **Purpose**: Encrypted voice data samples
- **Format**: Binary encrypted audio
- **Size**: 41 bytes
- **Usage**: Tests encryption/decryption of voice data

## Fuzzing Target
- **Binary**: `test/build-fuzz/fuzz_voice_encryption`
- **Purpose**: Tests voice encryption for:
  - Cryptographic key management
  - Encryption/decryption operations
  - Secure voice protocol handling
  - Key exchange mechanisms
  - Authentication in encrypted channels

## Expected Behaviors
- Encryption should handle malformed keys gracefully
- Decryption should not crash on invalid data
- Key management should be secure
- Voice encryption should be robust
- Authentication should be tamper-resistant

## Coverage Areas
- Voice encryption algorithms
- Cryptographic key management
- Secure voice communication protocols
- Encryption/decryption operations
- Authentication mechanisms
- Secure voice transmission
- Key exchange protocols
- Voice 