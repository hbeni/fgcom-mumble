# AGC Squelch Fuzzing Corpus

## Overview
This corpus contains test data for fuzzing Automatic Gain Control (AGC) and Squelch functionality in FGCom-mumble.

## Test Data Files

### agc_config.txt
- **Purpose**: AGC configuration parameters
- **Format**: Key-value pairs for AGC settings
- **Size**: 48 bytes
- **Usage**: Tests AGC algorithm parameter parsing

### audio_sample.txt
- **Purpose**: Raw audio sample data
- **Format**: Binary audio data
- **Size**: 39 bytes
- **Usage**: Tests AGC processing on actual audio input

## Fuzzing Target
- **Binary**: `test/build-fuzz/fuzz_agc`
- **Purpose**: Tests AGC and squelch algorithms for:
  - Buffer overflows in audio processing
  - Invalid parameter handling
  - Memory corruption in gain control
  - Squelch threshold edge cases

## Expected Behaviors
- AGC should handle malformed configuration gracefully
- Audio processing should not crash on invalid samples
- Squelch detection should be robust against edge cases
- Memory operations should be safe under all conditions

## Coverage Areas
- Automatic gain control algorithms
- Squelch detection and processing
- Audio threshold management
- Signal-to-noise ratio calculations
- Audio level normalization
