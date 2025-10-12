# Aung Fuzzing Corpus

## Overview
This corpus contains test data for fuzzing audio processing algorithms in FGCom-mumble.

## Test Data Files

### invalid_frequency.txt
- **Purpose**: Invalid frequency data
- **Format**: Malformed frequency values
- **Size**: 13 bytes
- **Usage**: Tests audio frequency validation

### multi_tone.txt
- **Purpose**: Multi-tone audio data
- **Format**: Complex audio signal data
- **Size**: 24 bytes
- **Usage**: Tests multi-tone audio processing

### pcm_format.txt
- **Purpose**: PCM audio format data
- **Format**: Pulse Code Modulation audio
- **Size**: Variable
- **Usage**: Tests PCM audio format handling

### silence.txt
- **Purpose**: Silent audio data
- **Format**: Zero-amplitude audio samples
- **Size**: Variable
- **Usage**: Tests silence detection and processing

### single_tone.txt
- **Purpose**: Single tone audio data
- **Format**: Pure tone audio signal
- **Size**: Variable
- **Usage**: Tests single-tone audio processing

## Fuzzing Target
- **Binary**: `test/build-fuzz/fuzz_audio_processing`
- **Purpose**: Tests audio processing for:
  - Audio codec algorithms
  - Audio effects processing
  - Sample rate conversion
  - Audio format handling
  - Tone detection and analysis

## Expected Behaviors
- Audio processing should handle all formats gracefully
- Codec operations should be robust
- Effects processing should not crash
- Sample rate conversion should be accurate
- Tone detection should be reliable

## Coverage Areas
- Audio codec algorithms
- Audio effects processing
- Sample rate conversion
- Audio format handling
- Tone detection algorithms
- Audio signal analysis
- Audio quality processing
- Audio compressio