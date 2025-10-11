# FGCom-mumble Fuzzing Corpus Best Practices

## Overview

This document outlines best practices for creating and maintaining high-quality fuzzing corpus files for FGCom-mumble security testing.

## Corpus Quality Principles

### 1. **Quality Over Quantity**
- Start with 10-100 high-quality seeds rather than thousands of redundant ones
- Each file should exercise different code paths
- Focus on diverse, meaningful inputs that trigger various program states

### 2. **Diverse Input Types**
- **Minimal valid inputs**: Smallest valid file that exercises basic functionality
- **Maximum complexity inputs**: Deeply nested structures, large sizes, complex data
- **Boundary conditions**: Empty inputs, single elements, maximum values
- **Error handling cases**: Almost-valid inputs, malformed data, corruption

### 3. **Code Path Coverage**
- Include inputs that trigger different branches and conditions
- Test various input lengths and formats
- Cover different character sets and encodings
- Exercise both success and failure paths

## Corpus Structure by Target

### Security Functions (`fuzz_security_functions`)
**Purpose**: Test authentication, authorization, input validation, encryption

**High-Quality Seeds**:
- `minimal_auth.txt`: `admin` - Basic authentication
- `complex_auth.txt`: `user:pass:role:admin:session:token` - Multi-field auth
- `empty_input.txt`: `` - Empty input handling
- `email_auth.txt`: `admin@domain.com` - Email format
- `unicode_auth.txt`: `管理员:пароль` - International characters
- `malformed_auth.txt`: `admin:password:invalid:format` - Error handling

**Coverage Goals**:
- Authentication mechanisms
- Input validation functions
- Encryption/decryption routines
- Session management
- Permission checking

### Network Protocol (`fuzz_network_protocol`)
**Purpose**: Test UDP packet handling, protocol parsing, network communication

**High-Quality Seeds**:
- `minimal_ping.txt`: `PING` - Basic protocol message
- `radio_message.txt`: `RADIO:118.100:TX:1000:40.7128:-74.0060` - Complex message
- `empty_packet.txt`: `` - Empty packet handling
- `status_message.txt`: `STATUS:CONNECTED:CHANNEL:1:QUALITY:85` - Status protocol
- `malformed_radio.txt`: `RADIO:118.100:TX:invalid:40.7128:-74.0060` - Error case

**Coverage Goals**:
- UDP packet parsing
- Protocol message validation
- Network timeout handling
- Message routing
- Error recovery

### Audio Processing (`fuzz_audio_processing`)
**Purpose**: Test audio codecs, sample processing, audio effects

**High-Quality Seeds**:
- `silence.txt`: `SILENCE` - No audio data
- `single_tone.txt`: `TONE:440` - Basic audio tone
- `multi_tone.txt`: `MULTI_TONE:440:880:1320` - Complex audio
- `pcm_format.txt`: `FORMAT:PCM:44100:16:STEREO` - Audio format
- `invalid_frequency.txt`: `TONE:invalid` - Error handling

**Coverage Goals**:
- Audio codec processing
- Sample rate conversion
- Audio effects processing
- Format validation
- Buffer management

### Frequency Management (`fuzz_frequency_management`)
**Purpose**: Test frequency validation, range checking, aviation frequencies

**High-Quality Seeds**:
- `ground_freq.txt`: `118.100` - Standard aviation frequency
- `emergency_freq.txt`: `121.500` - Emergency frequency
- `freq_range.txt`: `118.000:118.975` - Frequency range
- `min_frequency.txt`: `118.000` - Minimum valid frequency
- `max_frequency.txt`: `136.975` - Maximum valid frequency
- `invalid_freq.txt`: `invalid` - Error handling

**Coverage Goals**:
- Frequency validation
- Range checking
- Aviation frequency standards
- Frequency conversion
- Error handling

### Radio Propagation (`fuzz_radio_propagation`)
**Purpose**: Test coordinate calculations, distance computations, propagation models

**High-Quality Seeds**:
- `nyc_coords.txt`: `40.7128,-74.0060` - New York coordinates
- `london_coords.txt`: `51.5074,-0.1278` - London coordinates
- `distance_calc.txt`: `40.7128,-74.0060:40.7589,-73.9851` - Distance calculation
- `north_pole.txt`: `90,0` - Extreme coordinates
- `south_pole.txt`: `-90,0` - Extreme coordinates
- `invalid_coords.txt`: `invalid,coordinates` - Error handling

**Coverage Goals**:
- Coordinate validation
- Distance calculations
- Propagation models
- Geographic calculations
- Error handling

### Antenna Patterns (`fuzz_antenna_patterns`)
**Purpose**: Test antenna pattern calculations, gain patterns, radiation models

**High-Quality Seeds**:
- `omnidirectional.txt`: `OMNI:0:360:0` - Omnidirectional antenna
- `dipole.txt`: `DIPOLE:0:180:0` - Dipole antenna
- `yagi.txt`: `YAGI:0:60:0` - Yagi antenna
- `array_pattern.txt`: `ARRAY:0:360:0:4:0.5` - Array antenna
- `invalid_type.txt`: `INVALID:0:360:0` - Error handling

**Coverage Goals**:
- Antenna pattern calculations
- Gain pattern generation
- Radiation model validation
- Pattern interpolation
- Error handling

### ATIS Processing (`fuzz_atis_processing`)
**Purpose**: Test weather report parsing, aviation information processing

**High-Quality Seeds**:
- `minimal_atis.txt`: `ATIS A` - Basic ATIS
- `wind_info.txt`: `WIND 270 AT 10` - Wind information
- `full_atis.txt`: `ATIS A WIND 270 AT 10 VISIBILITY 10 MILES` - Complete ATIS
- `calm_wind.txt`: `WIND CALM` - Special wind condition
- `invalid_atis.txt`: `ATIS INVALID` - Error handling

**Coverage Goals**:
- Weather report parsing
- Aviation information processing
- ATIS message validation
- Weather data extraction
- Error handling

## Corpus Maintenance

### Regular Updates
1. **Monitor fuzzing results** for new code paths discovered
2. **Add new corpus files** based on fuzzing coverage analysis
3. **Remove redundant files** that don't improve coverage
4. **Update existing files** with new edge cases found

### Quality Monitoring
1. **Run corpus analysis** regularly to check diversity and coverage
2. **Monitor fuzzing coverage** to identify gaps
3. **Test corpus effectiveness** by measuring code coverage improvement
4. **Validate corpus quality** using automated analysis tools

### Best Practices
1. **Start small**: Begin with 10-100 high-quality seeds
2. **Focus on diversity**: Each file should exercise different code paths
3. **Include edge cases**: Boundary conditions, error conditions, extreme values
4. **Test different formats**: Various input encodings, character sets, structures
5. **Regular maintenance**: Update corpus based on fuzzing results

## Tools and Scripts

### Corpus Generation
- `scripts/fuzzing/generate_corpus.sh` - Generate high-quality corpus files
- `scripts/fuzzing/corpus_management.sh` - Comprehensive corpus management
- `scripts/fuzzing/analyze_corpus_quality.sh` - Analyze corpus quality

### Usage Examples
```bash
# Generate corpus for all targets
./scripts/fuzzing/generate_corpus.sh

# Analyze corpus quality
./scripts/fuzzing/analyze_corpus_quality.sh

# Full corpus management
./scripts/fuzzing/corpus_management.sh
```

## Quality Metrics

### Diversity Score (0-4)
- Minimal inputs: Basic functionality
- Complex inputs: Advanced features
- Boundary conditions: Edge cases
- Error handling: Malformed data

### Coverage Score (0-7)
- Short inputs: Minimal data
- Long inputs: Large data
- ASCII characters: Standard text
- Unicode characters: International text
- Special characters: Symbols and punctuation
- Simple formats: Basic structure
- Structured formats: Complex data

### Target Quality Levels
- **HIGH**: Diversity ≥ 3, Coverage ≥ 5
- **MEDIUM**: Diversity ≥ 2, Coverage ≥ 3
- **LOW**: Diversity < 2, Coverage < 3

## Conclusion

A high-quality fuzzing corpus is essential for effective security testing. By following these best practices and maintaining the corpus regularly, you can achieve comprehensive code coverage and identify security vulnerabilities effectively.

Remember: **Quality over quantity** - a small, diverse corpus is more effective than a large, redundant one.
