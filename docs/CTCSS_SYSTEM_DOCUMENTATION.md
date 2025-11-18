# CTCSS (Continuous Tone-Coded Squelch System) Documentation

## Overview

CTCSS (Continuous Tone-Coded Squelch System) is a radio communication feature that allows multiple users to share the same frequency without hearing each other's conversations. This implementation follows NATO military standards and international radio regulations, including proper regional restrictions for power line frequency interference.

## Table of Contents

1. [Quick Start](#quick-start)
2. [CTCSS Fundamentals](#ctcss-fundamentals)
3. [Tone Database](#tone-database)
4. [Regional Restrictions](#regional-restrictions)
5. [API Reference](#api-reference)
6. [Configuration](#configuration)
7. [Audio Processing](#audio-processing)
8. [Examples](#examples)
9. [Troubleshooting](#troubleshooting)

## Quick Start

### Basic Usage

```cpp
#include "lib/ctcss_system.h"

using namespace CTCSS;

// Initialize CTCSS system
auto& ctcss_system = CTCSSSystem::getInstance();
ctcss_system.initialize();

// Create default configuration
CTCSSConfig config = ctcss_system.createDefaultConfig();
config.ctcss_enabled = true;
config.tx_tone_hz = 100.0f;  // Transmit tone
config.rx_tone_hz = 100.0f;  // Receive tone

// Set configuration
std::string result = CTCSSAPI::setCTCSSConfig(config);
std::cout << "Configuration result: " << result << std::endl;

// Get tone information
std::string tone_info = CTCSSAPI::getToneInfo(100.0f);
std::cout << "Tone info: " << tone_info << std::endl;
```

### NATO Military Configuration

```cpp
// Create NATO military configuration
CTCSSConfig nato_config = ctcss_system.createNATOConfig();
// Uses 150.0 Hz as per NATO standards

// Set NATO configuration
std::string result = CTCSSAPI::setCTCSSConfig(nato_config);
```

## CTCSS Fundamentals

### How CTCSS Works

1. **Transmitting**: Your radio transmits voice + sub-audible tone
2. **Receiving**: Other radios only open squelch when they receive the correct tone
3. **Isolation**: Different groups can share the same frequency without interference

### Tone Characteristics

- **Frequency Range**: 67.0 - 254.1 Hz
- **Amplitude**: -10 to -20 dB below voice level
- **Duration**: Continuous during transmission
- **Tolerance**: ±2 Hz (civilian), ±1 Hz (military)

### Motorola PL Codes

Each CTCSS tone has a corresponding Motorola PL (Private Line) code:

| Frequency | PL Code | Description |
|-----------|---------|-------------|
| 67.0 Hz | 1A | Standard tone 1A |
| 69.3 Hz | 1B | Standard tone 1B |
| 100.0 Hz | 2B | Standard tone 2B (restricted in UK) |
| 150.0 Hz | NATO | NATO Military Standard |
| 254.1 Hz | 6C | Standard tone 6C |

## Tone Database

### Standard 39-Tone Series

The system includes the complete standard 39-tone CTCSS series:

#### Series 1: 67.0 - 94.8 Hz
```
67.0 Hz  (1A) - Standard tone 1A
69.3 Hz  (1B) - Standard tone 1B
71.9 Hz  (1C) - Standard tone 1C
74.4 Hz  (1D) - Standard tone 1D
77.0 Hz  (1E) - Standard tone 1E
79.7 Hz  (1F) - Standard tone 1F
82.5 Hz  (1G) - Standard tone 1G
85.4 Hz  (1H) - Standard tone 1H
88.5 Hz  (1I) - Standard tone 1I
91.5 Hz  (1J) - Standard tone 1J
94.8 Hz  (1K) - Standard tone 1K
```

#### Series 2: 97.4 - 127.3 Hz
```
97.4 Hz  (2A) - Standard tone 2A
100.0 Hz (2B) - Standard tone 2B (restricted in UK)
103.5 Hz (2C) - Standard tone 2C
107.2 Hz (2D) - Standard tone 2D
110.9 Hz (2E) - Standard tone 2E
114.8 Hz (2F) - Standard tone 2F
118.8 Hz (2G) - Standard tone 2G
123.0 Hz (2H) - Standard tone 2H
127.3 Hz (2I) - Standard tone 2I
```

#### Series 3: 131.8 - 162.2 Hz
```
131.8 Hz (3A) - Standard tone 3A
136.5 Hz (3B) - Standard tone 3B
141.3 Hz (3C) - Standard tone 3C
146.2 Hz (3D) - Standard tone 3D
151.4 Hz (3E) - Standard tone 3E
156.7 Hz (3F) - Standard tone 3F
162.2 Hz (3G) - Standard tone 3G
```

#### Series 4: 167.9 - 199.5 Hz
```
167.9 Hz (4A) - Standard tone 4A
173.8 Hz (4B) - Standard tone 4B
179.9 Hz (4C) - Standard tone 4C
186.2 Hz (4D) - Standard tone 4D
192.8 Hz (4E) - Standard tone 4E
199.5 Hz (4F) - Standard tone 4F
```

#### Series 5: 203.5 - 233.6 Hz
```
203.5 Hz (5A) - Standard tone 5A
206.5 Hz (5B) - Standard tone 5B
210.7 Hz (5C) - Standard tone 5C
218.1 Hz (5D) - Standard tone 5D
225.7 Hz (5E) - Standard tone 5E
229.1 Hz (5F) - Standard tone 5F
233.6 Hz (5G) - Standard tone 5G
```

#### Series 6: 241.8 - 254.1 Hz
```
241.8 Hz (6A) - Standard tone 6A
250.3 Hz (6B) - Standard tone 6B
254.1 Hz (6C) - Standard tone 6C
```

### NATO Military Tones

```
150.0 Hz (NATO) - NATO Military Standard
67.0 Hz  (MIL1) - Military tone 1
69.3 Hz  (MIL2) - Military tone 2
71.9 Hz  (MIL3) - Military tone 3
```

## Regional Restrictions

### Power Line Frequency Interference

Certain CTCSS tones are restricted in specific regions due to power line frequency interference:

#### United Kingdom (50Hz Power System)
**Restricted Tones:**
- 50.0 Hz - UK mains frequency
- 100.0 Hz - 2x UK mains frequency (most common restriction)
- 150.0 Hz - 3x UK mains frequency
- 200.0 Hz - 4x UK mains frequency
- 250.0 Hz - 5x UK mains frequency

**Reason**: Inadequately smoothed power supplies may cause unwanted squelch opening.

#### United States (60Hz Power System)
**Restricted Tones:**
- 60.0 Hz - US mains frequency
- 120.0 Hz - 2x US mains frequency
- 180.0 Hz - 3x US mains frequency
- 240.0 Hz - 4x US mains frequency

#### European Union (50Hz Power System)
**Restricted Tones:**
- 50.0 Hz - EU mains frequency
- 100.0 Hz - 2x EU mains frequency
- 150.0 Hz - 3x EU mains frequency
- 200.0 Hz - 4x EU mains frequency
- 250.0 Hz - 5x EU mains frequency

### Regional Recommendations

#### UK Recommendations
```cpp
// Get tones recommended for UK
std::string uk_tones = CTCSSAPI::getRegionalRecommendations(Region::UK);
```

**Recommended Tones for UK:**
- 67.0 Hz (1A) - Safe from power line interference
- 69.3 Hz (1B) - Safe from power line interference
- 71.9 Hz (1C) - Safe from power line interference
- 74.4 Hz (1D) - Safe from power line interference
- 77.0 Hz (1E) - Safe from power line interference
- 79.7 Hz (1F) - Safe from power line interference
- 82.5 Hz (1G) - Safe from power line interference
- 85.4 Hz (1H) - Safe from power line interference
- 88.5 Hz (1I) - Safe from power line interference
- 91.5 Hz (1J) - Safe from power line interference
- 94.8 Hz (1K) - Safe from power line interference

**Avoid in UK:**
- 100.0 Hz (2B) - 2x UK mains frequency
- 150.0 Hz (NATO) - 3x UK mains frequency
- 200.0 Hz - 4x UK mains frequency
- 250.0 Hz - 5x UK mains frequency

#### NATO Military Recommendations
```cpp
// Get NATO military configuration
CTCSSConfig nato_config = ctcss_system.createNATOConfig();
// Uses 150.0 Hz as per NATO standards
```

**NATO Standard:**
- 150.0 Hz (NATO) - NATO Military Standard tone

## API Reference

### Basic CTCSS Operations

#### Set CTCSS Configuration
```cpp
std::string setCTCSSConfig(const CTCSSConfig& config);
```

**Parameters:**
- `config`: CTCSS configuration structure

**Example:**
```cpp
CTCSSConfig config;
config.ctcss_enabled = true;
config.tx_tone_hz = 100.0f;
config.rx_tone_hz = 100.0f;
config.tone_decode_enabled = true;
config.tone_encode_enabled = true;
config.tone_tolerance_hz = 2.0f;
config.tone_level_db = -10.0f;

std::string result = CTCSSAPI::setCTCSSConfig(config);
```

**Response:**
```json
{
  "success": true,
  "message": "CTCSS configuration set"
}
```

#### Get CTCSS Configuration
```cpp
std::string getCTCSSConfig();
```

**Response:**
```json
{
  "success": true,
  "data": {
    "ctcss_enabled": true,
    "tx_tone_hz": 100.0,
    "rx_tone_hz": 100.0,
    "tone_decode_enabled": true,
    "tone_encode_enabled": true,
    "tone_tolerance_hz": 2.0,
    "tone_level_db": -10.0
  }
}
```

#### Enable/Disable CTCSS
```cpp
std::string enableCTCSS(bool enabled);
```

**Example:**
```cpp
std::string result = CTCSSAPI::enableCTCSS(true);
```

#### Set Transmit Tone
```cpp
std::string setTransmitTone(float frequency_hz);
```

**Example:**
```cpp
std::string result = CTCSSAPI::setTransmitTone(100.0f);
```

#### Set Receive Tone
```cpp
std::string setReceiveTone(float frequency_hz);
```

**Example:**
```cpp
std::string result = CTCSSAPI::setReceiveTone(100.0f);
```

### Tone Database Queries

#### Get Tone Information
```cpp
std::string getToneInfo(float frequency_hz);
```

**Example:**
```cpp
std::string tone_info = CTCSSAPI::getToneInfo(100.0f);
```

**Response:**
```json
{
  "success": true,
  "data": {
    "frequency_hz": 100.0,
    "motorola_pl_code": "2B",
    "description": "Standard tone 2B",
    "is_nato_standard": true,
    "is_restricted_region": true
  }
}
```

#### Get Tone Information by PL Code
```cpp
std::string getToneInfoByPLCode(const std::string& pl_code);
```

**Example:**
```cpp
std::string tone_info = CTCSSAPI::getToneInfoByPLCode("2B");
```

#### List Available Tones
```cpp
std::string listAvailableTones(Region region = Region::GLOBAL);
```

**Example:**
```cpp
// Get all tones
std::string all_tones = CTCSSAPI::listAvailableTones(Region::GLOBAL);

// Get UK-safe tones
std::string uk_tones = CTCSSAPI::listAvailableTones(Region::UK);
```

#### List NATO Tones
```cpp
std::string listNATOTones();
```

**Example:**
```cpp
std::string nato_tones = CTCSSAPI::listNATOTones();
```

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "frequency_hz": 150.0,
      "motorola_pl_code": "NATO",
      "description": "NATO Military Standard"
    }
  ]
}
```

#### List Restricted Tones
```cpp
std::string listRestrictedTones(Region region);
```

**Example:**
```cpp
std::string uk_restricted = CTCSSAPI::listRestrictedTones(Region::UK);
```

### Regional Restrictions

#### Check Regional Restrictions
```cpp
std::string checkRegionalRestrictions(float frequency_hz, Region region);
```

**Example:**
```cpp
std::string result = CTCSSAPI::checkRegionalRestrictions(100.0f, Region::UK);
```

**Response:**
```json
{
  "success": true,
  "data": {
    "frequency_hz": 100.0,
    "is_restricted": true,
    "is_allowed": false
  }
}
```

#### Get Regional Recommendations
```cpp
std::string getRegionalRecommendations(Region region);
```

**Example:**
```cpp
std::string uk_recommendations = CTCSSAPI::getRegionalRecommendations(Region::UK);
```

### Audio Processing

#### Process Audio with CTCSS
```cpp
std::string processAudioWithCTCSS(const std::string& audio_data, const CTCSSConfig& config);
```

**Example:**
```cpp
CTCSSConfig config;
config.ctcss_enabled = true;
config.tx_tone_hz = 100.0f;

std::string audio_data = "base64_encoded_audio_data";
std::string result = CTCSSAPI::processAudioWithCTCSS(audio_data, config);
```

#### Detect Tones in Audio
```cpp
std::string detectTonesInAudio(const std::string& audio_data);
```

**Example:**
```cpp
std::string audio_data = "base64_encoded_audio_data";
std::string result = CTCSSAPI::detectTonesInAudio(audio_data);
```

### Statistics and Monitoring

#### Get CTCSS Statistics
```cpp
std::string getCTCSSStatistics();
```

**Response:**
```json
{
  "success": true,
  "data": {
    "tones_generated": 1250,
    "tones_detected": 1180,
    "decode_attempts": 1500,
    "decode_successes": 1180,
    "average_detection_confidence": 0.95
  }
}
```

#### Reset CTCSS Statistics
```cpp
std::string resetCTCSSStatistics();
```

### Configuration Validation

#### Validate CTCSS Configuration
```cpp
std::string validateCTCSSConfig(const std::string& config_json);
```

**Example:**
```cpp
std::string config_json = R"({
  "ctcss_enabled": true,
  "tx_tone_hz": 100.0,
  "rx_tone_hz": 100.0,
  "tone_tolerance_hz": 2.0,
  "tone_level_db": -10.0
})";

std::string result = CTCSSAPI::validateCTCSSConfig(config_json);
```

#### Get Configuration Recommendations
```cpp
std::string getConfigRecommendations(Region region);
```

**Example:**
```cpp
std::string uk_config = CTCSSAPI::getConfigRecommendations(Region::UK);
```

## Configuration

### CTCSS Configuration Structure

```cpp
struct CTCSSConfig {
    bool ctcss_enabled = false;           // Enable/disable CTCSS
    float tx_tone_hz = 0.0f;             // Transmit tone frequency
    float rx_tone_hz = 0.0f;             // Receive tone frequency
    bool tone_decode_enabled = true;     // Enable tone decoding
    bool tone_encode_enabled = true;     // Enable tone encoding
    float tone_tolerance_hz = 2.0f;      // Tone detection tolerance
    float tone_level_db = -10.0f;        // Tone level relative to voice
};
```

### Configuration Presets

#### Default Configuration
```cpp
CTCSSConfig config = ctcss_system.createDefaultConfig();
// Uses standard civilian settings
```

#### NATO Military Configuration
```cpp
CTCSSConfig nato_config = ctcss_system.createNATOConfig();
// Uses 150.0 Hz NATO standard with stricter tolerance
```

#### Civilian Configuration
```cpp
CTCSSConfig civilian_config = ctcss_system.createCivilianConfig();
// Uses more tolerant settings for civilian use
```

### Regional Configuration Examples

#### UK Configuration
```cpp
CTCSSConfig uk_config;
uk_config.ctcss_enabled = true;
uk_config.tx_tone_hz = 67.0f;  // Safe from 50Hz power interference
uk_config.rx_tone_hz = 67.0f;  // Safe from 50Hz power interference
uk_config.tone_tolerance_hz = 2.0f;
uk_config.tone_level_db = -10.0f;
```

#### US Configuration
```cpp
CTCSSConfig us_config;
us_config.ctcss_enabled = true;
us_config.tx_tone_hz = 100.0f;  // Safe from 60Hz power interference
us_config.rx_tone_hz = 100.0f;  // Safe from 60Hz power interference
us_config.tone_tolerance_hz = 2.0f;
us_config.tone_level_db = -10.0f;
```

#### NATO Military Configuration
```cpp
CTCSSConfig nato_config;
nato_config.ctcss_enabled = true;
nato_config.tx_tone_hz = 150.0f;  // NATO standard
nato_config.rx_tone_hz = 150.0f;  // NATO standard
nato_config.tone_tolerance_hz = 1.0f;  // Stricter tolerance
nato_config.tone_level_db = -8.0f;     // Higher level
```

## Audio Processing

### Tone Generation

```cpp
// Generate CTCSS tone
std::vector<float> tone_buffer;
bool success = ctcss_system.generateCTCSSTone(
    100.0f,        // Frequency
    1000.0f,       // Duration (ms)
    48000.0f,      // Sample rate
    tone_buffer    // Output buffer
);
```

### Tone Detection

```cpp
// Detect CTCSS tone in audio
float detected_frequency;
float confidence;
bool tone_present = ctcss_system.detectCTCSSTone(
    audio_buffer,      // Input audio
    48000.0f,          // Sample rate
    detected_frequency, // Detected frequency
    confidence         // Detection confidence
);
```

### Audio Encoding

```cpp
// Encode CTCSS tone with voice audio
std::vector<float> output_audio;
bool success = ctcss_system.encodeCTCSSTone(
    voice_audio,    // Input voice audio
    100.0f,         // CTCSS tone frequency
    48000.0f,       // Sample rate
    output_audio    // Output audio with tone
);
```

### Audio Decoding

```cpp
// Decode CTCSS tone from audio
bool tone_present;
float confidence;
bool success = ctcss_system.decodeCTCSSTone(
    audio_input,        // Input audio
    100.0f,             // Expected tone frequency
    48000.0f,           // Sample rate
    tone_present,       // Tone present flag
    confidence          // Detection confidence
);
```

## Examples

### Complete CTCSS Setup

```cpp
#include "lib/ctcss_system.h"
#include <iostream>

int main() {
    // Initialize CTCSS system
    auto& ctcss_system = CTCSSSystem::getInstance();
    ctcss_system.initialize();
    
    // Create configuration for UK (avoiding 100.0 Hz)
    CTCSSConfig config;
    config.ctcss_enabled = true;
    config.tx_tone_hz = 67.0f;  // Safe from 50Hz power interference
    config.rx_tone_hz = 67.0f;  // Safe from 50Hz power interference
    config.tone_decode_enabled = true;
    config.tone_encode_enabled = true;
    config.tone_tolerance_hz = 2.0f;
    config.tone_level_db = -10.0f;
    
    // Set configuration
    std::string result = CTCSSAPI::setCTCSSConfig(config);
    std::cout << "Configuration result: " << result << std::endl;
    
    // Get tone information
    std::string tone_info = CTCSSAPI::getToneInfo(67.0f);
    std::cout << "Tone info: " << tone_info << std::endl;
    
    // Check regional restrictions
    std::string restrictions = CTCSSAPI::checkRegionalRestrictions(100.0f, Region::UK);
    std::cout << "UK restrictions for 100.0 Hz: " << restrictions << std::endl;
    
    // Get UK recommendations
    std::string uk_recommendations = CTCSSAPI::getRegionalRecommendations(Region::UK);
    std::cout << "UK recommendations: " << uk_recommendations << std::endl;
    
    return 0;
}
```

### NATO Military Setup

```cpp
#include "lib/ctcss_system.h"
#include <iostream>

int main() {
    // Initialize CTCSS system
    auto& ctcss_system = CTCSSSystem::getInstance();
    ctcss_system.initialize();
    
    // Create NATO military configuration
    CTCSSConfig nato_config = ctcss_system.createNATOConfig();
    
    // Set NATO configuration
    std::string result = CTCSSAPI::setCTCSSConfig(nato_config);
    std::cout << "NATO configuration result: " << result << std::endl;
    
    // Get NATO tone information
    std::string nato_tones = CTCSSAPI::listNATOTones();
    std::cout << "NATO tones: " << nato_tones << std::endl;
    
    // Get tone information for 150.0 Hz
    std::string tone_info = CTCSSAPI::getToneInfo(150.0f);
    std::cout << "NATO tone info: " << tone_info << std::endl;
    
    return 0;
}
```

### Regional Safety Check

```cpp
#include "lib/ctcss_system.h"
#include <iostream>

void checkToneSafety(float frequency_hz, Region region) {
    // Check if tone is restricted in region
    std::string restrictions = CTCSSAPI::checkRegionalRestrictions(frequency_hz, region);
    std::cout << "Restrictions for " << frequency_hz << " Hz in region " << static_cast<int>(region) << ": " << restrictions << std::endl;
    
    // Get tone information
    std::string tone_info = CTCSSAPI::getToneInfo(frequency_hz);
    std::cout << "Tone info: " << tone_info << std::endl;
}

int main() {
    auto& ctcss_system = CTCSSSystem::getInstance();
    ctcss_system.initialize();
    
    // Check various tones in different regions
    checkToneSafety(100.0f, Region::UK);   // Should be restricted
    checkToneSafety(67.0f, Region::UK);    // Should be safe
    checkToneSafety(150.0f, Region::NATO); // Should be safe for NATO
    checkToneSafety(150.0f, Region::CIVILIAN); // Should be restricted for civilian
    
    return 0;
}
```

### Audio Processing Example

```cpp
#include "lib/ctcss_system.h"
#include <iostream>
#include <vector>

int main() {
    auto& ctcss_system = CTCSSSystem::getInstance();
    ctcss_system.initialize();
    
    // Generate CTCSS tone
    std::vector<float> tone_buffer;
    bool success = ctcss_system.generateCTCSSTone(
        100.0f,        // Frequency
        1000.0f,       // Duration (ms)
        48000.0f,      // Sample rate
        tone_buffer    // Output buffer
    );
    
    if (success) {
        std::cout << "Generated CTCSS tone with " << tone_buffer.size() << " samples" << std::endl;
    }
    
    // Detect tone in audio
    float detected_frequency;
    float confidence;
    bool tone_present = ctcss_system.detectCTCSSTone(
        tone_buffer,        // Input audio
        48000.0f,           // Sample rate
        detected_frequency, // Detected frequency
        confidence         // Detection confidence
    );
    
    if (tone_present) {
        std::cout << "Detected tone: " << detected_frequency << " Hz (confidence: " << confidence << ")" << std::endl;
    }
    
    return 0;
}
```

## Troubleshooting

### Common Issues

#### 1. Tone Not Detected
**Problem**: CTCSS tone not being detected
**Solutions**:
- Check tone frequency is valid
- Verify tone level is appropriate (-10 to -20 dB)
- Ensure tone tolerance is set correctly
- Check for power line interference

#### 2. Regional Restrictions
**Problem**: Tone restricted in region
**Solutions**:
- Use regional recommendations
- Avoid power line harmonics
- Check regional restrictions before setting tone

#### 3. Audio Quality Issues
**Problem**: Poor audio quality with CTCSS
**Solutions**:
- Adjust tone level (-10 to -20 dB)
- Check tone tolerance settings
- Verify audio processing chain

#### 4. Configuration Errors
**Problem**: Invalid configuration
**Solutions**:
- Validate configuration before setting
- Check parameter ranges
- Use configuration presets

### Error Codes

| Error Code | Description | Solution |
|------------|-------------|----------|
| `INVALID_TONE_FREQUENCY` | Tone frequency not in database | Use valid tone frequency |
| `REGIONAL_RESTRICTION` | Tone restricted in region | Use regional recommendations |
| `INVALID_CONFIGURATION` | Configuration parameters invalid | Validate configuration |
| `AUDIO_PROCESSING_ERROR` | Audio processing failed | Check audio format and parameters |

### Debug Information

#### Enable Debug Logging
```cpp
// Enable debug logging for CTCSS system
// This will provide detailed information about tone detection and processing
```

#### Get Statistics
```cpp
std::string stats = CTCSSAPI::getCTCSSStatistics();
std::cout << "CTCSS Statistics: " << stats << std::endl;
```

#### Reset Statistics
```cpp
std::string result = CTCSSAPI::resetCTCSSStatistics();
std::cout << "Statistics reset: " << result << std::endl;
```

## Best Practices

### 1. Regional Considerations
- **UK**: Avoid 100.0 Hz (2x 50Hz power)
- **US**: Avoid 120.0 Hz (2x 60Hz power)
- **EU**: Avoid 100.0 Hz (2x 50Hz power)
- **NATO**: Use 150.0 Hz standard

### 2. Tone Selection
- Use standard 39-tone series
- Avoid power line harmonics
- Consider regional restrictions
- Use appropriate tolerance settings

### 3. Configuration
- Use regional presets when possible
- Validate configuration before setting
- Monitor statistics for performance
- Use appropriate tone levels

### 4. Audio Processing
- Maintain proper tone levels
- Use appropriate sample rates
- Monitor detection confidence
- Handle errors gracefully

## Conclusion

The CTCSS system provides comprehensive support for Continuous Tone-Coded Squelch System functionality, including:

- **Complete tone database** with 39 standard tones
- **Regional restrictions** for power line interference
- **NATO military standards** with 150.0 Hz standard
- **Comprehensive API** for all CTCSS operations
- **Audio processing** for tone generation and detection
- **Configuration management** with regional presets
- **Statistics and monitoring** for performance tracking

This implementation follows international radio regulations and NATO military standards, ensuring compatibility with real-world radio systems while providing proper regional restrictions for power line frequency interference.
