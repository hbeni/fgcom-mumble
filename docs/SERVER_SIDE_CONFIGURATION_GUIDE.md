# Server-Side Configuration Guide

## Overview

This guide is for **server administrators only**. Radio models and preset channels are defined and managed on the server side through configuration files, and external applications can only read this information through the read-only API.

## Table of Contents

1. [Configuration Files](#configuration-files)
2. [Radio Model Configuration](#radio-model-configuration)
3. [Preset Channel Configuration](#preset-channel-configuration)
4. [API Access Control](#api-access-control)
5. [Examples](#examples)

## Configuration Files

### Radio Models Configuration
- **File**: `config/radio_models.json`
- **Purpose**: Defines all available radio models and their specifications
- **Access**: Server-side only (read-only for external applications)

### Preset Channels Configuration
- **File**: `config/preset_channels.json`
- **Purpose**: Defines preset channel configurations for radio models
- **Access**: Server-side only (read-only for external applications)

## Radio Model Configuration

### Configuration File Structure

```json
{
  "radio_models": {
    "MODEL_NAME": {
      "modelName": "MODEL_NAME",
      "manufacturer": "MANUFACTURER",
      "country": "COUNTRY",
      "alliance": "ALLIANCE",
      "era": "ERA",
      "usage": "USAGE",
      "frequencyStartMHz": 30.0,
      "frequencyEndMHz": 87.975,
      "channelSpacingKHz": 25.0,
      "totalChannels": 2319,
      "portablePowerWatts": 2.0,
      "vehiclePowerWatts": 20.0,
      "encryptionCapable": true,
      "gpsCapable": true,
      "dataCapable": true,
      "networkCapable": true,
      "advancedEncryption": true,
      "supportedModes": ["FM", "AM", "CW", "Digital"],
      "presetChannels": 0,
      "fmSensitivity": -116.0,
      "sinad": 12.0,
      "customProperties": {
        "weight": "2.5 kg",
        "battery_life": "12 hours",
        "antenna_connector": "BNC"
      }
    }
  }
}
```

### Radio Model Fields

#### Basic Information
- **modelName**: Unique model name
- **manufacturer**: Manufacturer name
- **country**: Country of origin
- **alliance**: Military alliance (NATO, Warsaw Pact, etc.)
- **era**: Historical era (Cold War, Modern, etc.)
- **usage**: Intended usage (Tactical, Operational, etc.)

#### Frequency Specifications
- **frequencyStartMHz**: Start frequency in MHz
- **frequencyEndMHz**: End frequency in MHz
- **channelSpacingKHz**: Channel spacing in kHz
- **totalChannels**: Total number of channels

#### Power Specifications
- **portablePowerWatts**: Portable power in watts
- **vehiclePowerWatts**: Vehicle-mounted power in watts

#### Capabilities
- **encryptionCapable**: Encryption capability
- **gpsCapable**: GPS capability
- **dataCapable**: Data transmission capability
- **networkCapable**: Network capability
- **advancedEncryption**: Advanced encryption capability

#### Technical Specifications
- **fmSensitivity**: FM sensitivity in dBm
- **sinad**: SINAD in dB
- **supportedModes**: Supported modulation modes
- **presetChannels**: Number of preset channels (0 if none)

#### Custom Properties
- **customProperties**: Additional properties (weight, battery life, etc.)

## Preset Channel Configuration

### Configuration File Structure

```json
{
  "preset_channels": {
    "RADIO_MODEL": {
      "modelName": "RADIO_MODEL",
      "totalPresets": 99,
      "presets": {
        "PRESET_NUMBER": {
          "presetNumber": 1,
          "channelNumber": 100,
          "frequency": 31.25,
          "label": "Tactical 1",
          "description": "Primary tactical frequency",
          "modulationMode": "FM",
          "powerWatts": 2.0,
          "isActive": true,
          "customProperties": {
            "priority": "high",
            "encryption": "enabled",
            "gps": "enabled"
          }
        }
      }
    }
  }
}
```

### Preset Channel Fields

#### Basic Information
- **presetNumber**: Preset number (1-99)
- **channelNumber**: Channel number
- **frequency**: Frequency in MHz
- **label**: Preset label
- **description**: Preset description

#### Technical Specifications
- **modulationMode**: Modulation mode (FM, AM, CW, Digital)
- **powerWatts**: Power level in watts
- **isActive**: Whether preset is active

#### Custom Properties
- **customProperties**: Additional properties (priority, encryption, GPS, etc.)

## API Access Control

### Read-Only API for External Applications

```cpp
// External applications can only READ preset channel information
class PresetChannelClient {
public:
    // READ-ONLY operations
    APIResponse getPreset(const std::string& radioModel, int presetNumber);
    APIResponse getAllPresets(const std::string& radioModel);
    APIResponse searchPresets(const std::string& radioModel, const std::string& query);
    APIResponse getPresetsByFrequency(const std::string& radioModel, double frequency, double tolerance = 0.001);
    APIResponse getPresetsByChannel(const std::string& radioModel, int channelNumber);
    APIResponse getActivePresets(const std::string& radioModel);
    APIResponse getInactivePresets(const std::string& radioModel);
    
    // READ-ONLY statistics
    APIResponse getPresetStatistics(const std::string& radioModel);
    APIResponse getPresetCount(const std::string& radioModel);
    APIResponse getActivePresetCount(const std::string& radioModel);
    
    // READ-ONLY export
    APIResponse exportPresetChannelsToJSON(const std::string& radioModel);
    APIResponse exportPresetChannelsToCSV(const std::string& radioModel);
};
```

### API Endpoints (READ-ONLY)

```http
# Get preset information (READ-ONLY)
GET /api/v1/preset-channels/{radioModel}/{presetNumber}

# Get all presets for a radio model (READ-ONLY)
GET /api/v1/preset-channels/{radioModel}

# Search presets (READ-ONLY)
GET /api/v1/preset-channels/{radioModel}/search?q={query}

# Get preset statistics (READ-ONLY)
GET /api/v1/preset-channels/{radioModel}/statistics

# Export presets (READ-ONLY)
GET /api/v1/preset-channels/{radioModel}/export/json
GET /api/v1/preset-channels/{radioModel}/export/csv
```

## Examples

### Complete Server Configuration

#### 1. Radio Models Configuration (`config/radio_models.json`)

```json
{
  "radio_models": {
    "AN/PRC-152": {
      "modelName": "AN/PRC-152",
      "manufacturer": "USA",
      "country": "USA",
      "alliance": "NATO",
      "era": "Modern",
      "usage": "Multiband Inter/Intra Team Radio II",
      "frequencyStartMHz": 30.0,
      "frequencyEndMHz": 87.975,
      "channelSpacingKHz": 12.5,
      "totalChannels": 4638,
      "portablePowerWatts": 2.0,
      "vehiclePowerWatts": 20.0,
      "encryptionCapable": true,
      "gpsCapable": true,
      "dataCapable": true,
      "networkCapable": true,
      "advancedEncryption": true,
      "supportedModes": ["FM", "AM", "CW", "Digital"],
      "presetChannels": 99,
      "fmSensitivity": -116.0,
      "sinad": 12.0,
      "customProperties": {
        "weight": "2.7 kg",
        "battery_life": "15 hours",
        "antenna_connector": "BNC"
      }
    },
    "R-123 Magnolia": {
      "modelName": "R-123 Magnolia",
      "manufacturer": "Soviet Union",
      "country": "USSR",
      "alliance": "Warsaw Pact",
      "era": "Cold War",
      "usage": "Tank and Armored Vehicle Radio",
      "frequencyStartMHz": 20.0,
      "frequencyEndMHz": 51.5,
      "channelSpacingKHz": 25.0,
      "totalChannels": 1260,
      "portablePowerWatts": 0.0,
      "vehiclePowerWatts": 15.0,
      "encryptionCapable": false,
      "gpsCapable": false,
      "dataCapable": false,
      "networkCapable": false,
      "advancedEncryption": false,
      "supportedModes": ["FM"],
      "presetChannels": 4,
      "fmSensitivity": -110.0,
      "sinad": 10.0,
      "customProperties": {
        "weight": "3.5 kg",
        "battery_life": "N/A (Vehicle mounted)",
        "antenna_connector": "BNC"
      }
    }
  }
}
```

#### 2. Preset Channels Configuration (`config/preset_channels.json`)

```json
{
  "preset_channels": {
    "AN/PRC-152": {
      "modelName": "AN/PRC-152",
      "totalPresets": 99,
      "presets": {
        "1": {
          "presetNumber": 1,
          "channelNumber": 100,
          "frequency": 31.25,
          "label": "Tactical 1",
          "description": "Primary tactical frequency",
          "modulationMode": "FM",
          "powerWatts": 2.0,
          "isActive": true,
          "customProperties": {
            "priority": "high",
            "encryption": "enabled",
            "gps": "enabled"
          }
        },
        "2": {
          "presetNumber": 2,
          "channelNumber": 200,
          "frequency": 32.5,
          "label": "Tactical 2",
          "description": "Secondary tactical frequency",
          "modulationMode": "FM",
          "powerWatts": 2.0,
          "isActive": true,
          "customProperties": {
            "priority": "medium",
            "encryption": "enabled",
            "gps": "enabled"
          }
        },
        "3": {
          "presetNumber": 3,
          "channelNumber": 300,
          "frequency": 33.75,
          "label": "Emergency",
          "description": "Emergency frequency",
          "modulationMode": "FM",
          "powerWatts": 2.0,
          "isActive": true,
          "customProperties": {
            "priority": "critical",
            "encryption": "disabled",
            "gps": "enabled"
          }
        }
      }
    },
    "R-123 Magnolia": {
      "modelName": "R-123 Magnolia",
      "totalPresets": 4,
      "presets": {
        "1": {
          "presetNumber": 1,
          "channelNumber": 50,
          "frequency": 21.25,
          "label": "Tactical 1",
          "description": "Primary tactical frequency",
          "modulationMode": "FM",
          "powerWatts": 15.0,
          "isActive": true,
          "customProperties": {
            "priority": "high",
            "encryption": "disabled",
            "gps": "disabled"
          }
        },
        "2": {
          "presetNumber": 2,
          "channelNumber": 100,
          "frequency": 22.5,
          "label": "Tactical 2",
          "description": "Secondary tactical frequency",
          "modulationMode": "FM",
          "powerWatts": 15.0,
          "isActive": true,
          "customProperties": {
            "priority": "medium",
            "encryption": "disabled",
            "gps": "disabled"
          }
        }
      }
    }
  }
}
```

### External Client Usage (READ-ONLY)

```cpp
#include "lib/preset_channel_config_loader.h"

using namespace PresetChannelConfig;

// External client (READ-ONLY ACCESS)
class ExternalClient {
private:
    PresetChannelConfigLoader& configLoader;
    
public:
    ExternalClient() : configLoader(PresetChannelConfigLoader::getInstance()) {
        // Initialize with read-only access
        configLoader.initialize("../../config/preset_channels.json");
    }
    
    // Get preset information (READ-ONLY)
    void getPresetInfo(const std::string& radioModel, int presetNumber) {
        auto preset = configLoader.getPresetChannel(radioModel, presetNumber);
        if (preset.presetNumber != 0) {
            std::cout << "Preset: " << preset.label << " - " << preset.description << std::endl;
            std::cout << "Frequency: " << preset.frequency << " MHz" << std::endl;
            std::cout << "Channel: " << preset.channelNumber << std::endl;
            std::cout << "Modulation: " << preset.modulationMode << std::endl;
            std::cout << "Power: " << preset.powerWatts << "W" << std::endl;
            std::cout << "Active: " << (preset.isActive ? "Yes" : "No") << std::endl;
        }
    }
    
    // Get all presets for a radio model (READ-ONLY)
    void getAllPresets(const std::string& radioModel) {
        auto presets = configLoader.getAllPresetChannels(radioModel);
        std::cout << "Presets for " << radioModel << ":" << std::endl;
        for (const auto& preset : presets) {
            std::cout << "  " << preset.presetNumber << ": " << preset.label 
                      << " (" << preset.frequency << " MHz)" << std::endl;
        }
    }
    
    // Search presets (READ-ONLY)
    void searchPresets(const std::string& radioModel, const std::string& query) {
        auto results = configLoader.searchPresetChannels(radioModel, query);
        std::cout << "Search results for '" << query << "':" << std::endl;
        for (const auto& preset : results) {
            std::cout << "  " << preset.presetNumber << ": " << preset.label 
                      << " (" << preset.frequency << " MHz)" << std::endl;
        }
    }
    
    // Get preset statistics (READ-ONLY)
    void getPresetStatistics(const std::string& radioModel) {
        int totalPresets = configLoader.getPresetCount(radioModel);
        int activePresets = configLoader.getActivePresetCount(radioModel);
        int inactivePresets = configLoader.getInactivePresetCount(radioModel);
        double frequencyRange = configLoader.getPresetFrequencyRange(radioModel);
        
        std::cout << "Preset Statistics for " << radioModel << ":" << std::endl;
        std::cout << "  Total Presets: " << totalPresets << std::endl;
        std::cout << "  Active Presets: " << activePresets << std::endl;
        std::cout << "  Inactive Presets: " << inactivePresets << std::endl;
        std::cout << "  Frequency Range: " << frequencyRange << " MHz" << std::endl;
    }
    
    // Export presets (READ-ONLY)
    void exportPresets(const std::string& radioModel) {
        std::string json = configLoader.exportPresetChannelsToJSON(radioModel);
        std::string csv = configLoader.exportPresetChannelsToCSV(radioModel);
        
        std::cout << "JSON Export:" << std::endl;
        std::cout << json << std::endl;
        
        std::cout << "CSV Export:" << std::endl;
        std::cout << csv << std::endl;
    }
};

// Usage example
int main() {
    ExternalClient client;
    
    // Get AN/PRC-152 preset information
    client.getPresetInfo("AN/PRC-152", 1);
    
    // Get all presets for AN/PRC-152
    client.getAllPresets("AN/PRC-152");
    
    // Search for tactical presets
    client.searchPresets("AN/PRC-152", "tactical");
    
    // Get preset statistics
    client.getPresetStatistics("AN/PRC-152");
    
    // Export presets
    client.exportPresets("AN/PRC-152");
    
    return 0;
}
```

## Security Considerations

### API Access Control

1. **Authentication Required**: All API endpoints require valid API keys
2. **Read-Only Access**: External applications cannot modify radio models or presets
3. **Rate Limiting**: Built-in protection against abuse
4. **Server-Side Only**: Radio model and preset creation/modification is server-side only

### Server-Side Security

1. **Admin Access Only**: Configuration requires server administrator privileges
2. **Validation**: All configurations are validated before being loaded
3. **Backup**: Regular backups of configuration files
4. **Audit Logging**: All server-side changes are logged

## Troubleshooting

### Common Issues

1. **Configuration File Not Found**: Check file paths and permissions
2. **Invalid JSON**: Validate JSON syntax
3. **Missing Fields**: Ensure all required fields are present
4. **API Access Denied**: Check API key validity and permissions

### Debugging

1. **Check Configuration Files**: Verify JSON syntax and structure
2. **Validate Fields**: Ensure all required fields are present
3. **Test API Endpoints**: Test API endpoints manually
4. **Check Logs**: Review server logs for error messages

## Support

For additional support and documentation:

- **Radio Model Configuration**: [RADIO_MODEL_CONFIGURATION_GUIDE.md](RADIO_MODEL_CONFIGURATION_GUIDE.md)
- **Preset Channel API**: [PRESET_CHANNEL_API_DOCUMENTATION.md](PRESET_CHANNEL_API_DOCUMENTATION.md)
- **Radio Era Classification**: [RADIO_ERA_CLASSIFICATION.md](RADIO_ERA_CLASSIFICATION.md)
- **Examples**: [PRESET_CHANNEL_EXAMPLES.md](PRESET_CHANNEL_EXAMPLES.md)
