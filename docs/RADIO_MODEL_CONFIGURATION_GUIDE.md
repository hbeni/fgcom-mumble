# Radio Model Configuration Guide

## Overview

The FGCom-mumble system provides a comprehensive radio model configuration system that allows **server administrators** to define and manage radio equipment specifications. This guide covers how to use the configuration system, APIs, and **server-side** radio model management. **External applications can only read radio model information through the read-only API**.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Configuration System](#configuration-system)
3. [API Reference](#api-reference)
4. [Creating Custom Radio Models](#creating-custom-radio-models)
5. [Channel Numbering](#channel-numbering)
6. [Examples](#examples)
7. [Troubleshooting](#troubleshooting)

## Quick Start

### Server-Side Configuration (ADMINISTRATORS ONLY)

```cpp
#include "lib/radio_model_config.h"
#include "lib/radio_model_api.h"

using namespace RadioModelConfig;
using namespace RadioModelAPI;

// Initialize the configuration system (SERVER-SIDE ONLY)
RadioModelConfigManager::initialize("server_radio_models.json");

// Create a custom radio model (SERVER-SIDE ONLY)
RadioModelInfo myRadio;
myRadio.modelName = "Custom VHF Radio";
myRadio.manufacturer = "My Company";
myRadio.country = "USA";
myRadio.alliance = "NATO";
myRadio.era = "Modern";
myRadio.usage = "Tactical VHF";
myRadio.frequencyStartMHz = 30.0;
myRadio.frequencyEndMHz = 87.975;
myRadio.channelSpacingKHz = 25.0;
myRadio.portablePowerWatts = 2.0;
myRadio.vehiclePowerWatts = 20.0;
myRadio.encryptionCapable = true;
myRadio.gpsCapable = true;
myRadio.dataCapable = true;
myRadio.supportedModes = {"FM", "AM", "CW"};

// Add the model to the system (SERVER-SIDE ONLY)
RadioModelConfigManager::addModel(myRadio);
```

### External Application Usage (READ-ONLY)

```cpp
#include "lib/radio_model_api.h"

using namespace RadioModelAPI;

// Initialize the API client (READ-ONLY ACCESS)
RadioModelClient client("http://localhost:8080/api", "your_api_key");

// Get a radio model (READ-ONLY)
auto response = client.getModel("AN/PRC-152");
if (response.success) {
    // Use the radio model information
    std::cout << "Model: " << response.data << std::endl;
}

// Get all available models (READ-ONLY)
auto allModels = client.getAllModels();
if (allModels.success) {
    // Process available models
    std::cout << "Available models: " << allModels.data << std::endl;
}
```

### Using the Builder Pattern (SERVER-SIDE ONLY)

```cpp
// Use the builder pattern for easier model creation (SERVER-SIDE ONLY)
RadioModelBuilder builder;
RadioModelInfo radio = builder
    .setModelName("AN/PRC-152")
    .setManufacturer("USA")
    .setCountry("USA")
    .setAlliance("NATO")
    .setEra("Modern")
    .setUsage("Multiband Inter/Intra Team Radio II")
    .setFrequencyRange(30.0, 87.975)
    .setChannelSpacing(12.5)
    .setPortablePower(2.0)
    .setVehiclePower(20.0)
    .setEncryptionCapable(true)
    .setGPSCapable(true)
    .setDataCapable(true)
    .setNetworkCapable(true)
    .setAdvancedEncryption(true)
    .addSupportedMode("FM")
    .addSupportedMode("AM")
    .addSupportedMode("CW")
    .build();

// Validate the model (SERVER-SIDE ONLY)
if (builder.validate()) {
    RadioModelConfigManager::addModel(radio);
}
```

**Note:** The builder pattern is only available for server-side configuration. External applications cannot create or modify radio models.

## Configuration System

### Radio Model Specification

A radio model is defined by the `RadioModelSpec` structure:

```cpp
struct RadioModelSpec {
    std::string modelName;           // Unique model name
    std::string manufacturer;        // Manufacturer name
    std::string country;             // Country of origin
    std::string alliance;            // Military alliance (NATO, Warsaw Pact, etc.)
    std::string era;                 // Historical era (Cold War, Modern, etc.)
    std::string usage;               // Intended usage (Tactical, Operational, etc.)
    
    // Frequency specifications
    double frequencyStartMHz;        // Start frequency in MHz
    double frequencyEndMHz;         // End frequency in MHz
    double channelSpacingKHz;       // Channel spacing in kHz
    int totalChannels;              // Total number of channels
    
    // Power specifications
    double portablePowerWatts;       // Portable power in watts
    double vehiclePowerWatts;        // Vehicle-mounted power in watts
    
    // Capabilities
    bool encryptionCapable;          // Encryption capability
    bool gpsCapable;                 // GPS capability
    bool dataCapable;                // Data transmission capability
    bool networkCapable;             // Network capability
    bool advancedEncryption;         // Advanced encryption capability
    
    // Modes and features
    std::vector<std::string> supportedModes;    // Supported modes (FM, AM, CW, etc.)
    std::vector<std::string> presetChannels;    // Preset channel definitions
    std::map<std::string, std::string> customProperties;  // Custom properties
};
```

### Channel Numbering System

The system uses **logical sequential channel numbering**:

- **Channel 1**: Lowest frequency in the range
- **Channel 2**: Next frequency (start + channel spacing)
- **Channel N**: Highest frequency in the range

#### Examples:

**AN/PRC-77 (30.0-87.975 MHz, 25 kHz spacing):**
- Channel 1: 30.000 MHz
- Channel 2: 30.025 MHz
- Channel 3: 30.050 MHz
- ...
- Channel 2,319: 87.975 MHz

**AN/PRC-152 (30.0-87.975 MHz, 12.5 kHz spacing):**
- Channel 1: 30.000 MHz
- Channel 2: 30.0125 MHz
- Channel 3: 30.025 MHz
- ...
- Channel 4,638: 87.975 MHz

**R-105M (36.0-46.1 MHz, 25 kHz spacing):**
- Channel 1: 36.000 MHz
- Channel 2: 36.025 MHz
- Channel 3: 36.050 MHz
- ...
- Channel 404: 46.075 MHz

## API Reference

### Configuration Manager API

```cpp
// Initialization
RadioModelConfigManager::initialize("config.json");
RadioModelConfigManager::loadDefaultModels();

// Model management
bool addModel(const RadioModelSpec& model);
bool updateModel(const std::string& modelName, const RadioModelSpec& model);
bool removeModel(const std::string& modelName);
RadioModelSpec getModel(const std::string& modelName);
std::vector<std::string> getAllModelNames();
std::vector<RadioModelSpec> getAllModels();

// Model search and filtering
std::vector<std::string> getModelsByCountry(const std::string& country);
std::vector<std::string> getModelsByAlliance(const std::string& alliance);
std::vector<std::string> getModelsByEra(const std::string& era);
std::vector<std::string> getModelsByUsage(const std::string& usage);
std::vector<std::string> getModelsByFrequencyRange(double startMHz, double endMHz);
std::vector<std::string> getModelsByChannelSpacing(double spacingKHz);

// Model validation
bool validateModel(const RadioModelSpec& model);
std::vector<std::string> getValidationErrors(const RadioModelSpec& model);

// Export/Import
bool exportModels(const std::string& filePath, const std::vector<std::string>& modelNames = {});
bool importModels(const std::string& filePath, bool overwrite = false);
std::string exportToJSON(const std::vector<std::string>& modelNames = {});
bool importFromJSON(const std::string& jsonData, bool overwrite = false);
```

### Radio Model API

```cpp
// Model operations
APIResponse createModel(const RadioModelInfo& modelInfo);
APIResponse updateModel(const std::string& modelName, const RadioModelInfo& modelInfo);
APIResponse deleteModel(const std::string& modelName);
APIResponse getModel(const std::string& modelName);
APIResponse getAllModels();

// Search operations
APIResponse searchModels(const std::string& query);
APIResponse getModelsByCountry(const std::string& country);
APIResponse getModelsByAlliance(const std::string& alliance);
APIResponse getModelsByEra(const std::string& era);
APIResponse getModelsByUsage(const std::string& usage);

// Channel operations
APIResponse getChannelFrequency(const std::string& modelName, int channel);
APIResponse getFrequencyChannel(const std::string& modelName, double frequency);
APIResponse getAllChannels(const std::string& modelName);
APIResponse validateChannel(const std::string& modelName, int channel);
APIResponse validateFrequency(const std::string& modelName, double frequency);

// Configuration operations
APIResponse exportModels(const std::string& filePath, const std::vector<std::string>& modelNames = {});
APIResponse importModels(const std::string& filePath, bool overwrite = false);
APIResponse exportToJSON(const std::vector<std::string>& modelNames = {});
APIResponse importFromJSON(const std::string& jsonData, bool overwrite = false);
```

## Creating Custom Radio Models

### Method 1: Direct Specification

```cpp
RadioModelSpec customRadio;
customRadio.modelName = "My Custom Radio";
customRadio.manufacturer = "My Company";
customRadio.country = "USA";
customRadio.alliance = "NATO";
customRadio.era = "Modern";
customRadio.usage = "Tactical VHF";
customRadio.frequencyStartMHz = 30.0;
customRadio.frequencyEndMHz = 87.975;
customRadio.channelSpacingKHz = 25.0;
customRadio.calculateTotalChannels(); // Automatically calculate total channels
customRadio.portablePowerWatts = 2.0;
customRadio.vehiclePowerWatts = 20.0;
customRadio.encryptionCapable = true;
customRadio.gpsCapable = true;
customRadio.dataCapable = true;
customRadio.supportedModes = {"FM", "AM", "CW"};
customRadio.presetChannels = {"1", "100", "500", "1000"};

// Validate and add
if (RadioModelConfigManager::validateModel(customRadio)) {
    RadioModelConfigManager::addModel(customRadio);
}
```

### Method 2: Builder Pattern

```cpp
RadioModelBuilder builder;
RadioModelInfo radio = builder
    .setModelName("Custom Tactical Radio")
    .setManufacturer("My Company")
    .setCountry("USA")
    .setAlliance("NATO")
    .setEra("Modern")
    .setUsage("Tactical VHF")
    .setFrequencyRange(30.0, 87.975)
    .setChannelSpacing(25.0)
    .setPortablePower(2.0)
    .setVehiclePower(20.0)
    .setEncryptionCapable(true)
    .setGPSCapable(true)
    .setDataCapable(true)
    .addSupportedMode("FM")
    .addSupportedMode("AM")
    .addSupportedMode("CW")
    .addPresetChannel("1")
    .addPresetChannel("100")
    .addPresetChannel("500")
    .addPresetChannel("1000")
    .addCustomProperty("antenna_type", "dipole")
    .addCustomProperty("battery_life", "8_hours")
    .build();

// Validate and add
if (builder.validate()) {
    RadioModelConfigManager::addModel(radio);
}
```

### Method 3: JSON Configuration

```json
{
  "modelName": "Custom VHF Radio",
  "manufacturer": "My Company",
  "country": "USA",
  "alliance": "NATO",
  "era": "Modern",
  "usage": "Tactical VHF",
  "frequencyStartMHz": 30.0,
  "frequencyEndMHz": 87.975,
  "channelSpacingKHz": 25.0,
  "portablePowerWatts": 2.0,
  "vehiclePowerWatts": 20.0,
  "encryptionCapable": true,
  "gpsCapable": true,
  "dataCapable": true,
  "supportedModes": ["FM", "AM", "CW"],
  "presetChannels": ["1", "100", "500", "1000"],
  "customProperties": {
    "antenna_type": "dipole",
    "battery_life": "8_hours"
  }
}
```

## Channel Numbering

### Logical Sequential Numbering

The system uses logical sequential channel numbering that starts from 1 and increments by 1 for each channel spacing:

```
Channel N = Start Frequency + (N-1) × Channel Spacing
```

### Examples by Radio Type

#### NATO VHF Radios (25 kHz spacing)
- **AN/PRC-77**: 30.0-87.975 MHz → 2,319 channels
- **AN/PRC-148**: 30.0-87.975 MHz → 2,319 channels

#### NATO VHF Radios (12.5 kHz spacing)
- **AN/PRC-152**: 30.0-87.975 MHz → 4,638 channels

#### Soviet VHF Radios (25 kHz spacing)
- **R-105M**: 36.0-46.1 MHz → 404 channels
- **R-105D**: 20.0-35.9 MHz → 636 channels
- **R-107**: 20.0-52.0 MHz → 1,280 channels
- **R-123**: 20.0-51.5 MHz → 1,260 channels

### Channel Calculation Functions

```cpp
// Calculate frequency for a given channel
double frequency = RadioModelSpec::getFrequencyForChannel(channel);

// Calculate channel for a given frequency
int channel = RadioModelSpec::getChannelForFrequency(frequency);

// Get all channels
std::vector<double> channels = RadioModelSpec::getAllChannels();

// Validate frequency
bool valid = RadioModelSpec::isValidFrequency(frequency);
```

## Examples

### Example 1: Creating a Modern NATO Radio

```cpp
RadioModelBuilder builder;
RadioModelInfo modernNATO = builder
    .setModelName("AN/PRC-162")
    .setManufacturer("USA")
    .setCountry("USA")
    .setAlliance("NATO")
    .setEra("Modern")
    .setUsage("Advanced Tactical Radio")
    .setFrequencyRange(30.0, 87.975)
    .setChannelSpacing(12.5)
    .setPortablePower(2.0)
    .setVehiclePower(20.0)
    .setEncryptionCapable(true)
    .setGPSCapable(true)
    .setDataCapable(true)
    .setNetworkCapable(true)
    .setAdvancedEncryption(true)
    .addSupportedMode("FM")
    .addSupportedMode("AM")
    .addSupportedMode("CW")
    .addSupportedMode("Digital")
    .addPresetChannel("1")
    .addPresetChannel("100")
    .addPresetChannel("500")
    .addPresetChannel("1000")
    .addCustomProperty("encryption_type", "AES-256")
    .addCustomProperty("network_protocol", "IP")
    .build();

RadioModelConfigManager::addModel(modernNATO);
```

### Example 2: Creating a Soviet Cold War Radio

```cpp
RadioModelBuilder builder;
RadioModelInfo sovietRadio = builder
    .setModelName("R-105M")
    .setManufacturer("Soviet Union")
    .setCountry("USSR")
    .setAlliance("Warsaw Pact")
    .setEra("Cold War")
    .setUsage("Tactical VHF")
    .setFrequencyRange(36.0, 46.1)
    .setChannelSpacing(25.0)
    .setPortablePower(1.5)
    .setVehiclePower(20.0)
    .setEncryptionCapable(false)
    .setGPSCapable(false)
    .setDataCapable(false)
    .addSupportedMode("FM")
    .addSupportedMode("AM")
    .addPresetChannel("1")
    .addPresetChannel("100")
    .addPresetChannel("200")
    .addPresetChannel("300")
    .addCustomProperty("antenna_type", "whip")
    .addCustomProperty("battery_type", "lead_acid")
    .build();

RadioModelConfigManager::addModel(sovietRadio);
```

### Example 3: Creating a Civilian Radio

```cpp
RadioModelBuilder builder;
RadioModelInfo civilianRadio = builder
    .setModelName("Yaesu FT-857D")
    .setManufacturer("Yaesu")
    .setCountry("Japan")
    .setAlliance("Civilian")
    .setEra("Modern")
    .setUsage("Amateur Radio")
    .setFrequencyRange(1.8, 440.0)
    .setChannelSpacing(0.1)
    .setPortablePower(5.0)
    .setVehiclePower(100.0)
    .setEncryptionCapable(false)
    .setGPSCapable(false)
    .setDataCapable(true)
    .addSupportedMode("FM")
    .addSupportedMode("AM")
    .addSupportedMode("CW")
    .addSupportedMode("SSB")
    .addSupportedMode("Digital")
    .addPresetChannel("1")
    .addPresetChannel("10")
    .addPresetChannel("100")
    .addPresetChannel("1000")
    .addCustomProperty("antenna_type", "dipole")
    .addCustomProperty("power_source", "12V")
    .build();

RadioModelConfigManager::addModel(civilianRadio);
```

## Troubleshooting

### Common Issues

1. **Invalid Channel Numbers**
   - Ensure channel numbers are within the valid range (1 to totalChannels)
   - Check that the frequency range and channel spacing are correctly set

2. **Frequency Validation Errors**
   - Verify that frequencies are within the radio's frequency range
   - Check that the frequency range is properly defined

3. **Model Validation Failures**
   - Ensure all required fields are set
   - Check that power levels are positive
   - Verify that frequency ranges are logical

4. **Configuration Loading Errors**
   - Check that the configuration file exists and is readable
   - Verify that the JSON format is valid
   - Ensure that all required fields are present

### Debugging Tips

1. **Use Validation Functions**
   ```cpp
   if (!RadioModelConfigManager::validateModel(model)) {
       auto errors = RadioModelConfigManager::getValidationErrors(model);
       for (const auto& error : errors) {
           std::cout << "Error: " << error << std::endl;
       }
   }
   ```

2. **Check Model Specifications**
   ```cpp
   auto model = RadioModelConfigManager::getModel("My Radio");
   if (model.isValid()) {
       std::cout << "Model is valid" << std::endl;
   } else {
       std::cout << "Model is invalid" << std::endl;
   }
   ```

3. **Verify Channel Calculations**
   ```cpp
   int channel = model.getChannelForFrequency(30.025);
   double frequency = model.getFrequencyForChannel(2);
   std::cout << "Channel 2 = " << frequency << " MHz" << std::endl;
   ```

### Support

For additional support and documentation, refer to:
- [API Reference](API_REFERENCE_COMPLETE.md)
- [Configuration Examples](CONFIGURATION_EXAMPLES.md)
- [Troubleshooting Guide](TROUBLESHOOTING_GUIDE.md)
