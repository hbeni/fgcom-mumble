# Server-Side Radio Configuration Guide

## Overview

This guide is for **server administrators only**. Radio models are defined and managed on the server side, and external applications can only read this information through the read-only API.

## Table of Contents

1. [Server-Side Configuration](#server-side-configuration)
2. [Radio Model Definition](#radio-model-definition)
3. [Preset Channel Management](#preset-channel-management)
4. [API Access Control](#api-access-control)
5. [Examples](#examples)

## Server-Side Configuration

### Initialization

```cpp
#include "lib/radio_model_config.h"
#include "lib/radio_model_api.h"

using namespace RadioModelConfig;
using namespace RadioModelAPI;

// Initialize the server-side configuration system
RadioModelConfigManager::initialize("server_radio_models.json");

// Initialize the API server (read-only for external clients)
RadioModelAPIServer::initialize("1.0.0");
```

### Adding Radio Models (SERVER-SIDE ONLY)

```cpp
// Create AN/PRC-152 model (SERVER-SIDE ONLY)
RadioModelInfo an_prc152;
an_prc152.modelName = "AN/PRC-152";
an_prc152.manufacturer = "USA";
an_prc152.country = "USA";
an_prc152.alliance = "NATO";
an_prc152.era = "Modern";
an_prc152.usage = "Multiband Inter/Intra Team Radio II";
an_prc152.frequencyStartMHz = 30.0;
an_prc152.frequencyEndMHz = 87.975;
an_prc152.channelSpacingKHz = 12.5;
an_prc152.totalChannels = 4638;
an_prc152.portablePowerWatts = 2.0;
an_prc152.vehiclePowerWatts = 20.0;
an_prc152.encryptionCapable = true;
an_prc152.gpsCapable = true;
an_prc152.dataCapable = true;
an_prc152.networkCapable = true;
an_prc152.advancedEncryption = true;
an_prc152.supportedModes = {"FM", "AM", "CW", "Digital"};
an_prc152.presetChannels = {"1", "100", "500", "1000"};

// Add to server configuration (SERVER-SIDE ONLY)
RadioModelConfigManager::addModel(an_prc152);
```

### Using Builder Pattern (SERVER-SIDE ONLY)

```cpp
// Create R-105M model using builder (SERVER-SIDE ONLY)
RadioModelBuilder builder;
RadioModelInfo r105m = builder
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
    .build();

// Validate and add (SERVER-SIDE ONLY)
if (builder.validate()) {
    RadioModelConfigManager::addModel(r105m);
}
```

## Radio Model Definition

### Server-Side Model Structure

```cpp
struct RadioModelInfo {
    std::string modelName;           // Unique model name
    std::string manufacturer;        // Manufacturer name
    std::string country;             // Country of origin
    std::string alliance;            // Military alliance (NATO, Warsaw Pact, etc.)
    std::string era;                 // Historical era (Cold War, Modern, etc.)
    std::string usage;               // Intended usage (Tactical, Operational, etc.)
    
    // Frequency specifications
    double frequencyStartMHz;        // Start frequency in MHz
    double frequencyEndMHz;              // End frequency in MHz
    double channelSpacingKHz;        // Channel spacing in kHz
    int totalChannels;               // Total number of channels
    
    // Power specifications
    double portablePowerWatts;        // Portable power in watts
    double vehiclePowerWatts;        // Vehicle-mounted power in watts
    
    // Capabilities
    bool encryptionCapable;          // Encryption capability
    bool gpsCapable;                 // GPS capability
    bool dataCapable;                // Data transmission capability
    bool networkCapable;             // Network capability
    bool advancedEncryption;         // Advanced encryption capability
    
    // Modes and features
    std::vector<std::string> supportedModes;    // Supported modes (FM, AM, CW, etc.)
    std::vector<std::string> presetChannels;   // Preset channel definitions
    std::map<std::string, std::string> customProperties;  // Custom properties
};
```

### Server-Side Model Management

```cpp
// Add model (SERVER-SIDE ONLY)
bool addModel(const RadioModelInfo& model);

// Update model (SERVER-SIDE ONLY)
bool updateModel(const std::string& modelName, const RadioModelInfo& model);

// Remove model (SERVER-SIDE ONLY)
bool removeModel(const std::string& modelName);

// Get model (SERVER-SIDE ONLY)
RadioModelInfo getModel(const std::string& modelName);

// Get all models (SERVER-SIDE ONLY)
std::vector<RadioModelInfo> getAllModels();
```

## Preset Channel Management

### Server-Side Preset Configuration

```cpp
// Set preset channels for AN/PRC-152 (SERVER-SIDE ONLY)
PresetChannelManager::setPresetChannel("AN/PRC-152", 1, 100, "Tactical 1", "Primary tactical frequency");
PresetChannelManager::setPresetChannel("AN/PRC-152", 2, 200, "Tactical 2", "Secondary tactical frequency");
PresetChannelManager::setPresetChannel("AN/PRC-152", 3, 300, "Emergency", "Emergency frequency");
PresetChannelManager::setPresetChannel("AN/PRC-152", 4, 400, "Training", "Training frequency");
PresetChannelManager::setPresetChannel("AN/PRC-152", 5, 500, "Test", "Test frequency");

// Set preset channels for R-105M (SERVER-SIDE ONLY)
PresetChannelManager::setPresetChannel("R-105M", 1, 50, "Tactical 1", "Primary tactical frequency");
PresetChannelManager::setPresetChannel("R-105M", 2, 100, "Tactical 2", "Secondary tactical frequency");
PresetChannelManager::setPresetChannel("R-105M", 3, 150, "Emergency", "Emergency frequency");
PresetChannelManager::setPresetChannel("R-105M", 4, 200, "Training", "Training frequency");
```

### Server-Side Preset Management

```cpp
// Get preset information (SERVER-SIDE ONLY)
auto preset = PresetChannelManager::getPresetChannel("AN/PRC-152", 1);

// Get all presets for a radio model (SERVER-SIDE ONLY)
auto allPresets = PresetChannelManager::getAllPresetChannels("AN/PRC-152");

// Search presets (SERVER-SIDE ONLY)
auto tacticalPresets = PresetChannelManager::searchPresets("AN/PRC-152", "tactical");

// Get preset statistics (SERVER-SIDE ONLY)
int totalPresets = PresetChannelManager::getPresetCount("AN/PRC-152");
int activePresets = PresetChannelManager::getActivePresetCount("AN/PRC-152");
```

## API Access Control

### Read-Only API for External Applications

```cpp
// External applications can only READ radio model information
class RadioModelClient {
public:
    // READ-ONLY operations
    APIResponse getModel(const std::string& modelName);
    APIResponse getAllModels();
    APIResponse searchModels(const std::string& query);
    APIResponse getModelsByCountry(const std::string& country);
    APIResponse getModelsByAlliance(const std::string& alliance);
    APIResponse getModelsByEra(const std::string& era);
    APIResponse getModelsByUsage(const std::string& usage);
    APIResponse getModelsByFrequencyRange(double startMHz, double endMHz);
    APIResponse getModelsByChannelSpacing(double spacingKHz);
    
    // READ-ONLY channel operations
    APIResponse getChannelFrequency(const std::string& modelName, int channel);
    APIResponse getFrequencyChannel(const std::string& modelName, double frequency);
    APIResponse getAllChannels(const std::string& modelName);
    APIResponse validateChannel(const std::string& modelName, int channel);
    APIResponse validateFrequency(const std::string& modelName, double frequency);
    
    // READ-ONLY preset operations
    APIResponse getPreset(const std::string& radioModel, int presetNumber);
    APIResponse getAllPresets(const std::string& radioModel);
    APIResponse searchPresets(const std::string& radioModel, const std::string& query);
    APIResponse getPresetsByFrequency(const std::string& radioModel, double frequency, double tolerance = 0.001);
    APIResponse getPresetsByChannel(const std::string& radioModel, int channelNumber);
    APIResponse getActivePresets(const std::string& radioModel);
    APIResponse getInactivePresets(const std::string& radioModel);
    
    // READ-ONLY statistics
    APIResponse getModelStatistics();
    APIResponse getPresetStatistics(const std::string& radioModel);
    
    // READ-ONLY export
    APIResponse exportToJSON(const std::vector<std::string>& modelNames = {});
};
```

### API Endpoints (READ-ONLY)

```http
# Get radio model information (READ-ONLY)
GET /api/v1/radio-models/{modelName}

# Get all radio models (READ-ONLY)
GET /api/v1/radio-models

# Search radio models (READ-ONLY)
GET /api/v1/radio-models/search?q={query}

# Get preset information (READ-ONLY)
GET /api/v1/preset-channels/{radioModel}/{presetNumber}

# Get all presets for a radio model (READ-ONLY)
GET /api/v1/preset-channels/{radioModel}

# Search presets (READ-ONLY)
GET /api/v1/preset-channels/{radioModel}/search?q={query}

# Get preset statistics (READ-ONLY)
GET /api/v1/preset-channels/{radioModel}/statistics
```

## Examples

### Complete Server Configuration

```cpp
#include "lib/radio_model_config.h"
#include "lib/radio_model_api.h"
#include "lib/preset_channel_api.h"

using namespace RadioModelConfig;
using namespace RadioModelAPI;
using namespace PresetChannelAPI;

// Server initialization
void initializeServer() {
    // Initialize radio model configuration
    RadioModelConfigManager::initialize("server_radio_models.json");
    
    // Initialize preset channel system
    PresetChannelManager::initialize();
    
    // Initialize API server
    RadioModelAPIServer::initialize("1.0.0");
    PresetChannelAPIServer::initialize("1.0.0");
}

// Configure AN/PRC-152 (SERVER-SIDE ONLY)
void configureANPRC152() {
    // Create radio model
    RadioModelInfo an_prc152;
    an_prc152.modelName = "AN/PRC-152";
    an_prc152.manufacturer = "USA";
    an_prc152.country = "USA";
    an_prc152.alliance = "NATO";
    an_prc152.era = "Modern";
    an_prc152.usage = "Multiband Inter/Intra Team Radio II";
    an_prc152.frequencyStartMHz = 30.0;
    an_prc152.frequencyEndMHz = 87.975;
    an_prc152.channelSpacingKHz = 12.5;
    an_prc152.totalChannels = 4638;
    an_prc152.portablePowerWatts = 2.0;
    an_prc152.vehiclePowerWatts = 20.0;
    an_prc152.encryptionCapable = true;
    an_prc152.gpsCapable = true;
    an_prc152.dataCapable = true;
    an_prc152.networkCapable = true;
    an_prc152.advancedEncryption = true;
    an_prc152.supportedModes = {"FM", "AM", "CW", "Digital"};
    
    // Add to server configuration
    RadioModelConfigManager::addModel(an_prc152);
    
    // Configure preset channels
    std::vector<std::tuple<int, int, std::string, std::string>> presets = {
        {1, 100, "Tactical 1", "Primary tactical frequency"},
        {2, 200, "Tactical 2", "Secondary tactical frequency"},
        {3, 300, "Emergency", "Emergency frequency"},
        {4, 400, "Training", "Training frequency"},
        {5, 500, "Test", "Test frequency"}
    };
    
    for (const auto& preset : presets) {
        int presetNum = std::get<0>(preset);
        int channelNum = std::get<1>(preset);
        std::string label = std::get<2>(preset);
        std::string description = std::get<3>(preset);
        
        PresetChannelManager::setPresetChannel("AN/PRC-152", presetNum, channelNum, label, description);
    }
}

// Configure R-105M (SERVER-SIDE ONLY)
void configureR105M() {
    // Create radio model using builder
    RadioModelBuilder builder;
    RadioModelInfo r105m = builder
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
        .build();
    
    // Add to server configuration
    if (builder.validate()) {
        RadioModelConfigManager::addModel(r105m);
    }
    
    // Configure preset channels
    std::vector<std::tuple<int, int, std::string, std::string>> presets = {
        {1, 50, "Tactical 1", "Primary tactical frequency"},
        {2, 100, "Tactical 2", "Secondary tactical frequency"},
        {3, 150, "Emergency", "Emergency frequency"},
        {4, 200, "Training", "Training frequency"}
    };
    
    for (const auto& preset : presets) {
        int presetNum = std::get<0>(preset);
        int channelNum = std::get<1>(preset);
        std::string label = std::get<2>(preset);
        std::string description = std::get<3>(preset);
        
        PresetChannelManager::setPresetChannel("R-105M", presetNum, channelNum, label, description);
    }
}

// Main server configuration
int main() {
    // Initialize server
    initializeServer();
    
    // Configure radio models
    configureANPRC152();
    configureR105M();
    
    // Start API server
    RadioModelAPIServer::start();
    PresetChannelAPIServer::start();
    
    return 0;
}
```

### External Client Usage (READ-ONLY)

```cpp
#include "lib/radio_model_api.h"
#include "lib/preset_channel_api.h"

using namespace RadioModelAPI;
using namespace PresetChannelAPI;

// External client (READ-ONLY ACCESS)
class ExternalClient {
private:
    RadioModelClient radioClient;
    PresetChannelClient presetClient;
    
public:
    ExternalClient(const std::string& apiKey) 
        : radioClient("http://localhost:8080/api", apiKey),
          presetClient("http://localhost:8080/api", apiKey) {}
    
    // Get radio model information (READ-ONLY)
    void getRadioModelInfo(const std::string& modelName) {
        auto response = radioClient.getModel(modelName);
        if (response.success) {
            std::cout << "Radio Model: " << response.data << std::endl;
        }
    }
    
    // Get all available radio models (READ-ONLY)
    void getAllRadioModels() {
        auto response = radioClient.getAllModels();
        if (response.success) {
            std::cout << "Available Models: " << response.data << std::endl;
        }
    }
    
    // Search radio models (READ-ONLY)
    void searchRadioModels(const std::string& query) {
        auto response = radioClient.searchModels(query);
        if (response.success) {
            std::cout << "Search Results: " << response.data << std::endl;
        }
    }
    
    // Get preset information (READ-ONLY)
    void getPresetInfo(const std::string& radioModel, int presetNumber) {
        auto response = presetClient.getPreset(radioModel, presetNumber);
        if (response.success) {
            std::cout << "Preset: " << response.data << std::endl;
        }
    }
    
    // Get all presets for a radio model (READ-ONLY)
    void getAllPresets(const std::string& radioModel) {
        auto response = presetClient.getAllPresets(radioModel);
        if (response.success) {
            std::cout << "All Presets: " << response.data << std::endl;
        }
    }
    
    // Search presets (READ-ONLY)
    void searchPresets(const std::string& radioModel, const std::string& query) {
        auto response = presetClient.searchPresets(radioModel, query);
        if (response.success) {
            std::cout << "Preset Search Results: " << response.data << std::endl;
        }
    }
};

// Usage example
int main() {
    ExternalClient client("your_api_key");
    
    // Get AN/PRC-152 information
    client.getRadioModelInfo("AN/PRC-152");
    
    // Get all available models
    client.getAllRadioModels();
    
    // Search for NATO models
    client.searchRadioModels("NATO");
    
    // Get preset information
    client.getPresetInfo("AN/PRC-152", 1);
    
    // Get all presets for AN/PRC-152
    client.getAllPresets("AN/PRC-152");
    
    // Search for tactical presets
    client.searchPresets("AN/PRC-152", "tactical");
    
    return 0;
}
```

## Security Considerations

### API Access Control

1. **Authentication Required**: All API endpoints require valid API keys
2. **Read-Only Access**: External applications cannot modify radio models or presets
3. **Rate Limiting**: Built-in protection against abuse
4. **Server-Side Only**: Radio model creation/modification is server-side only

### Server-Side Security

1. **Admin Access Only**: Radio model configuration requires server administrator privileges
2. **Validation**: All radio models are validated before being added to the system
3. **Backup**: Regular backups of radio model configurations
4. **Audit Logging**: All server-side changes are logged

## Troubleshooting

### Common Issues

1. **API Access Denied**: Check API key validity and permissions
2. **Model Not Found**: Verify radio model exists on server
3. **Preset Not Found**: Verify preset exists for the specified radio model
4. **Network Issues**: Check server connectivity and firewall settings

### Debugging

1. **Check Server Logs**: Review server logs for error messages
2. **Verify API Endpoints**: Test API endpoints manually
3. **Validate Configuration**: Ensure server-side configuration is correct
4. **Check Permissions**: Verify API key has proper permissions

## Support

For additional support and documentation:

- **API Documentation**: [RADIO_MODEL_API_REFERENCE.md](RADIO_MODEL_API_REFERENCE.md)
- **Preset Channel API**: [PRESET_CHANNEL_API_DOCUMENTATION.md](PRESET_CHANNEL_API_DOCUMENTATION.md)
- **Configuration Guide**: [RADIO_MODEL_CONFIGURATION_GUIDE.md](RADIO_MODEL_CONFIGURATION_GUIDE.md)
- **Examples**: [PRESET_CHANNEL_EXAMPLES.md](PRESET_CHANNEL_EXAMPLES.md)
