# Preset Channel Examples

## Overview

This document provides comprehensive examples of how to use the Preset Channel API for managing radio preset channels, specifically focusing on the AN/PRC-152's 99 presets and other radio models.

## Table of Contents

1. [Basic Usage](#basic-usage)
2. [AN/PRC-152 Examples](#anprc-152-examples)
3. [API Examples](#api-examples)
4. [Advanced Features](#advanced-features)
5. [Integration Examples](#integration-examples)
6. [Troubleshooting](#troubleshooting)

## Basic Usage

### Creating Preset Channels

```cpp
#include "lib/preset_channel_api.h"
#include "lib/nato_vhf_equipment.h"

using namespace PresetChannelAPI;
using namespace NATO_VHF;

// Initialize the preset channel system
PresetChannelManager::initialize();

// Create a preset for AN/PRC-152
PresetChannelInfo preset;
preset.presetNumber = 1;
preset.channelNumber = 100;
preset.frequency = 30.125;  // 30.125 MHz
preset.label = "Tactical 1";
preset.description = "Primary tactical frequency";
preset.isActive = true;

// Set the preset
PresetChannelManager::setPresetChannel("AN/PRC-152", 1, 100, "Tactical 1", "Primary tactical frequency");
```

### Using the Builder Pattern

```cpp
// Use the builder pattern for easier preset creation
PresetChannelBuilder builder;
PresetChannelInfo preset = builder
    .setPresetNumber(1)
    .setChannelNumber(100)
    .setFrequency(30.125)
    .setLabel("Tactical 1")
    .setDescription("Primary tactical frequency")
    .setActive(true)
    .addCustomProperty("encryption", "AES-256")
    .addCustomProperty("power", "high")
    .build();

// Validate the preset
if (builder.validate()) {
    PresetChannelManager::setPresetChannel("AN/PRC-152", preset.presetNumber, preset.channelNumber, 
                                          preset.label, preset.description);
}
```

## AN/PRC-152 Examples

### Setting Up Tactical Presets

```cpp
// Create tactical presets for AN/PRC-152
std::vector<std::tuple<int, int, std::string, std::string>> tacticalPresets = {
    {1, 100, "Tactical 1", "Primary tactical frequency"},
    {2, 200, "Tactical 2", "Secondary tactical frequency"},
    {3, 300, "Tactical 3", "Tertiary tactical frequency"},
    {4, 400, "Emergency", "Emergency frequency"},
    {5, 500, "Training", "Training frequency"}
};

for (const auto& preset : tacticalPresets) {
    int presetNum = std::get<0>(preset);
    int channelNum = std::get<1>(preset);
    std::string label = std::get<2>(preset);
    std::string description = std::get<3>(preset);
    
    PresetChannelManager::setPresetChannel("AN/PRC-152", presetNum, channelNum, label, description);
}
```

### Setting Up Emergency Presets

```cpp
// Create emergency presets for AN/PRC-152
std::vector<std::tuple<int, int, std::string, std::string>> emergencyPresets = {
    {10, 1000, "Emergency 1", "Primary emergency frequency"},
    {11, 1100, "Emergency 2", "Secondary emergency frequency"},
    {12, 1200, "Emergency 3", "Tertiary emergency frequency"},
    {13, 1300, "Emergency 4", "Quaternary emergency frequency"},
    {14, 1400, "Emergency 5", "Quinary emergency frequency"}
};

for (const auto& preset : emergencyPresets) {
    int presetNum = std::get<0>(preset);
    int channelNum = std::get<1>(preset);
    std::string label = std::get<2>(preset);
    std::string description = std::get<3>(preset);
    
    PresetChannelManager::setPresetChannel("AN/PRC-152", presetNum, channelNum, label, description);
}
```

### Setting Up Training Presets

```cpp
// Create training presets for AN/PRC-152
std::vector<std::tuple<int, int, std::string, std::string>> trainingPresets = {
    {20, 2000, "Training 1", "Primary training frequency"},
    {21, 2100, "Training 2", "Secondary training frequency"},
    {22, 2200, "Training 3", "Tertiary training frequency"},
    {23, 2300, "Training 4", "Quaternary training frequency"},
    {24, 2400, "Training 5", "Quinary training frequency"}
};

for (const auto& preset : trainingPresets) {
    int presetNum = std::get<0>(preset);
    int channelNum = std::get<1>(preset);
    std::string label = std::get<2>(preset);
    std::string description = std::get<3>(preset);
    
    PresetChannelManager::setPresetChannel("AN/PRC-152", presetNum, channelNum, label, description);
}
```

### Setting Up Test Presets

```cpp
// Create test presets for AN/PRC-152
std::vector<std::tuple<int, int, std::string, std::string>> testPresets = {
    {30, 3000, "Test 1", "Primary test frequency"},
    {31, 3100, "Test 2", "Secondary test frequency"},
    {32, 3200, "Test 3", "Tertiary test frequency"},
    {33, 3300, "Test 4", "Quaternary test frequency"},
    {34, 3400, "Test 5", "Quinary test frequency"}
};

for (const auto& preset : testPresets) {
    int presetNum = std::get<0>(preset);
    int channelNum = std::get<1>(preset);
    std::string label = std::get<2>(preset);
    std::string description = std::get<3>(preset);
    
    PresetChannelManager::setPresetChannel("AN/PRC-152", presetNum, channelNum, label, description);
}
```

## API Examples

### RESTful API Usage

#### Create Preset
```bash
curl -X POST http://localhost:8080/api/v1/preset-channels/AN/PRC-152 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_api_key" \
  -d '{
    "presetNumber": 1,
    "channelNumber": 100,
    "frequency": 30.125,
    "label": "Tactical 1",
    "description": "Primary tactical frequency",
    "isActive": true,
    "customProperties": {
      "encryption": "AES-256",
      "power": "high"
    }
  }'
```

#### Get Preset
```bash
curl -X GET http://localhost:8080/api/v1/preset-channels/AN/PRC-152/1 \
  -H "Authorization: Bearer your_api_key"
```

#### Update Preset
```bash
curl -X PUT http://localhost:8080/api/v1/preset-channels/AN/PRC-152/1 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_api_key" \
  -d '{
    "label": "Updated Tactical 1",
    "description": "Updated primary tactical frequency",
    "isActive": true
  }'
```

#### Delete Preset
```bash
curl -X DELETE http://localhost:8080/api/v1/preset-channels/AN/PRC-152/1 \
  -H "Authorization: Bearer your_api_key"
```

#### Get All Presets
```bash
curl -X GET http://localhost:8080/api/v1/preset-channels/AN/PRC-152 \
  -H "Authorization: Bearer your_api_key"
```

### Search and Filtering

#### Search Presets
```bash
curl -X GET "http://localhost:8080/api/v1/preset-channels/AN/PRC-152/search?q=tactical" \
  -H "Authorization: Bearer your_api_key"
```

#### Get Presets by Frequency
```bash
curl -X GET "http://localhost:8080/api/v1/preset-channels/AN/PRC-152/frequency/30.125?tolerance=0.001" \
  -H "Authorization: Bearer your_api_key"
```

#### Get Presets by Channel
```bash
curl -X GET http://localhost:8080/api/v1/preset-channels/AN/PRC-152/channel/100 \
  -H "Authorization: Bearer your_api_key"
```

#### Get Active Presets
```bash
curl -X GET http://localhost:8080/api/v1/preset-channels/AN/PRC-152/active \
  -H "Authorization: Bearer your_api_key"
```

#### Get Inactive Presets
```bash
curl -X GET http://localhost:8080/api/v1/preset-channels/AN/PRC-152/inactive \
  -H "Authorization: Bearer your_api_key"
```

### Statistics

#### Get Preset Statistics
```bash
curl -X GET http://localhost:8080/api/v1/preset-channels/AN/PRC-152/statistics \
  -H "Authorization: Bearer your_api_key"
```

#### Get Preset Count
```bash
curl -X GET http://localhost:8080/api/v1/preset-channels/AN/PRC-152/count \
  -H "Authorization: Bearer your_api_key"
```

#### Get Active Preset Count
```bash
curl -X GET http://localhost:8080/api/v1/preset-channels/AN/PRC-152/count/active \
  -H "Authorization: Bearer your_api_key"
```

#### Get Inactive Preset Count
```bash
curl -X GET http://localhost:8080/api/v1/preset-channels/AN/PRC-152/count/inactive \
  -H "Authorization: Bearer your_api_key"
```

### Export/Import

#### Export Presets
```bash
curl -X POST http://localhost:8080/api/v1/preset-channels/AN/PRC-152/export \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_api_key" \
  -d '{
    "filePath": "an_prc152_presets.json"
  }'
```

#### Import Presets
```bash
curl -X POST http://localhost:8080/api/v1/preset-channels/AN/PRC-152/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_api_key" \
  -d '{
    "filePath": "imported_presets.json",
    "overwrite": false
  }'
```

#### Export to JSON
```bash
curl -X GET http://localhost:8080/api/v1/preset-channels/AN/PRC-152/export/json \
  -H "Authorization: Bearer your_api_key"
```

#### Import from JSON
```bash
curl -X POST http://localhost:8080/api/v1/preset-channels/AN/PRC-152/import/json \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_api_key" \
  -d '{
    "jsonData": "[{\"presetNumber\":1,\"channelNumber\":100,\"frequency\":30.125,\"label\":\"Tactical 1\",\"description\":\"Primary tactical frequency\",\"isActive\":true,\"customProperties\":{}}]",
    "overwrite": false
  }'
```

## Advanced Features

### Preset Channel Management

```cpp
// Create a comprehensive preset management system
class PresetManager {
private:
    std::string radioModel;
    std::map<int, PresetChannelInfo> presets;
    
public:
    PresetManager(const std::string& model) : radioModel(model) {}
    
    // Add preset
    bool addPreset(int presetNumber, int channelNumber, const std::string& label, 
                   const std::string& description = "") {
        return PresetChannelManager::setPresetChannel(radioModel, presetNumber, channelNumber, label, description);
    }
    
    // Get preset
    PresetChannelInfo getPreset(int presetNumber) {
        return PresetChannelManager::getPresetChannel(radioModel, presetNumber);
    }
    
    // Update preset
    bool updatePreset(int presetNumber, const std::string& label, const std::string& description) {
        auto preset = getPreset(presetNumber);
        if (preset.presetNumber == 0) return false;
        
        return PresetChannelManager::setPresetChannel(radioModel, presetNumber, preset.channelNumber, label, description);
    }
    
    // Delete preset
    bool deletePreset(int presetNumber) {
        return PresetChannelManager::deletePresetChannel(radioModel, presetNumber);
    }
    
    // Get all presets
    std::vector<PresetChannelInfo> getAllPresets() {
        return PresetChannelManager::getAllPresetChannels(radioModel);
    }
    
    // Search presets
    std::vector<PresetChannelInfo> searchPresets(const std::string& query) {
        return PresetChannelManager::searchPresets(radioModel, query);
    }
    
    // Get presets by frequency
    std::vector<PresetChannelInfo> getPresetsByFrequency(double frequency, double tolerance = 0.001) {
        return PresetChannelManager::getPresetsByFrequency(radioModel, frequency, tolerance);
    }
    
    // Get presets by channel
    std::vector<PresetChannelInfo> getPresetsByChannel(int channelNumber) {
        return PresetChannelManager::getPresetsByChannel(radioModel, channelNumber);
    }
    
    // Get active presets
    std::vector<PresetChannelInfo> getActivePresets() {
        return PresetChannelManager::getActivePresets(radioModel);
    }
    
    // Get inactive presets
    std::vector<PresetChannelInfo> getInactivePresets() {
        return PresetChannelManager::getInactivePresets(radioModel);
    }
    
    // Get preset statistics
    int getPresetCount() {
        return PresetChannelManager::getPresetCount(radioModel);
    }
    
    int getActivePresetCount() {
        return PresetChannelManager::getActivePresetCount(radioModel);
    }
    
    int getInactivePresetCount() {
        return PresetChannelManager::getInactivePresetCount(radioModel);
    }
    
    // Export/Import
    std::string exportToJSON() {
        return PresetChannelManager::exportPresetsToJSON(radioModel);
    }
    
    bool importFromJSON(const std::string& jsonData, bool overwrite = false) {
        return PresetChannelManager::importPresetsFromJSON(radioModel, jsonData, overwrite);
    }
    
    std::string exportToCSV() {
        return PresetChannelManager::exportPresetsToCSV(radioModel);
    }
    
    bool importFromCSV(const std::string& csvData, bool overwrite = false) {
        return PresetChannelManager::importPresetsFromCSV(radioModel, csvData, overwrite);
    }
    
    // Backup/Restore
    std::string backup() {
        return PresetChannelManager::backupPresets(radioModel);
    }
    
    bool restore(const std::string& backupData) {
        return PresetChannelManager::restorePresets(radioModel, backupData);
    }
    
    bool clear() {
        return PresetChannelManager::clearPresets(radioModel);
    }
};
```

### Preset Channel Validation

```cpp
// Validate preset channels
class PresetValidator {
public:
    static bool validatePreset(const PresetChannelInfo& preset) {
        // Check preset number
        if (preset.presetNumber < 1 || preset.presetNumber > 99) {
            return false;
        }
        
        // Check channel number
        if (preset.channelNumber < 1 || preset.channelNumber > 4638) {
            return false;
        }
        
        // Check frequency
        if (preset.frequency < 30.0 || preset.frequency > 87.975) {
            return false;
        }
        
        // Check label
        if (preset.label.empty()) {
            return false;
        }
        
        return true;
    }
    
    static std::vector<std::string> getValidationErrors(const PresetChannelInfo& preset) {
        std::vector<std::string> errors;
        
        if (preset.presetNumber < 1 || preset.presetNumber > 99) {
            errors.push_back("Preset number must be between 1 and 99");
        }
        
        if (preset.channelNumber < 1 || preset.channelNumber > 4638) {
            errors.push_back("Channel number must be between 1 and 4638");
        }
        
        if (preset.frequency < 30.0 || preset.frequency > 87.975) {
            errors.push_back("Frequency must be between 30.0 and 87.975 MHz");
        }
        
        if (preset.label.empty()) {
            errors.push_back("Label cannot be empty");
        }
        
        return errors;
    }
};
```

### Preset Channel Comparison

```cpp
// Compare preset channels between radio models
class PresetComparator {
public:
    static std::map<std::string, std::string> comparePresets(const std::string& model1, const std::string& model2) {
        return PresetChannelManager::comparePresets(model1, model2);
    }
    
    static std::vector<PresetChannelInfo> getCommonPresets(const std::string& model1, const std::string& model2) {
        return PresetChannelManager::getCommonPresets(model1, model2);
    }
    
    static std::vector<PresetChannelInfo> getUniquePresets(const std::string& model1, const std::string& model2) {
        return PresetChannelManager::getUniquePresets(model1, model2);
    }
    
    static bool arePresetsCompatible(const PresetChannelInfo& preset1, const PresetChannelInfo& preset2) {
        // Check if presets are compatible
        if (preset1.channelNumber == preset2.channelNumber) {
            return true;
        }
        
        if (std::abs(preset1.frequency - preset2.frequency) < 0.001) {
            return true;
        }
        
        return false;
    }
};
```

## Integration Examples

### Python Integration

```python
import requests
import json

class PresetChannelClient:
    def __init__(self, base_url="http://localhost:8080/api/v1", api_key=""):
        self.base_url = base_url
        self.api_key = api_key
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
    
    def create_preset(self, radio_model, preset_number, channel_number, label, description=""):
        url = f"{self.base_url}/preset-channels/{radio_model}"
        data = {
            "presetNumber": preset_number,
            "channelNumber": channel_number,
            "label": label,
            "description": description,
            "isActive": True
        }
        response = requests.post(url, headers=self.headers, json=data)
        return response.json()
    
    def get_preset(self, radio_model, preset_number):
        url = f"{self.base_url}/preset-channels/{radio_model}/{preset_number}"
        response = requests.get(url, headers=self.headers)
        return response.json()
    
    def update_preset(self, radio_model, preset_number, **kwargs):
        url = f"{self.base_url}/preset-channels/{radio_model}/{preset_number}"
        response = requests.put(url, headers=self.headers, json=kwargs)
        return response.json()
    
    def delete_preset(self, radio_model, preset_number):
        url = f"{self.base_url}/preset-channels/{radio_model}/{preset_number}"
        response = requests.delete(url, headers=self.headers)
        return response.json()
    
    def get_all_presets(self, radio_model):
        url = f"{self.base_url}/preset-channels/{radio_model}"
        response = requests.get(url, headers=self.headers)
        return response.json()
    
    def search_presets(self, radio_model, query):
        url = f"{self.base_url}/preset-channels/{radio_model}/search"
        params = {"q": query}
        response = requests.get(url, headers=self.headers, params=params)
        return response.json()
    
    def get_presets_by_frequency(self, radio_model, frequency, tolerance=0.001):
        url = f"{self.base_url}/preset-channels/{radio_model}/frequency/{frequency}"
        params = {"tolerance": tolerance}
        response = requests.get(url, headers=self.headers, params=params)
        return response.json()
    
    def get_presets_by_channel(self, radio_model, channel_number):
        url = f"{self.base_url}/preset-channels/{radio_model}/channel/{channel_number}"
        response = requests.get(url, headers=self.headers)
        return response.json()
    
    def get_active_presets(self, radio_model):
        url = f"{self.base_url}/preset-channels/{radio_model}/active"
        response = requests.get(url, headers=self.headers)
        return response.json()
    
    def get_inactive_presets(self, radio_model):
        url = f"{self.base_url}/preset-channels/{radio_model}/inactive"
        response = requests.get(url, headers=self.headers)
        return response.json()
    
    def get_preset_statistics(self, radio_model):
        url = f"{self.base_url}/preset-channels/{radio_model}/statistics"
        response = requests.get(url, headers=self.headers)
        return response.json()
    
    def export_presets(self, radio_model, file_path):
        url = f"{self.base_url}/preset-channels/{radio_model}/export"
        data = {"filePath": file_path}
        response = requests.post(url, headers=self.headers, json=data)
        return response.json()
    
    def import_presets(self, radio_model, file_path, overwrite=False):
        url = f"{self.base_url}/preset-channels/{radio_model}/import"
        data = {"filePath": file_path, "overwrite": overwrite}
        response = requests.post(url, headers=self.headers, json=data)
        return response.json()

# Usage example
client = PresetChannelClient(api_key="your_api_key")

# Create tactical presets
tactical_presets = [
    (1, 100, "Tactical 1", "Primary tactical frequency"),
    (2, 200, "Tactical 2", "Secondary tactical frequency"),
    (3, 300, "Tactical 3", "Tertiary tactical frequency"),
    (4, 400, "Emergency", "Emergency frequency"),
    (5, 500, "Training", "Training frequency")
]

for preset_num, channel_num, label, description in tactical_presets:
    result = client.create_preset("AN/PRC-152", preset_num, channel_num, label, description)
    print(f"Created preset {preset_num}: {result}")

# Get all presets
all_presets = client.get_all_presets("AN/PRC-152")
print(f"Total presets: {len(all_presets['data']['presets'])}")

# Search presets
tactical_results = client.search_presets("AN/PRC-152", "tactical")
print(f"Tactical presets: {len(tactical_results['data']['results'])}")

# Get preset statistics
stats = client.get_preset_statistics("AN/PRC-152")
print(f"Preset statistics: {stats['data']}")
```

### JavaScript Integration

```javascript
class PresetChannelClient {
    constructor(baseUrl = "http://localhost:8080/api/v1", apiKey = "") {
        this.baseUrl = baseUrl;
        this.apiKey = apiKey;
        this.headers = {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${apiKey}`
        };
    }
    
    async createPreset(radioModel, presetNumber, channelNumber, label, description = "") {
        const url = `${this.baseUrl}/preset-channels/${radioModel}`;
        const data = {
            presetNumber,
            channelNumber,
            label,
            description,
            isActive: true
        };
        const response = await fetch(url, {
            method: "POST",
            headers: this.headers,
            body: JSON.stringify(data)
        });
        return await response.json();
    }
    
    async getPreset(radioModel, presetNumber) {
        const url = `${this.baseUrl}/preset-channels/${radioModel}/${presetNumber}`;
        const response = await fetch(url, {
            method: "GET",
            headers: this.headers
        });
        return await response.json();
    }
    
    async updatePreset(radioModel, presetNumber, updates) {
        const url = `${this.baseUrl}/preset-channels/${radioModel}/${presetNumber}`;
        const response = await fetch(url, {
            method: "PUT",
            headers: this.headers,
            body: JSON.stringify(updates)
        });
        return await response.json();
    }
    
    async deletePreset(radioModel, presetNumber) {
        const url = `${this.baseUrl}/preset-channels/${radioModel}/${presetNumber}`;
        const response = await fetch(url, {
            method: "DELETE",
            headers: this.headers
        });
        return await response.json();
    }
    
    async getAllPresets(radioModel) {
        const url = `${this.baseUrl}/preset-channels/${radioModel}`;
        const response = await fetch(url, {
            method: "GET",
            headers: this.headers
        });
        return await response.json();
    }
    
    async searchPresets(radioModel, query) {
        const url = `${this.baseUrl}/preset-channels/${radioModel}/search`;
        const params = new URLSearchParams({ q: query });
        const response = await fetch(`${url}?${params}`, {
            method: "GET",
            headers: this.headers
        });
        return await response.json();
    }
    
    async getPresetsByFrequency(radioModel, frequency, tolerance = 0.001) {
        const url = `${this.baseUrl}/preset-channels/${radioModel}/frequency/${frequency}`;
        const params = new URLSearchParams({ tolerance });
        const response = await fetch(`${url}?${params}`, {
            method: "GET",
            headers: this.headers
        });
        return await response.json();
    }
    
    async getPresetsByChannel(radioModel, channelNumber) {
        const url = `${this.baseUrl}/preset-channels/${radioModel}/channel/${channelNumber}`;
        const response = await fetch(url, {
            method: "GET",
            headers: this.headers
        });
        return await response.json();
    }
    
    async getActivePresets(radioModel) {
        const url = `${this.baseUrl}/preset-channels/${radioModel}/active`;
        const response = await fetch(url, {
            method: "GET",
            headers: this.headers
        });
        return await response.json();
    }
    
    async getInactivePresets(radioModel) {
        const url = `${this.baseUrl}/preset-channels/${radioModel}/inactive`;
        const response = await fetch(url, {
            method: "GET",
            headers: this.headers
        });
        return await response.json();
    }
    
    async getPresetStatistics(radioModel) {
        const url = `${this.baseUrl}/preset-channels/${radioModel}/statistics`;
        const response = await fetch(url, {
            method: "GET",
            headers: this.headers
        });
        return await response.json();
    }
    
    async exportPresets(radioModel, filePath) {
        const url = `${this.baseUrl}/preset-channels/${radioModel}/export`;
        const data = { filePath };
        const response = await fetch(url, {
            method: "POST",
            headers: this.headers,
            body: JSON.stringify(data)
        });
        return await response.json();
    }
    
    async importPresets(radioModel, filePath, overwrite = false) {
        const url = `${this.baseUrl}/preset-channels/${radioModel}/import`;
        const data = { filePath, overwrite };
        const response = await fetch(url, {
            method: "POST",
            headers: this.headers,
            body: JSON.stringify(data)
        });
        return await response.json();
    }
}

// Usage example
const client = new PresetChannelClient(apiKey: "your_api_key");

// Create tactical presets
const tacticalPresets = [
    [1, 100, "Tactical 1", "Primary tactical frequency"],
    [2, 200, "Tactical 2", "Secondary tactical frequency"],
    [3, 300, "Tactical 3", "Tertiary tactical frequency"],
    [4, 400, "Emergency", "Emergency frequency"],
    [5, 500, "Training", "Training frequency"]
];

for (const [presetNum, channelNum, label, description] of tacticalPresets) {
    const result = await client.createPreset("AN/PRC-152", presetNum, channelNum, label, description);
    console.log(`Created preset ${presetNum}:`, result);
}

// Get all presets
const allPresets = await client.getAllPresets("AN/PRC-152");
console.log(`Total presets: ${allPresets.data.presets.length}`);

// Search presets
const tacticalResults = await client.searchPresets("AN/PRC-152", "tactical");
console.log(`Tactical presets: ${tacticalResults.data.results.length}`);

// Get preset statistics
const stats = await client.getPresetStatistics("AN/PRC-152");
console.log("Preset statistics:", stats.data);
```

## Troubleshooting

### Common Issues

1. **Invalid Preset Numbers**
   - Ensure preset numbers are between 1 and 99 for AN/PRC-152
   - Check that preset numbers are within the valid range for other radio models

2. **Invalid Channel Numbers**
   - Ensure channel numbers are within the radio's frequency range
   - Check that channel numbers are valid for the specific radio model

3. **Invalid Frequencies**
   - Verify frequencies are within the radio's frequency range
   - Check that frequencies match the channel spacing

4. **API Authentication Errors**
   - Verify API key is correct and valid
   - Check that API key has proper permissions

5. **Network Connection Issues**
   - Ensure the API server is running
   - Check network connectivity and firewall settings

### Debugging Tips

1. **Use Validation Functions**
   ```cpp
   if (!PresetChannelManager::validatePresetChannel("AN/PRC-152", 1, 100)) {
       auto errors = PresetChannelManager::getPresetValidationErrors("AN/PRC-152", 1);
       for (const auto& error : errors) {
           std::cout << "Error: " << error << std::endl;
       }
   }
   ```

2. **Check Preset Status**
   ```cpp
   auto preset = PresetChannelManager::getPresetChannel("AN/PRC-152", 1);
   if (preset.presetNumber == 0) {
       std::cout << "Preset not found" << std::endl;
   } else {
       std::cout << "Preset found: " << preset.label << std::endl;
   }
   ```

3. **Verify API Responses**
   ```bash
   curl -v -X GET http://localhost:8080/api/v1/preset-channels/AN/PRC-152/1 \
     -H "Authorization: Bearer your_api_key"
   ```

4. **Check System Logs**
   - Review server logs for error messages
   - Check client logs for connection issues
   - Verify API endpoint availability

### Support

For additional support and documentation:

- **API Documentation**: [PRESET_CHANNEL_API_DOCUMENTATION.md](PRESET_CHANNEL_API_DOCUMENTATION.md)
- **Configuration Guide**: [RADIO_MODEL_CONFIGURATION_GUIDE.md](RADIO_MODEL_CONFIGURATION_GUIDE.md)
- **Troubleshooting**: [PRESET_CHANNEL_TROUBLESHOOTING.md](PRESET_CHANNEL_TROUBLESHOOTING.md)
