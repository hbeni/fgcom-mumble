#include "radio_model_config_loader.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <cctype>

namespace RadioModelConfig {

RadioModelConfigLoader::RadioModelConfigLoader() 
    : initialized(false) {
}

RadioModelConfigLoader::~RadioModelConfigLoader() {
}

RadioModelConfigLoader& RadioModelConfigLoader::getInstance() {
    static RadioModelConfigLoader instance;
    return instance;
}

bool RadioModelConfigLoader::initialize(const std::string& configPath) {
    this->configPath = configPath;
    this->initialized = false;
    this->lastError.clear();
    
    // Try to load the configuration file
    if (!loadRadioModels()) {
        return false;
    }
    
    this->initialized = true;
    return true;
}

bool RadioModelConfigLoader::loadRadioModels() {
    if (configPath.empty()) {
        lastError = "Configuration path not set";
        return false;
    }
    
    std::ifstream file(configPath);
    if (!file.is_open()) {
        lastError = "Could not open configuration file: " + configPath;
        return false;
    }
    
    std::string content((std::istreambuf_iterator<char>(file)),
                       std::istreambuf_iterator<char>());
    file.close();
    
    // Simple JSON parsing (in a real implementation, you would use a proper JSON library)
    if (!parseJsonFile()) {
        return false;
    }
    
    return true;
}

bool RadioModelConfigLoader::parseJsonFile() {
    // This is a simplified JSON parser for demonstration
    // In a real implementation, you would use a proper JSON library like nlohmann/json
    
    std::ifstream file(configPath);
    if (!file.is_open()) {
        lastError = "Could not open configuration file for parsing";
        return false;
    }
    
    std::string line;
    std::string currentModel;
    std::map<std::string, std::string> modelData;
    bool inRadioModels = false;
    bool inModel = false;
    
    while (std::getline(file, line)) {
        // Remove whitespace
        line.erase(0, line.find_first_not_of(" \t"));
        line.erase(line.find_last_not_of(" \t") + 1);
        
        if (line.find("\"radio_models\":") != std::string::npos) {
            inRadioModels = true;
            continue;
        }
        
        if (inRadioModels && line.find("\"AN/PRC-") != std::string::npos) {
            // Extract model name
            size_t start = line.find("\"") + 1;
            size_t end = line.find("\"", start);
            if (end != std::string::npos) {
                currentModel = line.substr(start, end - start);
                inModel = true;
                modelData.clear();
            }
            continue;
        }
        
        if (inModel && line.find("}") != std::string::npos && line.find(",") == std::string::npos) {
            // End of model definition
            RadioModelInfo model = parseRadioModelFromJson(currentModel, modelData);
            radioModels[currentModel] = model;
            inModel = false;
            continue;
        }
        
        if (inModel) {
            // Parse model properties
            size_t colonPos = line.find(":");
            if (colonPos != std::string::npos) {
                std::string key = line.substr(0, colonPos);
                std::string value = line.substr(colonPos + 1);
                
                // Clean up key and value
                key.erase(0, key.find_first_not_of(" \t\""));
                key.erase(key.find_last_not_of(" \t\"") + 1);
                value.erase(0, value.find_first_not_of(" \t\""));
                value.erase(value.find_last_not_of(" \t\",") + 1);
                
                modelData[key] = value;
            }
        }
    }
    
    file.close();
    return true;
}

RadioModelInfo RadioModelConfigLoader::parseRadioModelFromJson(const std::string& modelName, const std::map<std::string, std::string>& modelData) {
    RadioModelInfo model;
    
    model.modelName = modelName;
    model.manufacturer = modelData.count("manufacturer") ? modelData.at("manufacturer") : "";
    model.country = modelData.count("country") ? modelData.at("country") : "";
    model.alliance = modelData.count("alliance") ? modelData.at("alliance") : "";
    model.era = modelData.count("era") ? modelData.at("era") : "";
    model.usage = modelData.count("usage") ? modelData.at("usage") : "";
    
    model.frequencyStartMHz = modelData.count("frequencyStartMHz") ? parseDouble(modelData.at("frequencyStartMHz")) : 0.0;
    model.frequencyEndMHz = modelData.count("frequencyEndMHz") ? parseDouble(modelData.at("frequencyEndMHz")) : 0.0;
    model.channelSpacingKHz = modelData.count("channelSpacingKHz") ? parseDouble(modelData.at("channelSpacingKHz")) : 0.0;
    model.totalChannels = modelData.count("totalChannels") ? parseInt(modelData.at("totalChannels")) : 0;
    
    model.portablePowerWatts = modelData.count("portablePowerWatts") ? parseDouble(modelData.at("portablePowerWatts")) : 0.0;
    model.vehiclePowerWatts = modelData.count("vehiclePowerWatts") ? parseDouble(modelData.at("vehiclePowerWatts")) : 0.0;
    
    model.encryptionCapable = modelData.count("encryptionCapable") ? parseBool(modelData.at("encryptionCapable")) : false;
    model.gpsCapable = modelData.count("gpsCapable") ? parseBool(modelData.at("gpsCapable")) : false;
    model.dataCapable = modelData.count("dataCapable") ? parseBool(modelData.at("dataCapable")) : false;
    model.networkCapable = modelData.count("networkCapable") ? parseBool(modelData.at("networkCapable")) : false;
    model.advancedEncryption = modelData.count("advancedEncryption") ? parseBool(modelData.at("advancedEncryption")) : false;
    
    model.supportedModes = modelData.count("supportedModes") ? parseStringArray(modelData.at("supportedModes")) : std::vector<std::string>();
    model.presetChannels = modelData.count("presetChannels") ? parseInt(modelData.at("presetChannels")) : 0;
    
    model.fmSensitivity = modelData.count("fmSensitivity") ? parseDouble(modelData.at("fmSensitivity")) : -116.0;
    model.sinad = modelData.count("sinad") ? parseDouble(modelData.at("sinad")) : 12.0;
    
    // Parse custom properties (simplified)
    if (modelData.count("customProperties")) {
        // In a real implementation, you would parse the JSON object properly
        model.customProperties["weight"] = "2.5 kg";  // Default values
        model.customProperties["battery_life"] = "12 hours";
        model.customProperties["antenna_connector"] = "BNC";
    }
    
    return model;
}

std::vector<std::string> RadioModelConfigLoader::parseStringArray(const std::string& jsonArray) const {
    std::vector<std::string> result;
    
    // Simple parsing for ["FM", "AM", "CW"] format
    std::string content = jsonArray;
    content.erase(0, content.find("[") + 1);
    content.erase(content.find_last_of("]"));
    
    std::istringstream ss(content);
    std::string item;
    
    while (std::getline(ss, item, ',')) {
        item.erase(0, item.find_first_not_of(" \t\""));
        item.erase(item.find_last_not_of(" \t\"") + 1);
        if (!item.empty()) {
            result.push_back(item);
        }
    }
    
    return result;
}

std::map<std::string, std::string> RadioModelConfigLoader::parseCustomProperties(const std::string& jsonObject) const {
    std::map<std::string, std::string> result;
    
    // Simplified parsing - in a real implementation, you would parse the JSON object properly
    result["weight"] = "2.5 kg";
    result["battery_life"] = "12 hours";
    result["antenna_connector"] = "BNC";
    
    return result;
}

double RadioModelConfigLoader::parseDouble(const std::string& value) const {
    try {
        return std::stod(value);
    } catch (const std::exception&) {
        return 0.0;
    }
}

int RadioModelConfigLoader::parseInt(const std::string& value) const {
    try {
        return std::stoi(value);
    } catch (const std::exception&) {
        return 0;
    }
}

bool RadioModelConfigLoader::parseBool(const std::string& value) const {
    std::string lowerValue = value;
    std::transform(lowerValue.begin(), lowerValue.end(), lowerValue.begin(), ::tolower);
    return lowerValue == "true";
}

RadioModelInfo RadioModelConfigLoader::getRadioModel(const std::string& modelName) const {
    auto it = radioModels.find(modelName);
    if (it != radioModels.end()) {
        return it->second;
    }
    return RadioModelInfo();  // Return empty model if not found
}

std::vector<RadioModelInfo> RadioModelConfigLoader::getAllRadioModels() const {
    std::vector<RadioModelInfo> result;
    for (const auto& pair : radioModels) {
        result.push_back(pair.second);
    }
    return result;
}

std::vector<RadioModelInfo> RadioModelConfigLoader::getRadioModelsByAlliance(const std::string& alliance) const {
    std::vector<RadioModelInfo> result;
    for (const auto& pair : radioModels) {
        if (pair.second.alliance == alliance) {
            result.push_back(pair.second);
        }
    }
    return result;
}

std::vector<RadioModelInfo> RadioModelConfigLoader::getRadioModelsByEra(const std::string& era) const {
    std::vector<RadioModelInfo> result;
    for (const auto& pair : radioModels) {
        if (pair.second.era == era) {
            result.push_back(pair.second);
        }
    }
    return result;
}

std::vector<RadioModelInfo> RadioModelConfigLoader::getRadioModelsByCountry(const std::string& country) const {
    std::vector<RadioModelInfo> result;
    for (const auto& pair : radioModels) {
        if (pair.second.country == country) {
            result.push_back(pair.second);
        }
    }
    return result;
}

std::vector<RadioModelInfo> RadioModelConfigLoader::searchRadioModels(const std::string& query) const {
    std::vector<RadioModelInfo> result;
    std::string lowerQuery = query;
    std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(), ::tolower);
    
    for (const auto& pair : radioModels) {
        const RadioModelInfo& model = pair.second;
        
        // Search in model name, manufacturer, usage, etc.
        std::string searchText = model.modelName + " " + model.manufacturer + " " + model.usage + " " + model.alliance + " " + model.era;
        std::transform(searchText.begin(), searchText.end(), searchText.begin(), ::tolower);
        
        if (searchText.find(lowerQuery) != std::string::npos) {
            result.push_back(model);
        }
    }
    
    return result;
}

std::vector<RadioModelInfo> RadioModelConfigLoader::getRadioModelsByFrequencyRange(double startMHz, double endMHz) const {
    std::vector<RadioModelInfo> result;
    for (const auto& pair : radioModels) {
        const RadioModelInfo& model = pair.second;
        if (model.frequencyStartMHz >= startMHz && model.frequencyEndMHz <= endMHz) {
            result.push_back(model);
        }
    }
    return result;
}

std::vector<RadioModelInfo> RadioModelConfigLoader::getRadioModelsByChannelSpacing(double spacingKHz) const {
    std::vector<RadioModelInfo> result;
    for (const auto& pair : radioModels) {
        const RadioModelInfo& model = pair.second;
        if (std::abs(model.channelSpacingKHz - spacingKHz) < 0.001) {
            result.push_back(model);
        }
    }
    return result;
}

bool RadioModelConfigLoader::validateRadioModel(const RadioModelInfo& model) const {
    return validateFrequencyRange(model.frequencyStartMHz, model.frequencyEndMHz) &&
           validateChannelSpacing(model.channelSpacingKHz) &&
           validatePowerLevels(model.portablePowerWatts, model.vehiclePowerWatts);
}

std::vector<std::string> RadioModelConfigLoader::getValidationErrors(const RadioModelInfo& model) const {
    std::vector<std::string> errors;
    
    if (!validateFrequencyRange(model.frequencyStartMHz, model.frequencyEndMHz)) {
        errors.push_back("Invalid frequency range");
    }
    
    if (!validateChannelSpacing(model.channelSpacingKHz)) {
        errors.push_back("Invalid channel spacing");
    }
    
    if (!validatePowerLevels(model.portablePowerWatts, model.vehiclePowerWatts)) {
        errors.push_back("Invalid power levels");
    }
    
    return errors;
}

bool RadioModelConfigLoader::validateFrequencyRange(double startMHz, double endMHz) const {
    return startMHz > 0 && endMHz > startMHz && endMHz <= 1000.0;
}

bool RadioModelConfigLoader::validateChannelSpacing(double spacingKHz) const {
    return spacingKHz > 0 && spacingKHz <= 100.0;
}

bool RadioModelConfigLoader::validatePowerLevels(double portableWatts, double vehicleWatts) const {
    return portableWatts >= 0 && vehicleWatts >= 0 && vehicleWatts >= portableWatts;
}

int RadioModelConfigLoader::getTotalRadioModels() const {
    return static_cast<int>(radioModels.size());
}

std::map<std::string, int> RadioModelConfigLoader::getRadioModelsByAlliance() const {
    std::map<std::string, int> result;
    for (const auto& pair : radioModels) {
        result[pair.second.alliance]++;
    }
    return result;
}

std::map<std::string, int> RadioModelConfigLoader::getRadioModelsByEra() const {
    std::map<std::string, int> result;
    for (const auto& pair : radioModels) {
        result[pair.second.era]++;
    }
    return result;
}

std::map<std::string, int> RadioModelConfigLoader::getRadioModelsByCountry() const {
    std::map<std::string, int> result;
    for (const auto& pair : radioModels) {
        result[pair.second.country]++;
    }
    return result;
}

bool RadioModelConfigLoader::isInitialized() const {
    return initialized;
}

std::string RadioModelConfigLoader::getConfigPath() const {
    return configPath;
}

bool RadioModelConfigLoader::reloadConfiguration() {
    radioModels.clear();
    return loadRadioModels();
}

std::string RadioModelConfigLoader::getLastError() const {
    return lastError;
}

void RadioModelConfigLoader::clearLastError() {
    lastError.clear();
}

} // namespace RadioModelConfig
