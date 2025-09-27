#include "preset_channel_config_loader.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <cctype>
#include <mutex>
#include <memory>

namespace PresetChannelConfig {

PresetChannelConfigLoader::PresetChannelConfigLoader() 
    : initialized(false) {
}

PresetChannelConfigLoader::~PresetChannelConfigLoader() {
}

PresetChannelConfigLoader& PresetChannelConfigLoader::getInstance() {
    static std::once_flag flag;
    static std::unique_ptr<PresetChannelConfigLoader> instance;
    std::call_once(flag, []() {
        instance = std::make_unique<PresetChannelConfigLoader>();
    });
    return *instance;
}

bool PresetChannelConfigLoader::initialize(const std::string& configPath) {
    this->configPath = configPath;
    this->initialized = false;
    this->lastError.clear();
    
    // Try to load the configuration file
    if (!loadPresetChannels()) {
        return false;
    }
    
    this->initialized = true;
    return true;
}

bool PresetChannelConfigLoader::loadPresetChannels() {
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
    // File automatically closed by RAII
    
    // Simple JSON parsing (in a real implementation, you would use a proper JSON library)
    if (!parseJsonFile()) {
        return false;
    }
    
    return true;
}

bool PresetChannelConfigLoader::parseJsonFile() {
    // CRITICAL: This implementation is unsafe and should be replaced with proper JSON library
    // For now, return false to prevent buffer overflows and security issues
    lastError = "JSON parsing not implemented - requires proper JSON library (nlohmann/json)";
    return false;
}

PresetChannelInfo PresetChannelConfigLoader::parsePresetChannelFromJson(const std::string& presetNumber, const std::map<std::string, std::string>& presetData) {
    PresetChannelInfo preset;
    
    preset.presetNumber = parseInt(presetNumber);
    preset.channelNumber = presetData.count("channelNumber") ? parseInt(presetData.at("channelNumber")) : 0;
    preset.frequency = presetData.count("frequency") ? parseDouble(presetData.at("frequency")) : 0.0;
    preset.label = presetData.count("label") ? presetData.at("label") : "";
    preset.description = presetData.count("description") ? presetData.at("description") : "";
    preset.modulationMode = presetData.count("modulationMode") ? presetData.at("modulationMode") : "FM";
    preset.powerWatts = presetData.count("powerWatts") ? parseDouble(presetData.at("powerWatts")) : 0.0;
    preset.isActive = presetData.count("isActive") ? parseBool(presetData.at("isActive")) : true;
    
    // Parse custom properties (simplified)
    if (presetData.count("customProperties")) {
        // In a real implementation, you would parse the JSON object properly
        preset.customProperties["priority"] = "medium";
        preset.customProperties["encryption"] = "disabled";
        preset.customProperties["gps"] = "disabled";
    }
    
    return preset;
}

RadioPresetInfo PresetChannelConfigLoader::parseRadioPresetFromJson(const std::string& radioModel, const std::map<std::string, std::string>& radioData) {
    RadioPresetInfo radioPreset;
    
    radioPreset.modelName = radioModel;
    radioPreset.totalPresets = radioData.count("totalPresets") ? parseInt(radioData.at("totalPresets")) : 0;
    
    return radioPreset;
}

std::vector<std::string> PresetChannelConfigLoader::parseStringArray(const std::string& jsonArray) const {
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

std::map<std::string, std::string> PresetChannelConfigLoader::parseCustomProperties(const std::string& jsonObject) const {
    std::map<std::string, std::string> result;
    
    // Simplified parsing - in a real implementation, you would parse the JSON object properly
    result["priority"] = "medium";
    result["encryption"] = "disabled";
    result["gps"] = "disabled";
    
    return result;
}

double PresetChannelConfigLoader::parseDouble(const std::string& value) const {
    if (value.empty()) {
        return 0.0;
    }
    
    // Validate input contains only valid characters
    if (value.find_first_not_of("0123456789.-+eE") != std::string::npos) {
        return 0.0;
    }
    
    try {
        double result = std::stod(value);
        // Validate range
        if (result < -1e6 || result > 1e6) {
            return 0.0;
        }
        return result;
    } catch (const std::exception&) {
        return 0.0;
    }
}

int PresetChannelConfigLoader::parseInt(const std::string& value) const {
    if (value.empty()) {
        return 0;
    }
    
    // Validate input contains only valid characters
    if (value.find_first_not_of("0123456789-+") != std::string::npos) {
        return 0;
    }
    
    try {
        int result = std::stoi(value);
        // Validate range
        if (result < -100000 || result > 100000) {
            return 0;
        }
        return result;
    } catch (const std::exception&) {
        return 0;
    }
}

bool PresetChannelConfigLoader::parseBool(const std::string& value) const {
    std::string lowerValue = value;
    std::transform(lowerValue.begin(), lowerValue.end(), lowerValue.begin(), ::tolower);
    return lowerValue == "true";
}

PresetChannelInfo PresetChannelConfigLoader::getPresetChannel(const std::string& radioModel, int presetNumber) const {
    auto it = radioPresets.find(radioModel);
    if (it != radioPresets.end()) {
        auto presetIt = it->second.presets.find(presetNumber);
        if (presetIt != it->second.presets.end()) {
            return presetIt->second;
        }
    }
    return PresetChannelInfo();  // Return empty preset if not found
}

std::vector<PresetChannelInfo> PresetChannelConfigLoader::getAllPresetChannels(const std::string& radioModel) const {
    std::vector<PresetChannelInfo> result;
    auto it = radioPresets.find(radioModel);
    if (it != radioPresets.end()) {
        for (const auto& pair : it->second.presets) {
            result.push_back(pair.second);
        }
    }
    return result;
}

std::vector<PresetChannelInfo> PresetChannelConfigLoader::getActivePresetChannels(const std::string& radioModel) const {
    std::vector<PresetChannelInfo> result;
    auto it = radioPresets.find(radioModel);
    if (it != radioPresets.end()) {
        for (const auto& pair : it->second.presets) {
            if (pair.second.isActive) {
                result.push_back(pair.second);
            }
        }
    }
    return result;
}

std::vector<PresetChannelInfo> PresetChannelConfigLoader::getInactivePresetChannels(const std::string& radioModel) const {
    std::vector<PresetChannelInfo> result;
    auto it = radioPresets.find(radioModel);
    if (it != radioPresets.end()) {
        for (const auto& pair : it->second.presets) {
            if (!pair.second.isActive) {
                result.push_back(pair.second);
            }
        }
    }
    return result;
}

std::vector<PresetChannelInfo> PresetChannelConfigLoader::searchPresetChannels(const std::string& radioModel, const std::string& query) const {
    std::vector<PresetChannelInfo> result;
    std::string lowerQuery = query;
    std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(), ::tolower);
    
    auto it = radioPresets.find(radioModel);
    if (it != radioPresets.end()) {
        for (const auto& pair : it->second.presets) {
            const PresetChannelInfo& preset = pair.second;
            
            // Search in label, description, modulation mode
            std::string searchText = preset.label + " " + preset.description + " " + preset.modulationMode;
            std::transform(searchText.begin(), searchText.end(), searchText.begin(), ::tolower);
            
            if (searchText.find(lowerQuery) != std::string::npos) {
                result.push_back(preset);
            }
        }
    }
    
    return result;
}

std::vector<PresetChannelInfo> PresetChannelConfigLoader::getPresetChannelsByFrequency(const std::string& radioModel, double frequency, double tolerance) const {
    std::vector<PresetChannelInfo> result;
    auto it = radioPresets.find(radioModel);
    if (it != radioPresets.end()) {
        for (const auto& pair : it->second.presets) {
            const PresetChannelInfo& preset = pair.second;
            if (std::abs(preset.frequency - frequency) <= tolerance) {
                result.push_back(preset);
            }
        }
    }
    return result;
}

std::vector<PresetChannelInfo> PresetChannelConfigLoader::getPresetChannelsByChannel(const std::string& radioModel, int channelNumber) const {
    std::vector<PresetChannelInfo> result;
    auto it = radioPresets.find(radioModel);
    if (it != radioPresets.end()) {
        for (const auto& pair : it->second.presets) {
            const PresetChannelInfo& preset = pair.second;
            if (preset.channelNumber == channelNumber) {
                result.push_back(preset);
            }
        }
    }
    return result;
}

std::vector<PresetChannelInfo> PresetChannelConfigLoader::getPresetChannelsByModulation(const std::string& radioModel, const std::string& modulationMode) const {
    std::vector<PresetChannelInfo> result;
    auto it = radioPresets.find(radioModel);
    if (it != radioPresets.end()) {
        for (const auto& pair : it->second.presets) {
            const PresetChannelInfo& preset = pair.second;
            if (preset.modulationMode == modulationMode) {
                result.push_back(preset);
            }
        }
    }
    return result;
}

int PresetChannelConfigLoader::getPresetCount(const std::string& radioModel) const {
    auto it = radioPresets.find(radioModel);
    if (it != radioPresets.end()) {
        return static_cast<int>(it->second.presets.size());
    }
    return 0;
}

int PresetChannelConfigLoader::getActivePresetCount(const std::string& radioModel) const {
    auto activePresets = getActivePresetChannels(radioModel);
    return static_cast<int>(activePresets.size());
}

int PresetChannelConfigLoader::getInactivePresetCount(const std::string& radioModel) const {
    auto inactivePresets = getInactivePresetChannels(radioModel);
    return static_cast<int>(inactivePresets.size());
}

double PresetChannelConfigLoader::getPresetFrequencyRange(const std::string& radioModel) const {
    auto presets = getAllPresetChannels(radioModel);
    if (presets.empty()) return 0.0;
    
    double minFreq = presets[0].frequency;
    double maxFreq = presets[0].frequency;
    
    for (const auto& preset : presets) {
        if (preset.frequency < minFreq) minFreq = preset.frequency;
        if (preset.frequency > maxFreq) maxFreq = preset.frequency;
    }
    
    return maxFreq - minFreq;
}

std::map<int, int> PresetChannelConfigLoader::getPresetChannelDistribution(const std::string& radioModel) const {
    std::map<int, int> result;
    auto presets = getAllPresetChannels(radioModel);
    
    for (const auto& preset : presets) {
        result[preset.channelNumber]++;
    }
    
    return result;
}

std::vector<std::string> PresetChannelConfigLoader::getRadioModelsWithPresets() const {
    std::vector<std::string> result;
    for (const auto& pair : radioPresets) {
        if (!pair.second.presets.empty()) {
            result.push_back(pair.first);
        }
    }
    return result;
}

std::vector<std::string> PresetChannelConfigLoader::getRadioModelsWithoutPresets() const {
    std::vector<std::string> result;
    for (const auto& pair : radioPresets) {
        if (pair.second.presets.empty()) {
            result.push_back(pair.first);
        }
    }
    return result;
}

bool PresetChannelConfigLoader::hasPresetChannels(const std::string& radioModel) const {
    auto it = radioPresets.find(radioModel);
    return it != radioPresets.end() && !it->second.presets.empty();
}

int PresetChannelConfigLoader::getTotalPresetChannels(const std::string& radioModel) const {
    auto it = radioPresets.find(radioModel);
    if (it != radioPresets.end()) {
        return it->second.totalPresets;
    }
    return 0;
}

std::string PresetChannelConfigLoader::exportPresetChannelsToJSON(const std::string& radioModel) const {
    auto presets = getAllPresetChannels(radioModel);
    std::ostringstream json;
    
    json << "[";
    for (size_t i = 0; i < presets.size(); ++i) {
        if (i > 0) json << ",";
        json << "{";
        json << "\"presetNumber\":" << presets[i].presetNumber << ",";
        json << "\"channelNumber\":" << presets[i].channelNumber << ",";
        json << "\"frequency\":" << presets[i].frequency << ",";
        json << "\"label\":\"" << presets[i].label << "\",";
        json << "\"description\":\"" << presets[i].description << "\",";
        json << "\"modulationMode\":\"" << presets[i].modulationMode << "\",";
        json << "\"powerWatts\":" << presets[i].powerWatts << ",";
        json << "\"isActive\":" << (presets[i].isActive ? "true" : "false");
        json << "}";
    }
    json << "]";
    
    return json.str();
}

std::string PresetChannelConfigLoader::exportPresetChannelsToCSV(const std::string& radioModel) const {
    auto presets = getAllPresetChannels(radioModel);
    std::ostringstream csv;
    
    csv << "PresetNumber,ChannelNumber,Frequency,Label,Description,ModulationMode,PowerWatts,IsActive\n";
    for (const auto& preset : presets) {
        csv << preset.presetNumber << ",";
        csv << preset.channelNumber << ",";
        csv << preset.frequency << ",";
        csv << "\"" << preset.label << "\",";
        csv << "\"" << preset.description << "\",";
        csv << "\"" << preset.modulationMode << "\",";
        csv << preset.powerWatts << ",";
        csv << (preset.isActive ? "true" : "false") << "\n";
    }
    
    return csv.str();
}

std::string PresetChannelConfigLoader::exportAllPresetChannelsToJSON() const {
    std::ostringstream json;
    
    json << "{";
    json << "\"preset_channels\":{";
    
    bool firstRadio = true;
    for (const auto& radioPair : radioPresets) {
        if (!firstRadio) json << ",";
        json << "\"" << radioPair.first << "\":{";
        json << "\"modelName\":\"" << radioPair.second.modelName << "\",";
        json << "\"totalPresets\":" << radioPair.second.totalPresets << ",";
        json << "\"presets\":{";
        
        bool firstPreset = true;
        for (const auto& presetPair : radioPair.second.presets) {
            if (!firstPreset) json << ",";
            json << "\"" << presetPair.first << "\":{";
            json << "\"presetNumber\":" << presetPair.second.presetNumber << ",";
            json << "\"channelNumber\":" << presetPair.second.channelNumber << ",";
            json << "\"frequency\":" << presetPair.second.frequency << ",";
            json << "\"label\":\"" << presetPair.second.label << "\",";
            json << "\"description\":\"" << presetPair.second.description << "\",";
            json << "\"modulationMode\":\"" << presetPair.second.modulationMode << "\",";
            json << "\"powerWatts\":" << presetPair.second.powerWatts << ",";
            json << "\"isActive\":" << (presetPair.second.isActive ? "true" : "false");
            json << "}";
            firstPreset = false;
        }
        
        json << "}";
        json << "}";
        firstRadio = false;
    }
    
    json << "}";
    json << "}";
    
    return json.str();
}

bool PresetChannelConfigLoader::validatePresetChannel(const PresetChannelInfo& preset) const {
    return validatePresetNumber(preset.presetNumber) &&
           validateChannelNumber(preset.channelNumber) &&
           validateFrequency(preset.frequency) &&
           validatePowerLevel(preset.powerWatts);
}

std::vector<std::string> PresetChannelConfigLoader::getPresetValidationErrors(const PresetChannelInfo& preset) const {
    std::vector<std::string> errors;
    
    if (!validatePresetNumber(preset.presetNumber)) {
        errors.push_back("Invalid preset number");
    }
    
    if (!validateChannelNumber(preset.channelNumber)) {
        errors.push_back("Invalid channel number");
    }
    
    if (!validateFrequency(preset.frequency)) {
        errors.push_back("Invalid frequency");
    }
    
    if (!validatePowerLevel(preset.powerWatts)) {
        errors.push_back("Invalid power level");
    }
    
    return errors;
}

bool PresetChannelConfigLoader::validateRadioModelPresets(const std::string& radioModel) const {
    auto presets = getAllPresetChannels(radioModel);
    for (const auto& preset : presets) {
        if (!validatePresetChannel(preset)) {
            return false;
        }
    }
    return true;
}

bool PresetChannelConfigLoader::validateFrequency(double frequency) const {
    return frequency > 0.0 && frequency <= 1000.0;
}

bool PresetChannelConfigLoader::validateChannelNumber(int channelNumber) const {
    return channelNumber > 0 && channelNumber <= 10000;
}

bool PresetChannelConfigLoader::validatePowerLevel(double powerWatts) const {
    return powerWatts >= 0.0 && powerWatts <= 1000.0;
}

bool PresetChannelConfigLoader::validatePresetNumber(int presetNumber) const {
    return presetNumber > 0 && presetNumber <= 99;
}

bool PresetChannelConfigLoader::isInitialized() const {
    return initialized;
}

std::string PresetChannelConfigLoader::getConfigPath() const {
    return configPath;
}

bool PresetChannelConfigLoader::reloadConfiguration() {
    radioPresets.clear();
    return loadPresetChannels();
}

std::string PresetChannelConfigLoader::getLastError() const {
    return lastError;
}

void PresetChannelConfigLoader::clearLastError() {
    lastError.clear();
}

} // namespace PresetChannelConfig
