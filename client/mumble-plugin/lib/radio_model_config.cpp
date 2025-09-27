#include "radio_model_config.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cmath>

namespace RadioModelConfig {

// Static member initialization
std::map<std::string, RadioModelSpec> RadioModelConfigManager::radioModels;
std::string RadioModelConfigManager::configFilePath = "radio_models.json";
bool RadioModelConfigManager::isInitialized = false;

// RadioModelConfigManager Implementation
void RadioModelConfigManager::initialize(const std::string& configFile) {
    configFilePath = configFile;
    loadDefaultModels();
    loadFromFile(configFile);
    isInitialized = true;
}

void RadioModelConfigManager::loadDefaultModels() {
    // Add default Soviet VHF models
    RadioModelSpec r105m;
    r105m.modelName = "R-105M";
    r105m.manufacturer = "Soviet Union";
    r105m.country = "USSR";
    r105m.alliance = "Warsaw Pact";
    r105m.era = "Cold War";
    r105m.usage = "Tactical VHF";
    r105m.frequencyStartMHz = 36.0;
    r105m.frequencyEndMHz = 46.1;
    r105m.channelSpacingKHz = 25.0;
    r105m.calculateTotalChannels();
    r105m.portablePowerWatts = 1.5;
    r105m.vehiclePowerWatts = 20.0;
    r105m.encryptionCapable = false;
    r105m.gpsCapable = false;
    r105m.dataCapable = false;
    r105m.networkCapable = false;
    r105m.advancedEncryption = false;
    r105m.supportedModes = {"FM", "AM"};
    radioModels["R-105M"] = r105m;
    
    // Add default NATO VHF models
    RadioModelSpec an_prc77;
    an_prc77.modelName = "AN/PRC-77";
    an_prc77.manufacturer = "USA";
    an_prc77.country = "USA";
    an_prc77.alliance = "NATO";
    an_prc77.era = "Cold War";
    an_prc77.usage = "Legacy VHF Tactical Radio";
    an_prc77.frequencyStartMHz = 30.0;
    an_prc77.frequencyEndMHz = 87.975;
    an_prc77.channelSpacingKHz = 25.0;
    an_prc77.calculateTotalChannels();
    an_prc77.portablePowerWatts = 2.0;
    an_prc77.vehiclePowerWatts = 20.0;
    an_prc77.encryptionCapable = false;
    an_prc77.gpsCapable = false;
    an_prc77.dataCapable = false;
    an_prc77.networkCapable = false;
    an_prc77.advancedEncryption = false;
    an_prc77.supportedModes = {"FM", "AM"};
    radioModels["AN/PRC-77"] = an_prc77;
}

bool RadioModelConfigManager::addModel(const RadioModelSpec& model) {
    if (!validateModel(model)) return false;
    radioModels[model.modelName] = model;
    return true;
}

bool RadioModelConfigManager::updateModel(const std::string& modelName, const RadioModelSpec& model) {
    if (radioModels.find(modelName) == radioModels.end()) return false;
    if (!validateModel(model)) return false;
    radioModels[modelName] = model;
    return true;
}

bool RadioModelConfigManager::removeModel(const std::string& modelName) {
    auto it = radioModels.find(modelName);
    if (it == radioModels.end()) return false;
    radioModels.erase(it);
    return true;
}

RadioModelSpec RadioModelConfigManager::getModel(const std::string& modelName) {
    auto it = radioModels.find(modelName);
    if (it == radioModels.end()) return RadioModelSpec();
    return it->second;
}

std::vector<std::string> RadioModelConfigManager::getAllModelNames() {
    std::vector<std::string> names;
    for (const auto& pair : radioModels) {
        names.push_back(pair.first);
    }
    return names;
}

std::vector<RadioModelSpec> RadioModelConfigManager::getAllModels() {
    std::vector<RadioModelSpec> models;
    for (const auto& pair : radioModels) {
        models.push_back(pair.second);
    }
    return models;
}

bool RadioModelConfigManager::validateModel(const RadioModelSpec& model) {
    return model.isValid();
}

std::vector<std::string> RadioModelConfigManager::getValidationErrors(const RadioModelSpec& model) {
    std::vector<std::string> errors;
    
    if (model.modelName.empty()) {
        errors.push_back("Model name is required");
    }
    if (model.frequencyStartMHz <= 0) {
        errors.push_back("Start frequency must be positive");
    }
    if (model.frequencyEndMHz <= model.frequencyStartMHz) {
        errors.push_back("End frequency must be greater than start frequency");
    }
    if (model.channelSpacingKHz <= 0) {
        errors.push_back("Channel spacing must be positive");
    }
    if (model.portablePowerWatts <= 0) {
        errors.push_back("Portable power must be positive");
    }
    if (model.vehiclePowerWatts <= 0) {
        errors.push_back("Vehicle power must be positive");
    }
    
    return errors;
}

// RadioModel Implementation
RadioModel::RadioModel(const RadioModelSpec& specification) 
    : spec(specification), currentChannel(1), currentPower(specification.portablePowerWatts), 
      isPortable(true), isOperational(true) {
    
    // Initialize features based on specification
    features["encryption"] = specification.encryptionCapable;
    features["gps"] = specification.gpsCapable;
    features["data"] = specification.dataCapable;
    features["network"] = specification.networkCapable;
    features["advanced_encryption"] = specification.advancedEncryption;
}

bool RadioModel::setChannel(int channel) {
    if (!isValidChannel(channel)) return false;
    currentChannel = channel;
    return true;
}

int RadioModel::getCurrentChannel() const {
    return currentChannel;
}

double RadioModel::getCurrentFrequency() const {
    return spec.getFrequencyForChannel(currentChannel);
}

bool RadioModel::setFrequency(double frequency) {
    if (!isValidFrequency(frequency)) return false;
    currentChannel = spec.getChannelForFrequency(frequency);
    return true;
}

void RadioModel::setPortableMode(bool portable) {
    isPortable = portable;
    currentPower = portable ? spec.portablePowerWatts : spec.vehiclePowerWatts;
}

bool RadioModel::isPortableMode() const {
    return isPortable;
}

double RadioModel::getCurrentPower() const {
    return currentPower;
}

void RadioModel::setPower(double power) {
    currentPower = std::max(0.1, std::min(power, isPortable ? spec.portablePowerWatts : spec.vehiclePowerWatts));
}

void RadioModel::setOperational(bool operational) {
    isOperational = operational;
}

bool RadioModel::isRadioOperational() const {
    return isOperational;
}

void RadioModel::setFeature(const std::string& feature, bool enabled) {
    features[feature] = enabled;
}

bool RadioModel::isFeatureEnabled(const std::string& feature) const {
    auto it = features.find(feature);
    return it != features.end() && it->second;
}

std::vector<std::string> RadioModel::getAvailableFeatures() const {
    std::vector<std::string> available;
    for (const auto& pair : features) {
        available.push_back(pair.first);
    }
    return available;
}

std::vector<std::string> RadioModel::getEnabledFeatures() const {
    std::vector<std::string> enabled;
    for (const auto& pair : features) {
        if (pair.second) {
            enabled.push_back(pair.first);
        }
    }
    return enabled;
}

void RadioModel::setCustomSetting(const std::string& key, const std::string& value) {
    customSettings[key] = value;
}

std::string RadioModel::getCustomSetting(const std::string& key) const {
    auto it = customSettings.find(key);
    return it != customSettings.end() ? it->second : "";
}

std::map<std::string, std::string> RadioModel::getAllCustomSettings() const {
    return customSettings;
}

RadioModelSpec RadioModel::getSpecification() const {
    return spec;
}

std::string RadioModel::getModelName() const {
    return spec.modelName;
}

std::string RadioModel::getManufacturer() const {
    return spec.manufacturer;
}

std::string RadioModel::getCountry() const {
    return spec.country;
}

std::string RadioModel::getAlliance() const {
    return spec.alliance;
}

std::string RadioModel::getEra() const {
    return spec.era;
}

std::string RadioModel::getUsage() const {
    return spec.usage;
}

bool RadioModel::isValidChannel(int channel) const {
    return channel >= 1 && channel <= spec.totalChannels;
}

bool RadioModel::isValidFrequency(double frequency) const {
    return spec.isValidFrequency(frequency);
}

std::vector<double> RadioModel::getAllChannels() const {
    return spec.getAllChannels();
}

int RadioModel::getTotalChannels() const {
    return spec.totalChannels;
}

double RadioModel::getFrequencyRange() const {
    return spec.frequencyEndMHz - spec.frequencyStartMHz;
}

double RadioModel::getChannelSpacing() const {
    return spec.channelSpacingKHz;
}

bool RadioModel::setPresetChannel(int preset, int channel) {
    if (preset < 0 || preset >= static_cast<int>(spec.presetChannels.size())) return false;
    if (!isValidChannel(channel)) return false;
    
    if (preset >= static_cast<int>(spec.presetChannels.size())) {
        spec.presetChannels.resize(preset + 1);
    }
    spec.presetChannels[preset] = std::to_string(channel);
    return true;
}

int RadioModel::getPresetChannel(int preset) const {
    if (preset < 0 || preset >= static_cast<int>(spec.presetChannels.size())) return 0;
    return std::stoi(spec.presetChannels[preset]);
}

bool RadioModel::selectPresetChannel(int preset) {
    if (preset < 0 || preset >= static_cast<int>(spec.presetChannels.size())) return false;
    int channel = getPresetChannel(preset);
    return setChannel(channel);
}

int RadioModel::getPresetChannelCount() const {
    return static_cast<int>(spec.presetChannels.size());
}

bool RadioModel::setMode(const std::string& mode) {
    if (std::find(spec.supportedModes.begin(), spec.supportedModes.end(), mode) == spec.supportedModes.end()) {
        return false;
    }
    customSettings["current_mode"] = mode;
    return true;
}

std::string RadioModel::getCurrentMode() const {
    return getCustomSetting("current_mode");
}

std::vector<std::string> RadioModel::getSupportedModes() const {
    return spec.supportedModes;
}

bool RadioModel::isModeSupported(const std::string& mode) const {
    return std::find(spec.supportedModes.begin(), spec.supportedModes.end(), mode) != spec.supportedModes.end();
}

bool RadioModel::validateConfiguration() const {
    return spec.isValid() && isOperational;
}

std::vector<std::string> RadioModel::getConfigurationErrors() const {
    std::vector<std::string> errors;
    
    if (!spec.isValid()) {
        errors.push_back("Invalid radio specification");
    }
    if (!isOperational) {
        errors.push_back("Radio is not operational");
    }
    
    return errors;
}

std::string RadioModel::toJSON() const {
    // Simplified JSON serialization
    std::ostringstream json;
    json << "{\n";
    json << "  \"modelName\": \"" << spec.modelName << "\",\n";
    json << "  \"currentChannel\": " << currentChannel << ",\n";
    json << "  \"currentPower\": " << currentPower << ",\n";
    json << "  \"isPortable\": " << (isPortable ? "true" : "false") << ",\n";
    json << "  \"isOperational\": " << (isOperational ? "true" : "false") << "\n";
    json << "}";
    return json.str();
}

bool RadioModel::fromJSON(const std::string& jsonData) {
    // Simplified JSON deserialization
    // In a real implementation, you would use a proper JSON library
    return true;
}

bool RadioModel::isCompatibleWith(const RadioModel& other) const {
    // Check if two radio models can communicate
    double freq1 = getCurrentFrequency();
    double freq2 = other.getCurrentFrequency();
    
    // Check if frequencies are within each other's valid range
    bool compatible1 = spec.isValidFrequency(freq2);
    bool compatible2 = other.spec.isValidFrequency(freq1);
    
    return compatible1 && compatible2;
}

std::map<std::string, std::string> RadioModel::compareWith(const RadioModel& other) const {
    std::map<std::string, std::string> comparison;
    
    comparison["model1"] = getModelName();
    comparison["model2"] = other.getModelName();
    comparison["compatible"] = isCompatibleWith(other) ? "Yes" : "No";
    comparison["frequency_range1"] = std::to_string(spec.frequencyStartMHz) + "-" + std::to_string(spec.frequencyEndMHz);
    comparison["frequency_range2"] = std::to_string(other.spec.frequencyStartMHz) + "-" + std::to_string(other.spec.frequencyEndMHz);
    comparison["channel_spacing1"] = std::to_string(spec.channelSpacingKHz);
    comparison["channel_spacing2"] = std::to_string(other.spec.channelSpacingKHz);
    
    return comparison;
}

} // namespace RadioModelConfig
