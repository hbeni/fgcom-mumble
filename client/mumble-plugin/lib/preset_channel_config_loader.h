#ifndef PRESET_CHANNEL_CONFIG_LOADER_H
#define PRESET_CHANNEL_CONFIG_LOADER_H

#include <string>
#include <vector>
#include <map>
#include <memory>

namespace PresetChannelConfig {

struct PresetChannelInfo {
    int presetNumber;
    int channelNumber;
    double frequency;
    std::string label;
    std::string description;
    std::string modulationMode;
    double powerWatts;
    bool isActive;
    std::map<std::string, std::string> customProperties;
};

struct RadioPresetInfo {
    std::string modelName;
    int totalPresets;
    std::map<int, PresetChannelInfo> presets;
};

class PresetChannelConfigLoader {
public:
    static PresetChannelConfigLoader& getInstance();
    
    // Initialize the configuration system
    bool initialize(const std::string& configPath = "../../config/preset_channels.json");
    
    // Load preset channels from configuration file
    bool loadPresetChannels();
    
    // Get preset channel information
    PresetChannelInfo getPresetChannel(const std::string& radioModel, int presetNumber) const;
    std::vector<PresetChannelInfo> getAllPresetChannels(const std::string& radioModel) const;
    std::vector<PresetChannelInfo> getActivePresetChannels(const std::string& radioModel) const;
    std::vector<PresetChannelInfo> getInactivePresetChannels(const std::string& radioModel) const;
    
    // Search functionality
    std::vector<PresetChannelInfo> searchPresetChannels(const std::string& radioModel, const std::string& query) const;
    std::vector<PresetChannelInfo> getPresetChannelsByFrequency(const std::string& radioModel, double frequency, double tolerance = 0.001) const;
    std::vector<PresetChannelInfo> getPresetChannelsByChannel(const std::string& radioModel, int channelNumber) const;
    std::vector<PresetChannelInfo> getPresetChannelsByModulation(const std::string& radioModel, const std::string& modulationMode) const;
    
    // Statistics
    int getPresetCount(const std::string& radioModel) const;
    int getActivePresetCount(const std::string& radioModel) const;
    int getInactivePresetCount(const std::string& radioModel) const;
    double getPresetFrequencyRange(const std::string& radioModel) const;
    std::map<int, int> getPresetChannelDistribution(const std::string& radioModel) const;
    
    // Radio model information
    std::vector<std::string> getRadioModelsWithPresets() const;
    std::vector<std::string> getRadioModelsWithoutPresets() const;
    bool hasPresetChannels(const std::string& radioModel) const;
    int getTotalPresetChannels(const std::string& radioModel) const;
    
    // Export functionality
    std::string exportPresetChannelsToJSON(const std::string& radioModel) const;
    std::string exportPresetChannelsToCSV(const std::string& radioModel) const;
    std::string exportAllPresetChannelsToJSON() const;
    
    // Validation
    bool validatePresetChannel(const PresetChannelInfo& preset) const;
    std::vector<std::string> getPresetValidationErrors(const PresetChannelInfo& preset) const;
    bool validateRadioModelPresets(const std::string& radioModel) const;
    
    // Configuration management
    bool isInitialized() const;
    std::string getConfigPath() const;
    bool reloadConfiguration();
    
    // Error handling
    std::string getLastError() const;
    void clearLastError();

public:
    PresetChannelConfigLoader();
    ~PresetChannelConfigLoader();
    
    // Disable copy constructor and assignment operator
    PresetChannelConfigLoader(const PresetChannelConfigLoader&) = delete;
    PresetChannelConfigLoader& operator=(const PresetChannelConfigLoader&) = delete;

private:
    
    // Internal methods
    bool parseJsonFile();
    PresetChannelInfo parsePresetChannelFromJson(const std::string& presetNumber, const std::map<std::string, std::string>& presetData);
    RadioPresetInfo parseRadioPresetFromJson(const std::string& radioModel, const std::map<std::string, std::string>& radioData);
    bool validateFrequency(double frequency) const;
    bool validateChannelNumber(int channelNumber) const;
    bool validatePowerLevel(double powerWatts) const;
    bool validatePresetNumber(int presetNumber) const;
    void addNewBandPresetChannels();
    
    // JSON parsing helpers
    std::vector<std::string> parseStringArray(const std::string& jsonArray) const;
    std::map<std::string, std::string> parseCustomProperties(const std::string& jsonObject) const;
    double parseDouble(const std::string& value) const;
    int parseInt(const std::string& value) const;
    bool parseBool(const std::string& value) const;
    
    // Member variables
    std::string configPath;
    std::map<std::string, RadioPresetInfo> radioPresets;
    bool initialized;
    std::string lastError;
};

} // namespace PresetChannelConfig

#endif // PRESET_CHANNEL_CONFIG_LOADER_H
