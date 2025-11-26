#ifndef RADIO_MODEL_CONFIG_LOADER_H
#define RADIO_MODEL_CONFIG_LOADER_H

#include <string>
#include <vector>
#include <map>
#include <memory>

namespace RadioModelConfig {

struct RadioModelInfo {
    std::string modelName;
    std::string manufacturer;
    std::string country;
    std::string alliance;
    std::string era;
    std::string usage;
    
    // Frequency specifications
    double frequencyStartMHz;
    double frequencyEndMHz;
    double channelSpacingKHz;
    int totalChannels;
    
    // Power specifications
    double portablePowerWatts;
    double vehiclePowerWatts;
    
    // Capabilities
    bool encryptionCapable;
    bool gpsCapable;
    bool dataCapable;
    bool networkCapable;
    bool advancedEncryption;
    
    // Modes and features
    std::vector<std::string> supportedModes;
    int presetChannels;
    
    // Technical specifications
    double fmSensitivity;  // dBm
    double sinad;           // dB
    
    // Custom properties
    std::map<std::string, std::string> customProperties;
};

class RadioModelConfigLoader {
public:
    static RadioModelConfigLoader& getInstance();
    
    // Initialize the configuration system
    bool initialize(const std::string& configPath = "../../config/radio_models.json");
    
    // Load radio models from configuration file
    bool loadRadioModels();
    
    // Get radio model information
    RadioModelInfo getRadioModel(const std::string& modelName) const;
    std::vector<RadioModelInfo> getAllRadioModels() const;
    std::vector<RadioModelInfo> getRadioModelsByAlliance(const std::string& alliance) const;
    std::vector<RadioModelInfo> getRadioModelsByEra(const std::string& era) const;
    std::vector<RadioModelInfo> getRadioModelsByCountry(const std::string& country) const;
    
    // Search functionality
    std::vector<RadioModelInfo> searchRadioModels(const std::string& query) const;
    std::vector<RadioModelInfo> getRadioModelsByFrequencyRange(double startMHz, double endMHz) const;
    std::vector<RadioModelInfo> getRadioModelsByChannelSpacing(double spacingKHz) const;
    
    // Validation
    bool validateRadioModel(const RadioModelInfo& model) const;
    std::vector<std::string> getValidationErrors(const RadioModelInfo& model) const;
    
    // Statistics
    int getTotalRadioModels() const;
    std::map<std::string, int> getRadioModelsByAlliance() const;
    std::map<std::string, int> getRadioModelsByEra() const;
    std::map<std::string, int> getRadioModelsByCountry() const;
    
    // Configuration management
    bool isInitialized() const;
    std::string getConfigPath() const;
    bool reloadConfiguration();
    
    // Error handling
    std::string getLastError() const;
    void clearLastError();

private:
    RadioModelConfigLoader();
    ~RadioModelConfigLoader();
    
    // Disable copy constructor and assignment operator
    RadioModelConfigLoader(const RadioModelConfigLoader&) = delete;
    RadioModelConfigLoader& operator=(const RadioModelConfigLoader&) = delete;
    
    // Internal methods
    bool parseJsonFile();
    RadioModelInfo parseRadioModelFromJson(const std::string& modelName, const std::map<std::string, std::string>& modelData);
    bool validateFrequencyRange(double startMHz, double endMHz) const;
    bool validateChannelSpacing(double spacingKHz) const;
    bool validatePowerLevels(double portableWatts, double vehicleWatts) const;
    
    // Member variables
    std::string configPath;
    std::map<std::string, RadioModelInfo> radioModels;
    bool initialized;
    std::string lastError;
    
    // JSON parsing helpers
    std::vector<std::string> parseStringArray(const std::string& jsonArray) const;
    std::map<std::string, std::string> parseCustomProperties(const std::string& jsonObject) const;
    double parseDouble(const std::string& value) const;
    int parseInt(const std::string& value) const;
    bool parseBool(const std::string& value) const;
};

} // namespace RadioModelConfig

#endif // RADIO_MODEL_CONFIG_LOADER_H
