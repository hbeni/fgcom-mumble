#ifndef FGCOM_RADIO_MODEL_CONFIG_H
#define FGCOM_RADIO_MODEL_CONFIG_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <fstream>
#include <sstream>
#include <algorithm>

// Radio Model Configuration System
namespace RadioModelConfig {

// Radio model specification structure
struct RadioModelSpec {
    std::string modelName;
    std::string manufacturer;
    std::string country;
    std::string alliance;
    std::string era;
    std::string usage;
    double frequencyStartMHz;
    double frequencyEndMHz;
    double channelSpacingKHz;
    int totalChannels;
    double portablePowerWatts;
    double vehiclePowerWatts;
    bool encryptionCapable;
    bool gpsCapable;
    bool dataCapable;
    bool networkCapable;
    bool advancedEncryption;
    std::vector<std::string> supportedModes;
    std::vector<std::string> presetChannels;
    std::map<std::string, std::string> customProperties;
    
    // Default constructor
    RadioModelSpec() : frequencyStartMHz(0.0), frequencyEndMHz(0.0), channelSpacingKHz(25.0), 
                      totalChannels(0), portablePowerWatts(1.0), vehiclePowerWatts(10.0),
                      encryptionCapable(false), gpsCapable(false), dataCapable(false),
                      networkCapable(false), advancedEncryption(false) {}
    
    // Validation
    bool isValid() const {
        return !modelName.empty() && 
               frequencyStartMHz > 0 && 
               frequencyEndMHz > frequencyStartMHz && 
               channelSpacingKHz > 0 && 
               totalChannels > 0;
    }
    
    // Calculate total channels from frequency range and spacing
    void calculateTotalChannels() {
        if (frequencyStartMHz > 0 && frequencyEndMHz > frequencyStartMHz && channelSpacingKHz > 0) {
            totalChannels = static_cast<int>(((frequencyEndMHz - frequencyStartMHz) * 1000.0 / channelSpacingKHz) + 1);
        }
    }
    
    // Get frequency for a given channel
    double getFrequencyForChannel(int channel) const {
        if (channel < 1 || channel > totalChannels) return 0.0;
        return frequencyStartMHz + ((channel - 1) * channelSpacingKHz / 1000.0);
    }
    
    // Get channel for a given frequency
    int getChannelForFrequency(double frequency) const {
        if (frequency < frequencyStartMHz || frequency > frequencyEndMHz) return 0;
        return static_cast<int>(((frequency - frequencyStartMHz) * 1000.0 / channelSpacingKHz) + 1);
    }
    
    // Check if frequency is valid for this radio
    bool isValidFrequency(double frequency) const {
        return frequency >= frequencyStartMHz && frequency <= frequencyEndMHz;
    }
    
    // Get all channels as frequency list
    std::vector<double> getAllChannels() const {
        std::vector<double> channels;
        double currentFreq = frequencyStartMHz;
        
        while (currentFreq <= frequencyEndMHz) {
            channels.push_back(currentFreq);
            currentFreq += channelSpacingKHz / 1000.0;
        }
        
        return channels;
    }
};

// Radio model configuration manager
class RadioModelConfigManager {
private:
    static std::map<std::string, RadioModelSpec> radioModels;
    static std::string configFilePath;
    static bool isInitialized;
    
public:
    // Initialization
    static void initialize(const std::string& configFile = "radio_models.json");
    static void loadDefaultModels();
    static void loadFromFile(const std::string& filePath);
    static void saveToFile(const std::string& filePath);
    
    // Model management
    static bool addModel(const RadioModelSpec& model);
    static bool updateModel(const std::string& modelName, const RadioModelSpec& model);
    static bool removeModel(const std::string& modelName);
    static RadioModelSpec getModel(const std::string& modelName);
    static std::vector<std::string> getAllModelNames();
    static std::vector<RadioModelSpec> getAllModels();
    
    // Model validation
    static bool validateModel(const RadioModelSpec& model);
    static std::vector<std::string> getValidationErrors(const RadioModelSpec& model);
    
    // Model search and filtering
    static std::vector<std::string> getModelsByCountry(const std::string& country);
    static std::vector<std::string> getModelsByAlliance(const std::string& alliance);
    static std::vector<std::string> getModelsByEra(const std::string& era);
    static std::vector<std::string> getModelsByUsage(const std::string& usage);
    static std::vector<std::string> getModelsByFrequencyRange(double startMHz, double endMHz);
    static std::vector<std::string> getModelsByChannelSpacing(double spacingKHz);
    
    // Model comparison
    static std::map<std::string, std::string> compareModels(const std::string& model1, const std::string& model2);
    static std::vector<std::string> getCompatibleModels(const std::string& modelName);
    
    // Configuration management
    static void setConfigFilePath(const std::string& path);
    static std::string getConfigFilePath();
    static bool isConfigLoaded();
    static void reloadConfig();
    static void resetToDefaults();
    
    // Export/Import
    static bool exportModels(const std::string& filePath, const std::vector<std::string>& modelNames = {});
    static bool importModels(const std::string& filePath, bool overwrite = false);
    static std::string exportToJSON(const std::vector<std::string>& modelNames = {});
    static bool importFromJSON(const std::string& jsonData, bool overwrite = false);
    
    // Statistics
    static std::map<std::string, int> getModelCountByCountry();
    static std::map<std::string, int> getModelCountByAlliance();
    static std::map<std::string, int> getModelCountByEra();
    static std::map<std::string, int> getModelCountByUsage();
    static int getTotalModelCount();
    static double getAverageChannelCount();
    static double getAverageFrequencyRange();
    
    // Utility functions
    static std::string generateModelID(const RadioModelSpec& model);
    static std::string formatModelSummary(const RadioModelSpec& model);
    static std::string formatModelComparison(const RadioModelSpec& model1, const RadioModelSpec& model2);
    static std::vector<std::string> getModelRecommendations(const std::string& criteria);
};

// Radio model factory
class RadioModelFactory {
public:
    // Create radio model from specification
    static std::unique_ptr<class RadioModel> createModel(const std::string& modelName);
    static std::unique_ptr<class RadioModel> createModel(const RadioModelSpec& spec);
    
    // Create radio model from JSON
    static std::unique_ptr<class RadioModel> createModelFromJSON(const std::string& jsonData);
    
    // Get available model types
    static std::vector<std::string> getAvailableModels();
    static std::vector<std::string> getModelsByType(const std::string& type);
    
    // Model validation
    static bool isModelAvailable(const std::string& modelName);
    static bool isModelCompatible(const std::string& model1, const std::string& model2);
};

// Generic radio model implementation
class RadioModel {
private:
    RadioModelSpec spec;
    int currentChannel;
    double currentPower;
    bool isPortable;
    bool isOperational;
    std::map<std::string, bool> features;
    std::map<std::string, std::string> customSettings;
    
public:
    RadioModel(const RadioModelSpec& specification);
    virtual ~RadioModel() = default;
    
    // Basic operations
    bool setChannel(int channel);
    int getCurrentChannel() const;
    double getCurrentFrequency() const;
    bool setFrequency(double frequency);
    
    // Power operations
    void setPortableMode(bool portable);
    bool isPortableMode() const;
    double getCurrentPower() const;
    void setPower(double power);
    
    // Operational status
    void setOperational(bool operational);
    bool isRadioOperational() const;
    
    // Feature management
    void setFeature(const std::string& feature, bool enabled);
    bool isFeatureEnabled(const std::string& feature) const;
    std::vector<std::string> getAvailableFeatures() const;
    std::vector<std::string> getEnabledFeatures() const;
    
    // Custom settings
    void setCustomSetting(const std::string& key, const std::string& value);
    std::string getCustomSetting(const std::string& key) const;
    std::map<std::string, std::string> getAllCustomSettings() const;
    
    // Model information
    RadioModelSpec getSpecification() const;
    std::string getModelName() const;
    std::string getManufacturer() const;
    std::string getCountry() const;
    std::string getAlliance() const;
    std::string getEra() const;
    std::string getUsage() const;
    
    // Channel operations
    bool isValidChannel(int channel) const;
    bool isValidFrequency(double frequency) const;
    std::vector<double> getAllChannels() const;
    int getTotalChannels() const;
    double getFrequencyRange() const;
    double getChannelSpacing() const;
    
    // Preset channels
    bool setPresetChannel(int preset, int channel);
    int getPresetChannel(int preset) const;
    bool selectPresetChannel(int preset);
    int getPresetChannelCount() const;
    
    // Mode operations
    bool setMode(const std::string& mode);
    std::string getCurrentMode() const;
    std::vector<std::string> getSupportedModes() const;
    bool isModeSupported(const std::string& mode) const;
    
    // Validation
    bool validateConfiguration() const;
    std::vector<std::string> getConfigurationErrors() const;
    
    // Serialization
    std::string toJSON() const;
    bool fromJSON(const std::string& jsonData);
    
    // Comparison
    bool isCompatibleWith(const RadioModel& other) const;
    std::map<std::string, std::string> compareWith(const RadioModel& other) const;
};

// JSON serialization helpers
class RadioModelJSON {
public:
    static std::string serialize(const RadioModelSpec& spec);
    static RadioModelSpec deserialize(const std::string& jsonData);
    static std::string serialize(const std::vector<RadioModelSpec>& specs);
    static std::vector<RadioModelSpec> deserializeArray(const std::string& jsonData);
    
    static std::string serialize(const RadioModel& model);
    static RadioModel deserializeModel(const std::string& jsonData);
    
    static bool validateJSON(const std::string& jsonData);
    static std::vector<std::string> getJSONErrors(const std::string& jsonData);
};

// Configuration file formats
class ConfigFileManager {
public:
    // JSON format
    static bool saveToJSON(const std::string& filePath, const std::vector<RadioModelSpec>& models);
    static std::vector<RadioModelSpec> loadFromJSON(const std::string& filePath);
    
    // CSV format
    static bool saveToCSV(const std::string& filePath, const std::vector<RadioModelSpec>& models);
    static std::vector<RadioModelSpec> loadFromCSV(const std::string& filePath);
    
    // XML format
    static bool saveToXML(const std::string& filePath, const std::vector<RadioModelSpec>& models);
    static std::vector<RadioModelSpec> loadFromXML(const std::string& filePath);
    
    // YAML format
    static bool saveToYAML(const std::string& filePath, const std::vector<RadioModelSpec>& models);
    static std::vector<RadioModelSpec> loadFromYAML(const std::string& filePath);
    
    // Format detection
    static std::string detectFormat(const std::string& filePath);
    static bool isSupportedFormat(const std::string& format);
    static std::vector<std::string> getSupportedFormats();
};

} // namespace RadioModelConfig

#endif // FGCOM_RADIO_MODEL_CONFIG_H
