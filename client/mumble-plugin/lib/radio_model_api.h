#ifndef FGCOM_RADIO_MODEL_API_H
#define FGCOM_RADIO_MODEL_API_H

#include "radio_model_config.h"
#include <string>
#include <vector>
#include <map>

// Radio Model API for external access
namespace RadioModelAPI {

// API Response structures
struct APIResponse {
    bool success;
    std::string message;
    std::string data;
    int errorCode;
    
    APIResponse() : success(false), errorCode(0) {}
    APIResponse(bool s, const std::string& m, const std::string& d = "", int e = 0) 
        : success(s), message(m), data(d), errorCode(e) {}
};

struct RadioModelInfo {
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
};

// Radio Model API Server
class RadioModelAPIServer {
private:
    static bool isInitialized;
    static std::string configPath;
    
public:
    // Initialization
    static void initialize(const std::string& configPath = "radio_models.json");
    static bool isAPIRunning();
    static void shutdown();
    
    // Model Management API (READ-ONLY)
    static APIResponse getModel(const std::string& modelName);
    static APIResponse getAllModels();
    static APIResponse getModelsByFilter(const std::map<std::string, std::string>& filters);
    
    // Model Search API
    static APIResponse searchModels(const std::string& query);
    static APIResponse getModelsByCountry(const std::string& country);
    static APIResponse getModelsByAlliance(const std::string& alliance);
    static APIResponse getModelsByEra(const std::string& era);
    static APIResponse getModelsByUsage(const std::string& usage);
    static APIResponse getModelsByFrequencyRange(double startMHz, double endMHz);
    static APIResponse getModelsByChannelSpacing(double spacingKHz);
    
    // Model Operations API (READ-ONLY)
    static APIResponse compareModels(const std::string& model1, const std::string& model2);
    static APIResponse getCompatibleModels(const std::string& modelName);
    static APIResponse getModelRecommendations(const std::string& criteria);
    
    // Channel Operations API
    static APIResponse getChannelFrequency(const std::string& modelName, int channel);
    static APIResponse getFrequencyChannel(const std::string& modelName, double frequency);
    static APIResponse getAllChannels(const std::string& modelName);
    static APIResponse validateChannel(const std::string& modelName, int channel);
    static APIResponse validateFrequency(const std::string& modelName, double frequency);
    
    // Configuration API (READ-ONLY)
    static APIResponse exportToJSON(const std::vector<std::string>& modelNames = {});
    
    // Statistics API
    static APIResponse getModelStatistics();
    static APIResponse getModelCountByCountry();
    static APIResponse getModelCountByAlliance();
    static APIResponse getModelCountByEra();
    static APIResponse getModelCountByUsage();
    static APIResponse getTotalModelCount();
    static APIResponse getAverageChannelCount();
    static APIResponse getAverageFrequencyRange();
    
    // Utility API
    static APIResponse generateModelID(const RadioModelInfo& modelInfo);
    static APIResponse formatModelSummary(const std::string& modelName);
    static APIResponse formatModelComparison(const std::string& model1, const std::string& model2);
    static APIResponse getModelRecommendations(const std::string& criteria);
    
    // Configuration Management API
    static APIResponse setConfigPath(const std::string& path);
    static APIResponse getConfigPath();
    static APIResponse reloadConfig();
    static APIResponse resetToDefaults();
    static APIResponse backupConfig();
    static APIResponse restoreConfig(const std::string& backupPath);
    
    // Health Check API
    static APIResponse healthCheck();
    static APIResponse getAPIVersion();
    static APIResponse getAPIStatus();
    static APIResponse getSystemInfo();
};

// Radio Model Client (for external applications)
class RadioModelClient {
private:
    std::string apiEndpoint;
    std::string apiKey;
    bool isConnected;
    
public:
    RadioModelClient(const std::string& endpoint = "http://localhost:8080/api", const std::string& key = "");
    
    // Connection management
    bool connect();
    void disconnect();
    bool isAPIConnected() const;
    
    // Model operations (READ-ONLY)
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
    
    // Configuration operations (READ-ONLY)
    APIResponse exportToJSON(const std::vector<std::string>& modelNames = {});
    
    // Utility operations
    APIResponse compareModels(const std::string& model1, const std::string& model2);
    APIResponse getCompatibleModels(const std::string& modelName);
    APIResponse getModelRecommendations(const std::string& criteria);
    APIResponse getModelStatistics();
    
    // Health check
    APIResponse healthCheck();
    APIResponse getAPIVersion();
    APIResponse getAPIStatus();
};

// Radio Model Builder (SERVER-SIDE ONLY - for internal server configuration)
class RadioModelBuilder {
private:
    RadioModelInfo modelInfo;
    
public:
    RadioModelBuilder();
    
    // Basic information (SERVER-SIDE ONLY)
    RadioModelBuilder& setModelName(const std::string& name);
    RadioModelBuilder& setManufacturer(const std::string& manufacturer);
    RadioModelBuilder& setCountry(const std::string& country);
    RadioModelBuilder& setAlliance(const std::string& alliance);
    RadioModelBuilder& setEra(const std::string& era);
    RadioModelBuilder& setUsage(const std::string& usage);
    
    // Frequency specifications (SERVER-SIDE ONLY)
    RadioModelBuilder& setFrequencyRange(double startMHz, double endMHz);
    RadioModelBuilder& setChannelSpacing(double spacingKHz);
    RadioModelBuilder& setTotalChannels(int channels);
    
    // Power specifications (SERVER-SIDE ONLY)
    RadioModelBuilder& setPortablePower(double powerWatts);
    RadioModelBuilder& setVehiclePower(double powerWatts);
    
    // Capabilities (SERVER-SIDE ONLY)
    RadioModelBuilder& setEncryptionCapable(bool capable);
    RadioModelBuilder& setGPSCapable(bool capable);
    RadioModelBuilder& setDataCapable(bool capable);
    RadioModelBuilder& setNetworkCapable(bool capable);
    RadioModelBuilder& setAdvancedEncryption(bool capable);
    
    // Modes and features (SERVER-SIDE ONLY)
    RadioModelBuilder& addSupportedMode(const std::string& mode);
    RadioModelBuilder& setSupportedModes(const std::vector<std::string>& modes);
    RadioModelBuilder& addPresetChannel(const std::string& channel);
    RadioModelBuilder& setPresetChannels(const std::vector<std::string>& channels);
    
    // Custom properties (SERVER-SIDE ONLY)
    RadioModelBuilder& addCustomProperty(const std::string& key, const std::string& value);
    RadioModelBuilder& setCustomProperties(const std::map<std::string, std::string>& properties);
    
    // Build and validation (SERVER-SIDE ONLY)
    RadioModelInfo build();
    bool validate();
    std::vector<std::string> getValidationErrors();
    
    // Reset (SERVER-SIDE ONLY)
    void reset();
};

// Radio Model Validator
class RadioModelValidator {
public:
    static bool validateModelInfo(const RadioModelInfo& modelInfo);
    static std::vector<std::string> getValidationErrors(const RadioModelInfo& modelInfo);
    static bool validateFrequencyRange(double startMHz, double endMHz);
    static bool validateChannelSpacing(double spacingKHz);
    static bool validatePowerLevels(double portablePower, double vehiclePower);
    static bool validateModelName(const std::string& name);
    static bool validateCountry(const std::string& country);
    static bool validateAlliance(const std::string& alliance);
    static bool validateEra(const std::string& era);
    static bool validateUsage(const std::string& usage);
    
    // Advanced validation
    static bool validateModelCompatibility(const RadioModelInfo& model1, const RadioModelInfo& model2);
    static bool validateFrequencyCompatibility(double freq1, double freq2, double tolerance = 0.001);
    static bool validateChannelSpacingCompatibility(double spacing1, double spacing2);
    static bool validatePowerCompatibility(double power1, double power2, double tolerance = 0.1);
};

// Radio Model Converter (for format conversion)
class RadioModelConverter {
public:
    // JSON conversion
    static std::string modelInfoToJSON(const RadioModelInfo& modelInfo);
    static RadioModelInfo jsonToModelInfo(const std::string& jsonData);
    static std::string modelInfoArrayToJSON(const std::vector<RadioModelInfo>& modelInfos);
    static std::vector<RadioModelInfo> jsonToModelInfoArray(const std::string& jsonData);
    
    // CSV conversion
    static std::string modelInfoToCSV(const RadioModelInfo& modelInfo);
    static RadioModelInfo csvToModelInfo(const std::string& csvData);
    static std::string modelInfoArrayToCSV(const std::vector<RadioModelInfo>& modelInfos);
    static std::vector<RadioModelInfo> csvToModelInfoArray(const std::string& csvData);
    
    // XML conversion
    static std::string modelInfoToXML(const RadioModelInfo& modelInfo);
    static RadioModelInfo xmlToModelInfo(const std::string& xmlData);
    static std::string modelInfoArrayToXML(const std::vector<RadioModelInfo>& modelInfos);
    static std::vector<RadioModelInfo> xmlToModelInfoArray(const std::string& xmlData);
    
    // YAML conversion
    static std::string modelInfoToYAML(const RadioModelInfo& modelInfo);
    static RadioModelInfo yamlToModelInfo(const std::string& yamlData);
    static std::string modelInfoArrayToYAML(const std::vector<RadioModelInfo>& modelInfos);
    static std::vector<RadioModelInfo> yamlToModelInfoArray(const std::string& yamlData);
    
    // Format detection
    static std::string detectFormat(const std::string& data);
    static bool isSupportedFormat(const std::string& format);
    static std::vector<std::string> getSupportedFormats();
};

} // namespace RadioModelAPI

#endif // FGCOM_RADIO_MODEL_API_H
