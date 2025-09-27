#ifndef FGCOM_PRESET_CHANNEL_API_H
#define FGCOM_PRESET_CHANNEL_API_H

#include <string>
#include <vector>
#include <map>
#include <memory>

// Preset Channel API for managing radio preset channels
namespace PresetChannelAPI {

// Preset channel information structure
struct PresetChannelInfo {
    int presetNumber;
    int channelNumber;
    double frequency;
    std::string label;
    std::string description;
    bool isActive;
    std::map<std::string, std::string> customProperties;
    
    PresetChannelInfo() : presetNumber(0), channelNumber(0), frequency(0.0), isActive(false) {}
    PresetChannelInfo(int preset, int channel, double freq, const std::string& lbl = "", const std::string& desc = "")
        : presetNumber(preset), channelNumber(channel), frequency(freq), label(lbl), description(desc), isActive(true) {}
};

// API Response structure
struct PresetAPIResponse {
    bool success;
    std::string message;
    std::string data;
    int errorCode;
    
    PresetAPIResponse() : success(false), errorCode(0) {}
    PresetAPIResponse(bool s, const std::string& m, const std::string& d = "", int e = 0) 
        : success(s), message(m), data(d), errorCode(e) {}
};

// Preset Channel Manager
class PresetChannelManager {
private:
    static std::map<std::string, std::vector<PresetChannelInfo>> radioPresets;
    static bool isInitialized;
    
public:
    // Initialization
    static void initialize();
    static bool isAPIRunning();
    static void shutdown();
    
    // Preset management for specific radio models
    static bool setPresetChannel(const std::string& radioModel, int presetNumber, int channelNumber, 
                                 const std::string& label = "", const std::string& description = "");
    static bool setPresetFrequency(const std::string& radioModel, int presetNumber, double frequency, 
                                  const std::string& label = "", const std::string& description = "");
    static PresetChannelInfo getPresetChannel(const std::string& radioModel, int presetNumber);
    static std::vector<PresetChannelInfo> getAllPresetChannels(const std::string& radioModel);
    static bool deletePresetChannel(const std::string& radioModel, int presetNumber);
    static bool clearAllPresets(const std::string& radioModel);
    
    // Preset operations
    static bool selectPresetChannel(const std::string& radioModel, int presetNumber);
    static bool isPresetActive(const std::string& radioModel, int presetNumber);
    static bool setPresetLabel(const std::string& radioModel, int presetNumber, const std::string& label);
    static bool setPresetDescription(const std::string& radioModel, int presetNumber, const std::string& description);
    static bool setPresetActive(const std::string& radioModel, int presetNumber, bool active);
    
    // Preset validation
    static bool validatePresetChannel(const std::string& radioModel, int presetNumber, int channelNumber);
    static bool validatePresetFrequency(const std::string& radioModel, int presetNumber, double frequency);
    static std::vector<std::string> getPresetValidationErrors(const std::string& radioModel, int presetNumber);
    
    // Preset search and filtering
    static std::vector<PresetChannelInfo> searchPresets(const std::string& radioModel, const std::string& query);
    static std::vector<PresetChannelInfo> getPresetsByFrequency(const std::string& radioModel, double frequency, double tolerance = 0.001);
    static std::vector<PresetChannelInfo> getPresetsByChannel(const std::string& radioModel, int channelNumber);
    static std::vector<PresetChannelInfo> getActivePresets(const std::string& radioModel);
    static std::vector<PresetChannelInfo> getInactivePresets(const std::string& radioModel);
    
    // Preset statistics
    static int getPresetCount(const std::string& radioModel);
    static int getActivePresetCount(const std::string& radioModel);
    static int getInactivePresetCount(const std::string& radioModel);
    static double getPresetFrequencyRange(const std::string& radioModel);
    static std::map<int, int> getPresetChannelDistribution(const std::string& radioModel);
    
    // Preset export/import
    static std::string exportPresetsToJSON(const std::string& radioModel);
    static bool importPresetsFromJSON(const std::string& radioModel, const std::string& jsonData, bool overwrite = false);
    static std::string exportPresetsToCSV(const std::string& radioModel);
    static bool importPresetsFromCSV(const std::string& radioModel, const std::string& csvData, bool overwrite = false);
    
    // Preset backup and restore
    static std::string backupPresets(const std::string& radioModel);
    static bool restorePresets(const std::string& radioModel, const std::string& backupData);
    static bool clearPresets(const std::string& radioModel);
    
    // Preset comparison
    static std::map<std::string, std::string> comparePresets(const std::string& radioModel1, const std::string& radioModel2);
    static std::vector<PresetChannelInfo> getCommonPresets(const std::string& radioModel1, const std::string& radioModel2);
    static std::vector<PresetChannelInfo> getUniquePresets(const std::string& radioModel1, const std::string& radioModel2);
    
    // Preset recommendations
    static std::vector<PresetChannelInfo> getPresetRecommendations(const std::string& radioModel, const std::string& criteria);
    static std::vector<PresetChannelInfo> getPopularPresets(const std::string& radioModel);
    static std::vector<PresetChannelInfo> getRecentlyUsedPresets(const std::string& radioModel);
};

// Preset Channel API Server
class PresetChannelAPIServer {
private:
    static bool isInitialized;
    static std::string apiVersion;
    
public:
    // Initialization
    static void initialize(const std::string& version = "1.0.0");
    static bool isAPIRunning();
    static void shutdown();
    static std::string getAPIVersion();
    
    // Preset management API
    static PresetAPIResponse createPreset(const std::string& radioModel, const PresetChannelInfo& presetInfo);
    static PresetAPIResponse updatePreset(const std::string& radioModel, int presetNumber, const PresetChannelInfo& presetInfo);
    static PresetAPIResponse deletePreset(const std::string& radioModel, int presetNumber);
    static PresetAPIResponse getPreset(const std::string& radioModel, int presetNumber);
    static PresetAPIResponse getAllPresets(const std::string& radioModel);
    static PresetAPIResponse getPresetsByFilter(const std::string& radioModel, const std::map<std::string, std::string>& filters);
    
    // Preset operations API
    static PresetAPIResponse selectPreset(const std::string& radioModel, int presetNumber);
    static PresetAPIResponse setPresetLabel(const std::string& radioModel, int presetNumber, const std::string& label);
    static PresetAPIResponse setPresetDescription(const std::string& radioModel, int presetNumber, const std::string& description);
    static PresetAPIResponse setPresetActive(const std::string& radioModel, int presetNumber, bool active);
    static PresetAPIResponse setPresetChannel(const std::string& radioModel, int presetNumber, int channelNumber);
    static PresetAPIResponse setPresetFrequency(const std::string& radioModel, int presetNumber, double frequency);
    
    // Preset search API
    static PresetAPIResponse searchPresets(const std::string& radioModel, const std::string& query);
    static PresetAPIResponse getPresetsByFrequency(const std::string& radioModel, double frequency, double tolerance = 0.001);
    static PresetAPIResponse getPresetsByChannel(const std::string& radioModel, int channelNumber);
    static PresetAPIResponse getActivePresets(const std::string& radioModel);
    static PresetAPIResponse getInactivePresets(const std::string& radioModel);
    
    // Preset statistics API
    static PresetAPIResponse getPresetStatistics(const std::string& radioModel);
    static PresetAPIResponse getPresetCount(const std::string& radioModel);
    static PresetAPIResponse getActivePresetCount(const std::string& radioModel);
    static PresetAPIResponse getInactivePresetCount(const std::string& radioModel);
    static PresetAPIResponse getPresetFrequencyRange(const std::string& radioModel);
    static PresetAPIResponse getPresetChannelDistribution(const std::string& radioModel);
    
    // Preset export/import API
    static PresetAPIResponse exportPresets(const std::string& radioModel, const std::string& filePath);
    static PresetAPIResponse importPresets(const std::string& radioModel, const std::string& filePath, bool overwrite = false);
    static PresetAPIResponse exportPresetsToJSON(const std::string& radioModel);
    static PresetAPIResponse importPresetsFromJSON(const std::string& radioModel, const std::string& jsonData, bool overwrite = false);
    static PresetAPIResponse exportPresetsToCSV(const std::string& radioModel);
    static PresetAPIResponse importPresetsFromCSV(const std::string& radioModel, const std::string& csvData, bool overwrite = false);
    
    // Preset backup/restore API
    static PresetAPIResponse backupPresets(const std::string& radioModel);
    static PresetAPIResponse restorePresets(const std::string& radioModel, const std::string& backupData);
    static PresetAPIResponse clearPresets(const std::string& radioModel);
    
    // Preset comparison API
    static PresetAPIResponse comparePresets(const std::string& radioModel1, const std::string& radioModel2);
    static PresetAPIResponse getCommonPresets(const std::string& radioModel1, const std::string& radioModel2);
    static PresetAPIResponse getUniquePresets(const std::string& radioModel1, const std::string& radioModel2);
    
    // Preset recommendations API
    static PresetAPIResponse getPresetRecommendations(const std::string& radioModel, const std::string& criteria);
    static PresetAPIResponse getPopularPresets(const std::string& radioModel);
    static PresetAPIResponse getRecentlyUsedPresets(const std::string& radioModel);
    
    // Health check API
    static PresetAPIResponse healthCheck();
    static PresetAPIResponse getAPIStatus();
    static PresetAPIResponse getSystemInfo();
};

// Preset Channel Client (for external applications)
class PresetChannelClient {
private:
    std::string apiEndpoint;
    std::string apiKey;
    bool isConnected;
    
public:
    PresetChannelClient(const std::string& endpoint = "http://localhost:8080/api", const std::string& key = "");
    
    // Connection management
    bool connect();
    void disconnect();
    bool isAPIConnected() const;
    
    // Preset operations
    PresetAPIResponse createPreset(const std::string& radioModel, const PresetChannelInfo& presetInfo);
    PresetAPIResponse updatePreset(const std::string& radioModel, int presetNumber, const PresetChannelInfo& presetInfo);
    PresetAPIResponse deletePreset(const std::string& radioModel, int presetNumber);
    PresetAPIResponse getPreset(const std::string& radioModel, int presetNumber);
    PresetAPIResponse getAllPresets(const std::string& radioModel);
    
    // Preset operations
    PresetAPIResponse selectPreset(const std::string& radioModel, int presetNumber);
    PresetAPIResponse setPresetLabel(const std::string& radioModel, int presetNumber, const std::string& label);
    PresetAPIResponse setPresetDescription(const std::string& radioModel, int presetNumber, const std::string& description);
    PresetAPIResponse setPresetActive(const std::string& radioModel, int presetNumber, bool active);
    PresetAPIResponse setPresetChannel(const std::string& radioModel, int presetNumber, int channelNumber);
    PresetAPIResponse setPresetFrequency(const std::string& radioModel, int presetNumber, double frequency);
    
    // Preset search
    PresetAPIResponse searchPresets(const std::string& radioModel, const std::string& query);
    PresetAPIResponse getPresetsByFrequency(const std::string& radioModel, double frequency, double tolerance = 0.001);
    PresetAPIResponse getPresetsByChannel(const std::string& radioModel, int channelNumber);
    PresetAPIResponse getActivePresets(const std::string& radioModel);
    PresetAPIResponse getInactivePresets(const std::string& radioModel);
    
    // Preset statistics
    PresetAPIResponse getPresetStatistics(const std::string& radioModel);
    PresetAPIResponse getPresetCount(const std::string& radioModel);
    PresetAPIResponse getActivePresetCount(const std::string& radioModel);
    PresetAPIResponse getInactivePresetCount(const std::string& radioModel);
    PresetAPIResponse getPresetFrequencyRange(const std::string& radioModel);
    PresetAPIResponse getPresetChannelDistribution(const std::string& radioModel);
    
    // Preset export/import
    PresetAPIResponse exportPresets(const std::string& radioModel, const std::string& filePath);
    PresetAPIResponse importPresets(const std::string& radioModel, const std::string& filePath, bool overwrite = false);
    PresetAPIResponse exportPresetsToJSON(const std::string& radioModel);
    PresetAPIResponse importPresetsFromJSON(const std::string& radioModel, const std::string& jsonData, bool overwrite = false);
    PresetAPIResponse exportPresetsToCSV(const std::string& radioModel);
    PresetAPIResponse importPresetsFromCSV(const std::string& radioModel, const std::string& csvData, bool overwrite = false);
    
    // Preset backup/restore
    PresetAPIResponse backupPresets(const std::string& radioModel);
    PresetAPIResponse restorePresets(const std::string& radioModel, const std::string& backupData);
    PresetAPIResponse clearPresets(const std::string& radioModel);
    
    // Preset comparison
    PresetAPIResponse comparePresets(const std::string& radioModel1, const std::string& radioModel2);
    PresetAPIResponse getCommonPresets(const std::string& radioModel1, const std::string& radioModel2);
    PresetAPIResponse getUniquePresets(const std::string& radioModel1, const std::string& radioModel2);
    
    // Preset recommendations
    PresetAPIResponse getPresetRecommendations(const std::string& radioModel, const std::string& criteria);
    PresetAPIResponse getPopularPresets(const std::string& radioModel);
    PresetAPIResponse getRecentlyUsedPresets(const std::string& radioModel);
    
    // Health check
    PresetAPIResponse healthCheck();
    PresetAPIResponse getAPIVersion();
    PresetAPIResponse getAPIStatus();
};

// Preset Channel Builder (for creating custom presets)
class PresetChannelBuilder {
private:
    PresetChannelInfo presetInfo;
    
public:
    PresetChannelBuilder();
    
    // Basic information
    PresetChannelBuilder& setPresetNumber(int presetNumber);
    PresetChannelBuilder& setChannelNumber(int channelNumber);
    PresetChannelBuilder& setFrequency(double frequency);
    PresetChannelBuilder& setLabel(const std::string& label);
    PresetChannelBuilder& setDescription(const std::string& description);
    PresetChannelBuilder& setActive(bool active);
    
    // Custom properties
    PresetChannelBuilder& addCustomProperty(const std::string& key, const std::string& value);
    PresetChannelBuilder& setCustomProperties(const std::map<std::string, std::string>& properties);
    
    // Build and validation
    PresetChannelInfo build();
    bool validate();
    std::vector<std::string> getValidationErrors();
    
    // Reset
    void reset();
};

// Preset Channel Validator
class PresetChannelValidator {
public:
    static bool validatePresetInfo(const PresetChannelInfo& presetInfo);
    static std::vector<std::string> getValidationErrors(const PresetChannelInfo& presetInfo);
    static bool validatePresetNumber(int presetNumber, int maxPresets);
    static bool validateChannelNumber(int channelNumber, int maxChannels);
    static bool validateFrequency(double frequency, double minFreq, double maxFreq);
    static bool validateLabel(const std::string& label);
    static bool validateDescription(const std::string& description);
    
    // Advanced validation
    static bool validatePresetCompatibility(const PresetChannelInfo& preset1, const PresetChannelInfo& preset2);
    static bool validateFrequencyCompatibility(double freq1, double freq2, double tolerance = 0.001);
    static bool validateChannelCompatibility(int channel1, int channel2);
};

// Preset Channel Converter (for format conversion)
class PresetChannelConverter {
public:
    // JSON conversion
    static std::string presetInfoToJSON(const PresetChannelInfo& presetInfo);
    static PresetChannelInfo jsonToPresetInfo(const std::string& jsonData);
    static std::string presetInfoArrayToJSON(const std::vector<PresetChannelInfo>& presetInfos);
    static std::vector<PresetChannelInfo> jsonToPresetInfoArray(const std::string& jsonData);
    
    // CSV conversion
    static std::string presetInfoToCSV(const PresetChannelInfo& presetInfo);
    static PresetChannelInfo csvToPresetInfo(const std::string& csvData);
    static std::string presetInfoArrayToCSV(const std::vector<PresetChannelInfo>& presetInfos);
    static std::vector<PresetChannelInfo> csvToPresetInfoArray(const std::string& csvData);
    
    // XML conversion
    static std::string presetInfoToXML(const PresetChannelInfo& presetInfo);
    static PresetChannelInfo xmlToPresetInfo(const std::string& xmlData);
    static std::string presetInfoArrayToXML(const std::vector<PresetChannelInfo>& presetInfos);
    static std::vector<PresetChannelInfo> xmlToPresetInfoArray(const std::string& xmlData);
    
    // YAML conversion
    static std::string presetInfoToYAML(const PresetChannelInfo& presetInfo);
    static PresetChannelInfo yamlToPresetInfo(const std::string& yamlData);
    static std::string presetInfoArrayToYAML(const std::vector<PresetChannelInfo>& presetInfos);
    static std::vector<PresetChannelInfo> yamlToPresetInfoArray(const std::string& yamlData);
    
    // Format detection
    static std::string detectFormat(const std::string& data);
    static bool isSupportedFormat(const std::string& format);
    static std::vector<std::string> getSupportedFormats();
};

} // namespace PresetChannelAPI

#endif // FGCOM_PRESET_CHANNEL_API_H
