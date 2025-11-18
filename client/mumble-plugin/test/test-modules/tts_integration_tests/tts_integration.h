/**
 * @file tts_integration.h
 * @brief TTS Integration class header
 * @author FGcom-mumble Development Team
 * @date 2025
 */

#ifndef TTS_INTEGRATION_H
#define TTS_INTEGRATION_H

#include <string>
#include <vector>
#include <map>

/**
 * @class TTSIntegration
 * @brief Main TTS system integration
 */
class TTSIntegration {
public:
    TTSIntegration();
    ~TTSIntegration();
    
    bool isInitialized() const;
    bool isEnabled() const;
    std::string getDefaultModel() const;
    int getSampleRate() const;
    int getBitrate() const;
    std::string getOutputDirectory() const;
    std::vector<std::string> getAvailableModels() const;
    bool loadConfiguration(const std::string& configPath);
    bool validateConfiguration();
    std::string preprocessText(const std::string& text);
    bool generateAudio(const std::string& text, const std::string& outputFile);
    std::string generateATISText(const std::string& airportCode,
                                const std::string& weatherInfo,
                                const std::string& runwayInfo);
    std::string loadTemplate(const std::string& templatePath);
    bool saveConfiguration(const std::string& outputPath);
    void resetConfiguration();
    bool initializeLogging();
    void setLogLevel(const std::string& level);
    std::string getLogLevel() const;
    bool setModel(const std::string& model);
    std::string getCurrentModel() const;
    bool validateText(const std::string& text);
    bool validateAudioFile(const std::string& filePath);
    bool generateATISAudio(const std::string& airportCode,
                          const std::string& weatherInfo,
                          const std::string& runwayInfo,
                          const std::string& outputFile);
    std::string processTemplate(const std::string& templateContent,
                               const std::map<std::string, std::string>& variables);
    bool isDefaultConfiguration() const;
    bool startMonitoring();
    bool isMonitoring() const;
    std::map<std::string, std::string> getMonitoringData() const;
    void stopMonitoring();

private:
    bool initialized_;
    bool enabled_;
    std::string defaultModel_;
    int sampleRate_;
    int bitrate_;
    std::string outputDirectory_;
    std::vector<std::string> availableModels_;
    std::string logLevel_;
    bool monitoring_;
};

#endif // TTS_INTEGRATION_H
