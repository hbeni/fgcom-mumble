/**
 * @file tts_configuration.h
 * @brief TTS Configuration class header
 * @author FGcom-mumble Development Team
 * @date 2025
 */

#ifndef TTS_CONFIGURATION_H
#define TTS_CONFIGURATION_H

#include <string>

/**
 * @class TTSConfiguration
 * @brief TTS system configuration management
 */
class TTSConfiguration {
public:
    TTSConfiguration();
    ~TTSConfiguration();
    
    bool isInitialized() const;
    std::string getDefaultModel() const;
    int getSampleRate() const;
    int getBitrate() const;
    std::string getOutputDirectory() const;
    bool loadConfiguration(const std::string& configPath);
    bool saveConfiguration(const std::string& outputPath);
    void resetConfiguration();
    bool validateConfiguration();
    bool isValidModel(const std::string& model) const;
    bool isValidSampleRate(int rate) const;
    bool isValidBitrate(int rate) const;
    bool isValidOutputDirectory(const std::string& dir) const;
    bool isDefaultConfiguration() const;

private:
    bool initialized_;
    std::string defaultModel_;
    int sampleRate_;
    int bitrate_;
    std::string outputDirectory_;
};

#endif // TTS_CONFIGURATION_H
