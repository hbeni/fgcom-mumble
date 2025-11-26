/**
 * @file piper_tts.h
 * @brief Piper TTS class header
 * @author FGcom-mumble Development Team
 * @date 2025
 */

#ifndef PIPER_TTS_H
#define PIPER_TTS_H

#include <string>
#include <vector>

/**
 * @class PiperTTS
 * @brief Piper Text-to-Speech integration
 */
class PiperTTS {
public:
    PiperTTS();
    ~PiperTTS();
    
    bool isInitialized() const;
    std::string getDefaultModel() const;
    int getSampleRate() const;
    int getBitrate() const;
    std::vector<std::string> getAvailableModels() const;
    bool generateAudio(const std::string& text, const std::string& outputFile);
    bool setModel(const std::string& model);
    std::string getCurrentModel() const;

private:
    bool initialized_;
    std::string defaultModel_;
    int sampleRate_;
    int bitrate_;
    std::vector<std::string> availableModels_;
};

#endif // PIPER_TTS_H
