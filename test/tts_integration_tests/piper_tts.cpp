/**
 * @file piper_tts.cpp
 * @brief Piper TTS class implementation
 * @author FGcom-mumble Development Team
 * @date 2025
 */

#include "piper_tts.h"
#include <fstream>

PiperTTS::PiperTTS() : initialized_(true), sampleRate_(22050), bitrate_(128) {
    defaultModel_ = "en_US-lessac-medium";
    availableModels_ = {"en_US-lessac-medium", "en_US-lessac-low", "en_US-lessac-high"};
}

PiperTTS::~PiperTTS() = default;

bool PiperTTS::isInitialized() const {
    return initialized_;
}

std::string PiperTTS::getDefaultModel() const {
    return defaultModel_;
}

int PiperTTS::getSampleRate() const {
    return sampleRate_;
}

int PiperTTS::getBitrate() const {
    return bitrate_;
}

std::vector<std::string> PiperTTS::getAvailableModels() const {
    return availableModels_;
}

bool PiperTTS::generateAudio(const std::string& text, const std::string& outputFile) {
    if (!initialized_ || text.empty()) return false;
    
    // Stub implementation - just write text to file
    std::ofstream file(outputFile);
    if (!file.is_open()) return false;
    
    file << "Generated audio for: " << text;
    file.close();
    return true;
}

bool PiperTTS::setModel(const std::string& model) {
    for (const auto& availableModel : availableModels_) {
        if (availableModel == model) {
            defaultModel_ = model;
            return true;
        }
    }
    return false;
}

std::string PiperTTS::getCurrentModel() const {
    return defaultModel_;
}
