/**
 * @file tts_configuration.cpp
 * @brief TTS Configuration class implementation
 * @author FGcom-mumble Development Team
 * @date 2025
 */

#include "tts_configuration.h"
#include <fstream>
#include <sstream>

TTSConfiguration::TTSConfiguration() : initialized_(true), sampleRate_(22050), bitrate_(128) {
    defaultModel_ = "en_US-lessac-medium";
    outputDirectory_ = "/tmp/tts_output";
}

TTSConfiguration::~TTSConfiguration() = default;

bool TTSConfiguration::isInitialized() const {
    return initialized_;
}

std::string TTSConfiguration::getDefaultModel() const {
    return defaultModel_;
}

int TTSConfiguration::getSampleRate() const {
    return sampleRate_;
}

int TTSConfiguration::getBitrate() const {
    return bitrate_;
}

std::string TTSConfiguration::getOutputDirectory() const {
    return outputDirectory_;
}

bool TTSConfiguration::loadConfiguration(const std::string& configPath) {
    std::ifstream file(configPath);
    if (!file.is_open()) return false;
    
    // Parse configuration file
    std::string line;
    while (std::getline(file, line)) {
        if (line.find("model=") == 0) {
            defaultModel_ = line.substr(6);
        } else if (line.find("sample_rate=") == 0) {
            sampleRate_ = std::stoi(line.substr(12));
        } else if (line.find("bitrate=") == 0) {
            bitrate_ = std::stoi(line.substr(8));
        } else if (line.find("output_dir=") == 0) {
            outputDirectory_ = line.substr(11);
        }
    }
    return true;
}

bool TTSConfiguration::saveConfiguration(const std::string& outputPath) {
    std::ofstream file(outputPath);
    if (!file.is_open()) return false;
    
    file << "model=" << defaultModel_ << "\n";
    file << "sample_rate=" << sampleRate_ << "\n";
    file << "bitrate=" << bitrate_ << "\n";
    file << "output_dir=" << outputDirectory_ << "\n";
    return true;
}

void TTSConfiguration::resetConfiguration() {
    defaultModel_ = "en_US-lessac-medium";
    sampleRate_ = 22050;
    bitrate_ = 128;
    outputDirectory_ = "/tmp/tts_output";
}

bool TTSConfiguration::validateConfiguration() {
    return !defaultModel_.empty() && sampleRate_ > 0 && bitrate_ > 0 && !outputDirectory_.empty();
}

bool TTSConfiguration::isValidModel(const std::string& model) const {
    return !model.empty() && model.find("en_US") != std::string::npos;
}

bool TTSConfiguration::isValidSampleRate(int rate) const {
    return rate > 0 && rate <= 48000;
}

bool TTSConfiguration::isValidBitrate(int rate) const {
    return rate > 0 && rate <= 320;
}

bool TTSConfiguration::isValidOutputDirectory(const std::string& dir) const {
    return !dir.empty();
}

bool TTSConfiguration::isDefaultConfiguration() const {
    return defaultModel_ == "en_US-lessac-medium" && 
           sampleRate_ == 22050 && 
           bitrate_ == 128;
}
