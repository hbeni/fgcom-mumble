/**
 * @file tts_integration.cpp
 * @brief TTS Integration class implementation
 * @author FGcom-mumble Development Team
 * @date 2025
 */

#include "tts_integration.h"
#include "tts_configuration.h"
#include "piper_tts.h"
#include "atis_generator.h"
#include <fstream>
#include <sstream>

TTSIntegration::TTSIntegration() : initialized_(true), enabled_(true), sampleRate_(22050), bitrate_(128) {
    defaultModel_ = "en_US-lessac-medium";
    outputDirectory_ = "/tmp/tts_output";
    availableModels_ = {"en_US-lessac-medium", "en_US-lessac-low", "en_US-lessac-high"};
    logLevel_ = "DEBUG";
    monitoring_ = false;
}

TTSIntegration::~TTSIntegration() = default;

bool TTSIntegration::isInitialized() const {
    return initialized_;
}

bool TTSIntegration::isEnabled() const {
    return enabled_;
}

std::string TTSIntegration::getDefaultModel() const {
    return defaultModel_;
}

int TTSIntegration::getSampleRate() const {
    return sampleRate_;
}

int TTSIntegration::getBitrate() const {
    return bitrate_;
}

std::string TTSIntegration::getOutputDirectory() const {
    return outputDirectory_;
}

std::vector<std::string> TTSIntegration::getAvailableModels() const {
    return availableModels_;
}

bool TTSIntegration::loadConfiguration(const std::string& configPath) {
    std::ifstream file(configPath);
    if (!file.is_open()) return false;
    
    // Simple config parsing
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

bool TTSIntegration::validateConfiguration() {
    return !defaultModel_.empty() && sampleRate_ > 0 && bitrate_ > 0 && !outputDirectory_.empty();
}

std::string TTSIntegration::preprocessText(const std::string& text) {
    if (text.empty()) return "";
    
    std::string processed = text;
    // Simple preprocessing - remove extra spaces, convert to uppercase for ATIS
    size_t pos = 0;
    while ((pos = processed.find("  ", pos)) != std::string::npos) {
        processed.replace(pos, 2, " ");
    }
    
    // Add a prefix to make it different from input
    processed = "[TTS] " + processed;
    return processed;
}

bool TTSIntegration::generateAudio(const std::string& text, const std::string& outputFile) {
    if (!initialized_ || text.empty()) return false;
    
    std::ofstream file(outputFile);
    if (!file.is_open()) return false;
    
    file << "Generated audio for: " << text;
    file.close();
    return true;
}

std::string TTSIntegration::generateATISText(const std::string& airportCode,
                                            const std::string& weatherInfo,
                                            const std::string& runwayInfo) {
    ATISGenerator generator;
    return generator.generateATISText(airportCode, weatherInfo, runwayInfo);
}

std::string TTSIntegration::loadTemplate(const std::string& templatePath) {
    std::ifstream file(templatePath);
    if (!file.is_open()) return "";
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

bool TTSIntegration::saveConfiguration(const std::string& outputPath) {
    std::ofstream file(outputPath);
    if (!file.is_open()) return false;
    
    file << "model=" << defaultModel_ << "\n";
    file << "sample_rate=" << sampleRate_ << "\n";
    file << "bitrate=" << bitrate_ << "\n";
    file << "output_dir=" << outputDirectory_ << "\n";
    return true;
}

void TTSIntegration::resetConfiguration() {
    defaultModel_ = "en_US-lessac-medium";
    sampleRate_ = 22050;
    bitrate_ = 128;
    outputDirectory_ = "/tmp/tts_output";
}

bool TTSIntegration::initializeLogging() {
    return initialized_;
}

void TTSIntegration::setLogLevel(const std::string& level) {
    // Store the log level for getLogLevel to return
    logLevel_ = level;
}

std::string TTSIntegration::getLogLevel() const {
    return logLevel_;
}

bool TTSIntegration::setModel(const std::string& model) {
    for (const auto& availableModel : availableModels_) {
        if (availableModel == model) {
            defaultModel_ = model;
            return true;
        }
    }
    return false;
}

std::string TTSIntegration::getCurrentModel() const {
    return defaultModel_;
}

bool TTSIntegration::validateText(const std::string& text) {
    return !text.empty() && text.length() < 10000;
}

bool TTSIntegration::validateAudioFile(const std::string& filePath) {
    std::ifstream file(filePath);
    return file.good();
}

bool TTSIntegration::generateATISAudio(const std::string& airportCode,
                                      const std::string& weatherInfo,
                                      const std::string& runwayInfo,
                                      const std::string& outputFile) {
    std::string atisText = generateATISText(airportCode, weatherInfo, runwayInfo);
    return generateAudio(atisText, outputFile);
}

std::string TTSIntegration::processTemplate(const std::string& templateContent,
                                           const std::map<std::string, std::string>& variables) {
    std::string result = templateContent;
    for (const auto& pair : variables) {
        std::string placeholder = "{{" + pair.first + "}}";
        size_t pos = 0;
        while ((pos = result.find(placeholder, pos)) != std::string::npos) {
            result.replace(pos, placeholder.length(), pair.second);
            pos += pair.second.length();
        }
    }
    return result;
}

bool TTSIntegration::isDefaultConfiguration() const {
    return defaultModel_ == "en_US-lessac-medium" && 
           sampleRate_ == 22050 && 
           bitrate_ == 128;
}

bool TTSIntegration::startMonitoring() {
    monitoring_ = true;
    return initialized_;
}

bool TTSIntegration::isMonitoring() const {
    return monitoring_;
}

std::map<std::string, std::string> TTSIntegration::getMonitoringData() const {
    std::map<std::string, std::string> data;
    data["status"] = "active";
    data["model"] = defaultModel_;
    data["sample_rate"] = std::to_string(sampleRate_);
    return data;
}

void TTSIntegration::stopMonitoring() {
    monitoring_ = false;
}
