/**
 * @file atis_generator.cpp
 * @brief ATIS Generator class implementation
 * @author FGcom-mumble Development Team
 * @date 2025
 */

#include "atis_generator.h"
#include <fstream>
#include <sstream>

ATISGenerator::ATISGenerator() : initialized_(true), updateInterval_(30) {
    defaultTemplate_ = "This is {airport} information {letter} at {time} Zulu. Wind {wind}. Visibility {visibility}. Temperature {temp}. Dew point {dewpoint}. Altimeter {altimeter}. Landing and departing runway {runway}. Advise on initial contact you have information {letter}.";
}

ATISGenerator::~ATISGenerator() = default;

bool ATISGenerator::isInitialized() const {
    return initialized_;
}

std::string ATISGenerator::getDefaultTemplate() const {
    return defaultTemplate_;
}

int ATISGenerator::getUpdateInterval() const {
    return updateInterval_;
}

std::string ATISGenerator::generateATISText(const std::string& airportCode, 
                                          const std::string& weatherInfo, 
                                          const std::string& runwayInfo) {
    if (!initialized_) return "";
    
    std::string result = defaultTemplate_;
    // Simple template replacement
    size_t pos = result.find("{airport}");
    if (pos != std::string::npos) {
        result.replace(pos, 9, airportCode);
    }
    pos = result.find("{wind}");
    if (pos != std::string::npos) {
        result.replace(pos, 6, weatherInfo);
    }
    pos = result.find("{runway}");
    if (pos != std::string::npos) {
        result.replace(pos, 8, runwayInfo);
    }
    return result;
}

std::string ATISGenerator::loadTemplate(const std::string& templatePath) {
    std::ifstream file(templatePath);
    if (!file.is_open()) {
        return defaultTemplate_;
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

bool ATISGenerator::generateATISAudio(const std::string& airportCode,
                                     const std::string& weatherInfo,
                                     const std::string& runwayInfo,
                                     const std::string& outputFile) {
    if (!initialized_) return false;
    
    // Check for invalid inputs
    if (airportCode.empty() || weatherInfo.empty() || runwayInfo.empty() || outputFile.empty()) {
        return false;
    }
    
    // Generate text first
    std::string atisText = generateATISText(airportCode, weatherInfo, runwayInfo);
    
    // Write to file (stub implementation)
    std::ofstream file(outputFile);
    if (!file.is_open()) return false;
    
    file << atisText;
    file.close();
    return true;
}

std::string ATISGenerator::processTemplate(const std::string& templateContent,
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
