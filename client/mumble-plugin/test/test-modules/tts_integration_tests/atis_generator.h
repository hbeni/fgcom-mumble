/**
 * @file atis_generator.h
 * @brief ATIS Generator class header
 * @author FGcom-mumble Development Team
 * @date 2025
 */

#ifndef ATIS_GENERATOR_H
#define ATIS_GENERATOR_H

#include <string>
#include <vector>
#include <map>

/**
 * @class ATISGenerator
 * @brief Generates ATIS (Automatic Terminal Information Service) content
 */
class ATISGenerator {
public:
    ATISGenerator();
    ~ATISGenerator();
    
    bool isInitialized() const;
    std::string getDefaultTemplate() const;
    int getUpdateInterval() const;
    std::string generateATISText(const std::string& airportCode, 
                                const std::string& weatherInfo, 
                                const std::string& runwayInfo);
    std::string loadTemplate(const std::string& templatePath);
    bool generateATISAudio(const std::string& airportCode,
                          const std::string& weatherInfo,
                          const std::string& runwayInfo,
                          const std::string& outputFile);
    std::string processTemplate(const std::string& templateContent,
                               const std::map<std::string, std::string>& variables);

private:
    bool initialized_;
    std::string defaultTemplate_;
    int updateInterval_;
};

#endif // ATIS_GENERATOR_H
