#ifndef FGCOM_ANTENNA_PATTERN_MAPPING_H
#define FGCOM_ANTENNA_PATTERN_MAPPING_H

#include <string>
#include <map>
#include <vector>
#include <memory>

/**
 * Antenna Pattern Mapping System for FGCom-mumble
 * 
 * This system maps vehicle types and frequencies to appropriate antenna pattern files
 * for VHF and UHF radio models.
 */

struct AntennaPatternInfo {
    std::string antenna_name;      // Internal antenna identifier
    std::string pattern_file;     // Path to pattern file
    double frequency_mhz;         // Operating frequency
    std::string vehicle_type;     // Vehicle type (aircraft, ground, maritime)
    std::string antenna_type;     // Antenna type (blade, whip, yagi, etc.)
    bool is_loaded;               // Whether pattern is currently loaded
    
    AntennaPatternInfo() : frequency_mhz(0.0), is_loaded(false) {}
    AntennaPatternInfo(const std::string& name, const std::string& file, 
                      double freq, const std::string& vtype, const std::string& atype)
        : antenna_name(name), pattern_file(file), frequency_mhz(freq), 
          vehicle_type(vtype), antenna_type(atype), is_loaded(false) {}
};

class FGCom_AntennaPatternMapping {
private:
    // Map: vehicle_type -> frequency -> antenna pattern info
    std::map<std::string, std::map<double, AntennaPatternInfo>> vhf_patterns;
    std::map<std::string, std::map<double, AntennaPatternInfo>> uhf_patterns;
    
    // Initialize pattern mappings
    void initializeVHFPatterns();
    void initializeUHFPatterns();
    
public:
    FGCom_AntennaPatternMapping();
    ~FGCom_AntennaPatternMapping();
    
    // Get antenna pattern info for VHF
    AntennaPatternInfo getVHFPattern(const std::string& vehicle_type, double frequency_mhz);
    
    // Get antenna pattern info for UHF
    AntennaPatternInfo getUHFPattern(const std::string& vehicle_type, double frequency_mhz);
    
    // Get all available patterns for a vehicle type
    std::vector<AntennaPatternInfo> getAvailableVHFPatterns(const std::string& vehicle_type);
    std::vector<AntennaPatternInfo> getAvailableUHFPatterns(const std::string& vehicle_type);
    
    // Check if pattern exists
    bool hasVHFPattern(const std::string& vehicle_type, double frequency_mhz);
    bool hasUHFPattern(const std::string& vehicle_type, double frequency_mhz);
    
    // Load pattern from file
    bool loadPatternFromFile(const std::string& pattern_file, AntennaPatternInfo& info);
    
    // Get closest frequency pattern
    AntennaPatternInfo getClosestVHFPattern(const std::string& vehicle_type, double frequency_mhz);
    AntennaPatternInfo getClosestUHFPattern(const std::string& vehicle_type, double frequency_mhz);
    
    // Vehicle type detection
    std::string detectVehicleType(const std::string& vehicle_name);
    
    // Frequency band detection
    bool isVHFFrequency(double frequency_mhz);
    bool isUHFFrequency(double frequency_mhz);
};

// Global pattern mapping instance
extern std::unique_ptr<FGCom_AntennaPatternMapping> g_antenna_pattern_mapping;

// Convenience functions
AntennaPatternInfo getAntennaPattern(const std::string& vehicle_type, double frequency_mhz);
bool loadAntennaPattern(const std::string& vehicle_type, double frequency_mhz);

#endif // FGCOM_ANTENNA_PATTERN_MAPPING_H
