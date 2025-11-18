#ifndef FGCOM_ANTENNA_PATTERN_MAPPING_H
#define FGCOM_ANTENNA_PATTERN_MAPPING_H

#include <string>
#include <map>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>

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
    
    // 3D attitude pattern support
    int roll_deg;                 // Roll angle in degrees (-180 to +180)
    int pitch_deg;                // Pitch angle in degrees (-180 to +180)
    int altitude_m;               // Altitude in meters
    bool is_3d_pattern;           // Whether this is a 3D attitude pattern
    
    AntennaPatternInfo() : frequency_mhz(0.0), is_loaded(false), 
                          roll_deg(0), pitch_deg(0), altitude_m(0), is_3d_pattern(false) {}
    AntennaPatternInfo(const std::string& name, const std::string& file, 
                      double freq, const std::string& vtype, const std::string& atype)
        : antenna_name(name), pattern_file(file), frequency_mhz(freq), 
          vehicle_type(vtype), antenna_type(atype), is_loaded(false),
          roll_deg(0), pitch_deg(0), altitude_m(0), is_3d_pattern(false) {}
    AntennaPatternInfo(const std::string& name, const std::string& file, 
                      double freq, const std::string& vtype, const std::string& atype,
                      int roll, int pitch, int alt)
        : antenna_name(name), pattern_file(file), frequency_mhz(freq), 
          vehicle_type(vtype), antenna_type(atype), is_loaded(false),
          roll_deg(roll), pitch_deg(pitch), altitude_m(alt), is_3d_pattern(true) {}
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
    
    // 3D attitude pattern methods
    AntennaPatternInfo get3DAttitudePattern(const std::string& vehicle_type, double frequency_mhz, 
                                           int roll_deg, int pitch_deg, int altitude_m);
    std::vector<AntennaPatternInfo> getAvailable3DPatterns(const std::string& vehicle_type, 
                                                          double frequency_mhz, int altitude_m);
    bool has3DAttitudePattern(const std::string& vehicle_type, double frequency_mhz, 
                             int roll_deg, int pitch_deg, int altitude_m);
    
    // Vehicle type detection
    std::string detectVehicleType(const std::string& vehicle_name);
    
    // Frequency band detection
    bool isVHFFrequency(double frequency_mhz);
    bool isUHFFrequency(double frequency_mhz);
};

// Thread-safe global pattern mapping instance
extern std::unique_ptr<FGCom_AntennaPatternMapping> g_antenna_pattern_mapping;
extern std::mutex g_antenna_mapping_mutex;
extern std::atomic<bool> g_antenna_mapping_initialized;

// Thread-safe getter function
FGCom_AntennaPatternMapping* getAntennaPatternMapping();

// Convenience functions
AntennaPatternInfo getAntennaPattern(const std::string& vehicle_type, double frequency_mhz);
bool loadAntennaPattern(const std::string& vehicle_type, double frequency_mhz);

#endif // FGCOM_ANTENNA_PATTERN_MAPPING_H
