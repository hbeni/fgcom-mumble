#ifndef FGCOM_STATIONARY_STATION_H
#define FGCOM_STATIONARY_STATION_H

#include <string>
#include <vector>
#include <map>
#include <memory>

/**
 * Stationary Station Support for FGCom-mumble
 * 
 * This header defines support for stationary stations including:
 * - Ground-based stations
 * - Coastal stations
 * - Maritime HF stations
 * - Emergency stations
 * - Weather stations
 * - Navigation stations
 */

// Stationary station types
enum class StationaryStationType {
    GROUND_BASED,       // General ground-based stations
    COASTAL,           // Coastal maritime stations
    MARITIME_HF,       // Maritime HF stations
    EMERGENCY,         // Emergency/disaster stations
    WEATHER,           // Weather stations
    NAVIGATION,         // Navigation stations
    MILITARY,          // Military installations
    AMATEUR           // Amateur radio stations
};

// Stationary station configuration
struct StationaryStationConfig {
    std::string station_id;
    std::string station_name;
    StationaryStationType station_type;
    double latitude;
    double longitude;
    double altitude_m;
    std::string antenna_type;
    double antenna_height_m;
    double power_watts;
    std::string modulation_mode;
    double frequency_khz;
    std::string ground_type;
    bool emergency_capable;
    bool weather_resistant;
    std::string notes;
    
    StationaryStationConfig() {
        station_id = "";
        station_name = "";
        station_type = StationaryStationType::GROUND_BASED;
        latitude = 0.0;
        longitude = 0.0;
        altitude_m = 0.0;
        antenna_type = "vertical";
        antenna_height_m = 10.0;
        power_watts = 100.0;
        modulation_mode = "SSB";
        frequency_khz = 14.0;
        ground_type = "average";
        emergency_capable = false;
        weather_resistant = false;
        notes = "";
    }
};

// Stationary station manager class
class FGCom_StationaryStationManager {
private:
    static bool initialized;
    static std::map<std::string, StationaryStationConfig> stations;
    static std::map<StationaryStationType, std::vector<std::string>> supported_modes;
    
public:
    // Initialize stationary station system
    static bool initialize();
    
    // Station management
    static bool addStation(const StationaryStationConfig& config);
    static bool removeStation(const std::string& station_id);
    static bool updateStation(const std::string& station_id, const StationaryStationConfig& config);
    static StationaryStationConfig getStation(const std::string& station_id);
    static std::vector<std::string> getAllStationIds();
    static std::vector<StationaryStationConfig> getStationsByType(StationaryStationType type);
    
    // Modulation mode support
    static bool setStationModulationMode(const std::string& station_id, const std::string& mode);
    static std::string getStationModulationMode(const std::string& station_id);
    static std::vector<std::string> getSupportedModesForStation(const std::string& station_id);
    static std::vector<std::string> getSupportedModesForType(StationaryStationType type);
    static bool validateModulationMode(const std::string& mode, StationaryStationType type);
    
    // Advanced modulation support
    static bool supportsAdvancedModulation(const std::string& station_id);
    static bool supportsAdvancedModulation(StationaryStationType type);
    static std::vector<std::string> getAdvancedModulationModes(const std::string& station_id);
    static std::vector<std::string> getAdvancedModulationModes(StationaryStationType type);
    
    // Station capabilities
    static bool isEmergencyStation(const std::string& station_id);
    static bool isWeatherStation(const std::string& station_id);
    static bool isNavigationStation(const std::string& station_id);
    static bool isMaritimeStation(const std::string& station_id);
    static bool isMilitaryStation(const std::string& station_id);
    
    // Frequency and power management
    static bool setStationFrequency(const std::string& station_id, double frequency_khz);
    static double getStationFrequency(const std::string& station_id);
    static bool setStationPower(const std::string& station_id, double power_watts);
    static double getStationPower(const std::string& station_id);
    
    // Antenna management
    static bool setStationAntenna(const std::string& station_id, const std::string& antenna_type);
    static std::string getStationAntenna(const std::string& station_id);
    static bool setStationAntennaHeight(const std::string& station_id, double height_m);
    static double getStationAntennaHeight(const std::string& station_id);
    
    // Ground system management
    static bool setStationGroundType(const std::string& station_id, const std::string& ground_type);
    static std::string getStationGroundType(const std::string& station_id);
    
    // Station status and diagnostics
    static std::map<std::string, std::string> getStationStatus(const std::string& station_id);
    static std::map<std::string, std::string> getSystemStatus();
    static std::vector<std::string> getStationDiagnostics(const std::string& station_id);
    
    // Search and filtering
    static std::vector<std::string> findStationsByLocation(double latitude, double longitude, double radius_km);
    static std::vector<std::string> findStationsByFrequency(double frequency_khz, double tolerance_khz);
    static std::vector<std::string> findStationsByModulation(const std::string& mode);
    static std::vector<std::string> findEmergencyStations();
    static std::vector<std::string> findMaritimeStations();
    
    // Configuration management
    static bool loadStationConfiguration(const std::string& config_file);
    static bool saveStationConfiguration(const std::string& config_file);
    static bool exportStationConfiguration(const std::string& station_id, const std::string& config_file);
    static bool importStationConfiguration(const std::string& config_file);
    
    // Cleanup
    static void shutdown();
};

// Stationary station signal processing
class FGCom_StationaryStationProcessor {
public:
    // Signal processing for different station types
    static double processGroundStationSignal(double input_signal, const StationaryStationConfig& config);
    static double processCoastalStationSignal(double input_signal, const StationaryStationConfig& config);
    static double processMaritimeStationSignal(double input_signal, const StationaryStationConfig& config);
    static double processEmergencyStationSignal(double input_signal, const StationaryStationConfig& config);
    static double processWeatherStationSignal(double input_signal, const StationaryStationConfig& config);
    static double processNavigationStationSignal(double input_signal, const StationaryStationConfig& config);
    
    // Advanced modulation processing
    static double processDSBSignal(double input_signal, const StationaryStationConfig& config);
    static double processISBSignal(double input_signal, const StationaryStationConfig& config);
    static double processVSBSignal(double input_signal, const StationaryStationConfig& config);
    static double processNFMSignal(double input_signal, const StationaryStationConfig& config);
    
    // Signal quality calculations
    static double calculateSignalQuality(const StationaryStationConfig& config);
    static double calculateSignalStrength(const StationaryStationConfig& config);
    static double calculateNoiseFloor(const StationaryStationConfig& config);
    static double calculateSignalToNoiseRatio(const StationaryStationConfig& config);
    
    // Station-specific calculations
    static double calculateGroundStationRange(const StationaryStationConfig& config);
    static double calculateCoastalStationRange(const StationaryStationConfig& config);
    static double calculateMaritimeStationRange(const StationaryStationConfig& config);
    static double calculateEmergencyStationRange(const StationaryStationConfig& config);
};

// Stationary station API endpoints
class FGCom_StationaryStationAPI {
public:
    // Station management endpoints
    static std::string createStation(const std::string& config_json);
    static std::string updateStation(const std::string& station_id, const std::string& config_json);
    static std::string deleteStation(const std::string& station_id);
    static std::string getStation(const std::string& station_id);
    static std::string listStations();
    static std::string listStationsByType(const std::string& type);
    
    // Modulation mode endpoints
    static std::string setModulationMode(const std::string& station_id, const std::string& mode);
    static std::string getModulationMode(const std::string& station_id);
    static std::string getSupportedModes(const std::string& station_id);
    static std::string getAdvancedModulationModes(const std::string& station_id);
    
    // Station capabilities endpoints
    static std::string getStationCapabilities(const std::string& station_id);
    static std::string getStationStatus(const std::string& station_id);
    static std::string getStationDiagnostics(const std::string& station_id);
    
    // Search endpoints
    static std::string searchStationsByLocation(const std::string& latitude, const std::string& longitude, const std::string& radius);
    static std::string searchStationsByFrequency(const std::string& frequency, const std::string& tolerance);
    static std::string searchStationsByModulation(const std::string& mode);
    static std::string searchEmergencyStations();
    static std::string searchMaritimeStations();
};

#endif // FGCOM_STATIONARY_STATION_H
