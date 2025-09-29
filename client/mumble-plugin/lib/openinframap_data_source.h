#ifndef FGCOM_OPENINFRAMAP_DATA_SOURCE_H
#define FGCOM_OPENINFRAMAP_DATA_SOURCE_H

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>

// Forward declarations
struct Substation;
struct PowerStation;

// Open Infrastructure Map data source integration
// Uses OpenStreetMap data via Overpass API for electrical infrastructure
class FGCom_OpenInfraMapDataSource {
private:
    static std::unique_ptr<FGCom_OpenInfraMapDataSource> instance;
    static std::mutex instance_mutex;
    
    // Configuration
    struct OpenInfraMapConfig {
        std::string overpass_api_url = "https://overpass-api.de/api/interpreter";
        std::string user_agent = "FGCom-mumble/1.0";
        int timeout_seconds = 30;
        int max_retries = 3;
        float update_interval_hours = 24.0f;
        bool enable_substation_data = true;
        bool enable_power_station_data = true;
        bool enable_transmission_line_data = false;
        float search_radius_km = 50.0f;
        bool cache_data = true;
        std::string cache_directory = "./cache/openinframap/";
    };
    
    OpenInfraMapConfig config;
    mutable std::mutex config_mutex;
    
    // Data storage
    std::vector<Substation> cached_substations;
    std::vector<PowerStation> cached_power_stations;
    mutable std::mutex data_mutex;
    
    // Update tracking
    std::chrono::system_clock::time_point last_update;
    std::atomic<bool> update_in_progress{false};
    
    // Callbacks for data updates
    std::function<void(const std::vector<Substation>&)> substation_update_callback;
    std::function<void(const std::vector<PowerStation>&)> power_station_update_callback;
    
public:
    // Constructor
    FGCom_OpenInfraMapDataSource();
    
    // Singleton access
    static FGCom_OpenInfraMapDataSource& getInstance();
    static void destroyInstance();
    
    // Configuration management
    void setConfig(const OpenInfraMapConfig& new_config);
    OpenInfraMapConfig getConfig() const;
    void setOverpassAPIUrl(const std::string& url);
    void setTimeout(int seconds);
    void setUpdateInterval(float hours);
    void setSearchRadius(float radius_km);
    void enableSubstationData(bool enable);
    void enablePowerStationData(bool enable);
    void enableTransmissionLineData(bool enable);
    void setCacheDirectory(const std::string& directory);
    
    // Data fetching
    bool fetchSubstationData(double lat, double lon, float radius_km = 50.0f);
    bool fetchPowerStationData(double lat, double lon, float radius_km = 50.0f);
    bool fetchTransmissionLineData(double lat, double lon, float radius_km = 50.0f);
    bool fetchAllData(double lat, double lon, float radius_km = 50.0f);
    
    // Data access
    std::vector<Substation> getSubstations(double lat, double lon, float radius_km = 50.0f);
    std::vector<PowerStation> getPowerStations(double lat, double lon, float radius_km = 50.0f);
    std::vector<Substation> getAllSubstations() const;
    std::vector<PowerStation> getAllPowerStations() const;
    
    // Data management
    void clearCache();
    void clearSubstationData();
    void clearPowerStationData();
    size_t getSubstationCount() const;
    size_t getPowerStationCount() const;
    
    // Update management
    bool isUpdateInProgress() const;
    std::chrono::system_clock::time_point getLastUpdateTime() const;
    bool needsUpdate() const;
    void forceUpdate(double lat, double lon, float radius_km = 50.0f);
    
    // Callback management
    void setSubstationUpdateCallback(std::function<void(const std::vector<Substation>&)> callback);
    void setPowerStationUpdateCallback(std::function<void(const std::vector<PowerStation>&)> callback);
    void clearCallbacks();
    
    // Status and diagnostics
    bool isDataAvailable() const;
    bool isSubstationDataAvailable() const;
    bool isPowerStationDataAvailable() const;
    std::string getStatusString() const;
    std::string getLastError() const;
    
private:
    // Internal methods
    void initializeDataSource();
    bool makeOverpassAPICall(const std::string& query, std::string& response);
    std::string buildSubstationQuery(double lat, double lon, float radius_km);
    std::string buildPowerStationQuery(double lat, double lon, float radius_km);
    std::string buildTransmissionLineQuery(double lat, double lon, float radius_km);
    
    // Data parsing
    bool parseSubstationData(const std::string& json_data, std::vector<Substation>& substations);
    bool parsePowerStationData(const std::string& json_data, std::vector<PowerStation>& power_stations);
    bool parseTransmissionLineData(const std::string& json_data, std::vector<Substation>& substations);
    
    // Utility methods
    float calculateDistance(double lat1, double lon1, double lat2, double lon2);
    std::string urlEncode(const std::string& str);
    bool saveToCache(const std::string& filename, const std::string& data);
    bool loadFromCache(const std::string& filename, std::string& data);
    bool isCacheValid(const std::string& filename);
    
    // Error handling
    std::string last_error;
    mutable std::mutex error_mutex;
    void setLastError(const std::string& error);
};

// Utility functions for Open Infrastructure Map integration
namespace OpenInfraMapUtils {
    // Query builders
    std::string buildSubstationOverpassQuery(double lat, double lon, float radius_km);
    std::string buildPowerStationOverpassQuery(double lat, double lon, float radius_km);
    std::string buildTransmissionLineOverpassQuery(double lat, double lon, float radius_km);
    
    // Data parsers
    bool parseOSMSubstationData(const std::string& json_data, std::vector<Substation>& substations);
    bool parseOSMPowerStationData(const std::string& json_data, std::vector<PowerStation>& power_stations);
    
    // Data converters
    Substation convertOSMToSubstation(const std::string& osm_data);
    PowerStation convertOSMToPowerStation(const std::string& osm_data);
    
    // Validation
    bool validateSubstationData(const Substation& substation);
    bool validatePowerStationData(const PowerStation& power_station);
    bool validateCoordinates(double lat, double lon);
    
    // Distance calculations
    float calculateDistanceToSubstation(double lat, double lon, const Substation& substation);
    float calculateDistanceToPowerStation(double lat, double lon, const PowerStation& power_station);
}

#endif // FGCOM_OPENINFRAMAP_DATA_SOURCE_H
