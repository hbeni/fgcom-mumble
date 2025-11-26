#ifndef FGCOM_ATMOSPHERIC_NOISE_H
#define FGCOM_ATMOSPHERIC_NOISE_H

#include <vector>
#include <chrono>
#include <string>
#include <mutex>
#include <atomic>
#include <memory>
#include <functional>

// Forward declarations
struct LightningStrike;

// EV Charging Station types
enum class EVChargingType {
    AC_LEVEL1,      // 1.4-1.9 kW (120V, 12-16A)
    AC_LEVEL2,      // 3.3-19.2 kW (240V, 13-80A)
    DC_FAST,        // 50-350 kW (400V+ DC)
    DC_ULTRA_FAST   // 350+ kW (800V+ DC)
};

// EV Charging Station data structure
struct EVChargingStation {
    double latitude;
    double longitude;
    float power_kw;
    EVChargingType charging_type;
    bool is_active;
    std::string operator_name;
    std::string station_id;
    float noise_factor;  // Station-specific noise multiplier
    std::chrono::system_clock::time_point last_updated;
};

// Substation types
enum class SubstationType {
    TRANSMISSION,      // High voltage transmission substations
    DISTRIBUTION,      // Medium voltage distribution substations
    SWITCHING,         // Switching substations (no transformation)
    CONVERTER,         // AC/DC converter substations
    INDUSTRIAL,        // Industrial facility substations
    RAILWAY            // Railway electrification substations
};

// Power station types
enum class PowerStationType {
    THERMAL,           // Coal, gas, oil-fired power plants
    NUCLEAR,           // Nuclear power plants
    HYDROELECTRIC,     // Hydroelectric power plants
    WIND,              // Wind farms
    SOLAR,             // Solar photovoltaic farms
    GEOTHERMAL,        // Geothermal power plants
    BIOMASS,           // Biomass power plants
    PUMPED_STORAGE     // Pumped storage hydroelectric
};

// Geometry types for complex shapes
enum class GeometryType {
    POINT,             // Single coordinate point
    POLYGON,           // Simple polygon
    MULTIPOLYGON,      // Multiple polygons
    LINESTRING,        // Line geometry
    MULTILINESTRING    // Multiple lines
};

// Substation data structure
struct Substation {
    double latitude;
    double longitude;
    SubstationType substation_type;
    float voltage_kv;           // Primary voltage level
    float capacity_mva;        // Substation capacity in MVA
    bool is_fenced;            // Whether substation is fenced
    GeometryType geometry_type;
    std::vector<std::vector<std::pair<double, double>>> polygons;  // Multipolygon coordinates
    bool is_active;
    std::string operator_name;
    std::string substation_id;
    float noise_factor;        // Substation-specific noise multiplier
    std::chrono::system_clock::time_point last_updated;
};

// Power station data structure
struct PowerStation {
    double latitude;
    double longitude;
    PowerStationType station_type;
    float capacity_mw;         // Peak rated output capacity in MW
    float current_output_mw;   // Current power output in MW
    bool is_fenced;           // Whether power station is fenced
    GeometryType geometry_type;
    std::vector<std::vector<std::pair<double, double>>> polygons;  // Multipolygon coordinates
    bool is_active;
    std::string operator_name;
    std::string station_id;
    float noise_factor;       // Station-specific noise multiplier
    std::chrono::system_clock::time_point last_updated;
};

// Environment types for noise floor calculation
enum class EnvironmentType {
    INDUSTRIAL,     // S7-S9+ (-100 to -85 dBm)
    URBAN,          // S5-S7 (-115 to -100 dBm) 
    SUBURBAN,       // S3-S5 (-125 to -115 dBm)
    REMOTE,         // S1-S3 (-140 to -125 dBm)
    OCEAN,          // S0-S2 (-145 to -130 dBm) - Very quiet RF environment
    DESERT,         // S0-S2 (-145 to -130 dBm) - Remote desert conditions
    POLAR           // S0-S1 (-145 to -135 dBm) - Quietest possible RF environment
};

// Time of day factors
enum class TimeOfDay {
    NIGHT,          // 22:00 - 06:00 (lower noise)
    DAY,            // 06:00 - 18:00 (higher noise)
    DUSK_DAWN       // 18:00 - 22:00 (transitional)
};

// Weather conditions affecting noise
struct NoiseWeatherConditions {
    bool has_thunderstorms;
    float storm_distance_km;
    float storm_intensity;
    bool has_precipitation;
    float temperature_celsius;
    float humidity_percent;
};

class FGCom_AtmosphericNoise {
private:
    static std::unique_ptr<FGCom_AtmosphericNoise> instance;
    static std::mutex instance_mutex;
    
    // Noise floor parameters
    EnvironmentType environment_type;
    TimeOfDay current_time_of_day;
    NoiseWeatherConditions weather;
    bool manual_environment_set;
    
    // User position
    double user_latitude;
    double user_longitude;
    std::string user_maidenhead;
    bool user_position_set;
    
    // OpenInfraMap callback
    std::function<void()> openinframap_callback;
    
    // Lightning strike effects
    std::vector<LightningStrike> nearby_strikes;
    std::vector<LightningStrike> recent_strikes;
    mutable std::mutex strikes_mutex;
    
    // EV Charging Station data
    std::vector<EVChargingStation> ev_charging_stations;
    mutable std::mutex ev_stations_mutex;
    
    // Substation data
    std::vector<Substation> substations;
    mutable std::mutex substations_mutex;
    
    // Power station data
    std::vector<PowerStation> power_stations;
    mutable std::mutex power_stations_mutex;
    
    // Open Infrastructure Map integration
    bool enable_openinframap_integration = false;
    mutable std::mutex openinframap_mutex;
    
    // Solar activity data
    float solar_flux_index;
    float k_index;
    float a_index;
    
public:
    // Configuration
    struct NoiseConfig {
        float base_thermal_noise = -174.0f;  // dBm/Hz (theoretical limit)
        float receiver_bandwidth_hz = 2400.0f;  // 2.4 kHz typical HF bandwidth
        float antenna_factor = 0.0f;  // Antenna noise factor
        bool enable_lightning_effects = true;
        bool enable_solar_effects = true;
        bool enable_environmental_effects = true;
        
        // Advanced features - OFF BY DEFAULT
        bool enable_itu_p372_model = false;      // ITU-R P.372 noise model
        bool enable_osm_integration = false;     // OpenStreetMap integration
        bool enable_population_density = false;  // Population density effects
        bool enable_power_line_analysis = false; // Power line noise analysis
        bool enable_traffic_analysis = false;    // Traffic noise analysis
        bool enable_industrial_analysis = false; // Industrial area analysis
        bool enable_ev_charging_analysis = false; // EV charging station analysis
        bool enable_substation_analysis = false; // Substation noise analysis
        bool enable_power_station_analysis = false; // Power station noise analysis
        bool enable_openinframap_integration = false; // Open Infrastructure Map integration
    };
    
    NoiseConfig config;
    mutable std::mutex config_mutex;
    
public:
    // Constructor for singleton
    FGCom_AtmosphericNoise();
    
public:
    // Singleton access
    static FGCom_AtmosphericNoise& getInstance();
    static void destroyInstance();
    
    // Main noise floor calculation
    float calculateNoiseFloor(double lat, double lon, float freq_mhz);
    float calculateNoiseFloor(double lat, double lon, float freq_mhz, EnvironmentType env_type);
    
    // Environment-specific calculations
    float getEnvironmentNoiseFloor(EnvironmentType env_type, float freq_mhz);
    float getTimeOfDayFactor(TimeOfDay time_of_day);
    float getWeatherNoiseFactor(const NoiseWeatherConditions& weather, float freq_mhz);
    
    // Lightning strike effects
    void addLightningStrike(const LightningStrike& strike);
    void updateLightningStrikes(const std::vector<LightningStrike>& strikes);
    float calculateLightningNoiseEffect(double lat, double lon, float freq_mhz);
    void cleanupOldStrikes();
    
    // Solar activity effects
    void updateSolarActivity(float sfi, float k_index, float a_index);
    float calculateSolarNoiseFactor(float freq_mhz);
    
    // Frequency-dependent calculations
    float getFrequencyNoiseFactor(float freq_mhz);
    float getAtmosphericNoiseFactor(float freq_mhz);
    
    // S-meter conversion utilities
    float dbmToSMeter(float dbm);
    float sMeterToDbm(int s_meter);
    std::string getNoiseDescription(float dbm);
    
    // Configuration management
    void setEnvironmentType(EnvironmentType env_type);
    void setTimeOfDay(TimeOfDay time_of_day);
    void setWeatherConditions(const NoiseWeatherConditions& weather);
    void setConfig(const NoiseConfig& config);
    NoiseConfig getConfig() const;
    void resetToDefaults();
    void enableAdvancedFeatures(bool enable);
    void enableSpecificFeature(const std::string& feature_name, bool enable);
    
    // Statistics and monitoring
    int getNearbyStrikeCount() const;
    float getAverageStrikeIntensity() const;
    float getCurrentSolarActivity() const;
    EnvironmentType getCurrentEnvironment() const;
    
    // Real-time updates
    void updateRealTimeData(double lat, double lon, float freq_mhz);
    void processWeatherUpdate(const NoiseWeatherConditions& weather);
    void processSolarUpdate(float sfi, float k_index, float a_index);
    
    // Manual environment setting (for Maidenhead locators or user override)
    void setManualEnvironment(EnvironmentType env_type);
    void setManualEnvironment(const std::string& environment_name);
    EnvironmentType getManualEnvironment() const;
    bool isManualEnvironmentSet() const;
    void clearManualEnvironment();
    
    // User position setting (GPS and Maidenhead)
    void setUserPosition(double lat, double lon);
    void setUserPosition(const std::string& maidenhead);
    void setUserPosition(double lat, double lon, const std::string& maidenhead);
    std::pair<double, double> getUserPosition() const;
    std::string getUserMaidenhead() const;
    bool isUserPositionSet() const;
    void clearUserPosition();
    
    // Position-based noise calculation
    float calculateNoiseFloorForUserPosition(float freq_mhz);
    float calculateNoiseFloorForUserPosition(float freq_mhz, EnvironmentType env_type);
    
    // Environment detection and override
    EnvironmentType detectEnvironmentFromCoordinates(double lat, double lon);
    EnvironmentType detectEnvironmentFromMaidenhead(const std::string& maidenhead);
    void overrideEnvironmentDetection(EnvironmentType env_type);
    
    // Advanced noise calculation methods (optional features)
    float calculateITUP372Noise(double lat, double lon, float freq_mhz);
    float calculateOSMBasedNoise(double lat, double lon, float freq_mhz);
    float calculatePopulationDensityNoise(double lat, double lon);
    float calculatePowerLineNoise(double lat, double lon, float freq_mhz);
    float calculateTrafficNoise(double lat, double lon, float freq_mhz);
    float calculateIndustrialNoise(double lat, double lon, float freq_mhz);
    float calculateEVChargingNoise(double lat, double lon, float freq_mhz);
    float calculateSubstationNoise(double lat, double lon, float freq_mhz);
    float calculatePowerStationNoise(double lat, double lon, float freq_mhz);
    
    // EV Charging Station management
    void addEVChargingStation(const EVChargingStation& station);
    void removeEVChargingStation(const std::string& station_id);
    void updateEVChargingStation(const std::string& station_id, const EVChargingStation& station);
    std::vector<EVChargingStation> getNearbyEVChargingStations(double lat, double lon, float radius_km = 10.0f);
    void clearEVChargingStations();
    size_t getEVChargingStationCount() const;
    
    // Substation management
    void addSubstation(const Substation& substation);
    void removeSubstation(const std::string& substation_id);
    void updateSubstation(const std::string& substation_id, const Substation& substation);
    std::vector<Substation> getNearbySubstations(double lat, double lon, float radius_km = 20.0f);
    void clearSubstations();
    size_t getSubstationCount() const;
    
    // Power station management
    void addPowerStation(const PowerStation& station);
    void removePowerStation(const std::string& station_id);
    void updatePowerStation(const std::string& station_id, const PowerStation& station);
    std::vector<PowerStation> getNearbyPowerStations(double lat, double lon, float radius_km = 50.0f);
    void clearPowerStations();
    size_t getPowerStationCount() const;
    
    // Open Infrastructure Map integration
    void enableOpenInfraMapIntegration(bool enable);
    bool isOpenInfraMapIntegrationEnabled() const;
    void updateFromOpenInfraMap(double lat, double lon, float radius_km = 50.0f);
    void setOpenInfraMapUpdateCallback(std::function<void()> callback);
    std::string getOpenInfraMapStatus() const;
    
private:
    // Internal helper methods
    void initializeNoiseSystem();
    float calculateDistance(double lat1, double lon1, double lat2, double lon2);
    float calculateDistanceToGeometry(double lat, double lon, const Substation& substation);
    float calculateDistanceToGeometry(double lat, double lon, const PowerStation& station);
    TimeOfDay determineTimeOfDay();
    EnvironmentType determineEnvironmentType(double lat, double lon);
    
    // Noise calculation helpers
    float calculateThermalNoise();
    float calculateAtmosphericNoise(float freq_mhz);
    float calculateManMadeNoise(EnvironmentType env_type, float freq_mhz);
    float calculateLightningNoise(double lat, double lon, float freq_mhz);
    
    // Frequency band specific calculations
    float get160mBandNoise(float base_noise);
    float get80mBandNoise(float base_noise);
    float get40mBandNoise(float base_noise);
    float get20mBandNoise(float base_noise);
    float get15mBandNoise(float base_noise);
    float get10mBandNoise(float base_noise);
    
    // Environment-specific noise calculations
    float getOceanNoiseAdjustments(float freq_mhz);
    float getDesertNoiseAdjustments(float freq_mhz);
    float getPolarNoiseAdjustments(float freq_mhz);
    
    // Weather effect calculations
    float calculateThunderstormEffect(const NoiseWeatherConditions& weather, float freq_mhz);
    float calculatePrecipitationEffect(const NoiseWeatherConditions& weather, float freq_mhz);
    float calculateTemperatureEffect(const NoiseWeatherConditions& weather, float freq_mhz);
};

// Utility functions for noise floor analysis
namespace NoiseFloorUtils {
    // Convert between different noise units
    float dbmToMicrovolts(float dbm, float impedance_ohms = 50.0f);
    float microvoltsToDbm(float microvolts, float impedance_ohms = 50.0f);
    
    // S-meter scale conversions
    std::string getSMeterDescription(int s_meter);
    float getSMeterRange(int s_meter);
    
    // Noise floor quality assessment
    std::string assessNoiseFloorQuality(float dbm);
    bool isNoiseFloorAcceptable(float dbm, EnvironmentType env_type);
    
    // Environmental noise prediction
    float predictUrbanNoise(float time_of_day_factor, float weather_factor);
    float predictIndustrialNoise(float activity_level, float time_of_day_factor);
    float predictRemoteNoise(float atmospheric_activity, float solar_activity);
    float predictOceanNoise(float atmospheric_activity, float solar_activity, float laptop_noise_factor);
    float predictDesertNoise(float atmospheric_activity, float solar_activity, float temperature_factor);
    float predictPolarNoise(float atmospheric_activity, float solar_activity, float auroral_activity, float seasonal_factor);
    float predictEVChargingNoise(float charging_activity, float time_of_day_factor, float weather_factor);
    float predictSubstationNoise(float voltage_level, float capacity_mva, float time_of_day_factor, float weather_factor);
    float predictPowerStationNoise(float capacity_mw, float output_mw, float time_of_day_factor, float weather_factor);
}

#endif // FGCOM_ATMOSPHERIC_NOISE_H
