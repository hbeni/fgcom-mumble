#ifndef FGCOM_ATMOSPHERIC_NOISE_H
#define FGCOM_ATMOSPHERIC_NOISE_H

#include <vector>
#include <chrono>
#include <string>
#include <mutex>
#include <atomic>
#include <memory>

// Forward declarations
struct LightningStrike;

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
    
    // Lightning strike effects
    std::vector<LightningStrike> nearby_strikes;
    std::vector<LightningStrike> recent_strikes;
    mutable std::mutex strikes_mutex;
    
    // Solar activity data
    float solar_flux_index;
    float k_index;
    float a_index;
    
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
    
private:
    // Internal helper methods
    void initializeNoiseSystem();
    float calculateDistance(double lat1, double lon1, double lat2, double lon2);
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
}

#endif // FGCOM_ATMOSPHERIC_NOISE_H
