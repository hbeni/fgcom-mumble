/*
 * Atmospheric Ducting Implementation
 * 
 * This file provides atmospheric ducting calculations for VHF/UHF propagation
 * including tropospheric ducting, temperature inversions, and humidity effects.
 */

#ifndef FGCOM_ATMOSPHERIC_DUCTING_H
#define FGCOM_ATMOSPHERIC_DUCTING_H

#include <vector>
#include <map>
#include <string>
#include <chrono>

// Atmospheric conditions structure for ducting
struct DuctingAtmosphericConditions {
    float temperature_celsius;
    float humidity_percent;
    float pressure_hpa;
    float wind_speed_ms;
    float wind_direction_deg;
    float altitude_m;
    std::chrono::system_clock::time_point timestamp;
};

// Ducting conditions structure
struct DuctingConditions {
    bool ducting_present;
    float ducting_strength;  // 0.0 to 1.0
    float ducting_height_m;  // Height of ducting layer
    float ducting_thickness_m;  // Thickness of ducting layer
    float temperature_inversion_strength;  // Temperature gradient
    float humidity_gradient;  // Humidity gradient
    float wind_shear;  // Wind shear effect
    std::string ducting_type;  // "surface", "elevated", "multiple"
};

// Ducting calculation parameters
struct DuctingCalculationParams {
    float frequency_hz;
    float distance_km;
    float tx_altitude_m;
    float rx_altitude_m;
    float tx_power_watts;
    bool enable_temperature_inversion;
    bool enable_humidity_effects;
    bool enable_wind_shear;
    float minimum_ducting_strength;
};

// Atmospheric ducting calculator class
class FGCom_AtmosphericDucting {
private:
    std::map<std::string, DuctingAtmosphericConditions> weather_cache;
    std::chrono::system_clock::time_point last_weather_update;
    bool weather_cache_enabled;
    float cache_timeout_seconds;
    
    // Ducting calculation methods
    float calculateTemperatureInversion(const std::vector<DuctingAtmosphericConditions>& profile);
    float calculateHumidityGradient(const std::vector<DuctingAtmosphericConditions>& profile);
    float calculateWindShear(const std::vector<DuctingAtmosphericConditions>& profile);
    float calculateDuctingHeight(const std::vector<DuctingAtmosphericConditions>& profile);
    float calculateDuctingThickness(const std::vector<DuctingAtmosphericConditions>& profile);
    
    // Atmospheric profile generation
    std::vector<DuctingAtmosphericConditions> generateAtmosphericProfile(
        double latitude, double longitude, double start_altitude, double end_altitude, int steps);
    
    // Ducting strength calculation
    float calculateDuctingStrength(const DuctingConditions& conditions, const DuctingCalculationParams& params);
    
    // Signal enhancement calculation
    float calculateSignalEnhancement(const DuctingConditions& conditions, float frequency_hz, float distance_km);
    
public:
    FGCom_AtmosphericDucting();
    ~FGCom_AtmosphericDucting();
    
    // Main ducting analysis
    DuctingConditions analyzeDuctingConditions(double latitude, double longitude, 
                                             double start_altitude, double end_altitude);
    
    // Ducting effects on propagation
    float calculateDuctingEffects(const DuctingConditions& conditions, 
                                 const DuctingCalculationParams& params);
    
    // Weather data integration
    void updateWeatherData(const std::map<std::string, DuctingAtmosphericConditions>& weather_data);
    void setWeatherCacheEnabled(bool enabled, float timeout_seconds = 300.0f);
    
    // Ducting prediction
    bool predictDuctingConditions(double latitude, double longitude, 
                                  const std::chrono::system_clock::time_point& time);
    
    // Ducting statistics
    struct DuctingStatistics {
        int total_analyses;
        int ducting_detected;
        float average_ducting_strength;
        float average_ducting_height;
        std::chrono::system_clock::time_point last_analysis;
    };
    
    DuctingStatistics getStatistics() const;
    void resetStatistics();
    
    // Configuration
    void setMinimumDuctingStrength(float strength);
    void setDuctingHeightRange(float min_height, float max_height);
    void setTemperatureInversionThreshold(float threshold);
    
private:
    float min_ducting_strength;
    float min_ducting_height;
    float max_ducting_height;
    float temperature_inversion_threshold;
    DuctingStatistics statistics;
};

// Utility functions for atmospheric calculations
namespace AtmosphericDuctingUtils {
    // Calculate atmospheric refraction index
    float calculateRefractionIndex(float temperature_celsius, float humidity_percent, float pressure_hpa);
    
    // Calculate temperature gradient
    float calculateTemperatureGradient(const std::vector<DuctingAtmosphericConditions>& profile);
    
    // Calculate humidity gradient
    float calculateHumidityGradient(const std::vector<DuctingAtmosphericConditions>& profile);
    
    // Calculate wind shear
    float calculateWindShear(const std::vector<DuctingAtmosphericConditions>& profile);
    
    // Calculate ducting probability
    float calculateDuctingProbability(const DuctingAtmosphericConditions& surface, 
                                    const DuctingAtmosphericConditions& elevated);
    
    // Calculate signal enhancement factor
    float calculateSignalEnhancement(float ducting_strength, float frequency_hz, float distance_km);
    
    // Validate atmospheric conditions
    bool validateDuctingAtmosphericConditions(const DuctingAtmosphericConditions& conditions);
}

#endif // FGCOM_ATMOSPHERIC_DUCTING_H
