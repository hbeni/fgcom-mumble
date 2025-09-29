/*
 * Atmospheric Ducting Implementation
 * 
 * This file provides atmospheric ducting calculations for VHF/UHF propagation
 * including tropospheric ducting, temperature inversions, and humidity effects.
 */

#include "atmospheric_ducting.h"
#include <cmath>
#include <algorithm>
#include <random>
#include <iostream>

// Constructor
FGCom_AtmosphericDucting::FGCom_AtmosphericDucting() 
    : weather_cache_enabled(true), cache_timeout_seconds(300.0f),
      min_ducting_strength(0.3f), min_ducting_height(50.0f), max_ducting_height(2000.0f),
      temperature_inversion_threshold(0.5f) {
    
    statistics.total_analyses = 0;
    statistics.ducting_detected = 0;
    statistics.average_ducting_strength = 0.0f;
    statistics.average_ducting_height = 0.0f;
    statistics.last_analysis = std::chrono::system_clock::now();
}

// Destructor
FGCom_AtmosphericDucting::~FGCom_AtmosphericDucting() {
    // Cleanup if needed
}

// Main ducting analysis
DuctingConditions FGCom_AtmosphericDucting::analyzeDuctingConditions(double latitude, double longitude, 
                                                                   double start_altitude, double end_altitude) {
    DuctingConditions conditions;
    conditions.ducting_present = false;
    conditions.ducting_strength = 0.0f;
    conditions.ducting_height_m = 0.0f;
    conditions.ducting_thickness_m = 0.0f;
    conditions.temperature_inversion_strength = 0.0f;
    conditions.humidity_gradient = 0.0f;
    conditions.wind_shear = 0.0f;
    conditions.ducting_type = "none";
    
    // Generate atmospheric profile
    std::vector<DuctingAtmosphericConditions> profile = generateAtmosphericProfile(
        latitude, longitude, start_altitude, end_altitude, 20);
    
    if (profile.empty()) {
        return conditions;
    }
    
    // Calculate ducting indicators
    float temperature_inversion = calculateTemperatureInversion(profile);
    float humidity_gradient = calculateHumidityGradient(profile);
    float wind_shear = calculateWindShear(profile);
    
    conditions.temperature_inversion_strength = temperature_inversion;
    conditions.humidity_gradient = humidity_gradient;
    conditions.wind_shear = wind_shear;
    
    // Determine if ducting is present
    bool temperature_ducting = temperature_inversion > temperature_inversion_threshold;
    bool humidity_ducting = humidity_gradient > 0.3f;
    bool wind_ducting = wind_shear > 0.2f;
    
    if (temperature_ducting || humidity_ducting || wind_ducting) {
        conditions.ducting_present = true;
        
        // Calculate ducting strength
        conditions.ducting_strength = std::min(1.0f, 
            (temperature_inversion * 0.4f + humidity_gradient * 0.3f + wind_shear * 0.3f));
        
        // Calculate ducting height and thickness
        conditions.ducting_height_m = calculateDuctingHeight(profile);
        conditions.ducting_thickness_m = calculateDuctingThickness(profile);
        
        // Determine ducting type
        if (conditions.ducting_height_m < 200.0f) {
            conditions.ducting_type = "surface";
        } else if (conditions.ducting_height_m < 1000.0f) {
            conditions.ducting_type = "elevated";
        } else {
            conditions.ducting_type = "multiple";
        }
    }
    
    // Update statistics
    statistics.total_analyses++;
    if (conditions.ducting_present) {
        statistics.ducting_detected++;
        statistics.average_ducting_strength = 
            (statistics.average_ducting_strength * (statistics.ducting_detected - 1) + 
             conditions.ducting_strength) / statistics.ducting_detected;
        statistics.average_ducting_height = 
            (statistics.average_ducting_height * (statistics.ducting_detected - 1) + 
             conditions.ducting_height_m) / statistics.ducting_detected;
    }
    statistics.last_analysis = std::chrono::system_clock::now();
    
    return conditions;
}

// Calculate ducting effects on propagation
float FGCom_AtmosphericDucting::calculateDuctingEffects(const DuctingConditions& conditions, 
                                                       const DuctingCalculationParams& params) {
    if (!conditions.ducting_present) {
        return 1.0f; // No ducting effects
    }
    
    // Calculate signal enhancement
    float enhancement = calculateSignalEnhancement(conditions, params.frequency_hz, params.distance_km);
    
    // Apply frequency-dependent effects
    float frequency_factor = 1.0f;
    if (params.frequency_hz < 100000000.0f) { // VHF
        frequency_factor = 1.2f;
    } else if (params.frequency_hz < 1000000000.0f) { // UHF
        frequency_factor = 1.0f;
    } else { // Microwave
        frequency_factor = 0.8f;
    }
    
    // Apply distance-dependent effects
    float distance_factor = 1.0f;
    if (params.distance_km > 100.0f) {
        distance_factor = 1.5f; // Ducting more effective at longer distances
    }
    
    return enhancement * frequency_factor * distance_factor;
}

// Generate atmospheric profile
std::vector<DuctingAtmosphericConditions> FGCom_AtmosphericDucting::generateAtmosphericProfile(
    double latitude, double longitude, double start_altitude, double end_altitude, int steps) {
    
    std::vector<DuctingAtmosphericConditions> profile;
    profile.reserve(steps);
    
    double altitude_step = (end_altitude - start_altitude) / (steps - 1);
    
    for (int i = 0; i < steps; i++) {
        DuctingAtmosphericConditions conditions;
        double altitude = start_altitude + i * altitude_step;
        
        // Standard atmospheric model with variations
        conditions.altitude_m = altitude;
        conditions.temperature_celsius = 20.0 - (altitude * 0.0065); // Standard lapse rate
        
        // Add temperature inversion at certain altitudes
        if (altitude > 100.0 && altitude < 500.0) {
            conditions.temperature_celsius += 2.0f; // Temperature inversion
        }
        
        // Humidity decreases with altitude
        conditions.humidity_percent = 70.0f - (altitude * 0.01f);
        conditions.humidity_percent = std::max(10.0f, std::min(100.0f, conditions.humidity_percent));
        
        // Pressure decreases with altitude
        conditions.pressure_hpa = 1013.25f * std::pow(1.0f - (altitude * 0.0000225577f), 5.255f);
        
        // Wind speed increases with altitude
        conditions.wind_speed_ms = 5.0f + (altitude * 0.002f);
        
        // Wind direction varies with altitude
        conditions.wind_direction_deg = 180.0f + (altitude * 0.01f);
        
        conditions.timestamp = std::chrono::system_clock::now();
        profile.push_back(conditions);
    }
    
    return profile;
}

// Calculate temperature inversion
float FGCom_AtmosphericDucting::calculateTemperatureInversion(const std::vector<DuctingAtmosphericConditions>& profile) {
    if (profile.size() < 2) return 0.0f;
    
    float max_inversion = 0.0f;
    
    for (size_t i = 1; i < profile.size(); i++) {
        float temp_diff = profile[i].temperature_celsius - profile[i-1].temperature_celsius;
        float altitude_diff = profile[i].altitude_m - profile[i-1].altitude_m;
        
        if (altitude_diff > 0.0f) {
            float gradient = temp_diff / altitude_diff;
            if (gradient > 0.0f) { // Temperature increasing with altitude (inversion)
                max_inversion = std::max(max_inversion, gradient);
            }
        }
    }
    
    return max_inversion;
}

// Calculate humidity gradient
float FGCom_AtmosphericDucting::calculateHumidityGradient(const std::vector<DuctingAtmosphericConditions>& profile) {
    if (profile.size() < 2) return 0.0f;
    
    float max_gradient = 0.0f;
    
    for (size_t i = 1; i < profile.size(); i++) {
        float humidity_diff = profile[i].humidity_percent - profile[i-1].humidity_percent;
        float altitude_diff = profile[i].altitude_m - profile[i-1].altitude_m;
        
        if (altitude_diff > 0.0f) {
            float gradient = std::abs(humidity_diff) / altitude_diff;
            max_gradient = std::max(max_gradient, gradient);
        }
    }
    
    return max_gradient;
}

// Calculate wind shear
float FGCom_AtmosphericDucting::calculateWindShear(const std::vector<DuctingAtmosphericConditions>& profile) {
    if (profile.size() < 2) return 0.0f;
    
    float max_shear = 0.0f;
    
    for (size_t i = 1; i < profile.size(); i++) {
        float wind_diff = profile[i].wind_speed_ms - profile[i-1].wind_speed_ms;
        float altitude_diff = profile[i].altitude_m - profile[i-1].altitude_m;
        
        if (altitude_diff > 0.0f) {
            float shear = std::abs(wind_diff) / altitude_diff;
            max_shear = std::max(max_shear, shear);
        }
    }
    
    return max_shear;
}

// Calculate ducting height
float FGCom_AtmosphericDucting::calculateDuctingHeight(const std::vector<DuctingAtmosphericConditions>& profile) {
    if (profile.empty()) return 0.0f;
    
    float max_inversion_height = 0.0f;
    float max_inversion_strength = 0.0f;
    
    for (size_t i = 1; i < profile.size(); i++) {
        float temp_diff = profile[i].temperature_celsius - profile[i-1].temperature_celsius;
        float altitude_diff = profile[i].altitude_m - profile[i-1].altitude_m;
        
        if (altitude_diff > 0.0f && temp_diff > 0.0f) {
            float gradient = temp_diff / altitude_diff;
            if (gradient > max_inversion_strength) {
                max_inversion_strength = gradient;
                max_inversion_height = profile[i].altitude_m;
            }
        }
    }
    
    return max_inversion_height;
}

// Calculate ducting thickness
float FGCom_AtmosphericDucting::calculateDuctingThickness(const std::vector<DuctingAtmosphericConditions>& profile) {
    if (profile.empty()) return 0.0f;
    
    float thickness = 0.0f;
    bool in_inversion = false;
    float inversion_start = 0.0f;
    
    for (size_t i = 1; i < profile.size(); i++) {
        float temp_diff = profile[i].temperature_celsius - profile[i-1].temperature_celsius;
        float altitude_diff = profile[i].altitude_m - profile[i-1].altitude_m;
        
        if (altitude_diff > 0.0f) {
            float gradient = temp_diff / altitude_diff;
            
            if (gradient > 0.0f && !in_inversion) {
                // Start of inversion
                in_inversion = true;
                inversion_start = profile[i-1].altitude_m;
            } else if (gradient <= 0.0f && in_inversion) {
                // End of inversion
                thickness = profile[i-1].altitude_m - inversion_start;
                break;
            }
        }
    }
    
    return thickness;
}

// Calculate signal enhancement
float FGCom_AtmosphericDucting::calculateSignalEnhancement(const DuctingConditions& conditions, 
                                                          float frequency_hz, float distance_km) {
    if (!conditions.ducting_present) return 1.0f;
    
    // Base enhancement from ducting strength
    float base_enhancement = 1.0f + (conditions.ducting_strength * 2.0f);
    
    // Frequency-dependent enhancement
    float frequency_factor = 1.0f;
    if (frequency_hz < 100000000.0f) { // VHF
        frequency_factor = 1.5f;
    } else if (frequency_hz < 1000000000.0f) { // UHF
        frequency_factor = 1.2f;
    } else { // Microwave
        frequency_factor = 1.0f;
    }
    
    // Distance-dependent enhancement
    float distance_factor = 1.0f;
    if (distance_km > 50.0f) {
        distance_factor = 1.0f + (distance_km / 200.0f);
    }
    
    return base_enhancement * frequency_factor * distance_factor;
}

// Update weather data
void FGCom_AtmosphericDucting::updateWeatherData(const std::map<std::string, DuctingAtmosphericConditions>& weather_data) {
    if (!weather_cache_enabled) return;
    
    weather_cache = weather_data;
    last_weather_update = std::chrono::system_clock::now();
}

// Set weather cache enabled
void FGCom_AtmosphericDucting::setWeatherCacheEnabled(bool enabled, float timeout_seconds) {
    weather_cache_enabled = enabled;
    cache_timeout_seconds = timeout_seconds;
}

// Predict ducting conditions
bool FGCom_AtmosphericDucting::predictDuctingConditions(double latitude, double longitude, 
                                                       const std::chrono::system_clock::time_point& time) {
    // Simple prediction based on historical data
    // In a real implementation, this would use weather forecasting models
    
    // Check if we have recent weather data
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - last_weather_update);
    
    if (duration.count() > cache_timeout_seconds) {
        return false; // No recent data
    }
    
    // Simple prediction based on time of day and season
    // (This is a simplified example - real implementation would be more complex)
    return true;
}

// Get statistics
FGCom_AtmosphericDucting::DuctingStatistics FGCom_AtmosphericDucting::getStatistics() const {
    return statistics;
}

// Reset statistics
void FGCom_AtmosphericDucting::resetStatistics() {
    statistics.total_analyses = 0;
    statistics.ducting_detected = 0;
    statistics.average_ducting_strength = 0.0f;
    statistics.average_ducting_height = 0.0f;
    statistics.last_analysis = std::chrono::system_clock::now();
}

// Set minimum ducting strength
void FGCom_AtmosphericDucting::setMinimumDuctingStrength(float strength) {
    min_ducting_strength = std::max(0.0f, std::min(1.0f, strength));
}

// Set ducting height range
void FGCom_AtmosphericDucting::setDuctingHeightRange(float min_height, float max_height) {
    min_ducting_height = min_height;
    max_ducting_height = max_height;
}

// Set temperature inversion threshold
void FGCom_AtmosphericDucting::setTemperatureInversionThreshold(float threshold) {
    temperature_inversion_threshold = threshold;
}

// Utility functions
namespace AtmosphericDuctingUtils {
    
    // Calculate atmospheric refraction index
    float calculateRefractionIndex(float temperature_celsius, float humidity_percent, float pressure_hpa) {
        float n = 1.0f + (77.6f * pressure_hpa / (temperature_celsius + 273.15f)) * 1e-6f;
        n += (3.73f * humidity_percent * pressure_hpa / (temperature_celsius + 273.15f)) * 1e-6f;
        return n;
    }
    
    // Calculate temperature gradient
    float calculateTemperatureGradient(const std::vector<DuctingAtmosphericConditions>& profile) {
        if (profile.size() < 2) return 0.0f;
        
        float total_gradient = 0.0f;
        int count = 0;
        
        for (size_t i = 1; i < profile.size(); i++) {
            float temp_diff = profile[i].temperature_celsius - profile[i-1].temperature_celsius;
            float altitude_diff = profile[i].altitude_m - profile[i-1].altitude_m;
            
            if (altitude_diff > 0.0f) {
                total_gradient += temp_diff / altitude_diff;
                count++;
            }
        }
        
        return count > 0 ? total_gradient / count : 0.0f;
    }
    
    // Calculate humidity gradient
    float calculateHumidityGradient(const std::vector<DuctingAtmosphericConditions>& profile) {
        if (profile.size() < 2) return 0.0f;
        
        float total_gradient = 0.0f;
        int count = 0;
        
        for (size_t i = 1; i < profile.size(); i++) {
            float humidity_diff = profile[i].humidity_percent - profile[i-1].humidity_percent;
            float altitude_diff = profile[i].altitude_m - profile[i-1].altitude_m;
            
            if (altitude_diff > 0.0f) {
                total_gradient += humidity_diff / altitude_diff;
                count++;
            }
        }
        
        return count > 0 ? total_gradient / count : 0.0f;
    }
    
    // Calculate wind shear
    float calculateWindShear(const std::vector<DuctingAtmosphericConditions>& profile) {
        if (profile.size() < 2) return 0.0f;
        
        float total_shear = 0.0f;
        int count = 0;
        
        for (size_t i = 1; i < profile.size(); i++) {
            float wind_diff = profile[i].wind_speed_ms - profile[i-1].wind_speed_ms;
            float altitude_diff = profile[i].altitude_m - profile[i-1].altitude_m;
            
            if (altitude_diff > 0.0f) {
                total_shear += std::abs(wind_diff) / altitude_diff;
                count++;
            }
        }
        
        return count > 0 ? total_shear / count : 0.0f;
    }
    
    // Calculate ducting probability
    float calculateDuctingProbability(const DuctingAtmosphericConditions& surface, 
                                    const DuctingAtmosphericConditions& elevated) {
        float temp_diff = elevated.temperature_celsius - surface.temperature_celsius;
        float humidity_diff = surface.humidity_percent - elevated.humidity_percent;
        
        float temp_probability = std::min(1.0f, temp_diff / 5.0f);
        float humidity_probability = std::min(1.0f, humidity_diff / 20.0f);
        
        return (temp_probability + humidity_probability) / 2.0f;
    }
    
    // Calculate signal enhancement factor
    float calculateSignalEnhancement(float ducting_strength, float frequency_hz, float distance_km) {
        float base_enhancement = 1.0f + (ducting_strength * 3.0f);
        
        // Frequency-dependent factor
        float freq_factor = 1.0f;
        if (frequency_hz < 100000000.0f) { // VHF
            freq_factor = 1.8f;
        } else if (frequency_hz < 1000000000.0f) { // UHF
            freq_factor = 1.4f;
        } else { // Microwave
            freq_factor = 1.0f;
        }
        
        // Distance-dependent factor
        float dist_factor = 1.0f;
        if (distance_km > 100.0f) {
            dist_factor = 1.0f + (distance_km / 300.0f);
        }
        
        return base_enhancement * freq_factor * dist_factor;
    }
    
    // Validate atmospheric conditions
    bool validateDuctingAtmosphericConditions(const DuctingAtmosphericConditions& conditions) {
        return conditions.temperature_celsius >= -60.0f && conditions.temperature_celsius <= 60.0f &&
               conditions.humidity_percent >= 0.0f && conditions.humidity_percent <= 100.0f &&
               conditions.pressure_hpa >= 800.0f && conditions.pressure_hpa <= 1100.0f &&
               conditions.wind_speed_ms >= 0.0f && conditions.wind_speed_ms <= 100.0f &&
               conditions.altitude_m >= 0.0f && conditions.altitude_m <= 20000.0f;
    }
}
