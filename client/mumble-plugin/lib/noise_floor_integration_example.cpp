/*
 * Example integration of atmospheric noise floor calculation
 * into the existing FGCom-Mumble propagation model
 */

#include "noise/atmospheric_noise.h"
#include "radio_model.h"  // Assuming this exists in the codebase
#include <iostream>

class FGCom_EnhancedPropagation {
private:
    FGCom_AtmosphericNoise& noise_calculator;
    
public:
    FGCom_EnhancedPropagation() : noise_calculator(FGCom_AtmosphericNoise::getInstance()) {}
    
    // Enhanced propagation calculation with noise floor
    float calculatePropagationWithNoise(
        double lat1, double lon1, double lat2, double lon2,
        float freq_mhz, float power_watts, EnvironmentType env_type
    ) {
        // Get noise floor for both locations
        float noise_floor_1 = noise_calculator.calculateNoiseFloor(lat1, lon1, freq_mhz, env_type);
        float noise_floor_2 = noise_calculator.calculateNoiseFloor(lat2, lon2, freq_mhz, env_type);
        
        // Use the higher noise floor (worst case)
        float effective_noise_floor = std::max(noise_floor_1, noise_floor_2);
        
        // Calculate basic propagation (existing code)
        float path_loss = calculateBasicPathLoss(lat1, lon1, lat2, lon2, freq_mhz);
        float received_power = power_watts - path_loss;
        
        // Convert to dBm for comparison
        float received_power_dbm = 10.0f * std::log10(received_power * 1000.0f);
        
        // Calculate signal-to-noise ratio
        float snr_db = received_power_dbm - effective_noise_floor;
        
        // Determine if signal is detectable
        float min_snr_db = 6.0f;  // Minimum SNR for reliable communication
        bool is_detectable = snr_db >= min_snr_db;
        
        // Return SNR or -999 if not detectable
        return is_detectable ? snr_db : -999.0f;
    }
    
    // Get noise floor information for display
    void getNoiseFloorInfo(double lat, double lon, float freq_mhz, EnvironmentType env_type) {
        float noise_floor = noise_calculator.calculateNoiseFloor(lat, lon, freq_mhz, env_type);
        float s_meter = noise_calculator.dbmToSMeter(noise_floor);
        std::string description = noise_calculator.getNoiseDescription(noise_floor);
        
        std::cout << "Noise Floor Information:" << std::endl;
        std::cout << "  Location: " << lat << ", " << lon << std::endl;
        std::cout << "  Frequency: " << freq_mhz << " MHz" << std::endl;
        std::cout << "  Environment: " << getEnvironmentName(env_type) << std::endl;
        std::cout << "  Noise Floor: " << noise_floor << " dBm" << std::endl;
        std::cout << "  S-Meter: S" << s_meter << std::endl;
        std::cout << "  Description: " << description << std::endl;
        std::cout << "  Quality: " << NoiseFloorUtils::assessNoiseFloorQuality(noise_floor) << std::endl;
    }
    
    // Update noise floor with real-time data
    void updateNoiseFloorData(double lat, double lon, float freq_mhz) {
        // Update with current conditions
        noise_calculator.updateRealTimeData(lat, lon, freq_mhz);
        
        // Process any new lightning strikes
        // (This would typically come from the lightning data thread)
        std::vector<LightningStrike> recent_strikes = getRecentLightningStrikes();
        noise_calculator.updateLightningStrikes(recent_strikes);
        
        // Update weather conditions
        WeatherConditions current_weather = getCurrentWeatherConditions();
        noise_calculator.processWeatherUpdate(current_weather);
        
        // Update solar activity
        float sfi = getCurrentSolarFluxIndex();
        float k_index = getCurrentKIndex();
        float a_index = getCurrentAIndex();
        noise_calculator.processSolarUpdate(sfi, k_index, a_index);
    }
    
private:
    // Placeholder methods - these would be implemented based on existing codebase
    float calculateBasicPathLoss(double lat1, double lon1, double lat2, double lon2, float freq_mhz) {
        // This would use the existing propagation calculation code
        // For now, return a simple distance-based calculation
        float distance_km = calculateDistance(lat1, lon1, lat2, lon2);
        return 20.0f * std::log10(distance_km) + 20.0f * std::log10(freq_mhz) + 32.45f;
    }
    
    float calculateDistance(double lat1, double lon1, double lat2, double lon2) {
        // Haversine formula
        const double R = 6371.0;  // Earth's radius in km
        double dlat = (lat2 - lat1) * M_PI / 180.0;
        double dlon = (lon2 - lon1) * M_PI / 180.0;
        double a = std::sin(dlat/2) * std::sin(dlat/2) +
                   std::cos(lat1 * M_PI / 180.0) * std::cos(lat2 * M_PI / 180.0) *
                   std::sin(dlon/2) * std::sin(dlon/2);
        double c = 2 * std::atan2(std::sqrt(a), std::sqrt(1-a));
        return R * c;
    }
    
    std::string getEnvironmentName(EnvironmentType env_type) {
        switch (env_type) {
            case EnvironmentType::REMOTE: return "Remote/National Park";
            case EnvironmentType::SUBURBAN: return "Suburban/Residential";
            case EnvironmentType::URBAN: return "Urban/City";
            case EnvironmentType::INDUSTRIAL: return "Industrial Area";
            default: return "Unknown";
        }
    }
    
    // Placeholder methods for real-time data
    std::vector<LightningStrike> getRecentLightningStrikes() {
        // This would interface with the existing lightning data system
        return std::vector<LightningStrike>();
    }
    
    WeatherConditions getCurrentWeatherConditions() {
        // This would interface with weather data sources
        WeatherConditions weather;
        weather.has_thunderstorms = false;
        weather.storm_distance_km = 0.0f;
        weather.storm_intensity = 0.0f;
        weather.has_precipitation = false;
        weather.temperature_celsius = 20.0f;
        weather.humidity_percent = 50.0f;
        return weather;
    }
    
    float getCurrentSolarFluxIndex() { return 100.0f; }
    float getCurrentKIndex() { return 2.0f; }
    float getCurrentAIndex() { return 5.0f; }
};

// Example usage function
void demonstrateNoiseFloorIntegration() {
    std::cout << "=== FGCom Noise Floor Integration Example ===" << std::endl;
    std::cout << std::endl;
    
    FGCom_EnhancedPropagation propagation;
    
    // Test locations
    double ny_lat = 40.7128, ny_lon = -74.0060;  // New York
    double la_lat = 34.0522, la_lon = -118.2437; // Los Angeles
    
    // Test different scenarios
    std::vector<std::pair<float, std::string>> test_cases = {
        {1.8f, "160m Band - Night"},
        {3.5f, "80m Band - Night"},
        {7.0f, "40m Band - Day"},
        {14.0f, "20m Band - Day"},
        {21.0f, "15m Band - Day"},
        {28.0f, "10m Band - Day"}
    };
    
    for (const auto& test_case : test_cases) {
        std::cout << "Testing " << test_case.second << ":" << std::endl;
        std::cout << "----------------------------------------" << std::endl;
        
        // Test different environments (ranked from quietest to noisiest)
        std::vector<EnvironmentType> environments = {
            EnvironmentType::POLAR,
            EnvironmentType::DESERT,
            EnvironmentType::OCEAN,
            EnvironmentType::REMOTE,
            EnvironmentType::SUBURBAN,
            EnvironmentType::URBAN,
            EnvironmentType::INDUSTRIAL
        };
        
        for (auto env : environments) {
            float snr = propagation.calculatePropagationWithNoise(
                ny_lat, ny_lon, la_lat, la_lon, test_case.first, 100.0f, env
            );
            
            std::string env_name = (env == EnvironmentType::POLAR) ? "Polar" :
                                  (env == EnvironmentType::DESERT) ? "Desert" :
                                  (env == EnvironmentType::OCEAN) ? "Ocean" :
                                  (env == EnvironmentType::REMOTE) ? "Remote" :
                                  (env == EnvironmentType::SUBURBAN) ? "Suburban" :
                                  (env == EnvironmentType::URBAN) ? "Urban" : "Industrial";
            
            if (snr > -999.0f) {
                std::cout << "  " << std::setw(10) << env_name 
                          << ": SNR = " << std::fixed << std::setprecision(1) 
                          << snr << " dB" << std::endl;
            } else {
                std::cout << "  " << std::setw(10) << env_name 
                          << ": Signal not detectable" << std::endl;
            }
        }
        
        std::cout << std::endl;
    }
    
    // Demonstrate noise floor information
    std::cout << "Noise Floor Analysis for New York (14.0 MHz):" << std::endl;
    std::cout << "=============================================" << std::endl;
    propagation.getNoiseFloorInfo(ny_lat, ny_lon, 14.0f, EnvironmentType::SUBURBAN);
    
    std::cout << std::endl;
    std::cout << "=== Integration Example Complete ===" << std::endl;
}
