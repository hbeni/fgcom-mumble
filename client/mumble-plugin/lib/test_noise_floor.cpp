#include "atmospheric_noise.h"
#include "noise_floor_utils.cpp"
#include <iostream>
#include <iomanip>

void testNoiseFloorCalculation() {
    std::cout << "=== FGCom Atmospheric Noise Floor Test ===" << std::endl;
    std::cout << std::endl;
    
    // Get the atmospheric noise instance
    auto& noise = FGCom_AtmosphericNoise::getInstance();
    
    // Test different environments
    std::cout << "Testing different environments at 14.0 MHz:" << std::endl;
    std::cout << "=========================================" << std::endl;
    
    double test_lat = 40.7128;  // New York
    double test_lon = -74.0060;
    float test_freq = 14.0f;     // 20m band
    
    // Test different environment types (ranked from quietest to noisiest)
    std::vector<std::pair<EnvironmentType, std::string>> environments = {
        {EnvironmentType::POLAR, "Polar Regions"},
        {EnvironmentType::DESERT, "Remote Desert"},
        {EnvironmentType::OCEAN, "Mid-Ocean/Sailboat"},
        {EnvironmentType::REMOTE, "Remote/National Park"},
        {EnvironmentType::SUBURBAN, "Suburban/Residential"},
        {EnvironmentType::URBAN, "Urban/City"},
        {EnvironmentType::INDUSTRIAL, "Industrial Area"}
    };
    
    for (const auto& env : environments) {
        float noise_floor = noise.calculateNoiseFloor(test_lat, test_lon, test_freq, env.first);
        float s_meter = noise.dbmToSMeter(noise_floor);
        std::string description = noise.getNoiseDescription(noise_floor);
        
        std::cout << std::left << std::setw(20) << env.second 
                  << std::setw(10) << std::fixed << std::setprecision(1) << noise_floor << " dBm"
                  << std::setw(8) << "S" << std::setprecision(1) << s_meter
                  << std::setw(25) << description << std::endl;
    }
    
    std::cout << std::endl;
    
    // Test different frequencies
    std::cout << "Testing different HF bands (Suburban environment):" << std::endl;
    std::cout << "==================================================" << std::endl;
    
    noise.setEnvironmentType(EnvironmentType::SUBURBAN);
    
    std::vector<std::pair<float, std::string>> bands = {
        {1.8f, "160m Band"},
        {3.5f, "80m Band"},
        {7.0f, "40m Band"},
        {14.0f, "20m Band"},
        {21.0f, "15m Band"},
        {28.0f, "10m Band"}
    };
    
    for (const auto& band : bands) {
        float noise_floor = noise.calculateNoiseFloor(test_lat, test_lon, band.first);
        float s_meter = noise.dbmToSMeter(noise_floor);
        std::string description = noise.getNoiseDescription(noise_floor);
        
        std::cout << std::left << std::setw(12) << band.second
                  << std::setw(10) << std::fixed << std::setprecision(1) << noise_floor << " dBm"
                  << std::setw(8) << "S" << std::setprecision(1) << s_meter
                  << std::setw(25) << description << std::endl;
    }
    
    std::cout << std::endl;
    
    // Test time of day effects
    std::cout << "Testing time of day effects (Suburban, 14.0 MHz):" << std::endl;
    std::cout << "=================================================" << std::endl;
    
    std::vector<std::pair<TimeOfDay, std::string>> times = {
        {TimeOfDay::NIGHT, "Night (22:00-06:00)"},
        {TimeOfDay::DAY, "Day (06:00-18:00)"},
        {TimeOfDay::DUSK_DAWN, "Dusk/Dawn (18:00-22:00)"}
    };
    
    for (const auto& time : times) {
        noise.setTimeOfDay(time.first);
        float noise_floor = noise.calculateNoiseFloor(test_lat, test_lon, test_freq);
        float s_meter = noise.dbmToSMeter(noise_floor);
        std::string description = noise.getNoiseDescription(noise_floor);
        
        std::cout << std::left << std::setw(25) << time.second
                  << std::setw(10) << std::fixed << std::setprecision(1) << noise_floor << " dBm"
                  << std::setw(8) << "S" << std::setprecision(1) << s_meter
                  << std::setw(25) << description << std::endl;
    }
    
    std::cout << std::endl;
    
    // Test weather effects
    std::cout << "Testing weather effects (Suburban, 14.0 MHz):" << std::endl;
    std::cout << "=============================================" << std::endl;
    
    // Normal weather
    WeatherConditions normal_weather;
    normal_weather.has_thunderstorms = false;
    normal_weather.storm_distance_km = 0.0f;
    normal_weather.storm_intensity = 0.0f;
    normal_weather.has_precipitation = false;
    normal_weather.temperature_celsius = 20.0f;
    normal_weather.humidity_percent = 50.0f;
    
    noise.setWeatherConditions(normal_weather);
    float normal_noise = noise.calculateNoiseFloor(test_lat, test_lon, test_freq);
    
    // Thunderstorm weather
    WeatherConditions storm_weather;
    storm_weather.has_thunderstorms = true;
    storm_weather.storm_distance_km = 25.0f;  // 25km away
    storm_weather.storm_intensity = 0.8f;     // Strong storm
    storm_weather.has_precipitation = true;
    storm_weather.temperature_celsius = 25.0f;
    storm_weather.humidity_percent = 90.0f;
    
    noise.setWeatherConditions(storm_weather);
    float storm_noise = noise.calculateNoiseFloor(test_lat, test_lon, test_freq);
    
    std::cout << std::left << std::setw(20) << "Normal Weather"
              << std::setw(10) << std::fixed << std::setprecision(1) << normal_noise << " dBm"
              << std::setw(8) << "S" << std::setprecision(1) << noise.dbmToSMeter(normal_noise)
              << std::setw(25) << noise.getNoiseDescription(normal_noise) << std::endl;
              
    std::cout << std::left << std::setw(20) << "Thunderstorm"
              << std::setw(10) << std::fixed << std::setprecision(1) << storm_noise << " dBm"
              << std::setw(8) << "S" << std::setprecision(1) << noise.dbmToSMeter(storm_noise)
              << std::setw(25) << noise.getNoiseDescription(storm_noise) << std::endl;
    
    std::cout << std::endl;
    std::cout << "Noise floor difference: " << std::fixed << std::setprecision(1) 
              << (storm_noise - normal_noise) << " dB" << std::endl;
    
    std::cout << std::endl;
    
    // Test utility functions
    std::cout << "Testing utility functions:" << std::endl;
    std::cout << "=========================" << std::endl;
    
    float test_dbm = -115.0f;
    float microvolts = NoiseFloorUtils::dbmToMicrovolts(test_dbm, 50.0f);
    float back_to_dbm = NoiseFloorUtils::microvoltsToDbm(microvolts, 50.0f);
    
    std::cout << "dBm to microvolts conversion:" << std::endl;
    std::cout << "  " << test_dbm << " dBm = " << std::fixed << std::setprecision(2) 
              << microvolts << " μV" << std::endl;
    std::cout << "  Back to dBm: " << std::fixed << std::setprecision(1) 
              << back_to_dbm << " dBm" << std::endl;
    
    std::cout << std::endl;
    std::cout << "Noise floor quality assessment:" << std::endl;
    std::cout << "  " << test_dbm << " dBm: " 
              << NoiseFloorUtils::assessNoiseFloorQuality(test_dbm) << std::endl;
    
    std::cout << std::endl;
    std::cout << "=== Test Complete ===" << std::endl;
}

int main() {
    try {
        testNoiseFloorCalculation();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
