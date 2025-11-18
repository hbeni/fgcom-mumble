/*
 * Advanced Noise Floor API - Full Implementation Example
 * 
 * This example demonstrates the complete advanced noise floor system
 * with all features OFF BY DEFAULT and accessible via API.
 */

#include "atmospheric_noise.h"
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>

void demonstrateAdvancedNoiseAPI() {
    std::cout << "=== Advanced Noise Floor API - Full Implementation ===" << std::endl;
    std::cout << std::endl;
    
    auto& noise = FGCom_AtmosphericNoise::getInstance();
    
    // Example 1: Default configuration (all advanced features OFF)
    std::cout << "Example 1: Default Configuration (Advanced Features OFF)" << std::endl;
    std::cout << "========================================================" << std::endl;
    
    auto default_config = noise.getConfig();
    std::cout << "ITU-R P.372 Model: " << (default_config.enable_itu_p372_model ? "ON" : "OFF") << std::endl;
    std::cout << "OSM Integration: " << (default_config.enable_osm_integration ? "ON" : "OFF") << std::endl;
    std::cout << "Population Density: " << (default_config.enable_population_density ? "ON" : "OFF") << std::endl;
    std::cout << "Power Line Analysis: " << (default_config.enable_power_line_analysis ? "ON" : "OFF") << std::endl;
    std::cout << "Traffic Analysis: " << (default_config.enable_traffic_analysis ? "ON" : "OFF") << std::endl;
    std::cout << "Industrial Analysis: " << (default_config.enable_industrial_analysis ? "ON" : "OFF") << std::endl;
    std::cout << std::endl;
    
    // Calculate noise floor with default settings
    double lat = 40.7128, lon = -74.0060;
    float freq = 14.0f;
    
    float default_noise = noise.calculateNoiseFloor(lat, lon, freq);
    std::cout << "Default Noise Floor: " << std::fixed << std::setprecision(1) << default_noise << " dBm" << std::endl;
    std::cout << "S-Meter: S" << noise.dbmToSMeter(default_noise) << std::endl;
    std::cout << std::endl;
    
    // Example 2: Enable all advanced features
    std::cout << "Example 2: Enable All Advanced Features" << std::endl;
    std::cout << "=========================================" << std::endl;
    
    noise.enableAdvancedFeatures(true);
    auto advanced_config = noise.getConfig();
    
    std::cout << "Advanced Configuration:" << std::endl;
    std::cout << "ITU-R P.372 Model: " << (advanced_config.enable_itu_p372_model ? "ON" : "OFF") << std::endl;
    std::cout << "OSM Integration: " << (advanced_config.enable_osm_integration ? "ON" : "OFF") << std::endl;
    std::cout << "Population Density: " << (advanced_config.enable_population_density ? "ON" : "OFF") << std::endl;
    std::cout << "Power Line Analysis: " << (advanced_config.enable_power_line_analysis ? "ON" : "OFF") << std::endl;
    std::cout << "Traffic Analysis: " << (advanced_config.enable_traffic_analysis ? "ON" : "OFF") << std::endl;
    std::cout << "Industrial Analysis: " << (advanced_config.enable_industrial_analysis ? "ON" : "OFF") << std::endl;
    std::cout << std::endl;
    
    float advanced_noise = noise.calculateNoiseFloor(lat, lon, freq);
    std::cout << "Advanced Noise Floor: " << std::fixed << std::setprecision(1) << advanced_noise << " dBm" << std::endl;
    std::cout << "S-Meter: S" << noise.dbmToSMeter(advanced_noise) << std::endl;
    std::cout << "Difference: " << (advanced_noise - default_noise) << " dB" << std::endl;
    std::cout << std::endl;
    
    // Example 3: Selective feature enabling
    std::cout << "Example 3: Selective Feature Enabling" << std::endl;
    std::cout << "=====================================" << std::endl;
    
    // Reset to defaults
    noise.resetToDefaults();
    
    // Enable only specific features
    noise.enableSpecificFeature("itu_p372_model", true);
    noise.enableSpecificFeature("population_density", true);
    noise.enableSpecificFeature("traffic_analysis", true);
    
    auto selective_config = noise.getConfig();
    std::cout << "Selective Configuration:" << std::endl;
    std::cout << "ITU-R P.372 Model: " << (selective_config.enable_itu_p372_model ? "ON" : "OFF") << std::endl;
    std::cout << "OSM Integration: " << (selective_config.enable_osm_integration ? "ON" : "OFF") << std::endl;
    std::cout << "Population Density: " << (selective_config.enable_population_density ? "ON" : "OFF") << std::endl;
    std::cout << "Power Line Analysis: " << (selective_config.enable_power_line_analysis ? "ON" : "OFF") << std::endl;
    std::cout << "Traffic Analysis: " << (selective_config.enable_traffic_analysis ? "ON" : "OFF") << std::endl;
    std::cout << "Industrial Analysis: " << (selective_config.enable_industrial_analysis ? "ON" : "OFF") << std::endl;
    std::cout << std::endl;
    
    float selective_noise = noise.calculateNoiseFloor(lat, lon, freq);
    std::cout << "Selective Noise Floor: " << std::fixed << std::setprecision(1) << selective_noise << " dBm" << std::endl;
    std::cout << "S-Meter: S" << noise.dbmToSMeter(selective_noise) << std::endl;
    std::cout << std::endl;
    
    // Example 4: Individual feature analysis
    std::cout << "Example 4: Individual Feature Analysis" << std::endl;
    std::cout << "======================================" << std::endl;
    
    // Reset to defaults
    noise.resetToDefaults();
    
    std::vector<std::pair<std::string, std::string>> features = {
        {"itu_p372_model", "ITU-R P.372 Model"},
        {"osm_integration", "OSM Integration"},
        {"population_density", "Population Density"},
        {"power_line_analysis", "Power Line Analysis"},
        {"traffic_analysis", "Traffic Analysis"},
        {"industrial_analysis", "Industrial Analysis"}
    };
    
    for (const auto& feature : features) {
        // Enable only this feature
        noise.resetToDefaults();
        noise.enableSpecificFeature(feature.first, true);
        
        float feature_noise = noise.calculateNoiseFloor(lat, lon, freq);
        float noise_contribution = feature_noise - default_noise;
        
        std::cout << std::left << std::setw(25) << feature.second
                  << std::setw(10) << std::fixed << std::setprecision(1) << feature_noise << " dBm"
                  << std::setw(8) << "S" << std::setprecision(1) << noise.dbmToSMeter(feature_noise)
                  << std::setw(15) << "Contribution: " << std::setprecision(1) << noise_contribution << " dB" << std::endl;
    }
    
    std::cout << std::endl;
    
    // Example 5: Different locations with advanced features
    std::cout << "Example 5: Different Locations with Advanced Features" << std::endl;
    std::cout << "=====================================================" << std::endl;
    
    // Enable all features for comparison
    noise.enableAdvancedFeatures(true);
    
    std::vector<std::pair<std::string, std::pair<double, double>>> locations = {
        {"Manhattan, NYC", {40.7589, -73.9851}},
        {"Central Park, NYC", {40.7829, -73.9654}},
        {"Suburban NJ", {40.6892, -74.0445}},
        {"Rural Upstate NY", {42.6526, -73.7562}},
        {"Remote Desert", {36.7783, -119.4179}},
        {"Mid-Ocean", {0.0, 0.0}},
        {"Polar Region", {-80.0, 0.0}}
    };
    
    for (const auto& location : locations) {
        double loc_lat = location.second.first;
        double loc_lon = location.second.second;
        
        float location_noise = noise.calculateNoiseFloor(loc_lat, loc_lon, freq);
        
        std::cout << std::left << std::setw(20) << location.first
                  << std::setw(10) << std::fixed << std::setprecision(1) << location_noise << " dBm"
                  << std::setw(8) << "S" << std::setprecision(1) << noise.dbmToSMeter(location_noise)
                  << std::setw(25) << noise.getNoiseDescription(location_noise) << std::endl;
    }
    
    std::cout << std::endl;
    
    // Reset to defaults
    noise.resetToDefaults();
    std::cout << "Reset to default configuration (advanced features OFF)" << std::endl;
    std::cout << std::endl;
    
    std::cout << "=== Advanced Noise Floor API Example Complete ===" << std::endl;
}

void demonstrateRESTAPI() {
    std::cout << "=== REST API Examples ===" << std::endl;
    std::cout << std::endl;
    
    std::cout << "1. Enable all advanced features:" << std::endl;
    std::cout << "POST /api/v1/noise/config" << std::endl;
    std::cout << "Content-Type: application/json" << std::endl;
    std::cout << "{" << std::endl;
    std::cout << "  \"enable_itu_p372_model\": true," << std::endl;
    std::cout << "  \"enable_osm_integration\": true," << std::endl;
    std::cout << "  \"enable_population_density\": true," << std::endl;
    std::cout << "  \"enable_power_line_analysis\": true," << std::endl;
    std::cout << "  \"enable_traffic_analysis\": true," << std::endl;
    std::cout << "  \"enable_industrial_analysis\": true" << std::endl;
    std::cout << "}" << std::endl;
    std::cout << std::endl;
    
    std::cout << "2. Enable specific features:" << std::endl;
    std::cout << "POST /api/v1/noise/config" << std::endl;
    std::cout << "Content-Type: application/json" << std::endl;
    std::cout << "{" << std::endl;
    std::cout << "  \"enable_itu_p372_model\": true," << std::endl;
    std::cout << "  \"enable_osm_integration\": false," << std::endl;
    std::cout << "  \"enable_population_density\": true," << std::endl;
    std::cout << "  \"enable_power_line_analysis\": false," << std::endl;
    std::cout << "  \"enable_traffic_analysis\": true," << std::endl;
    std::cout << "  \"enable_industrial_analysis\": false" << std::endl;
    std::cout << "}" << std::endl;
    std::cout << std::endl;
    
    std::cout << "3. Reset to defaults:" << std::endl;
    std::cout << "POST /api/v1/noise/config/reset" << std::endl;
    std::cout << std::endl;
    
    std::cout << "4. Get current configuration:" << std::endl;
    std::cout << "GET /api/v1/noise/config" << std::endl;
    std::cout << std::endl;
    
    std::cout << "5. Enable specific feature:" << std::endl;
    std::cout << "POST /api/v1/noise/config/feature" << std::endl;
    std::cout << "Content-Type: application/json" << std::endl;
    std::cout << "{" << std::endl;
    std::cout << "  \"feature\": \"itu_p372_model\"," << std::endl;
    std::cout << "  \"enable\": true" << std::endl;
    std::cout << "}" << std::endl;
    std::cout << std::endl;
    
    std::cout << "6. Calculate noise floor with advanced features:" << std::endl;
    std::cout << "GET /api/v1/noise/floor?lat=40.7128&lon=-74.0060&freq=14.0&advanced=true" << std::endl;
    std::cout << std::endl;
}

int main() {
    try {
        demonstrateAdvancedNoiseAPI();
        std::cout << std::endl;
        demonstrateRESTAPI();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
