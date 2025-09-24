/*
 * Advanced Noise Floor Configuration Example
 * 
 * This example shows how to configure the advanced noise floor features
 * that are OFF BY DEFAULT to avoid complexity and external dependencies.
 */

#include "atmospheric_noise.h"
#include <iostream>

void demonstrateAdvancedConfiguration() {
    std::cout << "=== Advanced Noise Floor Configuration ===" << std::endl;
    std::cout << std::endl;
    
    auto& noise = FGCom_AtmosphericNoise::getInstance();
    
    // Get current configuration
    auto config = noise.getConfig();
    
    std::cout << "Default Configuration (Advanced Features OFF):" << std::endl;
    std::cout << "==============================================" << std::endl;
    std::cout << "ITU-R P.372 Model: " << (config.enable_itu_p372_model ? "ON" : "OFF") << std::endl;
    std::cout << "OSM Integration: " << (config.enable_osm_integration ? "ON" : "OFF") << std::endl;
    std::cout << "Population Density: " << (config.enable_population_density ? "ON" : "OFF") << std::endl;
    std::cout << "Power Line Analysis: " << (config.enable_power_line_analysis ? "ON" : "OFF") << std::endl;
    std::cout << "Traffic Analysis: " << (config.enable_traffic_analysis ? "ON" : "OFF") << std::endl;
    std::cout << "Industrial Analysis: " << (config.enable_industrial_analysis ? "ON" : "OFF") << std::endl;
    std::cout << std::endl;
    
    // Example 1: Basic noise floor calculation (default behavior)
    std::cout << "Example 1: Basic Noise Floor (Default)" << std::endl;
    std::cout << "======================================" << std::endl;
    
    double lat = 40.7128, lon = -74.0060;
    float freq = 14.0f;
    
    float basic_noise = noise.calculateNoiseFloor(lat, lon, freq);
    std::cout << "Location: " << lat << ", " << lon << std::endl;
    std::cout << "Frequency: " << freq << " MHz" << std::endl;
    std::cout << "Basic Noise Floor: " << std::fixed << std::setprecision(1) << basic_noise << " dBm" << std::endl;
    std::cout << "S-Meter: S" << noise.dbmToSMeter(basic_noise) << std::endl;
    std::cout << std::endl;
    
    // Example 2: Enable advanced features (if needed)
    std::cout << "Example 2: Enabling Advanced Features" << std::endl;
    std::cout << "=====================================" << std::endl;
    
    // Create new configuration with advanced features enabled
    FGCom_AtmosphericNoise::NoiseConfig advanced_config = config;
    advanced_config.enable_itu_p372_model = true;      // Enable ITU-R P.372 model
    advanced_config.enable_osm_integration = true;    // Enable OpenStreetMap integration
    advanced_config.enable_population_density = true; // Enable population density analysis
    advanced_config.enable_power_line_analysis = true; // Enable power line analysis
    advanced_config.enable_traffic_analysis = true;   // Enable traffic analysis
    advanced_config.enable_industrial_analysis = true; // Enable industrial analysis
    
    // Apply advanced configuration
    noise.setConfig(advanced_config);
    
    std::cout << "Advanced Configuration:" << std::endl;
    std::cout << "ITU-R P.372 Model: " << (advanced_config.enable_itu_p372_model ? "ON" : "OFF") << std::endl;
    std::cout << "OSM Integration: " << (advanced_config.enable_osm_integration ? "ON" : "OFF") << std::endl;
    std::cout << "Population Density: " << (advanced_config.enable_population_density ? "ON" : "OFF") << std::endl;
    std::cout << "Power Line Analysis: " << (advanced_config.enable_power_line_analysis ? "ON" : "OFF") << std::endl;
    std::cout << "Traffic Analysis: " << (advanced_config.enable_traffic_analysis ? "ON" : "OFF") << std::endl;
    std::cout << "Industrial Analysis: " << (advanced_config.enable_industrial_analysis ? "ON" : "OFF") << std::endl;
    std::cout << std::endl;
    
    // Calculate noise floor with advanced features
    float advanced_noise = noise.calculateNoiseFloor(lat, lon, freq);
    std::cout << "Advanced Noise Floor: " << std::fixed << std::setprecision(1) << advanced_noise << " dBm" << std::endl;
    std::cout << "S-Meter: S" << noise.dbmToSMeter(advanced_noise) << std::endl;
    std::cout << "Difference: " << (advanced_noise - basic_noise) << " dB" << std::endl;
    std::cout << std::endl;
    
    // Example 3: Selective feature enabling
    std::cout << "Example 3: Selective Feature Enabling" << std::endl;
    std::cout << "=====================================" << std::endl;
    
    // Reset to default
    noise.setConfig(config);
    
    // Enable only specific features
    FGCom_AtmosphericNoise::NoiseConfig selective_config = config;
    selective_config.enable_itu_p372_model = true;     // Enable ITU-R P.372
    selective_config.enable_osm_integration = false;   // Keep OSM off (complex)
    selective_config.enable_population_density = true; // Enable population density
    selective_config.enable_power_line_analysis = false; // Keep power line analysis off
    selective_config.enable_traffic_analysis = false;   // Keep traffic analysis off
    selective_config.enable_industrial_analysis = false; // Keep industrial analysis off
    
    noise.setConfig(selective_config);
    
    float selective_noise = noise.calculateNoiseFloor(lat, lon, freq);
    std::cout << "Selective Configuration:" << std::endl;
    std::cout << "ITU-R P.372 Model: " << (selective_config.enable_itu_p372_model ? "ON" : "OFF") << std::endl;
    std::cout << "OSM Integration: " << (selective_config.enable_osm_integration ? "ON" : "OFF") << std::endl;
    std::cout << "Population Density: " << (selective_config.enable_population_density ? "ON" : "OFF") << std::endl;
    std::cout << "Power Line Analysis: " << (selective_config.enable_power_line_analysis ? "ON" : "OFF") << std::endl;
    std::cout << "Traffic Analysis: " << (selective_config.enable_traffic_analysis ? "ON" : "OFF") << std::endl;
    std::cout << "Industrial Analysis: " << (selective_config.enable_industrial_analysis ? "ON" : "OFF") << std::endl;
    std::cout << "Selective Noise Floor: " << std::fixed << std::setprecision(1) << selective_noise << " dBm" << std::endl;
    std::cout << std::endl;
    
    // Reset to default configuration
    noise.setConfig(config);
    std::cout << "Reset to default configuration (advanced features OFF)" << std::endl;
    std::cout << std::endl;
    
    std::cout << "=== Configuration Example Complete ===" << std::endl;
}

void demonstrateConfigurationAPI() {
    std::cout << "=== Configuration API Examples ===" << std::endl;
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
    
    std::cout << "2. Enable only ITU-R P.372 model:" << std::endl;
    std::cout << "POST /api/v1/noise/config" << std::endl;
    std::cout << "Content-Type: application/json" << std::endl;
    std::cout << "{" << std::endl;
    std::cout << "  \"enable_itu_p372_model\": true," << std::endl;
    std::cout << "  \"enable_osm_integration\": false," << std::endl;
    std::cout << "  \"enable_population_density\": false," << std::endl;
    std::cout << "  \"enable_power_line_analysis\": false," << std::endl;
    std::cout << "  \"enable_traffic_analysis\": false," << std::endl;
    std::cout << "  \"enable_industrial_analysis\": false" << std::endl;
    std::cout << "}" << std::endl;
    std::cout << std::endl;
    
    std::cout << "3. Reset to default (disable all advanced features):" << std::endl;
    std::cout << "POST /api/v1/noise/config" << std::endl;
    std::cout << "Content-Type: application/json" << std::endl;
    std::cout << "{" << std::endl;
    std::cout << "  \"enable_itu_p372_model\": false," << std::endl;
    std::cout << "  \"enable_osm_integration\": false," << std::endl;
    std::cout << "  \"enable_population_density\": false," << std::endl;
    std::cout << "  \"enable_power_line_analysis\": false," << std::endl;
    std::cout << "  \"enable_traffic_analysis\": false," << std::endl;
    std::cout << "  \"enable_industrial_analysis\": false" << std::endl;
    std::cout << "}" << std::endl;
    std::cout << std::endl;
    
    std::cout << "4. Get current configuration:" << std::endl;
    std::cout << "GET /api/v1/noise/config" << std::endl;
    std::cout << std::endl;
}

int main() {
    try {
        demonstrateAdvancedConfiguration();
        std::cout << std::endl;
        demonstrateConfigurationAPI();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
