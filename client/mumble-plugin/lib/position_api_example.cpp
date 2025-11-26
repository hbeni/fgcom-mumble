/*
 * Position API Example - GPS and Maidenhead Locator Support
 * 
 * This example demonstrates how users can set their position
 * using either GPS coordinates or Maidenhead locators via API.
 */

#include "noise/atmospheric_noise.h"
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>

void demonstratePositionAPI() {
    std::cout << "=== Position API - GPS and Maidenhead Support ===" << std::endl;
    std::cout << std::endl;
    
    auto& noise = FGCom_AtmosphericNoise::getInstance();
    
    // Example 1: Set position using GPS coordinates
    std::cout << "Example 1: Set Position Using GPS Coordinates" << std::endl;
    std::cout << "===============================================" << std::endl;
    
    double gps_lat = 40.7128;  // New York City
    double gps_lon = -74.0060;
    
    noise.setUserPosition(gps_lat, gps_lon);
    
    std::cout << "GPS Position Set: " << gps_lat << ", " << gps_lon << std::endl;
    std::cout << "User Position Set: " << (noise.isUserPositionSet() ? "YES" : "NO") << std::endl;
    
    auto user_pos = noise.getUserPosition();
    std::cout << "Retrieved Position: " << user_pos.first << ", " << user_pos.second << std::endl;
    
    std::string user_maidenhead = noise.getUserMaidenhead();
    std::cout << "Converted Maidenhead: " << user_maidenhead << std::endl;
    std::cout << std::endl;
    
    // Calculate noise floor for user position
    float freq = 14.0f;
    float user_noise = noise.calculateNoiseFloorForUserPosition(freq);
    std::cout << "Noise Floor for User Position: " << std::fixed << std::setprecision(1) 
              << user_noise << " dBm" << std::endl;
    std::cout << "S-Meter: S" << noise.dbmToSMeter(user_noise) << std::endl;
    std::cout << std::endl;
    
    // Example 2: Set position using Maidenhead locator
    std::cout << "Example 2: Set Position Using Maidenhead Locator" << std::endl;
    std::cout << "=================================================" << std::endl;
    
    std::string maidenhead = "JP88il";  // 1 km × 1 km precision
    noise.setUserPosition(maidenhead);
    
    std::cout << "Maidenhead Set: " << maidenhead << std::endl;
    std::cout << "User Position Set: " << (noise.isUserPositionSet() ? "YES" : "NO") << std::endl;
    
    auto maidenhead_pos = noise.getUserPosition();
    std::cout << "Converted Coordinates: " << maidenhead_pos.first << ", " << maidenhead_pos.second << std::endl;
    
    std::string retrieved_maidenhead = noise.getUserMaidenhead();
    std::cout << "Retrieved Maidenhead: " << retrieved_maidenhead << std::endl;
    std::cout << std::endl;
    
    // Calculate noise floor for Maidenhead position
    float maidenhead_noise = noise.calculateNoiseFloorForUserPosition(freq);
    std::cout << "Noise Floor for Maidenhead Position: " << std::fixed << std::setprecision(1) 
              << maidenhead_noise << " dBm" << std::endl;
    std::cout << "S-Meter: S" << noise.dbmToSMeter(maidenhead_noise) << std::endl;
    std::cout << std::endl;
    
    // Example 3: Set position with both GPS and Maidenhead
    std::cout << "Example 3: Set Position with Both GPS and Maidenhead" << std::endl;
    std::cout << "====================================================" << std::endl;
    
    double precise_lat = 40.7589;  // Central Park, NYC
    double precise_lon = -73.9851;
    std::string precise_maidenhead = "JP88il";
    
    noise.setUserPosition(precise_lat, precise_lon, precise_maidenhead);
    
    std::cout << "GPS Position: " << precise_lat << ", " << precise_lon << std::endl;
    std::cout << "Maidenhead: " << precise_maidenhead << std::endl;
    std::cout << "User Position Set: " << (noise.isUserPositionSet() ? "YES" : "NO") << std::endl;
    std::cout << std::endl;
    
    // Example 4: Different Maidenhead precision levels
    std::cout << "Example 4: Different Maidenhead Precision Levels" << std::endl;
    std::cout << "================================================" << std::endl;
    
    std::vector<std::pair<std::string, std::string>> maidenhead_examples = {
        {"JP88", "2-character (2° × 1° precision)"},
        {"JP88il", "4-character (1 km × 1 km precision)"},
        {"JP88il12", "6-character (100 m × 100 m precision)"},
        {"JP88il12ab", "8-character (10 m × 10 m precision)"}
    };
    
    for (const auto& example : maidenhead_examples) {
        noise.setUserPosition(example.first);
        auto pos = noise.getUserPosition();
        
        std::cout << std::left << std::setw(12) << example.first
                  << std::setw(35) << example.second
                  << std::setw(20) << std::fixed << std::setprecision(4) 
                  << pos.first << ", " << pos.second << std::endl;
    }
    
    std::cout << std::endl;
    
    // Example 5: Position-based environment detection
    std::cout << "Example 5: Position-based Environment Detection" << std::endl;
    std::cout << "===============================================" << std::endl;
    
    std::vector<std::pair<std::string, std::pair<double, double>>> test_locations = {
        {"Manhattan, NYC", {40.7589, -73.9851}},
        {"Central Park, NYC", {40.7829, -73.9654}},
        {"Suburban NJ", {40.6892, -74.0445}},
        {"Rural Upstate NY", {42.6526, -73.7562}},
        {"Remote Desert", {36.7783, -119.4179}},
        {"Mid-Ocean", {0.0, 0.0}},
        {"Polar Region", {-80.0, 0.0}}
    };
    
    for (const auto& location : test_locations) {
        noise.setUserPosition(location.second.first, location.second.second);
        
        // Auto-detect environment
        EnvironmentType detected_env = noise.detectEnvironmentFromCoordinates(
            location.second.first, location.second.second);
        
        // Calculate noise floor
        float location_noise = noise.calculateNoiseFloorForUserPosition(freq);
        
        std::cout << std::left << std::setw(20) << location.first
                  << std::setw(15) << std::fixed << std::setprecision(1) 
                  << location_noise << " dBm"
                  << std::setw(8) << "S" << std::setprecision(1) << noise.dbmToSMeter(location_noise)
                  << std::setw(15) << "Env: " << (int)detected_env << std::endl;
    }
    
    std::cout << std::endl;
    
    // Example 6: Manual environment override for Maidenhead
    std::cout << "Example 6: Manual Environment Override for Maidenhead" << std::endl;
    std::cout << "======================================================" << std::endl;
    
    // Set Maidenhead position
    noise.setUserPosition("JP88il");
    
    // Auto-detect environment (may be uncertain due to 1 km precision)
    EnvironmentType auto_env = noise.detectEnvironmentFromMaidenhead("JP88il");
    float auto_noise = noise.calculateNoiseFloorForUserPosition(freq);
    
    std::cout << "Maidenhead: JP88il (1 km × 1 km precision)" << std::endl;
    std::cout << "Auto-detected Environment: " << (int)auto_env << std::endl;
    std::cout << "Auto-detected Noise Floor: " << std::fixed << std::setprecision(1) 
              << auto_noise << " dBm" << std::endl;
    std::cout << std::endl;
    
    // User manually sets environment (more accurate)
    noise.setManualEnvironment("polar");
    EnvironmentType manual_env = noise.getManualEnvironment();
    float manual_noise = noise.calculateNoiseFloorForUserPosition(freq, manual_env);
    
    std::cout << "User Manual Environment: " << (int)manual_env << std::endl;
    std::cout << "Manual Noise Floor: " << std::fixed << std::setprecision(1) 
              << manual_noise << " dBm" << std::endl;
    std::cout << "Difference: " << (manual_noise - auto_noise) << " dB" << std::endl;
    std::cout << std::endl;
    
    // Clear position
    noise.clearUserPosition();
    std::cout << "Position cleared. User Position Set: " << (noise.isUserPositionSet() ? "YES" : "NO") << std::endl;
    std::cout << std::endl;
    
    std::cout << "=== Position API Example Complete ===" << std::endl;
}

void demonstrateRESTAPI() {
    std::cout << "=== REST API Examples ===" << std::endl;
    std::cout << std::endl;
    
    std::cout << "1. Set position using GPS coordinates:" << std::endl;
    std::cout << "POST /api/v1/noise/position" << std::endl;
    std::cout << "Content-Type: application/json" << std::endl;
    std::cout << "{" << std::endl;
    std::cout << "  \"latitude\": 40.7128," << std::endl;
    std::cout << "  \"longitude\": -74.0060" << std::endl;
    std::cout << "}" << std::endl;
    std::cout << std::endl;
    
    std::cout << "2. Set position using Maidenhead locator:" << std::endl;
    std::cout << "POST /api/v1/noise/position" << std::endl;
    std::cout << "Content-Type: application/json" << std::endl;
    std::cout << "{" << std::endl;
    std::cout << "  \"maidenhead\": \"JP88il\"" << std::endl;
    std::cout << "}" << std::endl;
    std::cout << std::endl;
    
    std::cout << "3. Set position with both GPS and Maidenhead:" << std::endl;
    std::cout << "POST /api/v1/noise/position" << std::endl;
    std::cout << "Content-Type: application/json" << std::endl;
    std::cout << "{" << std::endl;
    std::cout << "  \"latitude\": 40.7128," << std::endl;
    std::cout << "  \"longitude\": -74.0060," << std::endl;
    std::cout << "  \"maidenhead\": \"JP88il\"" << std::endl;
    std::cout << "}" << std::endl;
    std::cout << std::endl;
    
    std::cout << "4. Get current position:" << std::endl;
    std::cout << "GET /api/v1/noise/position" << std::endl;
    std::cout << std::endl;
    
    std::cout << "5. Calculate noise floor for user position:" << std::endl;
    std::cout << "GET /api/v1/noise/floor?freq=14.0" << std::endl;
    std::cout << std::endl;
    
    std::cout << "6. Calculate noise floor with manual environment:" << std::endl;
    std::cout << "GET /api/v1/noise/floor?freq=14.0&env=polar" << std::endl;
    std::cout << std::endl;
    
    std::cout << "7. Clear user position:" << std::endl;
    std::cout << "DELETE /api/v1/noise/position" << std::endl;
    std::cout << std::endl;
}

int main() {
    try {
        demonstratePositionAPI();
        std::cout << std::endl;
        demonstrateRESTAPI();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
