/*
 * API Example: Manual Noise Environment Setting
 * 
 * This example shows how to use the noise floor API to manually set
 * environment types, especially useful for Maidenhead locators where
 * automatic environment detection is uncertain.
 */

#include "atmospheric_noise.h"
#include <iostream>
#include <iomanip>

void demonstrateManualEnvironmentAPI() {
    std::cout << "=== FGCom Noise Floor API - Manual Environment Setting ===" << std::endl;
    std::cout << std::endl;
    
    auto& noise = FGCom_AtmosphericNoise::getInstance();
    
    // Example 1: User with GPS coordinates (precise location)
    std::cout << "Example 1: GPS-based automatic detection" << std::endl;
    std::cout << "==========================================" << std::endl;
    
    double gps_lat = 40.7128;  // New York City
    double gps_lon = -74.0060;
    float test_freq = 14.0f;
    
    // Clear any manual settings
    noise.clearManualEnvironment();
    
    // Auto-detect environment from GPS coordinates
    EnvironmentType detected_env = noise.detectEnvironmentFromCoordinates(gps_lat, gps_lon);
    float gps_noise_floor = noise.calculateNoiseFloor(gps_lat, gps_lon, test_freq);
    
    std::cout << "GPS Location: " << gps_lat << ", " << gps_lon << std::endl;
    std::cout << "Detected Environment: " << (int)detected_env << std::endl;
    std::cout << "Noise Floor: " << std::fixed << std::setprecision(1) << gps_noise_floor << " dBm" << std::endl;
    std::cout << "S-Meter: S" << noise.dbmToSMeter(gps_noise_floor) << std::endl;
    std::cout << std::endl;
    
    // Example 2: User with Maidenhead locator (uncertain location)
    std::cout << "Example 2: Maidenhead locator with manual environment setting" << std::endl;
    std::cout << "=============================================================" << std::endl;
    
    std::string maidenhead = "JP88il";  // 1 km × 1 km square
    std::cout << "Maidenhead Locator: " << maidenhead << " (1 km × 1 km precision)" << std::endl;
    
    // Try auto-detection from Maidenhead (approximate)
    EnvironmentType maidenhead_detected = noise.detectEnvironmentFromMaidenhead(maidenhead);
    std::cout << "Auto-detected from Maidenhead: " << (int)maidenhead_detected << std::endl;
    
    // User manually sets environment (more accurate for their specific location)
    std::cout << "User manually sets environment to: POLAR" << std::endl;
    noise.setManualEnvironment("polar");
    
    // Calculate noise floor with manual environment
    float manual_noise_floor = noise.calculateNoiseFloor(gps_lat, gps_lon, test_freq);
    
    std::cout << "Manual Environment: " << (int)noise.getManualEnvironment() << std::endl;
    std::cout << "Noise Floor: " << std::fixed << std::setprecision(1) << manual_noise_floor << " dBm" << std::endl;
    std::cout << "S-Meter: S" << noise.dbmToSMeter(manual_noise_floor) << std::endl;
    std::cout << "Difference: " << (manual_noise_floor - gps_noise_floor) << " dB" << std::endl;
    std::cout << std::endl;
    
    // Example 3: Different manual environments
    std::cout << "Example 3: Manual environment comparison" << std::endl;
    std::cout << "========================================" << std::endl;
    
    std::vector<std::pair<std::string, EnvironmentType>> environments = {
        {"Polar Regions", EnvironmentType::POLAR},
        {"Remote Desert", EnvironmentType::DESERT},
        {"Mid-Ocean", EnvironmentType::OCEAN},
        {"Remote/National Park", EnvironmentType::REMOTE},
        {"Suburban", EnvironmentType::SUBURBAN},
        {"Urban", EnvironmentType::URBAN},
        {"Industrial", EnvironmentType::INDUSTRIAL}
    };
    
    for (const auto& env : environments) {
        noise.setManualEnvironment(env.second);
        float noise_floor = noise.calculateNoiseFloor(gps_lat, gps_lon, test_freq);
        float s_meter = noise.dbmToSMeter(noise_floor);
        
        std::cout << std::left << std::setw(20) << env.first
                  << std::setw(10) << std::fixed << std::setprecision(1) << noise_floor << " dBm"
                  << std::setw(8) << "S" << std::setprecision(1) << s_meter
                  << std::setw(25) << noise.getNoiseDescription(noise_floor) << std::endl;
    }
    
    std::cout << std::endl;
    
    // Example 4: API usage patterns
    std::cout << "Example 4: API Usage Patterns" << std::endl;
    std::cout << "=============================" << std::endl;
    
    // Check if manual environment is set
    if (noise.isManualEnvironmentSet()) {
        std::cout << "Manual environment is set: " << (int)noise.getManualEnvironment() << std::endl;
    } else {
        std::cout << "Using automatic environment detection" << std::endl;
    }
    
    // Clear manual environment to return to auto-detection
    noise.clearManualEnvironment();
    std::cout << "Cleared manual environment - now using auto-detection" << std::endl;
    
    if (noise.isManualEnvironmentSet()) {
        std::cout << "Manual environment is still set" << std::endl;
    } else {
        std::cout << "Manual environment cleared - using auto-detection" << std::endl;
    }
    
    std::cout << std::endl;
    
    // Example 5: Practical use cases
    std::cout << "Example 5: Practical Use Cases" << std::endl;
    std::cout << "===============================" << std::endl;
    
    // Case 1: Sailboat in mid-ocean
    std::cout << "Case 1: Sailboat in mid-ocean" << std::endl;
    noise.setManualEnvironment("ocean");
    float ocean_noise = noise.calculateNoiseFloor(0.0, 0.0, 14.0f);  // Mid-Atlantic
    std::cout << "  Environment: Ocean" << std::endl;
    std::cout << "  Noise Floor: " << std::fixed << std::setprecision(1) << ocean_noise << " dBm" << std::endl;
    std::cout << "  S-Meter: S" << noise.dbmToSMeter(ocean_noise) << std::endl;
    std::cout << "  Quality: " << NoiseFloorUtils::assessNoiseFloorQuality(ocean_noise) << std::endl;
    std::cout << std::endl;
    
    // Case 2: Remote desert station
    std::cout << "Case 2: Remote desert station" << std::endl;
    noise.setManualEnvironment("desert");
    float desert_noise = noise.calculateNoiseFloor(25.0, 45.0, 14.0f);  // Arabian Desert
    std::cout << "  Environment: Desert" << std::endl;
    std::cout << "  Noise Floor: " << std::fixed << std::setprecision(1) << desert_noise << " dBm" << std::endl;
    std::cout << "  S-Meter: S" << noise.dbmToSMeter(desert_noise) << std::endl;
    std::cout << "  Quality: " << NoiseFloorUtils::assessNoiseFloorQuality(desert_noise) << std::endl;
    std::cout << std::endl;
    
    // Case 3: Polar research station
    std::cout << "Case 3: Polar research station" << std::endl;
    noise.setManualEnvironment("polar");
    float polar_noise = noise.calculateNoiseFloor(-80.0, 0.0, 14.0f);  // Antarctica
    std::cout << "  Environment: Polar" << std::endl;
    std::cout << "  Noise Floor: " << std::fixed << std::setprecision(1) << polar_noise << " dBm" << std::endl;
    std::cout << "  S-Meter: S" << noise.dbmToSMeter(polar_noise) << std::endl;
    std::cout << "  Quality: " << NoiseFloorUtils::assessNoiseFloorQuality(polar_noise) << std::endl;
    std::cout << std::endl;
    
    std::cout << "=== API Example Complete ===" << std::endl;
}

// REST API example functions
void demonstrateRESTAPI() {
    std::cout << "=== REST API Examples ===" << std::endl;
    std::cout << std::endl;
    
    std::cout << "1. Set manual environment via API:" << std::endl;
    std::cout << "POST /api/v1/noise/environment" << std::endl;
    std::cout << "Content-Type: application/json" << std::endl;
    std::cout << "{" << std::endl;
    std::cout << "  \"environment\": \"polar\"," << std::endl;
    std::cout << "  \"location\": \"JP88il\"," << std::endl;
    std::cout << "  \"frequency_mhz\": 14.0" << std::endl;
    std::cout << "}" << std::endl;
    std::cout << std::endl;
    
    std::cout << "2. Get noise floor with manual environment:" << std::endl;
    std::cout << "GET /api/v1/noise/floor?lat=40.7128&lon=-74.0060&freq=14.0&env=polar" << std::endl;
    std::cout << std::endl;
    
    std::cout << "3. Clear manual environment:" << std::endl;
    std::cout << "DELETE /api/v1/noise/environment" << std::endl;
    std::cout << std::endl;
    
    std::cout << "4. Get available environments:" << std::endl;
    std::cout << "GET /api/v1/noise/environments" << std::endl;
    std::cout << std::endl;
}

int main() {
    try {
        demonstrateManualEnvironmentAPI();
        std::cout << std::endl;
        demonstrateRESTAPI();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
