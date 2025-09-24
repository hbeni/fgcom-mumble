#ifndef FGCOM_MAIDENHEAD_UTILS_H
#define FGCOM_MAIDENHEAD_UTILS_H

#include <string>
#include <utility>

// Maidenhead locator utility functions
namespace MaidenheadUtils {
    
    // Convert Maidenhead locator to approximate latitude/longitude
    std::pair<double, double> maidenheadToLatLon(const std::string& locator);
    
    // Convert latitude/longitude to Maidenhead locator
    std::string latLonToMaidenhead(double lat, double lon, int precision = 6);
    
    // Get grid square size for given precision
    double getGridSquareSizeKm(int precision);
    double getGridSquareSizeDegrees(int precision);
    
    // Get grid square center coordinates
    std::pair<double, double> getGridSquareCenter(const std::string& locator);
    
    // Get grid square bounds (north, south, east, west)
    struct GridBounds {
        double north;
        double south;
        double east;
        double west;
    };
    GridBounds getGridSquareBounds(const std::string& locator);
    
    // Determine dominant environment type for a grid square
    enum class EnvironmentType;
    EnvironmentType determineGridSquareEnvironment(const std::string& locator);
    
    // Get environment confidence (how certain we are about the environment type)
    float getEnvironmentConfidence(const std::string& locator, EnvironmentType env_type);
    
    // Check if grid square spans multiple environment types
    bool hasMixedEnvironment(const std::string& locator);
    
    // Get list of possible environment types in a grid square
    std::vector<EnvironmentType> getPossibleEnvironments(const std::string& locator);
    
    // Calculate average noise floor for a grid square
    float calculateGridSquareNoiseFloor(const std::string& locator, float freq_mhz);
    
    // Calculate noise floor with uncertainty bounds
    struct NoiseFloorResult {
        float average_noise_floor;
        float min_noise_floor;
        float max_noise_floor;
        float uncertainty_db;
        EnvironmentType dominant_environment;
        float confidence;
    };
    NoiseFloorResult calculateGridSquareNoiseFloorWithUncertainty(const std::string& locator, float freq_mhz);
    
    // Validate Maidenhead locator format
    bool isValidMaidenhead(const std::string& locator);
    
    // Get precision level from locator string
    int getMaidenheadPrecision(const std::string& locator);
    
    // Convert between different precision levels
    std::string changeMaidenheadPrecision(const std::string& locator, int new_precision);
    
    // Get neighboring grid squares
    std::vector<std::string> getNeighboringGridSquares(const std::string& locator);
    
    // Calculate distance between two Maidenhead locators
    double calculateMaidenheadDistance(const std::string& locator1, const std::string& locator2);
    
    // Get grid square statistics
    struct GridSquareStats {
        double area_km2;
        double lat_span_degrees;
        double lon_span_degrees;
        int precision_level;
        std::string parent_grid_square;  // Higher precision parent
    };
    GridSquareStats getGridSquareStats(const std::string& locator);
}

#endif // FGCOM_MAIDENHEAD_UTILS_H
