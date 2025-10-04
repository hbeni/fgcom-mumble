/*
 * Noise Floor API for FGCom-mumble
 * Provides noise floor calculation and management structures
 */

#ifndef NOISE_FLOOR_H
#define NOISE_FLOOR_H

#include <string>
#include <chrono>
#include <vector>
#include <map>

namespace FGComNoiseFloor {

// Noise floor measurement data structure
struct NoiseFloorMeasurement {
    double latitude;
    double longitude;
    float frequency_mhz;
    float noise_floor_db;
    std::string measurement_type; // "atmospheric", "man_made", "thermal", "galactic"
    std::chrono::system_clock::time_point timestamp;
    bool is_valid;
    
    NoiseFloorMeasurement() : latitude(0.0), longitude(0.0), frequency_mhz(0.0f), 
                             noise_floor_db(0.0f), measurement_type("atmospheric"), is_valid(false) {
        timestamp = std::chrono::system_clock::now();
    }
};

// Noise floor cache for performance
struct NoiseFloorCache {
    std::map<std::string, NoiseFloorMeasurement> measurements;
    std::chrono::system_clock::time_point last_update;
    bool is_valid;
    
    NoiseFloorCache() : is_valid(false) {
        last_update = std::chrono::system_clock::now();
    }
};

// Noise floor calculation utilities
class NoiseFloorCalculator {
public:
    static float calculateAtmosphericNoise(float frequency_mhz, float latitude, float longitude);
    static float calculateManMadeNoise(float frequency_mhz, float latitude, float longitude);
    static float calculateThermalNoise(float frequency_mhz, float temperature_k);
    static float calculateGalacticNoise(float frequency_mhz, float latitude, float longitude);
    static float calculateTotalNoiseFloor(float frequency_mhz, float latitude, float longitude);
};

// Noise floor data API functions
class NoiseFloorAPI {
public:
    static NoiseFloorMeasurement getCurrentNoiseFloor(double lat, double lon, float frequency_mhz);
    static std::vector<NoiseFloorMeasurement> getNoiseFloorHistory(double lat, double lon, int hours);
    static bool submitNoiseFloorData(const NoiseFloorMeasurement& measurement);
    static bool submitNoiseFloorDataBatch(const std::vector<NoiseFloorMeasurement>& measurements);
    static bool updateNoiseFloorData(const std::string& measurement_id, const NoiseFloorMeasurement& measurement);
};

} // namespace FGComNoiseFloor

#endif // NOISE_FLOOR_H







