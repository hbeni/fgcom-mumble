#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <thread>
#include <vector>
#include <chrono>
#include <memory>
#include <random>
#include <cmath>
#include <fstream>
#include <sstream>

// Include the radio propagation modules
#include "../../client/mumble-plugin/lib/terrain_elevation.h"
#include "../../client/mumble-plugin/lib/radio_model.h"
#include "../../client/mumble-plugin/lib/radio_model_api.h"
#include "../../client/mumble-plugin/lib/propagation_physics.h"
#include "../../client/mumble-plugin/lib/antenna_ground_system.h"
#include "../../client/mumble-plugin/lib/antenna_orientation_calculator.h"
#include "../../client/mumble-plugin/lib/pattern_interpolation.h"

// Test fixtures and utilities
class Radio_Propagation_Test : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize test coordinates
        tx_coord.latitude = 40.7128;   // New York
        tx_coord.longitude = -74.0060;
        tx_coord.altitude = 100.0;     // 100m altitude
        
        rx_coord.latitude = 40.7589;   // 5km away
        rx_coord.longitude = -73.9851;
        rx_coord.altitude = 50.0;      // 50m altitude
        
        // Initialize test parameters
        test_frequency_vhf = 118.0;    // VHF frequency
        test_frequency_uhf = 300.0;    // UHF frequency
        test_frequency_hf = 14.0;      // HF frequency
        test_power = 10.0;             // 10W power
    }
    
    void TearDown() override {
        // Clean up after each test
    }
    
    // Test coordinates
    struct Coordinate {
        double latitude;
        double longitude;
        double altitude;
        
        double calculateDistance(const Coordinate& other) const {
            // Haversine formula for distance calculation
            double lat1_rad = latitude * M_PI / 180.0;
            double lat2_rad = other.latitude * M_PI / 180.0;
            double delta_lat = (other.latitude - latitude) * M_PI / 180.0;
            double delta_lon = (other.longitude - longitude) * M_PI / 180.0;
            
            double a = std::sin(delta_lat/2) * std::sin(delta_lat/2) +
                      std::cos(lat1_rad) * std::cos(lat2_rad) *
                      std::sin(delta_lon/2) * std::sin(delta_lon/2);
            double c = 2 * std::atan2(std::sqrt(a), std::sqrt(1-a));
            
            return 6371.0 * c; // Earth radius in km
        }
    };
    
    Coordinate tx_coord, rx_coord;
    double test_frequency_vhf, test_frequency_uhf, test_frequency_hf;
    double test_power;
    
    // Helper functions for test data generation
    std::vector<Coordinate> generateTerrainProfile(const Coordinate& start, const Coordinate& end, int points) {
        std::vector<Coordinate> profile;
        profile.reserve(points);
        
        for (int i = 0; i < points; ++i) {
            double fraction = static_cast<double>(i) / (points - 1);
            Coordinate point;
            point.latitude = start.latitude + (end.latitude - start.latitude) * fraction;
            point.longitude = start.longitude + (end.longitude - start.longitude) * fraction;
            point.altitude = start.altitude + (end.altitude - start.altitude) * fraction;
            profile.push_back(point);
        }
        
        return profile;
    }
    
    std::vector<Coordinate> generateObstructedProfile(const Coordinate& start, const Coordinate& end, int points, double obstruction_height) {
        std::vector<Coordinate> profile = generateTerrainProfile(start, end, points);
        
        // Add obstruction in the middle
        int middle = points / 2;
        profile[middle].altitude = obstruction_height;
        
        return profile;
    }
    
    // Helper to measure execution time
    template<typename Func>
    auto measureTime(Func&& func) -> decltype(func()) {
        auto start = std::chrono::high_resolution_clock::now();
        auto result = func();
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        std::cout << "Execution time: " << duration.count() << " microseconds" << std::endl;
        return result;
    }
    
    // Helper to generate test weather conditions
    struct WeatherConditions {
        double temperature_c;
        double humidity_percent;
        double pressure_hpa;
        double precipitation_mmh;
        bool fog;
        bool snow;
    };
    
    WeatherConditions generateWeatherConditions() {
        WeatherConditions weather;
        weather.temperature_c = 20.0;
        weather.humidity_percent = 50.0;
        weather.pressure_hpa = 1013.25;
        weather.precipitation_mmh = 0.0;
        weather.fog = false;
        weather.snow = false;
        return weather;
    }
    
    WeatherConditions generateAdverseWeather() {
        WeatherConditions weather;
        weather.temperature_c = -10.0;
        weather.humidity_percent = 90.0;
        weather.pressure_hpa = 980.0;
        weather.precipitation_mmh = 25.0;
        weather.fog = true;
        weather.snow = true;
        return weather;
    }
};

// Test suite for line-of-sight calculations
class LineOfSightTest : public Radio_Propagation_Test {
protected:
    void SetUp() override {
        Radio_Propagation_Test::SetUp();
    }
};

// Test suite for frequency-dependent propagation
class FrequencyPropagationTest : public Radio_Propagation_Test {
protected:
    void SetUp() override {
        Radio_Propagation_Test::SetUp();
    }
};

// Test suite for antenna patterns
class AntennaPatternTest : public Radio_Propagation_Test {
protected:
    void SetUp() override {
        Radio_Propagation_Test::SetUp();
    }
};

// Test suite for environmental effects
class EnvironmentalEffectsTest : public Radio_Propagation_Test {
protected:
    void SetUp() override {
        Radio_Propagation_Test::SetUp();
    }
};

// Test suite for noise floor calculations
class NoiseFloorTest : public Radio_Propagation_Test {
protected:
    void SetUp() override {
        Radio_Propagation_Test::SetUp();
    }
};

