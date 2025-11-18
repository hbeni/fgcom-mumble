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
#include <map>
#include <set>
#include <algorithm>
#include <numeric>
#include <filesystem>
#include "atis_functions.h"
#include "atis_test_classes.h"

// ATIS module test fixtures and utilities

// Test implementations start here
TEST_F(ATISWeatherIntegrationTest, WeatherDataFetching) {
    // Test weather data fetching from API
    for (const auto& airport : airports) {
        std::string weather_data = fetchWeatherData(airport, weather_api_key);
        EXPECT_FALSE(weather_data.empty()) << "Should fetch weather data for " << airport;
        
        // Validate weather data format
        EXPECT_TRUE(weather_data.find("wind") != std::string::npos) << "Should contain wind information";
        EXPECT_TRUE(weather_data.find("temperature") != std::string::npos) << "Should contain temperature";
        EXPECT_TRUE(weather_data.find("pressure") != std::string::npos) << "Should contain pressure";
    }
}

TEST_F(ATISWeatherIntegrationTest, WeatherChangeDetection) {
    // Test weather change detection
    std::string old_weather = "Wind 270 at 15 knots, visibility 10 miles";
    std::string new_weather = "Wind 280 at 18 knots, visibility 8 miles";
    
    bool significant_change = detectWeatherChange(old_weather, new_weather,
                                                 wind_threshold, temperature_threshold, pressure_threshold);
    EXPECT_TRUE(significant_change) << "Should detect significant weather change";
}

TEST_F(ATISWeatherIntegrationTest, ATISLetterSystem) {
    // Test ATIS letter generation
    std::string letter = getATISLetter("KJFK");
    EXPECT_FALSE(letter.empty()) << "Should generate ATIS letter";
    EXPECT_EQ(letter.length(), 1) << "ATIS letter should be single character";
    EXPECT_TRUE(std::isalpha(letter[0])) << "ATIS letter should be alphabetic";
}

TEST_F(ATISWeatherIntegrationTest, AutomaticATISGeneration) {
    // Test automatic ATIS generation
    std::string airport = "KJFK";
    std::string weather_data = "Wind 270 at 15 knots, visibility 10 miles, ceiling 2500 feet";
    
    std::string atis_content = generateAutomaticATIS(airport, weather_data);
    EXPECT_FALSE(atis_content.empty()) << "Should generate ATIS content";
    EXPECT_TRUE(atis_content.find(airport) != std::string::npos) << "Should contain airport code";
    EXPECT_TRUE(atis_content.find("wind") != std::string::npos) << "Should contain weather information";
}

TEST_F(ATISWeatherIntegrationTest, WeatherThresholds) {
    // Test weather threshold detection
    double wind_change = 5.0;
    double temperature_change = 2.0;
    double pressure_change = 0.5;
    
    EXPECT_FALSE(shouldUpdateATIS(wind_change, temperature_change, pressure_change,
                                 wind_threshold, temperature_threshold, pressure_threshold))
        << "Should not update ATIS for minor changes";
    
    wind_change = 15.0;
    temperature_change = 8.0;
    pressure_change = 2.0;
    
    EXPECT_TRUE(shouldUpdateATIS(wind_change, temperature_change, pressure_change,
                                wind_threshold, temperature_threshold, pressure_threshold))
        << "Should update ATIS for significant changes";
}

TEST_F(ATISWeatherIntegrationTest, NetworkGPUScalingIntegration) {
    // Test GPU scaling for ATIS generation
    int user_count = 100;
    int optimal_gpus = calculateOptimalGPUsForATIS(user_count);
    
    EXPECT_GE(optimal_gpus, 1) << "Should allocate at least 1 GPU for ATIS generation";
    EXPECT_LE(optimal_gpus, 8) << "Should not exceed maximum GPU allocation";
}

// Helper functions for ATIS weather integration tests
// Function implementations moved to atis_functions.cpp
