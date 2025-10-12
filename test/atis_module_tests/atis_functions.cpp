#include "atis_functions.h"

// Function implementations for ATIS module tests

std::string fetchWeatherData(const std::string& airport, const std::string& api_key) {
    // Suppress unused parameter warnings
    (void)airport;
    (void)api_key;
    
    // Mock weather data for testing
    return "WIND: 270/15KT, VIS: 10SM, CLR, TEMP: 22C, DEW: 18C, ALT: 29.92";
}

bool detectWeatherChange(const std::string& old_weather, const std::string& new_weather,
                        double wind_threshold, double temp_threshold, double pressure_threshold) {
    // Suppress unused parameter warnings
    (void)old_weather;
    (void)new_weather;
    (void)wind_threshold;
    (void)temp_threshold;
    (void)pressure_threshold;
    
    // Mock weather change detection
    return true;
}

std::string getATISLetter(const std::string& airport) {
    // Suppress unused parameter warning
    (void)airport;
    
    // Mock ATIS letter generation
    return "A";
}

std::string generateAutomaticATIS(const std::string& airport, const std::string& weather_data) {
    // Suppress unused parameter warnings
    (void)airport;
    (void)weather_data;
    
    // Mock ATIS generation
    return "KJFK ATIS INFORMATION A. WIND 270 AT 15. VISIBILITY 10. CLEAR. TEMPERATURE 22. DEW POINT 18. ALTIMETER 2992. LANDING AND DEPARTING RUNWAY 04L.";
}

bool shouldUpdateATIS(double wind_change, double temperature_change, double pressure_change,
                      double wind_threshold, double temp_threshold, double pressure_threshold) {
    // Check if any parameter exceeds threshold
    return (std::abs(wind_change) > wind_threshold) ||
           (std::abs(temperature_change) > temp_threshold) ||
           (std::abs(pressure_change) > pressure_threshold);
}

int calculateOptimalGPUsForATIS(int user_count) {
    // Calculate optimal GPU count based on user count
    if (user_count <= 20) return 1;
    if (user_count <= 50) return 2;
    if (user_count <= 100) return 3;
    if (user_count <= 150) return 4;
    return 5;
}
