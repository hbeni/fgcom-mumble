#include "atis_functions.h"

// Function implementations for ATIS module tests

std::string fetchWeatherData(const std::string& airport, const std::string& api_key) {
    // Suppress unused parameter warnings
    (void)airport;
    (void)api_key;
    
    // Mock weather data for testing - include all expected fields
    return "wind: 270/15KT, temperature: 22C, pressure: 29.92, visibility: 10SM, clear sky";
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
    (void)weather_data;
    
    // Mock ATIS generation - include airport and wind information
    return airport + " ATIS INFORMATION A. wind 270 AT 15. VISIBILITY 10. CLEAR. TEMPERATURE 22. DEW POINT 18. ALTIMETER 2992. LANDING AND DEPARTING RUNWAY 04L.";
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

// Additional ATIS functions for content tests
bool isValidAirportCode(const std::string& code) {
    // Check if airport code is valid (4 letters, uppercase)
    if (code.length() != 4) return false;
    
    for (char c : code) {
        if (!std::isalpha(c) || !std::isupper(c)) {
            return false;
        }
    }
    
    return true;
}

std::string generateWeatherInfo() {
    // Generate mock weather information
    return "Wind 270 at 15 knots, visibility 10 miles, clear sky, temperature 22 degrees, dew point 18 degrees, altimeter 29.92";
}

std::string generateRunwayInfo() {
    // Generate mock runway information
    return "Landing and departing runway 04L, wind calm, visibility good";
}

std::string generateATISContent(const std::string& airport_code, const std::string& weather_info, const std::string& runway_info) {
    // Generate complete ATIS content
    std::string atis_content = "This is " + airport_code + " ATIS information ";
    atis_content += getATISLetter(airport_code) + ". ";
    atis_content += weather_info + ". ";
    atis_content += runway_info + ". ";
    atis_content += "Advise you have information " + getATISLetter(airport_code) + ".";
    
    return atis_content;
}
