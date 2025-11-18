/*
 * Weather Data API for FGCom-mumble
 * Provides weather condition structures and utilities
 */

#ifndef WEATHER_DATA_H
#define WEATHER_DATA_H

#include <string>
#include <chrono>
#include <vector>

namespace FGComWeather {

// Weather condition data structure
struct WeatherConditions {
    std::string location;
    double latitude;
    double longitude;
    float temperature_celsius;
    float humidity_percent;
    float pressure_hpa;
    float wind_speed_ms;
    float wind_direction_deg;
    float visibility_km;
    std::string conditions;
    std::chrono::system_clock::time_point timestamp;
    
    WeatherConditions() : latitude(0.0), longitude(0.0), temperature_celsius(20.0f),
                         humidity_percent(50.0f), pressure_hpa(1013.25f), wind_speed_ms(0.0f),
                         wind_direction_deg(0.0f), visibility_km(10.0f) {
        timestamp = std::chrono::system_clock::now();
    }
};

// Weather data cache for performance
struct WeatherDataCache {
    std::vector<WeatherConditions> recent_conditions;
    std::chrono::system_clock::time_point last_update;
    bool is_valid;
    
    WeatherDataCache() : is_valid(false) {
        last_update = std::chrono::system_clock::now();
    }
};

// Weather data API functions
class WeatherDataAPI {
public:
    static WeatherConditions getCurrentConditions(const std::string& location);
    static std::vector<WeatherConditions> getWeatherHistory(const std::string& location, int hours);
    static std::vector<WeatherConditions> getWeatherForecast(const std::string& location, int hours);
    static bool submitWeatherData(const WeatherConditions& data);
    static bool submitWeatherDataBatch(const std::vector<WeatherConditions>& data);
    static bool updateWeatherData(const std::string& location, const WeatherConditions& data);
};

} // namespace FGComWeather

#endif // WEATHER_DATA_H
