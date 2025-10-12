#ifndef ATIS_FUNCTIONS_H
#define ATIS_FUNCTIONS_H

#include <string>

// Function declarations for ATIS module tests
std::string fetchWeatherData(const std::string& airport, const std::string& api_key);
bool detectWeatherChange(const std::string& old_weather, const std::string& new_weather,
                        double wind_threshold, double temp_threshold, double pressure_threshold);
std::string getATISLetter(const std::string& airport);
std::string generateAutomaticATIS(const std::string& airport, const std::string& weather_data);
bool shouldUpdateATIS(double wind_change, double temperature_change, double pressure_change,
                      double wind_threshold, double temp_threshold, double pressure_threshold);
int calculateOptimalGPUsForATIS(int user_count);

#endif // ATIS_FUNCTIONS_H
