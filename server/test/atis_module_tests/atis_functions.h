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

// Additional ATIS functions for content tests
bool isValidAirportCode(const std::string& code);
std::string generateWeatherInfo();
std::string generateRunwayInfo();
std::string generateATISContent(const std::string& airport_code, const std::string& weather_info, const std::string& runway_info);

#endif // ATIS_FUNCTIONS_H
