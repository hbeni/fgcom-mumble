/* 
 * This file is part of the FGCom-mumble distribution (https://github.com/hbeni/fgcom-mumble).
 * Copyright (c) 2020 Benedikt Hallinger
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef FGCOM_SOLAR_DATA_H
#define FGCOM_SOLAR_DATA_H

#include <string>
#include <chrono>
#include <mutex>
#include <thread>
#include <atomic>

// Solar conditions data structure
struct fgcom_solar_conditions {
    float sfi;                  // Solar Flux Index (10.7cm)
    float k_index;              // Geomagnetic K-index (0-9)
    float a_index;              // Planetary A-index
    double solar_zenith;        // Solar zenith angle (degrees)
    bool is_day;                // Day/night flag
    int day_of_year;            // Day of year (1-366)
    double solar_declination;   // Solar declination angle
    std::chrono::system_clock::time_point timestamp;
    
    fgcom_solar_conditions() {
        sfi = 70.0;             // Default quiet sun value
        k_index = 2.0;          // Default quiet conditions
        a_index = 7.0;          // Default quiet conditions
        solar_zenith = 90.0;    // Default to horizon
        is_day = false;         // Default to night
        day_of_year = 1;
        solar_declination = 0.0;
        timestamp = std::chrono::system_clock::now();
    }
};

// Solar data provider class
class FGCom_SolarDataProvider {
private:
    std::string noaa_api_url;
    std::chrono::system_clock::time_point last_update;
    std::chrono::minutes update_interval;
    std::mutex data_mutex;
    std::atomic<bool> update_thread_running;
    std::thread update_thread;
    
    fgcom_solar_conditions current_conditions;
    bool data_available;
    
    // NOAA API endpoints
    static const std::string NOAA_SFI_URL;
    static const std::string NOAA_KINDEX_URL;
    static const std::string NOAA_AINDEX_URL;
    
public:
    FGCom_SolarDataProvider();
    ~FGCom_SolarDataProvider();
    
    // Main interface methods
    fgcom_solar_conditions getCurrentConditions();
    bool updateFromNOAA();
    void startBackgroundUpdates();
    void stopBackgroundUpdates();
    
    // Solar calculations
    double calculateSolarZenith(double lat, double lon, const std::chrono::system_clock::time_point& time);
    double calculateSolarDeclination(int day_of_year);
    bool isDayTime(double lat, double lon, const std::chrono::system_clock::time_point& time);
    int getDayOfYear(const std::chrono::system_clock::time_point& time);
    
    // Data validation and fallback
    bool isDataValid();
    void setFallbackConditions();
    
    // Feature toggle helper
    bool isFeatureEnabled(const std::string& feature_name);
    
    // Propagation effects
    float getSolarFluxEffect(float frequency_mhz);
    float getGeomagneticEffect(float k_index);
    float getDayNightEffect(double solar_zenith, float frequency_mhz);
    
private:
    // Internal methods
    void backgroundUpdateLoop();
    bool fetchSolarFluxIndex();
    bool fetchKIndex();
    bool fetchAIndex();
    void updateSolarCalculations();
    
    // HTTP and JSON parsing helpers
    std::string makeHTTPRequest(const std::string& url);
    bool parseSFIResponse(const std::string& json_data);
    bool parseKIndexResponse(const std::string& json_data);
    bool parseAIndexResponse(const std::string& json_data);
};

// Solar propagation effects calculator
class FGCom_SolarPropagation {
public:
    // Calculate solar effects on HF propagation
    static float calculateSolarEffect(const fgcom_solar_conditions& conditions, 
                                    float frequency_mhz, 
                                    double distance_km,
                                    double solar_zenith);
    
    // Calculate MUF (Maximum Usable Frequency) based on solar conditions
    static float calculateMUF(const fgcom_solar_conditions& conditions, 
                            double distance_km,
                            double solar_zenith);
    
    // Calculate FOT (Frequency of Optimum Transmission)
    static float calculateFOT(const fgcom_solar_conditions& conditions, 
                            double distance_km);
    
    // Calculate LUF (Lowest Usable Frequency)
    static float calculateLUF(const fgcom_solar_conditions& conditions, 
                            double distance_km,
                            double solar_zenith);
    
    // Calculate absorption effects
    static float calculateAbsorption(const fgcom_solar_conditions& conditions, 
                                   float frequency_mhz,
                                   double solar_zenith);
    
    // Calculate skip zone effects
    static float calculateSkipZone(const fgcom_solar_conditions& conditions, 
                                 float frequency_mhz,
                                 double distance_km);
};

#endif // FGCOM_SOLAR_DATA_H
