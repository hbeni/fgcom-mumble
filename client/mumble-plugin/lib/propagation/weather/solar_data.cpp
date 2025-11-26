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

#include "solar_data.h"
#include "http/httplib.h"
#include "json/json.hpp"
#include "feature_toggles.h"
#include <iostream>
#include <sstream>
#include <cmath>
#include <ctime>

// NOAA API endpoints
const std::string FGCom_SolarDataProvider::NOAA_SFI_URL = "https://services.swpc.noaa.gov/json/solar-cycle/solar-cycle-25.json";
const std::string FGCom_SolarDataProvider::NOAA_KINDEX_URL = "https://services.swpc.noaa.gov/json/planetary_k_index_1m.json";
const std::string FGCom_SolarDataProvider::NOAA_AINDEX_URL = "https://services.swpc.noaa.gov/json/planetary_a_index.json";

FGCom_SolarDataProvider::FGCom_SolarDataProvider() 
    : noaa_api_url("https://services.swpc.noaa.gov/"),
      update_interval(std::chrono::minutes(15)),
      update_thread_running(false),
      data_available(false) {
    
    // Initialize with default conditions
    setFallbackConditions();
    last_update = std::chrono::system_clock::now();
}

FGCom_SolarDataProvider::~FGCom_SolarDataProvider() {
    stopBackgroundUpdates();
}

// Helper function to check feature toggles
bool FGCom_SolarDataProvider::isFeatureEnabled(const std::string& feature_name) {
    try {
        // TODO: Implement proper feature toggle integration
        // For now, we'll use a simple approach
        std::cout << "[SolarData] Feature toggle requested for: " << feature_name << " (defaulting to enabled)" << std::endl;
        return true; // Default to enabled for now
    } catch (const std::exception& e) {
        std::cout << "[SolarData] Feature toggle error for " << feature_name << ": " << e.what() << " (defaulting to enabled)" << std::endl;
        return true; // Default to enabled on error
    }
}

fgcom_solar_conditions FGCom_SolarDataProvider::getCurrentConditions() {
    std::lock_guard<std::mutex> lock(data_mutex);
    return current_conditions;
}

bool FGCom_SolarDataProvider::updateFromNOAA() {
    std::lock_guard<std::mutex> lock(data_mutex);
    
    // Check if external data sources are enabled
    if (!isFeatureEnabled("enable_external_solar_data_sources")) {
        return false;
    }
    
    // Check if game submission mode is enabled - if so, disable external fetching
    if (isFeatureEnabled("enable_solar_data_game_submission") && 
        !isFeatureEnabled("enable_solar_data_external_fetch")) {
        return false;
    }
    
    bool success = true;
    
    // Fetch solar flux index
    if (!fetchSolarFluxIndex()) {
        success = false;
    }
    
    // Fetch K-index
    if (!fetchKIndex()) {
        success = false;
    }
    
    // Fetch A-index
    if (!fetchAIndex()) {
        success = false;
    }
    
    if (success) {
        updateSolarCalculations();
        last_update = std::chrono::system_clock::now();
        data_available = true;
    } else {
        // Use fallback conditions if update fails
        setFallbackConditions();
    }
    
    return success;
}

void FGCom_SolarDataProvider::startBackgroundUpdates() {
    if (update_thread_running) {
        return; // Already running
    }
    
    update_thread_running = true;
    update_thread = std::thread(&FGCom_SolarDataProvider::backgroundUpdateLoop, this);
}

void FGCom_SolarDataProvider::stopBackgroundUpdates() {
    if (!update_thread_running) {
        return;
    }
    
    update_thread_running = false;
    if (update_thread.joinable()) {
        update_thread.join();
    }
}

double FGCom_SolarDataProvider::calculateSolarZenith(double lat, double lon, const std::chrono::system_clock::time_point& time) {
    (void)lon; // Suppress unused parameter warning
    // Convert time to UTC
    std::time_t time_t = std::chrono::system_clock::to_time_t(time);
    std::tm* utc_time = std::gmtime(&time_t);
    
    // Calculate day of year
    int day_of_year = getDayOfYear(time);
    
    // Calculate solar declination
    double declination = calculateSolarDeclination(day_of_year);
    
    // Calculate hour angle (simplified - assumes UTC)
    if (!utc_time) {
        return 0.0; // Return default value if time is invalid
    }
    double hour_angle = (utc_time->tm_hour + utc_time->tm_min / 60.0 + utc_time->tm_sec / 3600.0) * 15.0 - 180.0;
    
    // Convert to radians
    double lat_rad = lat * M_PI / 180.0;
    double decl_rad = declination * M_PI / 180.0;
    double hour_rad = hour_angle * M_PI / 180.0;
    
    // Calculate solar zenith angle
    double cos_zenith = sin(lat_rad) * sin(decl_rad) + cos(lat_rad) * cos(decl_rad) * cos(hour_rad);
    cos_zenith = std::max(-1.0, std::min(1.0, cos_zenith)); // Clamp to valid range
    
    double zenith = acos(cos_zenith) * 180.0 / M_PI;
    
    return zenith;
}

double FGCom_SolarDataProvider::calculateSolarDeclination(int day_of_year) {
    // Solar declination calculation (approximate)
    double declination = 23.45 * sin((284 + day_of_year) * 2 * M_PI / 365.0);
    return declination;
}

bool FGCom_SolarDataProvider::isDayTime(double lat, double lon, const std::chrono::system_clock::time_point& time) {
    double zenith = calculateSolarZenith(lat, lon, time);
    return zenith < 90.0; // Day if sun is above horizon
}

int FGCom_SolarDataProvider::getDayOfYear(const std::chrono::system_clock::time_point& time) {
    std::time_t time_t = std::chrono::system_clock::to_time_t(time);
    std::tm* utc_time = std::gmtime(&time_t);
    
    // Calculate day of year
    if (!utc_time) {
        return 1; // Return default day of year if time is invalid
    }
    int day_of_year = utc_time->tm_yday + 1;
    return day_of_year;
}

bool FGCom_SolarDataProvider::isDataValid() {
    auto now = std::chrono::system_clock::now();
    auto age = now - last_update;
    return data_available && (age < std::chrono::hours(24)); // Data valid for 24 hours
}

void FGCom_SolarDataProvider::setFallbackConditions() {
    current_conditions.sfi = 70.0;  // Quiet sun
    current_conditions.k_index = 2.0; // Quiet conditions
    current_conditions.a_index = 7.0; // Quiet conditions
    current_conditions.day_of_year = getDayOfYear(std::chrono::system_clock::now());
    current_conditions.solar_declination = calculateSolarDeclination(current_conditions.day_of_year);
    current_conditions.timestamp = std::chrono::system_clock::now();
}

float FGCom_SolarDataProvider::getSolarFluxEffect(float frequency_mhz) {
    (void)frequency_mhz; // Suppress unused parameter warning
    // Solar flux effect on HF propagation
    // Higher SFI generally improves HF propagation
    float sfi_factor = (current_conditions.sfi - 70.0) / 100.0; // Normalize around 70
    return 1.0 + (sfi_factor * 0.3); // Up to 30% improvement with high SFI
}

float FGCom_SolarDataProvider::getGeomagneticEffect(float k_index) {
    // Geomagnetic activity effect
    // Higher K-index degrades propagation
    if (k_index <= 2.0) return 1.0; // No effect
    if (k_index <= 4.0) return 0.9; // Slight degradation
    if (k_index <= 6.0) return 0.7; // Moderate degradation
    if (k_index <= 8.0) return 0.5; // Significant degradation
    return 0.3; // Severe degradation
}

float FGCom_SolarDataProvider::getDayNightEffect(double solar_zenith, float frequency_mhz) {
    // Day/night effect on HF propagation
    if (solar_zenith < 90.0) {
        // Daytime - D-layer absorption affects lower frequencies
        if (frequency_mhz < 10.0) return 0.5; // Heavy absorption
        if (frequency_mhz < 15.0) return 0.7; // Moderate absorption
        return 0.9; // Light absorption
    } else {
        // Nighttime - D-layer disappears, better propagation
        return 1.0;
    }
}

void FGCom_SolarDataProvider::backgroundUpdateLoop() {
    while (update_thread_running) {
        updateFromNOAA();
        
        // Sleep for update interval
        std::this_thread::sleep_for(update_interval);
    }
}

bool FGCom_SolarDataProvider::fetchSolarFluxIndex() {
    try {
        std::string response = makeHTTPRequest(NOAA_SFI_URL);
        if (response.empty()) return false;
        
        return parseSFIResponse(response);
    } catch (...) {
        return false;
    }
}

bool FGCom_SolarDataProvider::fetchKIndex() {
    try {
        std::string response = makeHTTPRequest(NOAA_KINDEX_URL);
        if (response.empty()) return false;
        
        return parseKIndexResponse(response);
    } catch (...) {
        return false;
    }
}

bool FGCom_SolarDataProvider::fetchAIndex() {
    try {
        std::string response = makeHTTPRequest(NOAA_AINDEX_URL);
        if (response.empty()) return false;
        
        return parseAIndexResponse(response);
    } catch (...) {
        return false;
    }
}

void FGCom_SolarDataProvider::updateSolarCalculations() {
    // Update solar calculations based on current time
    auto now = std::chrono::system_clock::now();
    current_conditions.day_of_year = getDayOfYear(now);
    current_conditions.solar_declination = calculateSolarDeclination(current_conditions.day_of_year);
}

std::string FGCom_SolarDataProvider::makeHTTPRequest(const std::string& url) {
    // Parse URL
    size_t protocol_pos = url.find("://");
    if (protocol_pos == std::string::npos) return "";
    
    std::string protocol = url.substr(0, protocol_pos);
    std::string host_path = url.substr(protocol_pos + 3);
    
    size_t path_pos = host_path.find('/');
    std::string host = (path_pos != std::string::npos) ? host_path.substr(0, path_pos) : host_path;
    std::string path = (path_pos != std::string::npos) ? host_path.substr(path_pos) : "/";
    
    // Make HTTP request
    httplib::Client client(host);
    client.set_connection_timeout(10, 0); // 10 seconds timeout
    client.set_read_timeout(10, 0);
    
    auto res = client.Get(path);
    if (res && res->status == 200) {
        return res->body;
    } else {
        std::cerr << "[SolarData] HTTP request failed: " << (res ? res->status : -1) << std::endl;
        return "";
    }
    
    return "";
}

bool FGCom_SolarDataProvider::parseSFIResponse(const std::string& json_data) {
    try {
        auto json = nlohmann::json::parse(json_data);
        
        // Extract latest SFI value
        if (json.contains("solar_flux") && json["solar_flux"].is_array()) {
            auto flux_array = json["solar_flux"];
            if (!flux_array.empty()) {
                auto latest = flux_array.back();
                if (latest.contains("flux")) {
                    current_conditions.sfi = latest["flux"];
                    return true;
                }
            }
        }
    } catch (...) {
        // JSON parsing failed
    }
    
    return false;
}

bool FGCom_SolarDataProvider::parseKIndexResponse(const std::string& json_data) {
    try {
        auto json = nlohmann::json::parse(json_data);
        
        // Extract latest K-index value
        if (json.is_array() && !json.empty()) {
            auto latest = json.back();
            if (latest.contains("kp")) {
                current_conditions.k_index = latest["kp"];
                return true;
            }
        }
    } catch (...) {
        // JSON parsing failed
    }
    
    return false;
}

bool FGCom_SolarDataProvider::parseAIndexResponse(const std::string& json_data) {
    try {
        auto json = nlohmann::json::parse(json_data);
        
        // Extract latest A-index value
        if (json.is_array() && !json.empty()) {
            auto latest = json.back();
            if (latest.contains("ap")) {
                current_conditions.a_index = latest["ap"];
                return true;
            }
        }
    } catch (...) {
        // JSON parsing failed
    }
    
    return false;
}

// Solar propagation effects calculator implementation
float FGCom_SolarPropagation::calculateSolarEffect(const fgcom_solar_conditions& conditions, 
                                                  float frequency_mhz, 
                                                  double distance_km,
                                                  double solar_zenith) {
    (void)distance_km; // Suppress unused parameter warning
    float effect = 1.0;
    
    // Solar flux effect
    float sfi_effect = (conditions.sfi - 70.0) / 100.0 * 0.3;
    effect *= (1.0 + sfi_effect);
    
    // Geomagnetic effect
    float geomag_effect = 1.0;
    if (conditions.k_index > 2.0) {
        geomag_effect = 1.0 - ((conditions.k_index - 2.0) / 7.0) * 0.7;
    }
    effect *= geomag_effect;
    
    // Day/night effect
    float daynight_effect = 1.0;
    if (solar_zenith < 90.0) { // Daytime
        if (frequency_mhz < 10.0) daynight_effect = 0.5;
        else if (frequency_mhz < 15.0) daynight_effect = 0.7;
        else daynight_effect = 0.9;
    }
    effect *= daynight_effect;
    
    return std::max(0.1f, std::min(2.0f, effect)); // Clamp to reasonable range
}

float FGCom_SolarPropagation::calculateMUF(const fgcom_solar_conditions& conditions, 
                                          double distance_km,
                                          double solar_zenith) {
    // Simplified MUF calculation
    float base_muf = 15.0; // Base MUF in MHz
    
    // Solar flux effect
    float sfi_factor = (conditions.sfi - 70.0) / 100.0;
    base_muf += sfi_factor * 10.0;
    
    // Distance effect
    base_muf += distance_km / 1000.0;
    
    // Solar zenith effect
    if (solar_zenith < 90.0) { // Daytime
        base_muf *= 1.5;
    }
    
    return std::max(5.0f, std::min(50.0f, base_muf));
}

float FGCom_SolarPropagation::calculateFOT(const fgcom_solar_conditions& conditions, 
                                          double distance_km) {
    // FOT is typically 85% of MUF
    return calculateMUF(conditions, distance_km, 0.0) * 0.85;
}

float FGCom_SolarPropagation::calculateLUF(const fgcom_solar_conditions& conditions, 
                                          double distance_km,
                                          double solar_zenith) {
    (void)distance_km; // Suppress unused parameter warning
    // LUF calculation (simplified)
    float base_luf = 3.0; // Base LUF in MHz
    
    // Geomagnetic effect
    if (conditions.k_index > 4.0) {
        base_luf += (conditions.k_index - 4.0) * 2.0;
    }
    
    // Solar zenith effect
    if (solar_zenith < 90.0) { // Daytime
        base_luf += 5.0; // Higher LUF during day
    }
    
    return std::max(1.0f, std::min(20.0f, base_luf));
}

float FGCom_SolarPropagation::calculateAbsorption(const fgcom_solar_conditions& conditions, 
                                                 float frequency_mhz,
                                                 double solar_zenith) {
    // D-layer absorption calculation
    if (solar_zenith >= 90.0) return 0.0; // No absorption at night
    
    // Daytime absorption
    float absorption = 0.0;
    if (frequency_mhz < 10.0) {
        absorption = 0.8; // Heavy absorption
    } else if (frequency_mhz < 15.0) {
        absorption = 0.5; // Moderate absorption
    } else if (frequency_mhz < 20.0) {
        absorption = 0.2; // Light absorption
    }
    
    // Solar flux effect on absorption
    float sfi_factor = (conditions.sfi - 70.0) / 100.0;
    absorption *= (1.0 + sfi_factor * 0.5);
    
    return std::min(1.0f, absorption);
}

float FGCom_SolarPropagation::calculateSkipZone(const fgcom_solar_conditions& conditions, 
                                               float frequency_mhz,
                                               double distance_km) {
    // Skip zone calculation
    float muf = calculateMUF(conditions, distance_km, 0.0);
    
    if (frequency_mhz > muf) {
        return 0.0; // No skip zone if frequency is above MUF
    }
    
    // Calculate skip zone radius (simplified)
    float skip_radius = 200.0; // Base skip radius in km
    
    // Solar flux effect
    float sfi_factor = (conditions.sfi - 70.0) / 100.0;
    skip_radius *= (1.0 + sfi_factor * 0.5);
    
    return skip_radius;
}
