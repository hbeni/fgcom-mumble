#include "openinframap_data_source.h"
#include "../noise/atmospheric_noise.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cmath>
#include <curl/curl.h>
#include "json/json.hpp"
#include <filesystem>

// Static member initialization
std::unique_ptr<FGCom_OpenInfraMapDataSource> FGCom_OpenInfraMapDataSource::instance = nullptr;
std::mutex FGCom_OpenInfraMapDataSource::instance_mutex;

// Callback for libcurl write function
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* data) {
    size_t total_size = size * nmemb;
    data->append((char*)contents, total_size);
    return total_size;
}

FGCom_OpenInfraMapDataSource::FGCom_OpenInfraMapDataSource() {
    initializeDataSource();
}

FGCom_OpenInfraMapDataSource& FGCom_OpenInfraMapDataSource::getInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    if (!instance) {
        instance = std::make_unique<FGCom_OpenInfraMapDataSource>();
    }
    return *instance;
}

void FGCom_OpenInfraMapDataSource::destroyInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    instance.reset();
}

void FGCom_OpenInfraMapDataSource::initializeDataSource() {
    // Initialize libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    // Set default configuration
    config = OpenInfraMapConfig();
    
    // Create cache directory if it doesn't exist
    std::filesystem::create_directories(config.cache_directory);
    
    last_update = std::chrono::system_clock::now() - std::chrono::hours(25); // Force initial update
}

void FGCom_OpenInfraMapDataSource::setConfig(const OpenInfraMapConfig& new_config) {
    std::lock_guard<std::mutex> lock(config_mutex);
    config = new_config;
}

FGCom_OpenInfraMapDataSource::OpenInfraMapConfig FGCom_OpenInfraMapDataSource::getConfig() const {
    std::lock_guard<std::mutex> lock(config_mutex);
    return config;
}

void FGCom_OpenInfraMapDataSource::setOverpassAPIUrl(const std::string& url) {
    std::lock_guard<std::mutex> lock(config_mutex);
    config.overpass_api_url = url;
}

void FGCom_OpenInfraMapDataSource::setTimeout(int seconds) {
    std::lock_guard<std::mutex> lock(config_mutex);
    config.timeout_seconds = seconds;
}

void FGCom_OpenInfraMapDataSource::setUpdateInterval(float hours) {
    std::lock_guard<std::mutex> lock(config_mutex);
    config.update_interval_hours = hours;
}

void FGCom_OpenInfraMapDataSource::setSearchRadius(float radius_km) {
    std::lock_guard<std::mutex> lock(config_mutex);
    config.search_radius_km = radius_km;
}

void FGCom_OpenInfraMapDataSource::enableSubstationData(bool enable) {
    std::lock_guard<std::mutex> lock(config_mutex);
    config.enable_substation_data = enable;
}

void FGCom_OpenInfraMapDataSource::enablePowerStationData(bool enable) {
    std::lock_guard<std::mutex> lock(config_mutex);
    config.enable_power_station_data = enable;
}

void FGCom_OpenInfraMapDataSource::enableTransmissionLineData(bool enable) {
    std::lock_guard<std::mutex> lock(config_mutex);
    config.enable_transmission_line_data = enable;
}

void FGCom_OpenInfraMapDataSource::setCacheDirectory(const std::string& directory) {
    std::lock_guard<std::mutex> lock(config_mutex);
    config.cache_directory = directory;
    std::filesystem::create_directories(directory);
}

bool FGCom_OpenInfraMapDataSource::fetchSubstationData(double lat, double lon, float radius_km) {
    if (!config.enable_substation_data) {
        setLastError("Substation data fetching is disabled");
        return false;
    }
    
    std::string query = buildSubstationQuery(lat, lon, radius_km);
    std::string response;
    
    if (!makeOverpassAPICall(query, response)) {
        return false;
    }
    
    std::vector<Substation> substations;
    if (!parseSubstationData(response, substations)) {
        setLastError("Failed to parse substation data");
        return false;
    }
    
    // Update cached data
    {
        std::lock_guard<std::mutex> lock(data_mutex);
        cached_substations = substations;
    }
    
    // Trigger callback if set
    if (substation_update_callback) {
        substation_update_callback(substations);
    }
    
    last_update = std::chrono::system_clock::now();
    return true;
}

bool FGCom_OpenInfraMapDataSource::fetchPowerStationData(double lat, double lon, float radius_km) {
    if (!config.enable_power_station_data) {
        setLastError("Power station data fetching is disabled");
        return false;
    }
    
    std::string query = buildPowerStationQuery(lat, lon, radius_km);
    std::string response;
    
    if (!makeOverpassAPICall(query, response)) {
        return false;
    }
    
    std::vector<PowerStation> power_stations;
    if (!parsePowerStationData(response, power_stations)) {
        setLastError("Failed to parse power station data");
        return false;
    }
    
    // Update cached data
    {
        std::lock_guard<std::mutex> lock(data_mutex);
        cached_power_stations = power_stations;
    }
    
    // Trigger callback if set
    if (power_station_update_callback) {
        power_station_update_callback(power_stations);
    }
    
    last_update = std::chrono::system_clock::now();
    return true;
}

bool FGCom_OpenInfraMapDataSource::fetchTransmissionLineData(double lat, double lon, float radius_km) {
    if (!config.enable_transmission_line_data) {
        setLastError("Transmission line data fetching is disabled");
        return false;
    }
    
    std::string query = buildTransmissionLineQuery(lat, lon, radius_km);
    std::string response;
    
    if (!makeOverpassAPICall(query, response)) {
        return false;
    }
    
    std::vector<Substation> substations;
    if (!parseTransmissionLineData(response, substations)) {
        setLastError("Failed to parse transmission line data");
        return false;
    }
    
    // Update cached data
    {
        std::lock_guard<std::mutex> lock(data_mutex);
        cached_substations.insert(cached_substations.end(), substations.begin(), substations.end());
    }
    
    last_update = std::chrono::system_clock::now();
    return true;
}

bool FGCom_OpenInfraMapDataSource::fetchAllData(double lat, double lon, float radius_km) {
    bool success = true;
    
    if (config.enable_substation_data) {
        success &= fetchSubstationData(lat, lon, radius_km);
    }
    
    if (config.enable_power_station_data) {
        success &= fetchPowerStationData(lat, lon, radius_km);
    }
    
    if (config.enable_transmission_line_data) {
        success &= fetchTransmissionLineData(lat, lon, radius_km);
    }
    
    return success;
}

std::vector<Substation> FGCom_OpenInfraMapDataSource::getSubstations(double lat, double lon, float radius_km) {
    std::lock_guard<std::mutex> lock(data_mutex);
    std::vector<Substation> nearby_substations;
    
    for (const auto& substation : cached_substations) {
        float distance = calculateDistance(lat, lon, substation.latitude, substation.longitude);
        if (distance <= radius_km) {
            nearby_substations.push_back(substation);
        }
    }
    
    return nearby_substations;
}

std::vector<PowerStation> FGCom_OpenInfraMapDataSource::getPowerStations(double lat, double lon, float radius_km) {
    std::lock_guard<std::mutex> lock(data_mutex);
    std::vector<PowerStation> nearby_power_stations;
    
    for (const auto& station : cached_power_stations) {
        float distance = calculateDistance(lat, lon, station.latitude, station.longitude);
        if (distance <= radius_km) {
            nearby_power_stations.push_back(station);
        }
    }
    
    return nearby_power_stations;
}

std::vector<Substation> FGCom_OpenInfraMapDataSource::getAllSubstations() const {
    std::lock_guard<std::mutex> lock(data_mutex);
    return cached_substations;
}

std::vector<PowerStation> FGCom_OpenInfraMapDataSource::getAllPowerStations() const {
    std::lock_guard<std::mutex> lock(data_mutex);
    return cached_power_stations;
}

void FGCom_OpenInfraMapDataSource::clearCache() {
    std::lock_guard<std::mutex> lock(data_mutex);
    cached_substations.clear();
    cached_power_stations.clear();
}

void FGCom_OpenInfraMapDataSource::clearSubstationData() {
    std::lock_guard<std::mutex> lock(data_mutex);
    cached_substations.clear();
}

void FGCom_OpenInfraMapDataSource::clearPowerStationData() {
    std::lock_guard<std::mutex> lock(data_mutex);
    cached_power_stations.clear();
}

size_t FGCom_OpenInfraMapDataSource::getSubstationCount() const {
    std::lock_guard<std::mutex> lock(data_mutex);
    return cached_substations.size();
}

size_t FGCom_OpenInfraMapDataSource::getPowerStationCount() const {
    std::lock_guard<std::mutex> lock(data_mutex);
    return cached_power_stations.size();
}

bool FGCom_OpenInfraMapDataSource::isUpdateInProgress() const {
    return update_in_progress.load();
}

std::chrono::system_clock::time_point FGCom_OpenInfraMapDataSource::getLastUpdateTime() const {
    return last_update;
}

bool FGCom_OpenInfraMapDataSource::needsUpdate() const {
    auto now = std::chrono::system_clock::now();
    auto time_since_update = std::chrono::duration_cast<std::chrono::hours>(now - last_update);
    return time_since_update.count() >= config.update_interval_hours;
}

void FGCom_OpenInfraMapDataSource::forceUpdate(double lat, double lon, float radius_km) {
    if (update_in_progress.load()) {
        return; // Update already in progress
    }
    
    update_in_progress.store(true);
    
    try {
        fetchAllData(lat, lon, radius_km);
    } catch (...) {
        setLastError("Exception during forced update");
    }
    
    update_in_progress.store(false);
}

void FGCom_OpenInfraMapDataSource::setSubstationUpdateCallback(std::function<void(const std::vector<Substation>&)> callback) {
    substation_update_callback = callback;
}

void FGCom_OpenInfraMapDataSource::setPowerStationUpdateCallback(std::function<void(const std::vector<PowerStation>&)> callback) {
    power_station_update_callback = callback;
}

void FGCom_OpenInfraMapDataSource::clearCallbacks() {
    substation_update_callback = nullptr;
    power_station_update_callback = nullptr;
}

bool FGCom_OpenInfraMapDataSource::isDataAvailable() const {
    std::lock_guard<std::mutex> lock(data_mutex);
    return !cached_substations.empty() || !cached_power_stations.empty();
}

bool FGCom_OpenInfraMapDataSource::isSubstationDataAvailable() const {
    std::lock_guard<std::mutex> lock(data_mutex);
    return !cached_substations.empty();
}

bool FGCom_OpenInfraMapDataSource::isPowerStationDataAvailable() const {
    std::lock_guard<std::mutex> lock(data_mutex);
    return !cached_power_stations.empty();
}

std::string FGCom_OpenInfraMapDataSource::getStatusString() const {
    std::stringstream ss;
    ss << "OpenInfraMap Data Source Status:\n";
    ss << "  Substations: " << getSubstationCount() << "\n";
    ss << "  Power Stations: " << getPowerStationCount() << "\n";
    ss << "  Last Update: " << std::chrono::duration_cast<std::chrono::minutes>(
        std::chrono::system_clock::now() - last_update).count() << " minutes ago\n";
    ss << "  Update In Progress: " << (isUpdateInProgress() ? "Yes" : "No") << "\n";
    return ss.str();
}

std::string FGCom_OpenInfraMapDataSource::getLastError() const {
    std::lock_guard<std::mutex> lock(error_mutex);
    return last_error;
}

bool FGCom_OpenInfraMapDataSource::makeOverpassAPICall(const std::string& query, std::string& response) {
    CURL* curl;
    CURLcode res;
    
    curl = curl_easy_init();
    if (!curl) {
        setLastError("Failed to initialize libcurl");
        return false;
    }
    
    // Set up the request
    std::string encoded_query = urlEncode(query);
    std::string url = config.overpass_api_url + "?data=" + encoded_query;
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, config.user_agent.c_str());
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, config.timeout_seconds);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    
    // Perform the request
    res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        setLastError("libcurl error: " + std::string(curl_easy_strerror(res)));
        curl_easy_cleanup(curl);
        return false;
    }
    
    curl_easy_cleanup(curl);
    return true;
}

std::string FGCom_OpenInfraMapDataSource::buildSubstationQuery(double lat, double lon, float radius_km) {
    std::stringstream query;
    query << "[out:json];\n";
    query << "(\n";
    query << "  node[\"power\"=\"substation\"](around:" << (radius_km * 1000) << "," << lat << "," << lon << ");\n";
    query << "  way[\"power\"=\"substation\"](around:" << (radius_km * 1000) << "," << lat << "," << lon << ");\n";
    query << "  relation[\"power\"=\"substation\"](around:" << (radius_km * 1000) << "," << lat << "," << lon << ");\n";
    query << ");\n";
    query << "out body;\n";
    query << ">;\n";
    query << "out skel qt;\n";
    return query.str();
}

std::string FGCom_OpenInfraMapDataSource::buildPowerStationQuery(double lat, double lon, float radius_km) {
    std::stringstream query;
    query << "[out:json];\n";
    query << "(\n";
    query << "  node[\"power\"=\"plant\"](around:" << (radius_km * 1000) << "," << lat << "," << lon << ");\n";
    query << "  way[\"power\"=\"plant\"](around:" << (radius_km * 1000) << "," << lat << "," << lon << ");\n";
    query << "  relation[\"power\"=\"plant\"](around:" << (radius_km * 1000) << "," << lat << "," << lon << ");\n";
    query << ");\n";
    query << "out body;\n";
    query << ">;\n";
    query << "out skel qt;\n";
    return query.str();
}

std::string FGCom_OpenInfraMapDataSource::buildTransmissionLineQuery(double lat, double lon, float radius_km) {
    std::stringstream query;
    query << "[out:json];\n";
    query << "(\n";
    query << "  way[\"power\"=\"line\"](around:" << (radius_km * 1000) << "," << lat << "," << lon << ");\n";
    query << "  way[\"power\"=\"cable\"](around:" << (radius_km * 1000) << "," << lat << "," << lon << ");\n";
    query << ");\n";
    query << "out body;\n";
    query << ">;\n";
    query << "out skel qt;\n";
    return query.str();
}

bool FGCom_OpenInfraMapDataSource::parseSubstationData(const std::string& json_data, std::vector<Substation>& substations) {
    try {
        nlohmann::json root = nlohmann::json::parse(json_data);
        
        if (!root.contains("elements")) {
            setLastError("No elements found in JSON data");
            return false;
        }
        
        const auto& elements = root["elements"];
        if (!elements.is_array()) {
            setLastError("Elements is not an array");
            return false;
        }
        
        for (const auto& element : elements) {
            if (!element.contains("type") || !element.contains("lat") || !element.contains("lon")) {
                continue; // Skip invalid elements
            }
            
            Substation substation;
            substation.latitude = element["lat"].get<double>();
            substation.longitude = element["lon"].get<double>();
            
            // Parse tags
            if (element.contains("tags")) {
                const auto& tags = element["tags"];
                
                // Determine substation type
                if (tags.contains("substation")) {
                    std::string substation_type = tags["substation"].get<std::string>();
                    if (substation_type == "transmission") {
                        substation.substation_type = SubstationType::TRANSMISSION;
                    } else if (substation_type == "distribution") {
                        substation.substation_type = SubstationType::DISTRIBUTION;
                    } else if (substation_type == "switching") {
                        substation.substation_type = SubstationType::SWITCHING;
                    } else if (substation_type == "converter") {
                        substation.substation_type = SubstationType::CONVERTER;
                    } else {
                        substation.substation_type = SubstationType::DISTRIBUTION; // Default
                    }
                } else {
                    substation.substation_type = SubstationType::DISTRIBUTION; // Default
                }
                
                // Parse voltage
                if (tags.contains("voltage")) {
                    std::string voltage_str = tags["voltage"].get<std::string>();
                    // Extract numeric value from voltage string (e.g., "345 kV" -> 345)
                    std::string numeric_part = voltage_str.substr(0, voltage_str.find(' '));
                    substation.voltage_kv = std::stof(numeric_part);
                } else {
                    substation.voltage_kv = 12.0f; // Default distribution voltage
                }
                
                // Parse capacity
                if (tags.contains("capacity")) {
                    std::string capacity_str = tags["capacity"].get<std::string>();
                    substation.capacity_mva = std::stof(capacity_str);
                } else {
                    substation.capacity_mva = 50.0f; // Default capacity
                }
                
                // Parse fencing
                substation.is_fenced = tags.contains("barrier") && tags["barrier"].get<std::string>() == "fence";
                
                // Parse operator
                if (tags.contains("operator")) {
                    substation.operator_name = tags["operator"].get<std::string>();
                } else {
                    substation.operator_name = "Unknown";
                }
                
                // Parse name
                if (tags.contains("name")) {
                    substation.substation_id = tags["name"].get<std::string>();
                } else {
                    substation.substation_id = "substation_" + std::to_string(substations.size());
                }
            }
            
            substation.is_active = true;
            substation.noise_factor = 1.0f;
            substation.geometry_type = GeometryType::POINT;
            substation.last_updated = std::chrono::system_clock::now();
            
            substations.push_back(substation);
        }
        
        return true;
    } catch (const nlohmann::json::exception& e) {
        setLastError("Failed to parse JSON data: " + std::string(e.what()));
        return false;
    }
    
    return true;
}

bool FGCom_OpenInfraMapDataSource::parsePowerStationData(const std::string& json_data, std::vector<PowerStation>& power_stations) {
    try {
        nlohmann::json root = nlohmann::json::parse(json_data);
        
        if (!root.contains("elements")) {
            setLastError("No elements found in JSON data");
            return false;
        }
        
        const auto& elements = root["elements"];
        if (!elements.is_array()) {
            setLastError("Elements is not an array");
            return false;
        }
        
        for (const auto& element : elements) {
            if (!element.contains("type") || !element.contains("lat") || !element.contains("lon")) {
                continue; // Skip invalid elements
            }
            
            PowerStation station;
            station.latitude = element["lat"].get<double>();
            station.longitude = element["lon"].get<double>();
            
            // Parse tags
            if (element.contains("tags")) {
                const auto& tags = element["tags"];
            
                // Determine power station type
                if (tags.contains("plant:source")) {
                    std::string source = tags["plant:source"].get<std::string>();
                    if (source == "coal" || source == "gas" || source == "oil") {
                        station.station_type = PowerStationType::THERMAL;
                    } else if (source == "nuclear") {
                        station.station_type = PowerStationType::NUCLEAR;
                    } else if (source == "hydro") {
                        station.station_type = PowerStationType::HYDROELECTRIC;
                    } else if (source == "wind") {
                        station.station_type = PowerStationType::WIND;
                    } else if (source == "solar") {
                        station.station_type = PowerStationType::SOLAR;
                    } else if (source == "geothermal") {
                        station.station_type = PowerStationType::GEOTHERMAL;
                    } else if (source == "biomass") {
                        station.station_type = PowerStationType::BIOMASS;
                    } else {
                        station.station_type = PowerStationType::THERMAL; // Default
                    }
                } else {
                    station.station_type = PowerStationType::THERMAL; // Default
                }
                
                // Parse capacity
                if (tags.contains("plant:output:electricity")) {
                    std::string capacity_str = tags["plant:output:electricity"].get<std::string>();
                    station.capacity_mw = std::stof(capacity_str);
                } else {
                    station.capacity_mw = 100.0f; // Default capacity
                }
                
                // Only include stations with 2MW+ capacity
                if (station.capacity_mw < 2.0f) {
                    continue;
                }
                
                // Parse current output (if available)
                if (tags.contains("plant:output:electricity:current")) {
                    std::string output_str = tags["plant:output:electricity:current"].get<std::string>();
                    station.current_output_mw = std::stof(output_str);
                } else {
                    station.current_output_mw = station.capacity_mw * 0.8f; // Assume 80% output
                }
                
                // Parse fencing
                station.is_fenced = tags.contains("barrier") && tags["barrier"].get<std::string>() == "fence";
                
                // Parse operator
                if (tags.contains("operator")) {
                    station.operator_name = tags["operator"].get<std::string>();
                } else {
                    station.operator_name = "Unknown";
                }
                
                // Parse name
                if (tags.contains("name")) {
                    station.station_id = tags["name"].get<std::string>();
                } else {
                    station.station_id = "power_station_" + std::to_string(power_stations.size());
                }
            }
            
            station.is_active = true;
            station.noise_factor = 1.0f;
            station.geometry_type = GeometryType::POINT;
            station.last_updated = std::chrono::system_clock::now();
            
            power_stations.push_back(station);
        }
        
        return true;
    } catch (const nlohmann::json::exception& e) {
        setLastError("Failed to parse JSON data: " + std::string(e.what()));
        return false;
    }
}

bool FGCom_OpenInfraMapDataSource::parseTransmissionLineData(const std::string& json_data, std::vector<Substation>& substations) {
    // For now, transmission lines are treated as substations
    // This could be enhanced to create transmission line objects
    return parseSubstationData(json_data, substations);
}

float FGCom_OpenInfraMapDataSource::calculateDistance(double lat1, double lon1, double lat2, double lon2) {
    const double R = 6371.0; // Earth's radius in kilometers
    double dlat = (lat2 - lat1) * M_PI / 180.0;
    double dlon = (lon2 - lon1) * M_PI / 180.0;
    double a = sin(dlat/2) * sin(dlat/2) + cos(lat1 * M_PI / 180.0) * cos(lat2 * M_PI / 180.0) * sin(dlon/2) * sin(dlon/2);
    double c = 2 * atan2(sqrt(a), sqrt(1-a));
    return R * c;
}

std::string FGCom_OpenInfraMapDataSource::urlEncode(const std::string& str) {
    std::string encoded;
    for (char c : str) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            encoded += c;
        } else {
            encoded += '%' + std::to_string(static_cast<int>(c));
        }
    }
    return encoded;
}

bool FGCom_OpenInfraMapDataSource::saveToCache(const std::string& filename, const std::string& data) {
    if (!config.cache_data) {
        return false;
    }
    
    std::string filepath = config.cache_directory + "/" + filename;
    std::ofstream file(filepath);
    if (!file.is_open()) {
        return false;
    }
    
    file << data;
    file.close();
    return true;
}

bool FGCom_OpenInfraMapDataSource::loadFromCache(const std::string& filename, std::string& data) {
    if (!config.cache_data) {
        return false;
    }
    
    std::string filepath = config.cache_directory + "/" + filename;
    std::ifstream file(filepath);
    if (!file.is_open()) {
        return false;
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    data = buffer.str();
    file.close();
    return true;
}

bool FGCom_OpenInfraMapDataSource::isCacheValid(const std::string& filename) {
    if (!config.cache_data) {
        return false;
    }
    
    std::string filepath = config.cache_directory + "/" + filename;
    auto file_time = std::filesystem::last_write_time(filepath);
    auto now = std::chrono::system_clock::now();
    auto file_duration = std::chrono::duration_cast<std::chrono::hours>(
        now - std::chrono::time_point_cast<std::chrono::system_clock::duration>(
            file_time - std::filesystem::file_time_type::clock::now() + now));
    
    return file_duration.count() < config.update_interval_hours;
}

void FGCom_OpenInfraMapDataSource::setLastError(const std::string& error) {
    std::lock_guard<std::mutex> lock(error_mutex);
    last_error = error;
}
