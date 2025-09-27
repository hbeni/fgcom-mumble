#include "stationary_station.h"
#include "advanced_modulation.h"
#include <algorithm>
#include <cmath>
#include <iostream>
#include <fstream>
#include <sstream>

// Static member initialization
bool FGCom_StationaryStationManager::initialized = false;
std::map<std::string, StationaryStationConfig> FGCom_StationaryStationManager::stations;
std::map<StationaryStationType, std::vector<std::string>> FGCom_StationaryStationManager::supported_modes;

bool FGCom_StationaryStationManager::initialize() {
    if (initialized) return true;
    
    // Initialize supported modes for each station type
    supported_modes[StationaryStationType::GROUND_BASED] = {
        "SSB", "CW", "AM", "FM", "DSB", "ISB", "VSB", "NFM"
    };
    
    supported_modes[StationaryStationType::COASTAL] = {
        "SSB", "CW", "AM", "DSB", "ISB", "VSB"
    };
    
    supported_modes[StationaryStationType::MARITIME_HF] = {
        "SSB", "CW", "AM", "DSB", "ISB", "VSB"
    };
    
    supported_modes[StationaryStationType::EMERGENCY] = {
        "SSB", "CW", "AM", "FM", "NFM", "DSB", "ISB", "VSB"
    };
    
    supported_modes[StationaryStationType::WEATHER] = {
        "SSB", "CW", "AM", "FM", "NFM"
    };
    
    supported_modes[StationaryStationType::NAVIGATION] = {
        "CW", "AM", "FM", "NFM"
    };
    
    supported_modes[StationaryStationType::MILITARY] = {
        "SSB", "CW", "AM", "FM", "NFM", "DSB", "ISB", "VSB"
    };
    
    supported_modes[StationaryStationType::AMATEUR] = {
        "SSB", "CW", "AM", "FM", "NFM", "DSB", "ISB", "VSB"
    };
    
    // Initialize advanced modulation system
    FGCom_AdvancedModulation::initialize();
    
    initialized = true;
    return true;
}

// Station management
bool FGCom_StationaryStationManager::addStation(const StationaryStationConfig& config) {
    if (!initialized) initialize();
    
    // Validate station configuration
    if (config.station_id.empty()) {
        return false;
    }
    
    // Check if station already exists
    if (stations.find(config.station_id) != stations.end()) {
        return false;
    }
    
    // Validate modulation mode for station type
    if (!validateModulationMode(config.modulation_mode, config.station_type)) {
        return false;
    }
    
    stations[config.station_id] = config;
    return true;
}

bool FGCom_StationaryStationManager::removeStation(const std::string& station_id) {
    if (!initialized) initialize();
    
    auto it = stations.find(station_id);
    if (it != stations.end()) {
        stations.erase(it);
        return true;
    }
    
    return false;
}

bool FGCom_StationaryStationManager::updateStation(const std::string& station_id, const StationaryStationConfig& config) {
    if (!initialized) initialize();
    
    auto it = stations.find(station_id);
    if (it != stations.end()) {
        // Validate modulation mode for station type
        if (!validateModulationMode(config.modulation_mode, config.station_type)) {
            return false;
        }
        
        it->second = config;
        return true;
    }
    
    return false;
}

StationaryStationConfig FGCom_StationaryStationManager::getStation(const std::string& station_id) {
    if (!initialized) initialize();
    
    auto it = stations.find(station_id);
    if (it != stations.end()) {
        return it->second;
    }
    
    return StationaryStationConfig(); // Return default config
}

std::vector<std::string> FGCom_StationaryStationManager::getAllStationIds() {
    if (!initialized) initialize();
    
    std::vector<std::string> ids;
    for (const auto& pair : stations) {
        ids.push_back(pair.first);
    }
    
    return ids;
}

std::vector<StationaryStationConfig> FGCom_StationaryStationManager::getStationsByType(StationaryStationType type) {
    if (!initialized) initialize();
    
    std::vector<StationaryStationConfig> result;
    for (const auto& pair : stations) {
        if (pair.second.station_type == type) {
            result.push_back(pair.second);
        }
    }
    
    return result;
}

// Modulation mode support
bool FGCom_StationaryStationManager::setStationModulationMode(const std::string& station_id, const std::string& mode) {
    if (!initialized) initialize();
    
    auto it = stations.find(station_id);
    if (it != stations.end()) {
        if (validateModulationMode(mode, it->second.station_type)) {
            it->second.modulation_mode = mode;
            return true;
        }
    }
    
    return false;
}

std::string FGCom_StationaryStationManager::getStationModulationMode(const std::string& station_id) {
    if (!initialized) initialize();
    
    auto it = stations.find(station_id);
    if (it != stations.end()) {
        return it->second.modulation_mode;
    }
    
    return "";
}

std::vector<std::string> FGCom_StationaryStationManager::getSupportedModesForStation(const std::string& station_id) {
    if (!initialized) initialize();
    
    auto it = stations.find(station_id);
    if (it != stations.end()) {
        return getSupportedModesForType(it->second.station_type);
    }
    
    return {};
}

std::vector<std::string> FGCom_StationaryStationManager::getSupportedModesForType(StationaryStationType type) {
    if (!initialized) initialize();
    
    auto it = supported_modes.find(type);
    if (it != supported_modes.end()) {
        return it->second;
    }
    
    return {};
}

bool FGCom_StationaryStationManager::validateModulationMode(const std::string& mode, StationaryStationType type) {
    if (!initialized) initialize();
    
    auto it = supported_modes.find(type);
    if (it != supported_modes.end()) {
        return std::find(it->second.begin(), it->second.end(), mode) != it->second.end();
    }
    
    return false;
}

// Advanced modulation support
bool FGCom_StationaryStationManager::supportsAdvancedModulation(const std::string& station_id) {
    if (!initialized) initialize();
    
    auto it = stations.find(station_id);
    if (it != stations.end()) {
        return supportsAdvancedModulation(it->second.station_type);
    }
    
    return false;
}

bool FGCom_StationaryStationManager::supportsAdvancedModulation(StationaryStationType type) {
    if (!initialized) initialize();
    
    auto it = supported_modes.find(type);
    if (it != supported_modes.end()) {
        const auto& modes = it->second;
        return std::find(modes.begin(), modes.end(), "DSB") != modes.end() ||
               std::find(modes.begin(), modes.end(), "ISB") != modes.end() ||
               std::find(modes.begin(), modes.end(), "VSB") != modes.end() ||
               std::find(modes.begin(), modes.end(), "NFM") != modes.end();
    }
    
    return false;
}

std::vector<std::string> FGCom_StationaryStationManager::getAdvancedModulationModes(const std::string& station_id) {
    if (!initialized) initialize();
    
    auto it = stations.find(station_id);
    if (it != stations.end()) {
        return getAdvancedModulationModes(it->second.station_type);
    }
    
    return {};
}

std::vector<std::string> FGCom_StationaryStationManager::getAdvancedModulationModes(StationaryStationType type) {
    if (!initialized) initialize();
    
    std::vector<std::string> advanced_modes;
    auto it = supported_modes.find(type);
    if (it != supported_modes.end()) {
        const auto& modes = it->second;
        for (const std::string& mode : {"DSB", "ISB", "VSB", "NFM"}) {
            if (std::find(modes.begin(), modes.end(), mode) != modes.end()) {
                advanced_modes.push_back(mode);
            }
        }
    }
    
    return advanced_modes;
}

// Station capabilities
bool FGCom_StationaryStationManager::isEmergencyStation(const std::string& station_id) {
    auto it = stations.find(station_id);
    if (it != stations.end()) {
        return it->second.station_type == StationaryStationType::EMERGENCY ||
               it->second.emergency_capable;
    }
    
    return false;
}

bool FGCom_StationaryStationManager::isWeatherStation(const std::string& station_id) {
    auto it = stations.find(station_id);
    if (it != stations.end()) {
        return it->second.station_type == StationaryStationType::WEATHER;
    }
    
    return false;
}

bool FGCom_StationaryStationManager::isNavigationStation(const std::string& station_id) {
    auto it = stations.find(station_id);
    if (it != stations.end()) {
        return it->second.station_type == StationaryStationType::NAVIGATION;
    }
    
    return false;
}

bool FGCom_StationaryStationManager::isMaritimeStation(const std::string& station_id) {
    auto it = stations.find(station_id);
    if (it != stations.end()) {
        return it->second.station_type == StationaryStationType::COASTAL ||
               it->second.station_type == StationaryStationType::MARITIME_HF;
    }
    
    return false;
}

bool FGCom_StationaryStationManager::isMilitaryStation(const std::string& station_id) {
    auto it = stations.find(station_id);
    if (it != stations.end()) {
        return it->second.station_type == StationaryStationType::MILITARY;
    }
    
    return false;
}

// Frequency and power management
bool FGCom_StationaryStationManager::setStationFrequency(const std::string& station_id, double frequency_khz) {
    if (!initialized) initialize();
    
    auto it = stations.find(station_id);
    if (it != stations.end()) {
        it->second.frequency_khz = frequency_khz;
        return true;
    }
    
    return false;
}

double FGCom_StationaryStationManager::getStationFrequency(const std::string& station_id) {
    if (!initialized) initialize();
    
    auto it = stations.find(station_id);
    if (it != stations.end()) {
        return it->second.frequency_khz;
    }
    
    return 0.0;
}

bool FGCom_StationaryStationManager::setStationPower(const std::string& station_id, double power_watts) {
    if (!initialized) initialize();
    
    auto it = stations.find(station_id);
    if (it != stations.end()) {
        it->second.power_watts = power_watts;
        return true;
    }
    
    return false;
}

double FGCom_StationaryStationManager::getStationPower(const std::string& station_id) {
    if (!initialized) initialize();
    
    auto it = stations.find(station_id);
    if (it != stations.end()) {
        return it->second.power_watts;
    }
    
    return 0.0;
}

// Antenna management
bool FGCom_StationaryStationManager::setStationAntenna(const std::string& station_id, const std::string& antenna_type) {
    if (!initialized) initialize();
    
    auto it = stations.find(station_id);
    if (it != stations.end()) {
        it->second.antenna_type = antenna_type;
        return true;
    }
    
    return false;
}

std::string FGCom_StationaryStationManager::getStationAntenna(const std::string& station_id) {
    if (!initialized) initialize();
    
    auto it = stations.find(station_id);
    if (it != stations.end()) {
        return it->second.antenna_type;
    }
    
    return "";
}

bool FGCom_StationaryStationManager::setStationAntennaHeight(const std::string& station_id, double height_m) {
    if (!initialized) initialize();
    
    auto it = stations.find(station_id);
    if (it != stations.end()) {
        it->second.antenna_height_m = height_m;
        return true;
    }
    
    return false;
}

double FGCom_StationaryStationManager::getStationAntennaHeight(const std::string& station_id) {
    if (!initialized) initialize();
    
    auto it = stations.find(station_id);
    if (it != stations.end()) {
        return it->second.antenna_height_m;
    }
    
    return 0.0;
}

// Ground system management
bool FGCom_StationaryStationManager::setStationGroundType(const std::string& station_id, const std::string& ground_type) {
    if (!initialized) initialize();
    
    auto it = stations.find(station_id);
    if (it != stations.end()) {
        it->second.ground_type = ground_type;
        return true;
    }
    
    return false;
}

std::string FGCom_StationaryStationManager::getStationGroundType(const std::string& station_id) {
    if (!initialized) initialize();
    
    auto it = stations.find(station_id);
    if (it != stations.end()) {
        return it->second.ground_type;
    }
    
    return "";
}

// Station status and diagnostics
std::map<std::string, std::string> FGCom_StationaryStationManager::getStationStatus(const std::string& station_id) {
    if (!initialized) initialize();
    
    std::map<std::string, std::string> status;
    
    auto it = stations.find(station_id);
    if (it != stations.end()) {
        const auto& config = it->second;
        status["station_id"] = config.station_id;
        status["station_name"] = config.station_name;
        status["station_type"] = std::to_string(static_cast<int>(config.station_type));
        status["latitude"] = std::to_string(config.latitude);
        status["longitude"] = std::to_string(config.longitude);
        status["altitude_m"] = std::to_string(config.altitude_m);
        status["antenna_type"] = config.antenna_type;
        status["antenna_height_m"] = std::to_string(config.antenna_height_m);
        status["power_watts"] = std::to_string(config.power_watts);
        status["modulation_mode"] = config.modulation_mode;
        status["frequency_khz"] = std::to_string(config.frequency_khz);
        status["ground_type"] = config.ground_type;
        status["emergency_capable"] = config.emergency_capable ? "true" : "false";
        status["weather_resistant"] = config.weather_resistant ? "true" : "false";
        status["notes"] = config.notes;
    }
    
    return status;
}

std::map<std::string, std::string> FGCom_StationaryStationManager::getSystemStatus() {
    if (!initialized) initialize();
    
    std::map<std::string, std::string> status;
    status["initialized"] = "true";
    status["total_stations"] = std::to_string(stations.size());
    status["supported_modes"] = "SSB,CW,AM,FM,DSB,ISB,VSB,NFM";
    status["advanced_modulation"] = "enabled";
    
    return status;
}

std::vector<std::string> FGCom_StationaryStationManager::getStationDiagnostics(const std::string& station_id) {
    if (!initialized) initialize();
    
    std::vector<std::string> diagnostics;
    
    auto it = stations.find(station_id);
    if (it != stations.end()) {
        const auto& config = it->second;
        
        diagnostics.push_back("Station ID: " + config.station_id);
        diagnostics.push_back("Station Name: " + config.station_name);
        diagnostics.push_back("Station Type: " + std::to_string(static_cast<int>(config.station_type)));
        diagnostics.push_back("Location: " + std::to_string(config.latitude) + ", " + std::to_string(config.longitude));
        diagnostics.push_back("Altitude: " + std::to_string(config.altitude_m) + "m");
        diagnostics.push_back("Antenna: " + config.antenna_type + " at " + std::to_string(config.antenna_height_m) + "m");
        diagnostics.push_back("Power: " + std::to_string(config.power_watts) + "W");
        diagnostics.push_back("Modulation: " + config.modulation_mode);
        diagnostics.push_back("Frequency: " + std::to_string(config.frequency_khz) + "kHz");
        diagnostics.push_back("Ground: " + config.ground_type);
        diagnostics.push_back("Emergency Capable: " + (config.emergency_capable ? "Yes" : "No"));
        diagnostics.push_back("Weather Resistant: " + (config.weather_resistant ? "Yes" : "No"));
        
        if (!config.notes.empty()) {
            diagnostics.push_back("Notes: " + config.notes);
        }
    }
    
    return diagnostics;
}

// Search and filtering
std::vector<std::string> FGCom_StationaryStationManager::findStationsByLocation(double latitude, double longitude, double radius_km) {
    if (!initialized) initialize();
    
    std::vector<std::string> result;
    
    for (const auto& pair : stations) {
        const auto& config = pair.second;
        
        // Calculate distance using Haversine formula
        double lat1_rad = latitude * M_PI / 180.0;
        double lon1_rad = longitude * M_PI / 180.0;
        double lat2_rad = config.latitude * M_PI / 180.0;
        double lon2_rad = config.longitude * M_PI / 180.0;
        
        double dlat = lat2_rad - lat1_rad;
        double dlon = lon2_rad - lon1_rad;
        
        double a = sin(dlat/2) * sin(dlat/2) + cos(lat1_rad) * cos(lat2_rad) * sin(dlon/2) * sin(dlon/2);
        double c = 2 * atan2(sqrt(a), sqrt(1-a));
        double distance_km = 6371.0 * c; // Earth radius in km
        
        if (distance_km <= radius_km) {
            result.push_back(pair.first);
        }
    }
    
    return result;
}

std::vector<std::string> FGCom_StationaryStationManager::findStationsByFrequency(double frequency_khz, double tolerance_khz) {
    if (!initialized) initialize();
    
    std::vector<std::string> result;
    
    for (const auto& pair : stations) {
        const auto& config = pair.second;
        double diff = std::abs(config.frequency_khz - frequency_khz);
        
        if (diff <= tolerance_khz) {
            result.push_back(pair.first);
        }
    }
    
    return result;
}

std::vector<std::string> FGCom_StationaryStationManager::findStationsByModulation(const std::string& mode) {
    if (!initialized) initialize();
    
    std::vector<std::string> result;
    
    for (const auto& pair : stations) {
        if (pair.second.modulation_mode == mode) {
            result.push_back(pair.first);
        }
    }
    
    return result;
}

std::vector<std::string> FGCom_StationaryStationManager::findEmergencyStations() {
    if (!initialized) initialize();
    
    std::vector<std::string> result;
    
    for (const auto& pair : stations) {
        if (pair.second.station_type == StationaryStationType::EMERGENCY || pair.second.emergency_capable) {
            result.push_back(pair.first);
        }
    }
    
    return result;
}

std::vector<std::string> FGCom_StationaryStationManager::findMaritimeStations() {
    if (!initialized) initialize();
    
    std::vector<std::string> result;
    
    for (const auto& pair : stations) {
        if (pair.second.station_type == StationaryStationType::COASTAL || 
            pair.second.station_type == StationaryStationType::MARITIME_HF) {
            result.push_back(pair.first);
        }
    }
    
    return result;
}

// Configuration management
bool FGCom_StationaryStationManager::loadStationConfiguration(const std::string& config_file) {
    if (!initialized) initialize();
    
    // This would load from a configuration file
    // For now, return true as a placeholder
    return true;
}

bool FGCom_StationaryStationManager::saveStationConfiguration(const std::string& config_file) {
    if (!initialized) initialize();
    
    // This would save to a configuration file
    // For now, return true as a placeholder
    return true;
}

bool FGCom_StationaryStationManager::exportStationConfiguration(const std::string& station_id, const std::string& config_file) {
    if (!initialized) initialize();
    
    auto it = stations.find(station_id);
    if (it != stations.end()) {
        // This would export the station configuration
        // For now, return true as a placeholder
        return true;
    }
    
    return false;
}

bool FGCom_StationaryStationManager::importStationConfiguration(const std::string& config_file) {
    if (!initialized) initialize();
    
    // This would import from a configuration file
    // For now, return true as a placeholder
    return true;
}

void FGCom_StationaryStationManager::shutdown() {
    stations.clear();
    supported_modes.clear();
    initialized = false;
}

// Stationary station signal processing
double FGCom_StationaryStationProcessor::processGroundStationSignal(double input_signal, const StationaryStationConfig& config) {
    // Ground station signal processing
    return input_signal * 1.0; // No modification for ground stations
}

double FGCom_StationaryStationProcessor::processCoastalStationSignal(double input_signal, const StationaryStationConfig& config) {
    // Coastal station signal processing with enhanced ground system
    return input_signal * 1.1; // 10% enhancement due to better ground
}

double FGCom_StationaryStationProcessor::processMaritimeStationSignal(double input_signal, const StationaryStationConfig& config) {
    // Maritime station signal processing
    return input_signal * 1.05; // 5% enhancement
}

double FGCom_StationaryStationProcessor::processEmergencyStationSignal(double input_signal, const StationaryStationConfig& config) {
    // Emergency station signal processing with priority
    return input_signal * 1.2; // 20% enhancement for emergency stations
}

double FGCom_StationaryStationProcessor::processWeatherStationSignal(double input_signal, const StationaryStationConfig& config) {
    // Weather station signal processing
    return input_signal * 1.0; // No modification
}

double FGCom_StationaryStationProcessor::processNavigationStationSignal(double input_signal, const StationaryStationConfig& config) {
    // Navigation station signal processing
    return input_signal * 1.0; // No modification
}

// Advanced modulation processing
double FGCom_StationaryStationProcessor::processDSBSignal(double input_signal, const StationaryStationConfig& config) {
    // DSB signal processing for stationary stations
    return input_signal * 0.75; // DSB efficiency
}

double FGCom_StationaryStationProcessor::processISBSignal(double input_signal, const StationaryStationConfig& config) {
    // ISB signal processing for stationary stations
    return input_signal * 0.85; // ISB efficiency
}

double FGCom_StationaryStationProcessor::processVSBSignal(double input_signal, const StationaryStationConfig& config) {
    // VSB signal processing for stationary stations
    return input_signal * 0.70; // VSB efficiency
}

double FGCom_StationaryStationProcessor::processNFMSignal(double input_signal, const StationaryStationConfig& config) {
    // NFM signal processing for stationary stations
    return input_signal * 0.60; // NFM efficiency
}

// Signal quality calculations
double FGCom_StationaryStationProcessor::calculateSignalQuality(const StationaryStationConfig& config) {
    // Calculate signal quality based on station configuration
    double quality = 0.8; // Base quality
    
    // Adjust based on antenna height
    quality += (config.antenna_height_m - 10.0) * 0.01;
    
    // Adjust based on power
    quality += (config.power_watts - 100.0) * 0.001;
    
    // Adjust based on ground type
    if (config.ground_type == "excellent") quality += 0.1;
    else if (config.ground_type == "good") quality += 0.05;
    else if (config.ground_type == "poor") quality -= 0.05;
    
    return std::max(0.0, std::min(1.0, quality));
}

double FGCom_StationaryStationProcessor::calculateSignalStrength(const StationaryStationConfig& config) {
    // Calculate signal strength based on power and antenna height
    double strength = 10.0 * log10(config.power_watts);
    strength += 20.0 * log10(config.antenna_height_m / 10.0);
    
    return strength;
}

double FGCom_StationaryStationProcessor::calculateNoiseFloor(const StationaryStationConfig& config) {
    // Calculate noise floor based on frequency and location
    double noise_floor = -120.0 + 10.0 * log10(config.frequency_khz / 1000.0);
    
    // Adjust for ground type
    if (config.ground_type == "excellent") noise_floor -= 5.0;
    else if (config.ground_type == "good") noise_floor -= 2.0;
    else if (config.ground_type == "poor") noise_floor += 5.0;
    
    return noise_floor;
}

double FGCom_StationaryStationProcessor::calculateSignalToNoiseRatio(const StationaryStationConfig& config) {
    double signal_strength = calculateSignalStrength(config);
    double noise_floor = calculateNoiseFloor(config);
    
    return signal_strength - noise_floor;
}

// Station-specific calculations
double FGCom_StationaryStationProcessor::calculateGroundStationRange(const StationaryStationConfig& config) {
    // Calculate range for ground-based stations
    double range_km = 50.0; // Base range
    
    // Adjust for antenna height
    range_km += config.antenna_height_m * 0.5;
    
    // Adjust for power
    range_km += sqrt(config.power_watts) * 0.1;
    
    return range_km;
}

double FGCom_StationaryStationProcessor::calculateCoastalStationRange(const StationaryStationConfig& config) {
    // Calculate range for coastal stations with enhanced ground system
    double range_km = 100.0; // Base range for coastal stations
    
    // Adjust for antenna height
    range_km += config.antenna_height_m * 0.8;
    
    // Adjust for power
    range_km += sqrt(config.power_watts) * 0.2;
    
    return range_km;
}

double FGCom_StationaryStationProcessor::calculateMaritimeStationRange(const StationaryStationConfig& config) {
    // Calculate range for maritime stations
    double range_km = 80.0; // Base range for maritime stations
    
    // Adjust for antenna height
    range_km += config.antenna_height_m * 0.6;
    
    // Adjust for power
    range_km += sqrt(config.power_watts) * 0.15;
    
    return range_km;
}

double FGCom_StationaryStationProcessor::calculateEmergencyStationRange(const StationaryStationConfig& config) {
    // Calculate range for emergency stations with priority
    double range_km = 120.0; // Base range for emergency stations
    
    // Adjust for antenna height
    range_km += config.antenna_height_m * 1.0;
    
    // Adjust for power
    range_km += sqrt(config.power_watts) * 0.25;
    
    return range_km;
}
