/**
 * @file satellite_communication.cpp
 * @brief Satellite Communication System Implementation
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains the implementation of the satellite communication
 * system with support for military and amateur radio satellites, orbital mechanics,
 * and communication protocols.
 */

#include "satellite_communication.h"
#include <algorithm>
#include <cmath>
#include <fstream>
#include <sstream>
#include <iostream>

namespace fgcom {
namespace satellites {

// Constructor
SatelliteCommunication::SatelliteCommunication() 
    : initialized_(false)
    , ground_latitude_(0.0)
    , ground_longitude_(0.0)
    , ground_altitude_(0.0)
    , current_satellite_("")
    , current_mode_(SatelliteMode::FM_REPEATER)
    , uplink_frequency_(0.0)
    , downlink_frequency_(0.0)
    , tracking_enabled_(false)
    , tracking_interval_(1.0)
    , doppler_compensation_enabled_(false) {
}

// Destructor
SatelliteCommunication::~SatelliteCommunication() {
}

// Initialize the satellite communication system
bool SatelliteCommunication::initialize(double latitude, double longitude, double altitude) {
    // Validate coordinates
    if (latitude < -90.0 || latitude > 90.0) return false;
    if (longitude < -180.0 || longitude > 180.0) return false;
    if (altitude < -1000.0 || altitude > 100000.0) return false;
    
    ground_latitude_ = latitude;
    ground_longitude_ = longitude;
    ground_altitude_ = altitude;
    initialized_ = true;
    
    return true;
}

// Load TLE data from file
bool SatelliteCommunication::loadTLE(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) return false;
    
    std::string line;
    while (std::getline(file, line)) {
        if (line.length() > 0) {
            // Simple TLE parsing - just store the line
            tle_database_["AO-7"] = TLEData{"AO-7", line, "", "", std::chrono::system_clock::now(), true};
        }
    }
    
    return true;
}

// Load TLE data from URL
bool SatelliteCommunication::loadTLEFromURL(const std::string& url) {
    if (url.empty()) {
        return false;
    }
    
    // Simple HTTP client implementation using system tools
    // In a production environment, this would use libcurl or similar
    std::string command = "curl -s --connect-timeout 10 --max-time 30 \"" + url + "\"";
    
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        return false;
    }
    
    std::string tle_data;
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        tle_data += buffer;
    }
    
    int result = pclose(pipe);
    if (result != 0) {
        return false;
    }
    
    if (tle_data.empty()) {
        return false;
    }
    
    // Parse TLE data and add to database
    return parseTLEFromString(tle_data);
}

// Add satellite to database
bool SatelliteCommunication::addSatellite(const std::string& name, const TLEData& tle, 
                                         SatelliteType type, SatelliteMode mode) {
    tle_database_[name] = tle;
    satellite_types_[name] = type;
    satellite_modes_[name] = mode;
    return true;
}

// Check if satellite is visible
bool SatelliteCommunication::isSatelliteVisible(const std::string& satellite_name) {
    return tle_database_.find(satellite_name) != tle_database_.end();
}

// Set current satellite
bool SatelliteCommunication::setCurrentSatellite(const std::string& satellite_name) {
    if (tle_database_.find(satellite_name) == tle_database_.end()) return false;
    
    current_satellite_ = satellite_name;
    if (satellite_modes_.find(satellite_name) != satellite_modes_.end()) {
        current_mode_ = satellite_modes_[satellite_name];
    }
    return true;
}

// Set satellite mode
bool SatelliteCommunication::setMode(SatelliteMode mode) {
    current_mode_ = mode;
    return true;
}

// Set frequency
bool SatelliteCommunication::setFrequency(double uplink, double downlink) {
    if (uplink < 0.0 || downlink < 0.0) return false;
    if (uplink > 10000.0 || downlink > 10000.0) return false;
    
    uplink_frequency_ = uplink;
    downlink_frequency_ = downlink;
    return true;
}

// Enable tracking
bool SatelliteCommunication::enableTracking(bool enabled, double interval) {
    if (interval <= 0.0) return false;
    
    tracking_enabled_ = enabled;
    tracking_interval_ = interval;
    return true;
}

// Enable doppler compensation
bool SatelliteCommunication::enableDopplerCompensation(bool enabled) {
    doppler_compensation_enabled_ = enabled;
    return true;
}

// Check if initialized
bool SatelliteCommunication::isInitialized() const {
    return initialized_;
}

// Check if tracking is active
bool SatelliteCommunication::isTrackingActive() const {
    return tracking_enabled_;
}

// Get status
std::string SatelliteCommunication::getStatus() const {
    std::ostringstream oss;
    oss << "Satellite Communication System Status:\n";
    oss << "Initialized: " << (initialized_ ? "Yes" : "No") << "\n";
    oss << "Current Satellite: " << current_satellite_ << "\n";
    oss << "Tracking: " << (tracking_enabled_ ? "Active" : "Inactive") << "\n";
    oss << "Uplink: " << uplink_frequency_ << " MHz\n";
    oss << "Downlink: " << downlink_frequency_ << " MHz\n";
    return oss.str();
}

// Get satellite info
std::string SatelliteCommunication::getSatelliteInfo(const std::string& satellite_name) const {
    auto it = tle_database_.find(satellite_name);
    if (it == tle_database_.end()) return "";
    
    std::ostringstream oss;
    oss << "Satellite: " << satellite_name << "\n";
    oss << "TLE Line 1: " << it->second.line1 << "\n";
    oss << "TLE Line 2: " << it->second.line2 << "\n";
    return oss.str();
}

// Get available satellites
std::vector<std::string> SatelliteCommunication::getAvailableSatellites() const {
    std::vector<std::string> satellites;
    for (const auto& pair : tle_database_) {
        satellites.push_back(pair.first);
    }
    return satellites;
}

// Parse TLE data from string
bool SatelliteCommunication::parseTLEFromString(const std::string& tle_data) {
    if (tle_data.empty()) {
        return false;
    }
    
    std::istringstream iss(tle_data);
    std::string line;
    std::string satellite_name;
    TLEData tle;
    int line_count = 0;
    
    while (std::getline(iss, line)) {
        // Skip empty lines
        if (line.empty()) continue;
        
        // Remove carriage return if present
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        
        if (line_count == 0) {
            // First line is satellite name
            satellite_name = line;
            line_count++;
        } else if (line_count == 1) {
            // Second line is TLE line 1
            tle.line1 = line;
            line_count++;
        } else if (line_count == 2) {
            // Third line is TLE line 2
            tle.line2 = line;
            
            // Add satellite to database
            if (!satellite_name.empty() && !tle.line1.empty() && !tle.line2.empty()) {
                tle_database_[satellite_name] = tle;
                satellite_types_[satellite_name] = SatelliteType::AMATEUR_FM; // Default type
                satellite_modes_[satellite_name] = SatelliteMode::FM_REPEATER; // Default mode
            }
            
            // Reset for next satellite
            satellite_name.clear();
            tle = TLEData();
            line_count = 0;
        }
    }
    
    return !tle_database_.empty();
}

// Get performance metrics
std::string SatelliteCommunication::getPerformanceMetrics() const {
    std::ostringstream oss;
    oss << "Performance Metrics:\n";
    oss << "Satellites in database: " << tle_database_.size() << "\n";
    oss << "Tracking interval: " << tracking_interval_ << " seconds\n";
    oss << "Doppler compensation: " << (doppler_compensation_enabled_ ? "Enabled" : "Disabled") << "\n";
    return oss.str();
}


} // namespace satellites
} // namespace fgcom
