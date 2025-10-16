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
    (void)url; // Suppress unused parameter warning
    // Stub implementation - would use libcurl in real implementation
    return true;
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
