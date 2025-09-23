#include "vehicle_dynamics.h"
#include <cmath>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <iomanip>

// Global instance
std::unique_ptr<FGCom_VehicleDynamicsManager> g_vehicle_dynamics_manager = nullptr;

// Constants
const double EARTH_RADIUS_KM = 6371.0;
const double DEG_TO_RAD = M_PI / 180.0;
const double RAD_TO_DEG = 180.0 / M_PI;

FGCom_VehicleDynamicsManager::FGCom_VehicleDynamicsManager() 
    : auto_cleanup_enabled(true), cleanup_interval_seconds(300) {
    last_cleanup = std::chrono::system_clock::now();
}

FGCom_VehicleDynamicsManager::~FGCom_VehicleDynamicsManager() {
    // Cleanup handled by unique_ptr
}

bool FGCom_VehicleDynamicsManager::registerVehicle(const std::string& vehicle_id, const std::string& vehicle_type) {
    std::lock_guard<std::mutex> lock(vehicles_mutex);
    
    if (vehicles.find(vehicle_id) != vehicles.end()) {
        return false; // Vehicle already exists
    }
    
    fgcom_vehicle_dynamics dynamics;
    dynamics.vehicle_id = vehicle_id;
    dynamics.position.vehicle_type = vehicle_type;
    dynamics.status = "active";
    dynamics.last_update = std::chrono::system_clock::now();
    
    vehicles[vehicle_id] = dynamics;
    return true;
}

bool FGCom_VehicleDynamicsManager::unregisterVehicle(const std::string& vehicle_id) {
    std::lock_guard<std::mutex> lock(vehicles_mutex);
    
    auto it = vehicles.find(vehicle_id);
    if (it == vehicles.end()) {
        return false; // Vehicle not found
    }
    
    vehicles.erase(it);
    return true;
}

bool FGCom_VehicleDynamicsManager::updateVehiclePosition(const std::string& vehicle_id, const fgcom_vehicle_position& position) {
    std::lock_guard<std::mutex> lock(vehicles_mutex);
    
    auto it = vehicles.find(vehicle_id);
    if (it == vehicles.end()) {
        return false; // Vehicle not found
    }
    
    it->second.position = position;
    it->second.last_update = std::chrono::system_clock::now();
    
    // Update magnetic declination if position changed significantly
    if (std::abs(it->second.position.latitude - position.latitude) > 0.01 ||
        std::abs(it->second.position.longitude - position.longitude) > 0.01) {
        it->second.attitude.magnetic_declination_deg = calculateMagneticDeclination(position.latitude, position.longitude);
    }
    
    return true;
}

bool FGCom_VehicleDynamicsManager::updateVehicleAttitude(const std::string& vehicle_id, const fgcom_vehicle_attitude& attitude) {
    std::lock_guard<std::mutex> lock(vehicles_mutex);
    
    auto it = vehicles.find(vehicle_id);
    if (it == vehicles.end()) {
        return false; // Vehicle not found
    }
    
    it->second.attitude = attitude;
    it->second.last_update = std::chrono::system_clock::now();
    
    // Update antenna orientations based on vehicle attitude
    for (auto& antenna : it->second.antennas) {
        transformAttitudeToAntennaOrientation(attitude, antenna);
    }
    
    return true;
}

bool FGCom_VehicleDynamicsManager::updateVehicleVelocity(const std::string& vehicle_id, const fgcom_vehicle_velocity& velocity) {
    std::lock_guard<std::mutex> lock(vehicles_mutex);
    
    auto it = vehicles.find(vehicle_id);
    if (it == vehicles.end()) {
        return false; // Vehicle not found
    }
    
    it->second.velocity = velocity;
    it->second.last_update = std::chrono::system_clock::now();
    return true;
}

bool FGCom_VehicleDynamicsManager::updateVehicleDynamics(const std::string& vehicle_id, const fgcom_vehicle_dynamics& dynamics) {
    std::lock_guard<std::mutex> lock(vehicles_mutex);
    
    auto it = vehicles.find(vehicle_id);
    if (it == vehicles.end()) {
        return false; // Vehicle not found
    }
    
    it->second = dynamics;
    it->second.last_update = std::chrono::system_clock::now();
    return true;
}

bool FGCom_VehicleDynamicsManager::addAntenna(const std::string& vehicle_id, const fgcom_antenna_orientation& antenna) {
    std::lock_guard<std::mutex> lock(vehicles_mutex);
    
    auto it = vehicles.find(vehicle_id);
    if (it == vehicles.end()) {
        return false; // Vehicle not found
    }
    
    // Check if antenna already exists
    for (const auto& existing_antenna : it->second.antennas) {
        if (existing_antenna.antenna_id == antenna.antenna_id) {
            return false; // Antenna already exists
        }
    }
    
    it->second.antennas.push_back(antenna);
    it->second.last_update = std::chrono::system_clock::now();
    return true;
}

bool FGCom_VehicleDynamicsManager::removeAntenna(const std::string& vehicle_id, const std::string& antenna_id) {
    std::lock_guard<std::mutex> lock(vehicles_mutex);
    
    auto it = vehicles.find(vehicle_id);
    if (it == vehicles.end()) {
        return false; // Vehicle not found
    }
    
    auto antenna_it = std::find_if(it->second.antennas.begin(), it->second.antennas.end(),
                                  [&antenna_id](const fgcom_antenna_orientation& antenna) {
                                      return antenna.antenna_id == antenna_id;
                                  });
    
    if (antenna_it == it->second.antennas.end()) {
        return false; // Antenna not found
    }
    
    it->second.antennas.erase(antenna_it);
    it->second.last_update = std::chrono::system_clock::now();
    return true;
}

bool FGCom_VehicleDynamicsManager::updateAntennaOrientation(const std::string& vehicle_id, const std::string& antenna_id,
                                                           const fgcom_antenna_orientation& orientation) {
    std::lock_guard<std::mutex> lock(vehicles_mutex);
    
    auto it = vehicles.find(vehicle_id);
    if (it == vehicles.end()) {
        return false; // Vehicle not found
    }
    
    auto antenna_it = std::find_if(it->second.antennas.begin(), it->second.antennas.end(),
                                  [&antenna_id](const fgcom_antenna_orientation& antenna) {
                                      return antenna.antenna_id == antenna_id;
                                  });
    
    if (antenna_it == it->second.antennas.end()) {
        return false; // Antenna not found
    }
    
    *antenna_it = orientation;
    antenna_it->timestamp = std::chrono::system_clock::now();
    it->second.last_update = std::chrono::system_clock::now();
    return true;
}

bool FGCom_VehicleDynamicsManager::rotateAntenna(const std::string& vehicle_id, const std::string& antenna_id,
                                                float target_azimuth, float target_elevation, bool immediate) {
    std::lock_guard<std::mutex> lock(vehicles_mutex);
    
    auto it = vehicles.find(vehicle_id);
    if (it == vehicles.end()) {
        return false; // Vehicle not found
    }
    
    auto antenna_it = std::find_if(it->second.antennas.begin(), it->second.antennas.end(),
                                  [&antenna_id](const fgcom_antenna_orientation& antenna) {
                                      return antenna.antenna_id == antenna_id;
                                  });
    
    if (antenna_it == it->second.antennas.end()) {
        return false; // Antenna not found
    }
    
    if (!antenna_it->is_rotatable) {
        return false; // Antenna is not rotatable
    }
    
    if (immediate) {
        antenna_it->azimuth_deg = normalizeAngle(target_azimuth);
        antenna_it->elevation_deg = std::max(-90.0f, std::min(90.0f, target_elevation));
    } else {
        // For non-immediate rotation, we would need to implement a rotation queue
        // For now, just set the target values
        antenna_it->azimuth_deg = normalizeAngle(target_azimuth);
        antenna_it->elevation_deg = std::max(-90.0f, std::min(90.0f, target_elevation));
    }
    
    antenna_it->timestamp = std::chrono::system_clock::now();
    it->second.last_update = std::chrono::system_clock::now();
    return true;
}

VehicleDynamicsResponse FGCom_VehicleDynamicsManager::getVehicleDynamics(const std::string& vehicle_id) {
    VehicleDynamicsResponse response;
    
    std::lock_guard<std::mutex> lock(vehicles_mutex);
    
    auto it = vehicles.find(vehicle_id);
    if (it == vehicles.end()) {
        response.message = "Vehicle not found";
        return response;
    }
    
    response.success = true;
    response.dynamics = it->second;
    response.message = "Vehicle dynamics retrieved successfully";
    return response;
}

VehicleListResponse FGCom_VehicleDynamicsManager::getAllVehicles() {
    VehicleListResponse response;
    
    std::lock_guard<std::mutex> lock(vehicles_mutex);
    
    response.success = true;
    response.message = "Vehicle list retrieved successfully";
    
    for (const auto& vehicle : vehicles) {
        response.vehicle_ids.push_back(vehicle.first);
        response.vehicle_types[vehicle.first] = vehicle.second.position.vehicle_type;
        response.vehicle_status[vehicle.first] = vehicle.second.status;
    }
    
    return response;
}

std::vector<fgcom_antenna_orientation> FGCom_VehicleDynamicsManager::getVehicleAntennas(const std::string& vehicle_id) {
    std::lock_guard<std::mutex> lock(vehicles_mutex);
    
    auto it = vehicles.find(vehicle_id);
    if (it == vehicles.end()) {
        return std::vector<fgcom_antenna_orientation>();
    }
    
    return it->second.antennas;
}

fgcom_vehicle_position FGCom_VehicleDynamicsManager::getVehiclePosition(const std::string& vehicle_id) {
    std::lock_guard<std::mutex> lock(vehicles_mutex);
    
    auto it = vehicles.find(vehicle_id);
    if (it == vehicles.end()) {
        return fgcom_vehicle_position(); // Return default position
    }
    
    return it->second.position;
}

fgcom_vehicle_attitude FGCom_VehicleDynamicsManager::getVehicleAttitude(const std::string& vehicle_id) {
    std::lock_guard<std::mutex> lock(vehicles_mutex);
    
    auto it = vehicles.find(vehicle_id);
    if (it == vehicles.end()) {
        return fgcom_vehicle_attitude(); // Return default attitude
    }
    
    return it->second.attitude;
}

fgcom_vehicle_velocity FGCom_VehicleDynamicsManager::getVehicleVelocity(const std::string& vehicle_id) {
    std::lock_guard<std::mutex> lock(vehicles_mutex);
    
    auto it = vehicles.find(vehicle_id);
    if (it == vehicles.end()) {
        return fgcom_vehicle_velocity(); // Return default velocity
    }
    
    return it->second.velocity;
}

AntennaRotationResponse FGCom_VehicleDynamicsManager::calculateAntennaRotation(const AntennaRotationRequest& request) {
    AntennaRotationResponse response;
    
    std::lock_guard<std::mutex> lock(vehicles_mutex);
    
    auto it = vehicles.find(request.vehicle_id);
    if (it == vehicles.end()) {
        response.message = "Vehicle not found";
        return response;
    }
    
    auto antenna_it = std::find_if(it->second.antennas.begin(), it->second.antennas.end(),
                                  [&request](const fgcom_antenna_orientation& antenna) {
                                      return antenna.antenna_id == request.antenna_id;
                                  });
    
    if (antenna_it == it->second.antennas.end()) {
        response.message = "Antenna not found";
        return response;
    }
    
    if (!antenna_it->is_rotatable) {
        response.message = "Antenna is not rotatable";
        return response;
    }
    
    response.success = true;
    response.current_orientation = *antenna_it;
    
    if (request.immediate) {
        response.estimated_arrival_time_sec = 0.0f;
        response.message = "Antenna rotation completed immediately";
    } else {
        // Calculate rotation time based on current position and target
        float azimuth_diff = std::abs(normalizeAngle(request.target_azimuth_deg - antenna_it->azimuth_deg));
        float elevation_diff = std::abs(request.target_elevation_deg - antenna_it->elevation_deg);
        
        float total_rotation_deg = std::sqrt(azimuth_diff * azimuth_diff + elevation_diff * elevation_diff);
        response.estimated_arrival_time_sec = total_rotation_deg / antenna_it->rotation_speed_deg_per_sec;
        response.message = "Antenna rotation calculated successfully";
    }
    
    return response;
}

std::vector<std::string> FGCom_VehicleDynamicsManager::getVehiclesInRange(double center_lat, double center_lon, float radius_km) {
    std::vector<std::string> vehicles_in_range;
    
    std::lock_guard<std::mutex> lock(vehicles_mutex);
    
    for (const auto& vehicle : vehicles) {
        float distance = calculateDistance(center_lat, center_lon, 
                                         vehicle.second.position.latitude, 
                                         vehicle.second.position.longitude);
        
        if (distance <= radius_km) {
            vehicles_in_range.push_back(vehicle.first);
        }
    }
    
    return vehicles_in_range;
}

std::vector<std::string> FGCom_VehicleDynamicsManager::getVehiclesByType(const std::string& vehicle_type) {
    std::vector<std::string> vehicles_of_type;
    
    std::lock_guard<std::mutex> lock(vehicles_mutex);
    
    for (const auto& vehicle : vehicles) {
        if (vehicle.second.position.vehicle_type == vehicle_type) {
            vehicles_of_type.push_back(vehicle.first);
        }
    }
    
    return vehicles_of_type;
}

bool FGCom_VehicleDynamicsManager::enableAutoTracking(const std::string& vehicle_id, const std::string& antenna_id,
                                                     const std::string& target_vehicle_id) {
    std::lock_guard<std::mutex> lock(vehicles_mutex);
    
    auto it = vehicles.find(vehicle_id);
    if (it == vehicles.end()) {
        return false; // Vehicle not found
    }
    
    auto antenna_it = std::find_if(it->second.antennas.begin(), it->second.antennas.end(),
                                  [&antenna_id](const fgcom_antenna_orientation& antenna) {
                                      return antenna.antenna_id == antenna_id;
                                  });
    
    if (antenna_it == it->second.antennas.end()) {
        return false; // Antenna not found
    }
    
    if (!antenna_it->is_rotatable) {
        return false; // Antenna is not rotatable
    }
    
    antenna_it->is_auto_tracking = true;
    antenna_it->timestamp = std::chrono::system_clock::now();
    it->second.last_update = std::chrono::system_clock::now();
    
    return true;
}

bool FGCom_VehicleDynamicsManager::disableAutoTracking(const std::string& vehicle_id, const std::string& antenna_id) {
    std::lock_guard<std::mutex> lock(vehicles_mutex);
    
    auto it = vehicles.find(vehicle_id);
    if (it == vehicles.end()) {
        return false; // Vehicle not found
    }
    
    auto antenna_it = std::find_if(it->second.antennas.begin(), it->second.antennas.end(),
                                  [&antenna_id](const fgcom_antenna_orientation& antenna) {
                                      return antenna.antenna_id == antenna_id;
                                  });
    
    if (antenna_it == it->second.antennas.end()) {
        return false; // Antenna not found
    }
    
    antenna_it->is_auto_tracking = false;
    antenna_it->timestamp = std::chrono::system_clock::now();
    it->second.last_update = std::chrono::system_clock::now();
    
    return true;
}

bool FGCom_VehicleDynamicsManager::updateAutoTracking() {
    std::lock_guard<std::mutex> lock(vehicles_mutex);
    
    bool updated = false;
    
    for (auto& vehicle : vehicles) {
        for (auto& antenna : vehicle.second.antennas) {
            if (antenna.is_auto_tracking) {
                // Implement auto-tracking logic here
                // For now, just mark as updated
                antenna.timestamp = std::chrono::system_clock::now();
                updated = true;
            }
        }
    }
    
    return updated;
}

void FGCom_VehicleDynamicsManager::cleanupInactiveVehicles() {
    std::lock_guard<std::mutex> lock(vehicles_mutex);
    
    auto now = std::chrono::system_clock::now();
    auto timeout = std::chrono::seconds(cleanup_interval_seconds);
    
    auto it = vehicles.begin();
    while (it != vehicles.end()) {
        if (now - it->second.last_update > timeout) {
            it = vehicles.erase(it);
        } else {
            ++it;
        }
    }
    
    last_cleanup = now;
}

void FGCom_VehicleDynamicsManager::setAutoCleanup(bool enabled, int interval_seconds) {
    auto_cleanup_enabled = enabled;
    cleanup_interval_seconds = interval_seconds;
}

std::map<std::string, std::string> FGCom_VehicleDynamicsManager::getSystemStatus() {
    std::map<std::string, std::string> status;
    
    std::lock_guard<std::mutex> lock(vehicles_mutex);
    
    status["total_vehicles"] = std::to_string(vehicles.size());
    status["auto_cleanup_enabled"] = auto_cleanup_enabled ? "true" : "false";
    status["cleanup_interval_seconds"] = std::to_string(cleanup_interval_seconds);
    
    int active_vehicles = 0;
    int total_antennas = 0;
    int rotatable_antennas = 0;
    int auto_tracking_antennas = 0;
    
    for (const auto& vehicle : vehicles) {
        if (vehicle.second.status == "active") {
            active_vehicles++;
        }
        
        total_antennas += vehicle.second.antennas.size();
        
        for (const auto& antenna : vehicle.second.antennas) {
            if (antenna.is_rotatable) {
                rotatable_antennas++;
            }
            if (antenna.is_auto_tracking) {
                auto_tracking_antennas++;
            }
        }
    }
    
    status["active_vehicles"] = std::to_string(active_vehicles);
    status["total_antennas"] = std::to_string(total_antennas);
    status["rotatable_antennas"] = std::to_string(rotatable_antennas);
    status["auto_tracking_antennas"] = std::to_string(auto_tracking_antennas);
    
    return status;
}

void FGCom_VehicleDynamicsManager::setDefaultRotationSpeed(float deg_per_sec) {
    // This would be used when creating new antennas
    // Implementation depends on how default values are stored
}

void FGCom_VehicleDynamicsManager::setMagneticDeclinationSource(const std::string& source) {
    // Implementation for magnetic declination source selection
}

void FGCom_VehicleDynamicsManager::setManualMagneticDeclination(float declination_deg) {
    // Implementation for manual magnetic declination setting
}

// Utility functions
float FGCom_VehicleDynamicsManager::calculateMagneticDeclination(double lat, double lon) {
    // Simplified magnetic declination calculation
    // In a real implementation, this would use a proper magnetic model
    // For now, return a rough approximation based on latitude
    return lat * 0.1f; // Very rough approximation
}

void FGCom_VehicleDynamicsManager::transformAttitudeToAntennaOrientation(const fgcom_vehicle_attitude& attitude,
                                                                        fgcom_antenna_orientation& antenna) {
    // Transform vehicle attitude to antenna orientation
    // This is a simplified transformation - real implementation would be more complex
    
    if (antenna.antenna_type == "yagi" || antenna.antenna_type == "dipole") {
        // For directional antennas, adjust orientation based on vehicle attitude
        antenna.azimuth_deg = normalizeAngle(antenna.azimuth_deg + attitude.yaw_deg);
        antenna.elevation_deg = std::max(-90.0f, std::min(90.0f, 
                                                         antenna.elevation_deg + attitude.pitch_deg));
    }
    // For omnidirectional antennas (vertical, whip), attitude has less effect
}

float FGCom_VehicleDynamicsManager::normalizeAngle(float angle_deg) {
    while (angle_deg < 0.0f) angle_deg += 360.0f;
    while (angle_deg >= 360.0f) angle_deg -= 360.0f;
    return angle_deg;
}

float FGCom_VehicleDynamicsManager::calculateDistance(double lat1, double lon1, double lat2, double lon2) {
    // Haversine formula for calculating distance between two points
    double dlat = (lat2 - lat1) * DEG_TO_RAD;
    double dlon = (lon2 - lon1) * DEG_TO_RAD;
    
    double a = std::sin(dlat/2) * std::sin(dlat/2) +
               std::cos(lat1 * DEG_TO_RAD) * std::cos(lat2 * DEG_TO_RAD) *
               std::sin(dlon/2) * std::sin(dlon/2);
    
    double c = 2 * std::atan2(std::sqrt(a), std::sqrt(1-a));
    
    return EARTH_RADIUS_KM * c;
}

float FGCom_VehicleDynamicsManager::calculateBearing(double lat1, double lon1, double lat2, double lon2) {
    // Calculate bearing between two points
    double dlat = (lat2 - lat1) * DEG_TO_RAD;
    double dlon = (lon2 - lon1) * DEG_TO_RAD;
    
    double y = std::sin(dlon) * std::cos(lat2 * DEG_TO_RAD);
    double x = std::cos(lat1 * DEG_TO_RAD) * std::sin(lat2 * DEG_TO_RAD) -
               std::sin(lat1 * DEG_TO_RAD) * std::cos(lat2 * DEG_TO_RAD) * std::cos(dlon);
    
    double bearing = std::atan2(y, x) * RAD_TO_DEG;
    return normalizeAngle(bearing);
}

// Global functions
bool initializeVehicleDynamicsManager() {
    if (g_vehicle_dynamics_manager) {
        return false; // Already initialized
    }
    
    g_vehicle_dynamics_manager = std::make_unique<FGCom_VehicleDynamicsManager>();
    return true;
}

void shutdownVehicleDynamicsManager() {
    g_vehicle_dynamics_manager.reset();
}
