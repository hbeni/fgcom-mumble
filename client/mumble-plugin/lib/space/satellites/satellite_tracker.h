/**
 * @file satellite_tracker.h
 * @brief Satellite Tracking Module for Radio Propagation
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This module provides satellite tracking capabilities for radio propagation
 * calculations, including orbital mechanics, visibility, and communication parameters.
 */

#ifndef SATELLITE_TRACKER_H
#define SATELLITE_TRACKER_H

#include <vector>
#include <memory>
#include <string>
#include <cstdint>
#include <chrono>
#include <map>

namespace FGCom {
namespace space {
namespace satellites {

/**
 * @enum SatelliteType
 * @brief Satellite type classification
 */
enum class SatelliteType {
    MILITARY,           ///< Military satellites
    AMATEUR_LINEAR,     ///< Amateur linear transponder satellites
    AMATEUR_FM,         ///< Amateur FM repeater satellites
    AMATEUR_DIGITAL,    ///< Amateur digital/data mode satellites
    NAVIGATION,         ///< Navigation satellites
    COMMUNICATION       ///< Communication satellites
};

/**
 * @struct SatellitePosition
 * @brief Current satellite position and velocity
 */
struct SatellitePosition {
    double latitude_deg;        ///< Latitude in degrees
    double longitude_deg;       ///< Longitude in degrees
    double altitude_km;          ///< Altitude in kilometers
    double velocity_km_s;        ///< Velocity in km/s
    double elevation_deg;        ///< Elevation angle from observer
    double azimuth_deg;          ///< Azimuth angle from observer
    double range_km;             ///< Range to satellite in km
    double doppler_shift_hz;     ///< Doppler shift in Hz
    std::chrono::system_clock::time_point timestamp;
};

/**
 * @struct SatellitePass
 * @brief Satellite pass information
 */
struct SatellitePass {
    std::string satellite_name;
    std::chrono::system_clock::time_point aos;  ///< Acquisition of Signal
    std::chrono::system_clock::time_point los;  ///< Loss of Signal
    double max_elevation_deg;
    std::chrono::system_clock::time_point max_elevation_time;
    double duration_seconds;
    bool is_visible;
};

/**
 * @struct SatelliteOrbit
 * @brief Orbital parameters
 */
struct SatelliteOrbit {
    double semi_major_axis_km;   ///< Semi-major axis
    double eccentricity;         ///< Eccentricity
    double inclination_deg;       ///< Inclination in degrees
    double raan_deg;             ///< Right Ascension of Ascending Node
    double argument_of_perigee_deg; ///< Argument of perigee
    double mean_anomaly_deg;     ///< Mean anomaly
    double period_minutes;        ///< Orbital period in minutes
};

/**
 * @class SatelliteTracker
 * @brief Main satellite tracking class
 * 
 * Provides comprehensive satellite tracking including:
 * - Real-time position calculations
 * - Visibility predictions
 * - Doppler shift calculations
 * - Pass predictions
 */
class SatelliteTracker {
public:
    /**
     * @brief Constructor
     */
    SatelliteTracker();
    
    /**
     * @brief Destructor
     */
    virtual ~SatelliteTracker();
    
    /**
     * @brief Initialize tracker
     * @param observer_lat Observer latitude
     * @param observer_lon Observer longitude
     * @param observer_alt_km Observer altitude in km
     * @return true if initialization successful
     */
    bool initialize(double observer_lat, double observer_lon, double observer_alt_km = 0.0);
    
    /**
     * @brief Register a satellite
     * @param name Satellite name
     * @param orbit Orbital parameters
     * @param type Satellite type
     * @return true if registration successful
     */
    bool registerSatellite(const std::string& name, const SatelliteOrbit& orbit, SatelliteType type);
    
    /**
     * @brief Get current satellite position
     * @param satellite_name Satellite name
     * @return Current position, or empty if not found
     */
    SatellitePosition getCurrentPosition(const std::string& satellite_name) const;
    
    /**
     * @brief Get satellite position at specific time
     * @param satellite_name Satellite name
     * @param timestamp Time point
     * @return Position at specified time
     */
    SatellitePosition getPositionAt(const std::string& satellite_name, 
                                   std::chrono::system_clock::time_point timestamp) const;
    
    /**
     * @brief Check if satellite is visible
     * @param satellite_name Satellite name
     * @return true if visible
     */
    bool isVisible(const std::string& satellite_name) const;
    
    /**
     * @brief Get next pass for satellite
     * @param satellite_name Satellite name
     * @return Next pass information
     */
    SatellitePass getNextPass(const std::string& satellite_name) const;
    
    /**
     * @brief Get all passes in time window
     * @param satellite_name Satellite name
     * @param start_time Start time
     * @param end_time End time
     * @return Vector of passes
     */
    std::vector<SatellitePass> getPasses(const std::string& satellite_name,
                                         std::chrono::system_clock::time_point start_time,
                                         std::chrono::system_clock::time_point end_time) const;
    
    /**
     * @brief Calculate Doppler shift for frequency
     * @param satellite_name Satellite name
     * @param frequency_mhz Operating frequency in MHz
     * @return Doppler shift in Hz
     */
    double calculateDopplerShift(const std::string& satellite_name, double frequency_mhz) const;
    
    /**
     * @brief Calculate path loss to satellite
     * @param satellite_name Satellite name
     * @param frequency_mhz Operating frequency in MHz
     * @return Path loss in dB
     */
    double calculatePathLoss(const std::string& satellite_name, double frequency_mhz) const;
    
    /**
     * @brief Get all registered satellites
     * @return Vector of satellite names
     */
    std::vector<std::string> getRegisteredSatellites() const;
    
    /**
     * @brief Update all satellite positions
     * @param timestamp Current time (defaults to now)
     */
    void updatePositions(std::chrono::system_clock::time_point timestamp = std::chrono::system_clock::now());
    
private:
    struct SatelliteData {
        SatelliteOrbit orbit;
        SatelliteType type;
        SatellitePosition current_position;
        std::chrono::system_clock::time_point last_update;
    };
    
    std::map<std::string, SatelliteData> satellites_;
    double observer_lat_;
    double observer_lon_;
    double observer_alt_km_;
    bool initialized_;
    
    // Internal calculation methods
    SatellitePosition calculatePosition(const SatelliteOrbit& orbit, 
                                       std::chrono::system_clock::time_point timestamp) const;
    bool isAboveHorizon(const SatellitePosition& position) const;
    double calculateElevation(const SatellitePosition& position) const;
    double calculateAzimuth(const SatellitePosition& position) const;
    double calculateRange(const SatellitePosition& position) const;
    double calculateDopplerShift_(const SatellitePosition& position, double frequency_mhz) const;
    double calculatePathLoss_(const SatellitePosition& position, double frequency_mhz) const;
};

} // namespace satellites
} // namespace space
} // namespace FGCom

#endif // SATELLITE_TRACKER_H

