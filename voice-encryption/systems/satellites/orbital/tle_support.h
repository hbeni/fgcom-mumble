/**
 * @file tle_support.h
 * @brief TLE (Two-Line Element) Support for Orbital Calculations
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains the implementation of TLE support for orbital
 * calculations, satellite tracking, and visibility predictions.
 * 
 * @details
 * TLE Support provides:
 * - TLE parsing and validation
 * - Orbital calculations using SGP4/SDP4 algorithms
 * - Satellite position calculations
 * - Visibility predictions
 * - Pass calculations
 * - Doppler shift calculations
 * - Ground station pointing
 * 
 * @see https://github.com/Supermagnum/fgcom-mumble
 * @see docs/TLE_SUPPORT_DOCUMENTATION.md
 */

#ifndef TLE_SUPPORT_H
#define TLE_SUPPORT_H

#include <vector>
#include <memory>
#include <string>
#include <cstdint>
#include <chrono>
#include <map>
#include <complex>

namespace fgcom {
namespace satellites {
namespace orbital {

/**
 * @struct TLE
 * @brief Two-Line Element set structure
 * 
 * @details
 * This structure contains a complete TLE set with all
 * orbital parameters.
 */
struct TLE {
    std::string satellite_name;     ///< Satellite name
    std::string line1;             ///< TLE line 1
    std::string line2;             ///< TLE line 2
    std::string line3;             ///< TLE line 3 (optional)
    std::chrono::system_clock::time_point epoch; ///< TLE epoch
    bool valid;                    ///< Whether TLE data is valid
    
    // Parsed orbital elements
    double inclination;            ///< Inclination (degrees)
    double right_ascension;        ///< Right ascension of ascending node (degrees)
    double eccentricity;           ///< Eccentricity
    double argument_perigee;       ///< Argument of perigee (degrees)
    double mean_anomaly;           ///< Mean anomaly (degrees)
    double mean_motion;            ///< Mean motion (revolutions per day)
    double bstar;                  ///< B-star drag coefficient
    double epoch_year;             ///< Epoch year
    double epoch_day;              ///< Epoch day of year
    int32_t element_number;        ///< Element number
    int32_t revolution_number;     ///< Revolution number at epoch
};

/**
 * @struct SatellitePosition
 * @brief Satellite position and velocity
 * 
 * @details
 * This structure contains the calculated position and velocity
 * of a satellite at a specific time.
 */
struct SatellitePosition {
    double latitude;                ///< Satellite latitude (degrees)
    double longitude;              ///< Satellite longitude (degrees)
    double altitude;               ///< Satellite altitude (km)
    double elevation;              ///< Elevation angle from ground station (degrees)
    double azimuth;                ///< Azimuth angle from ground station (degrees)
    double range;                  ///< Range to satellite (km)
    double velocity;               ///< Satellite velocity (km/s)
    double doppler_shift;          ///< Doppler shift (Hz)
    std::chrono::system_clock::time_point time; ///< Calculation time
    bool visible;                  ///< Whether satellite is visible
};

/**
 * @struct GroundStation
 * @brief Ground station location
 * 
 * @details
 * This structure contains the location and parameters
 * of a ground station.
 */
struct GroundStation {
    std::string name;              ///< Ground station name
    double latitude;              ///< Ground station latitude (degrees)
    double longitude;             ///< Ground station longitude (degrees)
    double altitude;              ///< Ground station altitude (m)
    double minimum_elevation;     ///< Minimum elevation angle (degrees)
    double maximum_range;          ///< Maximum range (km)
};

/**
 * @struct SatellitePass
 * @brief Satellite pass information
 * 
 * @details
 * This structure contains information about a satellite pass
 * including visibility times and elevation data.
 */
struct SatellitePass {
    std::string satellite_name;     ///< Satellite name
    std::chrono::system_clock::time_point aos;  ///< Acquisition of Signal
    std::chrono::system_clock::time_point los;  ///< Loss of Signal
    double max_elevation;           ///< Maximum elevation angle (degrees)
    std::chrono::system_clock::time_point max_elevation_time; ///< Time of max elevation
    double duration;                ///< Pass duration (seconds)
    bool visible;                   ///< Whether satellite is visible
    double aos_azimuth;            ///< AOS azimuth (degrees)
    double los_azimuth;            ///< LOS azimuth (degrees)
    double max_elevation_azimuth;   ///< Max elevation azimuth (degrees)
};

/**
 * @class TLESupport
 * @brief TLE Support for Orbital Calculations Implementation
 * 
 * @details
 * The TLESupport class implements complete TLE support for orbital
 * calculations, satellite tracking, and visibility predictions.
 * 
 * ## Technical Specifications
 * - **TLE Parsing**: Complete TLE parsing and validation
 * - **Orbital Calculations**: SGP4/SDP4 algorithms
 * - **Position Calculations**: Real-time satellite position
 * - **Visibility Predictions**: Satellite pass predictions
 * - **Doppler Calculations**: Frequency shift calculations
 * - **Ground Station Support**: Multiple ground station support
 * 
 * ## Usage Example
 * @code
 * #include "tle_support.h"
 * 
 * // Create TLE support instance
 * TLESupport tle_support;
 * 
 * // Initialize with ground station
 * GroundStation station;
 * station.name = "Home Station";
 * station.latitude = 40.7128;
 * station.longitude = -74.0060;
 * tle_support.initialize(station);
 * 
 * // Load TLE data
 * tle_support.loadTLE("iss.tle");
 * 
 * // Calculate satellite position
 * auto position = tle_support.calculatePosition("ISS");
 * 
 * // Get satellite passes
 * auto passes = tle_support.getPasses("ISS", 24); // Next 24 hours
 * @endcode
 * 
 * @note This class provides a unified interface for TLE operations.
 * 
 * @since 1.0.0
 * @version 1.0.0
 */
class TLESupport {
private:
    bool initialized_;                  ///< System initialization status
    
    // Ground station
    GroundStation ground_station_;     ///< Ground station parameters
    
    // TLE database
    std::map<std::string, TLE> tle_database_; ///< TLE database
    std::map<std::string, SatellitePosition> position_cache_; ///< Position cache
    
    // Calculation parameters
    double minimum_elevation_;         ///< Minimum elevation angle (degrees)
    double maximum_range_;            ///< Maximum range (km)
    bool doppler_calculation_enabled_; ///< Doppler calculation enabled
    bool position_caching_enabled_;   ///< Position caching enabled
    
    // Processing buffers
    std::vector<double> calculation_buffer_; ///< Calculation buffer
    
public:
    /**
     * @brief Default constructor
     * 
     * @details
     * Initializes the TLE support system with default parameters.
     */
    TLESupport();
    
    /**
     * @brief Virtual destructor
     * 
     * @details
     * Cleans up all resources used by the TLE support system.
     */
    virtual ~TLESupport();
    
    // Initialization and configuration
    
    /**
     * @brief Initialize the TLE support system
     * 
     * @param ground_station Ground station parameters
     * @return true if initialization successful, false otherwise
     * 
     * @details
     * Initializes the TLE support system with the specified
     * ground station parameters.
     * 
     * @note The system must be initialized before any other operations.
     */
    bool initialize(const GroundStation& ground_station);
    
    /**
     * @brief Load TLE data from file
     * 
     * @param filename TLE file path
     * @return true if TLE data loaded successfully, false otherwise
     * 
     * @details
     * Loads TLE data from a file for orbital calculations.
     */
    bool loadTLE(const std::string& filename);
    
    /**
     * @brief Load TLE data from URL
     * 
     * @param url TLE data URL
     * @return true if TLE data loaded successfully, false otherwise
     * 
     * @details
     * Loads TLE data from a URL for orbital calculations.
     */
    bool loadTLEFromURL(const std::string& url);
    
    /**
     * @brief Add TLE to database
     * 
     * @param satellite_name Satellite name
     * @param tle TLE data
     * @return true if TLE added successfully, false otherwise
     * 
     * @details
     * Adds a TLE to the database for orbital calculations.
     */
    bool addTLE(const std::string& satellite_name, const TLE& tle);
    
    /**
     * @brief Remove TLE from database
     * 
     * @param satellite_name Satellite name
     * @return true if TLE removed successfully, false otherwise
     * 
     * @details
     * Removes a TLE from the database.
     */
    bool removeTLE(const std::string& satellite_name);
    
    // Position calculations
    
    /**
     * @brief Calculate satellite position
     * 
     * @param satellite_name Satellite name
     * @param time Time for calculation
     * @return Calculated satellite position
     * 
     * @details
     * Calculates the position of the specified satellite at the given time.
     */
    SatellitePosition calculatePosition(const std::string& satellite_name,
                                      std::chrono::system_clock::time_point time);
    
    /**
     * @brief Calculate current satellite position
     * 
     * @param satellite_name Satellite name
     * @return Current satellite position
     * 
     * @details
     * Calculates the current position of the specified satellite.
     */
    SatellitePosition calculateCurrentPosition(const std::string& satellite_name);
    
    /**
     * @brief Calculate satellite velocity
     * 
     * @param satellite_name Satellite name
     * @param time Time for calculation
     * @return Satellite velocity (km/s)
     * 
     * @details
     * Calculates the velocity of the specified satellite at the given time.
     */
    double calculateVelocity(const std::string& satellite_name,
                           std::chrono::system_clock::time_point time);
    
    /**
     * @brief Calculate Doppler shift
     * 
     * @param satellite_name Satellite name
     * @param frequency Frequency in MHz
     * @param time Time for calculation
     * @return Doppler shift in Hz
     * 
     * @details
     * Calculates the Doppler shift for the specified frequency and time.
     */
    double calculateDopplerShift(const std::string& satellite_name,
                               double frequency,
                               std::chrono::system_clock::time_point time);
    
    // Visibility calculations
    
    /**
     * @brief Check satellite visibility
     * 
     * @param satellite_name Satellite name
     * @param time Time for calculation
     * @return true if satellite is visible, false otherwise
     * 
     * @details
     * Checks if the specified satellite is visible at the given time.
     */
    bool isSatelliteVisible(const std::string& satellite_name,
                          std::chrono::system_clock::time_point time);
    
    /**
     * @brief Calculate satellite elevation
     * 
     * @param satellite_name Satellite name
     * @param time Time for calculation
     * @return Elevation angle in degrees
     * 
     * @details
     * Calculates the elevation angle of the specified satellite at the given time.
     */
    double calculateElevation(const std::string& satellite_name,
                            std::chrono::system_clock::time_point time);
    
    /**
     * @brief Calculate satellite azimuth
     * 
     * @param satellite_name Satellite name
     * @param time Time for calculation
     * @return Azimuth angle in degrees
     * 
     * @details
     * Calculates the azimuth angle of the specified satellite at the given time.
     */
    double calculateAzimuth(const std::string& satellite_name,
                          std::chrono::system_clock::time_point time);
    
    /**
     * @brief Calculate satellite range
     * 
     * @param satellite_name Satellite name
     * @param time Time for calculation
     * @return Range in kilometers
     * 
     * @details
     * Calculates the range to the specified satellite at the given time.
     */
    double calculateRange(const std::string& satellite_name,
                        std::chrono::system_clock::time_point time);
    
    // Pass calculations
    
    /**
     * @brief Get satellite passes
     * 
     * @param satellite_name Satellite name
     * @param hours Number of hours to predict
     * @return Vector of satellite passes
     * 
     * @details
     * Calculates satellite passes for the specified time period.
     */
    std::vector<SatellitePass> getPasses(const std::string& satellite_name, int hours = 24);
    
    /**
     * @brief Get next satellite pass
     * 
     * @param satellite_name Satellite name
     * @return Next satellite pass
     * 
     * @details
     * Calculates the next satellite pass.
     */
    SatellitePass getNextPass(const std::string& satellite_name);
    
    /**
     * @brief Get current pass
     * 
     * @param satellite_name Satellite name
     * @return Current satellite pass
     * 
     * @details
     * Calculates the current satellite pass.
     */
    SatellitePass getCurrentPass(const std::string& satellite_name);
    
    // Configuration
    
    /**
     * @brief Set minimum elevation
     * 
     * @param elevation Minimum elevation angle in degrees
     * @return true if elevation set successfully, false otherwise
     * 
     * @details
     * Sets the minimum elevation angle for visibility calculations.
     */
    bool setMinimumElevation(double elevation);
    
    /**
     * @brief Set maximum range
     * 
     * @param range Maximum range in kilometers
     * @return true if range set successfully, false otherwise
     * 
     * @details
     * Sets the maximum range for visibility calculations.
     */
    bool setMaximumRange(double range);
    
    /**
     * @brief Enable Doppler calculation
     * 
     * @param enabled Enable Doppler calculation
     * @return true if Doppler calculation enabled successfully, false otherwise
     * 
     * @details
     * Enables or disables Doppler shift calculations.
     */
    bool enableDopplerCalculation(bool enabled);
    
    /**
     * @brief Enable position caching
     * 
     * @param enabled Enable position caching
     * @return true if caching enabled successfully, false otherwise
     * 
     * @details
     * Enables or disables position caching for performance.
     */
    bool enablePositionCaching(bool enabled);
    
    // Status and diagnostics
    
    /**
     * @brief Check if system is initialized
     * 
     * @return true if initialized, false otherwise
     * 
     * @details
     * Returns the initialization status of the TLE support system.
     */
    bool isInitialized() const;
    
    /**
     * @brief Get system status
     * 
     * @return Status string
     * 
     * @details
     * Returns a string describing the current status of the
     * TLE support system.
     */
    std::string getStatus() const;
    
    /**
     * @brief Get ground station
     * 
     * @return Ground station parameters
     * 
     * @details
     * Returns the current ground station parameters.
     */
    GroundStation getGroundStation() const;
    
    /**
     * @brief Get available satellites
     * 
     * @return Vector of available satellite names
     * 
     * @details
     * Returns a list of all available satellites in the database.
     */
    std::vector<std::string> getAvailableSatellites() const;
    
    /**
     * @brief Get TLE information
     * 
     * @param satellite_name Satellite name
     * @return TLE information string
     * 
     * @details
     * Returns detailed information about the specified satellite's TLE.
     */
    std::string getTLEInfo(const std::string& satellite_name) const;
    
    /**
     * @brief Get performance metrics
     * 
     * @return Performance metrics string
     * 
     * @details
     * Returns performance metrics for the TLE support system.
     */
    std::string getPerformanceMetrics() const;
};

/**
 * @namespace TLEUtils
 * @brief Utility functions for TLE support
 * 
 * @details
 * This namespace contains utility functions for TLE support,
 * including parsing, validation, and orbital calculations.
 * 
 * @since 1.0.0
 */
namespace TLEUtils {
    
    /**
     * @brief Parse TLE from string
     * 
     * @param tle_string TLE string data
     * @return Parsed TLE
     * 
     * @details
     * Parses TLE data from a string format.
     */
    TLE parseTLE(const std::string& tle_string);
    
    /**
     * @brief Validate TLE
     * 
     * @param tle TLE to validate
     * @return true if TLE is valid, false otherwise
     * 
     * @details
     * Validates that a TLE meets all requirements.
     */
    bool validateTLE(const TLE& tle);
    
    /**
     * @brief Calculate satellite position using SGP4
     * 
     * @param tle TLE data
     * @param time Time for calculation
     * @return Calculated position
     * 
     * @details
     * Calculates satellite position using the SGP4 algorithm.
     */
    SatellitePosition calculatePositionSGP4(const TLE& tle,
                                          std::chrono::system_clock::time_point time);
    
    /**
     * @brief Calculate satellite position using SDP4
     * 
     * @param tle TLE data
     * @param time Time for calculation
     * @return Calculated position
     * 
     * @details
     * Calculates satellite position using the SDP4 algorithm.
     */
    SatellitePosition calculatePositionSDP4(const TLE& tle,
                                          std::chrono::system_clock::time_point time);
    
    /**
     * @brief Calculate ground station pointing
     * 
     * @param satellite_pos Satellite position
     * @param ground_station Ground station parameters
     * @return Ground station pointing (elevation, azimuth)
     * 
     * @details
     * Calculates the ground station pointing angles for a satellite.
     */
    std::pair<double, double> calculateGroundStationPointing(
        const SatellitePosition& satellite_pos,
        const GroundStation& ground_station);
    
    /**
     * @brief Calculate distance between positions
     * 
     * @param pos1 First position
     * @param pos2 Second position
     * @return Distance in kilometers
     * 
     * @details
     * Calculates the distance between two positions.
     */
    double calculateDistance(const SatellitePosition& pos1, const SatellitePosition& pos2);
    
    /**
     * @brief Format TLE for display
     * 
     * @param tle TLE to format
     * @return Formatted TLE string
     * 
     * @details
     * Formats a TLE for display purposes.
     */
    std::string formatTLE(const TLE& tle);
    
    /**
     * @brief Format position for display
     * 
     * @param position Position to format
     * @return Formatted position string
     * 
     * @details
     * Formats a satellite position for display purposes.
     */
    std::string formatPosition(const SatellitePosition& position);
    
    /**
     * @brief Format pass for display
     * 
     * @param pass Pass to format
     * @return Formatted pass string
     * 
     * @details
     * Formats a satellite pass for display purposes.
     */
    std::string formatPass(const SatellitePass& pass);
}

} // namespace orbital
} // namespace satellites
} // namespace fgcom

#endif // TLE_SUPPORT_H
