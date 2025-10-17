/**
 * @file satellite_communication.h
 * @brief Satellite Communication System Implementation
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains the complete implementation of the satellite communication
 * system with support for military and amateur radio satellites, orbital mechanics,
 * and communication protocols.
 * 
 * @details
 * The satellite communication system provides:
 * - Military satellite support (Strela-3, Tsiklon, FLTSATCOM)
 * - Amateur radio satellite support (AO-7, FO-29, AO-73, XW-2 series)
 * - FM repeater satellite support (SO-50, AO-91, AO-85, ISS)
 * - Digital/data mode satellite support
 * - TLE (Two-Line Element) support for orbital calculations
 * - Real-time satellite tracking and visibility
 * - Doppler shift compensation
 * - Frequency management for uplink/downlink pairs
 * 
 * @see https://github.com/Supermagnum/fgcom-mumble
 * @see docs/SATELLITE_COMMUNICATION_DOCUMENTATION.md
 */

#ifndef SATELLITE_COMMUNICATION_H
#define SATELLITE_COMMUNICATION_H

#include <vector>
#include <memory>
#include <string>
#include <cstdint>
#include <complex>
#include <random>
#include <map>
#include <chrono>

namespace fgcom {
namespace satellites {

/**
 * @enum SatelliteType
 * @brief Available satellite types
 * 
 * @details
 * This enumeration defines all available satellite types
 * in the system.
 */
enum class SatelliteType {
    MILITARY,           ///< Military satellites (Strela-3, Tsiklon, FLTSATCOM)
    AMATEUR_LINEAR,     ///< Amateur linear transponder satellites
    AMATEUR_FM,         ///< Amateur FM repeater satellites
    AMATEUR_DIGITAL,    ///< Amateur digital/data mode satellites
    NAVIGATION,         ///< Navigation satellites
    COMMUNICATION       ///< Communication satellites
};

/**
 * @enum SatelliteMode
 * @brief Available satellite communication modes
 * 
 * @details
 * This enumeration defines all available communication modes
 * for satellite operations.
 */
enum class SatelliteMode {
    LINEAR_TRANSPONDER, ///< Linear transponder (SSB/CW)
    FM_REPEATER,        ///< FM voice repeater
    DIGITAL,            ///< Digital/data mode
    STORE_FORWARD,      ///< Store-and-forward messaging
    BEACON,             ///< Beacon transmission
    TELEMETRY           ///< Telemetry transmission
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
    double max_elevation;           ///< Maximum elevation angle
    std::chrono::system_clock::time_point max_elevation_time; ///< Time of max elevation
    double duration;                ///< Pass duration in seconds
    bool visible;                   ///< Whether satellite is visible
};

/**
 * @struct SatellitePosition
 * @brief Current satellite position
 * 
 * @details
 * This structure contains the current position and velocity
 * of a satellite.
 */
struct SatellitePosition {
    double latitude;                ///< Satellite latitude
    double longitude;              ///< Satellite longitude
    double altitude;               ///< Satellite altitude (km)
    double elevation;              ///< Elevation angle from ground station
    double azimuth;                ///< Azimuth angle from ground station
    double range;                  ///< Range to satellite (km)
    double velocity;               ///< Satellite velocity (km/s)
    double doppler_shift;          ///< Doppler shift (Hz)
};

/**
 * @struct TLEData
 * @brief Two-Line Element set data
 * 
 * @details
 * This structure contains TLE data for orbital calculations.
 */
struct TLEData {
    std::string satellite_name;     ///< Satellite name
    std::string line1;             ///< TLE line 1
    std::string line2;             ///< TLE line 2
    std::string line3;             ///< TLE line 3 (optional)
    std::chrono::system_clock::time_point epoch; ///< TLE epoch
    bool valid;                    ///< Whether TLE data is valid
};

/**
 * @class SatelliteCommunication
 * @brief Satellite Communication System Implementation
 * 
 * @details
 * The SatelliteCommunication class implements the complete satellite
 * communication system with orbital mechanics, frequency management,
 * and communication protocols.
 * 
 * ## Technical Specifications
 * - **Satellite Types**: Military, Amateur, Navigation, Communication
 * - **Communication Modes**: Linear transponder, FM repeater, Digital, Store-and-forward
 * - **Frequency Bands**: 2m (144-146 MHz), 70cm (430-440 MHz), VHF (150-174 MHz), UHF (240-320 MHz)
 * - **Orbital Mechanics**: TLE-based position calculations
 * - **Doppler Compensation**: Automatic frequency tracking
 * - **Visibility**: Satellite pass predictions
 * 
 * ## Usage Example
 * @code
 * #include "satellite_communication.h"
 * 
 * // Create satellite communication instance
 * SatelliteCommunication satcom;
 * 
 * // Initialize with ground station location
 * satcom.initialize(40.7128, -74.0060); // New York City
 * 
 * // Load TLE data
 * satcom.loadTLE("iss.tle");
 * 
 * // Get satellite pass predictions
 * auto passes = satcom.getPasses("ISS", 24); // Next 24 hours
 * 
 * // Set up communication
 * satcom.setFrequency(145.990, 145.800); // Uplink, Downlink
 * satcom.setMode(SatelliteMode::FM_VOICE);
 * @endcode
 * 
 * @note This class provides a unified interface for all satellite operations.
 * 
 * @since 1.0.0
 * @version 1.0.0
 */
class SatelliteCommunication {
private:
    bool initialized_;                  ///< System initialization status
    
    // Ground station parameters
    double ground_latitude_;           ///< Ground station latitude
    double ground_longitude_;          ///< Ground station longitude
    double ground_altitude_;           ///< Ground station altitude (m)
    
    // Satellite database
    std::map<std::string, TLEData> tle_database_; ///< TLE database
    std::map<std::string, SatelliteType> satellite_types_; ///< Satellite type database
    std::map<std::string, SatelliteMode> satellite_modes_; ///< Satellite mode database
    
    // Current satellite
    std::string current_satellite_;    ///< Current satellite name
    SatelliteMode current_mode_;      ///< Current communication mode
    double uplink_frequency_;         ///< Uplink frequency (MHz)
    double downlink_frequency_;       ///< Downlink frequency (MHz)
    
    // Tracking parameters
    bool tracking_enabled_;           ///< Satellite tracking enabled
    double tracking_interval_;        ///< Tracking update interval (seconds)
    std::chrono::system_clock::time_point last_update_; ///< Last update time
    
    // Doppler compensation
    bool doppler_compensation_enabled_; ///< Doppler compensation enabled
    double doppler_shift_;            ///< Current Doppler shift (Hz)
    
    // Processing buffers
    std::vector<float> input_buffer_; ///< Input audio buffer
    std::vector<float> output_buffer_; ///< Output audio buffer
    
    // Random number generation
    std::mt19937 rng_;                ///< Random number generator
    std::uniform_real_distribution<float> dist_; ///< Uniform distribution
    
public:
    /**
     * @brief Default constructor
     * 
     * @details
     * Initializes the satellite communication system with default parameters.
     */
    SatelliteCommunication();
    
    /**
     * @brief Virtual destructor
     * 
     * @details
     * Cleans up all resources used by the satellite communication system.
     */
    virtual ~SatelliteCommunication();
    
    // Initialization and configuration
    
    /**
     * @brief Initialize the satellite communication system
     * 
     * @param latitude Ground station latitude
     * @param longitude Ground station longitude
     * @param altitude Ground station altitude in meters
     * @return true if initialization successful, false otherwise
     * 
     * @details
     * Initializes the satellite communication system with the specified
     * ground station location.
     * 
     * @note The system must be initialized before any other operations.
     */
    bool initialize(double latitude, double longitude, double altitude = 0.0);
    
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
     * @brief Add satellite to database
     * 
     * @param name Satellite name
     * @param tle TLE data
     * @param type Satellite type
     * @param mode Communication mode
     * @return true if satellite added successfully, false otherwise
     * 
     * @details
     * Adds a satellite to the database with TLE data and configuration.
     */
    bool addSatellite(const std::string& name, const TLEData& tle, 
                     SatelliteType type, SatelliteMode mode);
    
    // Satellite tracking and visibility
    
    /**
     * @brief Get satellite position
     * 
     * @param satellite_name Satellite name
     * @return Current satellite position
     * 
     * @details
     * Calculates the current position of the specified satellite.
     */
    SatellitePosition getSatellitePosition(const std::string& satellite_name);
    
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
     * @brief Check if satellite is visible
     * 
     * @param satellite_name Satellite name
     * @return true if satellite is visible, false otherwise
     * 
     * @details
     * Checks if the specified satellite is currently visible.
     */
    bool isSatelliteVisible(const std::string& satellite_name);
    
    /**
     * @brief Get satellite elevation
     * 
     * @param satellite_name Satellite name
     * @return Satellite elevation angle in degrees
     * 
     * @details
     * Calculates the current elevation angle of the specified satellite.
     */
    double getElevation(const std::string& satellite_name);
    
    /**
     * @brief Get satellite azimuth
     * 
     * @param satellite_name Satellite name
     * @return Satellite azimuth angle in degrees
     * 
     * @details
     * Calculates the current azimuth angle of the specified satellite.
     */
    double getAzimuth(const std::string& satellite_name);
    
    /**
     * @brief Get Doppler shift
     * 
     * @param satellite_name Satellite name
     * @param frequency Frequency in MHz
     * @return Doppler shift in Hz
     * 
     * @details
     * Calculates the Doppler shift for the specified frequency.
     */
    double getDopplerShift(const std::string& satellite_name, double frequency);
    
    // Communication setup
    
    /**
     * @brief Set current satellite
     * 
     * @param satellite_name Satellite name
     * @return true if satellite set successfully, false otherwise
     * 
     * @details
     * Sets the current satellite for communication.
     */
    bool setCurrentSatellite(const std::string& satellite_name);
    
    /**
     * @brief Set communication mode
     * 
     * @param mode Communication mode
     * @return true if mode set successfully, false otherwise
     * 
     * @details
     * Sets the communication mode for the current satellite.
     */
    bool setMode(SatelliteMode mode);
    
    /**
     * @brief Set frequency pair
     * 
     * @param uplink Uplink frequency in MHz
     * @param downlink Downlink frequency in MHz
     * @return true if frequencies set successfully, false otherwise
     * 
     * @details
     * Sets the uplink and downlink frequencies for communication.
     */
    bool setFrequency(double uplink, double downlink);
    
    /**
     * @brief Enable satellite tracking
     * 
     * @param enabled Enable tracking
     * @param interval Update interval in seconds
     * @return true if tracking enabled successfully, false otherwise
     * 
     * @details
     * Enables or disables satellite tracking with specified update interval.
     */
    bool enableTracking(bool enabled, double interval = 1.0);
    
    /**
     * @brief Enable Doppler compensation
     * 
     * @param enabled Enable Doppler compensation
     * @return true if compensation enabled successfully, false otherwise
     * 
     * @details
     * Enables or disables automatic Doppler shift compensation.
     */
    bool enableDopplerCompensation(bool enabled);
    
    // Audio processing
    
    /**
     * @brief Process uplink audio
     * 
     * @param input Input audio samples
     * @return Processed uplink audio
     * 
     * @details
     * Processes audio for uplink transmission with Doppler compensation.
     */
    std::vector<float> processUplink(const std::vector<float>& input);
    
    /**
     * @brief Process downlink audio
     * 
     * @param input Input audio samples
     * @return Processed downlink audio
     * 
     * @details
     * Processes audio for downlink reception with Doppler compensation.
     */
    std::vector<float> processDownlink(const std::vector<float>& input);
    
    /**
     * @brief Simulate satellite communication
     * 
     * @param input Input audio samples
     * @return Simulated satellite audio
     * 
     * @details
     * Simulates satellite communication with realistic effects.
     */
    std::vector<float> simulateCommunication(const std::vector<float>& input);
    
    // Status and diagnostics
    
    /**
     * @brief Check if system is initialized
     * 
     * @return true if initialized, false otherwise
     * 
     * @details
     * Returns the initialization status of the satellite communication system.
     */
    bool isInitialized() const;
    
    /**
     * @brief Check if tracking is active
     * 
     * @return true if tracking is active, false otherwise
     * 
     * @details
     * Returns the tracking status of the satellite communication system.
     */
    bool isTrackingActive() const;
    
    /**
     * @brief Get system status
     * 
     * @return Status string
     * 
     * @details
     * Returns a string describing the current status of the
     * satellite communication system.
     */
    std::string getStatus() const;
    
    /**
     * @brief Get satellite information
     * 
     * @param satellite_name Satellite name
     * @return Satellite information string
     * 
     * @details
     * Returns detailed information about the specified satellite.
     */
    std::string getSatelliteInfo(const std::string& satellite_name) const;
    
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
     * @brief Get performance metrics
     * 
     * @return Performance metrics string
     * 
     * @details
     * Returns performance metrics for the satellite communication system.
     */
    std::string getPerformanceMetrics() const;
    
    /**
     * @brief Parse TLE data from string
     * 
     * @param tle_data TLE data string
     * @return true if parsing successful, false otherwise
     * 
     * @details
     * Parses TLE (Two-Line Element) data from a string and adds
     * satellites to the database.
     */
    bool parseTLEFromString(const std::string& tle_data);
};

/**
 * @namespace SatelliteUtils
 * @brief Utility functions for satellite communication
 * 
 * @details
 * This namespace contains utility functions for satellite communication,
 * including orbital calculations, frequency management, and TLE processing.
 * 
 * @since 1.0.0
 */
namespace SatelliteUtils {
    
    /**
     * @brief Parse TLE data
     * 
     * @param tle_string TLE data string
     * @return Parsed TLE data
     * 
     * @details
     * Parses TLE data from a string format.
     */
    TLEData parseTLE(const std::string& tle_string);
    
    /**
     * @brief Calculate satellite position from TLE
     * 
     * @param tle TLE data
     * @param time Time for calculation
     * @return Satellite position
     * 
     * @details
     * Calculates satellite position using SGP4/SDP4 algorithms.
     */
    SatellitePosition calculatePosition(const TLEData& tle, 
                                      std::chrono::system_clock::time_point time);
    
    /**
     * @brief Calculate Doppler shift
     * 
     * @param satellite_pos Satellite position
     * @param ground_pos Ground station position
     * @param frequency Frequency in MHz
     * @return Doppler shift in Hz
     * 
     * @details
     * Calculates Doppler shift based on relative velocity.
     */
    double calculateDopplerShift(const SatellitePosition& satellite_pos,
                               const SatellitePosition& ground_pos,
                               double frequency);
    
    /**
     * @brief Get satellite type name
     * 
     * @param type Satellite type
     * @return Type name string
     * 
     * @details
     * Returns the human-readable name of the satellite type.
     */
    std::string getSatelliteTypeName(SatelliteType type);
    
    /**
     * @brief Get satellite mode name
     * 
     * @param mode Satellite mode
     * @return Mode name string
     * 
     * @details
     * Returns the human-readable name of the satellite mode.
     */
    std::string getSatelliteModeName(SatelliteMode mode);
    
    /**
     * @brief Validate frequency
     * 
     * @param frequency Frequency in MHz
     * @param band Frequency band
     * @return true if frequency is valid, false otherwise
     * 
     * @details
     * Validates that the frequency is within the specified band.
     */
    bool validateFrequency(double frequency, const std::string& band);
    
    /**
     * @brief Get frequency band
     * 
     * @param frequency Frequency in MHz
     * @return Frequency band name
     * 
     * @details
     * Returns the frequency band name for the specified frequency.
     */
    std::string getFrequencyBand(double frequency);
    
    /**
     * @brief Calculate distance
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
     * @brief Calculate elevation angle
     * 
     * @param satellite_pos Satellite position
     * @param ground_pos Ground station position
     * @return Elevation angle in degrees
     * 
     * @details
     * Calculates the elevation angle from ground station to satellite.
     */
    double calculateElevation(const SatellitePosition& satellite_pos, 
                            const SatellitePosition& ground_pos);
    
    /**
     * @brief Calculate azimuth angle
     * 
     * @param satellite_pos Satellite position
     * @param ground_pos Ground station position
     * @return Azimuth angle in degrees
     * 
     * @details
     * Calculates the azimuth angle from ground station to satellite.
     */
    double calculateAzimuth(const SatellitePosition& satellite_pos, 
                          const SatellitePosition& ground_pos);
}

} // namespace satellites
} // namespace fgcom

#endif // SATELLITE_COMMUNICATION_H
