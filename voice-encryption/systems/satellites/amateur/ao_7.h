/**
 * @file ao_7.h
 * @brief AO-7 (AMSAT-OSCAR 7) Amateur Radio Satellite
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains the implementation of the AO-7 amateur radio
 * satellite system with linear transponder capabilities.
 * 
 * @details
 * AO-7 provides:
 * - Linear transponder operation (SSB/CW)
 * - Mode A: 145.850-145.950 MHz up → 29.400-29.500 MHz down
 * - Mode B: 432.125-432.175 MHz up → 145.975-145.925 MHz down
 * - Intermittent operation (battery dependent)
 * - TLE-based orbital calculations
 * 
 * @see https://github.com/Supermagnum/fgcom-mumble
 * @see docs/AO_7_DOCUMENTATION.md
 */

#ifndef AO_7_H
#define AO_7_H

#include <vector>
#include <memory>
#include <string>
#include <cstdint>
#include <chrono>
#include <map>

namespace fgcom {
namespace satellites {
namespace amateur {

/**
 * @enum AO7Mode
 * @brief AO-7 operation modes
 * 
 * @details
 * This enumeration defines the available operation modes
 * for AO-7 satellite.
 */
enum class AO7Mode {
    MODE_A,             ///< Mode A: 2m up → 10m down
    MODE_B,             ///< Mode B: 70cm up → 2m down
    INACTIVE,           ///< Satellite inactive
    BATTERY_CHARGING,   ///< Battery charging mode
    SUNLIGHT            ///< Sunlight mode (active)
};

/**
 * @enum AO7Transponder
 * @brief AO-7 transponder types
 * 
 * @details
 * This enumeration defines the available transponder types
 * for AO-7 operations.
 */
enum class AO7Transponder {
    LINEAR_A,           ///< Linear transponder Mode A
    LINEAR_B,           ///< Linear transponder Mode B
    BEACON,             ///< Beacon transmission
    TELEMETRY           ///< Telemetry transmission
};

/**
 * @struct AO7Config
 * @brief AO-7 configuration structure
 * 
 * @details
 * This structure contains the configuration parameters
 * for AO-7 operations.
 */
struct AO7Config {
    AO7Mode mode;                      ///< Operation mode
    AO7Transponder transponder;        ///< Transponder type
    double uplink_frequency;           ///< Uplink frequency (MHz)
    double downlink_frequency;         ///< Downlink frequency (MHz)
    double bandwidth;                  ///< Transponder bandwidth (kHz)
    bool doppler_compensation;         ///< Doppler compensation enabled
    bool squelch_enabled;              ///< Squelch enabled
    double squelch_threshold;          ///< Squelch threshold
    uint32_t power_level;              ///< Transmit power level
};

/**
 * @class AO7
 * @brief AO-7 Amateur Radio Satellite Implementation
 * 
 * @details
 * The AO7 class implements the complete AO-7 amateur radio
 * satellite system with linear transponder capabilities.
 * 
 * ## Technical Specifications
 * - **Satellite**: AO-7 (AMSAT-OSCAR 7)
 * - **Launch**: 1974
 * - **Status**: Still operational (intermittently)
 * - **Orbit**: 1450 km circular LEO
 * - **NORAD**: 07530
 * - **Modes**: Mode A (2m→10m), Mode B (70cm→2m)
 * - **Transponder**: Linear transponder
 * 
 * ## Usage Example
 * @code
 * #include "ao_7.h"
 * 
 * // Create AO-7 instance
 * AO7 ao7;
 * 
 * // Initialize with ground station location
 * ao7.initialize(40.7128, -74.0060);
 * 
 * // Load TLE data
 * ao7.loadTLE("ao_7.tle");
 * 
 * // Configure for Mode A
 * AO7Config config;
 * config.mode = AO7Mode::MODE_A;
 * config.transponder = AO7Transponder::LINEAR_A;
 * ao7.configure(config);
 * @endcode
 * 
 * @note This class provides a unified interface for AO-7 operations.
 * 
 * @since 1.0.0
 * @version 1.0.0
 */
class AO7 {
private:
    bool initialized_;                  ///< System initialization status
    
    // Ground station parameters
    double ground_latitude_;           ///< Ground station latitude
    double ground_longitude_;          ///< Ground station longitude
    double ground_altitude_;           ///< Ground station altitude (m)
    
    // Satellite parameters
    std::string satellite_name_;       ///< Satellite name
    AO7Config current_config_;         ///< Current configuration
    
    // Transponder parameters
    bool transponder_active_;          ///< Transponder active status
    double transponder_frequency_;     ///< Transponder frequency
    double transponder_bandwidth_;     ///< Transponder bandwidth
    bool doppler_compensation_enabled_; ///< Doppler compensation enabled
    
    // Processing buffers
    std::vector<float> input_buffer_;  ///< Input audio buffer
    std::vector<float> output_buffer_; ///< Output audio buffer
    
public:
    /**
     * @brief Default constructor
     * 
     * @details
     * Initializes the AO-7 system with default parameters.
     */
    AO7();
    
    /**
     * @brief Virtual destructor
     * 
     * @details
     * Cleans up all resources used by the AO-7 system.
     */
    virtual ~AO7();
    
    // Initialization and configuration
    
    /**
     * @brief Initialize the AO-7 system
     * 
     * @param latitude Ground station latitude
     * @param longitude Ground station longitude
     * @param altitude Ground station altitude in meters
     * @return true if initialization successful, false otherwise
     * 
     * @details
     * Initializes the AO-7 system with the specified
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
     * @brief Configure AO-7 system
     * 
     * @param config Configuration parameters
     * @return true if configuration successful, false otherwise
     * 
     * @details
     * Configures the AO-7 system with the specified parameters.
     */
    bool configure(const AO7Config& config);
    
    // Transponder operations
    
    /**
     * @brief Check transponder status
     * 
     * @return true if transponder is active, false otherwise
     * 
     * @details
     * Checks if the transponder is currently active.
     */
    bool isTransponderActive() const;
    
    /**
     * @brief Get transponder frequency
     * 
     * @return Transponder frequency in MHz
     * 
     * @details
     * Returns the current transponder frequency.
     */
    double getTransponderFrequency() const;
    
    /**
     * @brief Get transponder bandwidth
     * 
     * @return Transponder bandwidth in kHz
     * 
     * @details
     * Returns the current transponder bandwidth.
     */
    double getTransponderBandwidth() const;
    
    /**
     * @brief Process uplink audio
     * 
     * @param audio Input audio samples
     * @return Processed audio for transmission
     * 
     * @details
     * Processes audio for uplink transmission via AO-7.
     */
    std::vector<float> processUplink(const std::vector<float>& audio);
    
    /**
     * @brief Process downlink audio
     * 
     * @param audio Input audio samples
     * @return Processed received audio
     * 
     * @details
     * Processes received audio from AO-7 downlink.
     */
    std::vector<float> processDownlink(const std::vector<float>& audio);
    
    /**
     * @brief Simulate transponder operation
     * 
     * @param audio Input audio samples
     * @return Simulated transponder audio
     * 
     * @details
     * Simulates transponder operation with realistic effects.
     */
    std::vector<float> simulateTransponder(const std::vector<float>& audio);
    
    // Mode operations
    
    /**
     * @brief Set operation mode
     * 
     * @param mode Operation mode
     * @return true if mode set successfully, false otherwise
     * 
     * @details
     * Sets the operation mode for AO-7.
     */
    bool setMode(AO7Mode mode);
    
    /**
     * @brief Set transponder type
     * 
     * @param transponder Transponder type
     * @return true if transponder set successfully, false otherwise
     * 
     * @details
     * Sets the transponder type for AO-7.
     */
    bool setTransponder(AO7Transponder transponder);
    
    /**
     * @brief Enable Doppler compensation
     * 
     * @param enabled Enable Doppler compensation
     * @return true if compensation enabled successfully, false otherwise
     * 
     * @details
     * Enables or disables Doppler shift compensation.
     */
    bool enableDopplerCompensation(bool enabled);
    
    /**
     * @brief Set squelch parameters
     * 
     * @param enabled Enable squelch
     * @param threshold Squelch threshold
     * @return true if squelch set successfully, false otherwise
     * 
     * @details
     * Sets the squelch parameters for AO-7.
     */
    bool setSquelch(bool enabled, double threshold);
    
    // Status and diagnostics
    
    /**
     * @brief Check if system is initialized
     * 
     * @return true if initialized, false otherwise
     * 
     * @details
     * Returns the initialization status of the AO-7 system.
     */
    bool isInitialized() const;
    
    /**
     * @brief Get system status
     * 
     * @return Status string
     * 
     * @details
     * Returns a string describing the current status of the
     * AO-7 system.
     */
    std::string getStatus() const;
    
    /**
     * @brief Get current configuration
     * 
     * @return Current configuration
     * 
     * @details
     * Returns the current system configuration.
     */
    AO7Config getCurrentConfig() const;
    
    /**
     * @brief Get available modes
     * 
     * @return Vector of available modes
     * 
     * @details
     * Returns a list of all available operation modes.
     */
    std::vector<AO7Mode> getAvailableModes() const;
    
    /**
     * @brief Get available transponders
     * 
     * @return Vector of available transponders
     * 
     * @details
     * Returns a list of all available transponder types.
     */
    std::vector<AO7Transponder> getAvailableTransponders() const;
    
    /**
     * @brief Get performance metrics
     * 
     * @return Performance metrics string
     * 
     * @details
     * Returns performance metrics for the AO-7 system.
     */
    std::string getPerformanceMetrics() const;
};

/**
 * @namespace AO7Utils
 * @brief Utility functions for AO-7 system
 * 
 * @details
 * This namespace contains utility functions for the AO-7
 * system, including mode management, frequency calculations,
 * and transponder operations.
 * 
 * @since 1.0.0
 */
namespace AO7Utils {
    
    /**
     * @brief Get mode frequencies
     * 
     * @param mode Operation mode
     * @return Frequency pair (uplink, downlink) in MHz
     * 
     * @details
     * Returns the frequency pair for the specified mode.
     */
    std::pair<double, double> getModeFrequencies(AO7Mode mode);
    
    /**
     * @brief Get mode bandwidth
     * 
     * @param mode Operation mode
     * @return Bandwidth in kHz
     * 
     * @details
     * Returns the bandwidth for the specified mode.
     */
    double getModeBandwidth(AO7Mode mode);
    
    /**
     * @brief Get mode name
     * 
     * @param mode Operation mode
     * @return Mode name string
     * 
     * @details
     * Returns the human-readable name of the mode.
     */
    std::string getModeName(AO7Mode mode);
    
    /**
     * @brief Get transponder name
     * 
     * @param transponder Transponder type
     * @return Transponder name string
     * 
     * @details
     * Returns the human-readable name of the transponder.
     */
    std::string getTransponderName(AO7Transponder transponder);
    
    /**
     * @brief Validate configuration
     * 
     * @param config Configuration to validate
     * @return true if configuration is valid, false otherwise
     * 
     * @details
     * Validates that a configuration meets all requirements.
     */
    bool validateConfiguration(const AO7Config& config);
    
    /**
     * @brief Calculate Doppler shift
     * 
     * @param frequency Frequency in MHz
     * @param velocity Relative velocity in km/s
     * @return Doppler shift in Hz
     * 
     * @details
     * Calculates the Doppler shift for the specified frequency and velocity.
     */
    double calculateDopplerShift(double frequency, double velocity);
    
    /**
     * @brief Check satellite visibility
     * 
     * @param latitude Ground station latitude
     * @param longitude Ground station longitude
     * @param satellite_elevation Satellite elevation angle
     * @return true if satellite is visible, false otherwise
     * 
     * @details
     * Checks if the satellite is visible from the ground station.
     */
    bool checkVisibility(double latitude, double longitude, double satellite_elevation);
    
    /**
     * @brief Format frequency
     * 
     * @param frequency Frequency in MHz
     * @return Formatted frequency string
     * 
     * @details
     * Formats a frequency for display.
     */
    std::string formatFrequency(double frequency);
    
    /**
     * @brief Parse frequency
     * 
     * @param frequency_string Frequency string
     * @return Frequency in MHz
     * 
     * @details
     * Parses a frequency string to MHz.
     */
    double parseFrequency(const std::string& frequency_string);
}

} // namespace amateur
} // namespace satellites
} // namespace fgcom

#endif // AO_7_H
