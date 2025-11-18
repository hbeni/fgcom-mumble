/**
 * @file iss.h
 * @brief ISS (International Space Station) Amateur Radio Satellite
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains the implementation of the ISS amateur radio
 * satellite system with FM voice repeater and APRS digipeater capabilities.
 * 
 * @details
 * ISS provides:
 * - FM voice repeater (when crew active)
 * - APRS digipeater
 * - Uplink: 145.990 MHz
 * - Downlink: 145.800 MHz
 * - Packet: 145.825 MHz (APRS)
 * - Orbit: ~400 km LEO
 * - NORAD: 25544
 * 
 * @see https://github.com/Supermagnum/fgcom-mumble
 * @see docs/ISS_DOCUMENTATION.md
 */

#ifndef ISS_H
#define ISS_H

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
 * @enum ISSMode
 * @brief ISS operation modes
 * 
 * @details
 * This enumeration defines the available operation modes
 * for ISS amateur radio operations.
 */
enum class ISSMode {
    FM_VOICE,           ///< FM voice repeater
    APRS_DIGIPEATER,    ///< APRS digipeater
    PACKET,             ///< Packet radio
    BEACON,             ///< Beacon transmission
    TELEMETRY,          ///< Telemetry transmission
    INACTIVE            ///< ISS inactive
};

/**
 * @enum ISSService
 * @brief ISS service types
 * 
 * @details
 * This enumeration defines the available service types
 * for ISS operations.
 */
enum class ISSService {
    VOICE_COMMUNICATION,    ///< Voice communication
    APRS_DIGIPEATING,       ///< APRS digipeating
    PACKET_RADIO,           ///< Packet radio
    TELEMETRY,              ///< Telemetry data
    BEACON,                 ///< Beacon transmission
    CREW_COMMUNICATION      ///< Crew communication
};

/**
 * @struct ISSConfig
 * @brief ISS configuration structure
 * 
 * @details
 * This structure contains the configuration parameters
 * for ISS operations.
 */
struct ISSConfig {
    ISSMode mode;                       ///< Operation mode
    ISSService service;                 ///< Service type
    double uplink_frequency;            ///< Uplink frequency (MHz)
    double downlink_frequency;          ///< Downlink frequency (MHz)
    double packet_frequency;            ///< Packet frequency (MHz)
    bool crew_active;                   ///< Crew active status
    bool doppler_compensation;          ///< Doppler compensation enabled
    bool squelch_enabled;               ///< Squelch enabled
    double squelch_threshold;            ///< Squelch threshold
    uint32_t power_level;               ///< Transmit power level
    bool aprs_enabled;                  ///< APRS enabled
    std::string aprs_callsign;          ///< APRS callsign
};

/**
 * @struct APRSMessage
 * @brief APRS message structure
 * 
 * @details
 * This structure contains an APRS message for ISS digipeating.
 */
struct APRSMessage {
    std::string callsign;               ///< Station callsign
    std::string message;                ///< APRS message
    std::chrono::system_clock::time_point timestamp; ///< Message timestamp
    bool digipeated;                    ///< Whether message was digipeated
    std::string digipeater_path;        ///< Digipeater path
    uint32_t priority;                  ///< Message priority
};

/**
 * @class ISS
 * @brief ISS Amateur Radio Satellite Implementation
 * 
 * @details
 * The ISS class implements the complete ISS amateur radio
 * satellite system with FM voice repeater and APRS digipeater capabilities.
 * 
 * ## Technical Specifications
 * - **Satellite**: ISS (International Space Station)
 * - **Orbit**: ~400 km LEO
 * - **NORAD**: 25544
 * - **Uplink**: 145.990 MHz
 * - **Downlink**: 145.800 MHz
 * - **Packet**: 145.825 MHz (APRS)
 * - **Modes**: FM voice, APRS digipeater, Packet radio
 * - **Crew**: Active when crew is present
 * 
 * ## Usage Example
 * @code
 * #include "iss.h"
 * 
 * // Create ISS instance
 * ISS iss;
 * 
 * // Initialize with ground station location
 * iss.initialize(40.7128, -74.0060);
 * 
 * // Load TLE data
 * iss.loadTLE("iss.tle");
 * 
 * // Configure for FM voice
 * ISSConfig config;
 * config.mode = ISSMode::FM_VOICE;
 * config.service = ISSService::VOICE_COMMUNICATION;
 * iss.configure(config);
 * @endcode
 * 
 * @note This class provides a unified interface for ISS operations.
 * 
 * @since 1.0.0
 * @version 1.0.0
 */
class ISS {
private:
    bool initialized_;                  ///< System initialization status
    
    // Ground station parameters
    double ground_latitude_;           ///< Ground station latitude
    double ground_longitude_;          ///< Ground station longitude
    double ground_altitude_;           ///< Ground station altitude (m)
    
    // Satellite parameters
    std::string satellite_name_;       ///< Satellite name
    ISSConfig current_config_;         ///< Current configuration
    
    // ISS specific parameters
    bool crew_active_;                 ///< Crew active status
    bool voice_repeater_active_;       ///< Voice repeater active
    bool aprs_digipeater_active_;      ///< APRS digipeater active
    bool packet_radio_active_;         ///< Packet radio active
    
    // APRS parameters
    std::vector<APRSMessage> aprs_messages_; ///< APRS messages
    std::string aprs_callsign_;        ///< APRS callsign
    bool aprs_enabled_;                ///< APRS enabled
    
    // Processing buffers
    std::vector<float> input_buffer_;  ///< Input audio buffer
    std::vector<float> output_buffer_; ///< Output audio buffer
    std::vector<uint8_t> packet_buffer_; ///< Packet buffer
    
public:
    /**
     * @brief Default constructor
     * 
     * @details
     * Initializes the ISS system with default parameters.
     */
    ISS();
    
    /**
     * @brief Virtual destructor
     * 
     * @details
     * Cleans up all resources used by the ISS system.
     */
    virtual ~ISS();
    
    // Initialization and configuration
    
    /**
     * @brief Initialize the ISS system
     * 
     * @param latitude Ground station latitude
     * @param longitude Ground station longitude
     * @param altitude Ground station altitude in meters
     * @return true if initialization successful, false otherwise
     * 
     * @details
     * Initializes the ISS system with the specified
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
     * @brief Configure ISS system
     * 
     * @param config Configuration parameters
     * @return true if configuration successful, false otherwise
     * 
     * @details
     * Configures the ISS system with the specified parameters.
     */
    bool configure(const ISSConfig& config);
    
    // Voice operations
    
    /**
     * @brief Process voice uplink
     * 
     * @param audio Input audio samples
     * @return Processed audio for transmission
     * 
     * @details
     * Processes audio for uplink transmission via ISS.
     */
    std::vector<float> processVoiceUplink(const std::vector<float>& audio);
    
    /**
     * @brief Process voice downlink
     * 
     * @param audio Input audio samples
     * @return Processed received audio
     * 
     * @details
     * Processes received audio from ISS downlink.
     */
    std::vector<float> processVoiceDownlink(const std::vector<float>& audio);
    
    /**
     * @brief Check voice repeater status
     * 
     * @return true if voice repeater is active, false otherwise
     * 
     * @details
     * Checks if the voice repeater is currently active.
     */
    bool isVoiceRepeaterActive() const;
    
    // APRS operations
    
    /**
     * @brief Send APRS message
     * 
     * @param message APRS message
     * @return true if message sent successfully, false otherwise
     * 
     * @details
     * Sends an APRS message via ISS.
     */
    bool sendAPRSMessage(const APRSMessage& message);
    
    /**
     * @brief Receive APRS messages
     * 
     * @return Vector of received APRS messages
     * 
     * @details
     * Retrieves received APRS messages from ISS.
     */
    std::vector<APRSMessage> receiveAPRSMessages();
    
    /**
     * @brief Check APRS digipeater status
     * 
     * @return true if APRS digipeater is active, false otherwise
     * 
     * @details
     * Checks if the APRS digipeater is currently active.
     */
    bool isAPRSDigipeaterActive() const;
    
    // Packet operations
    
    /**
     * @brief Send packet data
     * 
     * @param data Packet data
     * @return true if packet sent successfully, false otherwise
     * 
     * @details
     * Sends packet data via ISS.
     */
    bool sendPacketData(const std::vector<uint8_t>& data);
    
    /**
     * @brief Receive packet data
     * 
     * @return Vector of received packet data
     * 
     * @details
     * Retrieves received packet data from ISS.
     */
    std::vector<uint8_t> receivePacketData();
    
    /**
     * @brief Check packet radio status
     * 
     * @return true if packet radio is active, false otherwise
     * 
     * @details
     * Checks if the packet radio is currently active.
     */
    bool isPacketRadioActive() const;
    
    // Configuration
    
    /**
     * @brief Set operation mode
     * 
     * @param mode Operation mode
     * @return true if mode set successfully, false otherwise
     * 
     * @details
     * Sets the operation mode for ISS.
     */
    bool setMode(ISSMode mode);
    
    /**
     * @brief Set service type
     * 
     * @param service Service type
     * @return true if service set successfully, false otherwise
     * 
     * @details
     * Sets the service type for ISS.
     */
    bool setService(ISSService service);
    
    /**
     * @brief Set crew status
     * 
     * @param active Crew active status
     * @return true if status set successfully, false otherwise
     * 
     * @details
     * Sets the crew active status for ISS.
     */
    bool setCrewStatus(bool active);
    
    /**
     * @brief Enable APRS
     * 
     * @param enabled Enable APRS
     * @param callsign APRS callsign
     * @return true if APRS enabled successfully, false otherwise
     * 
     * @details
     * Enables or disables APRS with the specified callsign.
     */
    bool enableAPRS(bool enabled, const std::string& callsign = "");
    
    // Status and diagnostics
    
    /**
     * @brief Check if system is initialized
     * 
     * @return true if initialized, false otherwise
     * 
     * @details
     * Returns the initialization status of the ISS system.
     */
    bool isInitialized() const;
    
    /**
     * @brief Get system status
     * 
     * @return Status string
     * 
     * @details
     * Returns a string describing the current status of the
     * ISS system.
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
    ISSConfig getCurrentConfig() const;
    
    /**
     * @brief Get crew status
     * 
     * @return Crew active status
     * 
     * @details
     * Returns the current crew active status.
     */
    bool getCrewStatus() const;
    
    /**
     * @brief Get available modes
     * 
     * @return Vector of available modes
     * 
     * @details
     * Returns a list of all available operation modes.
     */
    std::vector<ISSMode> getAvailableModes() const;
    
    /**
     * @brief Get available services
     * 
     * @return Vector of available services
     * 
     * @details
     * Returns a list of all available service types.
     */
    std::vector<ISSService> getAvailableServices() const;
    
    /**
     * @brief Get performance metrics
     * 
     * @return Performance metrics string
     * 
     * @details
     * Returns performance metrics for the ISS system.
     */
    std::string getPerformanceMetrics() const;
};

/**
 * @namespace ISSUtils
 * @brief Utility functions for ISS system
 * 
 * @details
 * This namespace contains utility functions for the ISS
 * system, including APRS processing, packet handling,
 * and crew status management.
 * 
 * @since 1.0.0
 */
namespace ISSUtils {
    
    /**
     * @brief Format APRS message
     * 
     * @param message APRS message
     * @return Formatted APRS string
     * 
     * @details
     * Formats an APRS message for transmission.
     */
    std::string formatAPRSMessage(const APRSMessage& message);
    
    /**
     * @brief Parse APRS message
     * 
     * @param data APRS data string
     * @return Parsed APRS message
     * 
     * @details
     * Parses an APRS message from received data.
     */
    APRSMessage parseAPRSMessage(const std::string& data);
    
    /**
     * @brief Get mode name
     * 
     * @param mode Operation mode
     * @return Mode name string
     * 
     * @details
     * Returns the human-readable name of the mode.
     */
    std::string getModeName(ISSMode mode);
    
    /**
     * @brief Get service name
     * 
     * @param service Service type
     * @return Service name string
     * 
     * @details
     * Returns the human-readable name of the service.
     */
    std::string getServiceName(ISSService service);
    
    /**
     * @brief Validate configuration
     * 
     * @param config Configuration to validate
     * @return true if configuration is valid, false otherwise
     * 
     * @details
     * Validates that a configuration meets all requirements.
     */
    bool validateConfiguration(const ISSConfig& config);
    
    /**
     * @brief Check crew schedule
     * 
     * @param time Current time
     * @return Crew active status
     * 
     * @details
     * Checks if crew is scheduled to be active at the specified time.
     */
    bool checkCrewSchedule(std::chrono::system_clock::time_point time);
    
    /**
     * @brief Calculate pass duration
     * 
     * @param latitude Ground station latitude
     * @param longitude Ground station longitude
     * @return Pass duration in minutes
     * 
     * @details
     * Calculates the ISS pass duration for the ground station.
     */
    double calculatePassDuration(double latitude, double longitude);
    
    /**
     * @brief Format callsign
     * 
     * @param callsign Callsign
     * @return Formatted callsign string
     * 
     * @details
     * Formats a callsign for APRS transmission.
     */
    std::string formatCallsign(const std::string& callsign);
    
    /**
     * @brief Validate callsign
     * 
     * @param callsign Callsign to validate
     * @return true if callsign is valid, false otherwise
     * 
     * @details
     * Validates that a callsign meets amateur radio standards.
     */
    bool validateCallsign(const std::string& callsign);
}

} // namespace amateur
} // namespace satellites
} // namespace fgcom

#endif // ISS_H
