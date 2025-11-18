/**
 * @file fltsatcom.h
 * @brief FLTSATCOM Series Military Satellite System
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains the implementation of the FLTSATCOM series military
 * satellite system for US Navy communications and tactical operations.
 * 
 * @details
 * FLTSATCOM provides:
 * - GEO (Geostationary) satellite communications
 * - UHF military band (240-320 MHz)
 * - US Navy communications
 * - Tactical military operations
 * - TLE-based orbital calculations
 * 
 * @see https://github.com/Supermagnum/fgcom-mumble
 * @see docs/FLTSATCOM_DOCUMENTATION.md
 */

#ifndef FLTSATCOM_H
#define FLTSATCOM_H

#include <vector>
#include <memory>
#include <string>
#include <cstdint>
#include <chrono>
#include <map>

namespace fgcom {
namespace satellites {
namespace military {

/**
 * @enum FLTSATCOMChannel
 * @brief FLTSATCOM communication channels
 * 
 * @details
 * This enumeration defines the available communication channels
 * for FLTSATCOM operations.
 */
enum class FLTSATCOMChannel {
    CHANNEL_1,          ///< Channel 1 (240-250 MHz)
    CHANNEL_2,          ///< Channel 2 (250-260 MHz)
    CHANNEL_3,          ///< Channel 3 (260-270 MHz)
    CHANNEL_4,          ///< Channel 4 (270-280 MHz)
    CHANNEL_5,          ///< Channel 5 (280-290 MHz)
    CHANNEL_6,          ///< Channel 6 (290-300 MHz)
    CHANNEL_7,          ///< Channel 7 (300-310 MHz)
    CHANNEL_8,          ///< Channel 8 (310-320 MHz)
    EMERGENCY,          ///< Emergency channel
    COMMAND             ///< Command channel
};

/**
 * @enum FLTSATCOMService
 * @brief FLTSATCOM service types
 * 
 * @details
 * This enumeration defines the available service types
 * for FLTSATCOM operations.
 */
enum class FLTSATCOMService {
    VOICE_COMMUNICATION,    ///< Voice communication
    DATA_TRANSMISSION,      ///< Data transmission
    TELEMETRY,             ///< Telemetry data
    COMMAND_CONTROL,        ///< Command and control
    EMERGENCY_SERVICES,     ///< Emergency services
    TACTICAL_OPERATIONS     ///< Tactical operations
};

/**
 * @struct FLTSATCOMConfig
 * @brief FLTSATCOM configuration structure
 * 
 * @details
 * This structure contains the configuration parameters
 * for FLTSATCOM operations.
 */
struct FLTSATCOMConfig {
    FLTSATCOMChannel channel;      ///< Communication channel
    FLTSATCOMService service;       ///< Service type
    double frequency;               ///< Operating frequency (MHz)
    double bandwidth;               ///< Channel bandwidth (MHz)
    uint32_t power_level;          ///< Transmit power level
    bool encryption_enabled;        ///< Encryption enabled
    std::string encryption_key;     ///< Encryption key
    uint32_t priority;             ///< Communication priority
    bool secure_mode;              ///< Secure mode enabled
};

/**
 * @class FLTSATCOM
 * @brief FLTSATCOM Military Satellite System Implementation
 * 
 * @details
 * The FLTSATCOM class implements the complete FLTSATCOM military
 * satellite system with GEO communications capabilities.
 * 
 * ## Technical Specifications
 * - **Orbit**: GEO (Geostationary)
 * - **Frequencies**: 240-320 MHz UHF military band
 * - **Use Case**: US Navy communications
 * - **Channels**: 8 primary channels + emergency + command
 * - **Services**: Voice, Data, Telemetry, Command, Emergency, Tactical
 * - **Coverage**: Global coverage from GEO
 * 
 * ## Usage Example
 * @code
 * #include "fltsatcom.h"
 * 
 * // Create FLTSATCOM instance
 * FLTSATCOM fltsatcom;
 * 
 * // Initialize with ground station location
 * fltsatcom.initialize(40.7128, -74.0060);
 * 
 * // Load TLE data
 * fltsatcom.loadTLE("fltsatcom.tle");
 * 
 * // Configure communication
 * FLTSATCOMConfig config;
 * config.channel = FLTSATCOMChannel::CHANNEL_1;
 * config.service = FLTSATCOMService::VOICE_COMMUNICATION;
 * fltsatcom.configure(config);
 * @endcode
 * 
 * @note This class provides a unified interface for FLTSATCOM operations.
 * 
 * @since 1.0.0
 * @version 1.0.0
 */
class FLTSATCOM {
private:
    bool initialized_;                  ///< System initialization status
    
    // Ground station parameters
    double ground_latitude_;           ///< Ground station latitude
    double ground_longitude_;          ///< Ground station longitude
    double ground_altitude_;           ///< Ground station altitude (m)
    
    // Satellite parameters
    std::string current_satellite_;    ///< Current satellite name
    FLTSATCOMConfig current_config_;   ///< Current configuration
    
    // Communication parameters
    bool secure_mode_enabled_;         ///< Secure mode enabled
    std::string encryption_key_;       ///< Current encryption key
    uint32_t communication_priority_; ///< Communication priority
    
    // Processing buffers
    std::vector<float> input_buffer_;  ///< Input audio buffer
    std::vector<float> output_buffer_; ///< Output audio buffer
    
public:
    /**
     * @brief Default constructor
     * 
     * @details
     * Initializes the FLTSATCOM system with default parameters.
     */
    FLTSATCOM();
    
    /**
     * @brief Virtual destructor
     * 
     * @details
     * Cleans up all resources used by the FLTSATCOM system.
     */
    virtual ~FLTSATCOM();
    
    // Initialization and configuration
    
    /**
     * @brief Initialize the FLTSATCOM system
     * 
     * @param latitude Ground station latitude
     * @param longitude Ground station longitude
     * @param altitude Ground station altitude in meters
     * @return true if initialization successful, false otherwise
     * 
     * @details
     * Initializes the FLTSATCOM system with the specified
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
     * @brief Configure FLTSATCOM system
     * 
     * @param config Configuration parameters
     * @return true if configuration successful, false otherwise
     * 
     * @details
     * Configures the FLTSATCOM system with the specified parameters.
     */
    bool configure(const FLTSATCOMConfig& config);
    
    // Communication operations
    
    /**
     * @brief Transmit voice
     * 
     * @param audio Input audio samples
     * @return Processed audio for transmission
     * 
     * @details
     * Processes audio for transmission via FLTSATCOM.
     */
    std::vector<float> transmitVoice(const std::vector<float>& audio);
    
    /**
     * @brief Receive voice
     * 
     * @param audio Input audio samples
     * @return Processed received audio
     * 
     * @details
     * Processes received audio from FLTSATCOM.
     */
    std::vector<float> receiveVoice(const std::vector<float>& audio);
    
    /**
     * @brief Transmit data
     * 
     * @param data Input data
     * @return Processed data for transmission
     * 
     * @details
     * Processes data for transmission via FLTSATCOM.
     */
    std::vector<uint8_t> transmitData(const std::vector<uint8_t>& data);
    
    /**
     * @brief Receive data
     * 
     * @param data Input data
     * @return Processed received data
     * 
     * @details
     * Processes received data from FLTSATCOM.
     */
    std::vector<uint8_t> receiveData(const std::vector<uint8_t>& data);
    
    /**
     * @brief Send telemetry
     * 
     * @param telemetry_data Telemetry data
     * @return true if telemetry sent successfully, false otherwise
     * 
     * @details
     * Sends telemetry data via FLTSATCOM.
     */
    bool sendTelemetry(const std::string& telemetry_data);
    
    /**
     * @brief Send command
     * 
     * @param command Command data
     * @return true if command sent successfully, false otherwise
     * 
     * @details
     * Sends command data via FLTSATCOM.
     */
    bool sendCommand(const std::string& command);
    
    // Configuration
    
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
     * @brief Set communication channel
     * 
     * @param channel Communication channel
     * @return true if channel set successfully, false otherwise
     * 
     * @details
     * Sets the communication channel.
     */
    bool setChannel(FLTSATCOMChannel channel);
    
    /**
     * @brief Set service type
     * 
     * @param service Service type
     * @return true if service set successfully, false otherwise
     * 
     * @details
     * Sets the service type.
     */
    bool setService(FLTSATCOMService service);
    
    /**
     * @brief Enable secure mode
     * 
     * @param enabled Enable secure mode
     * @param key Encryption key
     * @return true if secure mode enabled successfully, false otherwise
     * 
     * @details
     * Enables or disables secure mode with encryption.
     */
    bool enableSecureMode(bool enabled, const std::string& key = "");
    
    /**
     * @brief Set communication priority
     * 
     * @param priority Communication priority (1-10)
     * @return true if priority set successfully, false otherwise
     * 
     * @details
     * Sets the communication priority.
     */
    bool setPriority(uint32_t priority);
    
    // Status and diagnostics
    
    /**
     * @brief Check if system is initialized
     * 
     * @return true if initialized, false otherwise
     * 
     * @details
     * Returns the initialization status of the FLTSATCOM system.
     */
    bool isInitialized() const;
    
    /**
     * @brief Get system status
     * 
     * @return Status string
     * 
     * @details
     * Returns a string describing the current status of the
     * FLTSATCOM system.
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
    FLTSATCOMConfig getCurrentConfig() const;
    
    /**
     * @brief Get available channels
     * 
     * @return Vector of available channels
     * 
     * @details
     * Returns a list of all available communication channels.
     */
    std::vector<FLTSATCOMChannel> getAvailableChannels() const;
    
    /**
     * @brief Get available services
     * 
     * @return Vector of available services
     * 
     * @details
     * Returns a list of all available service types.
     */
    std::vector<FLTSATCOMService> getAvailableServices() const;
    
    /**
     * @brief Get performance metrics
     * 
     * @return Performance metrics string
     * 
     * @details
     * Returns performance metrics for the FLTSATCOM system.
     */
    std::string getPerformanceMetrics() const;
};

/**
 * @namespace FLTSATCOMUtils
 * @brief Utility functions for FLTSATCOM system
 * 
 * @details
 * This namespace contains utility functions for the FLTSATCOM
 * system, including channel management, encryption, and
 * communication operations.
 * 
 * @since 1.0.0
 */
namespace FLTSATCOMUtils {
    
    /**
     * @brief Get channel frequency
     * 
     * @param channel Communication channel
     * @return Channel frequency in MHz
     * 
     * @details
     * Returns the frequency for the specified channel.
     */
    double getChannelFrequency(FLTSATCOMChannel channel);
    
    /**
     * @brief Get channel bandwidth
     * 
     * @param channel Communication channel
     * @return Channel bandwidth in MHz
     * 
     * @details
     * Returns the bandwidth for the specified channel.
     */
    double getChannelBandwidth(FLTSATCOMChannel channel);
    
    /**
     * @brief Get channel name
     * 
     * @param channel Communication channel
     * @return Channel name string
     * 
     * @details
     * Returns the human-readable name of the channel.
     */
    std::string getChannelName(FLTSATCOMChannel channel);
    
    /**
     * @brief Get service name
     * 
     * @param service Service type
     * @return Service name string
     * 
     * @details
     * Returns the human-readable name of the service.
     */
    std::string getServiceName(FLTSATCOMService service);
    
    /**
     * @brief Validate configuration
     * 
     * @param config Configuration to validate
     * @return true if configuration is valid, false otherwise
     * 
     * @details
     * Validates that a configuration meets all requirements.
     */
    bool validateConfiguration(const FLTSATCOMConfig& config);
    
    /**
     * @brief Encrypt data
     * 
     * @param data Data to encrypt
     * @param key Encryption key
     * @return Encrypted data
     * 
     * @details
     * Encrypts data using the specified key.
     */
    std::vector<uint8_t> encryptData(const std::vector<uint8_t>& data, const std::string& key);
    
    /**
     * @brief Decrypt data
     * 
     * @param data Encrypted data
     * @param key Encryption key
     * @return Decrypted data
     * 
     * @details
     * Decrypts data using the specified key.
     */
    std::vector<uint8_t> decryptData(const std::vector<uint8_t>& data, const std::string& key);
    
    /**
     * @brief Format telemetry data
     * 
     * @param telemetry_data Telemetry data
     * @return Formatted telemetry string
     * 
     * @details
     * Formats telemetry data for transmission.
     */
    std::string formatTelemetry(const std::string& telemetry_data);
    
    /**
     * @brief Parse received telemetry
     * 
     * @param data Received telemetry data
     * @return Parsed telemetry string
     * 
     * @details
     * Parses received telemetry data.
     */
    std::string parseTelemetry(const std::string& data);
}

} // namespace military
} // namespace satellites
} // namespace fgcom

#endif // FLTSATCOM_H
