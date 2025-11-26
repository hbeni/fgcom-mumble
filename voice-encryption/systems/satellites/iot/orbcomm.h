/**
 * @file orbcomm.h
 * @brief Orbcomm LEO Data/IoT Satellite System
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains the implementation of the Orbcomm satellite
 * system for machine-to-machine communications, asset tracking,
 * and maritime applications.
 * 
 * @details
 * Orbcomm provides:
 * - LEO data communications
 * - Machine-to-machine (M2M) communications
 * - Asset tracking and monitoring
 * - Maritime communications
 * - IoT data transmission
 * - Frequencies: 137-138 MHz downlink, 148-150.05 MHz uplink
 * - Orbit: ~700-800 km LEO
 * 
 * @see https://github.com/Supermagnum/fgcom-mumble
 * @see docs/ORBCOMM_DOCUMENTATION.md
 */

#ifndef ORBCOMM_H
#define ORBCOMM_H

#include <vector>
#include <memory>
#include <string>
#include <cstdint>
#include <chrono>
#include <map>

namespace fgcom {
namespace satellites {
namespace iot {

/**
 * @enum OrbcommMessageType
 * @brief Orbcomm message types
 * 
 * @details
 * This enumeration defines the available message types
 * for Orbcomm operations.
 */
enum class OrbcommMessageType {
    DATA_TRANSMISSION,      ///< Data transmission
    ASSET_TRACKING,         ///< Asset tracking data
    MARITIME_DATA,          ///< Maritime data
    IOT_SENSOR_DATA,        ///< IoT sensor data
    MACHINE_TO_MACHINE,     ///< Machine-to-machine communication
    TELEMETRY,              ///< Telemetry data
    COMMAND,                ///< Command message
    STATUS_REPORT           ///< Status report
};

/**
 * @enum OrbcommService
 * @brief Orbcomm service types
 * 
 * @details
 * This enumeration defines the available service types
 * for Orbcomm operations.
 */
enum class OrbcommService {
    DATA_SERVICE,           ///< Data service
    TRACKING_SERVICE,     ///< Tracking service
    MARITIME_SERVICE,       ///< Maritime service
    IOT_SERVICE,           ///< IoT service
    M2M_SERVICE,           ///< Machine-to-machine service
    TELEMETRY_SERVICE,      ///< Telemetry service
    COMMAND_SERVICE,        ///< Command service
    EMERGENCY_SERVICE       ///< Emergency service
};

/**
 * @struct OrbcommMessage
 * @brief Orbcomm message structure
 * 
 * @details
 * This structure contains a complete Orbcomm message
 * with all necessary metadata.
 */
struct OrbcommMessage {
    std::string message_id;         ///< Unique message identifier
    OrbcommMessageType type;         ///< Message type
    OrbcommService service;          ///< Service type
    std::string sender_id;           ///< Sender identifier
    std::string recipient_id;        ///< Recipient identifier
    std::string content;             ///< Message content
    std::vector<uint8_t> data;       ///< Binary data payload
    std::chrono::system_clock::time_point timestamp; ///< Message timestamp
    uint32_t priority;               ///< Message priority (1-10)
    bool encrypted;                  ///< Whether message is encrypted
    std::string encryption_key;       ///< Encryption key identifier
    bool delivered;                  ///< Whether message has been delivered
    std::chrono::system_clock::time_point delivery_time; ///< Delivery timestamp
    double latitude;                 ///< Latitude (for tracking)
    double longitude;                ///< Longitude (for tracking)
    double altitude;                 ///< Altitude (for tracking)
};

/**
 * @struct OrbcommConfig
 * @brief Orbcomm configuration structure
 * 
 * @details
 * This structure contains the configuration parameters
 * for Orbcomm operations.
 */
struct OrbcommConfig {
    OrbcommService service;          ///< Service type
    double uplink_frequency;         ///< Uplink frequency (MHz)
    double downlink_frequency;       ///< Downlink frequency (MHz)
    uint32_t data_rate;              ///< Data rate (bps)
    bool encryption_enabled;         ///< Encryption enabled
    std::string encryption_key;      ///< Encryption key
    uint32_t priority;               ///< Communication priority
    bool tracking_enabled;           ///< Asset tracking enabled
    bool maritime_mode;              ///< Maritime mode enabled
    bool iot_mode;                   ///< IoT mode enabled
};

/**
 * @class Orbcomm
 * @brief Orbcomm LEO Data/IoT Satellite System Implementation
 * 
 * @details
 * The Orbcomm class implements the complete Orbcomm satellite
 * system with machine-to-machine communications and IoT capabilities.
 * 
 * ## Technical Specifications
 * - **Frequencies**: 137-138 MHz downlink, 148-150.05 MHz uplink
 * - **Orbit**: ~700-800 km LEO
 * - **Use Cases**: M2M communications, asset tracking, maritime, IoT
 * - **Message Types**: Data, Tracking, Maritime, IoT, M2M, Telemetry, Command, Status
 * - **Services**: Data, Tracking, Maritime, IoT, M2M, Telemetry, Command, Emergency
 * - **TLE Available**: Yes - search "Orbcomm" on Space-Track
 * - **NORAD Examples**: 23545, 25112, 25113, 25114, etc.
 * 
 * ## Usage Example
 * @code
 * #include "orbcomm.h"
 * 
 * // Create Orbcomm instance
 * Orbcomm orbcomm;
 * 
 * // Initialize with ground station location
 * orbcomm.initialize(40.7128, -74.0060);
 * 
 * // Load TLE data
 * orbcomm.loadTLE("orbcomm.tle");
 * 
 * // Configure for asset tracking
 * OrbcommConfig config;
 * config.service = OrbcommService::TRACKING_SERVICE;
 * config.tracking_enabled = true;
 * orbcomm.configure(config);
 * @endcode
 * 
 * @note This class provides a unified interface for Orbcomm operations.
 * 
 * @since 1.0.0
 * @version 1.0.0
 */
class Orbcomm {
private:
    bool initialized_;                  ///< System initialization status
    
    // Ground station parameters
    double ground_latitude_;           ///< Ground station latitude
    double ground_longitude_;          ///< Ground station longitude
    double ground_altitude_;           ///< Ground station altitude (m)
    
    // Satellite parameters
    std::string current_satellite_;    ///< Current satellite name
    OrbcommConfig current_config_;     ///< Current configuration
    
    // Message storage
    std::map<std::string, OrbcommMessage> message_storage_; ///< Message storage
    std::vector<std::string> message_queue_; ///< Message queue
    
    // Service parameters
    bool tracking_enabled_;            ///< Asset tracking enabled
    bool maritime_mode_enabled_;       ///< Maritime mode enabled
    bool iot_mode_enabled_;            ///< IoT mode enabled
    bool encryption_enabled_;         ///< Encryption enabled
    std::string encryption_key_;       ///< Current encryption key
    
    // Processing buffers
    std::vector<uint8_t> input_buffer_; ///< Input data buffer
    std::vector<uint8_t> output_buffer_; ///< Output data buffer
    
public:
    /**
     * @brief Default constructor
     * 
     * @details
     * Initializes the Orbcomm system with default parameters.
     */
    Orbcomm();
    
    /**
     * @brief Virtual destructor
     * 
     * @details
     * Cleans up all resources used by the Orbcomm system.
     */
    virtual ~Orbcomm();
    
    // Initialization and configuration
    
    /**
     * @brief Initialize the Orbcomm system
     * 
     * @param latitude Ground station latitude
     * @param longitude Ground station longitude
     * @param altitude Ground station altitude in meters
     * @return true if initialization successful, false otherwise
     * 
     * @details
     * Initializes the Orbcomm system with the specified
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
     * @brief Configure Orbcomm system
     * 
     * @param config Configuration parameters
     * @return true if configuration successful, false otherwise
     * 
     * @details
     * Configures the Orbcomm system with the specified parameters.
     */
    bool configure(const OrbcommConfig& config);
    
    // Message operations
    
    /**
     * @brief Send message
     * 
     * @param message Message to send
     * @return true if message sent successfully, false otherwise
     * 
     * @details
     * Sends a message via the Orbcomm satellite system.
     */
    bool sendMessage(const OrbcommMessage& message);
    
    /**
     * @brief Receive messages
     * 
     * @param recipient_id Recipient identifier
     * @return Vector of received messages
     * 
     * @details
     * Retrieves messages for the specified recipient.
     */
    std::vector<OrbcommMessage> receiveMessages(const std::string& recipient_id);
    
    /**
     * @brief Send asset tracking data
     * 
     * @param asset_id Asset identifier
     * @param latitude Asset latitude
     * @param longitude Asset longitude
     * @param altitude Asset altitude
     * @param timestamp Tracking timestamp
     * @return true if tracking data sent successfully, false otherwise
     * 
     * @details
     * Sends asset tracking data via Orbcomm.
     */
    bool sendAssetTracking(const std::string& asset_id, double latitude, 
                          double longitude, double altitude,
                          std::chrono::system_clock::time_point timestamp);
    
    /**
     * @brief Send IoT sensor data
     * 
     * @param sensor_id Sensor identifier
     * @param sensor_data Sensor data
     * @param timestamp Data timestamp
     * @return true if sensor data sent successfully, false otherwise
     * 
     * @details
     * Sends IoT sensor data via Orbcomm.
     */
    bool sendIoTSensorData(const std::string& sensor_id, 
                          const std::vector<uint8_t>& sensor_data,
                          std::chrono::system_clock::time_point timestamp);
    
    /**
     * @brief Send maritime data
     * 
     * @param vessel_id Vessel identifier
     * @param maritime_data Maritime data
     * @param timestamp Data timestamp
     * @return true if maritime data sent successfully, false otherwise
     * 
     * @details
     * Sends maritime data via Orbcomm.
     */
    bool sendMaritimeData(const std::string& vessel_id,
                         const std::string& maritime_data,
                         std::chrono::system_clock::time_point timestamp);
    
    /**
     * @brief Send M2M communication
     * 
     * @param machine_id Machine identifier
     * @param target_machine_id Target machine identifier
     * @param m2m_data M2M data
     * @return true if M2M communication sent successfully, false otherwise
     * 
     * @details
     * Sends machine-to-machine communication via Orbcomm.
     */
    bool sendM2MCommunication(const std::string& machine_id,
                            const std::string& target_machine_id,
                            const std::vector<uint8_t>& m2m_data);
    
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
     * @brief Set service type
     * 
     * @param service Service type
     * @return true if service set successfully, false otherwise
     * 
     * @details
     * Sets the service type for Orbcomm.
     */
    bool setService(OrbcommService service);
    
    /**
     * @brief Enable asset tracking
     * 
     * @param enabled Enable asset tracking
     * @return true if tracking enabled successfully, false otherwise
     * 
     * @details
     * Enables or disables asset tracking.
     */
    bool enableAssetTracking(bool enabled);
    
    /**
     * @brief Enable maritime mode
     * 
     * @param enabled Enable maritime mode
     * @return true if maritime mode enabled successfully, false otherwise
     * 
     * @details
     * Enables or disables maritime mode.
     */
    bool enableMaritimeMode(bool enabled);
    
    /**
     * @brief Enable IoT mode
     * 
     * @param enabled Enable IoT mode
     * @return true if IoT mode enabled successfully, false otherwise
     * 
     * @details
     * Enables or disables IoT mode.
     */
    bool enableIoTMode(bool enabled);
    
    /**
     * @brief Enable encryption
     * 
     * @param enabled Enable encryption
     * @param key Encryption key
     * @return true if encryption enabled successfully, false otherwise
     * 
     * @details
     * Enables or disables message encryption.
     */
    bool enableEncryption(bool enabled, const std::string& key = "");
    
    // Status and diagnostics
    
    /**
     * @brief Check if system is initialized
     * 
     * @return true if initialized, false otherwise
     * 
     * @details
     * Returns the initialization status of the Orbcomm system.
     */
    bool isInitialized() const;
    
    /**
     * @brief Get system status
     * 
     * @return Status string
     * 
     * @details
     * Returns a string describing the current status of the
     * Orbcomm system.
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
    OrbcommConfig getCurrentConfig() const;
    
    /**
     * @brief Get message count
     * 
     * @return Number of stored messages
     * 
     * @details
     * Returns the number of messages currently stored.
     */
    uint32_t getMessageCount() const;
    
    /**
     * @brief Get queue size
     * 
     * @return Number of queued messages
     * 
     * @details
     * Returns the number of messages in the queue.
     */
    uint32_t getQueueSize() const;
    
    /**
     * @brief Get available services
     * 
     * @return Vector of available services
     * 
     * @details
     * Returns a list of all available service types.
     */
    std::vector<OrbcommService> getAvailableServices() const;
    
    /**
     * @brief Get performance metrics
     * 
     * @return Performance metrics string
     * 
     * @details
     * Returns performance metrics for the Orbcomm system.
     */
    std::string getPerformanceMetrics() const;
};

/**
 * @namespace OrbcommUtils
 * @brief Utility functions for Orbcomm system
 * 
 * @details
 * This namespace contains utility functions for the Orbcomm
 * system, including message processing, encryption, and
 * satellite operations.
 * 
 * @since 1.0.0
 */
namespace OrbcommUtils {
    
    /**
     * @brief Encrypt message
     * 
     * @param message Message to encrypt
     * @param key Encryption key
     * @return Encrypted message
     * 
     * @details
     * Encrypts a message using the specified key.
     */
    OrbcommMessage encryptMessage(const OrbcommMessage& message, const std::string& key);
    
    /**
     * @brief Decrypt message
     * 
     * @param message Encrypted message
     * @param key Encryption key
     * @return Decrypted message
     * 
     * @details
     * Decrypts a message using the specified key.
     */
    OrbcommMessage decryptMessage(const OrbcommMessage& message, const std::string& key);
    
    /**
     * @brief Generate message ID
     * 
     * @return Generated message ID
     * 
     * @details
     * Generates a unique message identifier.
     */
    std::string generateMessageId();
    
    /**
     * @brief Validate message
     * 
     * @param message Message to validate
     * @return true if message is valid, false otherwise
     * 
     * @details
     * Validates that a message meets all requirements.
     */
    bool validateMessage(const OrbcommMessage& message);
    
    /**
     * @brief Get message type name
     * 
     * @param type Message type
     * @return Type name string
     * 
     * @details
     * Returns the human-readable name of the message type.
     */
    std::string getMessageTypeName(OrbcommMessageType type);
    
    /**
     * @brief Get service name
     * 
     * @param service Service type
     * @return Service name string
     * 
     * @details
     * Returns the human-readable name of the service.
     */
    std::string getServiceName(OrbcommService service);
    
    /**
     * @brief Format message for transmission
     * 
     * @param message Message to format
     * @return Formatted message string
     * 
     * @details
     * Formats a message for transmission over the satellite link.
     */
    std::string formatMessage(const OrbcommMessage& message);
    
    /**
     * @brief Parse received message
     * 
     * @param data Received message data
     * @return Parsed message
     * 
     * @details
     * Parses a received message from satellite data.
     */
    OrbcommMessage parseMessage(const std::string& data);
    
    /**
     * @brief Calculate data rate
     * 
     * @param message_size Message size in bytes
     * @param transmission_time Transmission time in seconds
     * @return Data rate in bps
     * 
     * @details
     * Calculates the data rate for a message transmission.
     */
    uint32_t calculateDataRate(size_t message_size, double transmission_time);
    
    /**
     * @brief Validate asset tracking data
     * 
     * @param latitude Asset latitude
     * @param longitude Asset longitude
     * @param altitude Asset altitude
     * @return true if tracking data is valid, false otherwise
     * 
     * @details
     * Validates that asset tracking data is within valid ranges.
     */
    bool validateAssetTrackingData(double latitude, double longitude, double altitude);
}

} // namespace iot
} // namespace satellites
} // namespace fgcom

#endif // ORBCOMM_H
