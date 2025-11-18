/**
 * @file gonets.h
 * @brief Gonets Russian LEO Data/IoT Satellite System
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains the implementation of the Gonets satellite
 * system for Russian store-and-forward messaging and IoT applications.
 * 
 * @details
 * Gonets provides:
 * - LEO data communications
 * - Store-and-forward messaging
 * - IoT data transmission
 * - Russian equivalent to Orbcomm
 * - Frequencies: 387-390 MHz
 * - Orbit: ~1400 km LEO
 * 
 * @see https://github.com/Supermagnum/fgcom-mumble
 * @see docs/GONETS_DOCUMENTATION.md
 */

#ifndef GONETS_H
#define GONETS_H

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
 * @enum GonetsMessageType
 * @brief Gonets message types
 * 
 * @details
 * This enumeration defines the available message types
 * for Gonets operations.
 */
enum class GonetsMessageType {
    STORE_FORWARD,         ///< Store-and-forward message
    IOT_SENSOR_DATA,       ///< IoT sensor data
    TELEMETRY,             ///< Telemetry data
    STATUS_REPORT,         ///< Status report
    COMMAND_MESSAGE,       ///< Command message
    EMERGENCY_MESSAGE,     ///< Emergency message
    ROUTINE_MESSAGE,       ///< Routine message
    DATA_TRANSMISSION      ///< Data transmission
};

/**
 * @enum GonetsService
 * @brief Gonets service types
 * 
 * @details
 * This enumeration defines the available service types
 * for Gonets operations.
 */
enum class GonetsService {
    STORE_FORWARD_SERVICE, ///< Store-and-forward service
    IOT_SERVICE,           ///< IoT service
    TELEMETRY_SERVICE,     ///< Telemetry service
    COMMAND_SERVICE,       ///< Command service
    EMERGENCY_SERVICE,     ///< Emergency service
    ROUTINE_SERVICE,       ///< Routine service
    DATA_SERVICE           ///< Data service
};

/**
 * @struct GonetsMessage
 * @brief Gonets message structure
 * 
 * @details
 * This structure contains a complete Gonets message
 * with all necessary metadata.
 */
struct GonetsMessage {
    std::string message_id;         ///< Unique message identifier
    GonetsMessageType type;         ///< Message type
    GonetsService service;          ///< Service type
    std::string sender_id;          ///< Sender identifier
    std::string recipient_id;       ///< Recipient identifier
    std::string content;            ///< Message content
    std::vector<uint8_t> data;      ///< Binary data payload
    std::chrono::system_clock::time_point timestamp; ///< Message timestamp
    uint32_t priority;              ///< Message priority (1-10)
    bool encrypted;                 ///< Whether message is encrypted
    std::string encryption_key;     ///< Encryption key identifier
    bool delivered;                 ///< Whether message has been delivered
    std::chrono::system_clock::time_point delivery_time; ///< Delivery timestamp
    bool store_forward;             ///< Whether message is store-and-forward
    std::string forward_path;       ///< Forward path for store-and-forward
};

/**
 * @struct GonetsConfig
 * @brief Gonets configuration structure
 * 
 * @details
 * This structure contains the configuration parameters
 * for Gonets operations.
 */
struct GonetsConfig {
    GonetsService service;          ///< Service type
    double frequency;               ///< Operating frequency (MHz)
    uint32_t data_rate;            ///< Data rate (bps)
    bool encryption_enabled;        ///< Encryption enabled
    std::string encryption_key;     ///< Encryption key
    uint32_t priority;             ///< Communication priority
    bool store_forward_enabled;     ///< Store-and-forward enabled
    bool iot_mode;                 ///< IoT mode enabled
    bool telemetry_enabled;        ///< Telemetry enabled
};

/**
 * @class Gonets
 * @brief Gonets Russian LEO Data/IoT Satellite System Implementation
 * 
 * @details
 * The Gonets class implements the complete Gonets satellite
 * system with store-and-forward messaging and IoT capabilities.
 * 
 * ## Technical Specifications
 * - **Frequencies**: 387-390 MHz
 * - **Orbit**: ~1400 km LEO
 * - **Use Cases**: Store-and-forward messaging, IoT, Telemetry
 * - **Message Types**: Store-forward, IoT, Telemetry, Status, Command, Emergency, Routine, Data
 * - **Services**: Store-forward, IoT, Telemetry, Command, Emergency, Routine, Data
 * - **TLE Available**: Yes
 * - **Russian equivalent to Orbcomm**
 * 
 * ## Usage Example
 * @code
 * #include "gonets.h"
 * 
 * // Create Gonets instance
 * Gonets gonets;
 * 
 * // Initialize with ground station location
 * gonets.initialize(55.7558, 37.6176); // Moscow
 * 
 * // Load TLE data
 * gonets.loadTLE("gonets.tle");
 * 
 * // Configure for store-and-forward
 * GonetsConfig config;
 * config.service = GonetsService::STORE_FORWARD_SERVICE;
 * config.store_forward_enabled = true;
 * gonets.configure(config);
 * @endcode
 * 
 * @note This class provides a unified interface for Gonets operations.
 * 
 * @since 1.0.0
 * @version 1.0.0
 */
class Gonets {
private:
    bool initialized_;                  ///< System initialization status
    
    // Ground station parameters
    double ground_latitude_;           ///< Ground station latitude
    double ground_longitude_;          ///< Ground station longitude
    double ground_altitude_;           ///< Ground station altitude (m)
    
    // Satellite parameters
    std::string current_satellite_;    ///< Current satellite name
    GonetsConfig current_config_;      ///< Current configuration
    
    // Message storage
    std::map<std::string, GonetsMessage> message_storage_; ///< Message storage
    std::vector<std::string> message_queue_; ///< Message queue
    std::vector<std::string> store_forward_queue_; ///< Store-and-forward queue
    
    // Service parameters
    bool store_forward_enabled_;      ///< Store-and-forward enabled
    bool iot_mode_enabled_;           ///< IoT mode enabled
    bool telemetry_enabled_;          ///< Telemetry enabled
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
     * Initializes the Gonets system with default parameters.
     */
    Gonets();
    
    /**
     * @brief Virtual destructor
     * 
     * @details
     * Cleans up all resources used by the Gonets system.
     */
    virtual ~Gonets();
    
    // Initialization and configuration
    
    /**
     * @brief Initialize the Gonets system
     * 
     * @param latitude Ground station latitude
     * @param longitude Ground station longitude
     * @param altitude Ground station altitude in meters
     * @return true if initialization successful, false otherwise
     * 
     * @details
     * Initializes the Gonets system with the specified
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
     * @brief Configure Gonets system
     * 
     * @param config Configuration parameters
     * @return true if configuration successful, false otherwise
     * 
     * @details
     * Configures the Gonets system with the specified parameters.
     */
    bool configure(const GonetsConfig& config);
    
    // Message operations
    
    /**
     * @brief Send message
     * 
     * @param message Message to send
     * @return true if message sent successfully, false otherwise
     * 
     * @details
     * Sends a message via the Gonets satellite system.
     */
    bool sendMessage(const GonetsMessage& message);
    
    /**
     * @brief Receive messages
     * 
     * @param recipient_id Recipient identifier
     * @return Vector of received messages
     * 
     * @details
     * Retrieves messages for the specified recipient.
     */
    std::vector<GonetsMessage> receiveMessages(const std::string& recipient_id);
    
    /**
     * @brief Send store-and-forward message
     * 
     * @param message Store-and-forward message
     * @param forward_path Forward path
     * @return true if message sent successfully, false otherwise
     * 
     * @details
     * Sends a store-and-forward message via Gonets.
     */
    bool sendStoreForwardMessage(const GonetsMessage& message, const std::string& forward_path);
    
    /**
     * @brief Process store-and-forward queue
     * 
     * @return Number of messages processed
     * 
     * @details
     * Processes the store-and-forward message queue.
     */
    uint32_t processStoreForwardQueue();
    
    /**
     * @brief Send IoT sensor data
     * 
     * @param sensor_id Sensor identifier
     * @param sensor_data Sensor data
     * @param timestamp Data timestamp
     * @return true if sensor data sent successfully, false otherwise
     * 
     * @details
     * Sends IoT sensor data via Gonets.
     */
    bool sendIoTSensorData(const std::string& sensor_id,
                          const std::vector<uint8_t>& sensor_data,
                          std::chrono::system_clock::time_point timestamp);
    
    /**
     * @brief Send telemetry data
     * 
     * @param telemetry_id Telemetry identifier
     * @param telemetry_data Telemetry data
     * @param timestamp Data timestamp
     * @return true if telemetry sent successfully, false otherwise
     * 
     * @details
     * Sends telemetry data via Gonets.
     */
    bool sendTelemetryData(const std::string& telemetry_id,
                          const std::string& telemetry_data,
                          std::chrono::system_clock::time_point timestamp);
    
    /**
     * @brief Send emergency message
     * 
     * @param emergency_id Emergency identifier
     * @param emergency_data Emergency data
     * @param priority Emergency priority
     * @return true if emergency message sent successfully, false otherwise
     * 
     * @details
     * Sends an emergency message via Gonets.
     */
    bool sendEmergencyMessage(const std::string& emergency_id,
                             const std::string& emergency_data,
                             uint32_t priority);
    
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
     * Sets the service type for Gonets.
     */
    bool setService(GonetsService service);
    
    /**
     * @brief Enable store-and-forward
     * 
     * @param enabled Enable store-and-forward
     * @return true if store-and-forward enabled successfully, false otherwise
     * 
     * @details
     * Enables or disables store-and-forward messaging.
     */
    bool enableStoreForward(bool enabled);
    
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
     * @brief Enable telemetry
     * 
     * @param enabled Enable telemetry
     * @return true if telemetry enabled successfully, false otherwise
     * 
     * @details
     * Enables or disables telemetry transmission.
     */
    bool enableTelemetry(bool enabled);
    
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
     * Returns the initialization status of the Gonets system.
     */
    bool isInitialized() const;
    
    /**
     * @brief Get system status
     * 
     * @return Status string
     * 
     * @details
     * Returns a string describing the current status of the
     * Gonets system.
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
    GonetsConfig getCurrentConfig() const;
    
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
     * @brief Get store-and-forward queue size
     * 
     * @return Number of store-and-forward messages
     * 
     * @details
     * Returns the number of messages in the store-and-forward queue.
     */
    uint32_t getStoreForwardQueueSize() const;
    
    /**
     * @brief Get available services
     * 
     * @return Vector of available services
     * 
     * @details
     * Returns a list of all available service types.
     */
    std::vector<GonetsService> getAvailableServices() const;
    
    /**
     * @brief Get performance metrics
     * 
     * @return Performance metrics string
     * 
     * @details
     * Returns performance metrics for the Gonets system.
     */
    std::string getPerformanceMetrics() const;
};

/**
 * @namespace GonetsUtils
 * @brief Utility functions for Gonets system
 * 
 * @details
 * This namespace contains utility functions for the Gonets
 * system, including message processing, encryption, and
 * satellite operations.
 * 
 * @since 1.0.0
 */
namespace GonetsUtils {
    
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
    GonetsMessage encryptMessage(const GonetsMessage& message, const std::string& key);
    
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
    GonetsMessage decryptMessage(const GonetsMessage& message, const std::string& key);
    
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
    bool validateMessage(const GonetsMessage& message);
    
    /**
     * @brief Get message type name
     * 
     * @param type Message type
     * @return Type name string
     * 
     * @details
     * Returns the human-readable name of the message type.
     */
    std::string getMessageTypeName(GonetsMessageType type);
    
    /**
     * @brief Get service name
     * 
     * @param service Service type
     * @return Service name string
     * 
     * @details
     * Returns the human-readable name of the service.
     */
    std::string getServiceName(GonetsService service);
    
    /**
     * @brief Format message for transmission
     * 
     * @param message Message to format
     * @return Formatted message string
     * 
     * @details
     * Formats a message for transmission over the satellite link.
     */
    std::string formatMessage(const GonetsMessage& message);
    
    /**
     * @brief Parse received message
     * 
     * @param data Received message data
     * @return Parsed message
     * 
     * @details
     * Parses a received message from satellite data.
     */
    GonetsMessage parseMessage(const std::string& data);
    
    /**
     * @brief Process store-and-forward path
     * 
     * @param forward_path Forward path string
     * @return Processed forward path
     * 
     * @details
     * Processes a store-and-forward path for routing.
     */
    std::string processForwardPath(const std::string& forward_path);
    
    /**
     * @brief Validate store-and-forward message
     * 
     * @param message Message to validate
     * @return true if message is valid for store-and-forward, false otherwise
     * 
     * @details
     * Validates that a message is suitable for store-and-forward.
     */
    bool validateStoreForwardMessage(const GonetsMessage& message);
}

} // namespace iot
} // namespace satellites
} // namespace fgcom

#endif // GONETS_H
