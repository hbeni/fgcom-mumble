/**
 * @file strela_3.h
 * @brief Strela-3 Series Military Satellite System
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains the implementation of the Strela-3 series military
 * satellite system for tactical military messaging and store-and-forward
 * communications.
 * 
 * @details
 * Strela-3 provides:
 * - LEO store-and-forward messaging
 * - Military VHF band (150-174 MHz)
 * - Tactical military communications
 * - Multiple satellite constellation
 * - TLE-based orbital calculations
 * 
 * @see https://github.com/Supermagnum/fgcom-mumble
 * @see docs/STRELA_3_DOCUMENTATION.md
 */

#ifndef STRELA_3_H
#define STRELA_3_H

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
 * @enum Strela3MessageType
 * @brief Strela-3 message types
 * 
 * @details
 * This enumeration defines the available message types
 * for Strela-3 store-and-forward operations.
 */
enum class Strela3MessageType {
    TACTICAL_MESSAGE,   ///< Tactical military message
    STATUS_REPORT,      ///< Status report
    EMERGENCY_MESSAGE,  ///< Emergency message
    ROUTINE_MESSAGE,    ///< Routine message
    COMMAND_MESSAGE     ///< Command message
};

/**
 * @struct Strela3Message
 * @brief Strela-3 message structure
 * 
 * @details
 * This structure contains a complete Strela-3 message
 * with all necessary metadata.
 */
struct Strela3Message {
    std::string message_id;         ///< Unique message identifier
    Strela3MessageType type;        ///< Message type
    std::string sender_id;          ///< Sender identifier
    std::string recipient_id;       ///< Recipient identifier
    std::string content;            ///< Message content
    std::chrono::system_clock::time_point timestamp; ///< Message timestamp
    uint32_t priority;              ///< Message priority (1-10)
    bool encrypted;                 ///< Whether message is encrypted
    std::string encryption_key;     ///< Encryption key identifier
    bool delivered;                 ///< Whether message has been delivered
    std::chrono::system_clock::time_point delivery_time; ///< Delivery timestamp
};

/**
 * @class Strela3
 * @brief Strela-3 Military Satellite System Implementation
 * 
 * @details
 * The Strela3 class implements the complete Strela-3 military
 * satellite system with store-and-forward messaging capabilities.
 * 
 * ## Technical Specifications
 * - **Orbit**: ~1400-1500 km circular LEO
 * - **Frequencies**: 150-174 MHz military VHF band
 * - **Use Case**: Tactical military messaging
 * - **Message Types**: Tactical, Status, Emergency, Routine, Command
 * - **Encryption**: Message-level encryption support
 * - **Store-and-Forward**: Message storage and forwarding
 * 
 * ## Usage Example
 * @code
 * #include "strela_3.h"
 * 
 * // Create Strela-3 instance
 * Strela3 strela;
 * 
 * // Initialize with ground station location
 * strela.initialize(40.7128, -74.0060);
 * 
 * // Load TLE data
 * strela.loadTLE("strela_3.tle");
 * 
 * // Send tactical message
 * Strela3Message message;
 * message.type = Strela3MessageType::TACTICAL_MESSAGE;
 * message.content = "Tactical message content";
 * strela.sendMessage(message);
 * @endcode
 * 
 * @note This class provides a unified interface for Strela-3 operations.
 * 
 * @since 1.0.0
 * @version 1.0.0
 */
class Strela3 {
private:
    bool initialized_;                  ///< System initialization status
    
    // Ground station parameters
    double ground_latitude_;           ///< Ground station latitude
    double ground_longitude_;          ///< Ground station longitude
    double ground_altitude_;           ///< Ground station altitude (m)
    
    // Satellite parameters
    std::string current_satellite_;    ///< Current satellite name
    double uplink_frequency_;         ///< Uplink frequency (MHz)
    double downlink_frequency_;       ///< Downlink frequency (MHz)
    
    // Message storage
    std::map<std::string, Strela3Message> message_storage_; ///< Message storage
    std::vector<std::string> message_queue_; ///< Message queue
    
    // Communication parameters
    bool encryption_enabled_;         ///< Encryption enabled
    std::string encryption_key_;      ///< Current encryption key
    uint32_t message_priority_;       ///< Message priority
    
    // Processing buffers
    std::vector<uint8_t> input_buffer_; ///< Input message buffer
    std::vector<uint8_t> output_buffer_; ///< Output message buffer
    
public:
    /**
     * @brief Default constructor
     * 
     * @details
     * Initializes the Strela-3 system with default parameters.
     */
    Strela3();
    
    /**
     * @brief Virtual destructor
     * 
     * @details
     * Cleans up all resources used by the Strela-3 system.
     */
    virtual ~Strela3();
    
    // Initialization and configuration
    
    /**
     * @brief Initialize the Strela-3 system
     * 
     * @param latitude Ground station latitude
     * @param longitude Ground station longitude
     * @param altitude Ground station altitude in meters
     * @return true if initialization successful, false otherwise
     * 
     * @details
     * Initializes the Strela-3 system with the specified
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
    
    // Message operations
    
    /**
     * @brief Send message
     * 
     * @param message Message to send
     * @return true if message sent successfully, false otherwise
     * 
     * @details
     * Sends a message via the Strela-3 satellite system.
     */
    bool sendMessage(const Strela3Message& message);
    
    /**
     * @brief Receive messages
     * 
     * @param recipient_id Recipient identifier
     * @return Vector of received messages
     * 
     * @details
     * Retrieves messages for the specified recipient.
     */
    std::vector<Strela3Message> receiveMessages(const std::string& recipient_id);
    
    /**
     * @brief Check message status
     * 
     * @param message_id Message identifier
     * @return Message status string
     * 
     * @details
     * Checks the status of a specific message.
     */
    std::string checkMessageStatus(const std::string& message_id);
    
    /**
     * @brief Delete message
     * 
     * @param message_id Message identifier
     * @return true if message deleted successfully, false otherwise
     * 
     * @details
     * Deletes a message from the system.
     */
    bool deleteMessage(const std::string& message_id);
    
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
    
    /**
     * @brief Set message priority
     * 
     * @param priority Message priority (1-10)
     * @return true if priority set successfully, false otherwise
     * 
     * @details
     * Sets the default message priority.
     */
    bool setMessagePriority(uint32_t priority);
    
    // Status and diagnostics
    
    /**
     * @brief Check if system is initialized
     * 
     * @return true if initialized, false otherwise
     * 
     * @details
     * Returns the initialization status of the Strela-3 system.
     */
    bool isInitialized() const;
    
    /**
     * @brief Get system status
     * 
     * @return Status string
     * 
     * @details
     * Returns a string describing the current status of the
     * Strela-3 system.
     */
    std::string getStatus() const;
    
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
     * @brief Get performance metrics
     * 
     * @return Performance metrics string
     * 
     * @details
     * Returns performance metrics for the Strela-3 system.
     */
    std::string getPerformanceMetrics() const;
};

/**
 * @namespace Strela3Utils
 * @brief Utility functions for Strela-3 system
 * 
 * @details
 * This namespace contains utility functions for the Strela-3
 * system, including message processing, encryption, and
 * satellite operations.
 * 
 * @since 1.0.0
 */
namespace Strela3Utils {
    
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
    Strela3Message encryptMessage(const Strela3Message& message, const std::string& key);
    
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
    Strela3Message decryptMessage(const Strela3Message& message, const std::string& key);
    
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
    bool validateMessage(const Strela3Message& message);
    
    /**
     * @brief Get message type name
     * 
     * @param type Message type
     * @return Type name string
     * 
     * @details
     * Returns the human-readable name of the message type.
     */
    std::string getMessageTypeName(Strela3MessageType type);
    
    /**
     * @brief Get message priority name
     * 
     * @param priority Message priority
     * @return Priority name string
     * 
     * @details
     * Returns the human-readable name of the message priority.
     */
    std::string getMessagePriorityName(uint32_t priority);
    
    /**
     * @brief Format message for transmission
     * 
     * @param message Message to format
     * @return Formatted message string
     * 
     * @details
     * Formats a message for transmission over the satellite link.
     */
    std::string formatMessage(const Strela3Message& message);
    
    /**
     * @brief Parse received message
     * 
     * @param data Received message data
     * @return Parsed message
     * 
     * @details
     * Parses a received message from satellite data.
     */
    Strela3Message parseMessage(const std::string& data);
}

} // namespace military
} // namespace satellites
} // namespace fgcom

#endif // STRELA_3_H
