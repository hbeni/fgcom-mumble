/* 
 * This file is part of the FGCom-mumble distribution (https://github.com/hbeni/fgcom-mumble).
 * Copyright (c) 2020 Benedikt Hallinger
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef FGCOM_INTERFACES_H
#define FGCOM_INTERFACES_H

#include <string>
#include <memory>
#include <functional>
#include <vector>
#include <atomic>
#include <mutex>

namespace fgcom {
namespace architecture {

// Forward declarations
struct RadioState;
struct ConnectionState;
struct PluginConfig;

/**
 * @brief Abstract interface for state management
 * 
 * Provides thread-safe state management with atomic operations
 * and proper synchronization mechanisms.
 */
class IStateManager {
public:
    virtual ~IStateManager() = default;
    
    /**
     * @brief Get current radio state atomically
     * @return RadioState Current radio state
     */
    virtual RadioState getRadioState() const = 0;
    
    /**
     * @brief Update radio state atomically
     * @param state New radio state
     * @return bool True if update successful
     */
    virtual bool updateRadioState(const RadioState& state) = 0;
    
    /**
     * @brief Get connection state atomically
     * @return ConnectionState Current connection state
     */
    virtual ConnectionState getConnectionState() const = 0;
    
    /**
     * @brief Update connection state atomically
     * @param state New connection state
     * @return bool True if update successful
     */
    virtual bool updateConnectionState(const ConnectionState& state) = 0;
    
    /**
     * @brief Check if state is valid
     * @return bool True if state is in valid state
     */
    virtual bool isValidState() const = 0;
    
    /**
     * @brief Reset state to initial values
     * @return bool True if reset successful
     */
    virtual bool resetState() = 0;
};

/**
 * @brief Abstract interface for hardware abstraction
 * 
 * Provides hardware abstraction layer for different platforms
 * and simulation environments.
 */
class IHardwareAbstraction {
public:
    virtual ~IHardwareAbstraction() = default;
    
    /**
     * @brief Initialize hardware abstraction
     * @return bool True if initialization successful
     */
    virtual bool initialize() = 0;
    
    /**
     * @brief Shutdown hardware abstraction
     * @return bool True if shutdown successful
     */
    virtual bool shutdown() = 0;
    
    /**
     * @brief Get current position data
     * @return std::tuple<double, double, double> lat, lon, alt
     */
    virtual std::tuple<double, double, double> getPosition() const = 0;
    
    /**
     * @brief Get current radio frequency
     * @param radio_id Radio identifier
     * @return double Frequency in Hz
     */
    virtual double getRadioFrequency(int radio_id) const = 0;
    
    /**
     * @brief Set radio frequency
     * @param radio_id Radio identifier
     * @param frequency Frequency in Hz
     * @return bool True if set successful
     */
    virtual bool setRadioFrequency(int radio_id, double frequency) = 0;
    
    /**
     * @brief Check if radio is transmitting
     * @param radio_id Radio identifier
     * @return bool True if transmitting
     */
    virtual bool isTransmitting(int radio_id) const = 0;
    
    /**
     * @brief Set transmission state
     * @param radio_id Radio identifier
     * @param transmitting Transmission state
     * @return bool True if set successful
     */
    virtual bool setTransmitting(int radio_id, bool transmitting) = 0;
};

/**
 * @brief Abstract interface for network communication
 * 
 * Provides network abstraction for different communication protocols
 * and connection types.
 */
class INetworkInterface {
public:
    virtual ~INetworkInterface() = default;
    
    /**
     * @brief Initialize network interface
     * @return bool True if initialization successful
     */
    virtual bool initialize() = 0;
    
    /**
     * @brief Shutdown network interface
     * @return bool True if shutdown successful
     */
    virtual bool shutdown() = 0;
    
    /**
     * @brief Connect to server
     * @param server Server address
     * @param port Server port
     * @return bool True if connection successful
     */
    virtual bool connect(const std::string& server, int port) = 0;
    
    /**
     * @brief Disconnect from server
     * @return bool True if disconnection successful
     */
    virtual bool disconnect() = 0;
    
    /**
     * @brief Check if connected
     * @return bool True if connected
     */
    virtual bool isConnected() const = 0;
    
    /**
     * @brief Send data
     * @param data Data to send
     * @return bool True if send successful
     */
    virtual bool sendData(const std::vector<uint8_t>& data) = 0;
    
    /**
     * @brief Receive data
     * @param data Buffer to receive data
     * @return bool True if receive successful
     */
    virtual bool receiveData(std::vector<uint8_t>& data) = 0;
};

/**
 * @brief Abstract interface for business logic
 * 
 * Provides business logic abstraction for radio simulation
 * and communication protocols.
 */
class IBusinessLogic {
public:
    virtual ~IBusinessLogic() = default;
    
    /**
     * @brief Initialize business logic
     * @return bool True if initialization successful
     */
    virtual bool initialize() = 0;
    
    /**
     * @brief Shutdown business logic
     * @return bool True if shutdown successful
     */
    virtual bool shutdown() = 0;
    
    /**
     * @brief Process radio transmission
     * @param frequency Transmission frequency
     * @param data Transmission data
     * @return bool True if processing successful
     */
    virtual bool processTransmission(double frequency, const std::vector<uint8_t>& data) = 0;
    
    /**
     * @brief Calculate signal strength
     * @param frequency Frequency
     * @param distance Distance to transmitter
     * @return double Signal strength in dB
     */
    virtual double calculateSignalStrength(double frequency, double distance) = 0;
    
    /**
     * @brief Check if frequency is in range
     * @param frequency Frequency to check
     * @return bool True if in range
     */
    virtual bool isFrequencyInRange(double frequency) = 0;
};

/**
 * @brief Abstract interface for error handling
 * 
 * Provides centralized error handling and reporting
 * with proper error categorization and recovery.
 */
class IErrorHandler {
public:
    virtual ~IErrorHandler() = default;
    
    /**
     * @brief Handle error
     * @param error_code Error code
     * @param error_message Error message
     * @param context Error context
     * @return bool True if error handled successfully
     */
    virtual bool handleError(int error_code, const std::string& error_message, const std::string& context) = 0;
    
    /**
     * @brief Get last error
     * @return std::string Last error message
     */
    virtual std::string getLastError() const = 0;
    
    /**
     * @brief Clear error state
     * @return bool True if cleared successfully
     */
    virtual bool clearError() = 0;
    
    /**
     * @brief Check if error occurred
     * @return bool True if error occurred
     */
    virtual bool hasError() const = 0;
};

/**
 * @brief Abstract interface for configuration management
 * 
 * Provides configuration management with validation
 * and persistence capabilities.
 */
class IConfigurationManager {
public:
    virtual ~IConfigurationManager() = default;
    
    /**
     * @brief Load configuration from file
     * @param filename Configuration file path
     * @return bool True if load successful
     */
    virtual bool loadConfiguration(const std::string& filename) = 0;
    
    /**
     * @brief Save configuration to file
     * @param filename Configuration file path
     * @return bool True if save successful
     */
    virtual bool saveConfiguration(const std::string& filename) = 0;
    
    /**
     * @brief Get configuration value
     * @param key Configuration key
     * @return std::string Configuration value
     */
    virtual std::string getValue(const std::string& key) const = 0;
    
    /**
     * @brief Set configuration value
     * @param key Configuration key
     * @param value Configuration value
     * @return bool True if set successful
     */
    virtual bool setValue(const std::string& key, const std::string& value) = 0;
    
    /**
     * @brief Validate configuration
     * @return bool True if configuration is valid
     */
    virtual bool validateConfiguration() const = 0;
};

} // namespace architecture
} // namespace fgcom

#endif // FGCOM_INTERFACES_H
