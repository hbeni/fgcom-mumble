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

#ifndef FGCOM_STATE_MANAGEMENT_H
#define FGCOM_STATE_MANAGEMENT_H

#include "interfaces.h"
#include <atomic>
#include <mutex>
#include <chrono>
#include <string>
#include <vector>
#include <map>

namespace fgcom {
namespace architecture {

/**
 * @brief Thread-safe radio state structure
 * 
 * Provides atomic operations for radio state management
 * with proper synchronization and validation.
 */
struct RadioState {
    // Atomic position data
    std::atomic<double> latitude{0.0};
    std::atomic<double> longitude{0.0};
    std::atomic<double> altitude{0.0};
    
    // Atomic radio data
    std::atomic<double> frequency{0.0};
    std::atomic<bool> isTransmitting{false};
    std::atomic<bool> isReceiving{false};
    
    // Atomic status flags
    std::atomic<bool> isActive{false};
    std::atomic<bool> isOperational{false};
    
    // Timestamp for state validation
    std::atomic<std::chrono::steady_clock::time_point> lastUpdate{
        std::chrono::steady_clock::now()
    };
    
    /**
     * @brief Validate radio state
     * @return bool True if state is valid
     */
    bool isValid() const {
        // Check if position is within valid range
        if (latitude.load() < -90.0 || latitude.load() > 90.0) return false;
        if (longitude.load() < -180.0 || longitude.load() > 180.0) return false;
        if (altitude.load() < -1000.0 || altitude.load() > 100000.0) return false;
        
        // Check if frequency is within valid range
        if (frequency.load() < 0.0 || frequency.load() > 1000000000.0) return false;
        
        // Check if state is not in conflicting states
        if (isTransmitting.load() && isReceiving.load()) return false;
        
        return true;
    }
    
    /**
     * @brief Reset radio state to initial values
     */
    void reset() {
        latitude.store(0.0);
        longitude.store(0.0);
        altitude.store(0.0);
        frequency.store(0.0);
        isTransmitting.store(false);
        isReceiving.store(false);
        isActive.store(false);
        isOperational.store(false);
        lastUpdate.store(std::chrono::steady_clock::now());
    }
    
    /**
     * @brief Update timestamp
     */
    void updateTimestamp() {
        lastUpdate.store(std::chrono::steady_clock::now());
    }
    
    /**
     * @brief Check if state is stale
     * @param maxAge Maximum age in milliseconds
     * @return bool True if state is stale
     */
    bool isStale(int maxAge = 5000) const {
        auto now = std::chrono::steady_clock::now();
        auto age = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - lastUpdate.load()
        );
        return age.count() > maxAge;
    }
};

/**
 * @brief Thread-safe connection state structure
 * 
 * Provides atomic operations for connection state management
 * with proper synchronization and validation.
 */
struct ConnectionState {
    // Atomic connection flags
    std::atomic<bool> isConnected{false};
    std::atomic<bool> isConnecting{false};
    std::atomic<bool> isDisconnecting{false};
    
    // Atomic connection data
    std::atomic<int> connectionId{0};
    std::atomic<int> serverPort{0};
    std::string serverAddress; // Protected by mutex
    
    // Atomic status flags
    std::atomic<bool> isAuthenticated{false};
    std::atomic<bool> isAuthorized{false};
    
    // Timestamp for connection validation
    std::atomic<std::chrono::steady_clock::time_point> lastConnection{
        std::chrono::steady_clock::now()
    };
    
    // Mutex for string operations
    mutable std::mutex addressMutex;
    
    /**
     * @brief Set server address thread-safely
     * @param address Server address
     */
    void setServerAddress(const std::string& address) {
        std::lock_guard<std::mutex> lock(addressMutex);
        serverAddress = address;
    }
    
    /**
     * @brief Get server address thread-safely
     * @return std::string Server address
     */
    std::string getServerAddress() const {
        std::lock_guard<std::mutex> lock(addressMutex);
        return serverAddress;
    }
    
    /**
     * @brief Validate connection state
     * @return bool True if state is valid
     */
    bool isValid() const {
        // Check if not in conflicting states
        if (isConnecting.load() && isDisconnecting.load()) return false;
        if (isConnecting.load() && isConnected.load()) return false;
        if (isDisconnecting.load() && !isConnected.load()) return false;
        
        // Check if port is valid
        if (serverPort.load() < 1 || serverPort.load() > 65535) return false;
        
        return true;
    }
    
    /**
     * @brief Reset connection state to initial values
     */
    void reset() {
        isConnected.store(false);
        isConnecting.store(false);
        isDisconnecting.store(false);
        connectionId.store(0);
        serverPort.store(0);
        isAuthenticated.store(false);
        isAuthorized.store(false);
        lastConnection.store(std::chrono::steady_clock::now());
        
        std::lock_guard<std::mutex> lock(addressMutex);
        serverAddress.clear();
    }
    
    /**
     * @brief Update connection timestamp
     */
    void updateTimestamp() {
        lastConnection.store(std::chrono::steady_clock::now());
    }
    
    /**
     * @brief Check if connection is stale
     * @param maxAge Maximum age in milliseconds
     * @return bool True if connection is stale
     */
    bool isStale(int maxAge = 30000) const {
        auto now = std::chrono::steady_clock::now();
        auto age = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - lastConnection.load()
        );
        return age.count() > maxAge;
    }
};

/**
 * @brief Thread-safe plugin configuration structure
 * 
 * Provides atomic operations for configuration management
 * with proper synchronization and validation.
 */
struct PluginConfig {
    // Atomic configuration flags
    std::atomic<bool> isEnabled{false};
    std::atomic<bool> isDebugMode{false};
    std::atomic<bool> isVerboseMode{false};
    
    // Atomic configuration values
    std::atomic<int> maxRetries{3};
    std::atomic<int> timeoutMs{5000};
    std::atomic<int> bufferSize{4096};
    
    // Atomic feature flags
    std::atomic<bool> enableThreading{true};
    std::atomic<bool> enableGPUAcceleration{false};
    std::atomic<bool> enableAPIServer{false};
    
    // Configuration strings (protected by mutex)
    std::string configFile;
    std::string logFile;
    std::string dataDirectory;
    
    // Mutex for string operations
    mutable std::mutex configMutex;
    
    /**
     * @brief Set configuration string thread-safely
     * @param key Configuration key
     * @param value Configuration value
     */
    void setStringValue(const std::string& key, const std::string& value) {
        std::lock_guard<std::mutex> lock(configMutex);
        if (key == "configFile") configFile = value;
        else if (key == "logFile") logFile = value;
        else if (key == "dataDirectory") dataDirectory = value;
    }
    
    /**
     * @brief Get configuration string thread-safely
     * @param key Configuration key
     * @return std::string Configuration value
     */
    std::string getStringValue(const std::string& key) const {
        std::lock_guard<std::mutex> lock(configMutex);
        if (key == "configFile") return configFile;
        else if (key == "logFile") return logFile;
        else if (key == "dataDirectory") return dataDirectory;
        return "";
    }
    
    /**
     * @brief Validate configuration
     * @return bool True if configuration is valid
     */
    bool isValid() const {
        // Check if timeout is valid
        if (timeoutMs.load() < 100 || timeoutMs.load() > 60000) return false;
        
        // Check if buffer size is valid
        if (bufferSize.load() < 1024 || bufferSize.load() > 1048576) return false;
        
        // Check if max retries is valid
        if (maxRetries.load() < 0 || maxRetries.load() > 10) return false;
        
        return true;
    }
    
    /**
     * @brief Reset configuration to default values
     */
    void reset() {
        isEnabled.store(false);
        isDebugMode.store(false);
        isVerboseMode.store(false);
        maxRetries.store(3);
        timeoutMs.store(5000);
        bufferSize.store(4096);
        enableThreading.store(true);
        enableGPUAcceleration.store(false);
        enableAPIServer.store(false);
        
        std::lock_guard<std::mutex> lock(configMutex);
        configFile.clear();
        logFile.clear();
        dataDirectory.clear();
    }
};

} // namespace architecture
} // namespace fgcom

#endif // FGCOM_STATE_MANAGEMENT_H
