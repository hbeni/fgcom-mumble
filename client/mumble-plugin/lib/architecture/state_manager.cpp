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

#include "state_management.h"
#include "interfaces.h"
#include <stdexcept>
#include <chrono>
#include <iostream>

namespace fgcom {
namespace architecture {

/**
 * @brief Thread-safe state manager implementation
 * 
 * Provides atomic operations for state management with proper
 * synchronization, validation, and error handling.
 */
class ThreadSafeStateManager : public IStateManager {
private:
    // Thread-safe state storage
    mutable std::mutex stateMutex;
    RadioState radioState;
    ConnectionState connectionState;
    PluginConfig pluginConfig;
    
    // Error handling
    std::atomic<bool> hasError{false};
    std::string lastError;
    mutable std::mutex errorMutex;
    
    // State validation
    std::atomic<bool> isInitialized{false};
    
public:
    ThreadSafeStateManager() {
        // Initialize with default values
        radioState.reset();
        connectionState.reset();
        pluginConfig.reset();
        isInitialized.store(true);
    }
    
    virtual ~ThreadSafeStateManager() = default;
    
    /**
     * @brief Get current radio state atomically
     * @return RadioState Current radio state
     */
    RadioState getRadioState() const override {
        std::lock_guard<std::mutex> lock(stateMutex);
        return radioState;
    }
    
    /**
     * @brief Update radio state atomically
     * @param state New radio state
     * @return bool True if update successful
     */
    bool updateRadioState(const RadioState& state) override {
        try {
            // Validate state before updating
            if (!state.isValid()) {
                setError("Invalid radio state provided", "updateRadioState");
                return false;
            }
            
            std::lock_guard<std::mutex> lock(stateMutex);
            
            // Update state atomically
            radioState.latitude.store(state.latitude.load());
            radioState.longitude.store(state.longitude.load());
            radioState.altitude.store(state.altitude.load());
            radioState.frequency.store(state.frequency.load());
            radioState.isTransmitting.store(state.isTransmitting.load());
            radioState.isReceiving.store(state.isReceiving.load());
            radioState.isActive.store(state.isActive.load());
            radioState.isOperational.store(state.isOperational.load());
            radioState.updateTimestamp();
            
            clearError();
            return true;
            
        } catch (const std::exception& e) {
            setError("Exception in updateRadioState: " + std::string(e.what()), "updateRadioState");
            return false;
        }
    }
    
    /**
     * @brief Get connection state atomically
     * @return ConnectionState Current connection state
     */
    ConnectionState getConnectionState() const override {
        std::lock_guard<std::mutex> lock(stateMutex);
        return connectionState;
    }
    
    /**
     * @brief Update connection state atomically
     * @param state New connection state
     * @return bool True if update successful
     */
    bool updateConnectionState(const ConnectionState& state) override {
        try {
            // Validate state before updating
            if (!state.isValid()) {
                setError("Invalid connection state provided", "updateConnectionState");
                return false;
            }
            
            std::lock_guard<std::mutex> lock(stateMutex);
            
            // Update state atomically
            connectionState.isConnected.store(state.isConnected.load());
            connectionState.isConnecting.store(state.isConnecting.load());
            connectionState.isDisconnecting.store(state.isDisconnecting.load());
            connectionState.connectionId.store(state.connectionId.load());
            connectionState.serverPort.store(state.serverPort.load());
            connectionState.isAuthenticated.store(state.isAuthenticated.load());
            connectionState.isAuthorized.store(state.isAuthorized.load());
            connectionState.setServerAddress(state.getServerAddress());
            connectionState.updateTimestamp();
            
            clearError();
            return true;
            
        } catch (const std::exception& e) {
            setError("Exception in updateConnectionState: " + std::string(e.what()), "updateConnectionState");
            return false;
        }
    }
    
    /**
     * @brief Check if state is valid
     * @return bool True if state is in valid state
     */
    bool isValidState() const override {
        std::lock_guard<std::mutex> lock(stateMutex);
        
        // Check if manager is initialized
        if (!isInitialized.load()) {
            return false;
        }
        
        // Check if radio state is valid
        if (!radioState.isValid()) {
            return false;
        }
        
        // Check if connection state is valid
        if (!connectionState.isValid()) {
            return false;
        }
        
        // Check if configuration is valid
        if (!pluginConfig.isValid()) {
            return false;
        }
        
        return true;
    }
    
    /**
     * @brief Reset state to initial values
     * @return bool True if reset successful
     */
    bool resetState() override {
        try {
            std::lock_guard<std::mutex> lock(stateMutex);
            
            // Reset all states
            radioState.reset();
            connectionState.reset();
            pluginConfig.reset();
            
            clearError();
            return true;
            
        } catch (const std::exception& e) {
            setError("Exception in resetState: " + std::string(e.what()), "resetState");
            return false;
        }
    }
    
    /**
     * @brief Get plugin configuration
     * @return PluginConfig Current configuration
     */
    PluginConfig getPluginConfig() const {
        std::lock_guard<std::mutex> lock(stateMutex);
        return pluginConfig;
    }
    
    /**
     * @brief Update plugin configuration
     * @param config New configuration
     * @return bool True if update successful
     */
    bool updatePluginConfig(const PluginConfig& config) {
        try {
            // Validate configuration before updating
            if (!config.isValid()) {
                setError("Invalid plugin configuration provided", "updatePluginConfig");
                return false;
            }
            
            std::lock_guard<std::mutex> lock(stateMutex);
            
            // Update configuration atomically
            pluginConfig.isEnabled.store(config.isEnabled.load());
            pluginConfig.isDebugMode.store(config.isDebugMode.load());
            pluginConfig.isVerboseMode.store(config.isVerboseMode.load());
            pluginConfig.maxRetries.store(config.maxRetries.load());
            pluginConfig.timeoutMs.store(config.timeoutMs.load());
            pluginConfig.bufferSize.store(config.bufferSize.load());
            pluginConfig.enableThreading.store(config.enableThreading.load());
            pluginConfig.enableGPUAcceleration.store(config.enableGPUAcceleration.load());
            pluginConfig.enableAPIServer.store(config.enableAPIServer.load());
            pluginConfig.setStringValue("configFile", config.getStringValue("configFile"));
            pluginConfig.setStringValue("logFile", config.getStringValue("logFile"));
            pluginConfig.setStringValue("dataDirectory", config.getStringValue("dataDirectory"));
            
            clearError();
            return true;
            
        } catch (const std::exception& e) {
            setError("Exception in updatePluginConfig: " + std::string(e.what()), "updatePluginConfig");
            return false;
        }
    }
    
    /**
     * @brief Check if radio state is stale
     * @param maxAge Maximum age in milliseconds
     * @return bool True if state is stale
     */
    bool isRadioStateStale(int maxAge = 5000) const {
        std::lock_guard<std::mutex> lock(stateMutex);
        return radioState.isStale(maxAge);
    }
    
    /**
     * @brief Check if connection state is stale
     * @param maxAge Maximum age in milliseconds
     * @return bool True if connection is stale
     */
    bool isConnectionStateStale(int maxAge = 30000) const {
        std::lock_guard<std::mutex> lock(stateMutex);
        return connectionState.isStale(maxAge);
    }
    
private:
    /**
     * @brief Set error state
     * @param error Error message
     * @param context Error context
     */
    void setError(const std::string& error, const std::string& context) const {
        std::lock_guard<std::mutex> lock(errorMutex);
        lastError = "[" + context + "] " + error;
        hasError.store(true);
        
        // Log error if debug mode is enabled
        if (pluginConfig.isDebugMode.load()) {
            std::cerr << "[ERROR] " << lastError << std::endl;
        }
    }
    
    /**
     * @brief Clear error state
     */
    void clearError() const {
        std::lock_guard<std::mutex> lock(errorMutex);
        lastError.clear();
        hasError.store(false);
    }
    
    /**
     * @brief Get last error message
     * @return std::string Last error message
     */
    std::string getLastError() const {
        std::lock_guard<std::mutex> lock(errorMutex);
        return lastError;
    }
    
    /**
     * @brief Check if error occurred
     * @return bool True if error occurred
     */
    bool hasErrorOccurred() const {
        return hasError.load();
    }
};

} // namespace architecture
} // namespace fgcom
