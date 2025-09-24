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

#ifndef FGCOM_MUMBLE_REFACTORED_H
#define FGCOM_MUMBLE_REFACTORED_H

#include "lib/architecture/interfaces.h"
#include "lib/architecture/state_management.h"
#include "lib/architecture/error_handler.h"
#include "lib/architecture/input_validation.h"
#include "mumble/MumbleAPI_v_1_0_x.h"
#include "mumble/MumblePlugin_v_1_0_x.h"
#include <memory>
#include <atomic>
#include <mutex>

namespace fgcom {
namespace plugin {

/**
 * @brief Refactored FGCom plugin with proper architecture
 * 
 * This class demonstrates proper separation of concerns with:
 * - Clear interfaces for all components
 * - Thread-safe state management
 * - Comprehensive error handling
 * - Input validation and sanitization
 * - Proper resource management
 */
class FGComPlugin {
private:
    // Core components with proper interfaces
    std::unique_ptr<architecture::IStateManager> stateManager;
    std::unique_ptr<architecture::IHardwareAbstraction> hardwareAbstraction;
    std::unique_ptr<architecture::INetworkInterface> networkInterface;
    std::unique_ptr<architecture::IBusinessLogic> businessLogic;
    std::unique_ptr<architecture::IErrorHandler> errorHandler;
    std::unique_ptr<architecture::IConfigurationManager> configManager;
    
    // Thread-safe state
    std::atomic<bool> isInitialized{false};
    std::atomic<bool> isActive{false};
    std::atomic<bool> isConnected{false};
    
    // Mumble API references
    MumbleAPI_v_1_0_x* mumbleAPI;
    mumble_plugin_id_t pluginId;
    
    // Thread safety
    mutable std::mutex pluginMutex;
    
public:
    /**
     * @brief Constructor with proper initialization
     * @param api Mumble API reference
     * @param pluginId Plugin ID
     */
    explicit FGComPlugin(MumbleAPI_v_1_0_x* api, mumble_plugin_id_t pluginId);
    
    /**
     * @brief Destructor with proper cleanup
     */
    ~FGComPlugin();
    
    // Disable copy constructor and assignment operator
    FGComPlugin(const FGComPlugin&) = delete;
    FGComPlugin& operator=(const FGComPlugin&) = delete;
    
    /**
     * @brief Initialize plugin with proper error handling
     * @return bool True if initialization successful
     */
    bool initialize();
    
    /**
     * @brief Shutdown plugin with proper cleanup
     * @return bool True if shutdown successful
     */
    bool shutdown();
    
    /**
     * @brief Activate plugin with proper state management
     * @param active Activation state
     * @return bool True if activation successful
     */
    bool setActive(bool active);
    
    /**
     * @brief Check if plugin is active
     * @return bool True if active
     */
    bool isPluginActive() const;
    
    /**
     * @brief Handle PTT change with proper validation
     * @return bool True if handling successful
     */
    bool handlePTTChange();
    
    /**
     * @brief Check if radio is operable
     * @return bool True if operable
     */
    bool isRadioOperable() const;
    
    /**
     * @brief Update position with proper validation
     * @param latitude Latitude in degrees
     * @param longitude Longitude in degrees
     * @param altitude Altitude in meters
     * @return bool True if update successful
     */
    bool updatePosition(double latitude, double longitude, double altitude);
    
    /**
     * @brief Update radio frequency with proper validation
     * @param radioId Radio identifier
     * @param frequency Frequency in Hz
     * @return bool True if update successful
     */
    bool updateRadioFrequency(int radioId, double frequency);
    
    /**
     * @brief Set transmission state with proper validation
     * @param radioId Radio identifier
     * @param transmitting Transmission state
     * @return bool True if set successful
     */
    bool setTransmissionState(int radioId, bool transmitting);
    
    /**
     * @brief Get current state information
     * @return architecture::RadioState Current radio state
     */
    architecture::RadioState getCurrentState() const;
    
    /**
     * @brief Get connection state
     * @return architecture::ConnectionState Current connection state
     */
    architecture::ConnectionState getConnectionState() const;
    
    /**
     * @brief Get error information
     * @return std::string Last error message
     */
    std::string getLastError() const;
    
    /**
     * @brief Check if error occurred
     * @return bool True if error occurred
     */
    bool hasError() const;
    
    /**
     * @brief Clear error state
     * @return bool True if cleared successfully
     */
    bool clearError();
    
    /**
     * @brief Get plugin version information
     * @return std::string Version string
     */
    std::string getVersion() const;
    
    /**
     * @brief Get plugin status information
     * @return std::string Status string
     */
    std::string getStatus() const;
    
private:
    /**
     * @brief Initialize components with proper error handling
     * @return bool True if initialization successful
     */
    bool initializeComponents();
    
    /**
     * @brief Shutdown components with proper cleanup
     * @return bool True if shutdown successful
     */
    bool shutdownComponents();
    
    /**
     * @brief Validate plugin state
     * @return bool True if state is valid
     */
    bool validateState() const;
    
    /**
     * @brief Log plugin event
     * @param message Log message
     * @param level Log level
     */
    void logEvent(const std::string& message, int level = 0) const;
    
    /**
     * @brief Handle plugin error
     * @param errorCode Error code
     * @param errorMessage Error message
     * @param context Error context
     * @return bool True if error handled
     */
    bool handlePluginError(int errorCode, const std::string& errorMessage, const std::string& context);
};

} // namespace plugin
} // namespace fgcom

#endif // FGCOM_MUMBLE_REFACTORED_H
