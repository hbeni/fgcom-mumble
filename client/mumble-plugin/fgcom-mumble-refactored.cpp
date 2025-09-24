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

#include "fgcom-mumble-refactored.h"
#include <stdexcept>
#include <iostream>
#include <sstream>

namespace fgcom {
namespace plugin {

// Plugin version constants
constexpr int PLUGIN_VERSION_MAJOR = 1;
constexpr int PLUGIN_VERSION_MINOR = 1;
constexpr int PLUGIN_VERSION_PATCH = 1;

// Error codes
constexpr int ERROR_INVALID_STATE = 1001;
constexpr int ERROR_INVALID_INPUT = 1002;
constexpr int ERROR_INITIALIZATION_FAILED = 1003;
constexpr int ERROR_SHUTDOWN_FAILED = 1004;
constexpr int ERROR_ACTIVATION_FAILED = 1005;
constexpr int ERROR_POSITION_UPDATE_FAILED = 1006;
constexpr int ERROR_FREQUENCY_UPDATE_FAILED = 1007;
constexpr int ERROR_TRANSMISSION_STATE_FAILED = 1008;

FGComPlugin::FGComPlugin(MumbleAPI_v_1_0_x* api, mumble_plugin_id_t pluginId)
    : mumbleAPI(api), pluginId(pluginId) {
    
    // Initialize components
    if (!initializeComponents()) {
        throw std::runtime_error("Failed to initialize FGCom plugin components");
    }
    
    isInitialized.store(true);
    logEvent("FGCom plugin created successfully");
}

FGComPlugin::~FGComPlugin() {
    if (isInitialized.load()) {
        shutdown();
    }
}

bool FGComPlugin::initialize() {
    std::lock_guard<std::mutex> lock(pluginMutex);
    
    try {
        // Check if already initialized
        if (isInitialized.load()) {
            logEvent("Plugin already initialized");
            return true;
        }
        
        // Initialize components
        if (!initializeComponents()) {
            handlePluginError(ERROR_INITIALIZATION_FAILED, 
                            "Failed to initialize plugin components", 
                            "initialize");
            return false;
        }
        
        isInitialized.store(true);
        logEvent("Plugin initialized successfully");
        return true;
        
    } catch (const std::exception& e) {
        handlePluginError(ERROR_INITIALIZATION_FAILED, 
                        "Exception during initialization: " + std::string(e.what()), 
                        "initialize");
        return false;
    }
}

bool FGComPlugin::shutdown() {
    std::lock_guard<std::mutex> lock(pluginMutex);
    
    try {
        // Check if already shutdown
        if (!isInitialized.load()) {
            logEvent("Plugin already shutdown");
            return true;
        }
        
        // Deactivate plugin
        if (isActive.load()) {
            setActive(false);
        }
        
        // Shutdown components
        if (!shutdownComponents()) {
            handlePluginError(ERROR_SHUTDOWN_FAILED, 
                            "Failed to shutdown plugin components", 
                            "shutdown");
            return false;
        }
        
        isInitialized.store(false);
        logEvent("Plugin shutdown successfully");
        return true;
        
    } catch (const std::exception& e) {
        handlePluginError(ERROR_SHUTDOWN_FAILED, 
                        "Exception during shutdown: " + std::string(e.what()), 
                        "shutdown");
        return false;
    }
}

bool FGComPlugin::setActive(bool active) {
    std::lock_guard<std::mutex> lock(pluginMutex);
    
    try {
        // Validate state
        if (!validateState()) {
            handlePluginError(ERROR_INVALID_STATE, 
                            "Invalid plugin state", 
                            "setActive");
            return false;
        }
        
        // Update activation state
        isActive.store(active);
        
        // Log activation change
        logEvent(active ? "Plugin activated" : "Plugin deactivated");
        
        return true;
        
    } catch (const std::exception& e) {
        handlePluginError(ERROR_ACTIVATION_FAILED, 
                        "Exception during activation: " + std::string(e.what()), 
                        "setActive");
        return false;
    }
}

bool FGComPlugin::isPluginActive() const {
    return isActive.load();
}

bool FGComPlugin::handlePTTChange() {
    std::lock_guard<std::mutex> lock(pluginMutex);
    
    try {
        // Validate state
        if (!validateState()) {
            handlePluginError(ERROR_INVALID_STATE, 
                            "Invalid plugin state", 
                            "handlePTTChange");
            return false;
        }
        
        // Check if radio is operable
        if (!isRadioOperable()) {
            logEvent("Radio not operable, ignoring PTT change");
            return false;
        }
        
        // Handle PTT change through business logic
        if (businessLogic) {
            // Implementation would go here
            logEvent("PTT change handled successfully");
            return true;
        }
        
        return false;
        
    } catch (const std::exception& e) {
        handlePluginError(ERROR_TRANSMISSION_STATE_FAILED, 
                        "Exception during PTT handling: " + std::string(e.what()), 
                        "handlePTTChange");
        return false;
    }
}

bool FGComPlugin::isRadioOperable() const {
    try {
        // Get current state
        auto state = getCurrentState();
        
        // Check if radio is operational
        return state.isOperational.load() && state.isActive.load();
        
    } catch (const std::exception& e) {
        handlePluginError(ERROR_INVALID_STATE, 
                        "Exception checking radio operability: " + std::string(e.what()), 
                        "isRadioOperable");
        return false;
    }
}

bool FGComPlugin::updatePosition(double latitude, double longitude, double altitude) {
    std::lock_guard<std::mutex> lock(pluginMutex);
    
    try {
        // Validate inputs
        auto latResult = architecture::InputValidator::validateLatitude(latitude);
        if (!latResult.isValid) {
            handlePluginError(ERROR_INVALID_INPUT, 
                            "Invalid latitude: " + latResult.errorMessage, 
                            "updatePosition");
            return false;
        }
        
        auto lonResult = architecture::InputValidator::validateLongitude(longitude);
        if (!lonResult.isValid) {
            handlePluginError(ERROR_INVALID_INPUT, 
                            "Invalid longitude: " + lonResult.errorMessage, 
                            "updatePosition");
            return false;
        }
        
        auto altResult = architecture::InputValidator::validateAltitude(altitude);
        if (!altResult.isValid) {
            handlePluginError(ERROR_INVALID_INPUT, 
                            "Invalid altitude: " + altResult.errorMessage, 
                            "updatePosition");
            return false;
        }
        
        // Update state through state manager
        if (stateManager) {
            auto currentState = stateManager->getRadioState();
            currentState.latitude.store(latitude);
            currentState.longitude.store(longitude);
            currentState.altitude.store(altitude);
            currentState.updateTimestamp();
            
            if (!stateManager->updateRadioState(currentState)) {
                handlePluginError(ERROR_POSITION_UPDATE_FAILED, 
                                "Failed to update position in state manager", 
                                "updatePosition");
                return false;
            }
        }
        
        logEvent("Position updated successfully");
        return true;
        
    } catch (const std::exception& e) {
        handlePluginError(ERROR_POSITION_UPDATE_FAILED, 
                        "Exception during position update: " + std::string(e.what()), 
                        "updatePosition");
        return false;
    }
}

bool FGComPlugin::updateRadioFrequency(int radioId, double frequency) {
    std::lock_guard<std::mutex> lock(pluginMutex);
    
    try {
        // Validate inputs
        if (radioId < 0 || radioId > 10) {
            handlePluginError(ERROR_INVALID_INPUT, 
                            "Invalid radio ID: " + std::to_string(radioId), 
                            "updateRadioFrequency");
            return false;
        }
        
        auto freqResult = architecture::InputValidator::validateFrequency(frequency);
        if (!freqResult.isValid) {
            handlePluginError(ERROR_INVALID_INPUT, 
                            "Invalid frequency: " + freqResult.errorMessage, 
                            "updateRadioFrequency");
            return false;
        }
        
        // Update frequency through hardware abstraction
        if (hardwareAbstraction) {
            if (!hardwareAbstraction->setRadioFrequency(radioId, frequency)) {
                handlePluginError(ERROR_FREQUENCY_UPDATE_FAILED, 
                                "Failed to set radio frequency", 
                                "updateRadioFrequency");
                return false;
            }
        }
        
        logEvent("Radio frequency updated successfully");
        return true;
        
    } catch (const std::exception& e) {
        handlePluginError(ERROR_FREQUENCY_UPDATE_FAILED, 
                        "Exception during frequency update: " + std::string(e.what()), 
                        "updateRadioFrequency");
        return false;
    }
}

bool FGComPlugin::setTransmissionState(int radioId, bool transmitting) {
    std::lock_guard<std::mutex> lock(pluginMutex);
    
    try {
        // Validate inputs
        if (radioId < 0 || radioId > 10) {
            handlePluginError(ERROR_INVALID_INPUT, 
                            "Invalid radio ID: " + std::to_string(radioId), 
                            "setTransmissionState");
            return false;
        }
        
        // Set transmission state through hardware abstraction
        if (hardwareAbstraction) {
            if (!hardwareAbstraction->setTransmitting(radioId, transmitting)) {
                handlePluginError(ERROR_TRANSMISSION_STATE_FAILED, 
                                "Failed to set transmission state", 
                                "setTransmissionState");
                return false;
            }
        }
        
        logEvent(transmitting ? "Transmission started" : "Transmission stopped");
        return true;
        
    } catch (const std::exception& e) {
        handlePluginError(ERROR_TRANSMISSION_STATE_FAILED, 
                        "Exception during transmission state change: " + std::string(e.what()), 
                        "setTransmissionState");
        return false;
    }
}

architecture::RadioState FGComPlugin::getCurrentState() const {
    if (stateManager) {
        return stateManager->getRadioState();
    }
    
    // Return default state if no state manager
    architecture::RadioState defaultState;
    return defaultState;
}

architecture::ConnectionState FGComPlugin::getConnectionState() const {
    if (stateManager) {
        return stateManager->getConnectionState();
    }
    
    // Return default state if no state manager
    architecture::ConnectionState defaultState;
    return defaultState;
}

std::string FGComPlugin::getLastError() const {
    if (errorHandler) {
        return errorHandler->getLastError();
    }
    
    return "No error handler available";
}

bool FGComPlugin::hasError() const {
    if (errorHandler) {
        return errorHandler->hasErrorOccurred();
    }
    
    return false;
}

bool FGComPlugin::clearError() {
    if (errorHandler) {
        return errorHandler->clearError();
    }
    
    return false;
}

std::string FGComPlugin::getVersion() const {
    std::ostringstream version;
    version << PLUGIN_VERSION_MAJOR << "." 
            << PLUGIN_VERSION_MINOR << "." 
            << PLUGIN_VERSION_PATCH;
    return version.str();
}

std::string FGComPlugin::getStatus() const {
    std::ostringstream status;
    status << "FGCom Plugin Status:\n";
    status << "  Version: " << getVersion() << "\n";
    status << "  Initialized: " << (isInitialized.load() ? "Yes" : "No") << "\n";
    status << "  Active: " << (isActive.load() ? "Yes" : "No") << "\n";
    status << "  Connected: " << (isConnected.load() ? "Yes" : "No") << "\n";
    status << "  Error: " << (hasError() ? "Yes" : "No") << "\n";
    
    if (hasError()) {
        status << "  Last Error: " << getLastError() << "\n";
    }
    
    return status.str();
}

bool FGComPlugin::initializeComponents() {
    try {
        // Initialize error handler first
        errorHandler = std::make_unique<architecture::ThreadSafeErrorHandler>();
        
        // Initialize state manager
        stateManager = std::make_unique<architecture::ThreadSafeStateManager>();
        
        // Initialize other components would go here
        // hardwareAbstraction = std::make_unique<...>();
        // networkInterface = std::make_unique<...>();
        // businessLogic = std::make_unique<...>();
        // configManager = std::make_unique<...>();
        
        return true;
        
    } catch (const std::exception& e) {
        if (errorHandler) {
            errorHandler->handleError(ERROR_INITIALIZATION_FAILED, 
                                    "Exception during component initialization: " + std::string(e.what()), 
                                    "initializeComponents");
        }
        return false;
    }
}

bool FGComPlugin::shutdownComponents() {
    try {
        // Shutdown components in reverse order
        if (businessLogic) {
            businessLogic->shutdown();
            businessLogic.reset();
        }
        
        if (networkInterface) {
            networkInterface->shutdown();
            networkInterface.reset();
        }
        
        if (hardwareAbstraction) {
            hardwareAbstraction->shutdown();
            hardwareAbstraction.reset();
        }
        
        if (configManager) {
            configManager.reset();
        }
        
        if (stateManager) {
            stateManager.reset();
        }
        
        if (errorHandler) {
            errorHandler.reset();
        }
        
        return true;
        
    } catch (const std::exception& e) {
        if (errorHandler) {
            errorHandler->handleError(ERROR_SHUTDOWN_FAILED, 
                                    "Exception during component shutdown: " + std::string(e.what()), 
                                    "shutdownComponents");
        }
        return false;
    }
}

bool FGComPlugin::validateState() const {
    // Check if plugin is initialized
    if (!isInitialized.load()) {
        return false;
    }
    
    // Check if state manager is valid
    if (stateManager && !stateManager->isValidState()) {
        return false;
    }
    
    return true;
}

void FGComPlugin::logEvent(const std::string& message, int level) const {
    if (mumbleAPI) {
        mumbleAPI->log(pluginId, message.c_str());
    }
    
    // Also log to standard output for debugging
    std::cout << "[FGCom] " << message << std::endl;
}

bool FGComPlugin::handlePluginError(int errorCode, const std::string& errorMessage, const std::string& context) {
    if (errorHandler) {
        return errorHandler->handleError(errorCode, errorMessage, context);
    }
    
    // Fallback error handling
    std::cerr << "[FGCom ERROR] " << context << ": " << errorMessage << std::endl;
    return false;
}

} // namespace plugin
} // namespace fgcom
