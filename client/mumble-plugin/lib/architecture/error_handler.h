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

#ifndef FGCOM_ERROR_HANDLER_H
#define FGCOM_ERROR_HANDLER_H

#include "interfaces.h"
#include <atomic>
#include <mutex>
#include <string>
#include <vector>
#include <chrono>
#include <functional>
#include <map>

namespace fgcom {
namespace architecture {

/**
 * @brief Error severity levels
 */
enum class ErrorSeverity {
    INFO = 0,
    WARNING = 1,
    ERROR = 2,
    CRITICAL = 3,
    FATAL = 4
};

/**
 * @brief Error categories for classification
 */
enum class ErrorCategory {
    GENERAL = 0,
    NETWORK = 1,
    STATE_MANAGEMENT = 2,
    HARDWARE = 3,
    CONFIGURATION = 4,
    THREADING = 5,
    MEMORY = 6,
    VALIDATION = 7,
    SECURITY = 8
};

/**
 * @brief Error information structure
 */
struct ErrorInfo {
    int errorCode;
    std::string errorMessage;
    std::string context;
    ErrorSeverity severity;
    ErrorCategory category;
    std::chrono::steady_clock::time_point timestamp;
    std::string stackTrace;
    
    ErrorInfo() : errorCode(0), severity(ErrorSeverity::INFO), category(ErrorCategory::GENERAL) {
        timestamp = std::chrono::steady_clock::now();
    }
};

/**
 * @brief Error recovery action types
 */
enum class RecoveryAction {
    NONE = 0,
    RETRY = 1,
    RESET = 2,
    SHUTDOWN = 3,
    RESTART = 4,
    FALLBACK = 5
};

/**
 * @brief Error recovery information
 */
struct RecoveryInfo {
    RecoveryAction action;
    int maxRetries;
    int currentRetries;
    std::chrono::milliseconds retryDelay;
    std::function<bool()> recoveryFunction;
    
    RecoveryInfo() : action(RecoveryAction::NONE), maxRetries(0), currentRetries(0), retryDelay(0) {}
};

/**
 * @brief Thread-safe error handler implementation
 * 
 * Provides comprehensive error handling with categorization,
 * recovery mechanisms, and proper logging.
 */
class ThreadSafeErrorHandler : public IErrorHandler {
private:
    // Error state management
    mutable std::mutex errorMutex;
    std::vector<ErrorInfo> errorHistory;
    std::atomic<bool> hasError{false};
    std::string lastError;
    std::atomic<int> errorCount{0};
    
    // Error recovery
    std::map<int, RecoveryInfo> recoveryMap;
    mutable std::mutex recoveryMutex;
    
    // Error callbacks
    std::vector<std::function<void(const ErrorInfo&)>> errorCallbacks;
    mutable std::mutex callbackMutex;
    
    // Configuration
    std::atomic<int> maxErrorHistory{1000};
    std::atomic<bool> enableLogging{true};
    std::atomic<bool> enableRecovery{true};
    
public:
    ThreadSafeErrorHandler() = default;
    virtual ~ThreadSafeErrorHandler() = default;
    
    /**
     * @brief Handle error with full context
     * @param error_code Error code
     * @param error_message Error message
     * @param context Error context
     * @param severity Error severity
     * @param category Error category
     * @return bool True if error handled successfully
     */
    bool handleError(int error_code, const std::string& error_message, const std::string& context,
                    ErrorSeverity severity = ErrorSeverity::ERROR, 
                    ErrorCategory category = ErrorCategory::GENERAL) {
        try {
            std::lock_guard<std::mutex> lock(errorMutex);
            
            // Create error info
            ErrorInfo errorInfo;
            errorInfo.errorCode = error_code;
            errorInfo.errorMessage = error_message;
            errorInfo.context = context;
            errorInfo.severity = severity;
            errorInfo.category = category;
            errorInfo.timestamp = std::chrono::steady_clock::now();
            
            // Add to history
            errorHistory.push_back(errorInfo);
            
            // Trim history if too large
            if (errorHistory.size() > maxErrorHistory.load()) {
                errorHistory.erase(errorHistory.begin());
            }
            
            // Update state
            lastError = error_message;
            hasError.store(true);
            errorCount.fetch_add(1);
            
            // Notify callbacks
            notifyCallbacks(errorInfo);
            
            // Attempt recovery if enabled
            if (enableRecovery.load()) {
                attemptRecovery(errorInfo);
            }
            
            return true;
            
        } catch (const std::exception& e) {
            // Fallback error handling
            std::cerr << "[CRITICAL] Error in error handler: " << e.what() << std::endl;
            return false;
        }
    }
    
    /**
     * @brief Handle error (simplified interface)
     * @param error_code Error code
     * @param error_message Error message
     * @param context Error context
     * @return bool True if error handled successfully
     */
    bool handleError(int error_code, const std::string& error_message, const std::string& context) override {
        return handleError(error_code, error_message, context, ErrorSeverity::ERROR, ErrorCategory::GENERAL);
    }
    
    /**
     * @brief Get last error
     * @return std::string Last error message
     */
    std::string getLastError() const override {
        std::lock_guard<std::mutex> lock(errorMutex);
        return lastError;
    }
    
    /**
     * @brief Clear error state
     * @return bool True if cleared successfully
     */
    bool clearError() override {
        std::lock_guard<std::mutex> lock(errorMutex);
        lastError.clear();
        hasError.store(false);
        return true;
    }
    
    /**
     * @brief Check if error occurred
     * @return bool True if error occurred
     */
    bool hasErrorOccurred() const override {
        return hasError.load();
    }
    
    /**
     * @brief Get error history
     * @return std::vector<ErrorInfo> Error history
     */
    std::vector<ErrorInfo> getErrorHistory() const {
        std::lock_guard<std::mutex> lock(errorMutex);
        return errorHistory;
    }
    
    /**
     * @brief Get error count
     * @return int Total error count
     */
    int getErrorCount() const {
        return errorCount.load();
    }
    
    /**
     * @brief Add error callback
     * @param callback Error callback function
     */
    void addErrorCallback(std::function<void(const ErrorInfo&)> callback) {
        std::lock_guard<std::mutex> lock(callbackMutex);
        errorCallbacks.push_back(callback);
    }
    
    /**
     * @brief Set recovery action for error code
     * @param error_code Error code
     * @param recovery Recovery information
     */
    void setRecoveryAction(int error_code, const RecoveryInfo& recovery) {
        std::lock_guard<std::mutex> lock(recoveryMutex);
        recoveryMap[error_code] = recovery;
    }
    
    /**
     * @brief Set maximum error history size
     * @param max_size Maximum history size
     */
    void setMaxErrorHistory(int max_size) {
        maxErrorHistory.store(max_size);
    }
    
    /**
     * @brief Enable or disable logging
     * @param enable True to enable logging
     */
    void setLoggingEnabled(bool enable) {
        enableLogging.store(enable);
    }
    
    /**
     * @brief Enable or disable recovery
     * @param enable True to enable recovery
     */
    void setRecoveryEnabled(bool enable) {
        enableRecovery.store(enable);
    }
    
    /**
     * @brief Clear error history
     */
    void clearErrorHistory() {
        std::lock_guard<std::mutex> lock(errorMutex);
        errorHistory.clear();
        errorCount.store(0);
    }
    
private:
    /**
     * @brief Notify error callbacks
     * @param errorInfo Error information
     */
    void notifyCallbacks(const ErrorInfo& errorInfo) {
        std::lock_guard<std::mutex> lock(callbackMutex);
        for (const auto& callback : errorCallbacks) {
            try {
                callback(errorInfo);
            } catch (const std::exception& e) {
                std::cerr << "[ERROR] Callback exception: " << e.what() << std::endl;
            }
        }
    }
    
    /**
     * @brief Attempt error recovery
     * @param errorInfo Error information
     */
    void attemptRecovery(const ErrorInfo& errorInfo) {
        std::lock_guard<std::mutex> lock(recoveryMutex);
        
        auto it = recoveryMap.find(errorInfo.errorCode);
        if (it != recoveryMap.end()) {
            RecoveryInfo& recovery = it->second;
            
            // Check if we can retry
            if (recovery.action == RecoveryAction::RETRY && 
                recovery.currentRetries < recovery.maxRetries) {
                
                recovery.currentRetries++;
                
                // Execute recovery function
                if (recovery.recoveryFunction && recovery.recoveryFunction()) {
                    // Recovery successful
                    recovery.currentRetries = 0;
                } else {
                    // Recovery failed, wait before next attempt
                    std::this_thread::sleep_for(recovery.retryDelay);
                }
            }
        }
    }
};

} // namespace architecture
} // namespace fgcom

#endif // FGCOM_ERROR_HANDLER_H
