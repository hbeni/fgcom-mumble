/**
 * @file tle_updater.h
 * @brief Automatic TLE File Updater
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains the implementation of automatic TLE file updates
 * to keep satellite tracking data current and accurate.
 * 
 * @details
 * TLE Updater provides:
 * - Automatic TLE file downloads
 * - Scheduled updates (hourly, daily, weekly)
 * - Multiple TLE data sources
 * - Background update processing
 * - Update status monitoring
 * - Error handling and retry logic
 * 
 * @see https://github.com/Supermagnum/fgcom-mumble
 * @see docs/TLE_UPDATER_DOCUMENTATION.md
 */

#ifndef TLE_UPDATER_H
#define TLE_UPDATER_H

#include <vector>
#include <memory>
#include <string>
#include <cstdint>
#include <chrono>
#include <map>
#include <thread>
#include <atomic>
#include <mutex>

namespace fgcom {
namespace satellites {
namespace orbital {

/**
 * @enum TLESource
 * @brief TLE data sources
 * 
 * @details
 * This enumeration defines the available TLE data sources
 * for automatic updates.
 */
enum class TLESource {
    CELESTRAK_AMATEUR,      ///< CelesTrak amateur satellites
    CELESTRAK_MILITARY,     ///< CelesTrak military satellites
    CELESTRAK_STARLINK,     ///< CelesTrak Starlink satellites
    CELESTRAK_WEATHER,      ///< CelesTrak weather satellites
    AMSAT,                  ///< AMSAT TLE data
    SPACE_TRACK,            ///< Space-Track.org
    CUSTOM_URL              ///< Custom URL
};

/**
 * @enum UpdateFrequency
 * @brief TLE update frequencies
 * 
 * @details
 * This enumeration defines the available update frequencies
 * for automatic TLE updates.
 */
enum class UpdateFrequency {
    HOURLY,                 ///< Update every hour
    DAILY,                  ///< Update daily
    WEEKLY,                 ///< Update weekly
    MANUAL                  ///< Manual updates only
};

/**
 * @struct TLESourceConfig
 * @brief TLE source configuration
 * 
 * @details
 * This structure contains the configuration for a TLE data source.
 */
struct TLESourceConfig {
    TLESource source;               ///< TLE source type
    std::string url;                ///< Source URL
    std::string filename;           ///< Local filename
    std::string username;           ///< Username (for Space-Track)
    std::string password;           ///< Password (for Space-Track)
    bool enabled;                   ///< Whether source is enabled
    UpdateFrequency frequency;      ///< Update frequency
    std::chrono::system_clock::time_point last_update; ///< Last update time
    bool auto_update;               ///< Whether to auto-update
};

/**
 * @struct UpdateStatus
 * @brief TLE update status
 * 
 * @details
 * This structure contains the status of TLE updates.
 */
struct UpdateStatus {
    std::string source_name;        ///< Source name
    bool update_successful;         ///< Whether update was successful
    std::chrono::system_clock::time_point update_time; ///< Update time
    std::string error_message;      ///< Error message (if any)
    uint32_t satellites_updated;    ///< Number of satellites updated
    double download_time;           ///< Download time in seconds
    uint64_t file_size;            ///< Downloaded file size in bytes
};

/**
 * @class TLEUpdater
 * @brief Automatic TLE File Updater Implementation
 * 
 * @details
 * The TLEUpdater class implements automatic TLE file updates
 * with support for multiple data sources and scheduling.
 * 
 * ## Technical Specifications
 * - **Multiple Sources**: CelesTrak, AMSAT, Space-Track, Custom URLs
 * - **Scheduled Updates**: Hourly, daily, weekly, manual
 * - **Background Processing**: Non-blocking updates
 * - **Error Handling**: Retry logic and error reporting
 * - **Status Monitoring**: Update status tracking
 * - **File Management**: Automatic file organization
 * 
 * ## Usage Example
 * @code
 * #include "tle_updater.h"
 * 
 * // Create TLE updater instance
 * TLEUpdater updater;
 * 
 * // Initialize with update directory
 * updater.initialize("./tle_data/");
 * 
 * // Add TLE sources
 * updater.addSource("amateur", TLESource::CELESTRAK_AMATEUR, UpdateFrequency::DAILY);
 * updater.addSource("military", TLESource::CELESTRAK_MILITARY, UpdateFrequency::WEEKLY);
 * 
 * // Start automatic updates
 * updater.startAutoUpdate();
 * 
 * // Check update status
 * auto status = updater.getUpdateStatus("amateur");
 * @endcode
 * 
 * @note This class provides a unified interface for TLE updates.
 * 
 * @since 1.0.0
 * @version 1.0.0
 */
class TLEUpdater {
private:
    bool initialized_;                  ///< System initialization status
    std::string update_directory_;      ///< TLE update directory
    
    // TLE sources
    std::map<std::string, TLESourceConfig> sources_; ///< TLE sources
    std::map<std::string, UpdateStatus> update_status_; ///< Update status
    
    // Background processing
    std::atomic<bool> auto_update_enabled_; ///< Auto-update enabled
    std::thread update_thread_;         ///< Update thread
    std::mutex update_mutex_;           ///< Update mutex
    std::atomic<bool> stop_thread_;     ///< Stop thread flag
    
    // Update parameters
    uint32_t max_retries_;              ///< Maximum retry attempts
    uint32_t retry_delay_;              ///< Retry delay in seconds
    uint32_t connection_timeout_;       ///< Connection timeout in seconds
    bool verify_ssl_;                   ///< SSL verification enabled
    
    // Processing buffers
    std::vector<uint8_t> download_buffer_; ///< Download buffer
    
public:
    /**
     * @brief Default constructor
     * 
     * @details
     * Initializes the TLE updater with default parameters.
     */
    TLEUpdater();
    
    /**
     * @brief Virtual destructor
     * 
     * @details
     * Cleans up all resources used by the TLE updater.
     */
    virtual ~TLEUpdater();
    
    // Initialization and configuration
    
    /**
     * @brief Initialize the TLE updater
     * 
     * @param update_directory TLE update directory
     * @return true if initialization successful, false otherwise
     * 
     * @details
     * Initializes the TLE updater with the specified directory.
     * 
     * @note The system must be initialized before any other operations.
     */
    bool initialize(const std::string& update_directory);
    
    /**
     * @brief Add TLE source
     * 
     * @param name Source name
     * @param source TLE source type
     * @param frequency Update frequency
     * @param url Custom URL (for CUSTOM_URL source)
     * @return true if source added successfully, false otherwise
     * 
     * @details
     * Adds a TLE data source for automatic updates.
     */
    bool addSource(const std::string& name, TLESource source, 
                   UpdateFrequency frequency, const std::string& url = "");
    
    /**
     * @brief Remove TLE source
     * 
     * @param name Source name
     * @return true if source removed successfully, false otherwise
     * 
     * @details
     * Removes a TLE data source.
     */
    bool removeSource(const std::string& name);
    
    /**
     * @brief Configure TLE source
     * 
     * @param name Source name
     * @param config Source configuration
     * @return true if source configured successfully, false otherwise
     * 
     * @details
     * Configures a TLE data source.
     */
    bool configureSource(const std::string& name, const TLESourceConfig& config);
    
    // Update operations
    
    /**
     * @brief Update TLE data
     * 
     * @param source_name Source name to update
     * @return true if update successful, false otherwise
     * 
     * @details
     * Updates TLE data for the specified source.
     */
    bool updateTLE(const std::string& source_name);
    
    /**
     * @brief Update all TLE data
     * 
     * @return Number of sources updated successfully
     * 
     * @details
     * Updates TLE data for all enabled sources.
     */
    uint32_t updateAllTLE();
    
    /**
     * @brief Start automatic updates
     * 
     * @return true if auto-update started successfully, false otherwise
     * 
     * @details
     * Starts automatic TLE updates in the background.
     */
    bool startAutoUpdate();
    
    /**
     * @brief Stop automatic updates
     * 
     * @return true if auto-update stopped successfully, false otherwise
     * 
     * @details
     * Stops automatic TLE updates.
     */
    bool stopAutoUpdate();
    
    /**
     * @brief Force update
     * 
     * @param source_name Source name to force update
     * @return true if force update successful, false otherwise
     * 
     * @details
     * Forces an immediate update for the specified source.
     */
    bool forceUpdate(const std::string& source_name);
    
    // Configuration
    
    /**
     * @brief Set update parameters
     * 
     * @param max_retries Maximum retry attempts
     * @param retry_delay Retry delay in seconds
     * @param connection_timeout Connection timeout in seconds
     * @return true if parameters set successfully, false otherwise
     * 
     * @details
     * Sets the update parameters for TLE downloads.
     */
    bool setUpdateParameters(uint32_t max_retries, uint32_t retry_delay, 
                           uint32_t connection_timeout);
    
    /**
     * @brief Set SSL verification
     * 
     * @param verify_ssl Enable SSL verification
     * @return true if SSL verification set successfully, false otherwise
     * 
     * @details
     * Enables or disables SSL certificate verification.
     */
    bool setSSLVerification(bool verify_ssl);
    
    /**
     * @brief Set Space-Track credentials
     * 
     * @param username Space-Track username
     * @param password Space-Track password
     * @return true if credentials set successfully, false otherwise
     * 
     * @details
     * Sets the Space-Track.org credentials for authentication.
     */
    bool setSpaceTrackCredentials(const std::string& username, const std::string& password);
    
    // Status and diagnostics
    
    /**
     * @brief Check if system is initialized
     * 
     * @return true if initialized, false otherwise
     * 
     * @details
     * Returns the initialization status of the TLE updater.
     */
    bool isInitialized() const;
    
    /**
     * @brief Check if auto-update is running
     * 
     * @return true if auto-update is running, false otherwise
     * 
     * @details
     * Returns the auto-update status.
     */
    bool isAutoUpdateRunning() const;
    
    /**
     * @brief Get system status
     * 
     * @return Status string
     * 
     * @details
     * Returns a string describing the current status of the
     * TLE updater.
     */
    std::string getStatus() const;
    
    /**
     * @brief Get update status
     * 
     * @param source_name Source name
     * @return Update status
     * 
     * @details
     * Returns the update status for the specified source.
     */
    UpdateStatus getUpdateStatus(const std::string& source_name) const;
    
    /**
     * @brief Get all update statuses
     * 
     * @return Map of all update statuses
     * 
     * @details
     * Returns the update status for all sources.
     */
    std::map<std::string, UpdateStatus> getAllUpdateStatuses() const;
    
    /**
     * @brief Get available sources
     * 
     * @return Vector of available source names
     * 
     * @details
     * Returns a list of all available TLE sources.
     */
    std::vector<std::string> getAvailableSources() const;
    
    /**
     * @brief Get source configuration
     * 
     * @param source_name Source name
     * @return Source configuration
     * 
     * @details
     * Returns the configuration for the specified source.
     */
    TLESourceConfig getSourceConfiguration(const std::string& source_name) const;
    
    /**
     * @brief Get performance metrics
     * 
     * @return Performance metrics string
     * 
     * @details
     * Returns performance metrics for the TLE updater.
     */
    std::string getPerformanceMetrics() const;
    
private:
    /**
     * @brief Update thread function
     * 
     * @details
     * Background thread function for automatic updates.
     */
    void updateThreadFunction();
    
    /**
     * @brief Download TLE data
     * 
     * @param source_name Source name
     * @param url Download URL
     * @param filename Local filename
     * @return true if download successful, false otherwise
     * 
     * @details
     * Downloads TLE data from the specified URL.
     */
    bool downloadTLEData(const std::string& source_name, const std::string& url, 
                        const std::string& filename);
    
    /**
     * @brief Process TLE data
     * 
     * @param source_name Source name
     * @param data Downloaded data
     * @return Number of satellites processed
     * 
     * @details
     * Processes downloaded TLE data.
     */
    uint32_t processTLEData(const std::string& source_name, const std::vector<uint8_t>& data);
    
    /**
     * @brief Get source URL
     * 
     * @param source TLE source type
     * @return Source URL
     * 
     * @details
     * Returns the URL for the specified TLE source.
     */
    std::string getSourceURL(TLESource source) const;
    
    /**
     * @brief Check if update is needed
     * 
     * @param source_name Source name
     * @return true if update is needed, false otherwise
     * 
     * @details
     * Checks if an update is needed for the specified source.
     */
    bool isUpdateNeeded(const std::string& source_name) const;
};

/**
 * @namespace TLEUpdaterUtils
 * @brief Utility functions for TLE updater
 * 
 * @details
 * This namespace contains utility functions for the TLE updater,
 * including URL generation, file management, and error handling.
 * 
 * @since 1.0.0
 */
namespace TLEUpdaterUtils {
    
    /**
     * @brief Get default TLE sources
     * 
     * @return Map of default TLE sources
     * 
     * @details
     * Returns a map of default TLE sources with their configurations.
     */
    std::map<std::string, TLESourceConfig> getDefaultSources();
    
    /**
     * @brief Get source name
     * 
     * @param source TLE source type
     * @return Source name string
     * 
     * @details
     * Returns the human-readable name of the TLE source.
     */
    std::string getSourceName(TLESource source);
    
    /**
     * @brief Get frequency name
     * 
     * @param frequency Update frequency
     * @return Frequency name string
     * 
     * @details
     * Returns the human-readable name of the update frequency.
     */
    std::string getFrequencyName(UpdateFrequency frequency);
    
    /**
     * @brief Validate source configuration
     * 
     * @param config Source configuration
     * @return true if configuration is valid, false otherwise
     * 
     * @details
     * Validates that a source configuration meets all requirements.
     */
    bool validateSourceConfiguration(const TLESourceConfig& config);
    
    /**
     * @brief Format update status
     * 
     * @param status Update status
     * @return Formatted status string
     * 
     * @details
     * Formats an update status for display.
     */
    std::string formatUpdateStatus(const UpdateStatus& status);
    
    /**
     * @brief Calculate next update time
     * 
     * @param frequency Update frequency
     * @param last_update Last update time
     * @return Next update time
     * 
     * @details
     * Calculates the next update time based on frequency and last update.
     */
    std::chrono::system_clock::time_point calculateNextUpdateTime(
        UpdateFrequency frequency,
        std::chrono::system_clock::time_point last_update);
    
    /**
     * @brief Check internet connectivity
     * 
     * @return true if internet is available, false otherwise
     * 
     * @details
     * Checks if internet connectivity is available.
     */
    bool checkInternetConnectivity();
    
    /**
     * @brief Get file size
     * 
     * @param filename File path
     * @return File size in bytes
     * 
     * @details
     * Returns the size of the specified file.
     */
    uint64_t getFileSize(const std::string& filename);
    
    /**
     * @brief Get file modification time
     * 
     * @param filename File path
     * @return File modification time
     * 
     * @details
     * Returns the modification time of the specified file.
     */
    std::chrono::system_clock::time_point getFileModificationTime(const std::string& filename);
}

} // namespace orbital
} // namespace satellites
} // namespace fgcom

#endif // TLE_UPDATER_H
