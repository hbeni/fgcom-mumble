/**
 * @file tle_updater.cpp
 * @brief TLE Automatic Updater Implementation
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains the implementation of automatic TLE file updates
 * to keep satellite tracking data current and accurate.
 */

#include "tle_updater.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <thread>
#include <chrono>
#include <curl/curl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <cstring>
#include <algorithm>
#include <iomanip>

namespace fgcom {
namespace satellites {
namespace orbital {

// Global variables for signal handling
static std::atomic<bool> g_shutdown_requested{false};
static TLEUpdater* g_updater_instance = nullptr;

// Signal handler for graceful shutdown
void signalHandler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cout << "\nReceived shutdown signal, stopping TLE updater..." << std::endl;
        g_shutdown_requested = true;
        if (g_updater_instance) {
            g_updater_instance->stopAutoUpdate();
        }
    }
}

// Callback function for libcurl to write data
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total_size = size * nmemb;
    std::vector<uint8_t>* buffer = static_cast<std::vector<uint8_t>*>(userp);
    buffer->insert(buffer->end(), static_cast<uint8_t*>(contents), 
                   static_cast<uint8_t*>(contents) + total_size);
    return total_size;
}

TLEUpdater::TLEUpdater() 
    : initialized_(false)
    , auto_update_enabled_(false)
    , stop_thread_(false)
    , max_retries_(3)
    , retry_delay_(30)
    , connection_timeout_(30)
    , verify_ssl_(true) {
    
    // Initialize libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

TLEUpdater::~TLEUpdater() {
    stopAutoUpdate();
    curl_global_cleanup();
}

bool TLEUpdater::initialize(const std::string& update_directory) {
    if (initialized_) {
        return true;
    }
    
    update_directory_ = update_directory;
    
    // Create update directory if it doesn't exist
    if (mkdir(update_directory_.c_str(), 0755) != 0 && errno != EEXIST) {
        std::cerr << "Error: Failed to create update directory: " << update_directory_ << std::endl;
        return false;
    }
    
    // Set up default sources
    setupDefaultSources();
    
    initialized_ = true;
    std::cout << "TLE Updater initialized successfully" << std::endl;
    std::cout << "Update directory: " << update_directory_ << std::endl;
    
    return true;
}

void TLEUpdater::setupDefaultSources() {
    // Amateur satellites (daily)
    TLESourceConfig amateur_config;
    amateur_config.source = TLESource::CELESTRAK_AMATEUR;
    amateur_config.url = "https://celestrak.org/NORAD/elements/gp.php?GROUP=amateur&FORMAT=tle";
    amateur_config.filename = "amateur.tle";
    amateur_config.enabled = true;
    amateur_config.frequency = UpdateFrequency::DAILY;
    amateur_config.auto_update = true;
    amateur_config.last_update = std::chrono::system_clock::now() - std::chrono::hours(25);
    sources_["amateur"] = amateur_config;
    
    // Military satellites (weekly)
    TLESourceConfig military_config;
    military_config.source = TLESource::CELESTRAK_MILITARY;
    military_config.url = "https://celestrak.org/NORAD/elements/gp.php?GROUP=military&FORMAT=tle";
    military_config.filename = "military.tle";
    military_config.enabled = true;
    military_config.frequency = UpdateFrequency::WEEKLY;
    military_config.auto_update = true;
    military_config.last_update = std::chrono::system_clock::now() - std::chrono::hours(25);
    sources_["military"] = military_config;
    
    // Starlink satellites (daily)
    TLESourceConfig starlink_config;
    starlink_config.source = TLESource::CELESTRAK_STARLINK;
    starlink_config.url = "https://celestrak.org/NORAD/elements/gp.php?GROUP=starlink&FORMAT=tle";
    starlink_config.filename = "starlink.tle";
    starlink_config.enabled = true;
    starlink_config.frequency = UpdateFrequency::DAILY;
    starlink_config.auto_update = true;
    starlink_config.last_update = std::chrono::system_clock::now() - std::chrono::hours(25);
    sources_["starlink"] = starlink_config;
    
    // Weather satellites (daily)
    TLESourceConfig weather_config;
    weather_config.source = TLESource::CELESTRAK_WEATHER;
    weather_config.url = "https://celestrak.org/NORAD/elements/weather.txt";
    weather_config.filename = "weather.tle";
    weather_config.enabled = true;
    weather_config.frequency = UpdateFrequency::DAILY;
    weather_config.auto_update = true;
    weather_config.last_update = std::chrono::system_clock::now() - std::chrono::hours(25);
    sources_["weather"] = weather_config;
    
    // ISS (hourly for critical tracking)
    TLESourceConfig iss_config;
    iss_config.source = TLESource::CUSTOM_URL;
    iss_config.url = "https://celestrak.org/NORAD/elements/gp.php?CATNR=25544&FORMAT=tle";
    iss_config.filename = "iss.tle";
    iss_config.enabled = true;
    iss_config.frequency = UpdateFrequency::HOURLY;
    iss_config.auto_update = true;
    iss_config.last_update = std::chrono::system_clock::now() - std::chrono::hours(2);
    sources_["iss"] = iss_config;
}

bool TLEUpdater::addSource(const std::string& name, TLESource source, 
                          UpdateFrequency frequency, const std::string& url) {
    if (!initialized_) {
        std::cerr << "Error: TLE updater not initialized" << std::endl;
        return false;
    }
    
    TLESourceConfig config;
    config.source = source;
    config.frequency = frequency;
    config.enabled = true;
    config.auto_update = true;
    config.last_update = std::chrono::system_clock::now() - std::chrono::hours(25);
    
    if (source == TLESource::CUSTOM_URL && !url.empty()) {
        config.url = url;
    } else {
        config.url = getSourceURL(source);
    }
    
    config.filename = name + ".tle";
    
    sources_[name] = config;
    std::cout << "Added TLE source: " << name << " (" << config.url << ")" << std::endl;
    
    return true;
}

bool TLEUpdater::removeSource(const std::string& name) {
    if (sources_.find(name) == sources_.end()) {
        std::cerr << "Error: Source not found: " << name << std::endl;
        return false;
    }
    
    sources_.erase(name);
    std::cout << "Removed TLE source: " << name << std::endl;
    
    return true;
}

bool TLEUpdater::updateTLE(const std::string& source_name) {
    if (!initialized_) {
        std::cerr << "Error: TLE updater not initialized" << std::endl;
        return false;
    }
    
    auto it = sources_.find(source_name);
    if (it == sources_.end()) {
        std::cerr << "Error: Source not found: " << source_name << std::endl;
        return false;
    }
    
    const TLESourceConfig& config = it->second;
    if (!config.enabled) {
        std::cout << "Source disabled: " << source_name << std::endl;
        return false;
    }
    
    std::cout << "Updating TLE data for: " << source_name << std::endl;
    std::cout << "URL: " << config.url << std::endl;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Download TLE data
    std::string filename = update_directory_ + "/" + config.filename;
    bool success = downloadTLEData(source_name, config.url, filename);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    // Update status
    UpdateStatus status;
    status.source_name = source_name;
    status.update_successful = success;
    status.update_time = std::chrono::system_clock::now();
    status.download_time = duration.count() / 1000.0;
    
    if (success) {
        // Get file size
        struct stat file_stat;
        if (stat(filename.c_str(), &file_stat) == 0) {
            status.file_size = file_stat.st_size;
        }
        
        // Process TLE data
        status.satellites_updated = processTLEData(source_name, download_buffer_);
        
        std::cout << "Successfully updated " << source_name 
                  << " (" << status.satellites_updated << " satellites, " 
                  << status.file_size << " bytes, " 
                  << std::fixed << std::setprecision(2) << status.download_time << "s)" << std::endl;
    } else {
        status.error_message = "Download failed";
        std::cerr << "Failed to update " << source_name << std::endl;
    }
    
    update_status_[source_name] = status;
    
    // Update last update time
    if (success) {
        sources_[source_name].last_update = std::chrono::system_clock::now();
    }
    
    return success;
}

uint32_t TLEUpdater::updateAllTLE() {
    if (!initialized_) {
        std::cerr << "Error: TLE updater not initialized" << std::endl;
        return 0;
    }
    
    std::cout << "Updating all TLE sources..." << std::endl;
    
    uint32_t success_count = 0;
    uint32_t total_count = 0;
    
    for (const auto& pair : sources_) {
        const std::string& name = pair.first;
        const TLESourceConfig& config = pair.second;
        
        if (config.enabled && config.auto_update) {
            total_count++;
            if (updateTLE(name)) {
                success_count++;
            }
        }
    }
    
    std::cout << "Updated " << success_count << "/" << total_count << " sources" << std::endl;
    
    return success_count > 0;
}

bool TLEUpdater::startAutoUpdate() {
    if (!initialized_) {
        std::cerr << "Error: TLE updater not initialized" << std::endl;
        return false;
    }
    
    if (auto_update_enabled_) {
        std::cout << "Auto-update already running" << std::endl;
        return true;
    }
    
    auto_update_enabled_ = true;
    stop_thread_ = false;
    
    // Start update thread
    update_thread_ = std::thread(&TLEUpdater::updateThreadFunction, this);
    
    std::cout << "Auto-update started" << std::endl;
    return true;
}

bool TLEUpdater::stopAutoUpdate() {
    if (!auto_update_enabled_) {
        return true;
    }
    
    std::cout << "Stopping auto-update..." << std::endl;
    
    auto_update_enabled_ = false;
    stop_thread_ = true;
    
    if (update_thread_.joinable()) {
        update_thread_.join();
    }
    
    std::cout << "Auto-update stopped" << std::endl;
    return true;
}

bool TLEUpdater::forceUpdate(const std::string& source_name) {
    if (!initialized_) {
        std::cerr << "Error: TLE updater not initialized" << std::endl;
        return false;
    }
    
    std::cout << "Force updating: " << source_name << std::endl;
    return updateTLE(source_name);
}

bool TLEUpdater::setUpdateParameters(uint32_t max_retries, uint32_t retry_delay, 
                                    uint32_t connection_timeout) {
    max_retries_ = max_retries;
    retry_delay_ = retry_delay;
    connection_timeout_ = connection_timeout;
    
    std::cout << "Update parameters set: retries=" << max_retries_ 
              << ", delay=" << retry_delay_ << "s, timeout=" << connection_timeout_ << "s" << std::endl;
    
    return true;
}

bool TLEUpdater::setSSLVerification(bool verify_ssl) {
    verify_ssl_ = verify_ssl;
    std::cout << "SSL verification: " << (verify_ssl_ ? "enabled" : "disabled") << std::endl;
    return true;
}

bool TLEUpdater::setSpaceTrackCredentials(const std::string& username, const std::string& password) {
    // Store credentials for Space-Track sources
    for (auto& pair : sources_) {
        if (pair.second.source == TLESource::SPACE_TRACK) {
            pair.second.username = username;
            pair.second.password = password;
        }
    }
    
    std::cout << "Space-Track credentials set" << std::endl;
    return true;
}

bool TLEUpdater::isInitialized() const {
    return initialized_;
}

bool TLEUpdater::isAutoUpdateRunning() const {
    return auto_update_enabled_;
}

std::string TLEUpdater::getStatus() const {
    std::ostringstream oss;
    oss << "TLE Updater Status:\n";
    oss << "  Initialized: " << (initialized_ ? "Yes" : "No") << "\n";
    oss << "  Auto-update: " << (auto_update_enabled_ ? "Running" : "Stopped") << "\n";
    oss << "  Sources: " << sources_.size() << "\n";
    oss << "  Update directory: " << update_directory_ << "\n";
    
    return oss.str();
}

UpdateStatus TLEUpdater::getUpdateStatus(const std::string& source_name) const {
    auto it = update_status_.find(source_name);
    if (it != update_status_.end()) {
        return it->second;
    }
    
    UpdateStatus empty_status;
    empty_status.source_name = source_name;
    empty_status.update_successful = false;
    empty_status.error_message = "No update status available";
    return empty_status;
}

std::map<std::string, UpdateStatus> TLEUpdater::getAllUpdateStatuses() const {
    return update_status_;
}

std::vector<std::string> TLEUpdater::getAvailableSources() const {
    std::vector<std::string> sources;
    for (const auto& pair : sources_) {
        sources.push_back(pair.first);
    }
    return sources;
}

TLESourceConfig TLEUpdater::getSourceConfiguration(const std::string& source_name) const {
    auto it = sources_.find(source_name);
    if (it != sources_.end()) {
        return it->second;
    }
    
    TLESourceConfig empty_config;
    return empty_config;
}

std::string TLEUpdater::getPerformanceMetrics() const {
    std::ostringstream oss;
    oss << "TLE Updater Performance Metrics:\n";
    oss << "  Total sources: " << sources_.size() << "\n";
    oss << "  Enabled sources: ";
    
    uint32_t enabled_count = 0;
    for (const auto& pair : sources_) {
        if (pair.second.enabled) {
            enabled_count++;
        }
    }
    oss << enabled_count << "\n";
    
    oss << "  Update statuses: " << update_status_.size() << "\n";
    
    return oss.str();
}

void TLEUpdater::updateThreadFunction() {
    std::cout << "Update thread started" << std::endl;
    
    while (!stop_thread_ && auto_update_enabled_) {
        std::lock_guard<std::mutex> lock(update_mutex_);
        
        // Check each source for updates
        for (const auto& pair : sources_) {
            if (stop_thread_) break;
            
            const std::string& name = pair.first;
            const TLESourceConfig& config = pair.second;
            
            if (config.enabled && config.auto_update && isUpdateNeeded(name)) {
                std::cout << "Auto-updating: " << name << std::endl;
                updateTLE(name);
            }
        }
        
        // Sleep for 1 hour before next check
        for (int i = 0; i < 3600 && !stop_thread_; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    
    std::cout << "Update thread stopped" << std::endl;
}

bool TLEUpdater::downloadTLEData(const std::string& source_name, const std::string& url, 
                                 const std::string& filename) {
    CURL* curl;
    CURLcode res;
    
    curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Error: Failed to initialize libcurl" << std::endl;
        return false;
    }
    
    // Clear download buffer
    download_buffer_.clear();
    
    // Set up curl options
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &download_buffer_);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, connection_timeout_);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify_ssl_ ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, verify_ssl_ ? 2L : 0L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "FGcom-Mumble-TLE-Updater/1.0");
    
    // Perform the request
    res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        std::cerr << "Error: curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        curl_easy_cleanup(curl);
        return false;
    }
    
    // Get HTTP response code
    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    
    if (response_code != 200) {
        std::cerr << "Error: HTTP response code: " << response_code << std::endl;
        curl_easy_cleanup(curl);
        return false;
    }
    
    curl_easy_cleanup(curl);
    
    // Write data to file
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error: Failed to open file for writing: " << filename << std::endl;
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(download_buffer_.data()), download_buffer_.size());
    file.close();
    
    return true;
}

uint32_t TLEUpdater::processTLEData(const std::string& source_name, const std::vector<uint8_t>& data) {
    // Simple TLE processing - count lines that look like TLE data
    std::string content(reinterpret_cast<const char*>(data.data()), data.size());
    std::istringstream iss(content);
    std::string line;
    uint32_t satellite_count = 0;
    
    while (std::getline(iss, line)) {
        // Count lines that start with "1 " or "2 " (TLE format)
        if (line.length() >= 2 && (line[0] == '1' || line[0] == '2') && line[1] == ' ') {
            satellite_count++;
        }
    }
    
    // Each satellite has 3 lines (name + 2 TLE lines), so divide by 3
    satellite_count = satellite_count / 3;
    
    return satellite_count;
}

std::string TLEUpdater::getSourceURL(TLESource source) const {
    switch (source) {
        case TLESource::CELESTRAK_AMATEUR:
            return "https://celestrak.org/NORAD/elements/gp.php?GROUP=amateur&FORMAT=tle";
        case TLESource::CELESTRAK_MILITARY:
            return "https://celestrak.org/NORAD/elements/gp.php?GROUP=military&FORMAT=tle";
        case TLESource::CELESTRAK_STARLINK:
            return "https://celestrak.org/NORAD/elements/gp.php?GROUP=starlink&FORMAT=tle";
        case TLESource::CELESTRAK_WEATHER:
            return "https://celestrak.org/NORAD/elements/weather.txt";
        case TLESource::AMSAT:
            return "https://amsat.org/tle/current/nasabare.txt";
        case TLESource::SPACE_TRACK:
            return "https://www.space-track.org/api/basicspacedata/query/class/tle_latest/format/tle";
        case TLESource::CUSTOM_URL:
        default:
            return "";
    }
}

bool TLEUpdater::isUpdateNeeded(const std::string& source_name) const {
    auto it = sources_.find(source_name);
    if (it == sources_.end()) {
        return false;
    }
    
    const TLESourceConfig& config = it->second;
    auto now = std::chrono::system_clock::now();
    auto time_since_update = now - config.last_update;
    
    switch (config.frequency) {
        case UpdateFrequency::HOURLY:
            return time_since_update >= std::chrono::hours(1);
        case UpdateFrequency::DAILY:
            return time_since_update >= std::chrono::hours(24);
        case UpdateFrequency::WEEKLY:
            return time_since_update >= std::chrono::hours(24 * 7);
        case UpdateFrequency::MANUAL:
        default:
            return false;
    }
}

} // namespace orbital
} // namespace satellites
} // namespace fgcom

// Main function for standalone TLE updater
int main(int argc, char* argv[]) {
    using namespace fgcom::satellites::orbital;
    
    // Set up signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    // Parse command line arguments
    std::string config_file = "";
    std::string update_dir = "./tle_data";
    std::string log_dir = "./logs";
    bool daemon_mode = false;
    bool force_update = false;
    std::string source_name = "";
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--config" && i + 1 < argc) {
            config_file = argv[++i];
        } else if (arg == "--update-dir" && i + 1 < argc) {
            update_dir = argv[++i];
        } else if (arg == "--log-dir" && i + 1 < argc) {
            log_dir = argv[++i];
        } else if (arg == "--daemon") {
            daemon_mode = true;
        } else if (arg == "--force") {
            force_update = true;
        } else if (arg == "--source" && i + 1 < argc) {
            source_name = argv[++i];
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "TLE Automatic Updater" << std::endl;
            std::cout << "Usage: " << argv[0] << " [options]" << std::endl;
            std::cout << "Options:" << std::endl;
            std::cout << "  --config <file>     Configuration file" << std::endl;
            std::cout << "  --update-dir <dir>  Update directory (default: ./tle_data)" << std::endl;
            std::cout << "  --log-dir <dir>     Log directory (default: ./logs)" << std::endl;
            std::cout << "  --daemon            Run in daemon mode" << std::endl;
            std::cout << "  --force             Force update all sources" << std::endl;
            std::cout << "  --source <name>     Update specific source" << std::endl;
            std::cout << "  --help, -h          Show this help" << std::endl;
            return 0;
        }
    }
    
    // Create TLE updater instance
    TLEUpdater updater;
    g_updater_instance = &updater;
    
    // Initialize updater
    if (!updater.initialize(update_dir)) {
        std::cerr << "Failed to initialize TLE updater" << std::endl;
        return 1;
    }
    
    std::cout << "TLE Updater started" << std::endl;
    std::cout << updater.getStatus() << std::endl;
    
    if (force_update) {
        if (!source_name.empty()) {
            std::cout << "Force updating source: " << source_name << std::endl;
            updater.forceUpdate(source_name);
        } else {
            std::cout << "Force updating all sources..." << std::endl;
            updater.updateAllTLE();
        }
    } else {
        // Start auto-update
        if (!updater.startAutoUpdate()) {
            std::cerr << "Failed to start auto-update" << std::endl;
            return 1;
        }
        
        if (daemon_mode) {
            std::cout << "Running in daemon mode..." << std::endl;
            // Keep running until shutdown signal
            while (!g_shutdown_requested) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        } else {
            std::cout << "Press Ctrl+C to stop..." << std::endl;
            // Keep running until shutdown signal
            while (!g_shutdown_requested) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    }
    
    std::cout << "TLE Updater stopped" << std::endl;
    return 0;
}
