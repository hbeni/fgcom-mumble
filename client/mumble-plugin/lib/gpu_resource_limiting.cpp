#include "gpu_resource_limiting.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <thread>
#include <filesystem>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#else
#include <sys/sysinfo.h>
#include <dirent.h>
#include <fstream>
#endif

namespace FGCom_GPU_ResourceLimiting {

// Static member initialization
GPUResourceLimitingManager* GPUResourceLimitingManager::instance = nullptr;
std::once_flag GPUResourceLimitingManager::init_flag;

// Constructor
GPUResourceLimitingManager::GPUResourceLimitingManager() {
    // Initialize known game processes
    known_game_processes = {
        "FlightGear.exe", "fgfs.exe", "X-Plane.exe", "x-plane.exe",
        "MicrosoftFlightSimulator.exe", "DCS.exe", "dcs.exe",
        "arma3.exe", "Arma3.exe", "Squad.exe", "squad.exe",
        "mumble.exe", "Mumble.exe", "teamspeak3.exe", "TeamSpeak3.exe"
    };
    
    // Initialize known game windows
    known_game_windows = {
        "FlightGear", "X-Plane", "Microsoft Flight Simulator",
        "DCS World", "Arma 3", "Squad", "Mumble", "TeamSpeak"
    };
    
    // Initialize timestamps
    stats.last_update = std::chrono::steady_clock::now();
    stats.last_alert = std::chrono::steady_clock::now();
    system_load.last_check = std::chrono::steady_clock::now();
}

// Destructor
GPUResourceLimitingManager::~GPUResourceLimitingManager() {
    shutdown();
}

// Singleton access
GPUResourceLimitingManager& GPUResourceLimitingManager::getInstance() {
    std::call_once(init_flag, []() {
        instance = new GPUResourceLimitingManager();
    });
    return *instance;
}

// Initialization
bool GPUResourceLimitingManager::initialize(const std::string& config_path) {
    std::lock_guard<std::mutex> lock(config_mutex);
    
    if (is_initialized.load()) {
        return true;
    }
    
    try {
        // Load configuration
        loadConfiguration();
        
        // Detect GPU capabilities
        gpu_available.store(detectGPUCapabilities());
        
        // Initialize monitoring if enabled
        if (config.enable_gpu_monitoring) {
            startMonitoring();
        }
        
        is_initialized.store(true);
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Failed to initialize GPU Resource Limiting Manager: " << e.what() << std::endl;
        return false;
    }
}

// Shutdown
void GPUResourceLimitingManager::shutdown() {
    if (!is_initialized.load()) {
        return;
    }
    
    shutdown_requested.store(true);
    
    // Stop monitoring
    stopMonitoring();
    
    // Wait for threads to finish
    if (monitoring_thread.joinable()) {
        monitoring_thread.join();
    }
    if (statistics_thread.joinable()) {
        statistics_thread.join();
    }
    
    is_initialized.store(false);
}

// Check if initialized
bool GPUResourceLimitingManager::isInitialized() const {
    return is_initialized.load();
}

// Configuration management
void GPUResourceLimitingManager::setConfiguration(const GPUResourceConfig& new_config) {
    std::lock_guard<std::mutex> lock(config_mutex);
    config = new_config;
    validateConfiguration();
}

GPUResourceConfig GPUResourceLimitingManager::getConfiguration() const {
    std::lock_guard<std::mutex> lock(config_mutex);
    return config;
}

void GPUResourceLimitingManager::updateConfiguration(const std::string& key, const std::string& value) {
    std::lock_guard<std::mutex> lock(config_mutex);
    
    if (key == "enable_gpu_resource_limiting") {
        config.enable_gpu_resource_limiting = (value == "true");
    } else if (key == "gpu_usage_percentage_limit") {
        config.gpu_usage_percentage_limit = std::stoi(value);
    } else if (key == "gpu_memory_limit_mb") {
        config.gpu_memory_limit_mb = std::stoi(value);
    } else if (key == "gpu_priority_level") {
        config.gpu_priority_level = std::stoi(value);
    } else if (key == "enable_adaptive_gpu_usage") {
        config.enable_adaptive_gpu_usage = (value == "true");
    } else if (key == "min_gpu_usage_percentage") {
        config.min_gpu_usage_percentage = std::stoi(value);
    } else if (key == "max_gpu_usage_percentage") {
        config.max_gpu_usage_percentage = std::stoi(value);
    } else if (key == "game_detection_reduction") {
        config.game_detection_reduction = std::stoi(value);
    } else if (key == "high_load_reduction") {
        config.high_load_reduction = std::stoi(value);
    } else if (key == "low_battery_reduction") {
        config.low_battery_reduction = std::stoi(value);
    } else if (key == "enable_gpu_monitoring") {
        config.enable_gpu_monitoring = (value == "true");
    } else if (key == "gpu_check_interval_ms") {
        config.gpu_check_interval_ms = std::stoi(value);
    } else if (key == "enforcement_strictness") {
        config.enforcement_strictness = std::stoi(value);
    } else if (key == "enable_gpu_usage_logging") {
        config.enable_gpu_usage_logging = (value == "true");
    } else if (key == "gpu_usage_log_file") {
        config.gpu_usage_log_file = value;
    } else if (key == "enable_gpu_statistics") {
        config.enable_gpu_statistics = (value == "true");
    } else if (key == "gpu_statistics_interval") {
        config.gpu_statistics_interval = std::stoi(value);
    } else if (key == "enable_gpu_alerts") {
        config.enable_gpu_alerts = (value == "true");
    } else if (key == "gpu_alert_threshold") {
        config.gpu_alert_threshold = std::stoi(value);
    } else if (key == "gpu_alert_cooldown") {
        config.gpu_alert_cooldown = std::stoi(value);
    }
    
    validateConfiguration();
}

// GPU resource management
bool GPUResourceLimitingManager::canUseGPU(double required_memory_mb) {
    if (!is_initialized.load() || !config.enable_gpu_resource_limiting) {
        return true;
    }
    
    std::lock_guard<std::mutex> lock(stats_mutex);
    
    // Check if GPU is available
    if (!gpu_available.load()) {
        return false;
    }
    
    // Check memory requirements
    if (required_memory_mb > 0 && current_gpu_memory.load() + required_memory_mb > config.gpu_memory_limit_mb) {
        return false;
    }
    
    // Check usage percentage
    double current_usage = current_gpu_usage.load();
    double max_usage = config.gpu_usage_percentage_limit;
    
    // Apply adaptive limits if enabled
    if (config.enable_adaptive_gpu_usage) {
        max_usage = calculateAdaptiveUsageLimit();
    }
    
    return current_usage < max_usage;
}

bool GPUResourceLimitingManager::requestGPUResources(double memory_mb, double max_usage_percentage) {
    if (!canUseGPU(memory_mb)) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(stats_mutex);
    
    // Update statistics
    stats.total_compute_operations++;
    stats.current_memory_usage_mb += memory_mb;
    
    // Update GPU usage
    if (max_usage_percentage > 0) {
        current_gpu_usage.store(max_usage_percentage);
    }
    
    return true;
}

void GPUResourceLimitingManager::releaseGPUResources() {
    std::lock_guard<std::mutex> lock(stats_mutex);
    
    // Reset GPU usage
    current_gpu_usage.store(0.0);
    current_gpu_memory.store(0.0);
}

void GPUResourceLimitingManager::setGPUUsageLimit(double percentage) {
    std::lock_guard<std::mutex> lock(config_mutex);
    config.gpu_usage_percentage_limit = static_cast<int>(percentage);
}

void GPUResourceLimitingManager::setGPUMemoryLimit(double memory_mb) {
    std::lock_guard<std::mutex> lock(config_mutex);
    config.gpu_memory_limit_mb = static_cast<int>(memory_mb);
}

// GPU usage monitoring
GPUUsageStats GPUResourceLimitingManager::getGPUUsageStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex);
    return stats;
}

SystemLoadInfo GPUResourceLimitingManager::getSystemLoadInfo() const {
    std::lock_guard<std::mutex> lock(system_load_mutex);
    return system_load;
}

double GPUResourceLimitingManager::getCurrentGPUUsagePercentage() const {
    return current_gpu_usage.load();
}

double GPUResourceLimitingManager::getCurrentGPUMemoryUsage() const {
    return current_gpu_memory.load();
}

bool GPUResourceLimitingManager::isGPUThrottled() const {
    return current_gpu_usage.load() > config.gpu_usage_percentage_limit * 0.8;
}

bool GPUResourceLimitingManager::isGPUBlocked() const {
    return current_gpu_usage.load() >= config.gpu_usage_percentage_limit;
}

// Adaptive GPU usage
void GPUResourceLimitingManager::enableAdaptiveUsage(bool enable) {
    std::lock_guard<std::mutex> lock(config_mutex);
    config.enable_adaptive_gpu_usage = enable;
}

void GPUResourceLimitingManager::setAdaptiveLimits(double min_percentage, double max_percentage) {
    std::lock_guard<std::mutex> lock(config_mutex);
    config.min_gpu_usage_percentage = static_cast<int>(min_percentage);
    config.max_gpu_usage_percentage = static_cast<int>(max_percentage);
}

double GPUResourceLimitingManager::calculateAdaptiveUsageLimit() const {
    if (!config.enable_adaptive_gpu_usage) {
        return config.gpu_usage_percentage_limit;
    }
    
    std::lock_guard<std::mutex> lock(system_load_mutex);
    
    double base_limit = config.gpu_usage_percentage_limit;
    double reduction = 0.0;
    
    // Apply game detection reduction
    if (system_load.game_detected) {
        reduction += config.game_detection_reduction;
    }
    
    // Apply high load reduction
    if (system_load.high_system_load) {
        reduction += config.high_load_reduction;
    }
    
    // Apply low battery reduction
    if (system_load.low_battery) {
        reduction += config.low_battery_reduction;
    }
    
    // Calculate final limit
    double final_limit = base_limit * (1.0 - reduction / 100.0);
    
    // Ensure within min/max bounds
    final_limit = std::max(final_limit, static_cast<double>(config.min_gpu_usage_percentage));
    final_limit = std::min(final_limit, static_cast<double>(config.max_gpu_usage_percentage));
    
    return final_limit;
}

// Game detection and priority
void GPUResourceLimitingManager::enableGameDetection(bool enable) {
    std::lock_guard<std::mutex> lock(config_mutex);
    // Game detection is always enabled when monitoring is enabled
}

void GPUResourceLimitingManager::addGameProcess(const std::string& process_name) {
    std::lock_guard<std::mutex> lock(config_mutex);
    known_game_processes.push_back(process_name);
}

void GPUResourceLimitingManager::addGameWindow(const std::string& window_title) {
    std::lock_guard<std::mutex> lock(config_mutex);
    known_game_windows.push_back(window_title);
}

bool GPUResourceLimitingManager::isGameDetected() const {
    std::lock_guard<std::mutex> lock(system_load_mutex);
    return system_load.game_detected;
}

void GPUResourceLimitingManager::setGamePriority(bool prioritize_game) {
    std::lock_guard<std::mutex> lock(config_mutex);
    if (prioritize_game) {
        config.gpu_priority_level = 1; // Lower priority for FGCom
    } else {
        config.gpu_priority_level = 5; // Normal priority
    }
}

// System load management
void GPUResourceLimitingManager::setHighLoadThreshold(double cpu_threshold, double memory_threshold) {
    std::lock_guard<std::mutex> lock(system_load_mutex);
    // Implementation would set thresholds for high load detection
}

void GPUResourceLimitingManager::setLowBatteryThreshold(double battery_threshold) {
    std::lock_guard<std::mutex> lock(system_load_mutex);
    // Implementation would set battery threshold
}

void GPUResourceLimitingManager::enableSystemLoadMonitoring(bool enable) {
    std::lock_guard<std::mutex> lock(config_mutex);
    config.enable_gpu_monitoring = enable;
}

// GPU monitoring and enforcement
void GPUResourceLimitingManager::startMonitoring() {
    if (is_monitoring.load()) {
        return;
    }
    
    is_monitoring.store(true);
    shutdown_requested.store(false);
    
    // Start monitoring thread
    monitoring_thread = std::thread(&GPUResourceLimitingManager::monitoringLoop, this);
    
    // Start statistics thread if enabled
    if (config.enable_gpu_statistics) {
        statistics_thread = std::thread(&GPUResourceLimitingManager::statisticsLoop, this);
    }
}

void GPUResourceLimitingManager::stopMonitoring() {
    if (!is_monitoring.load()) {
        return;
    }
    
    is_monitoring.store(false);
    shutdown_requested.store(true);
    monitoring_cv.notify_all();
}

bool GPUResourceLimitingManager::isMonitoring() const {
    return is_monitoring.load();
}

void GPUResourceLimitingManager::setMonitoringInterval(int interval_ms) {
    std::lock_guard<std::mutex> lock(config_mutex);
    config.gpu_check_interval_ms = interval_ms;
}

void GPUResourceLimitingManager::setEnforcementStrictness(int strictness) {
    std::lock_guard<std::mutex> lock(config_mutex);
    config.enforcement_strictness = std::max(1, std::min(5, strictness));
}

// Logging and statistics
void GPUResourceLimitingManager::enableLogging(bool enable, const std::string& log_file) {
    std::lock_guard<std::mutex> lock(config_mutex);
    config.enable_gpu_usage_logging = enable;
    if (!log_file.empty()) {
        config.gpu_usage_log_file = log_file;
    }
}

void GPUResourceLimitingManager::enableStatistics(bool enable, int interval_seconds) {
    std::lock_guard<std::mutex> lock(config_mutex);
    config.enable_gpu_statistics = enable;
    config.gpu_statistics_interval = interval_seconds;
}

void GPUResourceLimitingManager::enableAlerts(bool enable, double threshold) {
    std::lock_guard<std::mutex> lock(config_mutex);
    config.enable_gpu_alerts = enable;
    config.gpu_alert_threshold = static_cast<int>(threshold);
}

// API for external applications
std::string GPUResourceLimitingManager::getGPUStatusJSON() const {
    std::lock_guard<std::mutex> lock(stats_mutex);
    
    std::ostringstream json;
    json << "{";
    json << "\"gpu_available\":" << (gpu_available.load() ? "true" : "false") << ",";
    json << "\"current_usage_percentage\":" << current_gpu_usage.load() << ",";
    json << "\"current_memory_usage_mb\":" << current_gpu_memory.load() << ",";
    json << "\"usage_limit_percentage\":" << config.gpu_usage_percentage_limit << ",";
    json << "\"memory_limit_mb\":" << config.gpu_memory_limit_mb << ",";
    json << "\"is_throttled\":" << (isGPUThrottled() ? "true" : "false") << ",";
    json << "\"is_blocked\":" << (isGPUBlocked() ? "true" : "false") << ",";
    json << "\"adaptive_usage_enabled\":" << (config.enable_adaptive_gpu_usage ? "true" : "false") << ",";
    json << "\"game_detected\":" << (system_load.game_detected ? "true" : "false") << ",";
    json << "\"monitoring_enabled\":" << (is_monitoring.load() ? "true" : "false");
    json << "}";
    
    return json.str();
}

std::string GPUResourceLimitingManager::getGPUUsageReport() const {
    std::lock_guard<std::mutex> lock(stats_mutex);
    
    std::ostringstream report;
    report << "GPU Resource Usage Report\n";
    report << "========================\n";
    report << "GPU Available: " << (gpu_available.load() ? "Yes" : "No") << "\n";
    report << "Current Usage: " << current_gpu_usage.load() << "%\n";
    report << "Current Memory: " << current_gpu_memory.load() << " MB\n";
    report << "Usage Limit: " << config.gpu_usage_percentage_limit << "%\n";
    report << "Memory Limit: " << config.gpu_memory_limit_mb << " MB\n";
    report << "Throttled: " << (isGPUThrottled() ? "Yes" : "No") << "\n";
    report << "Blocked: " << (isGPUBlocked() ? "Yes" : "No") << "\n";
    report << "Game Detected: " << (system_load.game_detected ? "Yes" : "No") << "\n";
    report << "Monitoring: " << (is_monitoring.load() ? "Active" : "Inactive") << "\n";
    
    return report.str();
}

std::string GPUResourceLimitingManager::getGPUConfigurationJSON() const {
    std::lock_guard<std::mutex> lock(config_mutex);
    
    std::ostringstream json;
    json << "{";
    json << "\"enable_gpu_resource_limiting\":" << (config.enable_gpu_resource_limiting ? "true" : "false") << ",";
    json << "\"gpu_usage_percentage_limit\":" << config.gpu_usage_percentage_limit << ",";
    json << "\"gpu_memory_limit_mb\":" << config.gpu_memory_limit_mb << ",";
    json << "\"gpu_priority_level\":" << config.gpu_priority_level << ",";
    json << "\"enable_adaptive_gpu_usage\":" << (config.enable_adaptive_gpu_usage ? "true" : "false") << ",";
    json << "\"min_gpu_usage_percentage\":" << config.min_gpu_usage_percentage << ",";
    json << "\"max_gpu_usage_percentage\":" << config.max_gpu_usage_percentage << ",";
    json << "\"game_detection_reduction\":" << config.game_detection_reduction << ",";
    json << "\"high_load_reduction\":" << config.high_load_reduction << ",";
    json << "\"low_battery_reduction\":" << config.low_battery_reduction << ",";
    json << "\"enable_gpu_monitoring\":" << (config.enable_gpu_monitoring ? "true" : "false") << ",";
    json << "\"gpu_check_interval_ms\":" << config.gpu_check_interval_ms << ",";
    json << "\"enforcement_strictness\":" << config.enforcement_strictness << ",";
    json << "\"enable_gpu_usage_logging\":" << (config.enable_gpu_usage_logging ? "true" : "false") << ",";
    json << "\"gpu_usage_log_file\":\"" << config.gpu_usage_log_file << "\",";
    json << "\"enable_gpu_statistics\":" << (config.enable_gpu_statistics ? "true" : "false") << ",";
    json << "\"gpu_statistics_interval\":" << config.gpu_statistics_interval << ",";
    json << "\"enable_gpu_alerts\":" << (config.enable_gpu_alerts ? "true" : "false") << ",";
    json << "\"gpu_alert_threshold\":" << config.gpu_alert_threshold << ",";
    json << "\"gpu_alert_cooldown\":" << config.gpu_alert_cooldown;
    json << "}";
    
    return json.str();
}

// Utility methods
void GPUResourceLimitingManager::resetStatistics() {
    std::lock_guard<std::mutex> lock(stats_mutex);
    stats = GPUUsageStats();
    stats.last_update = std::chrono::steady_clock::now();
}

void GPUResourceLimitingManager::clearLogs() {
    if (config.enable_gpu_usage_logging && !config.gpu_usage_log_file.empty()) {
        std::ofstream log_file(config.gpu_usage_log_file, std::ios::trunc);
        log_file.close();
    }
}

void GPUResourceLimitingManager::exportStatistics(const std::string& filename) const {
    std::lock_guard<std::mutex> lock(stats_mutex);
    
    std::ofstream file(filename);
    if (file.is_open()) {
        file << "GPU Resource Statistics Export\n";
        file << "==============================\n";
        file << "Export Time: " << std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count() << "\n";
        file << "Current Usage: " << current_gpu_usage.load() << "%\n";
        file << "Current Memory: " << current_gpu_memory.load() << " MB\n";
        file << "Average Usage: " << stats.average_usage_percentage << "%\n";
        file << "Peak Usage: " << stats.peak_usage_percentage << "%\n";
        file << "Total Operations: " << stats.total_compute_operations << "\n";
        file << "Throttled Operations: " << stats.throttled_operations << "\n";
        file << "Blocked Operations: " << stats.blocked_operations << "\n";
        file.close();
    }
}

void GPUResourceLimitingManager::importConfiguration(const std::string& filename) {
    std::ifstream file(filename);
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            size_t pos = line.find('=');
            if (pos != std::string::npos) {
                std::string key = line.substr(0, pos);
                std::string value = line.substr(pos + 1);
                updateConfiguration(key, value);
            }
        }
        file.close();
    }
}

// Internal methods implementation
void GPUResourceLimitingManager::monitoringLoop() {
    while (!shutdown_requested.load() && is_monitoring.load()) {
        try {
            updateSystemLoad();
            updateGPUUsage();
            enforceGPULimits();
            
            if (config.enable_gpu_usage_logging) {
                logGPUUsage();
            }
            
            if (config.enable_gpu_alerts) {
                checkGPUAlerts();
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(config.gpu_check_interval_ms));
            
        } catch (const std::exception& e) {
            std::cerr << "Error in GPU monitoring loop: " << e.what() << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
    }
}

void GPUResourceLimitingManager::statisticsLoop() {
    while (!shutdown_requested.load() && is_monitoring.load()) {
        try {
            collectGPUStatistics();
            std::this_thread::sleep_for(std::chrono::seconds(config.gpu_statistics_interval));
            
        } catch (const std::exception& e) {
            std::cerr << "Error in GPU statistics loop: " << e.what() << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
    }
}

void GPUResourceLimitingManager::updateSystemLoad() {
    std::lock_guard<std::mutex> lock(system_load_mutex);
    
    // Update system load information
    system_load.cpu_usage_percentage = getCPUUsage();
    system_load.memory_usage_percentage = getMemoryUsage();
    system_load.gpu_usage_percentage = getCurrentGPUUsage();
    system_load.game_detected = isGameProcessRunning() || isGameWindowActive();
    system_load.low_battery = isLowBattery();
    system_load.high_system_load = isHighSystemLoad();
    system_load.last_check = std::chrono::steady_clock::now();
}

void GPUResourceLimitingManager::updateGPUUsage() {
    current_gpu_usage.store(getCurrentGPUUsage());
    current_gpu_memory.store(getCurrentGPUMemoryUsage());
}

void GPUResourceLimitingManager::detectGameRunning() {
    system_load.game_detected = isGameProcessRunning() || isGameWindowActive();
}

void GPUResourceLimitingManager::checkBatteryStatus() {
    system_load.low_battery = isLowBattery();
}

void GPUResourceLimitingManager::enforceGPULimits() {
    double current_usage = current_gpu_usage.load();
    double limit = config.gpu_usage_percentage_limit;
    
    if (config.enable_adaptive_gpu_usage) {
        limit = calculateAdaptiveUsageLimit();
    }
    
    if (current_usage > limit) {
        if (current_usage > limit * 1.2) {
            blockGPUUsage();
        } else {
            throttleGPUUsage(limit);
        }
    }
}

void GPUResourceLimitingManager::logGPUUsage() {
    if (!config.enable_gpu_usage_logging || config.gpu_usage_log_file.empty()) {
        return;
    }
    
    std::ofstream log_file(config.gpu_usage_log_file, std::ios::app);
    if (log_file.is_open()) {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        log_file << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << " ";
        log_file << "GPU Usage: " << current_gpu_usage.load() << "%, ";
        log_file << "Memory: " << current_gpu_memory.load() << "MB, ";
        log_file << "Game Detected: " << (system_load.game_detected ? "Yes" : "No") << ", ";
        log_file << "Throttled: " << (isGPUThrottled() ? "Yes" : "No") << "\n";
        log_file.close();
    }
}

void GPUResourceLimitingManager::collectGPUStatistics() {
    std::lock_guard<std::mutex> lock(stats_mutex);
    
    double current_usage = current_gpu_usage.load();
    stats.current_usage_percentage = current_usage;
    stats.current_memory_usage_mb = current_gpu_memory.load();
    
    // Update average usage
    if (stats.average_usage_percentage == 0.0) {
        stats.average_usage_percentage = current_usage;
    } else {
        stats.average_usage_percentage = (stats.average_usage_percentage + current_usage) / 2.0;
    }
    
    // Update peak usage
    if (current_usage > stats.peak_usage_percentage) {
        stats.peak_usage_percentage = current_usage;
    }
    
    stats.last_update = std::chrono::steady_clock::now();
}

void GPUResourceLimitingManager::checkGPUAlerts() {
    if (!config.enable_gpu_alerts) {
        return;
    }
    
    double current_usage = current_gpu_usage.load();
    if (current_usage > config.gpu_alert_threshold) {
        auto now = std::chrono::steady_clock::now();
        auto time_since_last_alert = std::chrono::duration_cast<std::chrono::seconds>(
            now - stats.last_alert).count();
        
        if (time_since_last_alert > config.gpu_alert_cooldown) {
            std::cout << "GPU Usage Alert: " << current_usage << "% (Threshold: " 
                      << config.gpu_alert_threshold << "%)" << std::endl;
            stats.last_alert = now;
        }
    }
}

// GPU detection and monitoring implementation
bool GPUResourceLimitingManager::detectGPUCapabilities() {
    // Mock implementation - in real implementation, this would detect actual GPU capabilities
    return true;
}

double GPUResourceLimitingManager::getCurrentGPUUsage() {
    // Mock implementation - in real implementation, this would query actual GPU usage
    return current_gpu_usage.load();
}

double GPUResourceLimitingManager::getCurrentGPUMemoryUsage() {
    // Mock implementation - in real implementation, this would query actual GPU memory usage
    return current_gpu_memory.load();
}

bool GPUResourceLimitingManager::isGPUAvailable() {
    return gpu_available.load();
}

// Game detection methods
bool GPUResourceLimitingManager::isGameProcessRunning() {
    // Mock implementation - in real implementation, this would check running processes
    return false;
}

bool GPUResourceLimitingManager::isGameWindowActive() {
    // Mock implementation - in real implementation, this would check active windows
    return false;
}

void GPUResourceLimitingManager::updateKnownGameProcesses() {
    // Implementation would update the list of known game processes
}

// System monitoring
double GPUResourceLimitingManager::getCPUUsage() {
    // Mock implementation - in real implementation, this would query actual CPU usage
    return 0.0;
}

double GPUResourceLimitingManager::getMemoryUsage() {
    // Mock implementation - in real implementation, this would query actual memory usage
    return 0.0;
}

bool GPUResourceLimitingManager::isLowBattery() {
    // Mock implementation - in real implementation, this would check battery status
    return false;
}

bool GPUResourceLimitingManager::isHighSystemLoad() {
    // Mock implementation - in real implementation, this would check system load
    return false;
}

// GPU priority and throttling
void GPUResourceLimitingManager::setGPUPriority(int priority) {
    // Implementation would set GPU priority
}

void GPUResourceLimitingManager::throttleGPUUsage(double target_usage) {
    // Implementation would throttle GPU usage
}

void GPUResourceLimitingManager::blockGPUUsage() {
    // Implementation would block GPU usage
}

void GPUResourceLimitingManager::allowGPUUsage() {
    // Implementation would allow GPU usage
}

// Configuration management
void GPUResourceLimitingManager::loadConfiguration() {
    // Mock implementation - in real implementation, this would load from config file
}

void GPUResourceLimitingManager::saveConfiguration() {
    // Mock implementation - in real implementation, this would save to config file
}

void GPUResourceLimitingManager::validateConfiguration() {
    // Validate configuration values
    config.gpu_usage_percentage_limit = std::max(0, std::min(100, config.gpu_usage_percentage_limit));
    config.gpu_memory_limit_mb = std::max(0, config.gpu_memory_limit_mb);
    config.gpu_priority_level = std::max(1, std::min(10, config.gpu_priority_level));
    config.min_gpu_usage_percentage = std::max(0, std::min(100, config.min_gpu_usage_percentage));
    config.max_gpu_usage_percentage = std::max(0, std::min(100, config.max_gpu_usage_percentage));
    config.enforcement_strictness = std::max(1, std::min(5, config.enforcement_strictness));
}

// GPU Resource Limiting API implementation
bool GPUResourceLimitingAPI::canUseGPU(double memory_mb) {
    return GPUResourceLimitingManager::getInstance().canUseGPU(memory_mb);
}

bool GPUResourceLimitingAPI::requestGPUResources(double memory_mb, double max_usage) {
    return GPUResourceLimitingManager::getInstance().requestGPUResources(memory_mb, max_usage);
}

void GPUResourceLimitingAPI::releaseGPUResources() {
    GPUResourceLimitingManager::getInstance().releaseGPUResources();
}

void GPUResourceLimitingAPI::setGPUUsageLimit(double percentage) {
    GPUResourceLimitingManager::getInstance().setGPUUsageLimit(percentage);
}

void GPUResourceLimitingAPI::setGPUMemoryLimit(double memory_mb) {
    GPUResourceLimitingManager::getInstance().setGPUMemoryLimit(memory_mb);
}

double GPUResourceLimitingAPI::getCurrentGPUUsage() {
    return GPUResourceLimitingManager::getInstance().getCurrentGPUUsagePercentage();
}

double GPUResourceLimitingAPI::getCurrentGPUMemoryUsage() {
    return GPUResourceLimitingManager::getInstance().getCurrentGPUMemoryUsage();
}

bool GPUResourceLimitingAPI::isGPUAvailable() {
    return GPUResourceLimitingManager::getInstance().isInitialized();
}

bool GPUResourceLimitingAPI::isGPUThrottled() {
    return GPUResourceLimitingManager::getInstance().isGPUThrottled();
}

bool GPUResourceLimitingAPI::isGPUBlocked() {
    return GPUResourceLimitingManager::getInstance().isGPUBlocked();
}

void GPUResourceLimitingAPI::setConfiguration(const std::string& key, const std::string& value) {
    GPUResourceLimitingManager::getInstance().updateConfiguration(key, value);
}

std::string GPUResourceLimitingAPI::getConfiguration(const std::string& key) {
    // Implementation would return specific configuration value
    return "";
}

std::string GPUResourceLimitingAPI::getConfigurationJSON() {
    return GPUResourceLimitingManager::getInstance().getGPUConfigurationJSON();
}

std::string GPUResourceLimitingAPI::getGPUStatusJSON() {
    return GPUResourceLimitingManager::getInstance().getGPUStatusJSON();
}

std::string GPUResourceLimitingAPI::getGPUUsageReport() {
    return GPUResourceLimitingManager::getInstance().getGPUUsageReport();
}

std::string GPUResourceLimitingAPI::getSystemLoadInfo() {
    return GPUResourceLimitingManager::getInstance().getSystemLoadInfo().game_detected ? "Game Detected" : "No Game";
}

void GPUResourceLimitingAPI::setGamePriority(bool prioritize_game) {
    GPUResourceLimitingManager::getInstance().setGamePriority(prioritize_game);
}

bool GPUResourceLimitingAPI::isGameDetected() {
    return GPUResourceLimitingManager::getInstance().isGameDetected();
}

void GPUResourceLimitingAPI::addGameProcess(const std::string& process_name) {
    GPUResourceLimitingManager::getInstance().addGameProcess(process_name);
}

void GPUResourceLimitingAPI::addGameWindow(const std::string& window_title) {
    GPUResourceLimitingManager::getInstance().addGameWindow(window_title);
}

void GPUResourceLimitingAPI::enableAdaptiveUsage(bool enable) {
    GPUResourceLimitingManager::getInstance().enableAdaptiveUsage(enable);
}

double GPUResourceLimitingAPI::calculateAdaptiveUsageLimit() {
    return GPUResourceLimitingManager::getInstance().calculateAdaptiveUsageLimit();
}

void GPUResourceLimitingAPI::setAdaptiveLimits(double min_percentage, double max_percentage) {
    GPUResourceLimitingManager::getInstance().setAdaptiveLimits(min_percentage, max_percentage);
}

void GPUResourceLimitingAPI::startMonitoring() {
    GPUResourceLimitingManager::getInstance().startMonitoring();
}

void GPUResourceLimitingAPI::stopMonitoring() {
    GPUResourceLimitingManager::getInstance().stopMonitoring();
}

bool GPUResourceLimitingAPI::isMonitoring() {
    return GPUResourceLimitingManager::getInstance().isMonitoring();
}

void GPUResourceLimitingAPI::setEnforcementStrictness(int strictness) {
    GPUResourceLimitingManager::getInstance().setEnforcementStrictness(strictness);
}

void GPUResourceLimitingAPI::enableLogging(bool enable, const std::string& log_file) {
    GPUResourceLimitingManager::getInstance().enableLogging(enable, log_file);
}

void GPUResourceLimitingAPI::enableStatistics(bool enable, int interval_seconds) {
    GPUResourceLimitingManager::getInstance().enableStatistics(enable, interval_seconds);
}

void GPUResourceLimitingAPI::enableAlerts(bool enable, double threshold) {
    GPUResourceLimitingManager::getInstance().enableAlerts(enable, threshold);
}

void GPUResourceLimitingAPI::resetStatistics() {
    GPUResourceLimitingManager::getInstance().resetStatistics();
}

void GPUResourceLimitingAPI::clearLogs() {
    GPUResourceLimitingManager::getInstance().clearLogs();
}

void GPUResourceLimitingAPI::exportStatistics(const std::string& filename) {
    GPUResourceLimitingManager::getInstance().exportStatistics(filename);
}

void GPUResourceLimitingAPI::importConfiguration(const std::string& filename) {
    GPUResourceLimitingManager::getInstance().importConfiguration(filename);
}

} // namespace FGCom_GPU_ResourceLimiting

