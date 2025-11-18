#ifndef FGCOM_GPU_RESOURCE_LIMITING_H
#define FGCOM_GPU_RESOURCE_LIMITING_H

#include <string>
#include <map>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <vector>
#include <memory>

namespace FGCom_GPU_ResourceLimiting {

// GPU Resource Limiting Configuration
struct GPUResourceConfig {
    bool enable_gpu_resource_limiting = true;
    int gpu_usage_percentage_limit = 30;
    int gpu_memory_limit_mb = 256;
    int gpu_priority_level = 3;
    bool enable_adaptive_gpu_usage = true;
    int min_gpu_usage_percentage = 10;
    int max_gpu_usage_percentage = 50;
    int game_detection_reduction = 50;
    int high_load_reduction = 30;
    int low_battery_reduction = 40;
    bool enable_gpu_monitoring = true;
    int gpu_check_interval_ms = 1000;
    int enforcement_strictness = 3;
    bool enable_gpu_usage_logging = false;
    std::string gpu_usage_log_file = "gpu_usage.log";
    bool enable_gpu_statistics = true;
    int gpu_statistics_interval = 60;
    bool enable_gpu_alerts = true;
    int gpu_alert_threshold = 80;
    int gpu_alert_cooldown = 300;
};

// GPU Usage Statistics
struct GPUUsageStats {
    double current_usage_percentage = 0.0;
    double current_memory_usage_mb = 0.0;
    double average_usage_percentage = 0.0;
    double peak_usage_percentage = 0.0;
    double total_compute_time_ms = 0.0;
    int total_compute_operations = 0;
    int throttled_operations = 0;
    int blocked_operations = 0;
    std::chrono::steady_clock::time_point last_update;
    std::chrono::steady_clock::time_point last_alert;
};

// System Load Information
struct SystemLoadInfo {
    double cpu_usage_percentage = 0.0;
    double memory_usage_percentage = 0.0;
    double gpu_usage_percentage = 0.0;
    bool game_detected = false;
    bool low_battery = false;
    bool high_system_load = false;
    std::chrono::steady_clock::time_point last_check;
};

// GPU Resource Limiting Manager
class GPUResourceLimitingManager {
private:
    static GPUResourceLimitingManager* instance;
    static std::once_flag init_flag;
    
    GPUResourceConfig config;
    GPUUsageStats stats;
    SystemLoadInfo system_load;
    
    std::atomic<bool> is_initialized{false};
    std::atomic<bool> is_monitoring{false};
    std::atomic<bool> shutdown_requested{false};
    
    std::thread monitoring_thread;
    std::thread statistics_thread;
    mutable std::mutex config_mutex;
    mutable std::mutex stats_mutex;
    mutable std::mutex system_load_mutex;
    std::condition_variable monitoring_cv;
    
    // Game detection
    std::vector<std::string> known_game_processes;
    std::vector<std::string> known_game_windows;
    
    // GPU monitoring
    std::atomic<double> current_gpu_usage{0.0};
    std::atomic<double> current_gpu_memory{0.0};
    std::atomic<bool> gpu_available{false};
    
    // Private constructor for singleton
    GPUResourceLimitingManager();
    ~GPUResourceLimitingManager();
    
    // Disable copy constructor and assignment operator
    GPUResourceLimitingManager(const GPUResourceLimitingManager&) = delete;
    GPUResourceLimitingManager& operator=(const GPUResourceLimitingManager&) = delete;
    
    // Internal methods
    void monitoringLoop();
    void statisticsLoop();
    void updateSystemLoad();
    void updateGPUUsage();
    void detectGameRunning();
    void checkBatteryStatus();
    void enforceGPULimits();
    void logGPUUsage();
    void collectGPUStatistics();
    void checkGPUAlerts();
    
    // GPU detection and monitoring
    bool detectGPUCapabilities();
    double getCurrentGPUUsage();
    bool isGPUAvailable();
    
    // Game detection methods
    bool isGameProcessRunning();
    bool isGameWindowActive();
    void updateKnownGameProcesses();
    
    // System monitoring
    double getCPUUsage();
    double getMemoryUsage();
    bool isLowBattery();
    bool isHighSystemLoad();
    
    // GPU priority and throttling
    void setGPUPriority(int priority);
    void throttleGPUUsage(double target_usage);
    void blockGPUUsage();
    void allowGPUUsage();
    
    // Configuration management
    void loadConfiguration();
    void saveConfiguration();
    void validateConfiguration();
    
public:
    // Singleton access
    static GPUResourceLimitingManager& getInstance();
    
    // Initialization and shutdown
    bool initialize(const std::string& config_path = "");
    void shutdown();
    bool isInitialized() const;
    
    // Configuration management
    void setConfiguration(const GPUResourceConfig& new_config);
    GPUResourceConfig getConfiguration() const;
    void updateConfiguration(const std::string& key, const std::string& value);
    
    // GPU resource management
    bool canUseGPU(double required_memory_mb = 0.0);
    bool requestGPUResources(double memory_mb, double max_usage_percentage = 0.0);
    void releaseGPUResources();
    void setGPUUsageLimit(double percentage);
    void setGPUMemoryLimit(double memory_mb);
    
    // GPU usage monitoring
    GPUUsageStats getGPUUsageStats() const;
    SystemLoadInfo getSystemLoadInfo() const;
    double getCurrentGPUUsagePercentage() const;
    double getCurrentGPUMemoryUsage() const;
    bool isGPUThrottled() const;
    bool isGPUBlocked() const;
    
    // GPU detection and monitoring (public access)
    double getCurrentGPUMemoryUsage();
    
    // Adaptive GPU usage
    void enableAdaptiveUsage(bool enable);
    void setAdaptiveLimits(double min_percentage, double max_percentage);
    double calculateAdaptiveUsageLimit() const;
    
    // Game detection and priority
    void enableGameDetection(bool enable);
    void addGameProcess(const std::string& process_name);
    void addGameWindow(const std::string& window_title);
    bool isGameDetected() const;
    void setGamePriority(bool prioritize_game);
    
    // System load management
    void setHighLoadThreshold(double cpu_threshold, double memory_threshold);
    void setLowBatteryThreshold(double battery_threshold);
    void enableSystemLoadMonitoring(bool enable);
    
    // GPU monitoring and enforcement
    void startMonitoring();
    void stopMonitoring();
    bool isMonitoring() const;
    void setMonitoringInterval(int interval_ms);
    void setEnforcementStrictness(int strictness);
    
    // Logging and statistics
    void enableLogging(bool enable, const std::string& log_file = "");
    void enableStatistics(bool enable, int interval_seconds = 60);
    void enableAlerts(bool enable, double threshold = 80.0);
    
    // API for external applications
    std::string getGPUStatusJSON() const;
    std::string getGPUUsageReport() const;
    std::string getGPUConfigurationJSON() const;
    
    // Utility methods
    void resetStatistics();
    void clearLogs();
    void exportStatistics(const std::string& filename) const;
    void importConfiguration(const std::string& filename);
};

// GPU Resource Limiting API for external applications
class GPUResourceLimitingAPI {
public:
    // GPU resource management
    static bool canUseGPU(double memory_mb = 0.0);
    static bool requestGPUResources(double memory_mb, double max_usage = 0.0);
    static void releaseGPUResources();
    static void setGPUUsageLimit(double percentage);
    static void setGPUMemoryLimit(double memory_mb);
    
    // GPU usage information
    static double getCurrentGPUUsage();
    static double getCurrentGPUMemoryUsage();
    static bool isGPUAvailable();
    static bool isGPUThrottled();
    static bool isGPUBlocked();
    
    // Configuration
    static void setConfiguration(const std::string& key, const std::string& value);
    static std::string getConfiguration(const std::string& key);
    static std::string getConfigurationJSON();
    
    // Statistics and monitoring
    static std::string getGPUStatusJSON();
    static std::string getGPUUsageReport();
    static std::string getSystemLoadInfo();
    
    // Game detection and priority
    static void setGamePriority(bool prioritize_game);
    static bool isGameDetected();
    static void addGameProcess(const std::string& process_name);
    static void addGameWindow(const std::string& window_title);
    
    // Adaptive usage
    static void enableAdaptiveUsage(bool enable);
    static double calculateAdaptiveUsageLimit();
    static void setAdaptiveLimits(double min_percentage, double max_percentage);
    
    // Monitoring and enforcement
    static void startMonitoring();
    static void stopMonitoring();
    static bool isMonitoring();
    static void setEnforcementStrictness(int strictness);
    
    // Logging and alerts
    static void enableLogging(bool enable, const std::string& log_file = "");
    static void enableStatistics(bool enable, int interval_seconds = 60);
    static void enableAlerts(bool enable, double threshold = 80.0);
    
    // Utility methods
    static void resetStatistics();
    static void clearLogs();
    static void exportStatistics(const std::string& filename);
    static void importConfiguration(const std::string& filename);
};

} // namespace FGCom_GPU_ResourceLimiting

#endif // FGCOM_GPU_RESOURCE_LIMITING_H
