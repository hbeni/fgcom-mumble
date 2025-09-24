#ifndef FGCOM_THREADING_EXTENSIONS_H
#define FGCOM_THREADING_EXTENSIONS_H

#include <thread>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <queue>
#include <condition_variable>
#include <vector>
#include <map>
#include <chrono>
#include <memory>
#include <functional>
#include <string>
#include <cstdint>
#include <ctime>

// Forward declarations
#include "threading_types.h"

// Forward declaration for solar conditions
struct fgcom_solar_conditions;

// Thread management configuration
struct ThreadingConfig {
    bool enable_solar_data_thread = true;
    bool enable_propagation_thread = true;
    bool enable_api_server_thread = true;
    bool enable_gpu_compute_thread = true;
    bool enable_lightning_data_thread = true;
    bool enable_weather_data_thread = true;
    bool enable_antenna_pattern_thread = true;
    
    // Thread priorities and intervals
    int solar_data_interval_minutes = 15;
    int propagation_interval_ms = 100;
    int gpu_compute_interval_ms = 10;
    int lightning_data_interval_seconds = 30;
    int weather_data_interval_minutes = 5;
    int antenna_pattern_interval_ms = 50;
    
    // Thread pool configuration
    int max_worker_threads = 8;
    int max_gpu_threads = 4;
    int max_api_threads = 16;
    bool enable_thread_affinity = false;
    std::vector<int> cpu_affinity_cores;
    
    // Performance monitoring
    bool enable_thread_monitoring = true;
    bool enable_performance_counters = true;
    int monitoring_interval_seconds = 60;
};

// Thread statistics and monitoring
struct ThreadStats {
    std::string thread_name;
    std::thread::id thread_id;
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point last_activity;
    std::atomic<uint64_t> total_operations;
    std::atomic<uint64_t> failed_operations;
    std::atomic<double> average_processing_time_ms;
    std::atomic<double> peak_processing_time_ms;
    std::atomic<double> cpu_usage_percent;
    std::atomic<size_t> memory_usage_bytes;
    std::atomic<bool> is_running;
    std::atomic<bool> is_busy;
    std::string last_error;
    std::chrono::system_clock::time_point last_error_time;
};

// Solar data cache with thread safety
struct SolarDataCache {
    std::mutex data_mutex;
    std::shared_mutex read_write_mutex;
    std::atomic<time_t> last_update;
    fgcom_solar_conditions current_data;
    std::vector<fgcom_solar_conditions> historical_data;
    std::atomic<bool> data_valid;
    std::atomic<int> update_failures;
    std::chrono::system_clock::time_point last_successful_update;
    std::string last_error_message;
    
    // Cache management
    size_t max_historical_entries = 1000;
    std::atomic<size_t> cache_hits;
    std::atomic<size_t> cache_misses;
    std::atomic<double> cache_hit_ratio;
};

// Propagation calculation queue with thread safety
struct PropagationQueue {
    std::mutex queue_mutex;
    std::shared_mutex read_write_mutex;
    std::queue<PropagationTask> pending_tasks;
    std::queue<PropagationTask> completed_tasks;
    std::atomic<size_t> queue_size;
    std::atomic<size_t> max_queue_size;
    std::atomic<bool> queue_full;
    std::condition_variable task_available;
    std::condition_variable queue_not_full;
    
    // Performance tracking
    std::atomic<uint64_t> total_tasks_processed;
    std::atomic<uint64_t> failed_tasks;
    std::atomic<double> average_processing_time_ms;
    std::atomic<double> queue_wait_time_ms;
};

// GPU compute queue with thread safety
struct GPUComputeQueue {
    std::mutex queue_mutex;
    std::shared_mutex read_write_mutex;
    std::queue<GPUComputeTask> pending_tasks;
    std::queue<GPUComputeTask> completed_tasks;
    std::atomic<bool> gpu_busy;
    std::atomic<size_t> active_tasks;
    std::atomic<size_t> max_concurrent_tasks;
    std::condition_variable task_available;
    std::condition_variable gpu_available;
    
    // GPU resource management
    std::atomic<size_t> gpu_memory_usage;
    std::atomic<size_t> gpu_memory_limit;
    std::atomic<double> gpu_utilization_percent;
    std::atomic<double> gpu_temperature_celsius;
    std::atomic<bool> gpu_overheating;
    
    // Performance tracking
    std::atomic<uint64_t> total_gpu_operations;
    std::atomic<uint64_t> failed_gpu_operations;
    std::atomic<double> average_gpu_processing_time_ms;
    std::atomic<double> gpu_queue_wait_time_ms;
};

// Lightning data cache with thread safety
struct LightningDataCache {
    std::mutex data_mutex;
    std::shared_mutex read_write_mutex;
    std::vector<LightningStrike> recent_strikes;
    std::vector<LightningStrike> nearby_strikes;
    std::atomic<time_t> last_update;
    std::atomic<bool> data_valid;
    std::atomic<int> update_failures;
    std::chrono::system_clock::time_point last_successful_update;
    
    // Cache management
    size_t max_recent_entries = 10000;
    size_t max_nearby_entries = 1000;
    double nearby_distance_km = 100.0;
    std::atomic<size_t> total_strikes_received;
    std::atomic<size_t> nearby_strikes_count;
};

// Weather data cache with thread safety
struct WeatherDataCache {
    std::mutex data_mutex;
    std::shared_mutex read_write_mutex;
    std::map<std::string, WeatherConditions> location_data;
    std::atomic<time_t> last_update;
    std::atomic<bool> data_valid;
    std::atomic<int> update_failures;
    std::chrono::system_clock::time_point last_successful_update;
    
    // Cache management
    size_t max_locations = 1000;
    std::atomic<size_t> total_locations_cached;
    std::atomic<size_t> cache_hits;
    std::atomic<size_t> cache_misses;
};

// Antenna pattern cache with thread safety
struct AntennaPatternCache {
    std::mutex data_mutex;
    std::shared_mutex read_write_mutex;
    std::map<std::string, AntennaPattern> pattern_cache;
    std::map<std::string, std::chrono::system_clock::time_point> pattern_timestamps;
    std::atomic<size_t> cache_size;
    std::atomic<size_t> max_cache_size;
    std::atomic<bool> cache_full;
    
    // Performance tracking
    std::atomic<uint64_t> cache_hits;
    std::atomic<uint64_t> cache_misses;
    std::atomic<double> cache_hit_ratio;
    std::atomic<double> average_load_time_ms;
};

// Thread manager class
class FGCom_ThreadManager {
private:
    static std::unique_ptr<FGCom_ThreadManager> instance;
    static std::mutex instance_mutex;
    
    ThreadingConfig config;
    std::map<std::string, ThreadStats> thread_stats;
    std::map<std::string, std::thread> managed_threads;
    std::mutex thread_mutex;
    
    // Global shutdown flags
    std::atomic<bool> global_shutdown;
    std::atomic<bool> solar_data_shutdown;
    std::atomic<bool> propagation_shutdown;
    std::atomic<bool> api_server_shutdown;
    std::atomic<bool> gpu_compute_shutdown;
    std::atomic<bool> lightning_data_shutdown;
    std::atomic<bool> weather_data_shutdown;
    std::atomic<bool> antenna_pattern_shutdown;
    
    // Data caches
    std::unique_ptr<SolarDataCache> solar_cache;
    std::unique_ptr<PropagationQueue> propagation_queue;
    std::unique_ptr<GPUComputeQueue> gpu_queue;
    std::unique_ptr<LightningDataCache> lightning_cache;
    std::unique_ptr<WeatherDataCache> weather_cache;
    std::unique_ptr<AntennaPatternCache> antenna_cache;
    
    // Thread monitoring
    std::thread monitoring_thread;
    std::atomic<bool> monitoring_shutdown;
    std::mutex monitoring_mutex;
    
    // Private constructor for singleton
    FGCom_ThreadManager();
    
public:
    // Singleton access
    static FGCom_ThreadManager& getInstance();
    static void destroyInstance();
    
    // Thread management
    bool startAllThreads();
    bool stopAllThreads();
    bool startThread(const std::string& thread_name);
    bool stopThread(const std::string& thread_name);
    bool isThreadRunning(const std::string& thread_name) const;
    
    // Configuration management
    void setConfig(const ThreadingConfig& new_config);
    ThreadingConfig getConfig() const;
    bool loadConfigFromFile(const std::string& config_file);
    bool saveConfigToFile(const std::string& config_file) const;
    
    // Thread statistics and monitoring
    ThreadStats getThreadStats(const std::string& thread_name) const;
    std::map<std::string, ThreadStats> getAllThreadStats() const;
    void resetThreadStats(const std::string& thread_name);
    void resetAllThreadStats();
    void updateThreadStats(const std::string& thread_name, const std::string& operation, double processing_time_ms, bool success);
    
    // Data cache access
    SolarDataCache* getSolarCache() const;
    PropagationQueue* getPropagationQueue() const;
    GPUComputeQueue* getGPUQueue() const;
    LightningDataCache* getLightningCache() const;
    WeatherDataCache* getWeatherCache() const;
    AntennaPatternCache* getAntennaCache() const;
    
    // Thread-safe data access
    bool getSolarData(fgcom_solar_conditions& data) const;
    bool updateSolarData(const fgcom_solar_conditions& data);
    bool addPropagationTask(const PropagationTask& task);
    bool getCompletedPropagationTask(PropagationTask& task);
    bool addGPUComputeTask(const GPUComputeTask& task);
    bool getCompletedGPUComputeTask(GPUComputeTask& task);
    
    // Performance monitoring
    void startMonitoring();
    void stopMonitoring();
    bool isMonitoringActive() const;
    void generatePerformanceReport() const;
    
    // Error handling
    void setThreadError(const std::string& thread_name, const std::string& error);
    std::string getThreadError(const std::string& thread_name) const;
    void clearThreadError(const std::string& thread_name);
    
    // Cleanup and shutdown
    void shutdown();
    void cleanup();
    
private:
    // Internal thread functions
    void solarDataThreadFunction();
    void propagationThreadFunction();
    void apiServerThreadFunction();
    void gpuComputeThreadFunction();
    void lightningDataThreadFunction();
    void weatherDataThreadFunction();
    void antennaPatternThreadFunction();
    void monitoringThreadFunction();
    
    // Internal helper methods
    void initializeCaches();
    void cleanupCaches();
    void updateThreadActivity(const std::string& thread_name);
    void logThreadEvent(const std::string& thread_name, const std::string& event);
    void handleThreadError(const std::string& thread_name, const std::string& error);
    
    // Performance monitoring helpers
    void updatePerformanceCounters();
    void calculateCacheStatistics();
    void generateThreadReport() const;
    void generateCacheReport() const;
};

// Thread-safe utility functions
namespace ThreadingUtils {
    // Thread-safe data access helpers
    template<typename T>
    bool safeRead(const std::shared_mutex& mutex, const T& data, std::function<void(const T&)> reader);
    
    template<typename T>
    bool safeWrite(std::shared_mutex& mutex, T& data, std::function<void(T&)> writer);
    
    // Queue management utilities
    template<typename T>
    bool safeEnqueue(std::mutex& mutex, std::queue<T>& queue, const T& item, std::condition_variable& not_full_cv);
    
    template<typename T>
    bool safeDequeue(std::mutex& mutex, std::queue<T>& queue, T& item, std::condition_variable& not_empty_cv);
    
    // Cache management utilities
    template<typename K, typename V>
    bool safeCacheGet(std::shared_mutex& mutex, const std::map<K, V>& cache, const K& key, V& value);
    
    template<typename K, typename V>
    bool safeCachePut(std::shared_mutex& mutex, std::map<K, V>& cache, const K& key, const V& value, size_t max_size);
    
    // Performance measurement utilities
    class PerformanceTimer {
    private:
        std::chrono::high_resolution_clock::time_point start_time;
        std::string operation_name;
        
    public:
        PerformanceTimer(const std::string& name);
        ~PerformanceTimer();
        double getElapsedTimeMs() const;
        void reset();
    };
    
    // Thread affinity utilities
    bool setThreadAffinity(std::thread& thread, int cpu_core);
    bool setThreadPriority(std::thread& thread, int priority);
    std::vector<int> getAvailableCPUCores();
    int getOptimalCPUCore(const std::string& thread_name);
    
    // Memory management utilities
    size_t getThreadMemoryUsage();
    size_t getProcessMemoryUsage();
    void optimizeMemoryUsage();
    bool isMemoryPressureHigh();
    
    // Error handling utilities
    void setThreadErrorHandler(std::function<void(const std::string&)> handler);
    void logThreadError(const std::string& thread_name, const std::string& error);
    std::string getLastThreadError();
}

// Global thread management functions (to be called from fgcom-mumble.cpp)
extern "C" {
    // Thread spawn functions
    void fgcom_spawnSolarDataManager();
    void fgcom_spawnPropagationEngine();
    void fgcom_spawnAPIServer();
    void fgcom_spawnGPUComputeEngine();
    void fgcom_spawnLightningDataManager();
    void fgcom_spawnWeatherDataManager();
    void fgcom_spawnAntennaPatternManager();
    
    // Thread control functions
    void fgcom_startAllBackgroundThreads();
    void fgcom_stopAllBackgroundThreads();
    bool fgcom_isBackgroundThreadRunning(const char* thread_name);
    
    // Data access functions
    bool fgcom_getSolarData(fgcom_solar_conditions* data);
    bool fgcom_updateSolarData(const fgcom_solar_conditions* data);
    bool fgcom_addPropagationTask(const PropagationTask* task);
    bool fgcom_getCompletedPropagationTask(PropagationTask* task);
    
    // Performance monitoring functions
    void fgcom_startThreadMonitoring();
    void fgcom_stopThreadMonitoring();
    void fgcom_generatePerformanceReport();
    
    // Configuration functions
    bool fgcom_loadThreadingConfig(const char* config_file);
    bool fgcom_saveThreadingConfig(const char* config_file);
}

#endif // FGCOM_THREADING_EXTENSIONS_H
