#ifndef FGCOM_GLOBAL_VARS_EXTENSIONS_H
#define FGCOM_GLOBAL_VARS_EXTENSIONS_H

#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <thread>
#include <chrono>
#include <string>
#include <vector>
#include <map>
#include <queue>
#include <condition_variable>

// =============================================================================
// EXISTING GLOBAL VARIABLES (from globalVars.h)
// =============================================================================
// These are the existing global variables that are already defined in globalVars.h
// We're extending the thread safety mechanisms for these

// Existing mutexes (already defined in globalVars.h)
extern std::mutex fgcom_localcfg_mtx;        // UDP server mutex
extern std::mutex fgcom_garbage_collector_mtx; // Garbage collector mutex
extern std::mutex fgcom_notification_mtx;    // Notification mutex
extern std::mutex fgcom_udp_client_mtx;      // UDP client mutex
extern std::mutex fgcom_debug_mtx;           // Debug output mutex

// =============================================================================
// NEW THREAD SAFETY EXTENSIONS
// =============================================================================

// Solar data management
extern std::mutex fgcom_solar_data_mtx;
extern std::shared_mutex fgcom_solar_data_rw_mtx;
extern std::atomic<bool> fgcom_solar_data_initialized;
extern std::atomic<time_t> fgcom_solar_data_last_update;
extern std::atomic<bool> fgcom_solar_data_update_in_progress;

// Propagation calculation cache
extern std::mutex fgcom_propagation_cache_mtx;
extern std::shared_mutex fgcom_propagation_cache_rw_mtx;
extern std::atomic<size_t> fgcom_propagation_cache_size;
extern std::atomic<bool> fgcom_propagation_cache_enabled;
extern std::atomic<time_t> fgcom_propagation_cache_last_cleanup;

// Band plan management
extern std::shared_mutex fgcom_band_plan_mtx;
extern std::atomic<bool> fgcom_band_plan_loaded;
extern std::atomic<time_t> fgcom_band_plan_last_update;
extern std::atomic<bool> fgcom_band_plan_update_in_progress;

// GPU compute management
extern std::mutex fgcom_gpu_compute_mtx;
extern std::shared_mutex fgcom_gpu_compute_rw_mtx;
extern std::atomic<bool> fgcom_gpu_compute_available;
extern std::atomic<bool> fgcom_gpu_compute_busy;
extern std::atomic<size_t> fgcom_gpu_compute_queue_size;
extern std::atomic<size_t> fgcom_gpu_memory_usage;
extern std::atomic<double> fgcom_gpu_utilization;

// Antenna pattern management
extern std::mutex fgcom_antenna_pattern_mtx;
extern std::shared_mutex fgcom_antenna_pattern_rw_mtx;
extern std::atomic<size_t> fgcom_antenna_pattern_cache_size;
extern std::atomic<bool> fgcom_antenna_pattern_cache_enabled;
extern std::atomic<time_t> fgcom_antenna_pattern_last_cleanup;

// Lightning data management
extern std::mutex fgcom_lightning_data_mtx;
extern std::shared_mutex fgcom_lightning_data_rw_mtx;
extern std::atomic<bool> fgcom_lightning_data_initialized;
extern std::atomic<time_t> fgcom_lightning_data_last_update;
extern std::atomic<size_t> fgcom_lightning_strikes_count;

// Weather data management
extern std::mutex fgcom_weather_data_mtx;
extern std::shared_mutex fgcom_weather_data_rw_mtx;
extern std::atomic<bool> fgcom_weather_data_initialized;
extern std::atomic<time_t> fgcom_weather_data_last_update;
extern std::atomic<size_t> fgcom_weather_locations_count;

// API server management
extern std::mutex fgcom_api_server_mtx;
extern std::shared_mutex fgcom_api_server_rw_mtx;
extern std::atomic<bool> fgcom_api_server_running;
extern std::atomic<size_t> fgcom_api_server_active_connections;
extern std::atomic<size_t> fgcom_api_server_total_requests;

// =============================================================================
// THREAD SHUTDOWN FLAGS
// =============================================================================

// Global shutdown flag
extern std::atomic<bool> fgcom_global_shutdown;

// Individual thread shutdown flags
extern std::atomic<bool> fgcom_solarDataShutdown;
extern std::atomic<bool> fgcom_propagationShutdown;
extern std::atomic<bool> fgcom_apiServerShutdown;
extern std::atomic<bool> fgcom_gpuComputeShutdown;
extern std::atomic<bool> fgcom_lightningDataShutdown;
extern std::atomic<bool> fgcom_weatherDataShutdown;
extern std::atomic<bool> fgcom_antennaPatternShutdown;

// =============================================================================
// THREAD SAFETY UTILITY STRUCTURES
// =============================================================================

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

// =============================================================================
// GLOBAL CACHE INSTANCES
// =============================================================================

// Global cache instances (extern declarations)
extern SolarDataCache* g_solar_data_cache;
extern GPUComputeQueue* g_gpu_compute_queue;
extern PropagationQueue* g_propagation_queue;
extern LightningDataCache* g_lightning_data_cache;
extern WeatherDataCache* g_weather_data_cache;
extern AntennaPatternCache* g_antenna_pattern_cache;

// =============================================================================
// THREAD SAFETY UTILITY FUNCTIONS
// =============================================================================

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

// =============================================================================
// INITIALIZATION AND CLEANUP FUNCTIONS
// =============================================================================

// Initialize all global variables and caches
void fgcom_initializeGlobalVarsExtensions();

// Cleanup all global variables and caches
void fgcom_cleanupGlobalVarsExtensions();

// Initialize individual cache systems
void fgcom_initializeSolarDataCache();
void fgcom_initializeGPUComputeQueue();
void fgcom_initializePropagationQueue();
void fgcom_initializeLightningDataCache();
void fgcom_initializeWeatherDataCache();
void fgcom_initializeAntennaPatternCache();

// Cleanup individual cache systems
void fgcom_cleanupSolarDataCache();
void fgcom_cleanupGPUComputeQueue();
void fgcom_cleanupPropagationQueue();
void fgcom_cleanupLightningDataCache();
void fgcom_cleanupWeatherDataCache();
void fgcom_cleanupAntennaPatternCache();

// =============================================================================
// THREAD SAFETY VALIDATION FUNCTIONS
// =============================================================================

// Validate thread safety configuration
bool fgcom_validateThreadSafety();

// Check for potential deadlocks
bool fgcom_checkForDeadlocks();

// Validate mutex ordering
bool fgcom_validateMutexOrdering();

// =============================================================================
// PERFORMANCE MONITORING FUNCTIONS
// =============================================================================

// Get thread safety statistics
struct ThreadSafetyStats {
    size_t total_mutex_locks;
    size_t total_shared_mutex_locks;
    size_t total_mutex_wait_time_ms;
    size_t total_shared_mutex_wait_time_ms;
    size_t deadlock_detections;
    size_t mutex_timeouts;
    double average_lock_wait_time_ms;
    double peak_lock_wait_time_ms;
};

ThreadSafetyStats fgcom_getThreadSafetyStats();

// Reset thread safety statistics
void fgcom_resetThreadSafetyStats();

// =============================================================================
// ERROR HANDLING FUNCTIONS
// =============================================================================

// Set thread safety error
void fgcom_setThreadSafetyError(const std::string& error);

// Get last thread safety error
std::string fgcom_getLastThreadSafetyError();

// Clear thread safety error
void fgcom_clearThreadSafetyError();

// =============================================================================
// DEBUGGING AND DIAGNOSTICS
// =============================================================================

// Enable/disable thread safety debugging
void fgcom_enableThreadSafetyDebugging(bool enable);

// Get current mutex status
std::map<std::string, bool> fgcom_getMutexStatus();

// Get current atomic variable values
std::map<std::string, std::string> fgcom_getAtomicValues();

// Generate thread safety report
void fgcom_generateThreadSafetyReport();

#endif // FGCOM_GLOBAL_VARS_EXTENSIONS_H
