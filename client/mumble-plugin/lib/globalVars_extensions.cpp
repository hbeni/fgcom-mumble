#include "globalVars_extensions.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <chrono>

// =============================================================================
// GLOBAL VARIABLE DEFINITIONS
// =============================================================================

// Solar data management
std::mutex fgcom_solar_data_mtx;
std::shared_mutex fgcom_solar_data_rw_mtx;
std::atomic<bool> fgcom_solar_data_initialized(false);
std::atomic<time_t> fgcom_solar_data_last_update(0);
std::atomic<bool> fgcom_solar_data_update_in_progress(false);

// Propagation calculation cache
std::mutex fgcom_propagation_cache_mtx;
std::shared_mutex fgcom_propagation_cache_rw_mtx;
std::atomic<size_t> fgcom_propagation_cache_size(0);
std::atomic<bool> fgcom_propagation_cache_enabled(true);
std::atomic<time_t> fgcom_propagation_cache_last_cleanup(0);

// Band plan management
std::shared_mutex fgcom_band_plan_mtx;
std::atomic<bool> fgcom_band_plan_loaded(false);
std::atomic<time_t> fgcom_band_plan_last_update(0);
std::atomic<bool> fgcom_band_plan_update_in_progress(false);

// GPU compute management
std::mutex fgcom_gpu_compute_mtx;
std::shared_mutex fgcom_gpu_compute_rw_mtx;
std::atomic<bool> fgcom_gpu_compute_available(false);
std::atomic<bool> fgcom_gpu_compute_busy(false);
std::atomic<size_t> fgcom_gpu_compute_queue_size(0);
std::atomic<size_t> fgcom_gpu_memory_usage(0);
std::atomic<double> fgcom_gpu_utilization(0.0);

// Antenna pattern management
std::mutex fgcom_antenna_pattern_mtx;
std::shared_mutex fgcom_antenna_pattern_rw_mtx;
std::atomic<size_t> fgcom_antenna_pattern_cache_size(0);
std::atomic<bool> fgcom_antenna_pattern_cache_enabled(true);
std::atomic<time_t> fgcom_antenna_pattern_last_cleanup(0);

// Lightning data management
std::mutex fgcom_lightning_data_mtx;
std::shared_mutex fgcom_lightning_data_rw_mtx;
std::atomic<bool> fgcom_lightning_data_initialized(false);
std::atomic<time_t> fgcom_lightning_data_last_update(0);
std::atomic<size_t> fgcom_lightning_strikes_count(0);

// Weather data management
std::mutex fgcom_weather_data_mtx;
std::shared_mutex fgcom_weather_data_rw_mtx;
std::atomic<bool> fgcom_weather_data_initialized(false);
std::atomic<time_t> fgcom_weather_data_last_update(0);
std::atomic<size_t> fgcom_weather_locations_count(0);

// API server management
std::mutex fgcom_api_server_mtx;
std::shared_mutex fgcom_api_server_rw_mtx;
std::atomic<bool> fgcom_api_server_running(false);
std::atomic<size_t> fgcom_api_server_active_connections(0);
std::atomic<size_t> fgcom_api_server_total_requests(0);

// =============================================================================
// THREAD SHUTDOWN FLAGS
// =============================================================================

// Global shutdown flag
std::atomic<bool> fgcom_global_shutdown(false);

// Individual thread shutdown flags
std::atomic<bool> fgcom_solarDataShutdown(false);
std::atomic<bool> fgcom_propagationShutdown(false);
std::atomic<bool> fgcom_apiServerShutdown(false);
std::atomic<bool> fgcom_gpuComputeShutdown(false);
std::atomic<bool> fgcom_lightningDataShutdown(false);
std::atomic<bool> fgcom_weatherDataShutdown(false);
std::atomic<bool> fgcom_antennaPatternShutdown(false);

// =============================================================================
// GLOBAL CACHE INSTANCES
// =============================================================================

// Global cache instances
SolarDataCache* g_solar_data_cache = nullptr;
GPUComputeQueue* g_gpu_compute_queue = nullptr;
PropagationQueue* g_propagation_queue = nullptr;
LightningDataCache* g_lightning_data_cache = nullptr;
WeatherDataCache* g_weather_data_cache = nullptr;
AntennaPatternCache* g_antenna_pattern_cache = nullptr;

// =============================================================================
// THREAD SAFETY STATISTICS
// =============================================================================

// Thread safety statistics
static ThreadSafetyStats g_thread_safety_stats = {0};
static std::mutex g_thread_safety_stats_mtx;
static std::string g_last_thread_safety_error;
static std::mutex g_thread_safety_error_mtx;
static bool g_thread_safety_debugging_enabled = false;

// =============================================================================
// INITIALIZATION AND CLEANUP FUNCTIONS
// =============================================================================

void fgcom_initializeGlobalVarsExtensions() {
    std::cout << "[GlobalVarsExtensions] Initializing global variables extensions..." << std::endl;
    
    // Initialize individual cache systems
    fgcom_initializeSolarDataCache();
    fgcom_initializeGPUComputeQueue();
    fgcom_initializePropagationQueue();
    fgcom_initializeLightningDataCache();
    fgcom_initializeWeatherDataCache();
    fgcom_initializeAntennaPatternCache();
    
    // Reset thread safety statistics
    fgcom_resetThreadSafetyStats();
    
    // Initialize atomic variables
    fgcom_solar_data_initialized = false;
    fgcom_solar_data_last_update = 0;
    fgcom_solar_data_update_in_progress = false;
    
    fgcom_propagation_cache_size = 0;
    fgcom_propagation_cache_enabled = true;
    fgcom_propagation_cache_last_cleanup = 0;
    
    fgcom_band_plan_loaded = false;
    fgcom_band_plan_last_update = 0;
    fgcom_band_plan_update_in_progress = false;
    
    fgcom_gpu_compute_available = false;
    fgcom_gpu_compute_busy = false;
    fgcom_gpu_compute_queue_size = 0;
    fgcom_gpu_memory_usage = 0;
    fgcom_gpu_utilization = 0.0;
    
    fgcom_antenna_pattern_cache_size = 0;
    fgcom_antenna_pattern_cache_enabled = true;
    fgcom_antenna_pattern_last_cleanup = 0;
    
    fgcom_lightning_data_initialized = false;
    fgcom_lightning_data_last_update = 0;
    fgcom_lightning_strikes_count = 0;
    
    fgcom_weather_data_initialized = false;
    fgcom_weather_data_last_update = 0;
    fgcom_weather_locations_count = 0;
    
    fgcom_api_server_running = false;
    fgcom_api_server_active_connections = 0;
    fgcom_api_server_total_requests = 0;
    
    // Initialize shutdown flags
    fgcom_global_shutdown = false;
    fgcom_solarDataShutdown = false;
    fgcom_propagationShutdown = false;
    fgcom_apiServerShutdown = false;
    fgcom_gpuComputeShutdown = false;
    fgcom_lightningDataShutdown = false;
    fgcom_weatherDataShutdown = false;
    fgcom_antennaPatternShutdown = false;
    
    std::cout << "[GlobalVarsExtensions] Global variables extensions initialized successfully" << std::endl;
}

void fgcom_cleanupGlobalVarsExtensions() {
    std::cout << "[GlobalVarsExtensions] Cleaning up global variables extensions..." << std::endl;
    
    // Set global shutdown flag
    fgcom_global_shutdown = true;
    
    // Cleanup individual cache systems
    fgcom_cleanupSolarDataCache();
    fgcom_cleanupGPUComputeQueue();
    fgcom_cleanupPropagationQueue();
    fgcom_cleanupLightningDataCache();
    fgcom_cleanupWeatherDataCache();
    fgcom_cleanupAntennaPatternCache();
    
    std::cout << "[GlobalVarsExtensions] Global variables extensions cleaned up successfully" << std::endl;
}

void fgcom_initializeSolarDataCache() {
    if (g_solar_data_cache) {
        delete g_solar_data_cache;
    }
    
    g_solar_data_cache = new SolarDataCache();
    g_solar_data_cache->last_update = 0;
    g_solar_data_cache->data_valid = false;
    g_solar_data_cache->update_failures = 0;
    g_solar_data_cache->max_historical_entries = 1000;
    g_solar_data_cache->cache_hits = 0;
    g_solar_data_cache->cache_misses = 0;
    g_solar_data_cache->cache_hit_ratio = 0.0;
    
    fgcom_solar_data_initialized = true;
    std::cout << "[GlobalVarsExtensions] Solar data cache initialized" << std::endl;
}

void fgcom_initializeGPUComputeQueue() {
    if (g_gpu_compute_queue) {
        delete g_gpu_compute_queue;
    }
    
    g_gpu_compute_queue = new GPUComputeQueue();
    g_gpu_compute_queue->gpu_busy = false;
    g_gpu_compute_queue->active_tasks = 0;
    g_gpu_compute_queue->max_concurrent_tasks = 4;
    g_gpu_compute_queue->gpu_memory_usage = 0;
    g_gpu_compute_queue->gpu_memory_limit = 1024 * 1024 * 1024; // 1GB
    g_gpu_compute_queue->gpu_utilization_percent = 0.0;
    g_gpu_compute_queue->gpu_temperature_celsius = 0.0;
    g_gpu_compute_queue->gpu_overheating = false;
    g_gpu_compute_queue->total_gpu_operations = 0;
    g_gpu_compute_queue->failed_gpu_operations = 0;
    g_gpu_compute_queue->average_gpu_processing_time_ms = 0.0;
    g_gpu_compute_queue->gpu_queue_wait_time_ms = 0.0;
    
    fgcom_gpu_compute_available = true;
    std::cout << "[GlobalVarsExtensions] GPU compute queue initialized" << std::endl;
}

void fgcom_initializePropagationQueue() {
    if (g_propagation_queue) {
        delete g_propagation_queue;
    }
    
    g_propagation_queue = new PropagationQueue();
    g_propagation_queue->queue_size = 0;
    g_propagation_queue->max_queue_size = 1000;
    g_propagation_queue->queue_full = false;
    g_propagation_queue->total_tasks_processed = 0;
    g_propagation_queue->failed_tasks = 0;
    g_propagation_queue->average_processing_time_ms = 0.0;
    g_propagation_queue->queue_wait_time_ms = 0.0;
    
    std::cout << "[GlobalVarsExtensions] Propagation queue initialized" << std::endl;
}

void fgcom_initializeLightningDataCache() {
    if (g_lightning_data_cache) {
        delete g_lightning_data_cache;
    }
    
    g_lightning_data_cache = new LightningDataCache();
    g_lightning_data_cache->last_update = 0;
    g_lightning_data_cache->data_valid = false;
    g_lightning_data_cache->update_failures = 0;
    g_lightning_data_cache->max_recent_entries = 10000;
    g_lightning_data_cache->max_nearby_entries = 1000;
    g_lightning_data_cache->nearby_distance_km = 100.0;
    g_lightning_data_cache->total_strikes_received = 0;
    g_lightning_data_cache->nearby_strikes_count = 0;
    
    fgcom_lightning_data_initialized = true;
    std::cout << "[GlobalVarsExtensions] Lightning data cache initialized" << std::endl;
}

void fgcom_initializeWeatherDataCache() {
    if (g_weather_data_cache) {
        delete g_weather_data_cache;
    }
    
    g_weather_data_cache = new WeatherDataCache();
    g_weather_data_cache->last_update = 0;
    g_weather_data_cache->data_valid = false;
    g_weather_data_cache->update_failures = 0;
    g_weather_data_cache->max_locations = 1000;
    g_weather_data_cache->total_locations_cached = 0;
    g_weather_data_cache->cache_hits = 0;
    g_weather_data_cache->cache_misses = 0;
    
    fgcom_weather_data_initialized = true;
    std::cout << "[GlobalVarsExtensions] Weather data cache initialized" << std::endl;
}

void fgcom_initializeAntennaPatternCache() {
    if (g_antenna_pattern_cache) {
        delete g_antenna_pattern_cache;
    }
    
    g_antenna_pattern_cache = new AntennaPatternCache();
    g_antenna_pattern_cache->cache_size = 0;
    g_antenna_pattern_cache->max_cache_size = 500;
    g_antenna_pattern_cache->cache_full = false;
    g_antenna_pattern_cache->cache_hits = 0;
    g_antenna_pattern_cache->cache_misses = 0;
    g_antenna_pattern_cache->cache_hit_ratio = 0.0;
    g_antenna_pattern_cache->average_load_time_ms = 0.0;
    
    std::cout << "[GlobalVarsExtensions] Antenna pattern cache initialized" << std::endl;
}

void fgcom_cleanupSolarDataCache() {
    if (g_solar_data_cache) {
        delete g_solar_data_cache;
        g_solar_data_cache = nullptr;
    }
    fgcom_solar_data_initialized = false;
    std::cout << "[GlobalVarsExtensions] Solar data cache cleaned up" << std::endl;
}

void fgcom_cleanupGPUComputeQueue() {
    if (g_gpu_compute_queue) {
        delete g_gpu_compute_queue;
        g_gpu_compute_queue = nullptr;
    }
    fgcom_gpu_compute_available = false;
    std::cout << "[GlobalVarsExtensions] GPU compute queue cleaned up" << std::endl;
}

void fgcom_cleanupPropagationQueue() {
    if (g_propagation_queue) {
        delete g_propagation_queue;
        g_propagation_queue = nullptr;
    }
    std::cout << "[GlobalVarsExtensions] Propagation queue cleaned up" << std::endl;
}

void fgcom_cleanupLightningDataCache() {
    if (g_lightning_data_cache) {
        delete g_lightning_data_cache;
        g_lightning_data_cache = nullptr;
    }
    fgcom_lightning_data_initialized = false;
    std::cout << "[GlobalVarsExtensions] Lightning data cache cleaned up" << std::endl;
}

void fgcom_cleanupWeatherDataCache() {
    if (g_weather_data_cache) {
        delete g_weather_data_cache;
        g_weather_data_cache = nullptr;
    }
    fgcom_weather_data_initialized = false;
    std::cout << "[GlobalVarsExtensions] Weather data cache cleaned up" << std::endl;
}

void fgcom_cleanupAntennaPatternCache() {
    if (g_antenna_pattern_cache) {
        delete g_antenna_pattern_cache;
        g_antenna_pattern_cache = nullptr;
    }
    std::cout << "[GlobalVarsExtensions] Antenna pattern cache cleaned up" << std::endl;
}

// =============================================================================
// THREAD SAFETY VALIDATION FUNCTIONS
// =============================================================================

bool fgcom_validateThreadSafety() {
    std::cout << "[GlobalVarsExtensions] Validating thread safety configuration..." << std::endl;
    
    bool is_valid = true;
    
    // Check if all caches are properly initialized
    if (!g_solar_data_cache) {
        std::cerr << "[GlobalVarsExtensions] ERROR: Solar data cache not initialized" << std::endl;
        is_valid = false;
    }
    
    if (!g_gpu_compute_queue) {
        std::cerr << "[GlobalVarsExtensions] ERROR: GPU compute queue not initialized" << std::endl;
        is_valid = false;
    }
    
    if (!g_propagation_queue) {
        std::cerr << "[GlobalVarsExtensions] ERROR: Propagation queue not initialized" << std::endl;
        is_valid = false;
    }
    
    if (!g_lightning_data_cache) {
        std::cerr << "[GlobalVarsExtensions] ERROR: Lightning data cache not initialized" << std::endl;
        is_valid = false;
    }
    
    if (!g_weather_data_cache) {
        std::cerr << "[GlobalVarsExtensions] ERROR: Weather data cache not initialized" << std::endl;
        is_valid = false;
    }
    
    if (!g_antenna_pattern_cache) {
        std::cerr << "[GlobalVarsExtensions] ERROR: Antenna pattern cache not initialized" << std::endl;
        is_valid = false;
    }
    
    // Check atomic variables
    if (!fgcom_solar_data_initialized.load()) {
        std::cerr << "[GlobalVarsExtensions] WARNING: Solar data not initialized" << std::endl;
    }
    
    if (!fgcom_lightning_data_initialized.load()) {
        std::cerr << "[GlobalVarsExtensions] WARNING: Lightning data not initialized" << std::endl;
    }
    
    if (!fgcom_weather_data_initialized.load()) {
        std::cerr << "[GlobalVarsExtensions] WARNING: Weather data not initialized" << std::endl;
    }
    
    if (is_valid) {
        std::cout << "[GlobalVarsExtensions] Thread safety validation passed" << std::endl;
    } else {
        std::cerr << "[GlobalVarsExtensions] Thread safety validation failed" << std::endl;
    }
    
    return is_valid;
}

bool fgcom_checkForDeadlocks() {
    // Placeholder for deadlock detection
    // In a real implementation, this would use platform-specific deadlock detection
    return false;
}

bool fgcom_validateMutexOrdering() {
    // Placeholder for mutex ordering validation
    // In a real implementation, this would check for potential lock ordering violations
    return true;
}

// =============================================================================
// PERFORMANCE MONITORING FUNCTIONS
// =============================================================================

ThreadSafetyStats fgcom_getThreadSafetyStats() {
    std::lock_guard<std::mutex> lock(g_thread_safety_stats_mtx);
    return g_thread_safety_stats;
}

void fgcom_resetThreadSafetyStats() {
    std::lock_guard<std::mutex> lock(g_thread_safety_stats_mtx);
    g_thread_safety_stats = ThreadSafetyStats{0};
}

// =============================================================================
// ERROR HANDLING FUNCTIONS
// =============================================================================

void fgcom_setThreadSafetyError(const std::string& error) {
    std::lock_guard<std::mutex> lock(g_thread_safety_error_mtx);
    g_last_thread_safety_error = error;
    std::cerr << "[GlobalVarsExtensions] Thread safety error: " << error << std::endl;
}

std::string fgcom_getLastThreadSafetyError() {
    std::lock_guard<std::mutex> lock(g_thread_safety_error_mtx);
    return g_last_thread_safety_error;
}

void fgcom_clearThreadSafetyError() {
    std::lock_guard<std::mutex> lock(g_thread_safety_error_mtx);
    g_last_thread_safety_error.clear();
}

// =============================================================================
// DEBUGGING AND DIAGNOSTICS
// =============================================================================

void fgcom_enableThreadSafetyDebugging(bool enable) {
    g_thread_safety_debugging_enabled = enable;
    std::cout << "[GlobalVarsExtensions] Thread safety debugging " << (enable ? "enabled" : "disabled") << std::endl;
}

std::map<std::string, bool> fgcom_getMutexStatus() {
    std::map<std::string, bool> status;
    
    // Check if mutexes are locked (placeholder implementation)
    status["fgcom_solar_data_mtx"] = false;
    status["fgcom_propagation_cache_mtx"] = false;
    status["fgcom_gpu_compute_mtx"] = false;
    status["fgcom_antenna_pattern_mtx"] = false;
    status["fgcom_lightning_data_mtx"] = false;
    status["fgcom_weather_data_mtx"] = false;
    status["fgcom_api_server_mtx"] = false;
    
    return status;
}

std::map<std::string, std::string> fgcom_getAtomicValues() {
    std::map<std::string, std::string> values;
    
    values["fgcom_solar_data_initialized"] = fgcom_solar_data_initialized.load() ? "true" : "false";
    values["fgcom_solar_data_last_update"] = std::to_string(fgcom_solar_data_last_update.load());
    values["fgcom_solar_data_update_in_progress"] = fgcom_solar_data_update_in_progress.load() ? "true" : "false";
    
    values["fgcom_propagation_cache_size"] = std::to_string(fgcom_propagation_cache_size.load());
    values["fgcom_propagation_cache_enabled"] = fgcom_propagation_cache_enabled.load() ? "true" : "false";
    
    values["fgcom_band_plan_loaded"] = fgcom_band_plan_loaded.load() ? "true" : "false";
    values["fgcom_band_plan_last_update"] = std::to_string(fgcom_band_plan_last_update.load());
    
    values["fgcom_gpu_compute_available"] = fgcom_gpu_compute_available.load() ? "true" : "false";
    values["fgcom_gpu_compute_busy"] = fgcom_gpu_compute_busy.load() ? "true" : "false";
    values["fgcom_gpu_compute_queue_size"] = std::to_string(fgcom_gpu_compute_queue_size.load());
    values["fgcom_gpu_memory_usage"] = std::to_string(fgcom_gpu_memory_usage.load());
    values["fgcom_gpu_utilization"] = std::to_string(fgcom_gpu_utilization.load());
    
    values["fgcom_antenna_pattern_cache_size"] = std::to_string(fgcom_antenna_pattern_cache_size.load());
    values["fgcom_antenna_pattern_cache_enabled"] = fgcom_antenna_pattern_cache_enabled.load() ? "true" : "false";
    
    values["fgcom_lightning_data_initialized"] = fgcom_lightning_data_initialized.load() ? "true" : "false";
    values["fgcom_lightning_data_last_update"] = std::to_string(fgcom_lightning_data_last_update.load());
    values["fgcom_lightning_strikes_count"] = std::to_string(fgcom_lightning_strikes_count.load());
    
    values["fgcom_weather_data_initialized"] = fgcom_weather_data_initialized.load() ? "true" : "false";
    values["fgcom_weather_data_last_update"] = std::to_string(fgcom_weather_data_last_update.load());
    values["fgcom_weather_locations_count"] = std::to_string(fgcom_weather_locations_count.load());
    
    values["fgcom_api_server_running"] = fgcom_api_server_running.load() ? "true" : "false";
    values["fgcom_api_server_active_connections"] = std::to_string(fgcom_api_server_active_connections.load());
    values["fgcom_api_server_total_requests"] = std::to_string(fgcom_api_server_total_requests.load());
    
    values["fgcom_global_shutdown"] = fgcom_global_shutdown.load() ? "true" : "false";
    values["fgcom_solarDataShutdown"] = fgcom_solarDataShutdown.load() ? "true" : "false";
    values["fgcom_propagationShutdown"] = fgcom_propagationShutdown.load() ? "true" : "false";
    values["fgcom_apiServerShutdown"] = fgcom_apiServerShutdown.load() ? "true" : "false";
    values["fgcom_gpuComputeShutdown"] = fgcom_gpuComputeShutdown.load() ? "true" : "false";
    values["fgcom_lightningDataShutdown"] = fgcom_lightningDataShutdown.load() ? "true" : "false";
    values["fgcom_weatherDataShutdown"] = fgcom_weatherDataShutdown.load() ? "true" : "false";
    values["fgcom_antennaPatternShutdown"] = fgcom_antennaPatternShutdown.load() ? "true" : "false";
    
    return values;
}

void fgcom_generateThreadSafetyReport() {
    std::cout << "\n=== FGCom-mumble Thread Safety Report ===" << std::endl;
    
    // Get thread safety statistics
    ThreadSafetyStats stats = fgcom_getThreadSafetyStats();
    
    std::cout << "\nThread Safety Statistics:" << std::endl;
    std::cout << "  Total Mutex Locks: " << stats.total_mutex_locks << std::endl;
    std::cout << "  Total Shared Mutex Locks: " << stats.total_shared_mutex_locks << std::endl;
    std::cout << "  Total Mutex Wait Time: " << stats.total_mutex_wait_time_ms << " ms" << std::endl;
    std::cout << "  Total Shared Mutex Wait Time: " << stats.total_shared_mutex_wait_time_ms << " ms" << std::endl;
    std::cout << "  Deadlock Detections: " << stats.deadlock_detections << std::endl;
    std::cout << "  Mutex Timeouts: " << stats.mutex_timeouts << std::endl;
    std::cout << "  Average Lock Wait Time: " << stats.average_lock_wait_time_ms << " ms" << std::endl;
    std::cout << "  Peak Lock Wait Time: " << stats.peak_lock_wait_time_ms << " ms" << std::endl;
    
    // Get atomic variable values
    std::map<std::string, std::string> atomic_values = fgcom_getAtomicValues();
    
    std::cout << "\nAtomic Variable Values:" << std::endl;
    for (const auto& pair : atomic_values) {
        std::cout << "  " << pair.first << ": " << pair.second << std::endl;
    }
    
    // Get mutex status
    std::map<std::string, bool> mutex_status = fgcom_getMutexStatus();
    
    std::cout << "\nMutex Status:" << std::endl;
    for (const auto& pair : mutex_status) {
        std::cout << "  " << pair.first << ": " << (pair.second ? "LOCKED" : "UNLOCKED") << std::endl;
    }
    
    // Cache status
    std::cout << "\nCache Status:" << std::endl;
    std::cout << "  Solar Data Cache: " << (g_solar_data_cache ? "INITIALIZED" : "NOT INITIALIZED") << std::endl;
    std::cout << "  GPU Compute Queue: " << (g_gpu_compute_queue ? "INITIALIZED" : "NOT INITIALIZED") << std::endl;
    std::cout << "  Propagation Queue: " << (g_propagation_queue ? "INITIALIZED" : "NOT INITIALIZED") << std::endl;
    std::cout << "  Lightning Data Cache: " << (g_lightning_data_cache ? "INITIALIZED" : "NOT INITIALIZED") << std::endl;
    std::cout << "  Weather Data Cache: " << (g_weather_data_cache ? "INITIALIZED" : "NOT INITIALIZED") << std::endl;
    std::cout << "  Antenna Pattern Cache: " << (g_antenna_pattern_cache ? "INITIALIZED" : "NOT INITIALIZED") << std::endl;
    
    // Last error
    std::string last_error = fgcom_getLastThreadSafetyError();
    if (!last_error.empty()) {
        std::cout << "\nLast Thread Safety Error: " << last_error << std::endl;
    }
    
    std::cout << "\n=== End Thread Safety Report ===" << std::endl;
}
