# FGCom-mumble Threading Architecture Extensions

## Overview

The FGCom-mumble threading architecture extensions provide a comprehensive multi-threading system that enhances the existing plugin with new background threads, thread safety mechanisms, and performance monitoring capabilities. This system is designed to handle complex radio propagation calculations, GPU acceleration, and real-time data processing while maintaining thread safety and optimal performance.

## Architecture Components

### 1. Thread Management System

The threading system is built around the `FGCom_ThreadManager` singleton class that manages all background threads and provides centralized control over the threading infrastructure.

#### Key Features:
- **Centralized Thread Management**: Single point of control for all background threads
- **Thread Safety**: Comprehensive mutex and atomic variable management
- **Performance Monitoring**: Real-time statistics and performance tracking
- **Error Handling**: Robust error detection and recovery mechanisms
- **Configuration Management**: Flexible configuration system for thread behavior

### 2. Background Threads

The system includes seven specialized background threads:

#### Solar Data Thread
- **Purpose**: Updates solar conditions data every 15 minutes
- **Function**: `fgcom_spawnSolarDataManager()`
- **Data Source**: NOAA/SWPC APIs
- **Thread Safety**: Uses `fgcom_solar_data_mtx` and `fgcom_solar_data_rw_mtx`

#### Propagation Engine Thread
- **Purpose**: Processes propagation calculation queue
- **Function**: `fgcom_spawnPropagationEngine()`
- **Processing Interval**: 100ms
- **Thread Safety**: Uses `fgcom_propagation_cache_mtx` and `fgcom_propagation_cache_rw_mtx`

#### API Server Thread
- **Purpose**: Handles HTTP API requests and WebSocket connections
- **Function**: `fgcom_spawnAPIServer()`
- **Port**: 8080 (configurable)
- **Thread Safety**: Uses `fgcom_api_server_mtx` and `fgcom_api_server_rw_mtx`

#### GPU Compute Engine Thread
- **Purpose**: Processes GPU-accelerated calculations
- **Function**: `fgcom_spawnGPUComputeEngine()`
- **Processing Interval**: 10ms
- **Thread Safety**: Uses `fgcom_gpu_compute_mtx` and `fgcom_gpu_compute_rw_mtx`

#### Lightning Data Thread
- **Purpose**: Updates lightning strike data every 30 seconds
- **Function**: `fgcom_spawnLightningDataManager()`
- **Data Source**: Lightning detection APIs
- **Thread Safety**: Uses `fgcom_lightning_data_mtx` and `fgcom_lightning_data_rw_mtx`

#### Weather Data Thread
- **Purpose**: Updates weather conditions every 5 minutes
- **Function**: `fgcom_spawnWeatherDataManager()`
- **Data Source**: Weather APIs (OpenWeatherMap, WeatherAPI, Open-Meteo)
- **Thread Safety**: Uses `fgcom_weather_data_mtx` and `fgcom_weather_data_rw_mtx`

#### Antenna Pattern Thread
- **Purpose**: Manages antenna pattern cache and calculations
- **Function**: `fgcom_spawnAntennaPatternManager()`
- **Processing Interval**: 50ms
- **Thread Safety**: Uses `fgcom_antenna_pattern_mtx` and `fgcom_antenna_pattern_rw_mtx`

### 3. Thread Safety Mechanisms

#### Mutex Types
- **Standard Mutex**: `std::mutex` for exclusive access
- **Shared Mutex**: `std::shared_mutex` for read-write access control
- **Atomic Variables**: `std::atomic` for lock-free operations

#### Global Mutexes
```cpp
extern std::mutex fgcom_solar_data_mtx;
extern std::shared_mutex fgcom_solar_data_rw_mtx;
extern std::mutex fgcom_propagation_cache_mtx;
extern std::shared_mutex fgcom_propagation_cache_rw_mtx;
extern std::shared_mutex fgcom_band_plan_mtx;
extern std::mutex fgcom_gpu_compute_mtx;
extern std::shared_mutex fgcom_gpu_compute_rw_mtx;
extern std::mutex fgcom_antenna_pattern_mtx;
extern std::shared_mutex fgcom_antenna_pattern_rw_mtx;
```

#### Atomic Variables
```cpp
extern std::atomic<bool> fgcom_solar_data_initialized;
extern std::atomic<time_t> fgcom_solar_data_last_update;
extern std::atomic<bool> fgcom_solar_data_update_in_progress;
extern std::atomic<size_t> fgcom_propagation_cache_size;
extern std::atomic<bool> fgcom_propagation_cache_enabled;
extern std::atomic<bool> fgcom_gpu_compute_available;
extern std::atomic<bool> fgcom_gpu_compute_busy;
extern std::atomic<size_t> fgcom_gpu_compute_queue_size;
```

### 4. Data Caches with Thread Safety

#### Solar Data Cache
```cpp
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
```

#### GPU Compute Queue
```cpp
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
```

### 5. Performance Monitoring

#### Thread Statistics
```cpp
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
```

#### Performance Metrics
- **Operation Counts**: Total and failed operations per thread
- **Processing Times**: Average and peak processing times
- **Resource Usage**: CPU and memory utilization
- **Cache Performance**: Hit ratios and access patterns
- **Queue Statistics**: Queue sizes and wait times
- **GPU Metrics**: Utilization, temperature, and memory usage

## Configuration

### Threading Configuration File

The system uses a comprehensive configuration file (`threading_config.conf`) with the following sections:

#### [threading]
```ini
enable_solar_data_thread = true
enable_propagation_thread = true
enable_api_server_thread = true
enable_gpu_compute_thread = true
enable_lightning_data_thread = true
enable_weather_data_thread = true
enable_antenna_pattern_thread = true

solar_data_interval_minutes = 15
propagation_interval_ms = 100
gpu_compute_interval_ms = 10
lightning_data_interval_seconds = 30
weather_data_interval_minutes = 5
antenna_pattern_interval_ms = 50

max_worker_threads = 8
max_gpu_threads = 4
max_api_threads = 16

enable_thread_monitoring = true
enable_performance_counters = true
monitoring_interval_seconds = 60
```

#### [solar_data_cache]
```ini
max_historical_entries = 1000
cache_timeout_seconds = 900
enable_cache_compression = false
retry_failed_updates = true
max_update_retries = 3
update_retry_delay_seconds = 60
```

#### [gpu_compute_queue]
```ini
max_concurrent_tasks = 4
gpu_memory_limit_mb = 1024
gpu_utilization_threshold = 80.0
gpu_temperature_threshold = 85.0
max_task_processing_time_ms = 5000
enable_gpu_task_retry = true
max_gpu_task_retries = 1
gpu_task_retry_delay_ms = 200
```

## Integration Guide

### 1. Adding Includes

Add these includes to your `fgcom-mumble.cpp`:

```cpp
#include "threading_extensions.h"
#include "globalVars_extensions.h"
#include "solar_data.h"
#include "gpu_accelerator.h"
#include "api_server.h"
```

### 2. Thread Declarations

Add thread declarations to your global variables section:

```cpp
// New background threads
std::thread fgcom_solarDataThread;
std::thread fgcom_propagationThread;
std::thread fgcom_apiServerThread;
std::thread fgcom_gpuComputeThread;
std::thread fgcom_lightningDataThread;
std::thread fgcom_weatherDataThread;
std::thread fgcom_antennaPatternThread;
```

### 3. Initialization

In `fgcom_initPlugin()`, add:

```cpp
void fgcom_initPlugin() {
    // Existing initialization code...
    
    // Initialize threading extensions
    fgcom_initializeGlobalVarsExtensions();
    
    // Initialize threading manager
    auto& thread_manager = FGCom_ThreadManager::getInstance();
    thread_manager.loadConfigFromFile("threading_config.conf");
    
    // Initialize GPU accelerator
    auto& gpu_accelerator = FGCom_GPUAccelerator::getInstance();
    gpu_accelerator.initializeGPU();
    
    // Start all background threads
    fgcom_solarDataThread = std::thread(fgcom_spawnSolarDataManager);
    fgcom_propagationThread = std::thread(fgcom_spawnPropagationEngine);
    fgcom_apiServerThread = std::thread(fgcom_spawnAPIServer);
    fgcom_gpuComputeThread = std::thread(fgcom_spawnGPUComputeEngine);
    fgcom_lightningDataThread = std::thread(fgcom_spawnLightningDataManager);
    fgcom_weatherDataThread = std::thread(fgcom_spawnWeatherDataManager);
    fgcom_antennaPatternThread = std::thread(fgcom_spawnAntennaPatternManager);
    
    // Start thread monitoring
    thread_manager.startMonitoring();
}
```

### 4. Shutdown

In `fgcom_shutdownPlugin()`, add:

```cpp
void fgcom_shutdownPlugin() {
    // Set shutdown flags
    fgcom_global_shutdown = true;
    fgcom_solarDataShutdown = true;
    fgcom_propagationShutdown = true;
    fgcom_apiServerShutdown = true;
    fgcom_gpuComputeShutdown = true;
    fgcom_lightningDataShutdown = true;
    fgcom_weatherDataShutdown = true;
    fgcom_antennaPatternShutdown = true;
    
    // Wait for all threads to finish
    if (fgcom_solarDataThread.joinable()) {
        fgcom_solarDataThread.join();
    }
    if (fgcom_propagationThread.joinable()) {
        fgcom_propagationThread.join();
    }
    if (fgcom_apiServerThread.joinable()) {
        fgcom_apiServerThread.join();
    }
    if (fgcom_gpuComputeThread.joinable()) {
        fgcom_gpuComputeThread.join();
    }
    if (fgcom_lightningDataThread.joinable()) {
        fgcom_lightningDataThread.join();
    }
    if (fgcom_weatherDataThread.joinable()) {
        fgcom_weatherDataThread.join();
    }
    if (fgcom_antennaPatternThread.joinable()) {
        fgcom_antennaPatternThread.join();
    }
    
    // Stop thread monitoring
    auto& thread_manager = FGCom_ThreadManager::getInstance();
    thread_manager.stopMonitoring();
    
    // Generate final performance report
    thread_manager.generatePerformanceReport();
    
    // Cleanup
    fgcom_cleanupGlobalVarsExtensions();
    FGCom_ThreadManager::destroyInstance();
    FGCom_GPUAccelerator::destroyInstance();
    
    // Existing shutdown code...
}
```

### 5. Thread Spawn Functions

Add the thread spawn functions to your `fgcom-mumble.cpp`:

```cpp
// Solar data manager (15-minute updates)
void fgcom_spawnSolarDataManager() {
    while (!fgcom_solarDataShutdown.load()) {
        try {
            // Update solar conditions
            auto& solar_provider = FGCom_SolarDataProvider::getInstance();
            fgcom_solar_conditions current_conditions = solar_provider.getCurrentConditions();
            
            // Update global cache
            if (g_solar_data_cache) {
                std::unique_lock<std::shared_mutex> lock(g_solar_data_cache->read_write_mutex);
                g_solar_data_cache->current_data = current_conditions;
                g_solar_data_cache->last_update = std::time(nullptr);
                g_solar_data_cache->data_valid = true;
            }
            
        } catch (const std::exception& e) {
            std::cerr << "Error in solar data manager: " << e.what() << std::endl;
        }
        
        std::this_thread::sleep_for(std::chrono::minutes(15));
    }
}

// Add other thread spawn functions...
```

## API Usage

### Thread Management

```cpp
// Get thread manager instance
auto& thread_manager = FGCom_ThreadManager::getInstance();

// Start all threads
thread_manager.startAllThreads();

// Stop all threads
thread_manager.stopAllThreads();

// Check if thread is running
bool is_running = thread_manager.isThreadRunning("solar_data");

// Get thread statistics
ThreadStats stats = thread_manager.getThreadStats("solar_data");
```

### Data Access

```cpp
// Get solar data
fgcom_solar_conditions solar_data;
if (thread_manager.getSolarData(solar_data)) {
    // Use solar data
}

// Add propagation task
PropagationTask task;
// ... populate task ...
thread_manager.addPropagationTask(task);

// Get completed task
PropagationTask completed_task;
if (thread_manager.getCompletedPropagationTask(completed_task)) {
    // Process completed task
}
```

### Performance Monitoring

```cpp
// Generate performance report
thread_manager.generatePerformanceReport();

// Get all thread statistics
std::map<std::string, ThreadStats> all_stats = thread_manager.getAllThreadStats();

// Reset statistics
thread_manager.resetAllThreadStats();
```

## Error Handling

### Thread Safety Errors

```cpp
// Set thread safety error
fgcom_setThreadSafetyError("Mutex timeout detected");

// Get last error
std::string error = fgcom_getLastThreadSafetyError();

// Clear error
fgcom_clearThreadSafetyError();
```

### Thread Recovery

```cpp
// Restart a specific thread
bool success = fgcom_restartBackgroundThread("solar_data");

// Check thread status
std::map<std::string, bool> status = fgcom_getBackgroundThreadStatus();
```

## Performance Optimization

### Thread Affinity

```cpp
// Set thread affinity
bool success = ThreadingUtils::setThreadAffinity(thread, cpu_core);

// Get optimal CPU core
int optimal_core = ThreadingUtils::getOptimalCPUCore("solar_data");
```

### Memory Management

```cpp
// Get memory usage
size_t thread_memory = ThreadingUtils::getThreadMemoryUsage();
size_t process_memory = ThreadingUtils::getProcessMemoryUsage();

// Optimize memory usage
ThreadingUtils::optimizeMemoryUsage();

// Check memory pressure
bool high_pressure = ThreadingUtils::isMemoryPressureHigh();
```

## Debugging and Diagnostics

### Enable Debugging

```cpp
// Enable thread safety debugging
fgcom_enableThreadSafetyDebugging(true);

// Generate thread safety report
fgcom_generateThreadSafetyReport();

// Get mutex status
std::map<std::string, bool> mutex_status = fgcom_getMutexStatus();

// Get atomic variable values
std::map<std::string, std::string> atomic_values = fgcom_getAtomicValues();
```

### Performance Profiling

```cpp
// Performance timer
ThreadingUtils::PerformanceTimer timer("operation_name");
// ... perform operation ...
double elapsed_ms = timer.getElapsedTimeMs();
```

## Best Practices

### 1. Thread Safety
- Always use appropriate mutexes for shared data access
- Prefer `std::shared_mutex` for read-heavy operations
- Use atomic variables for simple flags and counters
- Avoid holding locks for extended periods

### 2. Error Handling
- Always wrap thread operations in try-catch blocks
- Log errors with appropriate context
- Implement retry mechanisms for transient failures
- Monitor thread health and restart if necessary

### 3. Performance
- Use thread pools for CPU-intensive tasks
- Implement proper queue management
- Monitor resource usage and adjust limits
- Use profiling tools to identify bottlenecks

### 4. Configuration
- Use configuration files for thread parameters
- Implement runtime configuration changes
- Validate configuration values
- Provide sensible defaults

### 5. Monitoring
- Enable performance monitoring in production
- Set up alerts for critical metrics
- Generate regular performance reports
- Monitor thread health and resource usage

## Troubleshooting

### Common Issues

#### Thread Not Starting
- Check if thread is already running
- Verify configuration settings
- Check for resource constraints
- Review error logs

#### High CPU Usage
- Check thread intervals
- Monitor queue sizes
- Review processing logic
- Consider thread affinity

#### Memory Leaks
- Monitor cache sizes
- Check for proper cleanup
- Review memory allocation patterns
- Use memory profiling tools

#### Deadlocks
- Review mutex ordering
- Check for circular dependencies
- Use deadlock detection tools
- Implement timeout mechanisms

### Debugging Tools

#### Thread Safety Validation
```cpp
// Validate thread safety configuration
bool is_valid = fgcom_validateThreadSafety();

// Check for deadlocks
bool has_deadlock = fgcom_checkForDeadlocks();

// Validate mutex ordering
bool valid_ordering = fgcom_validateMutexOrdering();
```

#### Performance Analysis
```cpp
// Get thread safety statistics
ThreadSafetyStats stats = fgcom_getThreadSafetyStats();

// Generate performance report
thread_manager.generatePerformanceReport();

// Get cache statistics
calculateCacheStatistics();
```

## Conclusion

The FGCom-mumble threading architecture extensions provide a robust, scalable, and maintainable multi-threading system that enhances the plugin's capabilities while maintaining thread safety and optimal performance. The system is designed to be easily integrated into existing code and provides comprehensive monitoring and debugging capabilities.

For more information, refer to the individual header files and implementation files in the `client/mumble-plugin/lib/` directory.
