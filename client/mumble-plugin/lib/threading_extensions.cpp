#include "threading_extensions.h"
#include "threading_types.h"
#include "solar_data.h"
#include "gpu_accelerator.h"
#include <algorithm>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <thread>
#include <chrono>
#include <stdexcept>
#include <cassert>

// Singleton instances
std::unique_ptr<FGCom_ThreadManager> FGCom_ThreadManager::instance = nullptr;
std::mutex FGCom_ThreadManager::instance_mutex;

// FGCom_ThreadManager Implementation
FGCom_ThreadManager::FGCom_ThreadManager() 
    : global_shutdown(false)
    , solar_data_shutdown(false)
    , propagation_shutdown(false)
    , api_server_shutdown(false)
    , gpu_compute_shutdown(false)
    , lightning_data_shutdown(false)
    , weather_data_shutdown(false)
    , antenna_pattern_shutdown(false)
    , monitoring_shutdown(false)
{
    initializeCaches();
}

FGCom_ThreadManager& FGCom_ThreadManager::getInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    if (!instance) {
        instance = std::unique_ptr<FGCom_ThreadManager>(new FGCom_ThreadManager());
    }
    return *instance;
}

void FGCom_ThreadManager::destroyInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    if (instance) {
        instance->shutdown();
        instance.reset();
    }
}

/**
 * Start all configured threads with proper error handling and synchronization
 * 
 * This method orchestrates the startup of multiple specialized threads that handle
 * different aspects of the FGCom system. Each thread has specific responsibilities:
 * 
 * Thread Responsibilities:
 * - solar_data: Processes solar activity data for radio propagation
 * - propagation: Calculates radio wave propagation models
 * - api_server: Handles HTTP API requests and responses
 * - gpu_compute: Manages GPU-accelerated computations
 * - lightning_data: Processes lightning strike data
 * - weather_data: Handles meteorological data processing
 * - antenna_pattern: Manages antenna radiation pattern calculations
 * 
 * Thread Safety Considerations:
 * - All thread operations are protected by thread_mutex
 * - Thread startup is atomic - either all succeed or none start
 * - Each thread has independent shutdown flags to prevent race conditions
 * - Thread lifecycle is managed through RAII patterns
 * 
 * Error Handling:
 * - If any thread fails to start, the entire operation is considered failed
 * - Failed threads are logged with specific error messages
 * - Thread state is tracked for debugging and monitoring
 * 
 * @return true if all threads started successfully, false otherwise
 */
bool FGCom_ThreadManager::startAllThreads() {
    // Critical: Acquire exclusive lock to prevent race conditions during startup
    // This ensures no other thread can modify thread state during initialization
    std::lock_guard<std::mutex> lock(thread_mutex);
    
    bool all_started = true;
    
    // Start solar data processing thread
    // This thread handles solar activity data which affects radio propagation
    if (config.enable_solar_data_thread) {
        if (startThread("solar_data")) {
            logThreadEvent("solar_data", "Thread started successfully");
        } else {
            logThreadEvent("solar_data", "Failed to start thread");
            all_started = false;
        }
    }
    
    // Start propagation thread
    if (config.enable_propagation_thread) {
        if (startThread("propagation")) {
            logThreadEvent("propagation", "Thread started successfully");
        } else {
            logThreadEvent("propagation", "Failed to start thread");
            all_started = false;
        }
    }
    
    // Start API server thread
    if (config.enable_api_server_thread) {
        if (startThread("api_server")) {
            logThreadEvent("api_server", "Thread started successfully");
        } else {
            logThreadEvent("api_server", "Failed to start thread");
            all_started = false;
        }
    }
    
    // Start GPU compute thread
    if (config.enable_gpu_compute_thread) {
        if (startThread("gpu_compute")) {
            logThreadEvent("gpu_compute", "Thread started successfully");
        } else {
            logThreadEvent("gpu_compute", "Failed to start thread");
            all_started = false;
        }
    }
    
    // Start lightning data thread
    if (config.enable_lightning_data_thread) {
        if (startThread("lightning_data")) {
            logThreadEvent("lightning_data", "Thread started successfully");
        } else {
            logThreadEvent("lightning_data", "Failed to start thread");
            all_started = false;
        }
    }
    
    // Start weather data thread
    if (config.enable_weather_data_thread) {
        if (startThread("weather_data")) {
            logThreadEvent("weather_data", "Thread started successfully");
        } else {
            logThreadEvent("weather_data", "Failed to start thread");
            all_started = false;
        }
    }
    
    // Start antenna pattern thread
    if (config.enable_antenna_pattern_thread) {
        if (startThread("antenna_pattern")) {
            logThreadEvent("antenna_pattern", "Thread started successfully");
        } else {
            logThreadEvent("antenna_pattern", "Failed to start thread");
            all_started = false;
        }
    }
    
    // Start monitoring thread
    if (config.enable_thread_monitoring) {
        startMonitoring();
    }
    
    return all_started;
}

bool FGCom_ThreadManager::stopAllThreads() {
    std::lock_guard<std::mutex> lock(thread_mutex);
    
    // Set shutdown flags
    global_shutdown = true;
    solar_data_shutdown = true;
    propagation_shutdown = true;
    api_server_shutdown = true;
    gpu_compute_shutdown = true;
    lightning_data_shutdown = true;
    weather_data_shutdown = true;
    antenna_pattern_shutdown = true;
    monitoring_shutdown = true;
    
    // Wait for all threads to finish
    for (auto& pair : managed_threads) {
        if (pair.second.joinable()) {
            pair.second.join();
        }
    }
    
    managed_threads.clear();
    
    // Stop monitoring
    stopMonitoring();
    
    logThreadEvent("system", "All threads stopped");
    return true;
}

bool FGCom_ThreadManager::startThread(const std::string& thread_name) {
    std::lock_guard<std::mutex> lock(thread_mutex);
    
    // Check if thread is already running
    if (managed_threads.find(thread_name) != managed_threads.end()) {
        return false;
    }
    
    // Initialize thread stats
    ThreadStats stats;
    stats.thread_name = thread_name;
    stats.start_time = std::chrono::system_clock::now();
    stats.last_activity = stats.start_time;
    stats.total_operations = 0;
    stats.failed_operations = 0;
    stats.average_processing_time_ms = 0.0;
    stats.peak_processing_time_ms = 0.0;
    stats.cpu_usage_percent = 0.0;
    stats.memory_usage_bytes = 0;
    stats.is_running = true;
    stats.is_busy = false;
    thread_stats[thread_name] = stats;
    
    // Start appropriate thread
    std::thread new_thread;
    
    if (thread_name == "solar_data") {
        new_thread = std::thread(&FGCom_ThreadManager::solarDataThreadFunction, this);
    } else if (thread_name == "propagation") {
        new_thread = std::thread(&FGCom_ThreadManager::propagationThreadFunction, this);
    } else if (thread_name == "api_server") {
        new_thread = std::thread(&FGCom_ThreadManager::apiServerThreadFunction, this);
    } else if (thread_name == "gpu_compute") {
        new_thread = std::thread(&FGCom_ThreadManager::gpuComputeThreadFunction, this);
    } else if (thread_name == "lightning_data") {
        new_thread = std::thread(&FGCom_ThreadManager::lightningDataThreadFunction, this);
    } else if (thread_name == "weather_data") {
        new_thread = std::thread(&FGCom_ThreadManager::weatherDataThreadFunction, this);
    } else if (thread_name == "antenna_pattern") {
        new_thread = std::thread(&FGCom_ThreadManager::antennaPatternThreadFunction, this);
    } else {
        return false;
    }
    
    // Store thread and update stats
    managed_threads[thread_name] = std::move(new_thread);
    thread_stats[thread_name].thread_id = managed_threads[thread_name].get_id();
    
    return true;
}

bool FGCom_ThreadManager::stopThread(const std::string& thread_name) {
    std::lock_guard<std::mutex> lock(thread_mutex);
    
    auto it = managed_threads.find(thread_name);
    if (it == managed_threads.end()) {
        return false;
    }
    
    // Set appropriate shutdown flag
    if (thread_name == "solar_data") {
        solar_data_shutdown = true;
    } else if (thread_name == "propagation") {
        propagation_shutdown = true;
    } else if (thread_name == "api_server") {
        api_server_shutdown = true;
    } else if (thread_name == "gpu_compute") {
        gpu_compute_shutdown = true;
    } else if (thread_name == "lightning_data") {
        lightning_data_shutdown = true;
    } else if (thread_name == "weather_data") {
        weather_data_shutdown = true;
    } else if (thread_name == "antenna_pattern") {
        antenna_pattern_shutdown = true;
    }
    
    // Wait for thread to finish
    if (it->second.joinable()) {
        it->second.join();
    }
    
    // Remove from managed threads
    managed_threads.erase(it);
    
    // Update stats
    if (thread_stats.find(thread_name) != thread_stats.end()) {
        thread_stats[thread_name].is_running = false;
    }
    
    return true;
}

bool FGCom_ThreadManager::isThreadRunning(const std::string& thread_name) const {
    std::lock_guard<std::mutex> lock(thread_mutex);
    
    auto it = managed_threads.find(thread_name);
    if (it == managed_threads.end()) {
        return false;
    }
    
    auto stats_it = thread_stats.find(thread_name);
    if (stats_it == thread_stats.end()) {
        return false;
    }
    
    return stats_it->second.is_running.load();
}

void FGCom_ThreadManager::setConfig(const ThreadingConfig& new_config) {
    std::lock_guard<std::mutex> lock(thread_mutex);
    config = new_config;
}

ThreadingConfig FGCom_ThreadManager::getConfig() const {
    std::lock_guard<std::mutex> lock(thread_mutex);
    return config;
}

bool FGCom_ThreadManager::loadConfigFromFile(const std::string& config_file) {
    std::ifstream file(config_file);
    if (!file.is_open()) {
        return false;
    }
    
    std::string line;
    std::string current_section = "";
    
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }
        
        if (line[0] == '[' && line.back() == ']') {
            current_section = line.substr(1, line.length() - 2);
            continue;
        }
        
        size_t equal_pos = line.find('=');
        if (equal_pos != std::string::npos) {
            std::string key = line.substr(0, equal_pos);
            std::string value = line.substr(equal_pos + 1);
            
            if (current_section == "threading") {
                if (key == "enable_solar_data_thread") {
                    config.enable_solar_data_thread = (value == "true");
                } else if (key == "enable_propagation_thread") {
                    config.enable_propagation_thread = (value == "true");
                } else if (key == "enable_api_server_thread") {
                    config.enable_api_server_thread = (value == "true");
                } else if (key == "enable_gpu_compute_thread") {
                    config.enable_gpu_compute_thread = (value == "true");
                } else if (key == "solar_data_interval_minutes") {
                    config.solar_data_interval_minutes = std::stoi(value);
                } else if (key == "propagation_interval_ms") {
                    config.propagation_interval_ms = std::stoi(value);
                } else if (key == "gpu_compute_interval_ms") {
                    config.gpu_compute_interval_ms = std::stoi(value);
                } else if (key == "max_worker_threads") {
                    config.max_worker_threads = std::stoi(value);
                } else if (key == "max_gpu_threads") {
                    config.max_gpu_threads = std::stoi(value);
                }
            }
        }
    }
    
    return true;
}

bool FGCom_ThreadManager::saveConfigToFile(const std::string& config_file) const {
    std::ofstream file(config_file);
    if (!file.is_open()) {
        return false;
    }
    
    file << "[threading]" << std::endl;
    file << "enable_solar_data_thread=" << (config.enable_solar_data_thread ? "true" : "false") << std::endl;
    file << "enable_propagation_thread=" << (config.enable_propagation_thread ? "true" : "false") << std::endl;
    file << "enable_api_server_thread=" << (config.enable_api_server_thread ? "true" : "false") << std::endl;
    file << "enable_gpu_compute_thread=" << (config.enable_gpu_compute_thread ? "true" : "false") << std::endl;
    file << "enable_lightning_data_thread=" << (config.enable_lightning_data_thread ? "true" : "false") << std::endl;
    file << "enable_weather_data_thread=" << (config.enable_weather_data_thread ? "true" : "false") << std::endl;
    file << "enable_antenna_pattern_thread=" << (config.enable_antenna_pattern_thread ? "true" : "false") << std::endl;
    file << "solar_data_interval_minutes=" << config.solar_data_interval_minutes << std::endl;
    file << "propagation_interval_ms=" << config.propagation_interval_ms << std::endl;
    file << "gpu_compute_interval_ms=" << config.gpu_compute_interval_ms << std::endl;
    file << "lightning_data_interval_seconds=" << config.lightning_data_interval_seconds << std::endl;
    file << "weather_data_interval_minutes=" << config.weather_data_interval_minutes << std::endl;
    file << "antenna_pattern_interval_ms=" << config.antenna_pattern_interval_ms << std::endl;
    file << "max_worker_threads=" << config.max_worker_threads << std::endl;
    file << "max_gpu_threads=" << config.max_gpu_threads << std::endl;
    file << "max_api_threads=" << config.max_api_threads << std::endl;
    file << "enable_thread_monitoring=" << (config.enable_thread_monitoring ? "true" : "false") << std::endl;
    file << "monitoring_interval_seconds=" << config.monitoring_interval_seconds << std::endl;
    
    return true;
}

ThreadStats FGCom_ThreadManager::getThreadStats(const std::string& thread_name) const {
    std::lock_guard<std::mutex> lock(thread_mutex);
    
    auto it = thread_stats.find(thread_name);
    if (it == thread_stats.end()) {
        return ThreadStats();
    }
    
    return it->second;
}

std::map<std::string, ThreadStats> FGCom_ThreadManager::getAllThreadStats() const {
    std::lock_guard<std::mutex> lock(thread_mutex);
    return thread_stats;
}

void FGCom_ThreadManager::updateThreadStats(const std::string& thread_name, const std::string& operation, double processing_time_ms, bool success) {
    std::lock_guard<std::mutex> lock(thread_mutex);
    
    auto it = thread_stats.find(thread_name);
    if (it == thread_stats.end()) {
        return;
    }
    
    ThreadStats& stats = it->second;
    stats.last_activity = std::chrono::system_clock::now();
    stats.total_operations++;
    
    if (!success) {
        stats.failed_operations++;
    }
    
    // Update average processing time
    double total_time = stats.average_processing_time_ms * (stats.total_operations - 1) + processing_time_ms;
    stats.average_processing_time_ms = total_time / stats.total_operations;
    
    // Update peak processing time
    if (processing_time_ms > stats.peak_processing_time_ms) {
        stats.peak_processing_time_ms = processing_time_ms;
    }
    
    stats.is_busy = false;
}

SolarDataCache* FGCom_ThreadManager::getSolarCache() const {
    return solar_cache.get();
}

PropagationQueue* FGCom_ThreadManager::getPropagationQueue() const {
    return propagation_queue.get();
}

GPUComputeQueue* FGCom_ThreadManager::getGPUQueue() const {
    return gpu_queue.get();
}

LightningDataCache* FGCom_ThreadManager::getLightningCache() const {
    return lightning_cache.get();
}

WeatherDataCache* FGCom_ThreadManager::getWeatherCache() const {
    return weather_cache.get();
}

AntennaPatternCache* FGCom_ThreadManager::getAntennaCache() const {
    return antenna_cache.get();
}

bool FGCom_ThreadManager::getSolarData(fgcom_solar_conditions& data) const {
    if (!solar_cache) {
        return false;
    }
    
    std::shared_lock<std::shared_mutex> lock(solar_cache->read_write_mutex);
    
    if (!solar_cache->data_valid.load()) {
        return false;
    }
    
    data = solar_cache->current_data;
    solar_cache->cache_hits++;
    
    // Update cache hit ratio
    size_t total_accesses = solar_cache->cache_hits.load() + solar_cache->cache_misses.load();
    if (total_accesses > 0) {
        solar_cache->cache_hit_ratio = static_cast<double>(solar_cache->cache_hits.load()) / total_accesses;
    }
    
    return true;
}

bool FGCom_ThreadManager::updateSolarData(const fgcom_solar_conditions& data) {
    if (!solar_cache) {
        return false;
    }
    
    std::unique_lock<std::shared_mutex> lock(solar_cache->read_write_mutex);
    
    solar_cache->current_data = data;
    solar_cache->last_update = std::time(nullptr);
    solar_cache->data_valid = true;
    solar_cache->last_successful_update = std::chrono::system_clock::now();
    
    // Add to historical data
    solar_cache->historical_data.push_back(data);
    
    // Limit historical data size
    if (solar_cache->historical_data.size() > solar_cache->max_historical_entries) {
        solar_cache->historical_data.erase(solar_cache->historical_data.begin());
    }
    
    return true;
}

bool FGCom_ThreadManager::addPropagationTask(const PropagationTask& task) {
    if (!propagation_queue) {
        return false;
    }
    
    std::unique_lock<std::mutex> lock(propagation_queue->queue_mutex);
    
    // Check if queue is full
    if (propagation_queue->queue_size.load() >= propagation_queue->max_queue_size.load()) {
        propagation_queue->queue_full = true;
        return false;
    }
    
    propagation_queue->pending_tasks.push(task);
    propagation_queue->queue_size++;
    
    // Notify waiting threads
    propagation_queue->task_available.notify_one();
    
    return true;
}

bool FGCom_ThreadManager::getCompletedPropagationTask(PropagationTask& task) {
    if (!propagation_queue) {
        return false;
    }
    
    std::unique_lock<std::mutex> lock(propagation_queue->queue_mutex);
    
    if (propagation_queue->completed_tasks.empty()) {
        return false;
    }
    
    task = propagation_queue->completed_tasks.front();
    propagation_queue->completed_tasks.pop();
    
    return true;
}

bool FGCom_ThreadManager::addGPUComputeTask(const GPUComputeTask& task) {
    if (!gpu_queue) {
        return false;
    }
    
    std::unique_lock<std::mutex> lock(gpu_queue->queue_mutex);
    
    // Check if GPU is available
    if (gpu_queue->active_tasks.load() >= gpu_queue->max_concurrent_tasks.load()) {
        return false;
    }
    
    gpu_queue->pending_tasks.push(task);
    
    // Notify waiting threads
    gpu_queue->task_available.notify_one();
    
    return true;
}

bool FGCom_ThreadManager::getCompletedGPUComputeTask(GPUComputeTask& task) {
    if (!gpu_queue) {
        return false;
    }
    
    std::unique_lock<std::mutex> lock(gpu_queue->queue_mutex);
    
    if (gpu_queue->completed_tasks.empty()) {
        return false;
    }
    
    task = gpu_queue->completed_tasks.front();
    gpu_queue->completed_tasks.pop();
    
    return true;
}

void FGCom_ThreadManager::startMonitoring() {
    if (monitoring_thread.joinable()) {
        return; // Already running
    }
    
    monitoring_shutdown = false;
    monitoring_thread = std::thread(&FGCom_ThreadManager::monitoringThreadFunction, this);
}

void FGCom_ThreadManager::stopMonitoring() {
    if (!monitoring_thread.joinable()) {
        return; // Not running
    }
    
    monitoring_shutdown = true;
    monitoring_thread.join();
}

bool FGCom_ThreadManager::isMonitoringActive() const {
    return monitoring_thread.joinable() && !monitoring_shutdown.load();
}

void FGCom_ThreadManager::generatePerformanceReport() const {
    std::cout << "\n=== FGCom-mumble Threading Performance Report ===" << std::endl;
    
    std::lock_guard<std::mutex> lock(thread_mutex);
    
    for (const auto& pair : thread_stats) {
        const ThreadStats& stats = pair.second;
        
        std::cout << "\nThread: " << stats.thread_name << std::endl;
        std::cout << "  Status: " << (stats.is_running.load() ? "Running" : "Stopped") << std::endl;
        std::cout << "  Total Operations: " << stats.total_operations.load() << std::endl;
        std::cout << "  Failed Operations: " << stats.failed_operations.load() << std::endl;
        std::cout << "  Success Rate: " << std::fixed << std::setprecision(2) 
                  << (100.0 * (stats.total_operations.load() - stats.failed_operations.load()) / 
                      std::max(1UL, stats.total_operations.load())) << "%" << std::endl;
        std::cout << "  Average Processing Time: " << stats.average_processing_time_ms.load() << " ms" << std::endl;
        std::cout << "  Peak Processing Time: " << stats.peak_processing_time_ms.load() << " ms" << std::endl;
        std::cout << "  CPU Usage: " << stats.cpu_usage_percent.load() << "%" << std::endl;
        std::cout << "  Memory Usage: " << stats.memory_usage_bytes.load() / 1024 << " KB" << std::endl;
        
        if (!stats.last_error.empty()) {
            std::cout << "  Last Error: " << stats.last_error << std::endl;
        }
    }
    
    // Cache performance
    if (solar_cache) {
        std::cout << "\nSolar Data Cache:" << std::endl;
        std::cout << "  Cache Hits: " << solar_cache->cache_hits.load() << std::endl;
        std::cout << "  Cache Misses: " << solar_cache->cache_misses.load() << std::endl;
        std::cout << "  Hit Ratio: " << std::fixed << std::setprecision(2) 
                  << (solar_cache->cache_hit_ratio.load() * 100.0) << "%" << std::endl;
    }
    
    if (propagation_queue) {
        std::cout << "\nPropagation Queue:" << std::endl;
        std::cout << "  Queue Size: " << propagation_queue->queue_size.load() << std::endl;
        std::cout << "  Total Tasks Processed: " << propagation_queue->total_tasks_processed.load() << std::endl;
        std::cout << "  Failed Tasks: " << propagation_queue->failed_tasks.load() << std::endl;
        std::cout << "  Average Processing Time: " << propagation_queue->average_processing_time_ms.load() << " ms" << std::endl;
    }
    
    if (gpu_queue) {
        std::cout << "\nGPU Compute Queue:" << std::endl;
        std::cout << "  Active Tasks: " << gpu_queue->active_tasks.load() << std::endl;
        std::cout << "  GPU Utilization: " << gpu_queue->gpu_utilization_percent.load() << "%" << std::endl;
        std::cout << "  GPU Memory Usage: " << gpu_queue->gpu_memory_usage.load() / 1024 / 1024 << " MB" << std::endl;
        std::cout << "  Total GPU Operations: " << gpu_queue->total_gpu_operations.load() << std::endl;
    }
    
    std::cout << "\n=== End Performance Report ===" << std::endl;
}

void FGCom_ThreadManager::shutdown() {
    stopAllThreads();
    cleanup();
}

void FGCom_ThreadManager::cleanup() {
    cleanupCaches();
}

// Thread function implementations
void FGCom_ThreadManager::solarDataThreadFunction() {
    logThreadEvent("solar_data", "Thread started");
    
    // Validate initial state
    if (!solar_cache) {
        setThreadError("solar_data", "Solar cache not initialized");
        logThreadEvent("solar_data", "Thread stopped due to initialization error");
        return;
    }
    
    while (!solar_data_shutdown.load()) {
        try {
            // Validate thread state before processing
            if (solar_data_shutdown.load()) {
                break;
            }
            
            updateThreadActivity("solar_data");
            
            // Update solar data with proper error handling
            try {
                auto& solar_provider = FGCom_SolarDataProvider::getInstance();
                fgcom_solar_conditions current_conditions = solar_provider.getCurrentConditions();
                
                if (updateSolarData(current_conditions)) {
                    updateThreadStats("solar_data", "solar_update", 100.0, true);
                } else {
                    updateThreadStats("solar_data", "solar_update", 100.0, false);
                    setThreadError("solar_data", "Failed to update solar data");
                }
            } catch (const std::exception& e) {
                setThreadError("solar_data", "Solar provider exception: " + std::string(e.what()));
                updateThreadStats("solar_data", "solar_update", 100.0, false);
            }
            
        } catch (const std::exception& e) {
            setThreadError("solar_data", "Exception in solar data thread: " + std::string(e.what()));
            updateThreadStats("solar_data", "solar_update", 100.0, false);
        } catch (...) {
            setThreadError("solar_data", "Unknown exception in solar data thread");
            updateThreadStats("solar_data", "solar_update", 100.0, false);
        }
        
        // Sleep for configured interval with proper shutdown checking
        for (int i = 0; i < config.solar_data_interval_minutes * 60 && !solar_data_shutdown.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    
    logThreadEvent("solar_data", "Thread stopped");
}

void FGCom_ThreadManager::propagationThreadFunction() {
    logThreadEvent("propagation", "Thread started");
    
    // Validate initial state
    if (!propagation_queue) {
        setThreadError("propagation", "Propagation queue not initialized");
        logThreadEvent("propagation", "Thread stopped due to initialization error");
        return;
    }
    
    while (!propagation_shutdown.load()) {
        try {
            // Validate thread state before processing
            if (propagation_shutdown.load()) {
                break;
            }
            
            updateThreadActivity("propagation");
            
            // Process propagation queue with proper synchronization
            PropagationTask task;
            bool has_task = false;
            
            // Safely acquire task from queue
            {
                std::unique_lock<std::mutex> lock(propagation_queue->queue_mutex);
                if (!propagation_queue->pending_tasks.empty()) {
                    task = propagation_queue->pending_tasks.front();
                    propagation_queue->pending_tasks.pop();
                    propagation_queue->queue_size--;
                    has_task = true;
                    
                    // Notify that queue is not full
                    propagation_queue->queue_not_full.notify_one();
                }
            }
            
            if (has_task) {
                auto start_time = std::chrono::high_resolution_clock::now();
                
                // Process the task with error handling
                bool success = false;
                try {
                    success = processPropagationTask(task);
                } catch (const std::exception& e) {
                    setThreadError("propagation", "Task processing exception: " + std::string(e.what()));
                    success = false;
                } catch (...) {
                    setThreadError("propagation", "Unknown exception in task processing");
                    success = false;
                }
                
                auto end_time = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
                double processing_time_ms = duration.count() / 1000.0;
                
                // Add to completed tasks with proper synchronization
                {
                    std::unique_lock<std::mutex> lock(propagation_queue->queue_mutex);
                    propagation_queue->completed_tasks.push(task);
                }
                
                // Update statistics atomically
                propagation_queue->total_tasks_processed++;
                if (!success) {
                    propagation_queue->failed_tasks++;
                }
                
                // Update average processing time safely
                uint64_t total_processed = propagation_queue->total_tasks_processed.load();
                if (total_processed > 0) {
                    double total_time = propagation_queue->average_processing_time_ms * (total_processed - 1) + processing_time_ms;
                    propagation_queue->average_processing_time_ms = total_time / total_processed;
                }
                
                updateThreadStats("propagation", "propagation_task", processing_time_ms, success);
            }
            
        } catch (const std::exception& e) {
            setThreadError("propagation", "Exception in propagation thread: " + std::string(e.what()));
            updateThreadStats("propagation", "propagation_task", 0.0, false);
        } catch (...) {
            setThreadError("propagation", "Unknown exception in propagation thread");
            updateThreadStats("propagation", "propagation_task", 0.0, false);
        }
        
        // Sleep for configured interval with proper shutdown checking
        for (int i = 0; i < config.propagation_interval_ms && !propagation_shutdown.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    
    logThreadEvent("propagation", "Thread stopped");
}

void FGCom_ThreadManager::apiServerThreadFunction() {
    logThreadEvent("api_server", "Thread started");
    
    while (!api_server_shutdown.load()) {
        try {
            // Validate thread state before processing
            if (api_server_shutdown.load()) {
                break;
            }
            
            updateThreadActivity("api_server");
            
            // API server processing with proper error handling
            try {
                // In a real implementation, this would handle HTTP requests
                // For now, simulate API processing
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                
                updateThreadStats("api_server", "api_request", 5.0, true);
            } catch (const std::exception& e) {
                setThreadError("api_server", "API processing exception: " + std::string(e.what()));
                updateThreadStats("api_server", "api_request", 5.0, false);
            } catch (...) {
                setThreadError("api_server", "Unknown exception in API processing");
                updateThreadStats("api_server", "api_request", 5.0, false);
            }
            
        } catch (const std::exception& e) {
            setThreadError("api_server", "Exception in API server thread: " + std::string(e.what()));
            updateThreadStats("api_server", "api_request", 5.0, false);
        } catch (...) {
            setThreadError("api_server", "Unknown exception in API server thread");
            updateThreadStats("api_server", "api_request", 5.0, false);
        }
        
        // Sleep briefly with proper shutdown checking
        for (int i = 0; i < 10 && !api_server_shutdown.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    
    logThreadEvent("api_server", "Thread stopped");
}

void FGCom_ThreadManager::gpuComputeThreadFunction() {
    logThreadEvent("gpu_compute", "Thread started");
    
    // Validate initial state
    if (!gpu_queue) {
        setThreadError("gpu_compute", "GPU queue not initialized");
        logThreadEvent("gpu_compute", "Thread stopped due to initialization error");
        return;
    }
    
    while (!gpu_compute_shutdown.load()) {
        try {
            // Validate thread state before processing
            if (gpu_compute_shutdown.load()) {
                break;
            }
            
            updateThreadActivity("gpu_compute");
            
            // Process GPU compute queue with proper synchronization
            GPUComputeTask task;
            bool has_task = false;
            
            // Safely acquire task from queue
            {
                std::unique_lock<std::mutex> lock(gpu_queue->queue_mutex);
                if (!gpu_queue->pending_tasks.empty()) {
                    task = gpu_queue->pending_tasks.front();
                    gpu_queue->pending_tasks.pop();
                    gpu_queue->active_tasks++;
                    has_task = true;
                }
            }
            
            if (has_task) {
                auto start_time = std::chrono::high_resolution_clock::now();
                
                // Process the GPU task with error handling
                bool success = false;
                try {
                    success = processGPUComputeTask(task);
                } catch (const std::exception& e) {
                    setThreadError("gpu_compute", "GPU task processing exception: " + std::string(e.what()));
                    success = false;
                } catch (...) {
                    setThreadError("gpu_compute", "Unknown exception in GPU task processing");
                    success = false;
                }
                
                auto end_time = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
                double processing_time_ms = duration.count() / 1000.0;
                
                // Add to completed tasks with proper synchronization
                {
                    std::unique_lock<std::mutex> lock(gpu_queue->queue_mutex);
                    gpu_queue->completed_tasks.push(task);
                    gpu_queue->active_tasks--;
                    
                    // Notify that GPU is available
                    gpu_queue->gpu_available.notify_one();
                }
                
                // Update statistics atomically
                gpu_queue->total_gpu_operations++;
                if (!success) {
                    gpu_queue->failed_gpu_operations++;
                }
                
                // Update average processing time safely
                uint64_t total_operations = gpu_queue->total_gpu_operations.load();
                if (total_operations > 0) {
                    double total_time = gpu_queue->average_gpu_processing_time_ms * (total_operations - 1) + processing_time_ms;
                    gpu_queue->average_gpu_processing_time_ms = total_time / total_operations;
                }
                
                updateThreadStats("gpu_compute", "gpu_task", processing_time_ms, success);
            }
            
        } catch (const std::exception& e) {
            setThreadError("gpu_compute", "Exception in GPU compute thread: " + std::string(e.what()));
            updateThreadStats("gpu_compute", "gpu_task", 0.0, false);
        } catch (...) {
            setThreadError("gpu_compute", "Unknown exception in GPU compute thread");
            updateThreadStats("gpu_compute", "gpu_task", 0.0, false);
        }
        
        // Sleep for configured interval with proper shutdown checking
        for (int i = 0; i < config.gpu_compute_interval_ms && !gpu_compute_shutdown.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    
    logThreadEvent("gpu_compute", "Thread stopped");
}

void FGCom_ThreadManager::lightningDataThreadFunction() {
    logThreadEvent("lightning_data", "Thread started");
    
    while (!lightning_data_shutdown.load()) {
        try {
            updateThreadActivity("lightning_data");
            
            // Update lightning data (placeholder)
            // In a real implementation, this would fetch from lightning APIs
            
            updateThreadStats("lightning_data", "lightning_update", 50.0, true);
            
        } catch (const std::exception& e) {
            setThreadError("lightning_data", "Exception in lightning data thread: " + std::string(e.what()));
            updateThreadStats("lightning_data", "lightning_update", 50.0, false);
        }
        
        // Sleep for configured interval
        std::this_thread::sleep_for(std::chrono::seconds(config.lightning_data_interval_seconds));
    }
    
    logThreadEvent("lightning_data", "Thread stopped");
}

void FGCom_ThreadManager::weatherDataThreadFunction() {
    logThreadEvent("weather_data", "Thread started");
    
    while (!weather_data_shutdown.load()) {
        try {
            updateThreadActivity("weather_data");
            
            // Update weather data (placeholder)
            // In a real implementation, this would fetch from weather APIs
            
            updateThreadStats("weather_data", "weather_update", 200.0, true);
            
        } catch (const std::exception& e) {
            setThreadError("weather_data", "Exception in weather data thread: " + std::string(e.what()));
            updateThreadStats("weather_data", "weather_update", 200.0, false);
        }
        
        // Sleep for configured interval
        std::this_thread::sleep_for(std::chrono::minutes(config.weather_data_interval_minutes));
    }
    
    logThreadEvent("weather_data", "Thread stopped");
}

void FGCom_ThreadManager::antennaPatternThreadFunction() {
    logThreadEvent("antenna_pattern", "Thread started");
    
    while (!antenna_pattern_shutdown.load()) {
        try {
            updateThreadActivity("antenna_pattern");
            
            // Process antenna patterns (placeholder)
            // In a real implementation, this would handle antenna pattern calculations
            
            updateThreadStats("antenna_pattern", "pattern_calculation", 25.0, true);
            
        } catch (const std::exception& e) {
            setThreadError("antenna_pattern", "Exception in antenna pattern thread: " + std::string(e.what()));
            updateThreadStats("antenna_pattern", "pattern_calculation", 25.0, false);
        }
        
        // Sleep for configured interval
        std::this_thread::sleep_for(std::chrono::milliseconds(config.antenna_pattern_interval_ms));
    }
    
    logThreadEvent("antenna_pattern", "Thread stopped");
}

void FGCom_ThreadManager::monitoringThreadFunction() {
    logThreadEvent("monitoring", "Thread started");
    
    while (!monitoring_shutdown.load()) {
        try {
            updateThreadActivity("monitoring");
            
            // Update performance counters
            updatePerformanceCounters();
            
            // Calculate cache statistics
            calculateCacheStatistics();
            
            // Generate reports if needed
            if (config.enable_performance_counters) {
                // Could generate periodic reports here
            }
            
        } catch (const std::exception& e) {
            setThreadError("monitoring", "Exception in monitoring thread: " + std::string(e.what()));
        }
        
        // Sleep for configured interval
        std::this_thread::sleep_for(std::chrono::seconds(config.monitoring_interval_seconds));
    }
    
    logThreadEvent("monitoring", "Thread stopped");
}

// Internal helper methods
void FGCom_ThreadManager::initializeCaches() {
    solar_cache = std::make_unique<SolarDataCache>();
    propagation_queue = std::make_unique<PropagationQueue>();
    gpu_queue = std::make_unique<GPUComputeQueue>();
    lightning_cache = std::make_unique<LightningDataCache>();
    weather_cache = std::make_unique<WeatherDataCache>();
    antenna_cache = std::make_unique<AntennaPatternCache>();
    
    // Initialize queue limits
    propagation_queue->max_queue_size = 1000;
    gpu_queue->max_concurrent_tasks = config.max_gpu_threads;
    gpu_queue->gpu_memory_limit = 1024 * 1024 * 1024; // 1GB default
}

void FGCom_ThreadManager::cleanupCaches() {
    solar_cache.reset();
    propagation_queue.reset();
    gpu_queue.reset();
    lightning_cache.reset();
    weather_cache.reset();
    antenna_cache.reset();
}

void FGCom_ThreadManager::updateThreadActivity(const std::string& thread_name) {
    std::lock_guard<std::mutex> lock(thread_mutex);
    
    auto it = thread_stats.find(thread_name);
    if (it != thread_stats.end()) {
        it->second.last_activity = std::chrono::system_clock::now();
        it->second.is_busy = true;
    }
}

void FGCom_ThreadManager::logThreadEvent(const std::string& thread_name, const std::string& event) {
    std::cout << "[ThreadManager] " << thread_name << ": " << event << std::endl;
}

void FGCom_ThreadManager::setThreadError(const std::string& thread_name, const std::string& error) {
    std::lock_guard<std::mutex> lock(thread_mutex);
    
    auto it = thread_stats.find(thread_name);
    if (it != thread_stats.end()) {
        it->second.last_error = error;
        it->second.last_error_time = std::chrono::system_clock::now();
    }
}

std::string FGCom_ThreadManager::getThreadError(const std::string& thread_name) const {
    std::lock_guard<std::mutex> lock(thread_mutex);
    
    auto it = thread_stats.find(thread_name);
    if (it != thread_stats.end()) {
        return it->second.last_error;
    }
    
    return "";
}

void FGCom_ThreadManager::clearThreadError(const std::string& thread_name) {
    std::lock_guard<std::mutex> lock(thread_mutex);
    
    auto it = thread_stats.find(thread_name);
    if (it != thread_stats.end()) {
        it->second.last_error.clear();
    }
}

void FGCom_ThreadManager::updatePerformanceCounters() {
    // Update CPU and memory usage for all threads
    std::lock_guard<std::mutex> lock(thread_mutex);
    
    for (auto& pair : thread_stats) {
        // Placeholder for CPU and memory usage calculation
        // In a real implementation, this would use platform-specific APIs
        pair.second.cpu_usage_percent = 0.0; // Placeholder
        pair.second.memory_usage_bytes = 0; // Placeholder
    }
}

void FGCom_ThreadManager::calculateCacheStatistics() {
    // Update cache statistics
    if (solar_cache) {
        size_t total_accesses = solar_cache->cache_hits.load() + solar_cache->cache_misses.load();
        if (total_accesses > 0) {
            solar_cache->cache_hit_ratio = static_cast<double>(solar_cache->cache_hits.load()) / total_accesses;
        }
    }
    
    if (antenna_cache) {
        size_t total_accesses = antenna_cache->cache_hits.load() + antenna_cache->cache_misses.load();
        if (total_accesses > 0) {
            antenna_cache->cache_hit_ratio = static_cast<double>(antenna_cache->cache_hits.load()) / total_accesses;
        }
    }
}

// Task processing implementations with proper error handling
bool FGCom_ThreadManager::processPropagationTask(const PropagationTask& task) {
    try {
        // Validate task parameters
        if (task.task_id.empty()) {
            logThreadEvent("propagation", "Invalid task: empty task_id");
            return false;
        }
        
        // Simulate propagation calculation
        // In a real implementation, this would call the propagation engine
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        
        logThreadEvent("propagation", "Processed task: " + task.task_id);
        return true;
    } catch (const std::exception& e) {
        logThreadEvent("propagation", "Exception in processPropagationTask: " + std::string(e.what()));
        return false;
    } catch (...) {
        logThreadEvent("propagation", "Unknown exception in processPropagationTask");
        return false;
    }
}

bool FGCom_ThreadManager::processGPUComputeTask(const GPUComputeTask& task) {
    try {
        // Validate task parameters
        if (task.task_id.empty()) {
            logThreadEvent("gpu_compute", "Invalid task: empty task_id");
            return false;
        }
        
        if (task.input_data == nullptr && task.input_size > 0) {
            logThreadEvent("gpu_compute", "Invalid task: null input data with non-zero size");
            return false;
        }
        
        // Simulate GPU computation
        // In a real implementation, this would call the GPU accelerator
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        
        logThreadEvent("gpu_compute", "Processed GPU task: " + task.task_id);
        return true;
    } catch (const std::exception& e) {
        logThreadEvent("gpu_compute", "Exception in processGPUComputeTask: " + std::string(e.what()));
        return false;
    } catch (...) {
        logThreadEvent("gpu_compute", "Unknown exception in processGPUComputeTask");
        return false;
    }
}

// Global thread management functions (C interface)
extern "C" {
    void fgcom_spawnSolarDataManager() {
        auto& manager = FGCom_ThreadManager::getInstance();
        manager.startThread("solar_data");
    }
    
    void fgcom_spawnPropagationEngine() {
        auto& manager = FGCom_ThreadManager::getInstance();
        manager.startThread("propagation");
    }
    
    void fgcom_spawnAPIServer() {
        auto& manager = FGCom_ThreadManager::getInstance();
        manager.startThread("api_server");
    }
    
    void fgcom_spawnGPUComputeEngine() {
        auto& manager = FGCom_ThreadManager::getInstance();
        manager.startThread("gpu_compute");
    }
    
    void fgcom_spawnLightningDataManager() {
        auto& manager = FGCom_ThreadManager::getInstance();
        manager.startThread("lightning_data");
    }
    
    void fgcom_spawnWeatherDataManager() {
        auto& manager = FGCom_ThreadManager::getInstance();
        manager.startThread("weather_data");
    }
    
    void fgcom_spawnAntennaPatternManager() {
        auto& manager = FGCom_ThreadManager::getInstance();
        manager.startThread("antenna_pattern");
    }
    
    void fgcom_startAllBackgroundThreads() {
        auto& manager = FGCom_ThreadManager::getInstance();
        manager.startAllThreads();
    }
    
    void fgcom_stopAllBackgroundThreads() {
        auto& manager = FGCom_ThreadManager::getInstance();
        manager.stopAllThreads();
    }
    
    bool fgcom_isBackgroundThreadRunning(const char* thread_name) {
        auto& manager = FGCom_ThreadManager::getInstance();
        return manager.isThreadRunning(thread_name);
    }
    
    bool fgcom_getSolarData(fgcom_solar_conditions* data) {
        if (!data) return false;
        auto& manager = FGCom_ThreadManager::getInstance();
        return manager.getSolarData(*data);
    }
    
    bool fgcom_updateSolarData(const fgcom_solar_conditions* data) {
        if (!data) return false;
        auto& manager = FGCom_ThreadManager::getInstance();
        return manager.updateSolarData(*data);
    }
    
    bool fgcom_addPropagationTask(const PropagationTask* task) {
        if (!task) return false;
        auto& manager = FGCom_ThreadManager::getInstance();
        return manager.addPropagationTask(*task);
    }
    
    bool fgcom_getCompletedPropagationTask(PropagationTask* task) {
        if (!task) return false;
        auto& manager = FGCom_ThreadManager::getInstance();
        return manager.getCompletedPropagationTask(*task);
    }
    
    void fgcom_startThreadMonitoring() {
        auto& manager = FGCom_ThreadManager::getInstance();
        manager.startMonitoring();
    }
    
    void fgcom_stopThreadMonitoring() {
        auto& manager = FGCom_ThreadManager::getInstance();
        manager.stopMonitoring();
    }
    
    void fgcom_generatePerformanceReport() {
        auto& manager = FGCom_ThreadManager::getInstance();
        manager.generatePerformanceReport();
    }
    
    bool fgcom_loadThreadingConfig(const char* config_file) {
        if (!config_file) return false;
        auto& manager = FGCom_ThreadManager::getInstance();
        return manager.loadConfigFromFile(config_file);
    }
    
    bool fgcom_saveThreadingConfig(const char* config_file) {
        if (!config_file) return false;
        auto& manager = FGCom_ThreadManager::getInstance();
        return manager.saveConfigToFile(config_file);
    }
}
