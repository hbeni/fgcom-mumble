#include "gpu_accelerator.h"
#include <algorithm>
#include <cmath>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <thread>
#include <chrono>

// Singleton instances
std::unique_ptr<FGCom_GPUAccelerator> FGCom_GPUAccelerator::instance = nullptr;
std::mutex FGCom_GPUAccelerator::instance_mutex;

std::unique_ptr<FGCom_GPUConfig> FGCom_GPUConfig::instance = nullptr;
std::mutex FGCom_GPUConfig::instance_mutex;

// FGCom_GPUAccelerator Implementation
FGCom_GPUAccelerator::FGCom_GPUAccelerator() 
    : acceleration_mode(GPUAccelerationMode::DISABLED)
    , gpu_available(false)
    , primary_gpu_vendor(GPUVendor::UNKNOWN)
    , gpu_memory_limit_mb(1024)
    , max_concurrent_operations(4)
    , total_allocated_memory(0)
    , peak_memory_usage(0)
    , workers_running(false)
    , is_initialized(false)
{
    initializeDefaultConfiguration();
}

FGCom_GPUAccelerator& FGCom_GPUAccelerator::getInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    if (!instance) {
        instance = std::unique_ptr<FGCom_GPUAccelerator>(new FGCom_GPUAccelerator());
    }
    return *instance;
}

void FGCom_GPUAccelerator::destroyInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    if (instance) {
        instance->shutdown();
        instance.reset();
    }
}

bool FGCom_GPUAccelerator::initializeGPU() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    
    if (is_initialized) {
        return gpu_available;
    }
    
    // Detect available GPUs
    available_gpus = GPUAccelerationUtils::detectAvailableGPUs();
    
    if (available_gpus.empty()) {
        logInfo("No GPU devices detected");
        gpu_available = false;
        is_initialized = true;
        return false;
    }
    
    // Select primary GPU
    if (!available_gpus.empty()) {
        primary_gpu_vendor = available_gpus[0].vendor;
        gpu_available = true;
        
        // Initialize GPU-specific frameworks
        bool cuda_available = false;
        bool opencl_available = false;
        bool metal_available = false;
        
        switch (primary_gpu_vendor) {
            case GPUVendor::NVIDIA:
                cuda_available = initializeCUDA();
                break;
            case GPUVendor::AMD:
            case GPUVendor::INTEL:
                opencl_available = initializeOpenCL();
                break;
            case GPUVendor::APPLE:
                metal_available = initializeMetal();
                break;
            default:
                logError("Unsupported GPU vendor");
                gpu_available = false;
                break;
        }
        
        if (!cuda_available && !opencl_available && !metal_available) {
            logError("Failed to initialize GPU framework");
            gpu_available = false;
        }
    }
    
    if (gpu_available) {
        startWorkerThreads();
        logInfo("GPU acceleration initialized successfully");
    }
    
    is_initialized = true;
    return gpu_available;
}

bool FGCom_GPUAccelerator::initializeCUDA() {
    // CUDA initialization would go here
    // For now, return true if NVIDIA GPU is detected
    logInfo("CUDA initialization (placeholder)");
    return (primary_gpu_vendor == GPUVendor::NVIDIA);
}

bool FGCom_GPUAccelerator::initializeOpenCL() {
    // OpenCL initialization would go here
    // For now, return true if AMD/Intel GPU is detected
    logInfo("OpenCL initialization (placeholder)");
    return (primary_gpu_vendor == GPUVendor::AMD || primary_gpu_vendor == GPUVendor::INTEL);
}

bool FGCom_GPUAccelerator::initializeMetal() {
    // Apple Metal initialization would go here
    // For now, return true if Apple GPU is detected
    logInfo("Metal initialization (placeholder)");
    return (primary_gpu_vendor == GPUVendor::APPLE);
}

void FGCom_GPUAccelerator::setAccelerationMode(GPUAccelerationMode mode) {
    std::lock_guard<std::mutex> lock(instance_mutex);
    acceleration_mode = mode;
    
    switch (mode) {
        case GPUAccelerationMode::DISABLED:
            logInfo("GPU acceleration disabled");
            break;
        case GPUAccelerationMode::SERVER_ONLY:
            logInfo("GPU acceleration enabled on server only");
            break;
        case GPUAccelerationMode::CLIENT_ONLY:
            logInfo("GPU acceleration enabled on clients only");
            break;
        case GPUAccelerationMode::HYBRID:
            logInfo("GPU acceleration enabled in hybrid mode");
            break;
    }
}

GPUAccelerationMode FGCom_GPUAccelerator::getAccelerationMode() const {
    std::lock_guard<std::mutex> lock(instance_mutex);
    return acceleration_mode;
}

bool FGCom_GPUAccelerator::isGPUAvailable() const {
    std::lock_guard<std::mutex> lock(instance_mutex);
    return gpu_available;
}

std::vector<GPUDeviceInfo> FGCom_GPUAccelerator::getAvailableGPUs() const {
    std::lock_guard<std::mutex> lock(instance_mutex);
    return available_gpus;
}

GPUDeviceInfo FGCom_GPUAccelerator::getPrimaryGPU() const {
    std::lock_guard<std::mutex> lock(instance_mutex);
    if (available_gpus.empty()) {
        return GPUDeviceInfo();
    }
    return available_gpus[0];
}

bool FGCom_GPUAccelerator::accelerateAntennaPatterns(std::vector<AntennaGainPoint>& patterns, const std::string& operation_id) {
    if (acceleration_mode == GPUAccelerationMode::DISABLED || !gpu_available) {
        return false;
    }
    
    GPUOperationRequest request;
    request.operation_type = GPUOperationType::ANTENNA_PATTERN_CALCULATION;
    request.operation_id = operation_id.empty() ? "antenna_pattern_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) : operation_id;
    request.input_data = patterns.data();
    request.input_size = patterns.size() * sizeof(AntennaGainPoint);
    request.output_data = patterns.data();
    request.output_size = patterns.size() * sizeof(AntennaGainPoint);
    request.parameters["pattern_count"] = static_cast<float>(patterns.size());
    request.priority = 5;
    request.request_time = std::chrono::system_clock::now();
    request.requires_double_precision = false;
    request.estimated_memory_usage = request.input_size + request.output_size;
    
    return executeOperation(request);
}

bool FGCom_GPUAccelerator::acceleratePropagationCalculations(const std::vector<PropagationPath>& paths, const std::string& operation_id) {
    if (acceleration_mode == GPUAccelerationMode::DISABLED || !gpu_available) {
        return false;
    }
    
    GPUOperationRequest request;
    request.operation_type = GPUOperationType::PROPAGATION_MODELING;
    request.operation_id = operation_id.empty() ? "propagation_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) : operation_id;
    request.input_data = const_cast<PropagationPath*>(paths.data());
    request.input_size = paths.size() * sizeof(PropagationPath);
    request.parameters["path_count"] = static_cast<float>(paths.size());
    request.priority = 7;
    request.request_time = std::chrono::system_clock::now();
    request.requires_double_precision = true;
    request.estimated_memory_usage = request.input_size * 2; // Input + output
    
    return executeOperation(request);
}

bool FGCom_GPUAccelerator::accelerateAudioProcessing(float* audio_buffer, size_t samples, const std::string& operation_id) {
    if (acceleration_mode == GPUAccelerationMode::DISABLED || !gpu_available) {
        return false;
    }
    
    GPUOperationRequest request;
    request.operation_type = GPUOperationType::AUDIO_PROCESSING;
    request.operation_id = operation_id.empty() ? "audio_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) : operation_id;
    request.input_data = audio_buffer;
    request.input_size = samples * sizeof(float);
    request.output_data = audio_buffer;
    request.output_size = samples * sizeof(float);
    request.parameters["sample_count"] = static_cast<float>(samples);
    request.priority = 3;
    request.request_time = std::chrono::system_clock::now();
    request.requires_double_precision = false;
    request.estimated_memory_usage = request.input_size + request.output_size;
    
    return executeOperation(request);
}

bool FGCom_GPUAccelerator::accelerateFrequencyOffsetProcessing(float* audio_buffer, size_t samples, float offset_hz, const std::string& operation_id) {
    if (acceleration_mode == GPUAccelerationMode::DISABLED || !gpu_available) {
        return false;
    }
    
    GPUOperationRequest request;
    request.operation_type = GPUOperationType::FREQUENCY_OFFSET_PROCESSING;
    request.operation_id = operation_id.empty() ? "freq_offset_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) : operation_id;
    request.input_data = audio_buffer;
    request.input_size = samples * sizeof(float);
    request.output_data = audio_buffer;
    request.output_size = samples * sizeof(float);
    request.parameters["sample_count"] = static_cast<float>(samples);
    request.parameters["offset_hz"] = offset_hz;
    request.priority = 4;
    request.request_time = std::chrono::system_clock::now();
    request.requires_double_precision = false;
    request.estimated_memory_usage = request.input_size + request.output_size;
    
    return executeOperation(request);
}

bool FGCom_GPUAccelerator::accelerateFilterApplication(float* audio_buffer, size_t samples, const std::vector<float>& filter_coeffs, const std::string& operation_id) {
    if (acceleration_mode == GPUAccelerationMode::DISABLED || !gpu_available) {
        return false;
    }
    
    GPUOperationRequest request;
    request.operation_type = GPUOperationType::FILTER_APPLICATION;
    request.operation_id = operation_id.empty() ? "filter_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) : operation_id;
    request.input_data = audio_buffer;
    request.input_size = samples * sizeof(float);
    request.output_data = audio_buffer;
    request.output_size = samples * sizeof(float);
    request.parameters["sample_count"] = static_cast<float>(samples);
    request.parameters["filter_length"] = static_cast<float>(filter_coeffs.size());
    request.priority = 6;
    request.request_time = std::chrono::system_clock::now();
    request.requires_double_precision = false;
    request.estimated_memory_usage = request.input_size + request.output_size + filter_coeffs.size() * sizeof(float);
    
    return executeOperation(request);
}

void FGCom_GPUAccelerator::accelerateAntennaPatternsAsync(std::vector<AntennaGainPoint>& patterns, 
                                                         std::function<void(bool, const std::string&)> callback,
                                                         const std::string& operation_id) {
    if (acceleration_mode == GPUAccelerationMode::DISABLED || !gpu_available) {
        if (callback) callback(false, "GPU acceleration disabled or unavailable");
        return;
    }
    
    GPUOperationRequest request;
    request.operation_type = GPUOperationType::ANTENNA_PATTERN_CALCULATION;
    request.operation_id = operation_id.empty() ? "antenna_pattern_async_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) : operation_id;
    request.input_data = patterns.data();
    request.input_size = patterns.size() * sizeof(AntennaGainPoint);
    request.output_data = patterns.data();
    request.output_size = patterns.size() * sizeof(AntennaGainPoint);
    request.parameters["pattern_count"] = static_cast<float>(patterns.size());
    request.priority = 5;
    request.request_time = std::chrono::system_clock::now();
    request.requires_double_precision = false;
    request.estimated_memory_usage = request.input_size + request.output_size;
    request.callback = callback;
    
    // Add to operation queue
    {
        std::lock_guard<std::mutex> lock(queue_mutex);
        operation_queue.push_back(request);
    }
}

void FGCom_GPUAccelerator::registerClient(const std::string& client_id, const ClientGPUCapability& capability) {
    std::lock_guard<std::mutex> lock(client_mutex);
    client_capabilities[client_id] = capability;
    logInfo("Registered client: " + client_id + " with " + std::to_string(capability.available_gpus.size()) + " GPUs");
}

void FGCom_GPUAccelerator::unregisterClient(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(client_mutex);
    auto it = client_capabilities.find(client_id);
    if (it != client_capabilities.end()) {
        client_capabilities.erase(it);
        logInfo("Unregistered client: " + client_id);
    }
}

std::vector<std::string> FGCom_GPUAccelerator::getAvailableClients() const {
    std::lock_guard<std::mutex> lock(client_mutex);
    std::vector<std::string> available_clients;
    
    for (const auto& pair : client_capabilities) {
        if (pair.second.is_online) {
            available_clients.push_back(pair.first);
        }
    }
    
    return available_clients;
}

bool FGCom_GPUAccelerator::distributeOperation(const GPUOperationRequest& request) {
    if (acceleration_mode != GPUAccelerationMode::HYBRID) {
        return false;
    }
    
    std::string optimal_client = selectOptimalClient(request);
    if (!optimal_client.empty()) {
        return sendOperationToClient(optimal_client, request);
    }
    
    // Fall back to server processing
    return executeOperation(request);
}

std::string FGCom_GPUAccelerator::selectOptimalClient(const GPUOperationRequest& request) {
    std::lock_guard<std::mutex> lock(client_mutex);
    
    std::string best_client;
    float best_score = -1.0f;
    
    for (const auto& pair : client_capabilities) {
        if (!pair.second.is_online) continue;
        
        float score = calculateClientScore(pair.first, request);
        if (score > best_score) {
            best_score = score;
            best_client = pair.first;
        }
    }
    
    return best_client;
}

float FGCom_GPUAccelerator::calculateClientScore(const std::string& client_id, const GPUOperationRequest& request) const {
    auto it = client_capabilities.find(client_id);
    if (it == client_capabilities.end()) {
        return -1.0f;
    }
    
    const ClientGPUCapability& capability = it->second;
    
    // Check if client supports this operation type
    auto op_it = capability.supported_operations.find(request.operation_type);
    if (op_it == capability.supported_operations.end() || !op_it->second) {
        return -1.0f;
    }
    
    // Calculate score based on multiple factors
    float score = 0.0f;
    
    // GPU capability score (0-40 points)
    if (!capability.available_gpus.empty()) {
        const GPUDeviceInfo& gpu = capability.available_gpus[0];
        score += std::min(40.0f, gpu.total_memory_mb / 100.0f); // Memory score
        score += std::min(20.0f, gpu.utilization_percent / 5.0f); // Utilization score
    }
    
    // Network performance score (0-20 points)
    score += std::min(20.0f, capability.network_bandwidth_mbps / 10.0f);
    
    // Processing latency score (0-20 points)
    score += std::max(0.0f, 20.0f - capability.processing_latency_ms / 5.0f);
    
    // Memory availability score (0-20 points)
    if (request.estimated_memory_usage <= capability.max_memory_allocation) {
        score += 20.0f;
    } else {
        score += 20.0f * (capability.max_memory_allocation / request.estimated_memory_usage);
    }
    
    return score;
}

GPUAccelerationStats FGCom_GPUAccelerator::getStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex);
    return stats;
}

void FGCom_GPUAccelerator::resetStats() {
    std::lock_guard<std::mutex> lock(stats_mutex);
    stats = GPUAccelerationStats();
    stats.last_reset = std::chrono::system_clock::now();
}

void FGCom_GPUAccelerator::setAccelerationMode(GPUAccelerationMode mode) {
    std::lock_guard<std::mutex> lock(instance_mutex);
    acceleration_mode = mode;
    
    switch (mode) {
        case GPUAccelerationMode::DISABLED:
            logInfo("GPU acceleration disabled");
            break;
        case GPUAccelerationMode::SERVER_ONLY:
            logInfo("GPU acceleration enabled on server only");
            break;
        case GPUAccelerationMode::CLIENT_ONLY:
            logInfo("GPU acceleration enabled on clients only");
            break;
        case GPUAccelerationMode::HYBRID:
            logInfo("GPU acceleration enabled in hybrid mode");
            break;
    }
}

void FGCom_GPUAccelerator::initializeDefaultConfiguration() {
    // Set default operation priorities
    operation_priorities[GPUOperationType::AUDIO_PROCESSING] = 1; // Highest priority
    operation_priorities[GPUOperationType::FREQUENCY_OFFSET_PROCESSING] = 2;
    operation_priorities[GPUOperationType::FILTER_APPLICATION] = 3;
    operation_priorities[GPUOperationType::ANTENNA_PATTERN_CALCULATION] = 4;
    operation_priorities[GPUOperationType::PROPAGATION_MODELING] = 5;
    operation_priorities[GPUOperationType::BATCH_QSO_CALCULATION] = 6;
    operation_priorities[GPUOperationType::SOLAR_DATA_PROCESSING] = 7;
    operation_priorities[GPUOperationType::LIGHTNING_DATA_PROCESSING] = 8; // Lowest priority
}

void FGCom_GPUAccelerator::startWorkerThreads() {
    if (workers_running) return;
    
    workers_running = true;
    int num_threads = std::min(max_concurrent_operations, static_cast<int>(std::thread::hardware_concurrency()));
    
    for (int i = 0; i < num_threads; i++) {
        worker_threads.emplace_back(&FGCom_GPUAccelerator::workerThreadFunction, this);
    }
    
    logInfo("Started " + std::to_string(num_threads) + " GPU worker threads");
}

void FGCom_GPUAccelerator::stopWorkerThreads() {
    if (!workers_running) return;
    
    workers_running = false;
    
    for (auto& thread : worker_threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    
    worker_threads.clear();
    logInfo("Stopped GPU worker threads");
}

void FGCom_GPUAccelerator::workerThreadFunction() {
    while (workers_running) {
        GPUOperationRequest request;
        bool has_request = false;
        
        // Get next operation from queue
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            if (!operation_queue.empty()) {
                // Find highest priority operation
                auto it = std::min_element(operation_queue.begin(), operation_queue.end(),
                    [this](const GPUOperationRequest& a, const GPUOperationRequest& b) {
                        return operation_priorities[a.operation_type] < operation_priorities[b.operation_type];
                    });
                
                request = *it;
                operation_queue.erase(it);
                has_request = true;
            }
        }
        
        if (has_request) {
            auto start_time = std::chrono::high_resolution_clock::now();
            bool success = executeOperation(request);
            auto end_time = std::chrono::high_resolution_clock::now();
            
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
            float processing_time_ms = duration.count() / 1000.0f;
            
            // Update statistics
            {
                std::lock_guard<std::mutex> lock(stats_mutex);
                stats.total_operations++;
                if (success) {
                    stats.successful_operations++;
                } else {
                    stats.failed_operations++;
                }
                stats.total_processing_time_ms += processing_time_ms;
                stats.average_processing_time_ms = stats.total_processing_time_ms / stats.total_operations;
                
                std::string op_name = "operation_" + std::to_string(static_cast<int>(request.operation_type));
                stats.operation_counts[op_name]++;
                stats.operation_times[op_name] += processing_time_ms;
            }
            
            // Call callback if provided
            if (request.callback) {
                request.callback(success, success ? "" : "Operation failed");
            }
        } else {
            // No work to do, sleep briefly
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
}

bool FGCom_GPUAccelerator::executeOperation(const GPUOperationRequest& request) {
    switch (request.operation_type) {
        case GPUOperationType::ANTENNA_PATTERN_CALCULATION:
            return executeAntennaPatternCalculation(request);
        case GPUOperationType::PROPAGATION_MODELING:
            return executePropagationCalculation(request);
        case GPUOperationType::AUDIO_PROCESSING:
            return executeAudioProcessing(request);
        case GPUOperationType::FREQUENCY_OFFSET_PROCESSING:
            return executeFrequencyOffsetProcessing(request);
        case GPUOperationType::FILTER_APPLICATION:
            return executeFilterApplication(request);
        case GPUOperationType::BATCH_QSO_CALCULATION:
            return executeBatchQSOCalculation(request);
        default:
            logError("Unsupported operation type: " + std::to_string(static_cast<int>(request.operation_type)));
            return false;
    }
}

bool FGCom_GPUAccelerator::executeAntennaPatternCalculation(const GPUOperationRequest& request) {
    // Placeholder for GPU-accelerated antenna pattern calculation
    // In a real implementation, this would use CUDA/OpenCL/Metal kernels
    logInfo("Executing GPU antenna pattern calculation for " + request.operation_id);
    
    // Simulate processing time
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    
    return true;
}

bool FGCom_GPUAccelerator::executePropagationCalculation(const GPUOperationRequest& request) {
    // Placeholder for GPU-accelerated propagation calculation
    logInfo("Executing GPU propagation calculation for " + request.operation_id);
    
    // Simulate processing time
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    
    return true;
}

bool FGCom_GPUAccelerator::executeAudioProcessing(const GPUOperationRequest& request) {
    // Placeholder for GPU-accelerated audio processing
    logInfo("Executing GPU audio processing for " + request.operation_id);
    
    // Simulate processing time
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    
    return true;
}

bool FGCom_GPUAccelerator::executeFrequencyOffsetProcessing(const GPUOperationRequest& request) {
    // Placeholder for GPU-accelerated frequency offset processing
    logInfo("Executing GPU frequency offset processing for " + request.operation_id);
    
    // Simulate processing time
    std::this_thread::sleep_for(std::chrono::milliseconds(8));
    
    return true;
}

bool FGCom_GPUAccelerator::executeFilterApplication(const GPUOperationRequest& request) {
    // Placeholder for GPU-accelerated filter application
    logInfo("Executing GPU filter application for " + request.operation_id);
    
    // Simulate processing time
    std::this_thread::sleep_for(std::chrono::milliseconds(6));
    
    return true;
}

bool FGCom_GPUAccelerator::executeBatchQSOCalculation(const GPUOperationRequest& request) {
    // Placeholder for GPU-accelerated batch QSO calculation
    logInfo("Executing GPU batch QSO calculation for " + request.operation_id);
    
    // Simulate processing time
    std::this_thread::sleep_for(std::chrono::milliseconds(15));
    
    return true;
}

void FGCom_GPUAccelerator::shutdown() {
    stopWorkerThreads();
    cleanup();
    logInfo("GPU accelerator shutdown complete");
}

void FGCom_GPUAccelerator::cleanup() {
    // Clean up allocated memory
    {
        std::lock_guard<std::mutex> lock(memory_mutex);
        allocated_memory.clear();
        total_allocated_memory = 0;
    }
    
    // Clear operation queue
    {
        std::lock_guard<std::mutex> lock(queue_mutex);
        operation_queue.clear();
    }
    
    // Clear client capabilities
    {
        std::lock_guard<std::mutex> lock(client_mutex);
        client_capabilities.clear();
    }
}

void FGCom_GPUAccelerator::logError(const std::string& error) {
    last_error = error;
    if (error_callback) {
        error_callback(error);
    }
    std::cerr << "[GPUAccelerator] ERROR: " << error << std::endl;
}

void FGCom_GPUAccelerator::logInfo(const std::string& info) {
    if (log_callback) {
        log_callback(info);
    }
    std::cout << "[GPUAccelerator] INFO: " << info << std::endl;
}

// FGCom_GPUConfig Implementation
FGCom_GPUConfig::FGCom_GPUConfig() 
    : acceleration_mode(GPUAccelerationMode::DISABLED)
    , enable_cuda(true)
    , enable_opencl(true)
    , enable_metal(true)
    , memory_limit_mb(1024)
    , max_concurrent_operations(4)
{
    setDefaultConfiguration();
}

FGCom_GPUConfig& FGCom_GPUConfig::getInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    if (!instance) {
        instance = std::unique_ptr<FGCom_GPUConfig>(new FGCom_GPUConfig());
    }
    return *instance;
}

void FGCom_GPUConfig::destroyInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    instance.reset();
}

void FGCom_GPUConfig::setAccelerationMode(GPUAccelerationMode mode) {
    std::lock_guard<std::mutex> lock(instance_mutex);
    acceleration_mode = mode;
}

GPUAccelerationMode FGCom_GPUConfig::getAccelerationMode() const {
    std::lock_guard<std::mutex> lock(instance_mutex);
    return acceleration_mode;
}

void FGCom_GPUConfig::setDefaultConfiguration() {
    // Enable all operations by default
    enabled_operations[GPUOperationType::ANTENNA_PATTERN_CALCULATION] = true;
    enabled_operations[GPUOperationType::PROPAGATION_MODELING] = true;
    enabled_operations[GPUOperationType::AUDIO_PROCESSING] = true;
    enabled_operations[GPUOperationType::FREQUENCY_OFFSET_PROCESSING] = true;
    enabled_operations[GPUOperationType::FILTER_APPLICATION] = true;
    enabled_operations[GPUOperationType::BATCH_QSO_CALCULATION] = true;
    enabled_operations[GPUOperationType::SOLAR_DATA_PROCESSING] = true;
    enabled_operations[GPUOperationType::LIGHTNING_DATA_PROCESSING] = true;
    
    // Set default priorities
    operation_priorities[GPUOperationType::AUDIO_PROCESSING] = 1;
    operation_priorities[GPUOperationType::FREQUENCY_OFFSET_PROCESSING] = 2;
    operation_priorities[GPUOperationType::FILTER_APPLICATION] = 3;
    operation_priorities[GPUOperationType::ANTENNA_PATTERN_CALCULATION] = 4;
    operation_priorities[GPUOperationType::PROPAGATION_MODELING] = 5;
    operation_priorities[GPUOperationType::BATCH_QSO_CALCULATION] = 6;
    operation_priorities[GPUOperationType::SOLAR_DATA_PROCESSING] = 7;
    operation_priorities[GPUOperationType::LIGHTNING_DATA_PROCESSING] = 8;
}

bool FGCom_GPUConfig::loadConfigFromFile(const std::string& config_file) {
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
            
            if (current_section == "gpu_acceleration") {
                if (key == "acceleration_mode") {
                    if (value == "disabled") acceleration_mode = GPUAccelerationMode::DISABLED;
                    else if (value == "server_only") acceleration_mode = GPUAccelerationMode::SERVER_ONLY;
                    else if (value == "client_only") acceleration_mode = GPUAccelerationMode::CLIENT_ONLY;
                    else if (value == "hybrid") acceleration_mode = GPUAccelerationMode::HYBRID;
                } else if (key == "enable_cuda") {
                    enable_cuda = (value == "true");
                } else if (key == "enable_opencl") {
                    enable_opencl = (value == "true");
                } else if (key == "enable_metal") {
                    enable_metal = (value == "true");
                } else if (key == "memory_limit_mb") {
                    memory_limit_mb = std::stoul(value);
                } else if (key == "max_concurrent_operations") {
                    max_concurrent_operations = std::stoi(value);
                }
            }
        }
    }
    
    return true;
}

bool FGCom_GPUConfig::saveConfigToFile(const std::string& config_file) const {
    std::ofstream file(config_file);
    if (!file.is_open()) {
        return false;
    }
    
    file << "[gpu_acceleration]" << std::endl;
    file << "acceleration_mode=";
    switch (acceleration_mode) {
        case GPUAccelerationMode::DISABLED: file << "disabled"; break;
        case GPUAccelerationMode::SERVER_ONLY: file << "server_only"; break;
        case GPUAccelerationMode::CLIENT_ONLY: file << "client_only"; break;
        case GPUAccelerationMode::HYBRID: file << "hybrid"; break;
    }
    file << std::endl;
    
    file << "enable_cuda=" << (enable_cuda ? "true" : "false") << std::endl;
    file << "enable_opencl=" << (enable_opencl ? "true" : "false") << std::endl;
    file << "enable_metal=" << (enable_metal ? "true" : "false") << std::endl;
    file << "memory_limit_mb=" << memory_limit_mb << std::endl;
    file << "max_concurrent_operations=" << max_concurrent_operations << std::endl;
    
    return true;
}

// GPUAccelerationUtils Implementation
namespace GPUAccelerationUtils {
    std::vector<GPUDeviceInfo> detectAvailableGPUs() {
        std::vector<GPUDeviceInfo> gpus;
        
        // Placeholder implementation - in reality, this would use platform-specific APIs
        // to detect CUDA, OpenCL, or Metal devices
        
        // Example NVIDIA GPU detection
        GPUDeviceInfo nvidia_gpu;
        nvidia_gpu.device_name = "NVIDIA GeForce RTX 3080";
        nvidia_gpu.vendor = GPUVendor::NVIDIA;
        nvidia_gpu.total_memory_mb = 10240; // 10GB
        nvidia_gpu.free_memory_mb = 8192;
        nvidia_gpu.compute_capability_major = 8;
        nvidia_gpu.compute_capability_minor = 6;
        nvidia_gpu.max_threads_per_block = 1024;
        nvidia_gpu.max_blocks_per_grid = 65535;
        nvidia_gpu.clock_rate_mhz = 1710.0f;
        nvidia_gpu.multiprocessor_count = 68;
        nvidia_gpu.supports_double_precision = true;
        nvidia_gpu.supports_unified_memory = true;
        nvidia_gpu.driver_version = "470.86";
        nvidia_gpu.runtime_version = "11.4";
        nvidia_gpu.is_available = true;
        nvidia_gpu.utilization_percent = 0.0f;
        nvidia_gpu.temperature_celsius = 45.0f;
        nvidia_gpu.power_usage_watts = 150.0f;
        
        gpus.push_back(nvidia_gpu);
        
        return gpus;
    }
    
    GPUVendor detectGPUVendor(const std::string& device_name) {
        std::string lower_name = device_name;
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
        
        if (lower_name.find("nvidia") != std::string::npos || lower_name.find("geforce") != std::string::npos || lower_name.find("quadro") != std::string::npos) {
            return GPUVendor::NVIDIA;
        } else if (lower_name.find("amd") != std::string::npos || lower_name.find("radeon") != std::string::npos) {
            return GPUVendor::AMD;
        } else if (lower_name.find("intel") != std::string::npos || lower_name.find("iris") != std::string::npos) {
            return GPUVendor::INTEL;
        } else if (lower_name.find("apple") != std::string::npos || lower_name.find("m1") != std::string::npos || lower_name.find("m2") != std::string::npos) {
            return GPUVendor::APPLE;
        }
        
        return GPUVendor::UNKNOWN;
    }
    
    bool isNVIDIAGPUAvailable() {
        // Placeholder - would check for CUDA availability
        return true;
    }
    
    bool isAMDGPUAvailable() {
        // Placeholder - would check for OpenCL AMD devices
        return true;
    }
    
    bool isIntelGPUAvailable() {
        // Placeholder - would check for OpenCL Intel devices
        return true;
    }
    
    bool isAppleMetalAvailable() {
        // Placeholder - would check for Metal availability
        return true;
    }
    
    float estimateAntennaPatternProcessingTime(size_t pattern_count, size_t frequency_count) {
        // Simple estimation based on data size
        return static_cast<float>(pattern_count * frequency_count) * 0.001f; // 1ms per 1000 calculations
    }
    
    float estimatePropagationProcessingTime(size_t path_count, size_t frequency_count) {
        // More complex estimation for propagation calculations
        return static_cast<float>(path_count * frequency_count) * 0.002f; // 2ms per 1000 calculations
    }
    
    float estimateAudioProcessingTime(size_t sample_count, size_t channel_count) {
        // Audio processing is typically very fast
        return static_cast<float>(sample_count * channel_count) * 0.0001f; // 0.1ms per 1000 samples
    }
    
    size_t estimateMemoryUsage(GPUOperationType operation_type, const std::map<std::string, float>& parameters) {
        switch (operation_type) {
            case GPUOperationType::ANTENNA_PATTERN_CALCULATION: {
                float pattern_count = parameters.at("pattern_count");
                return static_cast<size_t>(pattern_count * sizeof(AntennaGainPoint) * 2); // Input + output
            }
            case GPUOperationType::PROPAGATION_MODELING: {
                float path_count = parameters.at("path_count");
                return static_cast<size_t>(path_count * sizeof(PropagationPath) * 2); // Input + output
            }
            case GPUOperationType::AUDIO_PROCESSING: {
                float sample_count = parameters.at("sample_count");
                return static_cast<size_t>(sample_count * sizeof(float) * 2); // Input + output
            }
            default:
                return 1024; // Default 1KB
        }
    }
    
    bool shouldUseGPU(GPUOperationType operation_type, const std::map<std::string, float>& parameters) {
        // Simple heuristic to determine if GPU acceleration is beneficial
        size_t estimated_memory = estimateMemoryUsage(operation_type, parameters);
        
        // Use GPU if memory usage is significant (>1MB) or if it's a compute-intensive operation
        return estimated_memory > 1024 * 1024 || 
               operation_type == GPUOperationType::PROPAGATION_MODELING ||
               operation_type == GPUOperationType::BATCH_QSO_CALCULATION;
    }
    
    GPUAccelerationMode selectOptimalMode(const std::vector<GPUDeviceInfo>& server_gpus, 
                                         const std::map<std::string, ClientGPUCapability>& client_capabilities) {
        bool server_has_gpu = !server_gpus.empty();
        bool clients_have_gpus = false;
        
        for (const auto& pair : client_capabilities) {
            if (!pair.second.available_gpus.empty()) {
                clients_have_gpus = true;
                break;
            }
        }
        
        if (server_has_gpu && clients_have_gpus) {
            return GPUAccelerationMode::HYBRID;
        } else if (server_has_gpu) {
            return GPUAccelerationMode::SERVER_ONLY;
        } else if (clients_have_gpus) {
            return GPUAccelerationMode::CLIENT_ONLY;
        } else {
            return GPUAccelerationMode::DISABLED;
        }
    }
    
    std::string selectOptimalClient(const GPUOperationRequest& request, 
                                   const std::map<std::string, ClientGPUCapability>& client_capabilities) {
        std::string best_client;
        float best_score = -1.0f;
        
        for (const auto& pair : client_capabilities) {
            if (!pair.second.is_online) continue;
            
            // Check if client supports this operation
            auto op_it = pair.second.supported_operations.find(request.operation_type);
            if (op_it == pair.second.supported_operations.end() || !op_it->second) {
                continue;
            }
            
            // Calculate score based on GPU capability and network performance
            float score = 0.0f;
            
            if (!pair.second.available_gpus.empty()) {
                const GPUDeviceInfo& gpu = pair.second.available_gpus[0];
                score += gpu.total_memory_mb / 100.0f; // Memory score
                score += (100.0f - gpu.utilization_percent) / 10.0f; // Availability score
            }
            
            score += pair.second.network_bandwidth_mbps / 10.0f; // Network score
            score += std::max(0.0f, 10.0f - pair.second.processing_latency_ms / 10.0f); // Latency score
            
            if (score > best_score) {
                best_score = score;
                best_client = pair.first;
            }
        }
        
        return best_client;
    }
}
