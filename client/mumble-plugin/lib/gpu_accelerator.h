#ifndef FGCOM_GPU_ACCELERATOR_H
#define FGCOM_GPU_ACCELERATOR_H

#include <vector>
#include <string>
#include <memory>
#include <map>
#include <chrono>
#include <mutex>
#include <functional>
#include <atomic>
#include <thread>
#include <queue>
#include <condition_variable>
#include <cstdint>
#include <cassert>
#include <stdexcept>

// Forward declarations
#include "gpu_types.h"

// GPU acceleration configuration
enum class GPUAccelerationMode {
    DISABLED = 0,    // No GPU acceleration
    SERVER_ONLY = 1, // GPU acceleration on server only
    CLIENT_ONLY = 2, // GPU acceleration on clients only
    HYBRID = 3       // Distribute between server and clients
};

// GPU vendor types
enum class GPUVendor {
    UNKNOWN = 0,
    NVIDIA = 1,
    AMD = 2,
    INTEL = 3,
    APPLE = 4
};

// GPU device information
struct GPUDeviceInfo {
    std::string device_name;
    GPUVendor vendor;
    size_t total_memory_mb;
    size_t free_memory_mb;
    int compute_capability_major;
    int compute_capability_minor;
    int max_threads_per_block;
    int max_blocks_per_grid;
    float clock_rate_mhz;
    int multiprocessor_count;
    bool supports_double_precision;
    bool supports_unified_memory;
    std::string driver_version;
    std::string runtime_version;
    bool is_available;
    float utilization_percent;
    float temperature_celsius;
    float power_usage_watts;
};

// GPU acceleration statistics
struct GPUAccelerationStats {
    int total_operations;
    int successful_operations;
    int failed_operations;
    float average_processing_time_ms;
    float total_processing_time_ms;
    size_t total_memory_allocated;
    size_t peak_memory_usage;
    float gpu_utilization_percent;
    float memory_utilization_percent;
    std::chrono::system_clock::time_point last_reset;
    std::map<std::string, int> operation_counts;
    std::map<std::string, float> operation_times;
    int memory_allocation_failures;
    int kernel_launch_failures;
    int synchronization_failures;
};

// GPU memory management
struct GPUMemoryBlock {
    void* device_ptr;
    size_t size_bytes;
    std::string allocation_id;
    std::chrono::system_clock::time_point allocation_time;
    bool is_locked;
    std::string owner_operation;
};

// GPU operation types
enum class GPUOperationType {
    ANTENNA_PATTERN_CALCULATION = 0,
    PROPAGATION_MODELING = 1,
    AUDIO_PROCESSING = 2,
    FREQUENCY_OFFSET_PROCESSING = 3,
    FILTER_APPLICATION = 4,
    BATCH_QSO_CALCULATION = 5,
    SOLAR_DATA_PROCESSING = 6,
    LIGHTNING_DATA_PROCESSING = 7
};

// GPU operation request
struct GPUOperationRequest {
    GPUOperationType operation_type;
    std::string operation_id;
    void* input_data;
    size_t input_size;
    void* output_data;
    size_t output_size;
    std::map<std::string, float> parameters;
    std::function<void(bool, const std::string&)> callback;
    int priority;
    std::chrono::system_clock::time_point request_time;
    bool requires_double_precision;
    size_t estimated_memory_usage;
};

// Client GPU capability information
struct ClientGPUCapability {
    std::string client_id;
    std::vector<GPUDeviceInfo> available_gpus;
    GPUAccelerationMode preferred_mode;
    bool supports_cuda;
    bool supports_opencl;
    bool supports_metal; // Apple Metal
    int max_concurrent_operations;
    size_t max_memory_allocation;
    float network_bandwidth_mbps;
    float processing_latency_ms;
    bool is_online;
    std::chrono::system_clock::time_point last_heartbeat;
    std::map<GPUOperationType, bool> supported_operations;
};

// Main GPU accelerator class
class FGCom_GPUAccelerator {
private:
    static std::unique_ptr<FGCom_GPUAccelerator> instance;
    static std::mutex instance_mutex;
    
    // Configuration
    GPUAccelerationMode acceleration_mode;
    bool gpu_available;
    std::vector<GPUDeviceInfo> available_gpus;
    GPUVendor primary_gpu_vendor;
    size_t gpu_memory_limit_mb;
    int max_concurrent_operations;
    
    // Statistics and monitoring
    GPUAccelerationStats stats;
    std::mutex stats_mutex;
    
    // Memory management
    std::map<std::string, GPUMemoryBlock> allocated_memory;
    std::mutex memory_mutex;
    size_t total_allocated_memory;
    size_t peak_memory_usage;
    
    // Operation queue and management
    std::vector<GPUOperationRequest> operation_queue;
    std::mutex queue_mutex;
    std::vector<std::thread> worker_threads;
    bool workers_running;
    
    // Client management (for hybrid mode)
    std::map<std::string, ClientGPUCapability> client_capabilities;
    mutable std::mutex client_mutex;
    
    // Private constructor for singleton
    FGCom_GPUAccelerator();
    
public:
    // Singleton access
    static FGCom_GPUAccelerator& getInstance();
    static void destroyInstance();
    
    // Initialization and configuration
    bool initializeGPU();
    bool initializeCUDA();
    bool initializeOpenCL();
    bool initializeMetal(); // Apple Metal
    void setAccelerationMode(GPUAccelerationMode mode);
    GPUAccelerationMode getAccelerationMode() const;
    bool isGPUAvailable() const;
    
    // GPU device management
    std::vector<GPUDeviceInfo> getAvailableGPUs() const;
    GPUDeviceInfo getPrimaryGPU() const;
    bool selectPrimaryGPU(int device_index);
    void updateGPUStatus();
    float getGPUUtilization() const;
    float getMemoryUtilization() const;
    
    // Core acceleration methods
    bool accelerateAntennaPatterns(std::vector<AntennaGainPoint>& patterns, const std::string& operation_id = "");
    bool acceleratePropagationCalculations(const std::vector<PropagationPath>& paths, const std::string& operation_id = "");
    bool accelerateAudioProcessing(float* audio_buffer, size_t samples, const std::string& operation_id = "");
    bool accelerateFrequencyOffsetProcessing(float* audio_buffer, size_t samples, float offset_hz, const std::string& operation_id = "");
    bool accelerateFilterApplication(float* audio_buffer, size_t samples, const std::vector<float>& filter_coeffs, const std::string& operation_id = "");
    bool accelerateBatchQSOCalculation(const std::vector<QSOParameters>& qso_params, const std::string& operation_id = "");
    
    // Asynchronous operations
    void accelerateAntennaPatternsAsync(std::vector<AntennaGainPoint>& patterns, 
                                       const std::function<void(bool, const std::string&)>& callback,
                                       const std::string& operation_id = "");
    void acceleratePropagationCalculationsAsync(const std::vector<PropagationPath>& paths,
                                               std::function<void(bool, const std::string&)> callback,
                                               const std::string& operation_id = "");
    void accelerateAudioProcessingAsync(float* audio_buffer, size_t samples,
                                       std::function<void(bool, const std::string&)> callback,
                                       const std::string& operation_id = "");
    
    // Memory management
    void* allocateGPUMemory(size_t size_bytes, const std::string& allocation_id = "");
    bool freeGPUMemory(const std::string& allocation_id);
    bool freeGPUMemory(void* device_ptr);
    size_t getTotalAllocatedMemory() const;
    size_t getFreeMemory() const;
    void optimizeMemoryUsage();
    void clearMemoryCache();
    
    // Client management (for hybrid mode)
    void registerClient(const std::string& client_id, const ClientGPUCapability& capability);
    void unregisterClient(const std::string& client_id);
    void updateClientCapability(const std::string& client_id, const ClientGPUCapability& capability);
    std::vector<std::string> getAvailableClients() const;
    ClientGPUCapability getClientCapability(const std::string& client_id) const;
    bool isClientAvailable(const std::string& client_id) const;
    
    // Operation distribution (hybrid mode)
    bool distributeOperation(const GPUOperationRequest& request);
    std::string selectOptimalClient(const GPUOperationRequest& request);
    bool sendOperationToClient(const std::string& client_id, const GPUOperationRequest& request);
    void handleClientResponse(const std::string& client_id, const std::string& operation_id, bool success, const std::string& error_message);
    
    // Performance monitoring
    GPUAccelerationStats getStats() const;
    void resetStats();
    void updateStats();
    float getAverageProcessingTime(GPUOperationType operation_type) const;
    int getOperationCount(GPUOperationType operation_type) const;
    float getSuccessRate() const;
    
    // Configuration management
    void setGPUMemoryLimit(size_t limit_mb);
    size_t getGPUMemoryLimit() const;
    void setMaxConcurrentOperations(int max_ops);
    int getMaxConcurrentOperations() const;
    void setOperationPriority(GPUOperationType operation_type, int priority);
    int getOperationPriority(GPUOperationType operation_type) const;
    
    // Error handling and logging
    std::string getLastError() const;
    void setErrorCallback(std::function<void(const std::string&)> callback);
    void setLogCallback(std::function<void(const std::string&)> callback);
    
    // Utility functions
    bool supportsOperation(GPUOperationType operation_type) const;
    size_t estimateMemoryUsage(GPUOperationType operation_type, const std::map<std::string, float>& parameters) const;
    float estimateProcessingTime(GPUOperationType operation_type, const std::map<std::string, float>& parameters) const;
    bool isOperationSupported(GPUOperationType operation_type) const;
    
    // Cleanup and shutdown
    void shutdown();
    void cleanup();
    
private:
    // Internal helper methods
    void initializeDefaultConfiguration();
    void startWorkerThreads();
    void stopWorkerThreads();
    void workerThreadFunction();
    void processOperationQueue();
    bool executeOperation(const GPUOperationRequest& request);
    
    // GPU-specific implementations
    bool executeAntennaPatternCalculation(const GPUOperationRequest& request);
    bool executePropagationCalculation(const GPUOperationRequest& request);
    bool executeAudioProcessing(const GPUOperationRequest& request);
    bool executeFrequencyOffsetProcessing(const GPUOperationRequest& request);
    bool executeFilterApplication(const GPUOperationRequest& request);
    bool executeBatchQSOCalculation(const GPUOperationRequest& request);
    
    // Memory management helpers
    bool allocateMemoryBlock(size_t size_bytes, const std::string& allocation_id);
    void deallocateMemoryBlock(const std::string& allocation_id);
    void updateMemoryStatistics();
    bool checkMemoryAvailability(size_t required_size) const;
    
    // Client communication helpers
    void sendHeartbeatToClients();
    void updateClientStatus();
    bool validateClientCapability(const ClientGPUCapability& capability) const;
    float calculateClientScore(const std::string& client_id, const GPUOperationRequest& request) const;
    
    // Error handling
    void logError(const std::string& error);
    void logInfo(const std::string& info);
    
    // Internal state
    std::string last_error;
    std::function<void(const std::string&)> error_callback;
    std::function<void(const std::string&)> log_callback;
    std::map<GPUOperationType, int> operation_priorities;
    bool is_initialized;
    std::chrono::system_clock::time_point last_client_update;
};

// GPU acceleration configuration management
class FGCom_GPUConfig {
private:
    static std::unique_ptr<FGCom_GPUConfig> instance;
    static std::mutex instance_mutex;
    
    GPUAccelerationMode acceleration_mode;
    bool enable_cuda;
    bool enable_opencl;
    bool enable_metal;
    size_t memory_limit_mb;
    int max_concurrent_operations;
    std::map<GPUOperationType, bool> enabled_operations;
    std::map<GPUOperationType, int> operation_priorities;
    
    // Private constructor for singleton
    FGCom_GPUConfig();
    
public:
    // Singleton access
    static FGCom_GPUConfig& getInstance();
    static void destroyInstance();
    
    // Configuration management
    void setAccelerationMode(GPUAccelerationMode mode);
    GPUAccelerationMode getAccelerationMode() const;
    void setCUDAEnabled(bool enabled);
    bool isCUDAEnabled() const;
    void setOpenCLEnabled(bool enabled);
    bool isOpenCLEnabled() const;
    void setMetalEnabled(bool enabled);
    bool isMetalEnabled() const;
    
    // Operation configuration
    void setOperationEnabled(GPUOperationType operation_type, bool enabled);
    bool isOperationEnabled(GPUOperationType operation_type) const;
    void setOperationPriority(GPUOperationType operation_type, int priority);
    int getOperationPriority(GPUOperationType operation_type) const;
    
    // Memory and performance configuration
    void setMemoryLimit(size_t limit_mb);
    size_t getMemoryLimit() const;
    void setMaxConcurrentOperations(int max_ops);
    int getMaxConcurrentOperations() const;
    
    // Configuration persistence
    bool loadConfigFromFile(const std::string& config_file);
    bool saveConfigToFile(const std::string& config_file) const;
    void setDefaultConfiguration();
    
    // Validation
    bool validateConfiguration() const;
    std::vector<std::string> getConfigurationErrors() const;
};

// Utility functions for GPU acceleration
namespace GPUAccelerationUtils {
    // GPU device detection
    std::vector<GPUDeviceInfo> detectAvailableGPUs();
    GPUVendor detectGPUVendor(const std::string& device_name);
    bool isNVIDIAGPUAvailable();
    bool isAMDGPUAvailable();
    bool isIntelGPUAvailable();
    bool isAppleMetalAvailable();
    
    // Performance estimation
    float estimateAntennaPatternProcessingTime(size_t pattern_count, size_t frequency_count);
    float estimatePropagationProcessingTime(size_t path_count, size_t frequency_count);
    float estimateAudioProcessingTime(size_t sample_count, size_t channel_count);
    size_t estimateMemoryUsage(GPUOperationType operation_type, const std::map<std::string, float>& parameters);
    
    // Memory management utilities
    size_t alignMemorySize(size_t size, size_t alignment = 256);
    bool isMemoryAligned(void* ptr, size_t alignment = 256);
    void* alignMemoryPointer(void* ptr, size_t alignment = 256);
    
    // Operation optimization
    bool shouldUseGPU(GPUOperationType operation_type, const std::map<std::string, float>& parameters);
    GPUAccelerationMode selectOptimalMode(const std::vector<GPUDeviceInfo>& server_gpus, 
                                         const std::map<std::string, ClientGPUCapability>& client_capabilities);
    std::string selectOptimalClient(const GPUOperationRequest& request, 
                                   const std::map<std::string, ClientGPUCapability>& client_capabilities);
    
    // Network communication utilities
    std::string serializeOperationRequest(const GPUOperationRequest& request);
    GPUOperationRequest deserializeOperationRequest(const std::string& serialized_data);
    std::string serializeOperationResponse(bool success, const std::string& error_message, void* result_data, size_t result_size);
    
    // Error handling utilities
    std::string getGPUErrorString(int error_code, GPUVendor vendor);
    bool isRecoverableError(int error_code, GPUVendor vendor);
    void logGPUError(const std::string& operation, int error_code, GPUVendor vendor);
}

#endif // FGCOM_GPU_ACCELERATOR_H
