#ifndef FGCOM_GPU_INTERFACE_H
#define FGCOM_GPU_INTERFACE_H

#include <string>
#include <vector>
#include <memory>
#include <map>
#include <functional>

// Forward declarations
struct AntennaGainPoint;
struct PropagationPath;
struct QSOParameters;

// Abstract interface for GPU acceleration
class IGPUAccelerator {
public:
    virtual ~IGPUAccelerator() = default;
    
    // Initialization
    virtual bool initializeGPU() = 0;
    virtual bool isGPUAvailable() const = 0;
    
    // Core acceleration methods
    virtual bool accelerateAntennaPatterns(std::vector<AntennaGainPoint>& patterns, const std::string& operation_id = "") = 0;
    virtual bool acceleratePropagationCalculations(const std::vector<PropagationPath>& paths, const std::string& operation_id = "") = 0;
    virtual bool accelerateAudioProcessing(float* audio_buffer, size_t samples, const std::string& operation_id = "") = 0;
    virtual bool accelerateFrequencyOffsetProcessing(float* audio_buffer, size_t samples, float offset_hz, const std::string& operation_id = "") = 0;
    virtual bool accelerateFilterApplication(float* audio_buffer, size_t samples, const std::vector<float>& filter_coeffs, const std::string& operation_id = "") = 0;
    virtual bool accelerateBatchQSOCalculation(const std::vector<QSOParameters>& qso_params, const std::string& operation_id = "") = 0;
    
    // Asynchronous operations
    virtual void accelerateAntennaPatternsAsync(std::vector<AntennaGainPoint>& patterns, 
                                               std::function<void(bool, const std::string&)> callback,
                                               const std::string& operation_id = "") = 0;
    virtual void acceleratePropagationCalculationsAsync(const std::vector<PropagationPath>& paths,
                                                       std::function<void(bool, const std::string&)> callback,
                                                       const std::string& operation_id = "") = 0;
    virtual void accelerateAudioProcessingAsync(float* audio_buffer, size_t samples,
                                               std::function<void(bool, const std::string&)> callback,
                                               const std::string& operation_id = "") = 0;
    
    // Memory management
    virtual void* allocateGPUMemory(size_t size_bytes, const std::string& allocation_id = "") = 0;
    virtual bool freeGPUMemory(const std::string& allocation_id) = 0;
    virtual bool freeGPUMemory(void* device_ptr) = 0;
    virtual size_t getTotalAllocatedMemory() const = 0;
    virtual size_t getFreeMemory() const = 0;
    virtual void optimizeMemoryUsage() = 0;
    virtual void clearMemoryCache() = 0;
    
    // Performance monitoring
    virtual void updateStats() = 0;
    virtual float getAverageProcessingTime(int operation_type) const = 0;
    virtual int getOperationCount(int operation_type) const = 0;
    virtual float getSuccessRate() const = 0;
    
    // Error handling
    virtual std::string getLastError() const = 0;
    virtual void setErrorCallback(std::function<void(const std::string&)> callback) = 0;
    virtual void setLogCallback(std::function<void(const std::string&)> callback) = 0;
    
    // Cleanup
    virtual void shutdown() = 0;
    virtual void cleanup() = 0;
};

// Abstract interface for GPU configuration
class IGPUConfig {
public:
    virtual ~IGPUConfig() = default;
    
    virtual void setAccelerationMode(int mode) = 0;
    virtual int getAccelerationMode() const = 0;
    virtual void setCUDAEnabled(bool enabled) = 0;
    virtual bool isCUDAEnabled() const = 0;
    virtual void setOpenCLEnabled(bool enabled) = 0;
    virtual bool isOpenCLEnabled() const = 0;
    virtual void setMetalEnabled(bool enabled) = 0;
    virtual bool isMetalEnabled() const = 0;
    
    virtual void setOperationEnabled(int operation_type, bool enabled) = 0;
    virtual bool isOperationEnabled(int operation_type) const = 0;
    virtual void setOperationPriority(int operation_type, int priority) = 0;
    virtual int getOperationPriority(int operation_type) const = 0;
    
    virtual void setMemoryLimit(size_t limit_mb) = 0;
    virtual size_t getMemoryLimit() const = 0;
    virtual void setMaxConcurrentOperations(int max_ops) = 0;
    virtual int getMaxConcurrentOperations() const = 0;
    
    virtual bool loadConfigFromFile(const std::string& config_file) = 0;
    virtual bool saveConfigToFile(const std::string& config_file) const = 0;
    virtual void setDefaultConfiguration() = 0;
    
    virtual bool validateConfiguration() const = 0;
    virtual std::vector<std::string> getConfigurationErrors() const = 0;
};

// Abstract interface for GPU device management
class IGPUDeviceManager {
public:
    virtual ~IGPUDeviceManager() = default;
    
    virtual std::vector<std::string> getAvailableGPUs() const = 0;
    virtual std::string getPrimaryGPU() const = 0;
    virtual bool selectPrimaryGPU(int device_index) = 0;
    virtual void updateGPUStatus() = 0;
    virtual float getGPUUtilization() const = 0;
    virtual float getMemoryUtilization() const = 0;
};

// Factory interface for creating GPU components
class IGPUComponentFactory {
public:
    virtual ~IGPUComponentFactory() = default;
    
    virtual std::unique_ptr<IGPUAccelerator> createGPUAccelerator() = 0;
    virtual std::unique_ptr<IGPUConfig> createGPUConfig() = 0;
    virtual std::unique_ptr<IGPUDeviceManager> createGPUDeviceManager() = 0;
};

// Utility functions for GPU acceleration
namespace GPUAccelerationUtils {
    // GPU device detection
    std::vector<std::string> detectAvailableGPUs();
    int detectGPUVendor(const std::string& device_name);
    bool isNVIDIAGPUAvailable();
    bool isAMDGPUAvailable();
    bool isIntelGPUAvailable();
    bool isAppleMetalAvailable();
    
    // Performance estimation
    float estimateAntennaPatternProcessingTime(size_t pattern_count, size_t frequency_count);
    float estimatePropagationProcessingTime(size_t path_count, size_t frequency_count);
    float estimateAudioProcessingTime(size_t sample_count, size_t channel_count);
    size_t estimateMemoryUsage(int operation_type, const std::map<std::string, float>& parameters);
    
    // Memory management utilities
    size_t alignMemorySize(size_t size, size_t alignment = 256);
    bool isMemoryAligned(void* ptr, size_t alignment = 256);
    void* alignMemoryPointer(void* ptr, size_t alignment = 256);
    
    // Operation optimization
    bool shouldUseGPU(int operation_type, const std::map<std::string, float>& parameters);
    int selectOptimalMode(const std::vector<std::string>& server_gpus, 
                         const std::map<std::string, std::string>& client_capabilities);
    std::string selectOptimalClient(const std::string& request, 
                                   const std::map<std::string, std::string>& client_capabilities);
    
    // Error handling utilities
    std::string getGPUErrorString(int error_code, int vendor);
    bool isRecoverableError(int error_code, int vendor);
    void logGPUError(const std::string& operation, int error_code, int vendor);
}

#endif // FGCOM_GPU_INTERFACE_H



