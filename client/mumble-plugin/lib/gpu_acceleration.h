/*
 * GPU Acceleration API for FGCom-mumble
 * Provides GPU acceleration utilities and interfaces
 */

#ifndef GPU_ACCELERATION_H
#define GPU_ACCELERATION_H

#include <string>
#include <vector>
#include <memory>

namespace FGComGPU {

// GPU acceleration status
enum class GPUAccelerationStatus {
    DISABLED,
    ENABLED,
    ERROR,
    NOT_SUPPORTED
};

// GPU acceleration configuration
struct GPUAccelerationConfig {
    bool enable_gpu_processing;
    bool enable_gpu_memory_optimization;
    bool enable_gpu_parallel_processing;
    int max_gpu_memory_mb;
    int gpu_thread_count;
    
    GPUAccelerationConfig() : enable_gpu_processing(false), 
                              enable_gpu_memory_optimization(false),
                              enable_gpu_parallel_processing(false),
                              max_gpu_memory_mb(1024), gpu_thread_count(4) {}
};

// GPU acceleration manager
class GPUAccelerationManager {
public:
    static GPUAccelerationStatus getAccelerationStatus();
    static bool isGPUSupported();
    static bool initializeGPU();
    static void shutdownGPU();
    static GPUAccelerationConfig getConfiguration();
    static bool setConfiguration(const GPUAccelerationConfig& config);
    static std::string getGPUInfo();
    static bool isGPUAvailable();
};

} // namespace FGComGPU

#endif // GPU_ACCELERATION_H



