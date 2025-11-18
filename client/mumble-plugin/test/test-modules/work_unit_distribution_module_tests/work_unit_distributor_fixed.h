#ifndef FGCOM_WORK_UNIT_DISTRIBUTOR_FIXED_H
#define FGCOM_WORK_UNIT_DISTRIBUTOR_FIXED_H

#include <vector>
#include <string>
#include <memory>
#include <map>
#include <chrono>
#include <mutex>
#include <atomic>
#include <thread>
#include <queue>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <unordered_set>

// Work unit types for propagation calculations
enum class WorkUnitType {
    PROPAGATION_GRID = 0,        // Grid-based propagation calculation
    ANTENNA_PATTERN = 1,         // Antenna pattern calculation
    FREQUENCY_OFFSET = 2,        // Frequency offset processing
    AUDIO_PROCESSING = 3,        // Audio signal processing
    BATCH_QSO = 4,              // Batch QSO calculation
    SOLAR_EFFECTS = 5,          // Solar effects calculation
    LIGHTNING_EFFECTS = 6       // Lightning effects calculation
};

// Work unit priority levels
enum class WorkUnitPriority {
    CRITICAL = 0,    // Real-time audio processing
    HIGH = 1,        // Propagation calculations
    MEDIUM = 2,      // Antenna patterns
    LOW = 3,         // Background processing
    BATCH = 4        // Batch operations
};

// Work unit status
enum class WorkUnitStatus {
    PENDING = 0,     // Waiting to be assigned
    ASSIGNED = 1,    // Assigned to a client
    PROCESSING = 2,  // Currently being processed
    COMPLETED = 3,   // Successfully completed
    FAILED = 4,      // Processing failed
    TIMEOUT = 5      // Processing timed out
};

// Work unit structure
struct WorkUnit {
    std::string unit_id;
    WorkUnitType type;
    WorkUnitPriority priority;
    WorkUnitStatus status;
    std::vector<double> input_data;
    std::map<std::string, double> parameters;
    size_t data_size_bytes;
    uint32_t max_processing_time_ms;
    std::string assigned_client_id;
    std::chrono::system_clock::time_point created_time;
    std::chrono::system_clock::time_point assigned_time;
    std::chrono::system_clock::time_point completed_time;
    std::vector<double> result_data;
    std::string error_message;
};

// Client work unit capability - copyable version
struct ClientWorkUnitCapability {
    std::string client_id;
    std::vector<WorkUnitType> supported_types;
    std::map<WorkUnitType, int> max_concurrent_units;
    std::map<WorkUnitType, double> processing_speed_multiplier;
    size_t max_memory_mb;
    bool supports_gpu;
    bool supports_double_precision;
    float network_bandwidth_mbps;
    float processing_latency_ms;
    bool is_online;
    std::chrono::system_clock::time_point last_heartbeat;
    
    // Current load - non-atomic for copyability
    int active_units;
    int pending_units;
    size_t memory_usage_mb;
    double cpu_utilization_percent;
    double gpu_utilization_percent;
    
    // Default constructor
    ClientWorkUnitCapability() 
        : active_units(0), pending_units(0), memory_usage_mb(0), 
          cpu_utilization_percent(0.0), gpu_utilization_percent(0.0) {}
    
    // Copy constructor
    ClientWorkUnitCapability(const ClientWorkUnitCapability& other) = default;
    
    // Assignment operator
    ClientWorkUnitCapability& operator=(const ClientWorkUnitCapability& other) = default;
};

// Work unit distribution statistics - copyable version
struct WorkUnitDistributionStats {
    uint64_t total_units_created;
    uint64_t total_units_completed;
    uint64_t total_units_failed;
    uint64_t total_units_timeout;
    double average_processing_time_ms;
    double average_queue_wait_time_ms;
    double distribution_efficiency_percent;
    
    // Per-client statistics
    std::map<std::string, uint64_t> client_units_completed;
    std::map<std::string, uint64_t> client_units_failed;
    std::map<std::string, double> client_average_processing_time_ms;
    
    // Queue statistics
    size_t pending_units_count;
    size_t processing_units_count;
    size_t completed_units_count;
    size_t failed_units_count;
    size_t timeout_units_count;
    
    // Default constructor
    WorkUnitDistributionStats() 
        : total_units_created(0), total_units_completed(0), total_units_failed(0), 
          total_units_timeout(0), average_processing_time_ms(0.0), 
          average_queue_wait_time_ms(0.0), distribution_efficiency_percent(0.0),
          pending_units_count(0), processing_units_count(0), completed_units_count(0),
          failed_units_count(0), timeout_units_count(0) {}
    
    // Copy constructor
    WorkUnitDistributionStats(const WorkUnitDistributionStats& other) = default;
    
    // Assignment operator
    WorkUnitDistributionStats& operator=(const WorkUnitDistributionStats& other) = default;
};

// Atomic statistics for thread-safe operations
struct AtomicWorkUnitStats {
    std::atomic<uint64_t> total_units_created;
    std::atomic<uint64_t> total_units_completed;
    std::atomic<uint64_t> total_units_failed;
    std::atomic<uint64_t> total_units_timeout;
    std::atomic<double> average_processing_time_ms;
    std::atomic<double> average_queue_wait_time_ms;
    std::atomic<double> distribution_efficiency_percent;
    std::atomic<size_t> pending_units_count;
    std::atomic<size_t> processing_units_count;
    std::atomic<size_t> completed_units_count;
    std::atomic<size_t> failed_units_count;
    std::atomic<size_t> timeout_units_count;
    
    AtomicWorkUnitStats() 
        : total_units_created(0), total_units_completed(0), total_units_failed(0), 
          total_units_timeout(0), average_processing_time_ms(0.0), 
          average_queue_wait_time_ms(0.0), distribution_efficiency_percent(0.0),
          pending_units_count(0), processing_units_count(0), completed_units_count(0),
          failed_units_count(0), timeout_units_count(0) {}
    
    // Convert to copyable version
    WorkUnitDistributionStats toCopyable() const {
        WorkUnitDistributionStats stats;
        stats.total_units_created = total_units_created.load();
        stats.total_units_completed = total_units_completed.load();
        stats.total_units_failed = total_units_failed.load();
        stats.total_units_timeout = total_units_timeout.load();
        stats.average_processing_time_ms = average_processing_time_ms.load();
        stats.average_queue_wait_time_ms = average_queue_wait_time_ms.load();
        stats.distribution_efficiency_percent = distribution_efficiency_percent.load();
        stats.pending_units_count = pending_units_count.load();
        stats.processing_units_count = processing_units_count.load();
        stats.completed_units_count = completed_units_count.load();
        stats.failed_units_count = failed_units_count.load();
        stats.timeout_units_count = timeout_units_count.load();
        return stats;
    }
};

// Atomic client capability for thread-safe operations
struct AtomicClientCapability {
    std::string client_id;
    std::vector<WorkUnitType> supported_types;
    std::map<WorkUnitType, int> max_concurrent_units;
    std::map<WorkUnitType, double> processing_speed_multiplier;
    size_t max_memory_mb;
    bool supports_gpu;
    bool supports_double_precision;
    float network_bandwidth_mbps;
    float processing_latency_ms;
    bool is_online;
    std::chrono::system_clock::time_point last_heartbeat;
    
    // Current load - atomic for thread safety
    std::atomic<int> active_units;
    std::atomic<int> pending_units;
    std::atomic<size_t> memory_usage_mb;
    std::atomic<double> cpu_utilization_percent;
    std::atomic<double> gpu_utilization_percent;
    
    AtomicClientCapability() 
        : active_units(0), pending_units(0), memory_usage_mb(0), 
          cpu_utilization_percent(0.0), gpu_utilization_percent(0.0) {}
    
    // Convert to copyable version
    ClientWorkUnitCapability toCopyable() const {
        ClientWorkUnitCapability capability;
        capability.client_id = client_id;
        capability.supported_types = supported_types;
        capability.max_concurrent_units = max_concurrent_units;
        capability.processing_speed_multiplier = processing_speed_multiplier;
        capability.max_memory_mb = max_memory_mb;
        capability.supports_gpu = supports_gpu;
        capability.supports_double_precision = supports_double_precision;
        capability.network_bandwidth_mbps = network_bandwidth_mbps;
        capability.processing_latency_ms = processing_latency_ms;
        capability.is_online = is_online;
        capability.last_heartbeat = last_heartbeat;
        capability.active_units = active_units.load();
        capability.pending_units = pending_units.load();
        capability.memory_usage_mb = memory_usage_mb.load();
        capability.cpu_utilization_percent = cpu_utilization_percent.load();
        capability.gpu_utilization_percent = gpu_utilization_percent.load();
        return capability;
    }
};

#endif // FGCOM_WORK_UNIT_DISTRIBUTOR_FIXED_H
