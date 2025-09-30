#ifndef FGCOM_WORK_UNIT_DISTRIBUTOR_TESTABLE_H
#define FGCOM_WORK_UNIT_DISTRIBUTOR_TESTABLE_H

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
#include <random>

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

// Work unit structure - completely copyable
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
    
    // Additional fields for testing
    size_t memory_requirement_mb;
    bool requires_gpu;
    bool requires_double_precision;
    int retry_count;
    int max_retries;
    bool success;
    
    // Default constructor
    WorkUnit() 
        : status(WorkUnitStatus::PENDING), data_size_bytes(0), max_processing_time_ms(5000),
          memory_requirement_mb(100), requires_gpu(false), requires_double_precision(false),
          retry_count(0), max_retries(3), success(false) {}
    
    // Copy constructor
    WorkUnit(const WorkUnit& other) = default;
    
    // Assignment operator
    WorkUnit& operator=(const WorkUnit& other) = default;
};

// Client work unit capability - completely copyable
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

// Work unit distribution statistics - completely copyable
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

// Thread-safe statistics manager - handles atomic operations internally
class ThreadSafeStatisticsManager {
private:
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
    
    std::mutex client_stats_mutex;
    std::map<std::string, uint64_t> client_units_completed;
    std::map<std::string, uint64_t> client_units_failed;
    std::map<std::string, double> client_average_processing_time_ms;

public:
    ThreadSafeStatisticsManager() 
        : total_units_created(0), total_units_completed(0), total_units_failed(0), 
          total_units_timeout(0), average_processing_time_ms(0.0), 
          average_queue_wait_time_ms(0.0), distribution_efficiency_percent(0.0),
          pending_units_count(0), processing_units_count(0), completed_units_count(0),
          failed_units_count(0), timeout_units_count(0) {}
    
    // Thread-safe operations
    void recordWorkUnitCreated() { total_units_created++; }
    void recordWorkUnitCompleted() { total_units_completed++; }
    void recordWorkUnitFailed() { total_units_failed++; }
    void recordWorkUnitTimeout() { total_units_timeout++; }
    
    void updateProcessingTime(double time_ms) {
        double current_avg = average_processing_time_ms.load();
        double new_avg = (current_avg + time_ms) / 2.0;
        average_processing_time_ms.store(new_avg);
    }
    
    void updateQueueWaitTime(double time_ms) {
        double current_avg = average_queue_wait_time_ms.load();
        double new_avg = (current_avg + time_ms) / 2.0;
        average_queue_wait_time_ms.store(new_avg);
    }
    
    void updatePendingCount(int delta) { pending_units_count += delta; }
    void updateProcessingCount(int delta) { processing_units_count += delta; }
    void updateCompletedCount(int delta) { completed_units_count += delta; }
    void updateFailedCount(int delta) { failed_units_count += delta; }
    void updateTimeoutCount(int delta) { timeout_units_count += delta; }
    
    void recordClientWorkUnitCompleted(const std::string& client_id) {
        std::lock_guard<std::mutex> lock(client_stats_mutex);
        client_units_completed[client_id]++;
    }
    
    void recordClientWorkUnitFailed(const std::string& client_id) {
        std::lock_guard<std::mutex> lock(client_stats_mutex);
        client_units_failed[client_id]++;
    }
    
    void updateClientProcessingTime(const std::string& client_id, double time_ms) {
        std::lock_guard<std::mutex> lock(client_stats_mutex);
        double current_avg = client_average_processing_time_ms[client_id];
        double new_avg = (current_avg + time_ms) / 2.0;
        client_average_processing_time_ms[client_id] = new_avg;
    }
    
    // Get copyable statistics
    WorkUnitDistributionStats getStatistics() {
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
        
        {
            std::lock_guard<std::mutex> lock(client_stats_mutex);
            stats.client_units_completed = client_units_completed;
            stats.client_units_failed = client_units_failed;
            stats.client_average_processing_time_ms = client_average_processing_time_ms;
        }
        
        return stats;
    }
    
    void resetStatistics() {
        total_units_created.store(0);
        total_units_completed.store(0);
        total_units_failed.store(0);
        total_units_timeout.store(0);
        average_processing_time_ms.store(0.0);
        average_queue_wait_time_ms.store(0.0);
        distribution_efficiency_percent.store(0.0);
        pending_units_count.store(0);
        processing_units_count.store(0);
        completed_units_count.store(0);
        failed_units_count.store(0);
        timeout_units_count.store(0);
        
        {
            std::lock_guard<std::mutex> lock(client_stats_mutex);
            client_units_completed.clear();
            client_units_failed.clear();
            client_average_processing_time_ms.clear();
        }
    }
};

// Thread-safe client capability manager
class ThreadSafeClientManager {
private:
    std::mutex clients_mutex;
    std::map<std::string, ClientWorkUnitCapability> client_capabilities;
    
    // Atomic counters for thread-safe operations
    std::atomic<int> active_units;
    std::atomic<int> pending_units;
    std::atomic<size_t> memory_usage_mb;
    std::atomic<double> cpu_utilization_percent;
    std::atomic<double> gpu_utilization_percent;

public:
    ThreadSafeClientManager() 
        : active_units(0), pending_units(0), memory_usage_mb(0), 
          cpu_utilization_percent(0.0), gpu_utilization_percent(0.0) {}
    
    bool registerClient(const std::string& client_id, const ClientWorkUnitCapability& capability) {
        std::lock_guard<std::mutex> lock(clients_mutex);
        client_capabilities[client_id] = capability;
        return true;
    }
    
    bool unregisterClient(const std::string& client_id) {
        std::lock_guard<std::mutex> lock(clients_mutex);
        return client_capabilities.erase(client_id) > 0;
    }
    
    bool updateClientCapability(const std::string& client_id, const ClientWorkUnitCapability& capability) {
        std::lock_guard<std::mutex> lock(clients_mutex);
        auto it = client_capabilities.find(client_id);
        if (it == client_capabilities.end()) {
            return false;
        }
        it->second = capability;
        return true;
    }
    
    std::vector<std::string> getAvailableClients() {
        std::lock_guard<std::mutex> lock(clients_mutex);
        std::vector<std::string> clients;
        for (const auto& pair : client_capabilities) {
            if (pair.second.is_online) {
                clients.push_back(pair.first);
            }
        }
        return clients;
    }
    
    ClientWorkUnitCapability getClientCapability(const std::string& client_id) {
        std::lock_guard<std::mutex> lock(clients_mutex);
        auto it = client_capabilities.find(client_id);
        if (it == client_capabilities.end()) {
            return ClientWorkUnitCapability();
        }
        return it->second;
    }
    
    size_t getClientCount() {
        std::lock_guard<std::mutex> lock(clients_mutex);
        return client_capabilities.size();
    }
    
    // Thread-safe load updates
    void updateActiveUnits(int delta) { active_units += delta; }
    void updatePendingUnits(int delta) { pending_units += delta; }
    void updateMemoryUsage(size_t delta) { memory_usage_mb += delta; }
    void updateCpuUtilization(double delta) { 
        double current = cpu_utilization_percent.load();
        cpu_utilization_percent.store(current + delta);
    }
    void updateGpuUtilization(double delta) { 
        double current = gpu_utilization_percent.load();
        gpu_utilization_percent.store(current + delta);
    }
    
    // Get current load
    int getActiveUnits() const { return active_units.load(); }
    int getPendingUnits() const { return pending_units.load(); }
    size_t getMemoryUsage() const { return memory_usage_mb.load(); }
    double getCpuUtilization() const { return cpu_utilization_percent.load(); }
    double getGpuUtilization() const { return gpu_utilization_percent.load(); }
};

#endif // FGCOM_WORK_UNIT_DISTRIBUTOR_TESTABLE_H
