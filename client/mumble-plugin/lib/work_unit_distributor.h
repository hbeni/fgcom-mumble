#ifndef FGCOM_WORK_UNIT_DISTRIBUTOR_H
#define FGCOM_WORK_UNIT_DISTRIBUTOR_H

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

// Forward declarations
#include "gpu_types.h"
#include "work_unit/work_unit_sharing.h"

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
    
    // Input data
    std::vector<double> input_data;
    std::map<std::string, double> parameters;
    size_t data_size_bytes;
    
    // Processing requirements
    std::string required_client_id;  // Specific client requirement
    std::vector<std::string> compatible_clients;  // Compatible clients
    int max_processing_time_ms;
    size_t memory_requirement_mb;
    bool requires_gpu;
    bool requires_double_precision;
    
    // Assignment and timing
    std::string assigned_client_id;
    std::chrono::system_clock::time_point created_time;
    std::chrono::system_clock::time_point assigned_time;
    std::chrono::system_clock::time_point started_time;
    std::chrono::system_clock::time_point completed_time;
    
    // Results
    std::vector<double> result_data;
    size_t result_size_bytes;
    std::string error_message;
    bool success;
    
    // Retry logic
    int retry_count;
    int max_retries;
    std::chrono::system_clock::time_point next_retry_time;
};

// Client work unit capability
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
    
    // Current load
    std::atomic<int> active_units;
    std::atomic<int> pending_units;
    std::atomic<size_t> memory_usage_mb;
    std::atomic<double> cpu_utilization_percent;
    std::atomic<double> gpu_utilization_percent;
};

// Work unit distribution statistics
struct WorkUnitDistributionStats {
    std::atomic<uint64_t> total_units_created;
    std::atomic<uint64_t> total_units_completed;
    std::atomic<uint64_t> total_units_failed;
    std::atomic<uint64_t> total_units_timeout;
    std::atomic<double> average_processing_time_ms;
    std::atomic<double> average_queue_wait_time_ms;
    std::atomic<double> distribution_efficiency_percent;
    
    // Per-client statistics
    std::map<std::string, uint64_t> client_units_completed;
    std::map<std::string, uint64_t> client_units_failed;
    std::map<std::string, double> client_average_processing_time_ms;
    
    // Queue statistics
    std::atomic<size_t> pending_units_count;
    std::atomic<size_t> processing_units_count;
    std::atomic<size_t> completed_units_count;
    std::atomic<size_t> failed_units_count;
};

// Work unit manager - handles work unit lifecycle
class WorkUnitManager {
private:
    std::map<std::string, WorkUnit> work_units;
    std::mutex units_mutex;
    
public:
    bool createWorkUnit(const WorkUnit& unit);
    bool updateWorkUnitStatus(const std::string& unit_id, WorkUnitStatus status);
    WorkUnit getWorkUnit(const std::string& unit_id);
    bool removeWorkUnit(const std::string& unit_id);
    std::vector<std::string> getWorkUnitsByStatus(WorkUnitStatus status);
};

// Client manager - handles client capabilities and registration
class ClientManager {
private:
    std::map<std::string, ClientWorkUnitCapability> client_capabilities;
    std::mutex clients_mutex;
    
public:
    bool registerClient(const std::string& client_id, const ClientWorkUnitCapability& capability);
    bool unregisterClient(const std::string& client_id);
    bool updateClientCapability(const std::string& client_id, const ClientWorkUnitCapability& capability);
    ClientWorkUnitCapability getClientCapability(const std::string& client_id);
    std::vector<std::string> getAvailableClients();
};

// Queue manager - handles queue operations
class QueueManager {
private:
    std::queue<std::string> pending_units_queue;
    std::map<std::string, std::vector<std::string>> client_assigned_units;
    std::mutex queue_mutex;
    std::condition_variable queue_condition;
    
public:
    bool enqueueWorkUnit(const std::string& unit_id);
    std::string dequeueWorkUnit();
    bool assignWorkUnitToClient(const std::string& unit_id, const std::string& client_id);
    std::vector<std::string> getClientAssignedUnits(const std::string& client_id);
    size_t getQueueSize();
};

// Statistics collector - handles performance metrics
class StatisticsCollector {
private:
    WorkUnitDistributionStats stats;
    std::mutex stats_mutex;
    
public:
    void recordWorkUnitCreated();
    void recordWorkUnitCompleted();
    void recordWorkUnitFailed();
    void recordWorkUnitTimeout();
    void updateProcessingTime(double time_ms);
    void updateQueueWaitTime(double time_ms);
    const WorkUnitDistributionStats& getStatistics();
    void resetStatistics();
};

// Thread manager - handles threading and synchronization
class ThreadManager {
private:
    std::vector<std::thread> worker_threads;
    std::atomic<bool> workers_running;
    std::mutex thread_mutex;
    
public:
    bool startWorkers(int num_threads);
    void stopWorkers();
    bool areWorkersRunning();
    void setWorkerFunction(std::function<void()> worker_func);
};

// Main work unit distributor class - coordinates all components
class FGCom_WorkUnitDistributor {
public:
    // Constructor and destructor
    FGCom_WorkUnitDistributor();
    ~FGCom_WorkUnitDistributor();
    
private:
    static std::unique_ptr<FGCom_WorkUnitDistributor> instance;
    static std::mutex instance_mutex;
    
    // Component managers
    std::unique_ptr<WorkUnitManager> work_unit_manager;
    std::unique_ptr<ClientManager> client_manager;
    std::unique_ptr<QueueManager> queue_manager;
    std::unique_ptr<StatisticsCollector> statistics_collector;
    std::unique_ptr<ThreadManager> thread_manager;
    
    // Work unit sharing manager (modular sharing interface)
    FGCom_WorkUnitSharingManager* sharing_manager;
    
    // Internal data structures (for direct access in implementation)
    std::map<std::string, WorkUnit> work_units;
    std::mutex units_mutex;
    std::map<std::string, ClientWorkUnitCapability> client_capabilities;
    std::mutex clients_mutex;
    std::queue<std::string> pending_units_queue;
    std::map<std::string, std::vector<std::string>> client_assigned_units;
    std::mutex queue_mutex;
    std::condition_variable queue_condition;
    WorkUnitDistributionStats stats;
    std::vector<std::thread> worker_threads;
    std::atomic<bool> workers_running;
    
    // Configuration
    std::atomic<bool> distribution_enabled;
    int max_concurrent_units;
    int max_queue_size;
    int unit_timeout_ms;
    bool enable_retry;
    int max_retries;
    int retry_delay_ms;
    
    // Internal methods
    void workerThreadFunction();
    std::string selectOptimalClient(const WorkUnit& unit);
    double calculateClientScore(const std::string& client_id, const WorkUnit& unit);
    bool assignWorkUnit(const std::string& unit_id, const std::string& client_id);
    void processCompletedWorkUnit(const std::string& unit_id, bool success, const std::string& error_message = "");
    void handleWorkUnitTimeout(const std::string& unit_id);
    void retryFailedWorkUnit(const std::string& unit_id);
    void cleanupCompletedUnits();
    void checkTimeouts();
    
    // Work unit sharing (modular)
    WorkUnitSharingResult shareWorkUnitWithClient(const std::string& unit_id, const std::string& client_id);
    
public:
    // Singleton access
    static FGCom_WorkUnitDistributor& getInstance();
    static void destroyInstance();
    
    // Initialization and configuration
    bool initialize();
    void shutdown();
    void setConfiguration(const std::map<std::string, std::string>& config);
    
    // Work unit sharing configuration
    bool setSharingStrategy(const std::string& strategy_name);
    std::string getSharingStrategy() const;
    std::vector<std::string> getAvailableSharingStrategies() const;
    WorkUnitSharingStats getSharingStatistics() const;
    
    // Work unit management
    std::string createWorkUnit(WorkUnitType type, const std::vector<double>& input_data, 
                              const std::map<std::string, double>& parameters = {});
    bool cancelWorkUnit(const std::string& unit_id);
    WorkUnitStatus getWorkUnitStatus(const std::string& unit_id);
    std::vector<double> getWorkUnitResult(const std::string& unit_id);
    std::string getWorkUnitError(const std::string& unit_id);
    
    // Client management
    bool registerClient(const std::string& client_id, const ClientWorkUnitCapability& capability);
    bool unregisterClient(const std::string& client_id);
    bool updateClientCapability(const std::string& client_id, const ClientWorkUnitCapability& capability);
    std::vector<std::string> getAvailableClients();
    const ClientWorkUnitCapability& getClientCapability(const std::string& client_id);
    
    // Work unit distribution
    bool distributeWorkUnit(const std::string& unit_id);
    bool processWorkUnitResult(const std::string& unit_id, const std::vector<double>& result_data, 
                              bool success, const std::string& error_message = "");
    
    // Queue management
    size_t getPendingUnitsCount();
    size_t getProcessingUnitsCount();
    size_t getCompletedUnitsCount();
    size_t getFailedUnitsCount();
    std::vector<std::string> getPendingUnits();
    std::vector<std::string> getProcessingUnits();
    std::vector<std::string> getCompletedUnits();
    std::vector<std::string> getFailedUnits();
    
    // Statistics and monitoring
    const WorkUnitDistributionStats& getStatistics();
    void resetStatistics();
    std::map<std::string, double> getClientPerformanceMetrics();
    std::map<WorkUnitType, uint64_t> getWorkUnitTypeStatistics();
    
    // Utility methods
    void cleanup();
    void forceCleanup();
    bool isHealthy();
    std::string getStatusReport();
};

// Work unit factory for creating specific types of work units
class FGCom_WorkUnitFactory {
public:
    static std::string createPropagationGridUnit(
        const std::vector<double>& grid_points,
        double frequency_mhz,
        double tx_power_watts,
        const std::map<std::string, double>& propagation_params = {}
    );
    
    static std::string createAntennaPatternUnit(
        const std::vector<double>& antenna_data,
        double frequency_mhz,
        const std::map<std::string, double>& antenna_params = {}
    );
    
    static std::string createBatchQSOUnit(
        const std::vector<std::vector<double>>& qso_data,
        double frequency_mhz,
        const std::map<std::string, double>& batch_params = {}
    );
    
    static std::string createSolarEffectsUnit(
        const std::vector<double>& solar_data,
        double frequency_mhz,
        const std::map<std::string, double>& solar_params = {}
    );
};

#endif // FGCOM_WORK_UNIT_DISTRIBUTOR_H
