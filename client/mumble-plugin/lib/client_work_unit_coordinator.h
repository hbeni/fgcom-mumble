#ifndef FGCOM_CLIENT_WORK_UNIT_COORDINATOR_H
#define FGCOM_CLIENT_WORK_UNIT_COORDINATOR_H

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
#include <future>

// Forward declarations
#include "work_unit_distributor.h"
#include "gpu_types.h"

// Client work unit coordinator
class FGCom_ClientWorkUnitCoordinator {
private:
    static std::unique_ptr<FGCom_ClientWorkUnitCoordinator> instance;
    static std::mutex instance_mutex;
    
    // Configuration
    std::string server_url;
    std::string client_id;
    bool coordinator_enabled;
    bool auto_request_work_units;
    int max_concurrent_work_units;
    int work_unit_request_interval_ms;
    int heartbeat_interval_ms;
    
    // Client capabilities
    ClientWorkUnitCapability client_capability;
    std::vector<WorkUnitType> supported_work_types;
    std::map<WorkUnitType, int> max_concurrent_by_type;
    
    // Work unit management
    std::map<std::string, WorkUnit> assigned_work_units;
    std::queue<std::string> processing_queue;
    std::map<std::string, std::future<void>> processing_futures;
    
    // Threading and synchronization
    std::mutex work_units_mutex;
    std::mutex processing_mutex;
    std::condition_variable work_available;
    std::vector<std::thread> worker_threads;
    std::thread heartbeat_thread;
    std::thread work_request_thread;
    std::atomic<bool> workers_running;
    std::atomic<bool> coordinator_running;
    
    // Statistics
    std::atomic<uint64_t> total_work_units_received;
    std::atomic<uint64_t> total_work_units_completed;
    std::atomic<uint64_t> total_work_units_failed;
    std::atomic<double> average_processing_time_ms;
    std::atomic<double> average_queue_wait_time_ms;
    
    // Internal methods
    void workerThreadFunction();
    void heartbeatThreadFunction();
    void workRequestThreadFunction();
    bool requestWorkUnitsFromServer();
    bool submitWorkUnitResult(const std::string& unit_id, const std::vector<double>& result_data, bool success, const std::string& error_message = "");
    void processWorkUnit(const std::string& unit_id);
    std::vector<double> executeWorkUnit(const WorkUnit& unit);
    void updateClientCapabilities();
    void handleWorkUnitTimeout(const std::string& unit_id);
    void cleanupCompletedWorkUnits();
    
public:
    // Singleton access
    static FGCom_ClientWorkUnitCoordinator& getInstance();
    static void destroyInstance();
    
    // Initialization and configuration
    bool initialize(const std::string& server_url, const std::string& client_id);
    void shutdown();
    void setConfiguration(const std::map<std::string, std::string>& config);
    
    // Client capability management
    void setClientCapability(const ClientWorkUnitCapability& capability);
    void updateCapability(const std::string& capability_type, const std::string& value);
    ClientWorkUnitCapability getClientCapability() const;
    
    // Work unit processing
    bool enableAutoWorkUnitRequests(bool enable);
    bool requestSpecificWorkUnitType(WorkUnitType type);
    std::vector<std::string> getAssignedWorkUnits();
    std::vector<std::string> getProcessingWorkUnits();
    WorkUnitStatus getWorkUnitStatus(const std::string& unit_id);
    
    // Statistics and monitoring
    std::map<std::string, double> getStatistics();
    void resetStatistics();
    bool isHealthy();
    std::string getStatusReport();
    
    // Utility methods
    void cleanup();
    void forceCleanup();
};

// Client work unit processor for specific work unit types
class FGCom_ClientWorkUnitProcessor {
public:
    // Propagation grid processing
    static std::vector<double> processPropagationGrid(
        const std::vector<double>& grid_points,
        double frequency_mhz,
        double tx_power_watts,
        const std::map<std::string, double>& parameters
    );
    
    // Antenna pattern processing
    static std::vector<double> processAntennaPattern(
        const std::vector<double>& antenna_data,
        double frequency_mhz,
        const std::map<std::string, double>& parameters
    );
    
    // Frequency offset processing
    static std::vector<double> processFrequencyOffset(
        const std::vector<double>& audio_data,
        double frequency_mhz,
        const std::map<std::string, double>& parameters
    );
    
    // Audio processing
    static std::vector<double> processAudio(
        const std::vector<double>& audio_data,
        const std::map<std::string, double>& parameters
    );
    
    // Batch QSO processing
    static std::vector<double> processBatchQSO(
        const std::vector<std::vector<double>>& qso_data,
        double frequency_mhz,
        const std::map<std::string, double>& parameters
    );
    
    // Solar effects processing
    static std::vector<double> processSolarEffects(
        const std::vector<double>& solar_data,
        double frequency_mhz,
        const std::map<std::string, double>& parameters
    );
    
    // Lightning effects processing
    static std::vector<double> processLightningEffects(
        const std::vector<double>& lightning_data,
        double frequency_mhz,
        const std::map<std::string, double>& parameters
    );
};

// Client-server communication protocol
class FGCom_ClientServerCommunicator {
private:
    std::string server_url;
    std::string client_id;
    std::chrono::system_clock::time_point last_heartbeat;
    std::atomic<bool> connection_healthy;
    
public:
    FGCom_ClientServerCommunicator(const std::string& server_url, const std::string& client_id);
    
    // Client registration
    bool registerClient(const ClientWorkUnitCapability& capability);
    bool unregisterClient();
    bool updateClientCapability(const ClientWorkUnitCapability& capability);
    bool sendHeartbeat();
    
    // Work unit requests
    std::vector<WorkUnit> requestWorkUnits(int max_units = 1);
    bool submitWorkUnitResult(const std::string& unit_id, const std::vector<double>& result_data, bool success, const std::string& error_message = "");
    
    // Server status queries
    bool getServerStatus();
    std::map<std::string, double> getServerStatistics();
    std::map<std::string, std::string> getServerConfiguration();
    
    // Connection management
    bool isConnected();
    void setConnectionTimeout(int timeout_ms);
    std::string getLastError();
    
private:
    std::string last_error;
    int connection_timeout_ms;
    
    // HTTP communication helpers
    std::string makeHTTPRequest(const std::string& endpoint, const std::string& method = "GET", const std::string& data = "");
    nlohmann::json parseJSONResponse(const std::string& response);
    bool handleHTTPError(int status_code, const std::string& response);
};

// Work unit result aggregator for combining distributed results
class FGCom_WorkUnitResultAggregator {
private:
    std::map<std::string, std::vector<double>> partial_results;
    std::map<std::string, std::vector<std::string>> contributing_clients;
    std::mutex results_mutex;
    
public:
    // Result aggregation
    bool addPartialResult(const std::string& work_unit_id, const std::string& client_id, const std::vector<double>& result_data);
    std::vector<double> getAggregatedResult(const std::string& work_unit_id);
    bool isResultComplete(const std::string& work_unit_id);
    std::vector<std::string> getContributingClients(const std::string& work_unit_id);
    
    // Result validation
    bool validateResult(const std::string& work_unit_id, const std::vector<double>& expected_result);
    double calculateResultConfidence(const std::string& work_unit_id);
    
    // Cleanup
    void removeResult(const std::string& work_unit_id);
    void cleanupOldResults(std::chrono::system_clock::time_point cutoff_time);
};

#endif // FGCOM_CLIENT_WORK_UNIT_COORDINATOR_H
