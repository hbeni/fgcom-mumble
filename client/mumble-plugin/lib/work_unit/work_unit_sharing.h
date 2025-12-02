#ifndef FGCOM_WORK_UNIT_SHARING_H
#define FGCOM_WORK_UNIT_SHARING_H

#include <vector>
#include <string>
#include <memory>
#include <map>
#include <functional>
#include <mutex>
#include <atomic>

// Forward declarations to avoid circular dependency
class WorkUnit;
struct ClientWorkUnitCapability;
class FGCom_WorkUnitDistributor;

// Work unit sharing result
enum class WorkUnitSharingResult {
    SUCCESS = 0,
    FAILED = 1,
    CLIENT_NOT_AVAILABLE = 2,
    NETWORK_ERROR = 3,
    INVALID_UNIT = 4,
    SHARING_DISABLED = 5
};

// Work unit sharing statistics
struct WorkUnitSharingStats {
    std::atomic<uint64_t> total_units_shared;
    std::atomic<uint64_t> total_units_failed;
    std::atomic<uint64_t> total_broadcasts;
    std::atomic<uint64_t> total_direct_assignments;
    std::atomic<double> average_sharing_time_ms;
    
    std::map<std::string, uint64_t> client_units_received;
    std::map<std::string, uint64_t> client_units_failed;
};

// Abstract base class for work unit sharing strategies
class FGCom_WorkUnitSharingStrategy {
public:
    virtual ~FGCom_WorkUnitSharingStrategy() = default;
    
    // Initialize the sharing strategy
    virtual bool initialize() = 0;
    
    // Shutdown the sharing strategy
    virtual void shutdown() = 0;
    
    // Share a work unit with a specific client
    virtual WorkUnitSharingResult shareWithClient(
        const std::string& unit_id,
        const WorkUnit& unit,
        const std::string& client_id,
        const ClientWorkUnitCapability& client_capability
    ) = 0;
    
    // Share a work unit with multiple clients (broadcast)
    virtual WorkUnitSharingResult shareWithClients(
        const std::string& unit_id,
        const WorkUnit& unit,
        const std::vector<std::string>& client_ids,
        const std::map<std::string, ClientWorkUnitCapability>& client_capabilities
    ) = 0;
    
    // Share a work unit with all available clients
    virtual WorkUnitSharingResult shareWithAllClients(
        const std::string& unit_id,
        const WorkUnit& unit,
        const std::map<std::string, ClientWorkUnitCapability>& all_client_capabilities
    ) = 0;
    
    // Check if a client is available for sharing
    virtual bool isClientAvailable(const std::string& client_id) const = 0;
    
    // Get sharing statistics
    virtual const WorkUnitSharingStats& getStatistics() const = 0;
    
    // Reset statistics
    virtual void resetStatistics() = 0;
    
    // Get strategy name
    virtual std::string getStrategyName() const = 0;
    
    // Set callback for notification when work unit is shared
    virtual void setOnSharedCallback(std::function<void(const std::string& unit_id, const std::string& client_id)> callback) = 0;
    
    // Set callback for notification when sharing fails
    virtual void setOnFailedCallback(std::function<void(const std::string& unit_id, const std::string& client_id, WorkUnitSharingResult reason)> callback) = 0;
};

// Direct assignment sharing strategy - assigns work unit directly to a single client
class FGCom_DirectAssignmentSharingStrategy : public FGCom_WorkUnitSharingStrategy {
private:
    WorkUnitSharingStats stats;
    std::function<void(const std::string&, const std::string&)> on_shared_callback;
    std::function<void(const std::string&, const std::string&, WorkUnitSharingResult)> on_failed_callback;
    std::map<std::string, bool> client_availability;
    mutable std::mutex stats_mutex;
    mutable std::mutex availability_mutex;
    
public:
    FGCom_DirectAssignmentSharingStrategy();
    virtual ~FGCom_DirectAssignmentSharingStrategy();
    
    bool initialize() override;
    void shutdown() override;
    
    WorkUnitSharingResult shareWithClient(
        const std::string& unit_id,
        const WorkUnit& unit,
        const std::string& client_id,
        const ClientWorkUnitCapability& client_capability
    ) override;
    
    WorkUnitSharingResult shareWithClients(
        const std::string& unit_id,
        const WorkUnit& unit,
        const std::vector<std::string>& client_ids,
        const std::map<std::string, ClientWorkUnitCapability>& client_capabilities
    ) override;
    
    WorkUnitSharingResult shareWithAllClients(
        const std::string& unit_id,
        const WorkUnit& unit,
        const std::map<std::string, ClientWorkUnitCapability>& all_client_capabilities
    ) override;
    
    bool isClientAvailable(const std::string& client_id) const override;
    
    const WorkUnitSharingStats& getStatistics() const override;
    void resetStatistics() override;
    
    std::string getStrategyName() const override;
    
    void setOnSharedCallback(std::function<void(const std::string&, const std::string&)> callback) override;
    void setOnFailedCallback(std::function<void(const std::string&, const std::string&, WorkUnitSharingResult)> callback) override;
    
    // Update client availability
    void updateClientAvailability(const std::string& client_id, bool available);
};

// Broadcast sharing strategy - broadcasts work unit to multiple clients
class FGCom_BroadcastSharingStrategy : public FGCom_WorkUnitSharingStrategy {
private:
    WorkUnitSharingStats stats;
    std::function<void(const std::string&, const std::string&)> on_shared_callback;
    std::function<void(const std::string&, const std::string&, WorkUnitSharingResult)> on_failed_callback;
    std::map<std::string, bool> client_availability;
    mutable std::mutex stats_mutex;
    mutable std::mutex availability_mutex;
    int max_broadcast_clients;
    
public:
    explicit FGCom_BroadcastSharingStrategy(int max_clients = 10);
    virtual ~FGCom_BroadcastSharingStrategy();
    
    bool initialize() override;
    void shutdown() override;
    
    WorkUnitSharingResult shareWithClient(
        const std::string& unit_id,
        const WorkUnit& unit,
        const std::string& client_id,
        const ClientWorkUnitCapability& client_capability
    ) override;
    
    WorkUnitSharingResult shareWithClients(
        const std::string& unit_id,
        const WorkUnit& unit,
        const std::vector<std::string>& client_ids,
        const std::map<std::string, ClientWorkUnitCapability>& client_capabilities
    ) override;
    
    WorkUnitSharingResult shareWithAllClients(
        const std::string& unit_id,
        const WorkUnit& unit,
        const std::map<std::string, ClientWorkUnitCapability>& all_client_capabilities
    ) override;
    
    bool isClientAvailable(const std::string& client_id) const override;
    
    const WorkUnitSharingStats& getStatistics() const override;
    void resetStatistics() override;
    
    std::string getStrategyName() const override;
    
    void setOnSharedCallback(std::function<void(const std::string&, const std::string&)> callback) override;
    void setOnFailedCallback(std::function<void(const std::string&, const std::string&, WorkUnitSharingResult)> callback) override;
    
    // Update client availability
    void updateClientAvailability(const std::string& client_id, bool available);
    
    // Set maximum number of clients to broadcast to
    void setMaxBroadcastClients(int max_clients);
};

// Load balancing sharing strategy - distributes work units based on client load
class FGCom_LoadBalancingSharingStrategy : public FGCom_WorkUnitSharingStrategy {
private:
    WorkUnitSharingStats stats;
    std::function<void(const std::string&, const std::string&)> on_shared_callback;
    std::function<void(const std::string&, const std::string&, WorkUnitSharingResult)> on_failed_callback;
    std::map<std::string, bool> client_availability;
    std::map<std::string, int> client_load;
    mutable std::mutex stats_mutex;
    mutable std::mutex availability_mutex;
    mutable std::mutex load_mutex;
    
public:
    FGCom_LoadBalancingSharingStrategy();
    virtual ~FGCom_LoadBalancingSharingStrategy();
    
    bool initialize() override;
    void shutdown() override;
    
    WorkUnitSharingResult shareWithClient(
        const std::string& unit_id,
        const WorkUnit& unit,
        const std::string& client_id,
        const ClientWorkUnitCapability& client_capability
    ) override;
    
    WorkUnitSharingResult shareWithClients(
        const std::string& unit_id,
        const WorkUnit& unit,
        const std::vector<std::string>& client_ids,
        const std::map<std::string, ClientWorkUnitCapability>& client_capabilities
    ) override;
    
    WorkUnitSharingResult shareWithAllClients(
        const std::string& unit_id,
        const WorkUnit& unit,
        const std::map<std::string, ClientWorkUnitCapability>& all_client_capabilities
    ) override;
    
    bool isClientAvailable(const std::string& client_id) const override;
    
    const WorkUnitSharingStats& getStatistics() const override;
    void resetStatistics() override;
    
    std::string getStrategyName() const override;
    
    void setOnSharedCallback(std::function<void(const std::string&, const std::string&)> callback) override;
    void setOnFailedCallback(std::function<void(const std::string&, const std::string&, WorkUnitSharingResult)> callback) override;
    
    // Update client availability
    void updateClientAvailability(const std::string& client_id, bool available);
    
    // Update client load
    void updateClientLoad(const std::string& client_id, int load);
    
    // Select best client based on load
    std::string selectBestClient(const std::map<std::string, ClientWorkUnitCapability>& client_capabilities) const;
};

// Work unit sharing manager - manages sharing strategies
class FGCom_WorkUnitSharingManager {
private:
    static std::unique_ptr<FGCom_WorkUnitSharingManager> instance;
    static std::mutex instance_mutex;
    
    std::unique_ptr<FGCom_WorkUnitSharingStrategy> current_strategy;
    std::map<std::string, std::unique_ptr<FGCom_WorkUnitSharingStrategy>> available_strategies;
    std::string default_strategy_name;
    mutable std::mutex strategy_mutex;
    
public:
    // Singleton access
    static FGCom_WorkUnitSharingManager& getInstance();
    static void destroyInstance();
    
    // Initialization
    bool initialize(const std::string& default_strategy = "direct");
    void shutdown();
    
    // Strategy management
    bool registerStrategy(const std::string& name, std::unique_ptr<FGCom_WorkUnitSharingStrategy> strategy);
    bool setStrategy(const std::string& strategy_name);
    std::string getCurrentStrategyName() const;
    std::vector<std::string> getAvailableStrategies() const;
    
    // Sharing operations (delegate to current strategy)
    WorkUnitSharingResult shareWithClient(
        const std::string& unit_id,
        const WorkUnit& unit,
        const std::string& client_id,
        const ClientWorkUnitCapability& client_capability
    );
    
    WorkUnitSharingResult shareWithClients(
        const std::string& unit_id,
        const WorkUnit& unit,
        const std::vector<std::string>& client_ids,
        const std::map<std::string, ClientWorkUnitCapability>& client_capabilities
    );
    
    WorkUnitSharingResult shareWithAllClients(
        const std::string& unit_id,
        const WorkUnit& unit,
        const std::map<std::string, ClientWorkUnitCapability>& all_client_capabilities
    );
    
    bool isClientAvailable(const std::string& client_id) const;
    const WorkUnitSharingStats& getStatistics() const;
    void resetStatistics() const;
    
    // Get current strategy
    FGCom_WorkUnitSharingStrategy* getCurrentStrategy() const;
};

#endif // FGCOM_WORK_UNIT_SHARING_H

